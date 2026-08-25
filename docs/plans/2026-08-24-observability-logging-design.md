# Observability: structured logging across the control plane and the sandbox

**Status:** implemented.
**Operator view:** [`../hosted/observability.md`](../hosted/observability.md).
**Scope:** the log surface. Metrics (`fluidbox-server::metrics`, Phase F #34) and
the ledger (`fluidbox-core::event`) are unchanged and stay authoritative for
their own questions.

## 1. The problem

Before this work the control plane logged with bare interpolated strings:

```rust
tracing::warn!("reap {id}: {e}");
tracing::error!("transition {id}->{next:?} failed: {e}");
```

~250 of them across ~114k lines of Rust, plus `console.error("fluidbox-runner:
fatal:", e)` in the sandbox. That has four properties, all bad:

1. **Nothing is queryable.** You can grep for a session id. That is the entire
   capability. "How many runs failed with a provider error today", "which tenant
   is driving this load", "which endpoint is slow" are all unanswerable without
   writing a regex per module.
2. **Nothing is correlated.** The `TraceLayer` created a `debug_span!("http", …)`
   — and a span below the filter is never created, so at the default `info`
   filter it attached **nothing to anything**. Request correlation looked
   present and was absent. There was also no completion record at all: no access
   log, no latency signal.
3. **Whole planes were dark.** `api.rs` (84 KB): zero. `internal.rs` (112 KB, the
   permission gate): four. `broker.rs` (224 KB): twelve. `oauth.rs` (175 KB):
   sixteen. `triggers.rs`, `bindings.rs`, `rbac.rs`, `seal.rs`: zero.
4. **Nothing filtered credentials.** `warn!("fetch failed: {e}")` where `e` is a
   reqwest error carrying `?code=…`, or a sqlx error quoting a connection
   string, went straight to stdout — and from there to whatever aggregator the
   deployment ships to, which usually has a different retention policy and a
   different access-control list than the database.

The ledger's `Redactor` covers exactly one egress: `append_event`. Logs are a
second egress with the same hazard and none of that guarantee.

## 2. Shape of the solution

A new **leaf crate**, `fluidbox-obs`. It depends on nothing else in the
workspace, so every crate — including `fluidbox-core`, at the bottom of the
dependency order — can log through it without inverting anything.

```
fluidbox-obs
├── redact.rs    value patterns + field-name deny list + safe URL rendering
├── field.rs     the canonical field vocabulary and its closed value sets
├── format.rs    the ObsLayer: capture, merge, redact, format, write
├── config.rs    LogConfig::from_env, boot-refusing on a bad value
├── init.rs      subscriber assembly, global and test
├── span.rs      the correlation spans and W3C trace identity
├── throttle.rs  per-callsite rate limiting
├── timing.rs    Stopwatch
├── stats.rs     the subsystem's own counters
└── capture.rs   an in-memory sink, published for other crates' tests
```

Four properties, in priority order.

### 2.1 Structured

One flat JSON object per record, stable envelope, typed fields. Flat rather than
nested: one index level, cheap to query, no ambiguity about whether `http.status`
is an object.

Field names are `const`s in `field.rs`, not string literals at call sites.
Structured logging only pays off if the same fact is spelled the same way
everywhere; `session_id` in one module and `run_id` in another produces two index
columns for one concept, and every query then gets one of them wrong. Three
invariants are asserted: names are flat snake_case, no name collides with a
reserved envelope key, and **no vocabulary name is one the redactor would always
blank** (a field declared everywhere and empty everywhere is a bug worth failing
a build over).

`error_kind` is a **closed** set of fourteen values. It is what alerts group on,
so it cannot be "whatever the call site felt like" — the moment it is, every
panel built on it silently stops covering new failures. The free-form detail goes
in `error`, which nothing aggregates.

### 2.2 Correlated

`request_id` on every record inside an HTTP request; `session_id` on every record
about a run, on any plane, on any task, **including the sandbox runner's**.

Two mechanics matter:

- **Spans, not parameters.** Ids are inherited from the enclosing span, so a
  helper five frames down logs them without knowing a run exists. `.instrument()`
  rather than `Span::enter()` everywhere async: an entered guard held across an
  `.await` attributes whatever the executor runs next to the wrong run.
- **Late binding.** Authentication happens inside the handler, well after the
  request span opens, and a field not declared at creation can never be recorded.
  So the request span declares `principal`, `tenant_id`, `user_id`, `session_id`
  as `Empty`, and `auth.rs` fills them the moment a principal resolves.

`trace_id` is the request id in W3C hex, or the caller's if they sent a
`traceparent`. That is forward compatibility in the DATA, which is the expensive
part to change later — no OpenTelemetry dependency, no exporter, no second
configuration surface.

**The correlation pin.** `init` always appends `fluidbox_obs::span=trace` to the
filter. A span whose level fails the filter is never created and attaches no
fields, so under `RUST_LOG=error` the surviving ERROR records would arrive
stripped of exactly the ids that make them actionable. The pin is one module and
spans only — pinning the whole crate would force this crate's own events past an
operator's filter, making the module meant to be invisible the one thing
`RUST_LOG=error` cannot silence.

### 2.3 Redacted

Two independent mechanisms, both applied to every value:

- **By shape** — compiled patterns, prefiltered through a `RegexSet` so a clean
  line does one pass and allocates nothing.
- **By position** — a field-name deny list, checked before the value is rendered
  or measured.

**The second matters more.** The highest-value secrets in this system have no
recognisable shape: a KEK, a per-tenant LiteLLM virtual key, a webhook HMAC
secret and a random database password are all just entropy. Shape-matching alone
is a false sense of safety. Together, a secret has to be *both* shapeless *and*
recorded under an innocuous name to escape — which is a bug you can name in
review rather than a class you cannot see.

Writing the runner's tests exposed a hole in both implementations: field-name
blanking only ever looked at the **top level**, so the most realistic leak went
through — a failing HTTP client logged as
`{ response: { headers: { authorization: "…" } } }` puts the credential two
levels down. Both sides now handle nesting (recursive key blanking in JS, name
matching inside a rendering in Rust). This is the single best argument for the
tests: the property is not obvious, and the hole was in the first draft of both.

**No disable switch.** The only argument for one is "redaction is hiding
something I need", which the design answers by preserving context — a scrubbed
connection string keeps its host and role, a scrubbed callback keeps the
parameter name. Against that, a disable switch is one environment variable
between production and credentials in a third-party log store, and the pressure
to flip it arrives exactly when judgement is worst. Over-redaction is fixed by a
reviewed change to the allow list.

### 2.4 Bounded

The classic production logging failure is not too little output; it is a hot loop
that fills the disk and buries the signal. Several loops here retry on a fixed
tick and log every failure (network-grant re-verification every ~2s, sweepers
every 10s). Pointed at a persistent fault they emit the same line forever.

Per-callsite fixed-window budget, default 200/s — two orders of magnitude above
anything healthy here, so it only fires on the pathological case. **Nothing is
lost silently**: suppressions are counted, and the offending callsites are named
in one WARN per interval. ERROR is deliberately not exempt — an error in a 2s
retry loop is precisely the flood this exists to stop, and "this error fired
40,000 times" is more useful than 40,000 copies of it.

Field and record ceilings exist for the same reason: one `Debug` of a large
structure can produce megabytes, and a pipeline that must buffer it drops
everything around it. An over-long text record is cut at a UTF-8 boundary; an
over-long JSON record becomes a compact, structurally valid fallback. An
arbitrary serialized prefix cannot be repaired reliably.

## 3. Decisions worth defending

### 3.1 The formatter is ours

Not `tracing_subscriber`'s JSON layer. This is a security property, not taste:
redaction is only a guarantee if **every byte reaching the sink passes through
code that scrubs**, and owning the one write path makes that structural instead
of a convention someone can forget. `tracing_subscriber` also splits formatting
across two traits and stashes span fields as an opaque pre-rendered string, which
(a) leaves seams in the guarantee and (b) makes duplicate-key merging a
string-parsing problem. Keeping typed field vectors in the span extension makes
"the event's statement of a fact wins" a two-line rule.

It also costs **zero new dependencies** — no `tracing-serde`, no `json` feature.

### 3.2 The database commit is the funnel

Canonical events have more than one append path: ordinary writes call
`append_event`, while approval decisions, expiries, and terminal-deny claims
append inside their owning transaction. `fluidbox-db::commit_and_mirror_events`
is the common boundary: it commits first, then mirrors exactly the events and
sequences made durable. A failed commit produces no phantom log record, and the
transactional approval paths cannot disappear from the mirror.

The alternative — sprinkling `info!` through those paths — would have been more
code, worse coverage, and would silently stop working when someone moved a
`return`.

### 3.3 Logs carry no content

**The tenancy boundary.** Tool arguments, agent messages, tool summaries and run
summaries stay in the ledger. The ledger is tenant-scoped with row-level security
behind it; the log stream is one shared pipe with one access-control list for
every tenant at once. Putting one tenant's agent commands there would quietly
undo a property this system calls a signature requirement.

Logs record the SHAPE — `tool`, `verdict`, `source`, `digest`, `bytes`,
`duration_ms` — and `session_id` + `tool_call_id` join back to the ledger. The
test `event_log::tests::event_content_never_reaches_the_shared_log` is what stops
someone helpfully adding `summary = %summary` or a free-form runner/upstream
error to an arm later.

### 3.4 One wide event per request, not two

The instinct is "handling GET /x" then "GET /x → 200". That is twice the volume
for strictly less information: the pair has to be correlated by the reader, the
first half tells you nothing the second does not, and a request that never
finishes leaves a dangling opener indistinguishable from one still in flight. The
single completion record says what happened; the **span** says something is
happening now.

### 3.5 Level policy

- `4xx` at INFO. It is the caller's mistake and ordinary traffic on a public API;
  logging it at WARN trains operators to ignore warnings, which is the expensive
  failure.
- `429`/`503` at WARN — neither a fault nor nothing: the system working as
  designed, but sustained backpressure is worth seeing without going looking.
- `5xx` at ERROR. Ours.
- A gate `allow` at DEBUG, a `deny`/`require_approval` at INFO. "Why did this run
  not do the thing" must be answerable without raising the level and reproducing.
- A run FAILING is WARN, not ERROR: usually the tenant's code or the agent's
  judgement, not a fault in this control plane. The control plane's own faults
  are ERROR, where they happen.
- `403` from `require_audience` is WARN: in a correct deployment it never fires,
  so it means version skew or a token being probed.

### 3.6 The default filter moved `fluidbox_server` to `info`

It was `debug`, chosen when the crate emitted a handful of debug lines. It now
emits far more, so keeping `debug` would have turned a quiet default into a
firehose. This is a deliberate, disclosed reduction in default verbosity; `debug`
is one variable away.

## 4. The two redactors

`fluidbox-core::event::Redactor` (ledger) and `fluidbox-obs::redact::Redactor`
(logs) are **deliberately independent restatements** of one rule. The codebase
already relies on that pattern — `SESSION_TOKEN_PREFIX` documents it — and
independence buys defence in depth. It costs a drift hazard, answered by a parity
test in `fluidbox-core` over a shared corpus.

That test surfaced a real finding, deliberately **not** fixed here: the ledger's
redactor is narrower, and does not cover JWTs, PEM private-key blocks, OAuth
material in a callback URL, an explicit `client_secret=` assignment, or shapeless
secrets named in prose. Each *can* reach an event body. The test pins the gap as
a named list so it is reviewed rather than accidental, and fails in both
directions — closing one is a welcome failure that tells you to shorten the list.
Widening a distinct security control deserves its own review, not a ride-along in
a logging change.

## 5. The sandbox half

`images/runner-lib/log.mjs` emits the same envelope, with `session_id` bound at
construction. A run's story spans two processes and the interesting question
during an incident is almost always about the SEAM — "the gate allowed it, so why
did the tool not run". Answering it means one query over both halves, which only
works if they agree on the shape and on `session_id`.

Redaction matters **more** there: that process holds every credential the sandbox
is given, and one of them — the LLM-audience session token — *is* the value of
`ANTHROPIC_API_KEY`. Its stderr is collected by the container runtime, so a leak
there travels further than one in the control plane.

`FLUIDBOX_LOG_FORMAT`/`FLUIDBOX_LOG_LEVEL` are forwarded into the runner env, so
one setting governs both halves. The runner falls back to `info`/`json` on
anything it cannot parse — an `EnvFilter` directive string degrades to the
default rather than silencing the sandbox.

## 6. What was deliberately not built

- **An OpenTelemetry exporter.** Large dependency tree, a background exporter, a
  second configuration surface, for a deployment that ships stdout to a
  collector. The forward compatibility that matters is in the data (`trace_id`),
  and it is there.
- **A log shipper, file rotation, or a second sink.** The platform running the
  container already solves these; a second implementation inside the process is a
  second thing to configure and a second thing to fail.
- **Per-tenant log routing.** Would require a sink per tenant and answers a
  question the tenant-scoped ledger already answers.
- **Sampling by rate.** The per-callsite limiter is the bound that matches the
  actual failure mode here. Probabilistic sampling loses the one record you
  wanted; a per-callsite budget loses the 40,000th copy of one you already have.
- **Widening the ledger's redactor.** §4.

## 7. Verification

- `fluidbox-obs`: 62 tests. The headline is
  `no_credential_family_reaches_the_sink_by_any_route` — every credential family
  driven through every callsite shape (interpolated message, structured field,
  `Debug` value, inherited span field, sensitively-named field) with nothing
  reaching the sink. Plus
  `correlation_survives_a_filter_that_only_admits_errors`, which is the
  regression this whole design turns on.
- `request_log`: 18, including real axum-router coverage of matched paths,
  late-bound identity, body completion/error/drop, byte counts, and 503
  classification.
- `fluidbox-db::event_log`: content-boundary, join-key, URL-host, and level-policy
  tests for the post-commit canonical mirror.
- `error`: every variant classifies into the closed vocabulary; internal detail
  reaches the log and never the caller.
- `images/runner-lib/log.test.mjs`: 14, including nested shapeless credentials and
  text-mode control-character injection.
- `fluidbox-core`: the cross-crate redaction parity tripwire.
