# Logging and observability

The operator view of what fluidbox emits, how to read it, and what it will never
contain. The engineering rationale lives in
[`../plans/2026-08-24-observability-logging-design.md`](../plans/2026-08-24-observability-logging-design.md);
this document is the runbook.

fluidbox has three observability surfaces and they answer different questions:

| Surface | Question it answers | Scope | Retention |
|---|---|---|---|
| **Logs** (this document) | *What happened, in what order, and why* | Deployment-wide, all tenants | Whatever your collector keeps |
| **Metrics** (`/v1/admin/metrics`) | *How much, how often, how slow* | Deployment-wide, fixed-cardinality | Whatever your TSDB keeps |
| **The ledger** (`/v1/sessions/{id}/events`) | *What a run did, as an audit record* | Per tenant, row-level-security enforced | Durable, in Postgres |

They are deliberately not interchangeable. The most important consequence is in
[What logs never contain](#what-logs-never-contain).

## The record

One flat JSON object per line, on stdout.

```json
{"ts":"2026-08-24T09:12:33.481920Z","level":"info",
 "target":"fluidbox_server::orchestrator","msg":"run status changed",
 "service":"fluidbox-server","version":"0.8.0","instance":"fluidbox-7d9c4-x2k1","pid":1,
 "span":"run","spans":["http","run"],"span_id":"00000000000004d2",
 "request_id":"018f2c3d-0000-7000-8000-000000000001",
 "trace_id":"018f2c3d000070008000000000000001",
 "session_id":"018f2c3e-…","tenant_id":"018f0a11-…","actor":"system",
 "event":"session.status_changed","from":"provisioning","to":"running"}
```

Flat, not nested: one index level, and no ambiguity about whether `http.status`
is an object.

### Envelope keys

| Key | Meaning |
|---|---|
| `ts` | RFC 3339, UTC, microseconds |
| `level` | `trace` \| `debug` \| `info` \| `warn` \| `error` |
| `target` | Rust module path, or the runner's component |
| `msg` | The human sentence |
| `service` | `fluidbox-server` \| `fluidbox-runner` |
| `version` | Build version |
| `instance` | Replica identity — the pod name on Kubernetes |
| `span` / `spans` | Innermost span, and the chain from root |
| `span_id` | The span's id, 16 hex digits, unique within this process |
| `file` / `line` | Present when `FLUIDBOX_LOG_LOCATION=1` (default on for text) |

A field whose name collides with one of these is written with a trailing
underscore (`level_`) rather than shadowing the envelope.

### The fields that make it useful

Everything else is a field from the record or an enclosing span. The ones worth
knowing:

- **`request_id`** — on every record produced while serving one HTTP request,
  and echoed to the caller in the `x-request-id` response header. A user with a
  failed request can quote it; you can then pull every line of that request.
- **`trace_id`** — the same identity in W3C shape, adopted from an inbound
  `traceparent` when the caller sends one, so a request that crossed a gateway
  keeps one id end to end.
- **`session_id`** — the run. On every record about it, from any plane, on any
  task, **including the runner's own records inside the sandbox**. This is the
  join that lets you read one run's whole story.
- **`tenant_id`**, **`user_id`**, **`principal`** — who asked. `principal` is
  `operator` \| `user` \| `pat` \| `trigger` \| `runner` \| `worker`.
- **`error_kind`** — a CLOSED classification on every failure: `db`, `upstream`,
  `timeout`, `unauthenticated`, `forbidden`, `not_found`, `invalid`, `conflict`,
  `capacity`, `policy`, `custody`, `budget`, `provider`, `internal`. Group and
  alert on this, never on `msg`.
- **`outcome`** — `ok` \| `error`.
- **`duration_ms`** — one name for elapsed time, everywhere.
- **`retrying`** — `true` when the loop that logged this will come back. "This
  failed" and "this failed and will retry in 10s" read identically in prose and
  are completely different operationally.

## Queries that answer real questions

Written for `jq` against a stream; translate to your collector's syntax.

```bash
# Everything about one run, both halves — control plane AND sandbox.
jq 'select(.session_id=="018f2c3e-…")'

# Everything about one user-reported failure, from the id in their x-request-id.
jq 'select(.request_id=="018f2c3d-…")'

# Which endpoints are slow.
jq 'select(.msg=="request") | {route, duration_ms}'

# Are the errors ours or a dependency's?
jq 'select(.error_kind) | .error_kind' | sort | uniq -c

# Why is this run not doing anything? (Refusals sit at INFO on purpose.)
jq 'select(.event=="tool.decision" and .verdict!="allow") | {tool, verdict, source, reason}'

# Which tenant is driving the load.
jq 'select(.msg=="request") | .tenant_id' | sort | uniq -c | sort -rn

# Runs stuck before they ever started.
jq 'select(.msg=="launching run" or .msg=="workspace materialised" or .msg=="sandbox provisioned")'
```

## What logs never contain

**Logs carry identity, classification, timing and outcome. They never carry
content.** Tool arguments, agent messages, tool result summaries, run summaries,
prompts and model output do not appear — not redacted, not truncated, not at
`debug`.

This is a tenancy decision, not caution. The ledger is tenant-scoped with
row-level security behind it; the log stream is one shared pipe to whatever
aggregator you ship to, with one access-control list for every tenant at once.
Putting one tenant's agent commands there would quietly undo a property this
system treats as a signature requirement.

So the log records the SHAPE (`tool`, `verdict`, `source`, `digest`, `bytes`,
`duration_ms`) and **`session_id` + `tool_call_id` join it to the ledger**, where
the content is, under the access controls content deserves.

### Redaction

Every value written is scrubbed twice over, by two independent mechanisms:

- **By shape** — credential patterns: fluidbox session/trigger/PAT tokens,
  Anthropic/OpenAI keys, GitHub PATs, AWS key ids, Slack tokens, JWTs, bearer
  and basic headers, PEM private-key blocks, connection-string passwords, and
  OAuth material in query strings.
- **By position** — a field-name deny list. This is the half that matters most,
  because the highest-value secrets here have **no recognisable shape**: a KEK, a
  LiteLLM virtual key, a webhook HMAC secret and a random database password are
  all just entropy, and no pattern will ever match one. It applies at any depth,
  so a credential nested inside a logged HTTP response is caught too.

Redaction preserves the diagnostic. A scrubbed connection string keeps its host
and role; a scrubbed OAuth callback keeps the parameter name; a scrubbed pod name
keeps everything but the credential-shaped part. You lose the secret, not the
ability to debug.

It applies to the envelope too, not just the fields — `service`, `instance` and
`version` are scrubbed once when the subscriber is built. Those are
operator-set, so that is defence in depth rather than a live hole; but "every
byte reaching the sink passes through redaction" is the claim, and a claim with
one exception is not the claim.

**There is no switch to turn redaction off.** The only argument for one is
"redaction is hiding something I need", which the design answers by keeping
context; against that, a disable switch is one environment variable between
production and credentials in a third-party log store, and the pressure to flip
it arrives exactly when judgement is worst. If a field is genuinely
over-redacted, the fix is a reviewed change to the allow list in
`fluidbox-obs::redact`.

## Configuration

All optional. A malformed value **fails boot** with a message naming the
variable — a logging knob that silently ignores what you typed is how a
deployment ends up believing it emits JSON while it emits ANSI-coloured text
into an aggregator. `just doctor` checks these before you find out that way.

| Variable | Default | Notes |
|---|---|---|
| `FLUIDBOX_LOG_FORMAT` | `auto` | `json` \| `text` \| `auto`. `auto` = text on a terminal, json off one |
| `FLUIDBOX_LOG_LEVEL` | see below | A bare level, or a full `EnvFilter` directive set |
| `RUST_LOG` | — | **Wins over `FLUIDBOX_LOG_LEVEL` when set** |
| `FLUIDBOX_LOG_THROTTLE_PER_SEC` | `200` | Per-callsite budget; `0` disables |
| `FLUIDBOX_LOG_THROTTLE_REPORT_SECS` | `60` | Suppression report interval; `0` disables |
| `FLUIDBOX_LOG_MAX_FIELD_BYTES` | `8192` | Per-field ceiling |
| `FLUIDBOX_LOG_MAX_LINE_BYTES` | `65536` | Per-record ceiling |
| `FLUIDBOX_LOG_INSTANCE` | `$HOSTNAME` | Replica identity |
| `FLUIDBOX_LOG_LOCATION` | text: on, json: off | Include `file`/`line` |
| `FLUIDBOX_LOG_COLOR` | `auto` | ANSI, text format only |
| `FLUIDBOX_LOG_THREAD_NAMES` | off | Include the tokio worker name |

The default filter is
`info,fluidbox_server=info,fluidbox_db=info,sqlx=warn,hyper=warn,h2=warn,…` —
the third-party transport crates are quieted because they log per-frame at
`debug` and carry no control-plane meaning. `sqlx=warn` is deliberate and useful:
sqlx logs a **slow query** at warn, so slow-query logging is on by default.

`FLUIDBOX_LOG_FORMAT` and `FLUIDBOX_LOG_LEVEL` are **forwarded to sandbox
runners**, so one setting governs both halves of a run.

On Kubernetes these are `server.logFormat`, `server.logLevel`,
`server.logThrottlePerSec` and `server.logThrottleReportSecs` in the chart;
`FLUIDBOX_LOG_INSTANCE` is bound to the pod name automatically.

### Turning up detail during an incident

```bash
RUST_LOG=info,fluidbox_server=debug   # step-by-step for the control plane
RUST_LOG=info,fluidbox_server::broker=debug,fluidbox_server::oauth=debug
```

Correlation survives any filter, including `RUST_LOG=error`: the spans that
carry `request_id` and `session_id` are pinned enabled independently, so the
errors that survive a tightened filter still say whose request they belong to.

## The logging subsystem's own health

Exposed as metrics, because a log that silently drops records is worse than a
sparse one — an operator reading a quiet log concludes the system is quiet.

| Metric | Meaning |
|---|---|
| `fluidbox_log_records_total` | Records written |
| `fluidbox_log_suppressed_total` | **Records DROPPED by the rate limiter** |
| `fluidbox_log_redactions_total` | Values blanked or rewritten |
| `fluidbox_log_truncations_total` | Values or records cut at a ceiling |
| `fluidbox_log_write_errors_total` | Failed writes to the sink |

**Alert on `fluidbox_log_suppressed_total` increasing.** Non-zero means the log
is incomplete. Nothing is lost silently, though: the server emits one WARN per
interval naming the offending callsites and their counts —

```json
{"level":"warn","msg":"log records were suppressed by the per-callsite rate limit…",
 "suppressed":40213,"callsites":1,"window_secs":60,
 "worst":"fluidbox_server::netgrant@crates/…/netgrant.rs:358 ×40213"}
```

— which is enough to go fix the loop, or raise the budget if the volume is
genuinely wanted.

`fluidbox_log_write_errors_total` is the only evidence a full disk or a closed
pipe produced: logging never propagates a write failure, because a broken log
must not take a control plane down.

## Boot

Logging is built **before configuration is read** — a config error is among the
things most worth logging, and until that line runs every diagnostic is lost.
So a replica that never came up still leaves records:

```json
{"level":"info","msg":"logging initialised …","format":"json","filter":"info,fluidbox_server=info,…","throttle_per_sec":200}
{"level":"info","msg":"connecting to the database"}
{"level":"error","msg":"BOOT FAILED — the control plane did not start","error":"…","error_kind":"internal"}
```

The one thing that cannot be a record is a malformed `FLUIDBOX_LOG_*` value
itself — logging is not up yet, by definition. That refusal goes to stderr as
plain text, names the variable and its accepted set, and `just doctor` catches
it before you get there.

Everything the boot banner reports is a field: pool sizing, RLS posture,
provider, queue caps, sealing mode, LLM key mode, egress limits, listener binds,
the workload-identity mode. "What was this replica configured with" is a
group-by, and comparable across replicas — which is usually when you want to ask
it.

A **spike** in `fluidbox_log_redactions_total` is worth a look. A steady rate is
normal (upstream errors quote URLs); a step change means something newly started
carrying credential-shaped text into logs, which is usually a new code path
logging something it should not.

## Runbook: reading an incident

1. **Get an id.** A user report gives you `x-request-id`; an alert gives you a
   `session_id`; a dashboard gives you a `route` and a window.
2. **Pull the whole story.** Filter on that one id. Both halves of a run — the
   control plane's records and the sandbox runner's — carry `session_id`.
3. **Classify before diagnosing.** Read `error_kind` first. `capacity` and
   `policy` mean the system is working as designed; `db`, `upstream` and
   `provider` point at a dependency; `internal` points at us.
4. **Check the seam.** If the two halves disagree, the interesting record is the
   last one before they diverged — usually a gate verdict
   (`event="tool.decision"`) or an audience refusal.
5. **Check whether the log is complete.** If `fluidbox_log_suppressed_total`
   moved during your window, some records are missing and the suppression report
   names which callsite.
6. **Escalate to the ledger for content.** Logs will not tell you what the agent
   ran. `GET /v1/sessions/{id}/events` will, under that tenant's access controls.

## Shipping logs elsewhere

Records go to **stdout**, one JSON object per line, which every container log
collector already handles. There is deliberately no built-in shipper, no
OpenTelemetry exporter and no file rotation: the platform running the container
already solves those, and a second implementation inside the process is a second
thing to configure and a second thing to fail.

`trace_id` and `span_id` are emitted in the W3C shape, so if you later run a
collector, these records join traces it already has without a schema change.
