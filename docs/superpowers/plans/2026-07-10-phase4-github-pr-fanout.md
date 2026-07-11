# Phase 4 — GitHub PR-Review Fan-Out Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One GitHub `pull_request` event independently borrows every matching agent subscription: a generic event spine (ingress → verify → normalize → match → `create_run` → publish) with two-level DB-unique idempotency, a GitHub App connection (webhook verify + installation tokens), exact-head-SHA workspaces, a real fork `ReadOnly` trust tier, and PR-comment/Check publishers with stable update-in-place identity — GitHub confined to ONE connector module.

**Architecture:** The spine is provider-ignorant: `events.rs` (router/matcher/dedup) speaks only `NormalizedEvent`/`ResultDestination`/`WorkspaceSpec`; `connectors/mod.rs` is the single dispatch point mapping a provider name to a module; `connectors/github.rs` owns §6.3's five duties (verify, normalize, workspace resolve, —, publish). Dedup reuses the Phase-3 claim-row pattern at two levels (`trigger_deliveries` unique on `(connection_id, external_event_id)`; `trigger_dispatches` unique on `(delivery_id, subscription_id)`), so a webhook retry heals a partial fan-out instead of duplicating it. Publication rides the existing `result_deliveries` worker via two new `ResultDestination` variants; stable comment identity lives in a new `external_results` table keyed `(subscription, kind, resource_key)`.

**Tech Stack:** Rust (axum/sqlx/tokio, `jsonwebtoken` for App JWTs), Neon Postgres, Next.js dashboard (presentation-only), bash e2e with a fake GitHub API (python) + `file://` clone base.

## Global Constraints

- Backend 100% Rust; dashboard presentation-only; Neon Postgres (CLAUDE.md hard constraints).
- **§17 SETTLED (user, 2026-07-10): #1 App-only result identity** (attribution inside content; check name `fluidbox/<subscription>`); **#2 default events `pull_request.opened` + `pull_request.reopened`, `synchronize` opt-in** per subscription; **#3 update-in-place** (one stable comment per (subscription, PR); one check per head SHA under a stable name). Record all three in the design doc §17.
- GitHub is a tenant of the seam, not the feature: **router/matcher/dedup (`events.rs`) and `run_service.rs` must contain no "github"** (e2e greps this). ALL GitHub knowledge in `connectors/github.rs`; `connectors/mod.rs` is the one provider→module dispatch. n=1 discipline: no abstract connector SDK/trait registry (§17 #8).
- Every match → the same `run_service::create_run`, `InvocationContext.kind = event`. RunSpec frozen at creation; server is the single status writer; ledger accepts only `Redacted<EventEnvelope>` (no new event types — publishes reuse `callback.delivered/failed`).
- Webhook retries must never duplicate runs or comments (claim rows, both levels, DB-unique).
- Fork events downgrade to `TrustTier::ReadOnly` — enforced at the permission gate on top of the policy verdict; subscriptions/policies **cannot** override it. Fail-safe: unknown/missing head repo ⇒ fork.
- Credentials: App private key + webhook secret AEAD-sealed (`seal.rs`); never in any response, RunSpec, sandbox, ledger, or artifact. PAT connections keep working for fetch. Fetch creds via `GIT_CONFIG_*` env only.
- One agent's failure shows only on its own comment/check; a dead destination never mutates a run (delivery decoupling inherited).
- New env vars (`FLUIDBOX_GITHUB_CLONE_BASE`, optional) → `.env.example` + CLAUDE.md. `FLUIDBOX_GITHUB_API_URL` already exists.
- E2E needs no public URL: locally-crafted GitHub-shaped payloads signed with the webhook secret; fake GitHub API via `FLUIDBOX_GITHUB_API_URL`; clone via `file://` clone base. Real-GitHub pass is manual (document it). Live tier self-skips without `ANTHROPIC_API_KEY`; **live runs autonomous** (supervised hangs at awaiting_approval).
- Touching `internal.rs` (permission path) ⇒ governance suite must stay green (`just e2e` phase runs it).
- Done only when `just check` AND `just e2e` fully green including the NEW e2e phase. Do NOT start Phase 5. Update `docs/HANDOVER.md` (rev 6).
- Unit/db tests and `just e2e` need the dev stack STOPPED; db tests need `set -a; source .env; set +a`.
- Commit after every task with the session trailers.

## File Structure

- Create: `migrations/0005_github_events.sql` — deliveries/dispatches/external_results, subscription event columns, connection webhook secret.
- Create: `crates/fluidbox-server/src/connectors/mod.rs` — provider dispatch + provider-neutral types (`VerifiedDelivery`, `NormalizedEvent`, `PublishContext`…).
- Create: `crates/fluidbox-server/src/connectors/github.rs` — ALL GitHub knowledge (signature verify, PR normalize, App JWT + installation tokens, PAT/App validation + repo listing, comment/check publishers).
- Create: `crates/fluidbox-server/src/events.rs` — provider-ignorant ingress/dedup/matcher/fan-out (grep-clean of github).
- Create: `scripts/e2e-github.sh` — new acceptance phase.
- Modify: `crates/fluidbox-core/src/spec.rs` (InvocationContext event fields, `TrustTier::as_str`, ResultDestination variants), `crates/fluidbox-core/src/policy.rs` (`read_only_denial`).
- Modify: `crates/fluidbox-db/src/lib.rs` (new rows/fns; `create_session` trust_tier + bind_dispatch; subscription/connection columns).
- Modify: `crates/fluidbox-server/src/{run_service.rs, internal.rs, triggers.rs, connections.rs, deliveries.rs, orchestrator.rs, config.rs, state.rs, main.rs}`.
- Modify: `Cargo.toml` (workspace `jsonwebtoken`), `crates/fluidbox-server/Cargo.toml`.
- Modify: `apps/web/app/lib/api.ts`, `apps/web/app/connections/page.tsx`, `apps/web/app/triggers/page.tsx`.
- Modify: `scripts/e2e.sh` (7 phases), `.env.example`, `CLAUDE.md`, `docs/HANDOVER.md`, design doc §17.

---

### Task 1: Core — event-shaped InvocationContext + GitHub ResultDestinations

**Files:** Modify `crates/fluidbox-core/src/spec.rs`.

**Interfaces (Produces):**
- `InvocationContext` gains (all `Option`, `skip_serializing_if`, wire-compat): `provider: Option<String>`, `external_event_id: Option<String>`, `event_type: Option<String>`, `resource: Option<String>` (e.g. `"acme/site#1"`), `occurred_at: Option<DateTime<Utc>>`.
- `ResultDestination` gains: `GitHubPrComment { connection_id: Uuid, repository: String, pr_number: i64 }` (tag `github_pr_comment`), `GitHubCheck { connection_id: Uuid, repository: String, head_sha: String }` (tag `github_check`).
- `impl TrustTier { pub fn as_str(&self) -> &'static str }` → `"trusted" | "read_only"`.

- [x] Write failing tests in `spec.rs`: old InvocationContext JSON (no new fields) still deserializes; event-kind context roundtrips; both new destinations roundtrip with exact wire tags; `TrustTier::as_str`.
- [x] Implement; `cargo test -p fluidbox-core spec::` green.
- [x] Commit `feat(core): event invocation context + github result destinations`.

### Task 2: Core — real ReadOnly trust tier classifier

**Files:** Modify `crates/fluidbox-core/src/policy.rs`.

**Interfaces (Produces):** `pub fn read_only_denial(req: &ToolCallRequest) -> Option<String>` — `None` = read-safe; `Some(reason)` = must be denied at the gate. Applied only when `RunSpec.trust_tier == ReadOnly`, AFTER policy evaluation, narrowing only.

Semantics (allowlist, fail-safe):
- Read-safe tools: `Read`, `Glob`, `Grep`, `LS`, `NotebookRead`.
- `Bash`: deny if command contains any shell metachar (`;`, `|`, `&`, `` ` ``, `$`, `(`, `)`, `<`, `>`, newline); else allow only token-bounded prefixes (reuse `prefix_matches`): `ls, cat, head, tail, wc, grep, rg, pwd, git status, git log, git diff, git show, git branch, git blame`.
- Everything else (Edit/Write/WebFetch/mcp__*/unknown/other Bash) → `Some("read-only trust tier (untrusted event source): …")`.

- [x] Failing tests: Read/Grep allowed; `git diff`/`cat x` allowed; `cat a; rm -rf /` denied (metachar); `git push`, `Edit`, `WebFetch`, unknown tool denied; `git statusx` denied (token boundary).
- [x] Implement; `cargo test -p fluidbox-core policy::` green. Commit `feat(core): read-only trust tier classifier`.

### Task 3: Migration 0005 + DB layer

**Files:** Create `migrations/0005_github_events.sql`; modify `crates/fluidbox-db/src/lib.rs`.

```sql
-- Phase 4: connected-service events (design §6.3/§6.4/§7/§10).
-- §17 #1–#3 settled 2026-07-10: App-only identity; default events
-- opened+reopened (synchronize opt-in); results update in place.
alter table integration_connections add column webhook_secret_sealed bytea;
alter table trigger_subscriptions
    add column connection_id uuid references integration_connections(id),
    add column resource_selector jsonb,   -- {"repositories": ["owner/name",…]}; null/[] = all
    add column event_filter jsonb,        -- {"events": ["pull_request.opened",…]}
    add column event_publish jsonb;       -- ["pr_comment","check"]
create index trigger_subscriptions_connection
    on trigger_subscriptions(connection_id) where connection_id is not null;

-- Level 1: one row per external delivery (webhook retries collapse here).
create table trigger_deliveries (
    id uuid primary key,
    connection_id uuid not null references integration_connections(id) on delete cascade,
    external_event_id text not null,
    event_type text not null,
    payload jsonb not null,
    payload_digest text not null,
    occurred_at timestamptz,
    received_at timestamptz not null default now(),
    unique (connection_id, external_event_id)
);
-- Level 2: at most one run per (delivery, subscription) — the fan-out claim.
create table trigger_dispatches (
    id uuid primary key,
    delivery_id uuid not null references trigger_deliveries(id) on delete cascade,
    subscription_id uuid not null references trigger_subscriptions(id) on delete cascade,
    session_id uuid references sessions(id) on delete set null,
    status text not null default 'created',   -- created|skipped|error
    skip_reason text,
    created_at timestamptz not null default now(),
    unique (delivery_id, subscription_id)
);
create index trigger_dispatches_subscription on trigger_dispatches(subscription_id);

-- §17 #3: stable external result identity — later events UPDATE, never spam.
create table external_results (
    id uuid primary key,
    subscription_id uuid not null references trigger_subscriptions(id) on delete cascade,
    kind text not null,           -- 'github_pr_comment'
    resource_key text not null,   -- 'owner/name#42'
    external_id text not null,
    external_url text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (subscription_id, kind, resource_key)
);
```

**Interfaces (Produces):** rows `TriggerDeliveryRow`, `TriggerDispatchRow`, `ExternalResultRow`; fns `insert_trigger_delivery(...) -> (TriggerDeliveryRow, bool /*fresh*/)` (on conflict fetch existing), `claim_trigger_dispatch(pool, delivery, subscription) -> Option<TriggerDispatchRow>` (None = already claimed), `mark_dispatch_outcome(pool, id, status, skip_reason)`, `list_event_subscriptions(pool, connection)` (enabled + kind='event'), `list_delivery_dispatches`, `list_connection_deliveries(pool, connection, limit)`, `get_external_result(pool, sub, kind, key)`, `upsert_external_result(pool, sub, kind, key, external_id, url)`; `create_connection` gains `webhook_secret_sealed: Option<&[u8]>`; `connection_webhook_secret_sealed(pool, id)`; `create_trigger_subscription` gains `connection_id: Option<Uuid>, resource_selector: Option<&Value>, event_filter: Option<&Value>, event_publish: Option<&Value>`; `TriggerSubscriptionRow`/struct gains those fields; `create_session` gains `trust_tier: &str` + `bind_dispatch: Option<Uuid>` (same transaction updates `trigger_dispatches.session_id` and sets `sessions.trust_tier`).

- [x] Write SQL; extend rows/fns; update ALL `create_session`/`create_trigger_subscription`/`create_connection` callers (`run_service.rs` passes `run_spec.trust_tier.as_str()` and `req.bound_dispatch`; existing callers pass `None`/trusted).
- [x] `cargo build --workspace` green (server boots migrations on next run). Commit `feat(db): event delivery/dispatch/external-result tables + wiring`.

### Task 4: Connector — GitHub verify + normalize (pure, tested)

**Files:** Create `crates/fluidbox-server/src/connectors/mod.rs`, `crates/fluidbox-server/src/connectors/github.rs`; modify `main.rs` (`mod connectors;`).

**Interfaces (Produces), in `connectors/mod.rs`:**
```rust
pub struct VerifiedDelivery { pub external_event_id: String, pub event_name: String }
pub struct NormalizeCtx { pub connection_id: Uuid, pub clone_base: String }
pub struct NormalizedEvent {
    pub event_type: String,            // "pull_request.opened"
    pub resource: String,              // container for matching: "acme/site"
    pub resource_key: String,          // stable identity: "acme/site#1"
    pub actor: Option<String>,
    pub occurred_at: Option<DateTime<Utc>>,
    pub trust_tier: TrustTier,
    pub workspace: Option<WorkspaceSpec>,          // exact head SHA
    pub context: BTreeMap<String, String>,         // task-template input
    pub publishable: BTreeMap<String, ResultDestination>, // "pr_comment"/"check" → instantiated
    pub attributes: serde_json::Value,             // frozen into InvocationContext
}
pub fn connector_for(provider: &str) -> Option<&'static str>;           // "github"|"github_app" → "github"
pub fn verify(connector: &str, headers: &HeaderMap, body: &[u8], secret: &str) -> Result<VerifiedDelivery, String>;
pub fn normalize(connector: &str, event_name: &str, payload: &Value, ctx: &NormalizeCtx) -> Result<Option<NormalizedEvent>, String>;
pub fn supported_events(connector: &str) -> &'static [&'static str];    // opened/reopened/synchronize
pub fn default_events(connector: &str) -> Vec<String>;                  // §17 #2
pub fn publish_modes(connector: &str) -> &'static [&'static str];       // ["pr_comment","check"]
pub fn sample_context(connector: &str) -> BTreeMap<String, String>;     // template validation
```
GitHub specifics (`github.rs`): `X-Hub-Signature-256: sha256=<hex hmac(secret, raw body)>` (compare sha256-of-both, like `auth.rs`); `X-GitHub-Delivery` → external id; `X-GitHub-Event` → event name. Normalize only `pull_request` with action ∈ {opened, reopened, synchronize} → `Some`; everything else (ping, other actions) → `Ok(None)`. Fork = `pull_request.head.repo.id != pull_request.base.repo.id` **or head repo missing** ⇒ `ReadOnly` + `CheckoutMode::ReadOnly`. Workspace: `GitRepository { connection_id, repository: full_name, clone_url: format!("{clone_base}/{full_name}"), ref: None, commit_sha: Some(head_sha), checkout_mode }`. Context keys: `repository, pr_number, pr_title, pr_url, pr_author, head_sha, head_ref, base_sha, base_ref, action, event, fork`.

- [x] Failing tests (fixture payload as `serde_json::json!`): signature verify (pinned openssl-cross-checked vector; tampered body fails; missing header fails); opened/reopened/synchronize normalize; other action → None; fork downgrade (+ missing head.repo ⇒ fork); context/workspace/publishable/resource_key contents; `sample_context` renders `default_events` templates.
- [x] Implement; `cargo test -p fluidbox-server connectors::` green. Commit `feat(server): github connector — webhook verify + PR normalize`.

### Task 5: GitHub App auth + connections

**Files:** Modify `Cargo.toml` (workspace `jsonwebtoken = "9"`), `crates/fluidbox-server/Cargo.toml`, `connectors/github.rs`, `connections.rs`, `orchestrator.rs`, `state.rs`, `config.rs`.

**Interfaces (Produces):**
- `github.rs`: `app_jwt(app_id: &str, pem: &str) -> Result<String, String>` (RS256, iat −60s, exp +540s, iss = app_id); `installation_token(state, conn) -> Result<String, String>` (POST `/app/installations/{id}/access_tokens`, cached in `state.connector_tokens: Mutex<HashMap<Uuid, (String, DateTime<Utc>)>>`, refresh < 300 s left); `validate_app(state, app_id, installation_id, pem) -> Result<Value /*metadata*/, ApiError>` (GET `/app`, GET `/app/installations/{id}`); `list_repos(state, conn, page, per_page)` branching PAT (`/user/repos`) vs App (installation token → `/installation/repositories`); `fetch_auth_header(state, conn) -> anyhow::Result<String>` (PAT → `basic x-access-token:<pat>`; App → mint installation token → same shape). Move the `github_get` HTTP helper here from `connections.rs`.
- `connections.rs::create` accepts `provider: "github_app"` with `app_id, installation_id, private_key, webhook_secret` (all required, all consumed; key + secret sealed; metadata `{app_id, installation_id, app_slug, account_login}`). PAT path unchanged. `repos` handler delegates to `connectors::github::list_repos`.
- `orchestrator.rs::connection_auth_header` → delegate to a provider dispatch `connectors::fetch_auth_header(state, conn)` (mod.rs matches provider → github).
- `config.rs`: `github_clone_base: String` (env `FLUIDBOX_GITHUB_CLONE_BASE`, default `https://github.com`).

- [x] Tests: `app_jwt` produces 3-part token whose decoded claims carry `iss`/`exp` (decode header+claims with base64, no network); PAT fetch header unchanged shape.
- [x] Implement; `cargo build --workspace` + tests green. Commit `feat(server): github app connections — jwt, installation tokens, sealed webhook secret`.

### Task 6: Trust tier enforced at the permission gate + create_run plumbing

**Files:** Modify `crates/fluidbox-server/src/run_service.rs`, `internal.rs`, callers (`api.rs`, `triggers.rs`, `scheduler.rs`).

**Interfaces:** `CreateRun` gains `trust_tier: TrustTier` and `bound_dispatch: Option<Uuid>` (existing callers: `TrustTier::Trusted`, `None`). `run_service` freezes it into the RunSpec and passes `as_str()` to `create_session`. In `internal.rs::permission`, immediately after `policy.evaluate(...)`: if `run_spec.trust_tier == TrustTier::ReadOnly` and `read_only_denial(&tool_req)` returns `Some(reason)` and the effective verdict isn't already Deny → respond deny with `source: "trust_tier"` in the `ToolDecision` ledger event (short-circuit before the approval machinery — no approval escape).

- [x] Implement; run `cargo test --workspace` (stack stopped, env sourced). Commit `feat(server): fork trust tier is real — read-only enforcement at the gate`.

### Task 7: Event subscriptions (`triggers.rs::create`)

**Files:** Modify `crates/fluidbox-server/src/triggers.rs`.

`CreateTrigger` gains: `connection: Option<String>` (uuid), `repositories: Option<Vec<String>>`, `events: Option<Vec<String>>`, `publish: Option<Vec<String>>`. `connection` set ⇒ `trigger_kind = "event"` (mutually exclusive with `schedule`). Validation: connection exists/tenant/active, `connector_for(provider)` known, `webhook_secret_sealed` present (else 400 "connection cannot receive events"); `events ⊆ supported_events` (default `default_events()` — §17 #2); `publish ⊆ publish_modes` (default `["pr_comment"]`; explicit `[]` = dashboard/webhook only); repositories all `valid_repo_name`; task_template required and must render from `sample_context` (strict, like the schedule check). Store via new `create_trigger_subscription` params. Response includes the connection's ingress URL path (`/v1/ingress/github/{connection_id}`).

- [x] Implement + unit-test validation edges compile-level; `cargo build`. Commit `feat(server): event trigger subscriptions (§17 #2 defaults)`.

### Task 8: The event spine — `events.rs` ingress/dedup/match/fan-out

**Files:** Create `crates/fluidbox-server/src/events.rs`; modify `main.rs` (route + mod), `error.rs` if a 401 variant is missing.

Route: `POST /v1/ingress/{provider}/{connection_id}` (public router, NO auth — the signature is the auth; body as `bytes::Bytes`, 2 MB cap → 413). Flow (provider-ignorant; github appears nowhere):
1. Load connection (404 if missing), require `status == "active"` (409), require `connectors::connector_for(conn.provider) == Some(path_provider)` (404).
2. Unseal `webhook_secret_sealed` (400 if absent/sealer off). `connectors::verify(...)` → 401 on failure (no delivery row).
3. Parse JSON; `connectors::normalize(...)`; `Ok(None)` → `200 {"ignored": event_name}` (no row).
4. `insert_trigger_delivery` (dedup level 1; `duplicate` flag in response).
5. `list_event_subscriptions(connection)`; filter: `event_filter.events` contains `event_type` AND (`resource_selector.repositories` null/empty OR contains `normalized.resource`).
6. Per match: `claim_trigger_dispatch` (level 2; `None` → count as `already_dispatched`, skip). Render `sub.task_template` with `normalized.context` (strict; failure ⇒ `mark_dispatch_outcome(error)`, continue others). Destinations = subscription `result_destinations` (signed webhooks) + `event_publish` modes looked up in `normalized.publishable`. `create_run` with: subscription autonomy/budgets/pins via `sub_run_params`, `explicit_workspace = normalized.workspace` (event-derived precedence), `trust_tier = normalized.trust_tier`, `invocation = InvocationContext { kind: Event, subscription_id, provider: conn.provider→connector name, external_event_id, event_type, resource: resource_key, actor, attributes, occurred_at, received_at: now }`, `bound_dispatch: Some(dispatch.id)`, `bound_invocation: None`. `SkippedOverlap` → `mark_dispatch_outcome(skipped, "overlap")`; `Err` → `mark_dispatch_outcome(error, msg)` (recorded, not retried — scheduler precedent).
7. `200 { delivery_id, event_type, duplicate, dispatched: [{subscription_id, session_id}], skipped: [...] }`.
Also: `GET /v1/connections/{id}/deliveries` (admin) — recent deliveries with their dispatches.

- [x] Implement; `cargo build`; matcher logic unit tests (event filter + repo selector, in `events.rs::tests` with plain structs — no DB). Commit `feat(server): provider-ignorant event ingress, two-level dedup, fan-out`.

### Task 9: Publisher — comment/check destinations in the delivery worker

**Files:** Modify `crates/fluidbox-server/src/deliveries.rs`, `connectors/mod.rs`, `connectors/github.rs`.

**Interfaces:** `connectors::publish(state, dest: &ResultDestination, ctx: &PublishContext) -> Result<PublishOutcome, String>` where `PublishContext { session_id, subscription_id: Option<Uuid>, subscription_name: String, agent_name: String, status: String, summary: Option<String>, commit_sha: Option<String> }`, `PublishOutcome { external_url: String, digest: String }`. `deliveries.rs::try_deliver` matches: `SignedWebhook` → existing path; `GitHubPrComment`/`GitHubCheck` → build `PublishContext` (sub name via `d.subscription_id`, agent/status/summary from session + run_spec, sha from frozen workspace) → `connectors::publish`. Ledger reuses `CallbackDelivered/Failed` with `url = external_url`.

GitHub publish semantics (§17 #1/#3): comment — `resource_key = "{repository}#{pr_number}"`; `get_external_result` → PATCH `/repos/{repo}/issues/comments/{id}`; 404/410 or absent → POST `/repos/{repo}/issues/{pr}/comments` then `upsert_external_result`. Body: `### 🤖 {agent_name} — {status}` + summary (or failure note) + footer `_fluidbox · trigger **{sub}** · run {id} · commit {short_sha}_` (+ "updated for `{sha}`" when updating). Check — POST `/repos/{repo}/check-runs` `{ name: "fluidbox/{sub}", head_sha, status: "completed", conclusion, output: { title: "{agent}: {status}", summary } }`; conclusion map: completed→success, cancelled→cancelled, else failure. Auth: installation token (App-only, #1).

- [x] Implement + comment-body/conclusion-map unit tests; `cargo test --workspace` green. Commit `feat(server): PR comment/check publishers with stable update-in-place identity`.

### Task 10: Dashboard (presentation-only)

**Files:** Modify `apps/web/app/lib/api.ts`, `apps/web/app/connections/page.tsx`, `apps/web/app/triggers/page.tsx`.

- Connections: "GitHub App" create form (app id, installation id, private key PEM textarea, webhook secret) beside the PAT form; App rows show the ingress URL to paste into GitHub webhook settings.
- Triggers: create form gains "fire on repository events" (connection picker, repositories, event checkboxes with synchronize labeled as opt-in cost amplifier, publish modes); event subscriptions show connection/events/repos badges and recent dispatches.
- [x] `cd apps/web && pnpm build` green. Commit `web: github app connections + event trigger subscriptions`.

### Task 11: Acceptance — `scripts/e2e-github.sh` + suite wiring

**Files:** Create `scripts/e2e-github.sh`; modify `scripts/e2e.sh` (insert as phase 6/7 before failure paths — the script owns its stack like `e2e-schedule.sh`).

Skeleton: fake GitHub API (python http.server) implementing `GET /app`, `GET /app/installations/{id}`, `POST /app/installations/{id}/access_tokens`, `GET /installation/repositories`, `POST /repos/{r}/issues/{n}/comments`, `PATCH /repos/{r}/issues/comments/{id}`, `POST /repos/{r}/check-runs` — every request appended to a log file the assertions grep. `file://` fixture repo `acme/site` (main + `pr-1`/`pr-2` branches for head SHAs). Server env: `FLUIDBOX_GITHUB_API_URL=http://127.0.0.1:<port>`, `FLUIDBOX_GITHUB_CLONE_BASE=file://<fixdir>`. Payload signing: `sig=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$WHSEC" | awk '{print $2}')`.

Checks (~55): App connection create (secret sealed, never echoed) → ingress URL; three differently-configured subscriptions (A comment, B check, C comment+check with synchronize opted in); **one signed PR-opened → 3 dispatches, 3 runs, each frozen at the exact head SHA with kind=event context** (assert via `run_spec`); **verbatim retry → duplicate:true, zero new dispatches/runs/comments**; bad signature → 401 + no delivery row; ping + unhandled action → 200 ignored, no row; fork payload → `run_spec.trust_tier == "read_only"` + permission-gate probe (session token via psql like governance-e2e): `Edit` denied source=trust_tier, `Read` allowed; publisher: A's comment POSTed once with agent name + run id; B's check named `fluidbox/<B>` at head SHA; synchronize (new head SHA) → only C fires; C's comment PATCHed in place (no second POST), C gets a second check at the new SHA; `external_results` row count stable; **seam grep**: `events.rs` + `run_service.rs` contain no `github` (case-insensitive); live tier (self-skips): 3 autonomous agents complete a real review of the fixture at the exact SHA and publish 3 attributable comments.

- [x] Write script; run `bash scripts/e2e-github.sh` standalone until green; wire into `e2e.sh` (phases renumbered 7). Commit `test(e2e): github pr-review fan-out acceptance phase`.

### Task 12: Docs + full gates

**Files:** Modify design doc §17 (record #1–#3 settled), `.env.example` (+`FLUIDBOX_GITHUB_CLONE_BASE` comment, github_app connection note), `CLAUDE.md` (invariant bullet for the event spine + env note), `docs/HANDOVER.md` (rev 6: what shipped, rough edges, manual real-GitHub pass instructions).

- [x] `just check` fully green (fmt, clippy -D warnings, workspace tests, web build) — stack stopped, env sourced.
- [x] `just e2e` fully green — all 7 phases.
- [x] Update docs; commit `docs: handover rev 6 — phase 4 shipped (github pr fan-out)`; push.

## Self-Review

- Spec coverage: §6.3 five duties (verify/normalize/workspace = Task 4–5; match = Task 8 generic; publish = Task 9) ✓; §6.4 two-level dedup (Task 3+8) ✓; §7.2 fan-out (Task 8) ✓; §7.3 fork tier (Tasks 2+6, e2e probe) ✓; §7.4 stable results (Task 9) ✓; §12 acceptance (Task 11 mirrors the demo incl. retry-no-dup) ✓; §17 #1–#3 recorded (Task 12) ✓; seam test (Task 11 grep) ✓.
- Type consistency: `NormalizedEvent`/`PublishContext` names match across Tasks 4/8/9; `create_session(trust_tier, bind_dispatch)` matches Tasks 3/6/8.
- No placeholders: schemas, signatures, semantics, and assertions are stated concretely above.
