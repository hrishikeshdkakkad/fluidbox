# Phase 2 — Generic API Borrowing & Signed Result Callbacks — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An external service holding only a scoped trigger token can invoke one registered agent (`POST /v1/triggers/{id}/invoke` with `Idempotency-Key`) and receive one signed terminal callback containing status, summary, artifacts, and cost — with retried invocations creating exactly one run.

**Architecture:** A `trigger_subscriptions` table is the standing "borrow instruction" (design doc §3.5); scoped tokens live in the existing `api_tokens` table under `kind='trigger'`. All entry points (manual UI/CLI via `POST /v1/sessions`, API triggers via invoke) converge on one internal `run_service::create_run` that freezes an `InvocationContext` + `result_destinations` into the RunSpec. On any transition to a terminal state, `result_deliveries` rows are enqueued; an independent retry worker signs (HMAC-SHA256, per-subscription sealed secret) and POSTs the canonical result. A completed run stays completed regardless of callback outcomes.

**Tech Stack:** Rust (axum 0.8, sqlx 0.9, hmac 0.12 — the only new dependency), Neon Postgres (migration 0003), Next.js 16 dashboard, bash e2e phase.

## Global Constraints

- Backend is 100% Rust; the Next.js dashboard is presentation-only (CLAUDE.md hard constraint).
- RunSpec stays immutable & wire-compatible: new fields use `#[serde(default)]` so frozen M1/Phase-1 rows deserialize forever.
- §17 #6 decision (settled with user 2026-07-10): **task and workspace overrides are opt-in per subscription, both default OFF** (`allow_task_override`, `allow_workspace_override`).
- Overrides may only narrow: invoke callers can never supply `connection_id`, `clone_url`, local paths, budgets, or autonomy. Budgets tighten via `Budgets::tightened_by`; autonomy is subscription config gated by the policy's `autonomy.permitted` (same gate as manual runs).
- Callback destinations are pre-registered on the subscription; the invoke body cannot supply a URL (design §6.1 "optional-*approved*-destination", conservative subset).
- Callback signing secrets are AEAD-sealed at rest via the existing `seal::Sealer` (`FLUIDBOX_CREDENTIAL_KEY`); trigger tokens are stored sha256-hashed (verify-only), never sealed. Neither ever appears in an API response after creation, a RunSpec, the ledger, or a sandbox.
- Trigger tokens must NOT authenticate any admin endpoint, and the admin token must not authenticate invoke.
- No connector failure can mutate a session status; `result_deliveries` is independently retryable state.
- The server is the single status writer — the delivery enqueue hook lives inside the one `orchestrator::transition` funnel and only fires on `next.is_terminal()`.
- DB tests are Neon-gated (self-skip without `DATABASE_URL`); run with `set -a; source .env; set +a; cargo test -p fluidbox-db`.
- Quality bar per task: `cargo fmt --all` + `cargo clippy --workspace --all-targets -- -D warnings` + tests green before each commit. Phase bar: `just check` AND `just e2e` fully green (new trigger acceptance phase included).
- Commit style: lowercase area prefixes (`db:`, `core:`, `server:`, `web:`, `test(e2e):`, `docs:`), commit after every task.

---

### Task 1: Core invocation types frozen into the RunSpec

**Files:**
- Modify: `crates/fluidbox-core/src/spec.rs` (imports at top; new types after `TrustTier`; two new `RunSpec` fields; tests at bottom)
- Modify: `crates/fluidbox-core/src/lib.rs:16` (re-exports)

**Interfaces:**
- Produces: `InvocationKind` (Manual|Api|Schedule|Event, snake_case, Default=Manual), `InvocationContext { kind, subscription_id: Option<Uuid>, actor: Option<String>, attributes: Value, received_at: Option<DateTime<Utc>> }` (Default = manual/None/Null/None), `ResultDestination::SignedWebhook { url: String }` (tag="kind", snake_case), `RunSpec.invocation: InvocationContext` + `RunSpec.result_destinations: Vec<ResultDestination>` (both `#[serde(default)]`).

- [ ] **Step 1: Write the failing tests** (append inside `mod tests` in `spec.rs`)

```rust
    #[test]
    fn run_spec_without_invocation_defaults_to_manual() {
        // Every frozen M1/Phase-1 RunSpec lacks these fields — they must
        // deserialize forever, defaulting to a manual invocation.
        let old = serde_json::json!({
            "agent_id": Uuid::now_v7(), "agent_revision_id": Uuid::now_v7(),
            "agent_name": "a", "harness": "claude-agent-sdk", "runner_image": "img",
            "model": "m", "system_prompt": null, "task": "t",
            "workspace": {"kind": "scratch"},
            "autonomy": "supervised", "trust_tier": "trusted",
            "budgets": {"max_wall_clock_secs": 1, "max_tokens": 1, "max_cost_usd": 1.0, "max_tool_calls": 1},
            "policy_id": Uuid::now_v7(), "policy_version": 1,
            "policy_snapshot": {"name": "p"}
        });
        let spec: RunSpec = serde_json::from_value(old).unwrap();
        assert_eq!(spec.invocation.kind, InvocationKind::Manual);
        assert!(spec.invocation.subscription_id.is_none());
        assert!(spec.result_destinations.is_empty());
    }

    #[test]
    fn invocation_context_roundtrips_api_kind() {
        let sub = Uuid::now_v7();
        let ctx = InvocationContext {
            kind: InvocationKind::Api,
            subscription_id: Some(sub),
            actor: Some("trigger:nightly".into()),
            attributes: serde_json::json!({"context": {"ticket": "INC-42"}}),
            received_at: Some(chrono::Utc::now()),
        };
        let v = serde_json::to_value(&ctx).unwrap();
        assert_eq!(v["kind"], "api");
        let back: InvocationContext = serde_json::from_value(v).unwrap();
        assert_eq!(back.subscription_id, Some(sub));
    }

    #[test]
    fn result_destination_wire_shape() {
        let d = ResultDestination::SignedWebhook { url: "https://x.test/cb".into() };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v, serde_json::json!({"kind": "signed_webhook", "url": "https://x.test/cb"}));
        let back: ResultDestination = serde_json::from_value(v).unwrap();
        assert_eq!(back, d);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p fluidbox-core spec::`
Expected: FAIL to compile — `InvocationKind`, `InvocationContext`, `ResultDestination` not found.

- [ ] **Step 3: Implement the types**

At the top of `spec.rs`, extend imports:

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
```

After the `TrustTier` block, add:

```rust
/// Why a run exists (design doc §3.4) — the provider-neutral envelope frozen
/// into the RunSpec and stored on `sessions.trigger`. Phase 2 uses
/// `manual` and `api`; `schedule`/`event` arrive with later phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InvocationKind {
    #[default]
    Manual,
    Api,
    Schedule,
    Event,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvocationContext {
    pub kind: InvocationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<Uuid>,
    /// Human-attributable origin, e.g. "trigger:<subscription name>".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Caller-supplied structured context (untrusted external text — it is
    /// context, never system instruction).
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub attributes: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<DateTime<Utc>>,
}

impl Default for InvocationContext {
    /// The default an old frozen RunSpec deserializes to: a manual run.
    fn default() -> Self {
        Self {
            kind: InvocationKind::Manual,
            subscription_id: None,
            actor: None,
            attributes: Value::Null,
            received_at: None,
        }
    }
}

/// Where a run's canonical result is published (design doc §3.7). The run's
/// artifacts and ledger stay in fluidbox either way; publication is
/// asynchronous and independently retryable. Secrets are NOT part of the
/// destination — the signing secret stays sealed on the subscription.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResultDestination {
    SignedWebhook { url: String },
}
```

In `RunSpec`, after `policy_snapshot`, add:

```rust
    /// Why this run exists. `#[serde(default)]` keeps every pre-Phase-2
    /// frozen RunSpec deserializable (defaults to a manual invocation).
    #[serde(default)]
    pub invocation: InvocationContext,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_destinations: Vec<ResultDestination>,
```

In `lib.rs`, extend the spec re-export:

```rust
pub use spec::{Autonomy, Budgets, InvocationContext, InvocationKind, ResultDestination, RunSpec, TrustTier};
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fluidbox-core`
Expected: PASS (all existing + 3 new).

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/fluidbox-core
git commit -m "core: InvocationContext + ResultDestination frozen into the RunSpec"
```

---

### Task 2: Migration 0003 + subscription/token repositories

**Files:**
- Create: `migrations/0003_triggers.sql`
- Modify: `crates/fluidbox-db/src/lib.rs` (new row structs after `IntegrationConnectionRow`; new section after "Integration connections"; token fns near the existing Tokens section; tests at bottom)

**Interfaces:**
- Produces: `TriggerSubscriptionRow` (serializable, NO secret field), `create_trigger_subscription(pool, tenant, agent_id, name, trigger_kind, pinned_revision_id, task_template, allow_task_override, allow_workspace_override, autonomy, budget_override, workspace_override, result_destinations, callback_secret_sealed) -> TriggerSubscriptionRow`, `list_trigger_subscriptions(pool, tenant)`, `get_trigger_subscription(pool, id)`, `set_trigger_subscription_enabled(pool, id, enabled) -> Option<Row>`, `subscription_callback_secret_sealed(pool, id) -> Option<Vec<u8>>`, `create_trigger_token(pool, tenant, subscription, token_plain)`, `subscription_for_token(pool, token_plain) -> Option<Uuid>`, `revoke_trigger_tokens(pool, subscription) -> u64`.

- [ ] **Step 1: Write the migration** — `migrations/0003_triggers.sql`:

```sql
-- Phase 2 of "borrow the agent, on demand": generic API borrowing.
-- (docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md §3.5/§6.1/§9/§10)

-- A subscription is the standing instruction that says when an agent may be
-- borrowed. It may only narrow the agent/policy authority — never widen it.
-- §17 #6 (settled 2026-07-10): caller task/workspace overrides are opt-in
-- per subscription and default OFF.
create table trigger_subscriptions (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    agent_id uuid not null references agents(id),
    name text not null,
    trigger_kind text not null default 'api',   -- api (schedule/event later)
    pinned_revision_id uuid references agent_revisions(id), -- null = latest
    enabled boolean not null default true,
    task_template text,                          -- {{key}} ← invoke context
    allow_task_override boolean not null default false,
    allow_workspace_override boolean not null default false,
    autonomy text,                               -- null = supervised
    budget_override jsonb,                       -- tightens; never widens
    workspace_override jsonb,                    -- WorkspaceSpec
    result_destinations jsonb not null default '[]',
    -- AEAD-sealed HMAC secret for signed_webhook destinations (seal.rs).
    -- Never selected by row queries; never returned after creation.
    callback_secret_sealed bytea,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, name)
);
create index trigger_subscriptions_tenant on trigger_subscriptions(tenant_id);

-- One row per invoke (a generated key when the caller omits Idempotency-Key).
-- unique(subscription_id, idempotency_key) is what makes retries create
-- exactly one run.
create table trigger_invocations (
    id uuid primary key,
    subscription_id uuid not null references trigger_subscriptions(id) on delete cascade,
    idempotency_key text not null,
    request_digest text not null,
    session_id uuid references sessions(id) on delete cascade,
    created_at timestamptz not null default now(),
    unique (subscription_id, idempotency_key)
);
create index trigger_invocations_session on trigger_invocations(session_id);

-- Result publication state — independent of the session lifecycle by
-- construction (design §9): a completed run stays completed even when its
-- callback fails forever.
create table result_deliveries (
    id uuid primary key,
    session_id uuid not null references sessions(id) on delete cascade,
    subscription_id uuid references trigger_subscriptions(id) on delete cascade,
    destination jsonb not null,                  -- ResultDestination
    status text not null default 'pending',      -- pending|delivered|failed
    attempts int not null default 0,
    next_attempt_at timestamptz not null default now(),
    last_error text,
    payload_digest text,
    delivered_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index result_deliveries_due on result_deliveries(next_attempt_at) where status = 'pending';
create index result_deliveries_session on result_deliveries(session_id);
create index result_deliveries_subscription on result_deliveries(subscription_id);

-- Scoped trigger tokens ride the existing api_tokens table (kind='trigger').
alter table api_tokens add column subscription_id uuid references trigger_subscriptions(id) on delete cascade;
create index api_tokens_subscription on api_tokens(subscription_id);
```

- [ ] **Step 2: Write the failing DB test** (append in `mod tests` of `fluidbox-db/src/lib.rs`)

```rust
    #[tokio::test]
    async fn trigger_subscription_lifecycle_token_and_secret_isolation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let policy = upsert_policy(&pool, tenant, "test-trig", "name: test-trig",
            &serde_json::json!({"name": "test-trig"})).await.unwrap();
        let agent = create_agent(&pool, tenant, "test-trig-agent", None).await.unwrap();
        let _rev = append_agent_revision(&pool, agent.id, "claude-agent-sdk", "img:test",
            "claude-haiku-4-5", None, policy.id, &serde_json::json!({}), None).await.unwrap();

        let sealed = b"nonce||not-a-real-secret".to_vec();
        let sub = create_trigger_subscription(
            &pool, tenant, agent.id, "test-sub", "api", None,
            Some("Investigate {{ticket}}"), false, false, None, None, None,
            &serde_json::json!([{"kind": "signed_webhook", "url": "http://127.0.0.1:1/cb"}]),
            Some(&sealed),
        ).await.unwrap();
        assert!(sub.enabled);
        assert!(!sub.allow_task_override);

        // Row serialization can never leak the sealed secret.
        let as_json = serde_json::to_value(&sub).unwrap();
        assert!(as_json.get("callback_secret_sealed").is_none());

        // The single secret reader returns the sealed bytes.
        let got = subscription_callback_secret_sealed(&pool, sub.id).await.unwrap();
        assert_eq!(got, Some(sealed));

        // Trigger tokens: hashed at rest, resolvable, revocable.
        create_trigger_token(&pool, tenant, sub.id, "fbx_trig_testtoken123").await.unwrap();
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_testtoken123").await.unwrap(),
            Some(sub.id)
        );
        assert_eq!(subscription_for_token(&pool, "fbx_trig_wrong").await.unwrap(), None);
        let revoked = revoke_trigger_tokens(&pool, sub.id).await.unwrap();
        assert_eq!(revoked, 1);
        assert_eq!(subscription_for_token(&pool, "fbx_trig_testtoken123").await.unwrap(), None);

        // Enable toggle.
        let off = set_trigger_subscription_enabled(&pool, sub.id, false).await.unwrap().unwrap();
        assert!(!off.enabled);

        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id).execute(&pool).await.unwrap();
    }
```

- [ ] **Step 3: Run to verify failure**

Run: `set -a; source .env; set +a; cargo test -p fluidbox-db trigger_subscription`
Expected: FAIL to compile — functions not defined.

- [ ] **Step 4: Implement rows + queries**

Row struct (after `IntegrationConnectionRow`; same "no credential field, explicit column lists" doctrine):

```rust
/// Deliberately has NO callback-secret field — every query selects explicit
/// columns so the sealed secret can never ride into an API response.
/// `subscription_callback_secret_sealed` is the only reader.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TriggerSubscriptionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub name: String,
    pub trigger_kind: String,
    pub pinned_revision_id: Option<Uuid>,
    pub enabled: bool,
    pub task_template: Option<String>,
    pub allow_task_override: bool,
    pub allow_workspace_override: bool,
    pub autonomy: Option<String>,
    pub budget_override: Option<Value>,
    pub workspace_override: Option<Value>,
    pub result_destinations: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

Shared column list (define once above the queries):

```rust
const SUBSCRIPTION_COLS: &str = "id, tenant_id, agent_id, name, trigger_kind, pinned_revision_id, \
     enabled, task_template, allow_task_override, allow_workspace_override, autonomy, \
     budget_override, workspace_override, result_destinations, created_at, updated_at";
```

Queries (new section `// ─── Trigger subscriptions ───…`):

```rust
#[allow(clippy::too_many_arguments)]
pub async fn create_trigger_subscription(
    pool: &PgPool,
    tenant: Uuid,
    agent_id: Uuid,
    name: &str,
    trigger_kind: &str,
    pinned_revision_id: Option<Uuid>,
    task_template: Option<&str>,
    allow_task_override: bool,
    allow_workspace_override: bool,
    autonomy: Option<&str>,
    budget_override: Option<&Value>,
    workspace_override: Option<&Value>,
    result_destinations: &Value,
    callback_secret_sealed: Option<&[u8]>,
) -> sqlx::Result<TriggerSubscriptionRow> {
    sqlx::query_as(&format!(
        "insert into trigger_subscriptions
           (id, tenant_id, agent_id, name, trigger_kind, pinned_revision_id, task_template,
            allow_task_override, allow_workspace_override, autonomy, budget_override,
            workspace_override, result_destinations, callback_secret_sealed)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         returning {SUBSCRIPTION_COLS}"
    ))
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(agent_id)
    .bind(name)
    .bind(trigger_kind)
    .bind(pinned_revision_id)
    .bind(task_template)
    .bind(allow_task_override)
    .bind(allow_workspace_override)
    .bind(autonomy)
    .bind(budget_override)
    .bind(workspace_override)
    .bind(result_destinations)
    .bind(callback_secret_sealed)
    .fetch_one(pool)
    .await
}

pub async fn list_trigger_subscriptions(
    pool: &PgPool,
    tenant: Uuid,
) -> sqlx::Result<Vec<TriggerSubscriptionRow>> {
    sqlx::query_as(&format!(
        "select {SUBSCRIPTION_COLS} from trigger_subscriptions
         where tenant_id = $1 order by created_at desc"
    ))
    .bind(tenant)
    .fetch_all(pool)
    .await
}

pub async fn get_trigger_subscription(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<TriggerSubscriptionRow>> {
    sqlx::query_as(&format!(
        "select {SUBSCRIPTION_COLS} from trigger_subscriptions where id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn set_trigger_subscription_enabled(
    pool: &PgPool,
    id: Uuid,
    enabled: bool,
) -> sqlx::Result<Option<TriggerSubscriptionRow>> {
    sqlx::query_as(&format!(
        "update trigger_subscriptions set enabled = $2, updated_at = now()
         where id = $1 returning {SUBSCRIPTION_COLS}"
    ))
    .bind(id)
    .bind(enabled)
    .fetch_optional(pool)
    .await
}

/// The only reader of the sealed callback secret. Deliveries for in-flight
/// runs must still sign after a disable, so this does not require `enabled`.
pub async fn subscription_callback_secret_sealed(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<Vec<u8>>> {
    let row = sqlx::query(
        "select callback_secret_sealed from trigger_subscriptions where id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.get::<Option<Vec<u8>>, _>("callback_secret_sealed")))
}
```

Token fns (in the existing `// ─── Tokens ───` section, mirroring session tokens; trigger tokens have no expiry — revocation is their lifecycle):

```rust
pub async fn create_trigger_token(
    pool: &PgPool,
    tenant: Uuid,
    subscription: Uuid,
    token_plain: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "insert into api_tokens (id, tenant_id, kind, subscription_id, token_sha256)
         values ($1, $2, 'trigger', $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(subscription)
    .bind(sha256_hex(token_plain))
    .execute(pool)
    .await?;
    Ok(())
}

/// Resolves a scoped trigger token to its subscription. This is the entire
/// authority of the token — it can never satisfy Admin or SessionAuth.
pub async fn subscription_for_token(
    pool: &PgPool,
    token_plain: &str,
) -> sqlx::Result<Option<Uuid>> {
    let row = sqlx::query(
        "select subscription_id from api_tokens
         where kind = 'trigger' and token_sha256 = $1
           and revoked_at is null
           and (expires_at is null or expires_at > now())",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.get::<Option<Uuid>, _>("subscription_id")))
}

/// Rotation support: kill every live token for the subscription.
pub async fn revoke_trigger_tokens(pool: &PgPool, subscription: Uuid) -> sqlx::Result<u64> {
    let res = sqlx::query(
        "update api_tokens set revoked_at = now()
         where kind = 'trigger' and subscription_id = $1 and revoked_at is null",
    )
    .bind(subscription)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
```

- [ ] **Step 5: Run to verify pass**

Run: `set -a; source .env; set +a; cargo test -p fluidbox-db trigger_subscription`
Expected: PASS (migration 0003 auto-applies on `connect`).

- [ ] **Step 6: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add migrations/0003_triggers.sql crates/fluidbox-db
git commit -m "db: trigger subscriptions + scoped trigger tokens (migration 0003)"
```

---

### Task 3: Idempotency claims, delivery queue, sessions.trigger plumbing

**Files:**
- Modify: `crates/fluidbox-db/src/lib.rs` (SessionRow field; `create_session` 10th param; new sections; update the two test call sites of `create_session`; tests)

**Interfaces:**
- Consumes: `trigger_invocations` / `result_deliveries` tables (Task 2).
- Produces: `SessionRow.trigger: Option<Value>`; `create_session(..., trigger: Option<&Value>)`; `InvocationClaim { Claimed{invocation_id}, Replay{session_id, request_digest}, InFlight }`; `claim_invocation(pool, subscription, key, digest) -> InvocationClaim`; `bind_invocation(pool, invocation_id, session_id)`; `release_invocation(pool, invocation_id)`; `list_subscription_sessions(pool, subscription, limit) -> Vec<SessionRow>`; `subscription_owns_session(pool, subscription, session) -> bool`; `ResultDeliveryRow`; `enqueue_result_delivery(pool, session, subscription, destination) -> ResultDeliveryRow`; `due_result_deliveries(pool, limit)`; `mark_delivery_attempt(pool, id, ok, error, payload_digest, retry_in_secs, max_attempts) -> Option<ResultDeliveryRow>`; `list_session_deliveries(pool, session)`; `list_subscription_deliveries(pool, subscription, limit)`.

- [ ] **Step 1: Write the failing tests** (append in `mod tests`)

```rust
    #[tokio::test]
    async fn invocation_claims_are_idempotent_by_key() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let policy = upsert_policy(&pool, tenant, "test-idem", "name: test-idem",
            &serde_json::json!({"name": "test-idem"})).await.unwrap();
        let agent = create_agent(&pool, tenant, "test-idem-agent", None).await.unwrap();
        let rev = append_agent_revision(&pool, agent.id, "claude-agent-sdk", "img:test",
            "claude-haiku-4-5", None, policy.id, &serde_json::json!({}), None).await.unwrap();
        let sub = create_trigger_subscription(&pool, tenant, agent.id, "test-idem-sub", "api",
            None, Some("t"), false, false, None, None, None,
            &serde_json::json!([]), None).await.unwrap();

        // First claim wins.
        let c1 = claim_invocation(&pool, sub.id, "key-1", "digest-a").await.unwrap();
        let InvocationClaim::Claimed { invocation_id } = c1 else { panic!("wanted Claimed, got {c1:?}") };

        // Same key while unbound → InFlight (a concurrent retry must wait).
        assert!(matches!(
            claim_invocation(&pool, sub.id, "key-1", "digest-a").await.unwrap(),
            InvocationClaim::InFlight
        ));

        // Bind to a real session, then the same key replays that session.
        let session = create_session(&pool, tenant, agent.id, rev.id, "supervised", "t",
            &serde_json::json!({"kind":"scratch"}), &serde_json::json!({}),
            &serde_json::json!({}), Some(&serde_json::json!({"kind":"api"}))).await.unwrap();
        assert_eq!(session.trigger, Some(serde_json::json!({"kind":"api"})));
        bind_invocation(&pool, invocation_id, session.id).await.unwrap();
        let c3 = claim_invocation(&pool, sub.id, "key-1", "digest-a").await.unwrap();
        match c3 {
            InvocationClaim::Replay { session_id, request_digest } => {
                assert_eq!(session_id, session.id);
                assert_eq!(request_digest, "digest-a");
            }
            other => panic!("wanted Replay, got {other:?}"),
        }

        // A released (failed-creation) claim frees the key immediately.
        let c4 = claim_invocation(&pool, sub.id, "key-2", "digest-b").await.unwrap();
        let InvocationClaim::Claimed { invocation_id: inv2 } = c4 else { panic!() };
        release_invocation(&pool, inv2).await.unwrap();
        assert!(matches!(
            claim_invocation(&pool, sub.id, "key-2", "digest-b").await.unwrap(),
            InvocationClaim::Claimed { .. }
        ));

        assert!(subscription_owns_session(&pool, sub.id, session.id).await.unwrap());
        let listed = list_subscription_sessions(&pool, sub.id, 10).await.unwrap();
        assert!(listed.iter().any(|s| s.id == session.id));

        sqlx::query("delete from sessions where id = $1").bind(session.id).execute(&pool).await.unwrap();
        sqlx::query("delete from trigger_subscriptions where id = $1").bind(sub.id).execute(&pool).await.unwrap();
    }

    #[tokio::test]
    async fn result_delivery_attempt_state_machine() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let policy = upsert_policy(&pool, tenant, "test-del", "name: test-del",
            &serde_json::json!({"name": "test-del"})).await.unwrap();
        let agent = create_agent(&pool, tenant, "test-del-agent", None).await.unwrap();
        let rev = append_agent_revision(&pool, agent.id, "claude-agent-sdk", "img:test",
            "claude-haiku-4-5", None, policy.id, &serde_json::json!({}), None).await.unwrap();
        let session = create_session(&pool, tenant, agent.id, rev.id, "supervised", "t",
            &serde_json::json!({"kind":"scratch"}), &serde_json::json!({}),
            &serde_json::json!({}), None).await.unwrap();

        let dest = serde_json::json!({"kind": "signed_webhook", "url": "http://127.0.0.1:1/cb"});
        let d = enqueue_result_delivery(&pool, session.id, None, &dest).await.unwrap();
        assert_eq!(d.status, "pending");
        assert_eq!(d.attempts, 0);

        // Due immediately.
        let due = due_result_deliveries(&pool, 10).await.unwrap();
        assert!(due.iter().any(|x| x.id == d.id));

        // Failure → still pending, attempts=1, pushed into the future (not due).
        let after = mark_delivery_attempt(&pool, d.id, false, Some("connection refused"), None, 30, 3)
            .await.unwrap().unwrap();
        assert_eq!((after.status.as_str(), after.attempts), ("pending", 1));
        assert!(!due_result_deliveries(&pool, 50).await.unwrap().iter().any(|x| x.id == d.id));

        // Exhausting attempts → failed, terminal for the delivery only.
        mark_delivery_attempt(&pool, d.id, false, Some("refused"), None, 30, 3).await.unwrap();
        let last = mark_delivery_attempt(&pool, d.id, false, Some("refused"), None, 30, 3)
            .await.unwrap().unwrap();
        assert_eq!((last.status.as_str(), last.attempts), ("failed", 3));

        // Success path on a second delivery.
        let d2 = enqueue_result_delivery(&pool, session.id, None, &dest).await.unwrap();
        let okd = mark_delivery_attempt(&pool, d2.id, true, None, Some("sha256:x"), 0, 3)
            .await.unwrap().unwrap();
        assert_eq!(okd.status, "delivered");
        assert!(okd.delivered_at.is_some());
        assert_eq!(okd.payload_digest.as_deref(), Some("sha256:x"));

        let listed = list_session_deliveries(&pool, session.id).await.unwrap();
        assert_eq!(listed.len(), 2);

        sqlx::query("delete from sessions where id = $1").bind(session.id).execute(&pool).await.unwrap();
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `set -a; source .env; set +a; cargo test -p fluidbox-db invocation_claims result_delivery`
Expected: FAIL to compile.

- [ ] **Step 3: Implement**

`SessionRow`: add after `run_spec`:

```rust
    /// InvocationContext envelope (design §3.4). Null for pre-Phase-2 rows.
    pub trigger: Option<Value>,
```

`create_session`: add a `trigger: Option<&Value>` parameter (last), bind as `$10`:

```rust
#[allow(clippy::too_many_arguments)]
pub async fn create_session(
    pool: &PgPool,
    tenant: Uuid,
    agent_id: Uuid,
    agent_revision_id: Uuid,
    autonomy: &str,
    task: &str,
    repo_source: &Value,
    run_spec: &Value,
    budgets: &Value,
    trigger: Option<&Value>,
) -> sqlx::Result<SessionRow> {
    sqlx::query_as(
        "insert into sessions
           (id, tenant_id, agent_id, agent_revision_id, autonomy, task, repo_source, run_spec, budgets, trigger)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(agent_id)
    .bind(agent_revision_id)
    .bind(autonomy)
    .bind(task)
    .bind(repo_source)
    .bind(run_spec)
    .bind(budgets)
    .bind(trigger)
    .fetch_one(pool)
    .await
}
```

Update the two existing test call sites (`append_event_assigns_gapless_seq_and_notifies`, `stale_nonstarted_sweep_finds_only_old_prelaunch_sessions` — 3 calls total) to pass `None` as the new final argument.

New section `// ─── Trigger invocations (Idempotency-Key) ───…`:

```rust
#[derive(Debug)]
pub enum InvocationClaim {
    /// We own this key — create the run, then `bind_invocation`.
    Claimed { invocation_id: Uuid },
    /// This key already produced a run — return it (after digest check).
    Replay { session_id: Uuid, request_digest: String },
    /// Another request holds the key mid-creation — caller should 409.
    InFlight,
}

/// Claim an idempotency key. Exactly one concurrent caller wins the insert;
/// a claim whose creation crashed (bound to no session) becomes re-claimable
/// after 60s so a dangling row can't wedge the key forever.
pub async fn claim_invocation(
    pool: &PgPool,
    subscription: Uuid,
    idempotency_key: &str,
    request_digest: &str,
) -> sqlx::Result<InvocationClaim> {
    let inserted = sqlx::query(
        "insert into trigger_invocations (id, subscription_id, idempotency_key, request_digest)
         values ($1, $2, $3, $4)
         on conflict (subscription_id, idempotency_key) do nothing
         returning id",
    )
    .bind(Uuid::now_v7())
    .bind(subscription)
    .bind(idempotency_key)
    .bind(request_digest)
    .fetch_optional(pool)
    .await?;
    if let Some(row) = inserted {
        return Ok(InvocationClaim::Claimed { invocation_id: row.get("id") });
    }
    let existing = sqlx::query(
        "select id, session_id, request_digest, created_at from trigger_invocations
         where subscription_id = $1 and idempotency_key = $2",
    )
    .bind(subscription)
    .bind(idempotency_key)
    .fetch_one(pool)
    .await?;
    if let Some(session_id) = existing.get::<Option<Uuid>, _>("session_id") {
        return Ok(InvocationClaim::Replay {
            session_id,
            request_digest: existing.get("request_digest"),
        });
    }
    // Unbound claim: take it over only once it is stale (crashed creator).
    let takeover = sqlx::query(
        "update trigger_invocations
            set created_at = now(), request_digest = $3
          where subscription_id = $1 and idempotency_key = $2
            and session_id is null and created_at < now() - interval '60 seconds'
          returning id",
    )
    .bind(subscription)
    .bind(idempotency_key)
    .bind(request_digest)
    .fetch_optional(pool)
    .await?;
    Ok(match takeover {
        Some(row) => InvocationClaim::Claimed { invocation_id: row.get("id") },
        None => InvocationClaim::InFlight,
    })
}

pub async fn bind_invocation(pool: &PgPool, invocation: Uuid, session: Uuid) -> sqlx::Result<()> {
    sqlx::query("update trigger_invocations set session_id = $2 where id = $1")
        .bind(invocation)
        .bind(session)
        .execute(pool)
        .await?;
    Ok(())
}

/// Free a claim whose run creation failed, so an immediate retry can re-try.
pub async fn release_invocation(pool: &PgPool, invocation: Uuid) -> sqlx::Result<()> {
    sqlx::query("delete from trigger_invocations where id = $1 and session_id is null")
        .bind(invocation)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_subscription_sessions(
    pool: &PgPool,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<SessionRow>> {
    sqlx::query_as(
        "select s.* from sessions s
         join trigger_invocations i on i.session_id = s.id
         where i.subscription_id = $1
         order by s.created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Scopes the trigger-token polling endpoint to runs this subscription made.
pub async fn subscription_owns_session(
    pool: &PgPool,
    subscription: Uuid,
    session: Uuid,
) -> sqlx::Result<bool> {
    let row = sqlx::query(
        "select exists(
           select 1 from trigger_invocations
           where subscription_id = $1 and session_id = $2
         ) as owned",
    )
    .bind(subscription)
    .bind(session)
    .fetch_one(pool)
    .await?;
    Ok(row.get::<bool, _>("owned"))
}
```

New section `// ─── Result deliveries ───…`:

```rust
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ResultDeliveryRow {
    pub id: Uuid,
    pub session_id: Uuid,
    pub subscription_id: Option<Uuid>,
    pub destination: Value,
    pub status: String,
    pub attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub payload_digest: Option<String>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn enqueue_result_delivery(
    pool: &PgPool,
    session: Uuid,
    subscription: Option<Uuid>,
    destination: &Value,
) -> sqlx::Result<ResultDeliveryRow> {
    sqlx::query_as(
        "insert into result_deliveries (id, session_id, subscription_id, destination)
         values ($1, $2, $3, $4) returning *",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(subscription)
    .bind(destination)
    .fetch_one(pool)
    .await
}

/// Due work for the (single, sequential) delivery worker. No row locking:
/// there is one worker task per server and attempts are awaited one at a
/// time, so a row can never be attempted twice concurrently. Delivery is
/// at-least-once by design — receivers dedup on the delivery id.
pub async fn due_result_deliveries(
    pool: &PgPool,
    limit: i64,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    sqlx::query_as(
        "select * from result_deliveries
         where status = 'pending' and next_attempt_at <= now()
         order by next_attempt_at limit $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Record one attempt. ok → delivered; failure → attempts+1 and either
/// rescheduled (`retry_in_secs`) or terminally 'failed' at `max_attempts`.
pub async fn mark_delivery_attempt(
    pool: &PgPool,
    id: Uuid,
    ok: bool,
    error: Option<&str>,
    payload_digest: Option<&str>,
    retry_in_secs: i64,
    max_attempts: i32,
) -> sqlx::Result<Option<ResultDeliveryRow>> {
    sqlx::query_as(
        "update result_deliveries set
            attempts = attempts + 1,
            status = case when $2 then 'delivered'
                          when attempts + 1 >= $6 then 'failed'
                          else 'pending' end,
            delivered_at = case when $2 then now() else delivered_at end,
            last_error = $3,
            payload_digest = coalesce($4, payload_digest),
            next_attempt_at = now() + make_interval(secs => $5),
            updated_at = now()
         where id = $1 returning *",
    )
    .bind(id)
    .bind(ok)
    .bind(error)
    .bind(payload_digest)
    .bind(retry_in_secs as f64)
    .bind(max_attempts)
    .fetch_optional(pool)
    .await
}

pub async fn list_session_deliveries(
    pool: &PgPool,
    session: Uuid,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    sqlx::query_as("select * from result_deliveries where session_id = $1 order by created_at")
        .bind(session)
        .fetch_all(pool)
        .await
}

pub async fn list_subscription_deliveries(
    pool: &PgPool,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    sqlx::query_as(
        "select * from result_deliveries where subscription_id = $1
         order by created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .fetch_all(pool)
    .await
}
```

Also fix the api.rs call site of `create_session` (add `None` for now — Task 4 replaces the whole call path; adding `None` here keeps the workspace compiling between commits).

- [ ] **Step 4: Run to verify pass**

Run: `set -a; source .env; set +a; cargo test -p fluidbox-db && cargo build --workspace`
Expected: PASS; whole workspace still compiles.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/fluidbox-db crates/fluidbox-server
git commit -m "db: invocation idempotency claims + result delivery queue; sessions.trigger plumbed"
```

---

### Task 4: Unified `run_service::create_run`; manual API converges on it

**Files:**
- Create: `crates/fluidbox-server/src/run_service.rs`
- Modify: `crates/fluidbox-server/src/api.rs` (make `resolve_workspace_input` + `valid_repo_name` `pub(crate)`; shrink `create_session`)
- Modify: `crates/fluidbox-server/src/main.rs:1-14` (add `mod run_service;`)

**Interfaces:**
- Consumes: `fluidbox_core::spec::{InvocationContext, ResultDestination}` (Task 1), `fluidbox_db::create_session` 10-param (Task 3).
- Produces: `run_service::RevisionSelector { Latest, Pinned(Uuid) }`, `run_service::CreateRun { agent: String, revision: RevisionSelector, task: String, explicit_workspace: Option<WorkspaceSpec>, autonomy: Autonomy, budget_override: Option<Budgets>, invocation: InvocationContext, result_destinations: Vec<ResultDestination> }`, `run_service::create_run(state: &AppState, req: CreateRun) -> ApiResult<fluidbox_db::SessionRow>`.

- [ ] **Step 1: Write `run_service.rs`** (this is a refactor-by-extraction of `api.rs::create_session` lines 393-525 — behavior must be identical for manual runs; the diff-visible novelty is revision pinning, invocation freezing, and destinations):

```rust
//! The one internal run-creation service (design doc §4). Every entry point
//! — manual UI/CLI (`POST /v1/sessions`), API triggers, and later schedules
//! and events — converges here. It resolves and freezes: the immutable
//! agent revision, the effective workspace, autonomy, tightened budgets,
//! the invocation context, and the result destinations. An invocation may
//! narrow the agent's authority; nothing here can widen it.

use crate::error::{ApiError, ApiResult};
use crate::orchestrator;
use crate::state::AppState;
use fluidbox_core::policy::Policy;
use fluidbox_core::spec::{
    Autonomy, Budgets, InvocationContext, ResultDestination, RunSpec, TrustTier, WorkspaceSpec,
};
use uuid::Uuid;

pub enum RevisionSelector {
    /// The agent's current (latest) revision — what manual runs use today.
    Latest,
    /// A subscription-pinned revision; must belong to the agent.
    Pinned(Uuid),
}

pub struct CreateRun {
    /// Agent id or name.
    pub agent: String,
    pub revision: RevisionSelector,
    pub task: String,
    /// Validated workspace the invocation supplies explicitly (precedence:
    /// explicit > revision default > scratch). Callers validate their own
    /// inputs (admin API: resolve_workspace_input; triggers: narrowing).
    pub explicit_workspace: Option<WorkspaceSpec>,
    pub autonomy: Autonomy,
    pub budget_override: Option<Budgets>,
    pub invocation: InvocationContext,
    pub result_destinations: Vec<ResultDestination>,
}

pub async fn create_run(state: &AppState, req: CreateRun) -> ApiResult<fluidbox_db::SessionRow> {
    // Resolve agent by id or name.
    let agent = match Uuid::parse_str(&req.agent) {
        Ok(id) => fluidbox_db::get_agent(&state.pool, id).await?,
        Err(_) => fluidbox_db::get_agent_by_name(&state.pool, state.tenant_id, &req.agent).await?,
    }
    .filter(|a| a.tenant_id == state.tenant_id)
    .ok_or_else(|| ApiError::BadRequest(format!("unknown agent '{}'", req.agent)))?;

    let rev = match req.revision {
        RevisionSelector::Latest => fluidbox_db::latest_revision(&state.pool, agent.id)
            .await?
            .ok_or_else(|| ApiError::BadRequest("agent has no revisions".into()))?,
        RevisionSelector::Pinned(id) => fluidbox_db::get_revision(&state.pool, id)
            .await?
            .filter(|r| r.agent_id == agent.id)
            .ok_or_else(|| {
                ApiError::BadRequest(format!("revision {id} does not belong to agent '{}'", agent.name))
            })?,
    };
    let policy_row = fluidbox_db::get_policy(&state.pool, rev.policy_id)
        .await?
        .ok_or_else(|| ApiError::Internal("revision policy missing".into()))?;
    let policy: Policy = serde_json::from_value(policy_row.parsed.clone())
        .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;

    // Autonomy permission gate: a policy may forbid autonomous runs.
    if req.autonomy == Autonomy::Autonomous && !policy.autonomy.permitted {
        return Err(ApiError::BadRequest(
            "policy does not permit autonomous runs".into(),
        ));
    }

    let agent_budgets: Budgets = serde_json::from_value(rev.budgets.clone()).unwrap_or_default();
    // The policy's budgets are a ceiling: revision defaults and per-run
    // requests may only tighten below them, never widen past them.
    let ceiling = agent_budgets.tightened_by(&policy.budgets);
    let effective_budgets = match &req.budget_override {
        Some(b) => ceiling.tightened_by(b),
        None => ceiling,
    };

    // Workspace precedence (design §3.3): explicit > revision default > scratch.
    let revision_default: Option<WorkspaceSpec> = rev
        .default_workspace
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| ApiError::Internal(format!("bad stored default workspace: {e}")))?;
    let workspace = WorkspaceSpec::resolve(req.explicit_workspace, revision_default);

    // A connection-backed workspace must still be usable at run time.
    if let WorkspaceSpec::GitRepository {
        connection_id: Some(cid),
        ..
    } = &workspace
    {
        let active = fluidbox_db::get_connection(&state.pool, *cid)
            .await?
            .filter(|c| c.tenant_id == state.tenant_id)
            .map(|c| c.status == "active")
            .unwrap_or(false);
        if !active {
            return Err(ApiError::BadRequest(format!(
                "workspace connection {cid} is not active — reconnect it or override the workspace"
            )));
        }
    }

    let run_spec = RunSpec {
        agent_id: agent.id,
        agent_revision_id: rev.id,
        agent_name: agent.name.clone(),
        harness: rev.harness.clone(),
        runner_image: rev.runner_image.clone(),
        model: rev.model.clone(),
        system_prompt: rev.system_prompt.clone(),
        task: req.task.clone(),
        workspace: workspace.clone(),
        autonomy: req.autonomy,
        trust_tier: TrustTier::Trusted,
        budgets: effective_budgets.clone(),
        policy_id: policy_row.id,
        policy_version: policy_row.version,
        policy_snapshot: policy,
        invocation: req.invocation.clone(),
        result_destinations: req.result_destinations.clone(),
    };

    let session = fluidbox_db::create_session(
        &state.pool,
        state.tenant_id,
        agent.id,
        rev.id,
        req.autonomy.as_str(),
        &req.task,
        &serde_json::to_value(&workspace)?,
        &serde_json::to_value(&run_spec)?,
        &serde_json::to_value(&effective_budgets)?,
        Some(&serde_json::to_value(&req.invocation)?),
    )
    .await?;

    crate::ledger::record(
        state,
        session.id,
        fluidbox_core::event::Actor::System,
        fluidbox_core::event::EventBody::SessionCreated {
            task: req.task.clone(),
            agent: agent.name.clone(),
            autonomy: req.autonomy.as_str().into(),
        },
    )
    .await;

    // Kick off the run.
    orchestrator::spawn_run(state.clone(), session.id);

    Ok(session)
}
```

(Note the one intentional hardening vs the old code: `.filter(|a| a.tenant_id == state.tenant_id)` on agent-by-id, matching the by-name behavior.)

- [ ] **Step 2: Shrink `api.rs::create_session` onto it** — the whole body after workspace-input handling becomes:

```rust
pub async fn create_session(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<CreateSession>,
) -> ApiResult<Json<Value>> {
    let explicit_input = match (req.workspace, req.repo) {
        (Some(_), Some(_)) => {
            return Err(ApiError::BadRequest(
                "provide either `workspace` or legacy `repo`, not both".into(),
            ))
        }
        (w, r) => w.or(r),
    };
    let explicit = match explicit_input {
        Some(input) => Some(resolve_workspace_input(&state, input).await?),
        None => None,
    };
    let autonomy = if req.autonomous {
        Autonomy::Autonomous
    } else {
        Autonomy::Supervised
    };
    let session = crate::run_service::create_run(
        &state,
        crate::run_service::CreateRun {
            agent: req.agent,
            revision: crate::run_service::RevisionSelector::Latest,
            task: req.task,
            explicit_workspace: explicit,
            autonomy,
            budget_override: req.budgets,
            invocation: InvocationContext {
                kind: InvocationKind::Manual,
                subscription_id: None,
                actor: Some("operator".into()),
                attributes: Value::Null,
                received_at: Some(chrono::Utc::now()),
            },
            result_destinations: vec![],
        },
    )
    .await?;
    Ok(Json(json!({ "session": session })))
}
```

Adjust `api.rs` imports (`use fluidbox_core::spec::{Autonomy, Budgets, CheckoutMode, InvocationContext, InvocationKind, WorkspaceSpec};` — drop now-unused `RunSpec`, `TrustTier`, `Policy` import if unused), mark `pub(crate) async fn resolve_workspace_input` and `pub(crate) fn valid_repo_name`, and remove the now-dead Task-3 `None` shim. Add `mod run_service;` to `main.rs`.

- [ ] **Step 3: Verify — full test suite + behavioral spot-check**

Run: `set -a; source .env; set +a; cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS. (Behavioral proof that manual runs are unchanged comes from the existing e2e phases in Task 9 — governance + git-workspace suites drive `POST /v1/sessions` end-to-end.)

- [ ] **Step 4: fmt + commit**

```bash
cargo fmt --all
git add crates/fluidbox-server
git commit -m "server: unified create_run service; manual sessions converge on it"
```

---

### Task 5: Trigger auth extractor + pure invoke helpers (template, narrowing, digest)

**Files:**
- Modify: `crates/fluidbox-server/src/auth.rs` (add `TriggerAuth`)
- Create: `crates/fluidbox-server/src/triggers.rs` (pure helpers + unit tests only in this task)
- Modify: `crates/fluidbox-server/src/main.rs` (add `mod triggers;`)

**Interfaces:**
- Produces: `auth::TriggerAuth { subscription_id: Uuid }` (FromRequestParts; resolves ONLY `kind='trigger'` tokens); `triggers::InvokeWorkspace { repository, r#ref, commit_sha: Option<String> ×3 }` (Deserialize+Serialize); `triggers::render_task_template(&str, &BTreeMap<String,String>) -> Result<String, String>`; `triggers::narrow_workspace(&WorkspaceSpec, &InvokeWorkspace) -> Result<WorkspaceSpec, String>`; `triggers::canonical_digest(&Option<String>, &BTreeMap<String,String>, &Option<InvokeWorkspace>) -> String`.

- [ ] **Step 1: Write failing unit tests** (bottom of new `triggers.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::spec::{CheckoutMode, WorkspaceSpec};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn ctx(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn template_renders_context_keys() {
        let out = render_task_template("Investigate {{ticket}} ({{ severity }})",
            &ctx(&[("ticket", "INC-42"), ("severity", "high")])).unwrap();
        assert_eq!(out, "Investigate INC-42 (high)");
        // No placeholders → template passes through untouched.
        assert_eq!(render_task_template("static", &ctx(&[])).unwrap(), "static");
    }

    #[test]
    fn template_rejects_missing_keys_and_unclosed_braces() {
        // Missing key must 400, not silently leave a hole in the prompt.
        assert!(render_task_template("do {{thing}}", &ctx(&[])).is_err());
        assert!(render_task_template("do {{thing", &ctx(&[("thing", "x")])).is_err());
    }

    fn git_base(connection: bool) -> WorkspaceSpec {
        WorkspaceSpec::GitRepository {
            connection_id: connection.then(Uuid::now_v7),
            repository: Some("acme/base".into()),
            clone_url: "https://github.com/acme/base.git".into(),
            r#ref: Some("main".into()),
            commit_sha: None,
            checkout_mode: CheckoutMode::WritableCopy,
        }
    }

    #[test]
    fn narrowing_swaps_ref_and_commit_within_base() {
        let out = narrow_workspace(&git_base(true), &InvokeWorkspace {
            repository: None, r#ref: Some("feature".into()),
            commit_sha: Some("a".repeat(40)),
        }).unwrap();
        let WorkspaceSpec::GitRepository { r#ref, commit_sha, clone_url, connection_id, .. } = out
            else { panic!() };
        assert_eq!(r#ref.as_deref(), Some("feature"));
        assert_eq!(commit_sha.as_deref(), Some(&"a".repeat(40)[..]));
        assert_eq!(clone_url, "https://github.com/acme/base.git"); // repo unchanged
        assert!(connection_id.is_some()); // same connection — never a new one
    }

    #[test]
    fn narrowing_repository_swap_stays_on_github_and_same_connection() {
        let out = narrow_workspace(&git_base(true), &InvokeWorkspace {
            repository: Some("acme/other".into()), r#ref: None, commit_sha: None,
        }).unwrap();
        let WorkspaceSpec::GitRepository { repository, clone_url, r#ref, .. } = out else { panic!() };
        assert_eq!(repository.as_deref(), Some("acme/other"));
        assert_eq!(clone_url, "https://github.com/acme/other.git");
        assert_eq!(r#ref.as_deref(), Some("main")); // base ref inherited
    }

    #[test]
    fn narrowing_rejects_escapes() {
        // repository swap on a non-github base (file:// fixture) → refused.
        let file_base = WorkspaceSpec::GitRepository {
            connection_id: None, repository: None,
            clone_url: "file:///tmp/fixture".into(),
            r#ref: None, commit_sha: None, checkout_mode: CheckoutMode::WritableCopy,
        };
        assert!(narrow_workspace(&file_base, &InvokeWorkspace {
            repository: Some("a/b".into()), r#ref: None, commit_sha: None }).is_err());
        // …but ref-only narrowing of that base is fine.
        assert!(narrow_workspace(&file_base, &InvokeWorkspace {
            repository: None, r#ref: Some("feature".into()), commit_sha: None }).is_ok());
        // Scratch/local bases cannot be narrowed into a git workspace.
        assert!(narrow_workspace(&WorkspaceSpec::Scratch, &InvokeWorkspace {
            repository: None, r#ref: Some("x".into()), commit_sha: None }).is_err());
        // Malformed inputs.
        assert!(narrow_workspace(&git_base(true), &InvokeWorkspace {
            repository: Some("no-slash".into()), r#ref: None, commit_sha: None }).is_err());
        assert!(narrow_workspace(&git_base(true), &InvokeWorkspace {
            repository: None, r#ref: None, commit_sha: Some("zz".into()) }).is_err());
    }

    #[test]
    fn canonical_digest_is_order_independent_and_body_sensitive() {
        let a = canonical_digest(&Some("t".into()), &ctx(&[("a", "1"), ("b", "2")]), &None);
        let b = canonical_digest(&Some("t".into()), &ctx(&[("b", "2"), ("a", "1")]), &None);
        assert_eq!(a, b); // BTreeMap canonicalizes key order
        let c = canonical_digest(&Some("t2".into()), &ctx(&[("a", "1"), ("b", "2")]), &None);
        assert_ne!(a, c);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p fluidbox-server triggers::`
Expected: FAIL to compile.

- [ ] **Step 3: Implement the helpers** (top of `triggers.rs`)

```rust
//! API trigger subscriptions & scoped invocation (design doc §3.5/§6.1).
//! A trigger borrows an agent: it can start only the runs its subscription
//! allows and nothing else. §17 #6 (settled): caller task/workspace
//! overrides are opt-in per subscription, default OFF.

use crate::auth::{Admin, TriggerAuth};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use fluidbox_core::spec::{
    Autonomy, Budgets, InvocationContext, InvocationKind, ResultDestination, WorkspaceSpec,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

/// The only workspace fields an external caller may send: pick a repository
/// / ref / commit within the subscription's authority. Deliberately NO
/// `connection_id`, `clone_url`, or local path — those would widen it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvokeWorkspace {
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub r#ref: Option<String>,
    #[serde(default)]
    pub commit_sha: Option<String>,
}

/// `{{key}}` substitution from the invocation context. Strict: an unknown
/// key or unclosed brace is an error — a silently-empty hole in an agent
/// task is worse than a 400.
pub fn render_task_template(
    template: &str,
    ctx: &BTreeMap<String, String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let Some(j) = after.find("}}") else {
            return Err("task_template has an unclosed '{{'".into());
        };
        let key = after[..j].trim();
        match ctx.get(key) {
            Some(v) => out.push_str(v),
            None => {
                return Err(format!(
                    "task_template references '{{{{{key}}}}}' but the invocation context has no '{key}'"
                ))
            }
        }
        rest = &after[j + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Narrow a git workspace within the subscription's authority: swap the
/// repository (github + same connection only) and/or pin ref/commit. The
/// base comes from the subscription or the agent revision — never from the
/// caller — so the result can only ever be a subset of configured authority.
pub fn narrow_workspace(
    base: &WorkspaceSpec,
    req: &InvokeWorkspace,
) -> Result<WorkspaceSpec, String> {
    let WorkspaceSpec::GitRepository {
        connection_id,
        repository,
        clone_url,
        r#ref,
        commit_sha,
        checkout_mode,
    } = base
    else {
        return Err(
            "this subscription's workspace is not a git repository — nothing to narrow".into(),
        );
    };
    if let Some(sha) = &req.commit_sha {
        if sha.len() < 7 || sha.len() > 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("invalid commit_sha '{sha}'"));
        }
    }
    let (repository, clone_url) = match &req.repository {
        None => (repository.clone(), clone_url.clone()),
        Some(repo) => {
            if !crate::api::valid_repo_name(repo) {
                return Err(format!("repository must be 'owner/name' (got '{repo}')"));
            }
            // A repo swap is only meaningful inside a github-backed base;
            // retargeting an arbitrary clone_url would escape it.
            if connection_id.is_none() && !clone_url.starts_with("https://github.com/") {
                return Err("cannot retarget a non-github workspace".into());
            }
            (Some(repo.clone()), format!("https://github.com/{repo}.git"))
        }
    };
    Ok(WorkspaceSpec::GitRepository {
        connection_id: *connection_id,
        repository,
        clone_url,
        r#ref: req.r#ref.clone().or_else(|| r#ref.clone()),
        commit_sha: req.commit_sha.clone().or_else(|| commit_sha.clone()),
        checkout_mode: *checkout_mode,
    })
}

/// Canonical request digest for Idempotency-Key reuse detection. BTreeMap
/// gives key-order independence; same semantic body → same digest.
pub fn canonical_digest(
    task: &Option<String>,
    context: &BTreeMap<String, String>,
    workspace: &Option<InvokeWorkspace>,
) -> String {
    #[derive(Serialize)]
    struct Canonical<'a> {
        task: &'a Option<String>,
        context: &'a BTreeMap<String, String>,
        workspace: &'a Option<InvokeWorkspace>,
    }
    fluidbox_db::sha256_hex(
        &serde_json::to_string(&Canonical { task, context, workspace })
            .expect("canonical body serializes"),
    )
}
```

In `auth.rs`, after `SessionAuth`:

```rust
/// Scoped trigger-token authentication. The token's entire authority is its
/// subscription: it can invoke that subscription and poll the runs it
/// created — it can never satisfy `Admin` or `SessionAuth`.
pub struct TriggerAuth {
    pub subscription_id: Uuid,
}

impl FromRequestParts<AppState> for TriggerAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or(ApiError::Unauthorized)?;
        let subscription_id = fluidbox_db::subscription_for_token(&state.pool, &token)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        Ok(TriggerAuth { subscription_id })
    }
}
```

Add `mod triggers;` to `main.rs`. Make `valid_repo_name` in api.rs `pub(crate) fn`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fluidbox-server triggers:: && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS (temporary `#[allow(dead_code)]`/unused warnings are NOT acceptable — if clippy flags unused items, add the endpoints task's `use` sites or a `pub` visibility keeps them referenced; in practice Task 6 lands before a full-suite run, but each task must be clippy-clean: if needed, mark the not-yet-routed handlers module with `pub` items only, which clippy accepts).

- [ ] **Step 5: fmt + commit**

```bash
cargo fmt --all
git add crates/fluidbox-server
git commit -m "server: trigger auth extractor + templating/narrowing/digest helpers"
```

---

### Task 6: Trigger endpoints — create/list/detail/enable/disable/rotate + scoped invoke & poll

**Files:**
- Modify: `crates/fluidbox-server/src/triggers.rs` (handlers below the helpers)
- Modify: `crates/fluidbox-server/src/main.rs` (routes in the `public` router)

**Interfaces:**
- Consumes: `run_service::create_run` (Task 4), db fns (Tasks 2-3), helpers (Task 5), `crate::api::resolve_workspace_input` + `WorkspaceInput`.
- Produces routes: `POST /v1/triggers` (Admin), `GET /v1/triggers` (Admin), `GET /v1/triggers/{id}` (Admin), `POST /v1/triggers/{id}/enable` & `/disable` (Admin), `POST /v1/triggers/{id}/rotate_token` (Admin), `POST /v1/triggers/{id}/invoke` (TriggerAuth), `GET /v1/triggers/{id}/runs/{sid}` (TriggerAuth).

- [ ] **Step 1: Implement admin handlers** (append to `triggers.rs`):

```rust
// ─── Admin: subscription management ───────────────────────────────────────

const TOKEN_PREFIX: &str = "fbx_trig_";
const SECRET_PREFIX: &str = "fbx_whsec_";

fn random_hex_token(prefix: &str) -> String {
    // 2 × v4 uuid = 256 bits of entropy, no extra deps (same trick as
    // orchestrator::uuid_token).
    format!(
        "{prefix}{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

#[derive(Deserialize)]
pub struct CreateTrigger {
    /// Agent id or name.
    pub agent: String,
    pub name: String,
    #[serde(default)]
    pub task_template: Option<String>,
    #[serde(default)]
    pub allow_task_override: bool,
    #[serde(default)]
    pub allow_workspace_override: bool,
    #[serde(default)]
    pub autonomous: bool,
    #[serde(default)]
    pub budgets: Option<Budgets>,
    /// Subscription-level workspace (validated like any workspace input).
    #[serde(default)]
    pub workspace: Option<crate::api::WorkspaceInput>,
    /// Pre-registered signed-webhook destination (design §6.1: destinations
    /// are approved at subscription time, never invented by the caller).
    #[serde(default)]
    pub callback_url: Option<String>,
    /// Pin the run to a specific revision id; omitted = always latest.
    #[serde(default)]
    pub pinned_revision_id: Option<Uuid>,
}

pub async fn create(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<CreateTrigger>,
) -> ApiResult<Json<Value>> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    let agent = match Uuid::parse_str(&req.agent) {
        Ok(id) => fluidbox_db::get_agent(&state.pool, id).await?,
        Err(_) => fluidbox_db::get_agent_by_name(&state.pool, state.tenant_id, &req.agent).await?,
    }
    .filter(|a| a.tenant_id == state.tenant_id)
    .ok_or_else(|| ApiError::BadRequest(format!("unknown agent '{}'", req.agent)))?;
    if let Some(rid) = req.pinned_revision_id {
        fluidbox_db::get_revision(&state.pool, rid)
            .await?
            .filter(|r| r.agent_id == agent.id)
            .ok_or_else(|| {
                ApiError::BadRequest(format!("revision {rid} does not belong to this agent"))
            })?;
    }
    // A subscription that can never produce a task is dead config.
    if req.task_template.as_deref().map(str::trim).unwrap_or("").is_empty()
        && !req.allow_task_override
    {
        return Err(ApiError::BadRequest(
            "provide a task_template or set allow_task_override".into(),
        ));
    }
    let workspace_value = match req.workspace {
        None => None,
        Some(input) => match crate::api::resolve_workspace_input(&state, input).await? {
            WorkspaceSpec::Scratch => None,
            spec => Some(serde_json::to_value(&spec)?),
        },
    };

    // Signed-webhook destination: generate + seal the HMAC secret now;
    // the plaintext is returned exactly once, in this response.
    let (destinations, secret_plain, secret_sealed) = match &req.callback_url {
        None => (json!([]), None, None),
        Some(url) => {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(ApiError::BadRequest(
                    "callback_url must be http(s)".into(),
                ));
            }
            let sealer = state.sealer.as_ref().ok_or_else(|| {
                ApiError::BadRequest(
                    "signed callbacks are disabled: set FLUIDBOX_CREDENTIAL_KEY on the server"
                        .into(),
                )
            })?;
            let secret = random_hex_token(SECRET_PREFIX);
            let sealed = sealer.seal(&secret);
            let dests = serde_json::to_value(vec![ResultDestination::SignedWebhook {
                url: url.clone(),
            }])?;
            (dests, Some(secret), Some(sealed))
        }
    };

    let sub = fluidbox_db::create_trigger_subscription(
        &state.pool,
        state.tenant_id,
        agent.id,
        name,
        "api",
        req.pinned_revision_id,
        req.task_template.as_deref().map(str::trim).filter(|t| !t.is_empty()),
        req.allow_task_override,
        req.allow_workspace_override,
        req.autonomous.then_some("autonomous"),
        req.budgets
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?
            .as_ref(),
        workspace_value.as_ref(),
        &destinations,
        secret_sealed.as_deref(),
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            ApiError::Conflict(format!("a trigger named '{name}' already exists"))
        }
        _ => ApiError::Db(e),
    })?;

    let token = random_hex_token(TOKEN_PREFIX);
    fluidbox_db::create_trigger_token(&state.pool, state.tenant_id, sub.id, &token).await?;

    // token + callback_secret appear ONLY here, once, at creation.
    Ok(Json(json!({
        "subscription": sub,
        "token": token,
        "callback_secret": secret_plain,
    })))
}

pub async fn list(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let subscriptions = fluidbox_db::list_trigger_subscriptions(&state.pool, state.tenant_id).await?;
    Ok(Json(json!({ "subscriptions": subscriptions })))
}

pub async fn get(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let sub = fluidbox_db::get_trigger_subscription(&state.pool, id)
        .await?
        .filter(|s| s.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    let sessions = fluidbox_db::list_subscription_sessions(&state.pool, id, 20).await?;
    let deliveries = fluidbox_db::list_subscription_deliveries(&state.pool, id, 20).await?;
    Ok(Json(json!({
        "subscription": sub, "sessions": sessions, "deliveries": deliveries
    })))
}

async fn set_enabled(state: &AppState, id: Uuid, enabled: bool) -> ApiResult<Json<Value>> {
    let sub = fluidbox_db::get_trigger_subscription(&state.pool, id)
        .await?
        .filter(|s| s.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    let row = fluidbox_db::set_trigger_subscription_enabled(&state.pool, sub.id, enabled)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "subscription": row })))
}

pub async fn enable(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    set_enabled(&state, id, true).await
}

pub async fn disable(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    set_enabled(&state, id, false).await
}

/// Rotation: every live token dies, one new token is minted and returned once.
pub async fn rotate_token(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let sub = fluidbox_db::get_trigger_subscription(&state.pool, id)
        .await?
        .filter(|s| s.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    let revoked = fluidbox_db::revoke_trigger_tokens(&state.pool, sub.id).await?;
    let token = random_hex_token(TOKEN_PREFIX);
    fluidbox_db::create_trigger_token(&state.pool, state.tenant_id, sub.id, &token).await?;
    Ok(Json(json!({ "token": token, "revoked": revoked })))
}
```

- [ ] **Step 2: Implement invoke + poll** (append):

```rust
// ─── Scoped: invoke & poll ────────────────────────────────────────────────

const MAX_TASK_CHARS: usize = 16_384;
const MAX_CONTEXT_BYTES: usize = 8_192;
const MAX_IDEMPOTENCY_KEY_CHARS: usize = 200;

#[derive(Deserialize)]
pub struct InvokeBody {
    #[serde(default)]
    pub task: Option<String>,
    #[serde(default)]
    pub context: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    pub workspace: Option<InvokeWorkspace>,
}

/// Flatten the caller's context object into strings; nested values are
/// rejected — context is template input and audit data, not a payload bus.
fn flatten_context(raw: Option<serde_json::Map<String, Value>>) -> Result<BTreeMap<String, String>, ApiError> {
    let Some(map) = raw else { return Ok(BTreeMap::new()) };
    let mut out = BTreeMap::new();
    for (k, v) in map {
        let s = match v {
            Value::String(s) => s,
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "context.{k} must be a string, number, or bool"
                )))
            }
        };
        out.insert(k, s);
    }
    let size: usize = out.iter().map(|(k, v)| k.len() + v.len()).sum();
    if size > MAX_CONTEXT_BYTES {
        return Err(ApiError::BadRequest(format!(
            "context too large ({size} bytes > {MAX_CONTEXT_BYTES})"
        )));
    }
    Ok(out)
}

pub async fn invoke(
    auth: TriggerAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<InvokeBody>,
) -> ApiResult<Json<Value>> {
    // The token IS the authority; the path must match it.
    if auth.subscription_id != id {
        return Err(ApiError::Unauthorized);
    }
    let sub = fluidbox_db::get_trigger_subscription(&state.pool, id)
        .await?
        .filter(|s| s.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    if !sub.enabled {
        return Err(ApiError::Conflict("trigger subscription is disabled".into()));
    }

    // §17 #6: overrides are opt-in per subscription, default off.
    if body.task.is_some() && !sub.allow_task_override {
        return Err(ApiError::BadRequest(
            "this subscription does not allow task override".into(),
        ));
    }
    if body.workspace.is_some() && !sub.allow_workspace_override {
        return Err(ApiError::BadRequest(
            "this subscription does not allow workspace override".into(),
        ));
    }
    if body.task.as_deref().map(|t| t.chars().count() > MAX_TASK_CHARS).unwrap_or(false) {
        return Err(ApiError::BadRequest(format!(
            "task too large (> {MAX_TASK_CHARS} chars)"
        )));
    }
    let context = flatten_context(body.context)?;

    // Effective task: allowed caller task, else the rendered template.
    let task = match body.task.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => t.to_string(),
        None => {
            let template = sub.task_template.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "no task: subscription has no task_template and no caller task was allowed/provided"
                        .into(),
                )
            })?;
            render_task_template(template, &context).map_err(ApiError::BadRequest)?
        }
    };

    // Effective workspace: subscription override > (narrowed by caller when
    // allowed). When neither exists, create_run falls through to the agent
    // revision default and then scratch — same precedence as every run.
    let sub_workspace: Option<WorkspaceSpec> = sub
        .workspace_override
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| ApiError::Internal(format!("bad stored subscription workspace: {e}")))?;
    let explicit_workspace = match &body.workspace {
        None => sub_workspace,
        Some(nw) => {
            // Narrowing base: subscription workspace, else the revision default.
            let base = match sub_workspace {
                Some(ws) => ws,
                None => {
                    let rev = match sub.pinned_revision_id {
                        Some(rid) => fluidbox_db::get_revision(&state.pool, rid).await?,
                        None => fluidbox_db::latest_revision(&state.pool, sub.agent_id).await?,
                    }
                    .ok_or_else(|| ApiError::BadRequest("agent has no revisions".into()))?;
                    rev.default_workspace
                        .as_ref()
                        .map(|v| serde_json::from_value(v.clone()))
                        .transpose()
                        .map_err(|e| ApiError::Internal(format!("bad stored default workspace: {e}")))?
                        .ok_or_else(|| {
                            ApiError::BadRequest(
                                "workspace override needs a git workspace on the subscription or agent revision"
                                    .into(),
                            )
                        })?
                }
            };
            Some(narrow_workspace(&base, nw).map_err(ApiError::BadRequest)?)
        }
    };

    // Idempotency: caller key dedups; absent key → unique auto key (the
    // invocation row is still written so every invoke is auditable).
    let provided_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_string);
    if provided_key.as_deref().map(|k| k.chars().count() > MAX_IDEMPOTENCY_KEY_CHARS).unwrap_or(false) {
        return Err(ApiError::BadRequest("Idempotency-Key too long".into()));
    }
    let digest = canonical_digest(&body.task, &context, &body.workspace);
    let key = provided_key
        .clone()
        .unwrap_or_else(|| format!("auto-{}", Uuid::now_v7()));

    let claim = fluidbox_db::claim_invocation(&state.pool, sub.id, &key, &digest).await?;
    let invocation_id = match claim {
        fluidbox_db::InvocationClaim::Replay { session_id, request_digest } => {
            if request_digest != digest {
                return Err(ApiError::UnprocessableEntity(
                    "Idempotency-Key was already used with a different request body".into(),
                ));
            }
            let session = fluidbox_db::get_session(&state.pool, session_id)
                .await?
                .ok_or(ApiError::NotFound)?;
            return Ok(Json(json!({
                "session_id": session.id,
                "status": session.status,
                "replay": true,
                "poll_url": format!("/v1/triggers/{}/runs/{}", sub.id, session.id),
            })));
        }
        fluidbox_db::InvocationClaim::InFlight => {
            return Err(ApiError::Conflict(
                "an invocation with this Idempotency-Key is being created — retry shortly".into(),
            ))
        }
        fluidbox_db::InvocationClaim::Claimed { invocation_id } => invocation_id,
    };

    let autonomy = match sub.autonomy.as_deref() {
        Some("autonomous") => Autonomy::Autonomous,
        _ => Autonomy::Supervised,
    };
    let budget_override: Option<Budgets> = sub
        .budget_override
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| ApiError::Internal(format!("bad stored budget override: {e}")))?;
    let destinations: Vec<ResultDestination> =
        serde_json::from_value(sub.result_destinations.clone())
            .map_err(|e| ApiError::Internal(format!("bad stored destinations: {e}")))?;

    let invocation = InvocationContext {
        kind: InvocationKind::Api,
        subscription_id: Some(sub.id),
        actor: Some(format!("trigger:{}", sub.name)),
        attributes: json!({
            "context": context,
            "idempotency_key": provided_key,
        }),
        received_at: Some(chrono::Utc::now()),
    };

    let created = crate::run_service::create_run(
        &state,
        crate::run_service::CreateRun {
            agent: sub.agent_id.to_string(),
            revision: match sub.pinned_revision_id {
                Some(rid) => crate::run_service::RevisionSelector::Pinned(rid),
                None => crate::run_service::RevisionSelector::Latest,
            },
            task,
            explicit_workspace,
            autonomy,
            budget_override,
            invocation,
            result_destinations: destinations,
        },
    )
    .await;

    match created {
        Ok(session) => {
            fluidbox_db::bind_invocation(&state.pool, invocation_id, session.id).await?;
            Ok(Json(json!({
                "session_id": session.id,
                "status": session.status,
                "replay": false,
                "poll_url": format!("/v1/triggers/{}/runs/{}", sub.id, session.id),
            })))
        }
        Err(e) => {
            // Free the key so the caller's retry isn't wedged behind a failure.
            fluidbox_db::release_invocation(&state.pool, invocation_id).await.ok();
            Err(e)
        }
    }
}

/// Scoped polling: a trigger token can read exactly the runs it created.
pub async fn poll_run(
    auth: TriggerAuth,
    State(state): State<AppState>,
    Path((id, sid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<Value>> {
    if auth.subscription_id != id {
        return Err(ApiError::Unauthorized);
    }
    if !fluidbox_db::subscription_owns_session(&state.pool, id, sid).await? {
        return Err(ApiError::NotFound);
    }
    let session = fluidbox_db::get_session(&state.pool, sid)
        .await?
        .ok_or(ApiError::NotFound)?;
    let payload = crate::deliveries::result_payload(&state, &session, None, None).await?;
    Ok(Json(payload))
}
```

- [ ] **Step 3: Routes in `main.rs`** — after the `/connections/...` routes:

```rust
        .route("/triggers", get(triggers::list).post(triggers::create))
        .route("/triggers/{id}", get(triggers::get))
        .route("/triggers/{id}/enable", post(triggers::enable))
        .route("/triggers/{id}/disable", post(triggers::disable))
        .route("/triggers/{id}/rotate_token", post(triggers::rotate_token))
        .route("/triggers/{id}/invoke", post(triggers::invoke))
        .route("/triggers/{id}/runs/{sid}", get(triggers::poll_run))
```

Note: `poll_run` calls `deliveries::result_payload`, which lands in Task 7. To keep Task 6 compiling on its own, EITHER implement Task 7's `deliveries.rs` skeleton (`result_payload` only) in this task, or land Tasks 6+7 as one commit. Preferred: move `result_payload` into this task as `crates/fluidbox-server/src/deliveries.rs` with just the payload builder (Task 7 then adds signing/worker/hook to the same file):

```rust
//! Result payload + signed webhook delivery (design doc §9).

use crate::error::ApiResult;
use crate::state::AppState;
use fluidbox_core::spec::RunSpec;
use fluidbox_db::SessionRow;
use serde_json::{json, Value};
use uuid::Uuid;

/// The canonical run result (design §9): status, summary, artifacts, usage/
/// cost, timestamps, invocation reference. Shared by the signed callback and
/// the scoped polling endpoint so external services see one shape.
pub async fn result_payload(
    state: &AppState,
    session: &SessionRow,
    delivery_id: Option<Uuid>,
    attempt: Option<i32>,
) -> ApiResult<Value> {
    let usage = fluidbox_db::usage_totals(&state.pool, session.id).await?;
    let tool_calls = fluidbox_db::tool_call_count(&state.pool, session.id).await?;
    let artifacts = fluidbox_db::list_artifacts(&state.pool, session.id).await?;
    let run_spec: Option<RunSpec> = serde_json::from_value(session.run_spec.clone()).ok();
    Ok(json!({
        "event": "run.finished",
        "delivery_id": delivery_id,
        "attempt": attempt,
        "run": {
            "id": session.id,
            "status": session.status,
            "status_reason": session.status_reason,
            "agent_id": session.agent_id,
            "agent_revision_id": session.agent_revision_id,
            "agent_name": run_spec.as_ref().map(|r| r.agent_name.clone()),
            "task": session.task,
            "summary": session.result_summary,
            "invocation": session.trigger,
            "created_at": session.created_at,
            "started_at": session.started_at,
            "finished_at": session.finished_at,
        },
        "usage": {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cache_read_tokens": usage.cache_read_tokens,
            "cache_write_tokens": usage.cache_write_tokens,
            "cost_usd": usage.cost_usd,
            "requests": usage.requests,
            "tool_calls": tool_calls,
        },
        "artifacts": artifacts.iter().map(|a| json!({
            "id": a.id, "kind": a.kind, "name": a.name,
            "content_type": a.content_type, "content": a.content,
        })).collect::<Vec<_>>(),
    }))
}
```

Add `mod deliveries;` to `main.rs`.

- [ ] **Step 4: Verify**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: PASS. Then a live smoke against a dev server (optional but cheap):

```bash
# in one shell: cargo run -p fluidbox-server   (or reuse just dev)
source .env
curl -s -X POST -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" -H "content-type: application/json" \
  -d '{"agent":"claude-fixer","name":"smoke","task_template":"say {{word}}"}' \
  http://127.0.0.1:8787/v1/triggers | python3 -m json.tool
# take .token → invoke:
curl -s -X POST -H "authorization: Bearer fbx_trig_…" -H "content-type: application/json" \
  -H "Idempotency-Key: k1" -d '{"context":{"word":"hi"}}' \
  http://127.0.0.1:8787/v1/triggers/<id>/invoke
```

- [ ] **Step 5: fmt + commit**

```bash
cargo fmt --all
git add crates/fluidbox-server
git commit -m "server: trigger subscriptions API + scoped invoke with Idempotency-Key"
```

---

### Task 7: Signed result callbacks — signer, worker, terminal-transition hook

**Files:**
- Modify: `Cargo.toml` (workspace deps: add `hmac = "0.12"`)
- Modify: `crates/fluidbox-server/Cargo.toml` (add `hmac.workspace = true`)
- Modify: `crates/fluidbox-server/src/deliveries.rs` (signing + enqueue + worker)
- Modify: `crates/fluidbox-server/src/orchestrator.rs:27-49` (`transition` hook)
- Modify: `crates/fluidbox-core/src/event.rs` (two EventBody variants)
- Modify: `crates/fluidbox-server/src/api.rs` + `main.rs` (GET `/v1/sessions/{id}/deliveries`)
- Modify: `crates/fluidbox-server/src/main.rs` (spawn worker)

**Interfaces:**
- Consumes: `enqueue_result_delivery`, `due_result_deliveries`, `mark_delivery_attempt`, `subscription_callback_secret_sealed` (Tasks 2-3), `result_payload` (Task 6).
- Produces: `deliveries::sign_payload(secret: &str, timestamp: i64, body: &str) -> String` ("v1=<hex hmac-sha256 of `{ts}.{body}`>"); `deliveries::enqueue_for_session(state, session_id)`; `deliveries::spawn_worker(state)`; wire headers `x-fluidbox-event: run.finished`, `x-fluidbox-delivery: <id>`, `x-fluidbox-timestamp: <unix secs>`, `x-fluidbox-signature: v1=<hex>`; `EventBody::CallbackDelivered/CallbackFailed` ("callback.delivered"/"callback.failed").

- [ ] **Step 1: Write the failing signer test** (in `deliveries.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_stable_and_verifiable() {
        // Pinned vector — the e2e receiver recomputes this with
        // `printf '%s.%s' ts body | openssl dgst -sha256 -hmac secret`.
        let sig = sign_payload("fbx_whsec_test", 1_752_000_000, r#"{"a":1}"#);
        assert!(sig.starts_with("v1="));
        assert_eq!(sig.len(), 3 + 64);
        assert_eq!(sig, sign_payload("fbx_whsec_test", 1_752_000_000, r#"{"a":1}"#));
        assert_ne!(sig, sign_payload("fbx_whsec_test", 1_752_000_001, r#"{"a":1}"#));
        assert_ne!(sig, sign_payload("other", 1_752_000_000, r#"{"a":1}"#));
    }

    #[test]
    fn backoff_grows_then_caps() {
        assert_eq!(backoff_secs(1), 5);
        assert_eq!(backoff_secs(2), 30);
        assert_eq!(backoff_secs(6), 3600);
        assert_eq!(backoff_secs(99), 3600);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p fluidbox-server deliveries::`
Expected: FAIL to compile.

- [ ] **Step 3: Implement** — add deps, then in `deliveries.rs`:

```rust
use fluidbox_core::event::{Actor, EventBody};
use fluidbox_core::spec::ResultDestination;
use std::time::Duration;

/// attempts→wait: 5s, 30s, 2m, 10m, 30m, then 1h forever (attempt n is the
/// n-th failure; MAX_ATTEMPTS bounds the total).
const BACKOFF_SECS: [i64; 6] = [5, 30, 120, 600, 1800, 3600];
pub const MAX_ATTEMPTS: i32 = 6;
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

pub fn backoff_secs(attempt: i32) -> i64 {
    BACKOFF_SECS
        .get((attempt.max(1) - 1) as usize)
        .copied()
        .unwrap_or(3600)
}

/// `v1=<hex hmac-sha256(secret, "{timestamp}.{body}")>` — receivers verify
/// by recomputing over the exact raw body bytes.
pub fn sign_payload(secret: &str, timestamp: i64, body: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("hmac accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    format!("v1={}", hex::encode(mac.finalize().into_bytes()))
}

/// Called by the orchestrator on every transition into a terminal state.
/// Failures here are logged, never propagated — result publication must not
/// touch the run lifecycle (design §9).
pub async fn enqueue_for_session(state: &AppState, session_id: Uuid) {
    let Ok(Some(session)) = fluidbox_db::get_session(&state.pool, session_id).await else {
        return;
    };
    let Ok(run_spec) = serde_json::from_value::<RunSpec>(session.run_spec.clone()) else {
        return;
    };
    for dest in &run_spec.result_destinations {
        let dest_json = match serde_json::to_value(dest) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match fluidbox_db::enqueue_result_delivery(
            &state.pool,
            session_id,
            run_spec.invocation.subscription_id,
            &dest_json,
        )
        .await
        {
            Ok(d) => tracing::info!("enqueued result delivery {} for {session_id}", d.id),
            Err(e) => tracing::error!("enqueue delivery for {session_id} failed: {e}"),
        }
    }
}

/// The delivery worker: single sequential loop (no locking needed — see
/// due_result_deliveries). At-least-once semantics; receivers dedup on
/// x-fluidbox-delivery.
pub fn spawn_worker(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3));
        loop {
            tick.tick().await;
            let due = match fluidbox_db::due_result_deliveries(&state.pool, 10).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("delivery poll failed: {e}");
                    continue;
                }
            };
            for d in due {
                attempt(&state, &d).await;
            }
        }
    });
}

async fn attempt(state: &AppState, d: &fluidbox_db::ResultDeliveryRow) {
    let outcome = try_deliver(state, d).await;
    let (ok, err, digest) = match &outcome {
        Ok(digest) => (true, None, Some(digest.as_str())),
        Err(e) => (false, Some(e.as_str()), None),
    };
    let next_attempt = d.attempts + 1;
    let updated = fluidbox_db::mark_delivery_attempt(
        &state.pool,
        d.id,
        ok,
        err,
        digest,
        backoff_secs(next_attempt),
        MAX_ATTEMPTS,
    )
    .await;
    let Ok(Some(row)) = updated else { return };
    // Timeline visibility: record delivered / terminally-failed (not every
    // intermediate retry — that's the deliveries table's job).
    let url = row
        .destination
        .get("url")
        .and_then(|u| u.as_str())
        .unwrap_or("?")
        .to_string();
    match row.status.as_str() {
        "delivered" => {
            crate::ledger::record(
                state,
                row.session_id,
                Actor::System,
                EventBody::CallbackDelivered {
                    delivery_id: row.id,
                    url,
                    attempt: row.attempts,
                },
            )
            .await;
        }
        "failed" => {
            crate::ledger::record(
                state,
                row.session_id,
                Actor::System,
                EventBody::CallbackFailed {
                    delivery_id: row.id,
                    url,
                    attempts: row.attempts,
                    error: row.last_error.clone().unwrap_or_default(),
                },
            )
            .await;
        }
        _ => {}
    }
}

/// One HTTP attempt. Returns the payload digest on 2xx.
async fn try_deliver(
    state: &AppState,
    d: &fluidbox_db::ResultDeliveryRow,
) -> Result<String, String> {
    let dest: ResultDestination = serde_json::from_value(d.destination.clone())
        .map_err(|e| format!("bad destination: {e}"))?;
    let ResultDestination::SignedWebhook { url } = dest;
    let sub_id = d
        .subscription_id
        .ok_or("delivery has no subscription (cannot resolve signing secret)")?;
    let sealed = fluidbox_db::subscription_callback_secret_sealed(&state.pool, sub_id)
        .await
        .map_err(|e| format!("secret lookup failed: {e}"))?
        .ok_or("subscription has no callback secret")?;
    let sealer = state
        .sealer
        .as_ref()
        .ok_or("FLUIDBOX_CREDENTIAL_KEY not configured")?;
    let secret = sealer.open(&sealed).map_err(|e| e.to_string())?;

    let session = fluidbox_db::get_session(&state.pool, d.session_id)
        .await
        .map_err(|e| format!("session lookup failed: {e}"))?
        .ok_or("session vanished")?;
    let payload = crate::deliveries::result_payload(state, &session, Some(d.id), Some(d.attempts + 1))
        .await
        .map_err(|e| format!("payload build failed: {e}"))?;
    let body = payload.to_string();
    let digest = format!("sha256:{}", fluidbox_db::sha256_hex(&body));
    let ts = chrono::Utc::now().timestamp();
    let sig = sign_payload(&secret, ts, &body);

    let res = state
        .http
        .post(&url)
        .timeout(DELIVERY_TIMEOUT)
        .header("content-type", "application/json")
        .header("x-fluidbox-event", "run.finished")
        .header("x-fluidbox-delivery", d.id.to_string())
        .header("x-fluidbox-timestamp", ts.to_string())
        .header("x-fluidbox-signature", sig)
        .body(body)
        .send()
        .await
        // reqwest errors carry the URL, never headers/body — safe to store.
        .map_err(|e| format!("request failed: {e}"))?;
    if res.status().is_success() {
        Ok(digest)
    } else {
        Err(format!("destination returned {}", res.status()))
    }
}
```

(Adjust the Task-6 skeleton's imports to the final set; `result_payload` stays as written.)

`event.rs` — after `RunError`:

```rust
    #[serde(rename = "callback.delivered")]
    CallbackDelivered {
        delivery_id: Uuid,
        url: String,
        attempt: i32,
    },
    #[serde(rename = "callback.failed")]
    CallbackFailed {
        delivery_id: Uuid,
        url: String,
        attempts: i32,
        error: String,
    },
```

`orchestrator.rs::transition` — inside the `Ok(Some((from, _)))` arm, after the ledger record:

```rust
            if next.is_terminal() {
                // Publication is decoupled: enqueue rows; the delivery worker
                // owns retries. This is the ONLY enqueue point — every exit
                // path (finalize/fail/cancel/sweeps) funnels through here,
                // and the state machine makes terminal entry exactly-once.
                crate::deliveries::enqueue_for_session(state, id).await;
            }
```

`api.rs` — session deliveries endpoint:

```rust
pub async fn session_deliveries(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deliveries = fluidbox_db::list_session_deliveries(&state.pool, id).await?;
    Ok(Json(json!({ "deliveries": deliveries })))
}
```

`main.rs`: route `.route("/sessions/{id}/deliveries", get(api::session_deliveries))` + `deliveries::spawn_worker(state.clone());` next to `workers::spawn_all`.

- [ ] **Step 4: Verify**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, including the pinned signature vector. Cross-check the vector against openssl:

```bash
printf '%s.%s' 1752000000 '{"a":1}' | openssl dgst -sha256 -hmac fbx_whsec_test
# must equal the hex in sign_payload("fbx_whsec_test", 1752000000, "{\"a\":1}")
```

- [ ] **Step 5: fmt + commit**

```bash
cargo fmt --all
git add Cargo.toml Cargo.lock crates
git commit -m "server: signed result callbacks — HMAC delivery worker + terminal enqueue hook"
```

---

### Task 8: Dashboard — Triggers page, invocation & delivery status

**Files:**
- Modify: `apps/web/app/lib/api.ts` (types)
- Create: `apps/web/app/triggers/page.tsx`
- Modify: `apps/web/app/components/Rail.tsx:8-15` (nav entry)
- Modify: `apps/web/app/sessions/[id]/page.tsx` (invocation chip + deliveries panel)

**Interfaces:**
- Consumes: `GET/POST /v1/triggers...`, `GET /v1/sessions/{id}/deliveries` via the existing proxy; `apiGet/apiPost`; `PageHead` from `components/bits`; agents list from `/agents`.
- Produces (api.ts):

```ts
export interface TriggerSubscription {
  id: string;
  agent_id: string;
  name: string;
  trigger_kind: string;
  pinned_revision_id: string | null;
  enabled: boolean;
  task_template: string | null;
  allow_task_override: boolean;
  allow_workspace_override: boolean;
  autonomy: string | null;
  result_destinations: { kind: string; url?: string }[];
  created_at: string;
}

export interface ResultDelivery {
  id: string;
  session_id: string;
  subscription_id: string | null;
  destination: { kind: string; url?: string };
  status: string; // pending | delivered | failed
  attempts: number;
  next_attempt_at: string;
  last_error: string | null;
  delivered_at: string | null;
  created_at: string;
}

export interface InvocationEnvelope {
  kind: string;
  subscription_id?: string;
  actor?: string;
  attributes?: Record<string, unknown>;
  received_at?: string;
}
```

  and `Session` gains `trigger: InvocationEnvelope | null;`.

- [ ] **Step 1: api.ts** — add the three interfaces above + the `Session.trigger` field.

- [ ] **Step 2: `triggers/page.tsx`** — follow the connections-page structure exactly (PageHead + panel + rows + modal). Contents:
  - Load `apiGet<{subscriptions: TriggerSubscription[]}>("/triggers")` and `apiGet<{agents: Agent[]}>("/agents")` (to label agent names).
  - Each row: name (mono, accent), agent name, chips for `template`/`task override`/`workspace override`/`autonomous`, callback URL (truncated), `enabled` pill (reuse `autopill supervised|autonomous` classes like connections' status pill), buttons: `disable`/`enable` (`apiPost(\`/triggers/${id}/disable\`, {})`), `rotate token` (result shown in the show-once modal), and an expand toggle.
  - Expanded row: fetch `apiGet(\`/triggers/${id}\`)` → recent sessions (id short + status + created, linking `/sessions/{id}`) and recent deliveries (status pill, attempts, last_error truncated).
  - "+ New trigger" modal: agent `<select>` (from agents), name, task_template `<textarea>`, checkboxes `allow task override` / `allow workspace override` / `autonomous`, callback URL input. Submit → `apiPost("/triggers", {...})`. On success show a **show-once panel** (monospace, copy-paste blocks) with `token`, `callback_secret` (when present), and a ready-to-run curl:

```text
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Idempotency-Key: my-key-1" \
  -H "Content-Type: application/json" \
  -d '{"context": {"ticket": "INC-42"}}' \
  <API>/v1/triggers/<id>/invoke
```

    with an explicit warning line: "This token and secret are shown once and stored hashed/sealed — copy them now."
- [ ] **Step 3: Rail** — add `{ href: "/triggers", label: "Triggers", ico: "⚡" }` between Connections and Settings.
- [ ] **Step 4: Session detail page** — where the header chips render (autonomy pill etc.): if `session.trigger && session.trigger.kind !== "manual"`, render a chip `via {session.trigger.actor ?? session.trigger.kind}`. Below artifacts, a "Result deliveries" panel shown only when `apiGet<{deliveries: ResultDelivery[]}>(\`/sessions/${id}/deliveries\`)` is non-empty: destination URL, status pill, attempts, delivered_at/next_attempt_at, last_error. Poll it on the same cadence the page already refreshes non-terminal sessions.
- [ ] **Step 5: Verify**

Run: `cd apps/web && pnpm build`
Expected: builds clean (type errors are the failure mode here). Manual spot-check via `just dev` optional.

- [ ] **Step 6: commit**

```bash
git add apps/web
git commit -m "web: triggers page + invocation/delivery status on sessions"
```

---

### Task 9: E2E acceptance phase — `scripts/e2e-trigger.sh` + suite wiring

**Files:**
- Create: `scripts/e2e-trigger.sh` (executable)
- Modify: `scripts/e2e.sh` (insert phase; renumber to /5)
- Modify: `justfile` e2e comment (mention triggers)

**Interfaces:**
- Consumes: everything above over real HTTP; `e2e-lib.sh` helpers; `openssl` (add to `require_cmd`).

Pattern: exactly `e2e-git-workspace.sh` — no-model assertions always run; live tier self-skips. The receiver is a python3 http server writing each delivery (headers + raw body) to a JSON file.

- [ ] **Step 1: Write the script** — full content:

```bash
#!/usr/bin/env bash
# Phase 2 acceptance — generic API borrowing + signed result callbacks
# (design doc §12 Phase 2):
#   • scoped trigger tokens: can invoke, can poll own runs, CANNOT touch the
#     admin API; admin token cannot invoke
#   • §17 #6: task/workspace overrides opt-in per subscription (default off)
#   • task templates render invoke context; missing keys are 400s
#   • Idempotency-Key: retries return the same run; body drift → 422
#   • InvocationContext kind=api frozen into the session + RunSpec
#   • signed terminal callback (HMAC verified out-of-band with openssl);
#     the run stays terminal even when its callback destination is dead
#   • live: external service borrows claude-fixer and receives a signed
#     callback with status/summary/artifacts/cost (self-skips without key)
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker python3 curl git cargo openssl
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
CT="content-type: application/json"

if ! port_in_use; then
  cargo build -q -p fluidbox-server || exit 1
  trap 'stop_server' EXIT
  start_server || exit 1
fi

B=/tmp/fbx-trig-body.json
post() { curl -s -o "$B" -w "%{http_code}" -X POST -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }
tpost() { # token path body [extra-header]
  curl -s -o "$B" -w "%{http_code}" -X POST -H "authorization: Bearer $1" -H "$CT" \
    ${4:+-H "$4"} -d "$3" "$API/v1$2"
}
sfield() { curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']$2"; }
wait_terminal() {
  local deadline=$(( $(date +%s) + ${2:-240} )) st=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    st=$(sfield "$1" "['status']")
    case "$st" in completed|failed|cancelled|budget_exceeded) echo "$st"; return 0 ;; esac
    sleep 3
  done
  echo "timeout(last=$st)"; return 1
}

say "RECEIVER — the 'external service' capturing signed callbacks"
RCV_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fbx-trig-rcv.XXXXXX")
RCV_PORT=8899
python3 - "$RCV_PORT" "$RCV_DIR" <<'PYEOF' &
import http.server, json, sys, pathlib
port, out = int(sys.argv[1]), pathlib.Path(sys.argv[2])
n = 0
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global n
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        n += 1
        (out / f"delivery-{n}.json").write_text(json.dumps({
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode()}))
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
PYEOF
RCV_PID=$!
trap 'kill $RCV_PID 2>/dev/null; stop_server' EXIT
sleep 0.5
ok "callback receiver on :$RCV_PORT"

say "FIXTURE — git repo for workspace-narrowing + zero-spend failure runs"
FX=$(mktemp -d "${TMPDIR:-/tmp}/fbx-trig-fx.XXXXXX")
git -C "$FX" init -q -b main
git -C "$FX" config user.email e2e@fluidbox.dev
git -C "$FX" config user.name fbx-e2e
echo "v1" > "$FX/f.txt"; git -C "$FX" add -A; git -C "$FX" commit -qm c1
SHA1=$(git -C "$FX" rev-parse HEAD)
git -C "$FX" branch feature
echo "v2" > "$FX/f.txt"; git -C "$FX" add -A; git -C "$FX" commit -qm c2
URL="file://$FX"
ok "fixture ready"

say "SUBSCRIPTIONS — template-only (SUB1), overrides-on (SUB2), dead callback (SUB3)"
AGENT="trig-agent-$$"
post "/agents" "{\"name\":\"$AGENT\",\"policy\":\"default\"}" >/dev/null
AGENT_GIT="trig-agent-git-$$"
post "/agents" "{\"name\":\"$AGENT_GIT\",\"policy\":\"default\",
  \"default_workspace\":{\"kind\":\"git_repository\",\"clone_url\":\"$URL\",\"ref\":\"main\"}}" >/dev/null

CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"sub1-$$\",
  \"task_template\":\"Investigate {{ticket}} and report.\",
  \"callback_url\":\"http://127.0.0.1:$RCV_PORT/cb\"}")
SUB1=$(cat "$B" | j "['subscription']['id']")
TOK1=$(cat "$B" | j "['token']")
SEC1=$(cat "$B" | j "['callback_secret']")
[ "$CODE" = "200" ] && [ -n "$SUB1" ] && ok "SUB1 created" || { no "SUB1 create → $CODE: $(cat "$B")"; exit 1; }
case "$TOK1" in fbx_trig_*) ok "token minted (shown once, fbx_trig_ prefix)";; *) no "bad token '$TOK1'";; esac
case "$SEC1" in fbx_whsec_*) ok "callback secret minted (fbx_whsec_ prefix)";; *) no "bad secret '$SEC1'";; esac
LISTED_SECRETS=$(curl -s -H "$H" "$API/v1/triggers" | grep -c "fbx_whsec_\|callback_secret_sealed")
[ "$LISTED_SECRETS" = "0" ] && ok "list endpoint never re-exposes token/secret" || no "secret material leaked in list"

CODE=$(post "/triggers" "{\"agent\":\"$AGENT_GIT\",\"name\":\"sub2-$$\",
  \"task_template\":\"noop\",\"allow_task_override\":true,\"allow_workspace_override\":true}")
SUB2=$(cat "$B" | j "['subscription']['id']"); TOK2=$(cat "$B" | j "['token']")
[ "$CODE" = "200" ] && ok "SUB2 (overrides on) created" || no "SUB2 create → $CODE"

CODE=$(post "/triggers" "{\"agent\":\"$AGENT_GIT\",\"name\":\"sub3-$$\",
  \"task_template\":\"noop\",\"allow_workspace_override\":true,
  \"callback_url\":\"http://127.0.0.1:9/dead\"}")
SUB3=$(cat "$B" | j "['subscription']['id']"); TOK3=$(cat "$B" | j "['token']")
[ "$CODE" = "200" ] && ok "SUB3 (dead callback) created" || no "SUB3 create → $CODE"

CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"sub-bad-$$\"}")
[ "$CODE" = "400" ] && ok "template-less + no override → 400 (dead config refused)" || no "wanted 400, got $CODE"

say "TOKEN SCOPE — a trigger token is not an admin token (and vice versa)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "authorization: Bearer $TOK1" "$API/v1/sessions")
[ "$CODE" = "401" ] && ok "trigger token → GET /v1/sessions 401" || no "wanted 401, got $CODE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "authorization: Bearer $TOK1" "$API/v1/agents")
[ "$CODE" = "401" ] && ok "trigger token → GET /v1/agents 401" || no "wanted 401, got $CODE"
CODE=$(tpost "$TOK1" "/sessions" "{\"agent\":\"$AGENT\",\"task\":\"x\"}")
[ "$CODE" = "401" ] && ok "trigger token → POST /v1/sessions 401" || no "wanted 401, got $CODE"
CODE=$(tpost "$FLUIDBOX_ADMIN_TOKEN" "/triggers/$SUB1/invoke" "{}")
[ "$CODE" = "401" ] && ok "admin token cannot invoke" || no "wanted 401, got $CODE"
CODE=$(tpost "fbx_trig_garbage" "/triggers/$SUB1/invoke" "{}")
[ "$CODE" = "401" ] && ok "garbage token → 401" || no "wanted 401, got $CODE"
CODE=$(tpost "$TOK2" "/triggers/$SUB1/invoke" "{}")
[ "$CODE" = "401" ] && ok "SUB2's token cannot invoke SUB1" || no "wanted 401, got $CODE"

say "INVOKE — template + context; InvocationContext frozen"
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"context":{"ticket":"INC-42"}}' "Idempotency-Key: key-A")
S1=$(cat "$B" | j "['session_id']")
[ "$CODE" = "200" ] && [ -n "$S1" ] && ok "invoke created run $S1" || { no "invoke → $CODE: $(cat "$B")"; exit 1; }
TASK1=$(sfield "$S1" "['task']")
[ "$TASK1" = "Investigate INC-42 and report." ] && ok "template rendered the context" || no "task wrong: '$TASK1'"
TKIND=$(sfield "$S1" "['trigger']['kind']")
[ "$TKIND" = "api" ] && ok "sessions.trigger kind=api" || no "trigger kind '$TKIND'"
RSKIND=$(sfield "$S1" "['run_spec']['invocation']['kind']")
[ "$RSKIND" = "api" ] && ok "RunSpec froze invocation kind=api" || no "run_spec invocation '$RSKIND'"
RSSUB=$(sfield "$S1" "['run_spec']['invocation']['subscription_id']")
[ "$RSSUB" = "$SUB1" ] && ok "RunSpec froze the subscription id" || no "frozen subscription '$RSSUB'"

CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"context":{"wrong":"x"}}')
[ "$CODE" = "400" ] && ok "missing template key → 400" || no "wanted 400, got $CODE"

say "§17 #6 — overrides are opt-in (SUB1 off, SUB2 on)"
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"task":"pwned","context":{"ticket":"x"}}')
[ "$CODE" = "400" ] && ok "task override w/o opt-in → 400" || no "wanted 400, got $CODE"
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"workspace":{"ref":"main"},"context":{"ticket":"x"}}')
[ "$CODE" = "400" ] && ok "workspace override w/o opt-in → 400" || no "wanted 400, got $CODE"

CODE=$(tpost "$TOK2" "/triggers/$SUB2/invoke" '{"task":"custom task from caller","workspace":{"ref":"feature"}}')
S2=$(cat "$B" | j "['session_id']")
[ "$CODE" = "200" ] && ok "SUB2 override invoke accepted" || no "SUB2 invoke → $CODE: $(cat "$B")"
[ "$(sfield "$S2" "['task']")" = "custom task from caller" ] && ok "caller task honored (opt-in)" || no "task not overridden"
[ "$(sfield "$S2" "['repo_source']['ref']")" = "feature" ] && ok "workspace narrowed to ref=feature" || no "ref not narrowed"
CODE=$(tpost "$TOK2" "/triggers/$SUB2/invoke" '{"workspace":{"repository":"a/b"}}')
[ "$CODE" = "400" ] && ok "repo retarget of a file:// base → 400 (cannot escape)" || no "wanted 400, got $CODE"

say "IDEMPOTENCY — retries create exactly one run"
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"context":{"ticket":"INC-42"}}' "Idempotency-Key: key-A")
S1B=$(cat "$B" | j "['session_id']"); REPLAY=$(cat "$B" | j "['replay']")
[ "$CODE" = "200" ] && [ "$S1B" = "$S1" ] && [ "$REPLAY" = "True" ] \
  && ok "same key → same run (replay=true)" || no "replay wrong: code=$CODE id=$S1B replay=$REPLAY"
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"context":{"ticket":"OTHER"}}' "Idempotency-Key: key-A")
[ "$CODE" = "422" ] && ok "key reuse with different body → 422" || no "wanted 422, got $CODE"
N_RUNS=$(curl -s -H "$H" "$API/v1/triggers/$SUB1" | python3 -c "
import sys, json; print(len(json.load(sys.stdin)['sessions']))")
[ "$N_RUNS" = "1" ] && ok "subscription has exactly one run" || no "expected 1 run, got $N_RUNS"

say "DISABLE / ENABLE / ROTATE"
post "/triggers/$SUB1/disable" "{}" >/dev/null
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"context":{"ticket":"x"}}')
[ "$CODE" = "409" ] && ok "disabled subscription → 409" || no "wanted 409, got $CODE"
post "/triggers/$SUB1/enable" "{}" >/dev/null
CODE=$(post "/triggers/$SUB1/rotate_token" "{}")
TOK1_NEW=$(cat "$B" | j "['token']")
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"context":{"ticket":"x"}}' "Idempotency-Key: key-A")
[ "$CODE" = "401" ] && ok "old token dead after rotation" || no "wanted 401, got $CODE"
CODE=$(tpost "$TOK1_NEW" "/triggers/$SUB1/invoke" '{"context":{"ticket":"INC-42"}}' "Idempotency-Key: key-A")
[ "$CODE" = "200" ] && ok "new token works (and key-A still replays)" || no "wanted 200, got $CODE"

say "SIGNED CALLBACK — terminal run → one verified delivery (no model needed)"
FINAL1=$(wait_terminal "$S1" 240) || true
case "$FINAL1" in completed|failed) ok "S1 terminal ($FINAL1)";; *) no "S1 not terminal: $FINAL1";; esac
DFILE=""
for _ in $(seq 1 30); do
  DFILE=$(ls "$RCV_DIR"/delivery-*.json 2>/dev/null | head -1)
  [ -n "$DFILE" ] && break
  sleep 2
done
[ -n "$DFILE" ] && ok "callback received by the external service" || no "no callback within 60s"
if [ -n "$DFILE" ]; then
  TS=$(python3 -c "import json;print(json.load(open('$DFILE'))['headers']['x-fluidbox-timestamp'])")
  SIG=$(python3 -c "import json;print(json.load(open('$DFILE'))['headers']['x-fluidbox-signature'])")
  DLV=$(python3 -c "import json;print(json.load(open('$DFILE'))['headers']['x-fluidbox-delivery'])")
  BODY=$(python3 -c "import json;print(json.load(open('$DFILE'))['body'])")
  CALC="v1=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SEC1" | sed 's/^.* //')"
  [ "$CALC" = "$SIG" ] && ok "HMAC signature verifies with the shown-once secret" || no "signature mismatch"
  RUN_ID=$(python3 -c "import json;print(json.loads(json.load(open('$DFILE'))['body'])['run']['id'])")
  [ "$RUN_ID" = "$S1" ] && ok "payload carries the right run" || no "payload run '$RUN_ID'"
  PSTATUS=$(python3 -c "import json;print(json.loads(json.load(open('$DFILE'))['body'])['run']['status'])")
  [ "$PSTATUS" = "$FINAL1" ] && ok "payload status matches terminal state" || no "payload status '$PSTATUS'"
  python3 -c "
import json, sys
p = json.loads(json.load(open('$DFILE'))['body'])
assert 'cost_usd' in p['usage'] and isinstance(p['artifacts'], list) and 'summary' in p['run']
" && ok "payload has status/summary/artifacts/cost" || no "payload missing acceptance fields"
  DSTAT=$(curl -s -H "$H" "$API/v1/sessions/$S1/deliveries" | j "['deliveries'][0]['status']")
  [ "$DSTAT" = "delivered" ] && ok "delivery row marked delivered" || no "delivery status '$DSTAT'"
fi

say "DEAD DESTINATION — the run stays terminal; only the delivery retries"
CODE=$(tpost "$TOK3" "/triggers/$SUB3/invoke" '{"workspace":{"ref":"feature"},"context":{}}')
S3=$(cat "$B" | j "['session_id']")
FINAL3=$(wait_terminal "$S3" 240) || true
case "$FINAL3" in completed|failed) ok "S3 terminal ($FINAL3) despite dead callback";; *) no "S3 terminal: $FINAL3";; esac
sleep 4   # worker tick + first refused attempt
D3=$(curl -s -H "$H" "$API/v1/sessions/$S3/deliveries")
D3A=$(echo "$D3" | j "['deliveries'][0]['attempts']")
D3S=$(echo "$D3" | j "['deliveries'][0]['status']")
[ "${D3A:-0}" -ge 1 ] && [ "$D3S" != "delivered" ] && ok "dead destination: attempts=$D3A status=$D3S" \
  || no "delivery not retrying (attempts=$D3A status=$D3S)"
[ "$(sfield "$S3" "['status']")" = "$FINAL3" ] && ok "run status untouched by callback failure" || no "run status mutated!"

say "SCOPED POLLING"
CODE=$(curl -s -o "$B" -w "%{http_code}" -H "authorization: Bearer $TOK1_NEW" "$API/v1/triggers/$SUB1/runs/$S1")
[ "$CODE" = "200" ] && [ "$(cat "$B" | j "['run']['id']")" = "$S1" ] \
  && ok "trigger token polls its own run" || no "poll → $CODE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "authorization: Bearer $TOK1_NEW" "$API/v1/triggers/$SUB1/runs/$S3")
[ "$CODE" = "404" ] && ok "cannot poll another subscription's run" || no "wanted 404, got $CODE"

say "LIVE — external service borrows claude-fixer, gets the full callback"
if [ "${E2E_SKIP_LIVE:-0}" = "1" ] || [ -z "${ANTHROPIC_API_KEY:-}" ] \
   || ! curl -fsS -m 3 http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1; then
  echo "  SKIP: live tier needs ANTHROPIC_API_KEY + gateway (E2E_SKIP_LIVE=${E2E_SKIP_LIVE:-0})"
else
  CODE=$(post "/triggers" "{\"agent\":\"claude-fixer\",\"name\":\"sub-live-$$\",
    \"task_template\":\"State the result of {{a}} plus {{b}}, then stop.\",
    \"callback_url\":\"http://127.0.0.1:$RCV_PORT/cb\"}")
  SUBL=$(cat "$B" | j "['subscription']['id']"); TOKL=$(cat "$B" | j "['token']"); SECL=$(cat "$B" | j "['callback_secret']")
  CODE=$(tpost "$TOKL" "/triggers/$SUBL/invoke" '{"context":{"a":"2","b":"3"}}' "Idempotency-Key: live-1")
  SL=$(cat "$B" | j "['session_id']")
  [ "$CODE" = "200" ] && ok "live borrow started ($SL)" || no "live invoke → $CODE"
  FINALL=$(wait_terminal "$SL" 420) || true
  [ "$FINALL" = "completed" ] && ok "live run completed" || no "live terminal: $FINALL"
  LFILE=""
  for _ in $(seq 1 30); do
    LFILE=$(grep -l "$SL" "$RCV_DIR"/delivery-*.json 2>/dev/null | head -1)
    [ -n "$LFILE" ] && break
    sleep 2
  done
  if [ -n "$LFILE" ]; then
    LTS=$(python3 -c "import json;print(json.load(open('$LFILE'))['headers']['x-fluidbox-timestamp'])")
    LSIG=$(python3 -c "import json;print(json.load(open('$LFILE'))['headers']['x-fluidbox-signature'])")
    LBODY=$(python3 -c "import json;print(json.load(open('$LFILE'))['body'])")
    LCALC="v1=$(printf '%s.%s' "$LTS" "$LBODY" | openssl dgst -sha256 -hmac "$SECL" | sed 's/^.* //')"
    [ "$LCALC" = "$LSIG" ] && ok "live callback signature verifies" || no "live signature mismatch"
    python3 -c "
import json
p = json.loads(json.load(open('$LFILE'))['body'])
assert p['run']['status'] == 'completed'
assert p['usage']['cost_usd'] > 0, 'live run must have real cost'
assert p['run']['summary'], 'live run must carry a summary'
" && ok "live callback: completed + real cost + summary" || no "live payload incomplete"
  else
    no "no live callback within 60s"
  fi
fi

rm -rf "$FX" "$RCV_DIR"

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
```

`chmod +x scripts/e2e-trigger.sh`.

- [ ] **Step 2: Wire into `e2e.sh`** — update the header comment (5 phases), renumber the `say` banners, and insert between git workspaces and failure paths:

```bash
say "PHASE 4/5 — api triggers & signed callbacks"
bash "$ROOT/scripts/e2e-trigger.sh" || SUITE_FAIL=1

say "PHASE 5/5 — failure paths"
```

Update the `justfile` e2e comment: `# Full acceptance suite: live demo A + governance + git workspaces + api triggers + failure paths.`

- [ ] **Step 3: Run the FULL bar** (stop any `just dev` first):

```bash
set -a; source .env; set +a
just check          # fmt + clippy -D warnings + all tests + web build
just e2e            # all 5 phases green
```

Expected: `just check` green; `just e2e` prints ALL PHASES PASSED, with the new phase contributing ~35 checks. Fix anything that fails before committing; restart the dev server afterwards if it was running.

- [ ] **Step 4: commit**

```bash
git add scripts/e2e-trigger.sh scripts/e2e.sh justfile
git commit -m "test(e2e): api-trigger acceptance phase — scoped tokens, idempotency, signed callbacks"
```

---

### Task 10: Docs — HANDOVER rev 4 + CLAUDE.md

**Files:**
- Modify: `docs/HANDOVER.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: HANDOVER.md rev 4** — update the header line (rev 4, Phase 2 shipped, new e2e totals from the actual run), add a §1 bullet mirroring the Phase-1 bullet's density: subscriptions (§17 #6 opt-in flags), scoped tokens (`api_tokens kind='trigger'`, sha256, rotation), unified `run_service::create_run` (manual + trigger convergence), Idempotency-Key semantics (replay/422/409), InvocationContext frozen in RunSpec + `sessions.trigger`, signed callbacks (`x-fluidbox-signature: v1=hmac-sha256("{ts}.{body}")`, sealed per-subscription secrets, 6-attempt backoff, run lifecycle never blocked), dashboard Triggers page. Update §6 progress: Phase 2 ✅ with acceptance script name; Phase 3 (schedules) ⏭ next. Add rough edges honestly, at minimum: subscriptions are create/enable/disable/rotate only (no edit/delete); callback secrets are shown once and not re-showable (rotate = recreate the subscription); `concurrency_policy`/`resource_selector` columns deferred to the phases that enforce them (3 and 4); callbacks may deliver at-least-once (receivers dedup on `x-fluidbox-delivery`); crash between terminal transition and enqueue loses the delivery (no boot reconciliation yet).
- [ ] **Step 2: CLAUDE.md** — update the `just e2e` comment line (add api-triggers phase), and add to the invariants section: "**Trigger tokens are subscription-scoped** (`api_tokens.kind='trigger'`, sha256-hashed): they can invoke their one subscription and poll its runs — never the admin API. Invoke overrides are opt-in per subscription (§17 #6) and can only narrow. **Result delivery is decoupled from the run lifecycle**: `result_deliveries` rows are enqueued inside the single `orchestrator::transition` funnel on terminal entry; the retry worker signs with per-subscription sealed secrets; a callback failure can never mutate a session."
- [ ] **Step 3: Final verification + commit**

```bash
just check   # one last full bar after doc edits (cheap, catches fmt drift)
git add docs/HANDOVER.md CLAUDE.md
git commit -m "docs: handover rev 4 — design-doc Phase 2 (API triggers + signed callbacks) shipped"
```

---

## Self-Review (performed at plan-writing time)

1. **Spec coverage** — goal items ↔ tasks: scoped trigger tokens (T2 db, T5 auth, T9 scope checks); trigger_subscriptions per §10 seed (T2; `resource_selector`/`event_filter`/`concurrency_policy` deliberately deferred to Phases 3/4 where they're enforced — documented in T10); unified create_run + api.rs refactor (T4); invoke + Idempotency-Key exactly-once (T3 claims, T6 endpoint, T9 proof); InvocationContext kind=api frozen (T1, T4, T6; asserted in T9); signed callbacks via result_deliveries, async + independently retryable, run stays completed (T3, T7; proven in T9 dead-destination block); trigger + delivery status in dashboard (T8). §12 acceptance sentence is verbatim the T9 live block. §17 #6 settled decision is enforced (T6) and tested (T9).
2. **Placeholder scan** — every code step carries the actual code; the one intentionally-non-literal step is T8's page markup (structure + class names + data flow specified, mirroring an existing page in the same repo — the pattern file is named).
3. **Type consistency** — `create_session` 10-param signature consistent across T3/T4; `InvocationClaim` variants match T3 test and T6 match arms; `sign_payload(secret, ts, body)` shape matches T7 test, T7 wire headers, and T9's openssl recomputation; `result_payload(state, session, Option<Uuid>, Option<i32>)` consumed by both T6 `poll_run` and T7 `try_deliver`; `SUBSCRIPTION_COLS` used by all four subscription queries; `narrow_workspace` consumes `crate::api::valid_repo_name` made `pub(crate)` in T5.
