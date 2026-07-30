# Automation API Contract & Template Clarity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Revision 2 (2026-07-30):** incorporates the external (Codex/GPT-5.6-sol) plan review. Material changes: `CallbackUpdate::Clear` binds key_version **1** not 0 (CHECK constraint `in (1,2)`, migration 0014:51); subscription+schedule PATCH is **one atomic transaction** with an `updated_at` optimistic-concurrency guard; `UpdateTrigger` is `deny_unknown_fields` deserialized from raw JSON so immutable-field attempts 400; schedule PATCH merges omitted fields from the existing row; `Sealed` is destructured (not `split(&Some(...))`, which doesn't compile); `buildCurl` uses shell-expandable quoting and emits a `task` body for template-less automations; the event system-variable list is the full 12-name `sample_context()` set; the secrets modal is truly secrets-only; the detail page follows Shell/last-good-snapshot conventions; the response table documents **422** for idempotency-key reuse (what the server actually returns — the current modal's 409 copy is a pre-existing bug we fix in passing).

**Goal:** Make the automation API contract durable (always copyable from a new `/automations/{id}` page, live-rendered from the DB), add `PATCH /v1/triggers/{id}` for the mutable subset, and make the composer's task-template box self-explanatory.

**Architecture:** Backend: one URL helper + one ingress-path helper shared by every contract-carrying response, one pure update-resolution function + PATCH handler in `triggers.rs`, one new atomic `fluidbox-db` method (no migrations — all columns exist). Frontend: extract the contract-rendering logic into a pure lib (`automation-contract.ts`) + shared component (`AutomationContract.tsx`), consumed by a new detail page, a trimmed one-time-secrets modal, and a pre-save preview card in the composer.

**Tech Stack:** Rust (axum, sqlx, serde_json), Next.js 16 App Router (client components), vitest.

**Spec:** `docs/superpowers/specs/2026-07-29-automation-api-contract-design.md` — read it first.

## Global Constraints

- Backend is 100% Rust; the dashboard is presentation-only (all logic server-side or in pure, tested TS libs).
- Trigger token & callback secret are one-time: sha256-hashed / sealed at rest, NEVER re-shown. Recovery = rotation. Consequence for PATCH: a response that mints a secret may only be sent AFTER the transaction that stored it commits, and that transaction must be all-or-nothing.
- Absolute URLs come ONLY from the server (`FLUIDBOX_PUBLIC_URL`); the dashboard must never derive hosts.
- Trigger kind and agent are immutable on PATCH — enforced by `deny_unknown_fields` + explicit 400 mapping (serde silently ignoring unknown keys is NOT enforcement).
- `callback_secret_key_version` has `CHECK (in (1, 2))` (migration 0014:51). NULL bytes bind version 1 (the `Sealed::split` convention) — never 0.
- Tenant-owned DB methods take `TenantScope` and carry `tenant_id = $n` predicates (signature requirement).
- Do NOT run `just check` / `just e2e` / DB-backed tests (they need env or spend money; owner-triggered only). Verify with: `cargo test -p fluidbox-server`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all -- --check`, and in `apps/web`: `pnpm vitest run`, `pnpm build`.
- Next.js in this repo is newer than training data — check `node_modules/next/dist/docs/` if any App Router API surprises you. Existing pages (`apps/web/app/sessions/[id]/page.tsx`) are the pattern reference. `Shell` already wraps pages in `<main>` (`apps/web/app/components/Shell.tsx:33`) — new pages must NOT add their own `<main>`.
- Commit after every task. Commit trailer:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`

---

### Task 1: Rust — `contract_urls` + `ingress_path_for` helpers; URL fields on GET/LIST/rotate

**Files:**
- Modify: `crates/fluidbox-server/src/triggers.rs` (helpers near line 210; `create` ~line 668–681; `rotate_token` ~line 785–792; `get` ~line 698–721; `list` ~line 684–696; tests module at line 1115)

**Interfaces:**
- Produces:
  - `fn contract_urls(base: &str, sub_id: Uuid, ingress_path: Option<&str>) -> serde_json::Map<String, Value>` — keys `base_url`, `invoke_url`, `poll_url_template`, `ingress_url`.
  - `async fn ingress_path_for(state: &AppState, scope: fluidbox_db::TenantScope, sub: &fluidbox_db::TriggerSubscriptionRow) -> ApiResult<Option<String>>` — recomputes the event-ingress path (None for api/schedule kinds). Used by `get`, `rotate_token`, and Task 4's `update`.
  - `GET /v1/triggers/{id}` response gains the four URL keys; `GET /v1/triggers` gains top-level `base_url` (deliberate: the list UI never renders contracts — spec amended to match).
- Consumes: existing `connectors::connector_for(provider) -> Option<&'static str>`, `fluidbox_db::{scoped_tx, get_connection}`.

- [ ] **Step 1: Write the failing test** (append inside `mod tests` in `triggers.rs`):

```rust
#[test]
fn contract_urls_shapes_and_trims() {
    let id = Uuid::nil();
    let m = contract_urls("https://fb.example/", id, None);
    assert_eq!(m["base_url"], "https://fb.example");
    assert_eq!(
        m["invoke_url"],
        format!("https://fb.example/v1/triggers/{id}/invoke")
    );
    assert_eq!(
        m["poll_url_template"],
        format!("https://fb.example/v1/triggers/{id}/runs/{{session_id}}")
    );
    assert_eq!(m["ingress_url"], Value::Null);

    let m = contract_urls("https://fb.example", id, Some("/v1/ingress/github/app/7"));
    assert_eq!(m["ingress_url"], "https://fb.example/v1/ingress/github/app/7");
}
```

- [ ] **Step 2: Run it — must fail to compile** (`contract_urls` not defined):
`cargo test -p fluidbox-server contract_urls_shapes -- --nocapture` → expect compile error.

- [ ] **Step 3: Implement the helpers** (place after `random_hex_token`, ~line 221):

```rust
/// Caller-facing URL block for a subscription's integration contract.
/// The control plane is the only party that knows its own public address
/// (the dashboard reaches it through a same-origin proxy), so create,
/// rotate, get, and update all hand these over rather than letting a client
/// guess. Nothing here is secret: it is public_url + subscription id.
fn contract_urls(
    base: &str,
    sub_id: Uuid,
    ingress_path: Option<&str>,
) -> serde_json::Map<String, Value> {
    let base = base.trim_end_matches('/');
    let mut m = serde_json::Map::new();
    m.insert("base_url".into(), json!(base));
    m.insert(
        "invoke_url".into(),
        json!(format!("{base}/v1/triggers/{sub_id}/invoke")),
    );
    m.insert(
        "poll_url_template".into(),
        json!(format!("{base}/v1/triggers/{sub_id}/runs/{{session_id}}")),
    );
    m.insert(
        "ingress_url".into(),
        json!(ingress_path.map(|p| format!("{base}{p}"))),
    );
    m
}

/// Recompute an event subscription's ingress path (registration-level for
/// seamless connections, per-connection otherwise) so the contract is
/// rebuildable forever, not a one-time artifact of the create response.
/// api/schedule kinds have no ingress.
async fn ingress_path_for(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    sub: &fluidbox_db::TriggerSubscriptionRow,
) -> ApiResult<Option<String>> {
    let ("event", Some(cid)) = (sub.trigger_kind.as_str(), sub.connection_id) else {
        return Ok(None);
    };
    let mut tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
    let conn = fluidbox_db::get_connection(&mut *tx, scope, cid).await?;
    tx.commit().await?;
    Ok(conn.and_then(|c| {
        crate::connectors::connector_for(&c.provider).map(|connector| match c.registration_id {
            Some(rid) => format!("/v1/ingress/{connector}/app/{rid}"),
            None => format!("/v1/ingress/{connector}/{cid}"),
        })
    }))
}
```

(If the `let ("event", Some(cid)) = … else` destructuring displeases the borrow checker on `sub.trigger_kind.as_str()`, use a plain `match` returning early — behavior identical. If `get_connection`'s call shape differs, copy it from `create` at triggers.rs:426.)

- [ ] **Step 4: Test passes:** `cargo test -p fluidbox-server contract_urls_shapes` → PASS.

- [ ] **Step 5: Use the helpers in `create` and `rotate_token`.** In `create` (lines 668–681) replace the final `Ok(Json(json!({...})))` with:

```rust
    let mut body = serde_json::Map::new();
    body.insert("subscription".into(), serde_json::to_value(&sub)?);
    body.insert("schedule".into(), serde_json::to_value(&schedule_row)?);
    body.insert("token".into(), json!(token));
    body.insert("callback_secret".into(), json!(secret_plain));
    body.insert("ingress_path".into(), json!(ingress_path));
    body.extend(contract_urls(
        &state.cfg.public_url,
        sub.id,
        ingress_path.as_deref(),
    ));
    Ok(Json(Value::Object(body)))
```

In `rotate_token` (lines 785–792) replace the final `Ok(Json(json!({...})))` with:

```rust
    let ingress_path = ingress_path_for(&state, scope, &sub).await?;
    let mut body = serde_json::Map::new();
    body.insert("token".into(), json!(token));
    body.insert("revoked".into(), json!(revoked));
    body.extend(contract_urls(
        &state.cfg.public_url,
        sub.id,
        ingress_path.as_deref(),
    ));
    Ok(Json(Value::Object(body)))
```

- [ ] **Step 6: Add URLs to `get`.** Replace the body of `get` after the four fetches (lines 717–720) with:

```rust
    let ingress_path = ingress_path_for(&state, scope, &sub).await?;
    let mut body = serde_json::Map::new();
    body.insert("subscription".into(), serde_json::to_value(&sub)?);
    body.insert("schedule".into(), serde_json::to_value(&schedule)?);
    body.insert("sessions".into(), serde_json::to_value(&sessions)?);
    body.insert("deliveries".into(), serde_json::to_value(&deliveries)?);
    body.insert("invocations".into(), serde_json::to_value(&invocations)?);
    body.extend(contract_urls(
        &state.cfg.public_url,
        sub.id,
        ingress_path.as_deref(),
    ));
    Ok(Json(Value::Object(body)))
```

- [ ] **Step 7: Add `base_url` to `list`** (line 693):

```rust
    Ok(Json(json!({
        "subscriptions": subscriptions,
        "schedules": schedules,
        "base_url": state.cfg.public_url.trim_end_matches('/'),
    })))
```

- [ ] **Step 8: Verify:** `cargo test -p fluidbox-server && cargo clippy -p fluidbox-server -- -D warnings` → all green.

- [ ] **Step 9: Commit:** `git add crates/fluidbox-server/src/triggers.rs && git commit -m "feat(server): contract URL + ingress helpers on trigger get/list/rotate"`

---

### Task 2: Rust — `UpdateTrigger` (deny_unknown_fields), `ScheduleUpdate`, pure `resolve_update` + `merge_schedule` + tests

**Files:**
- Modify: `crates/fluidbox-server/src/triggers.rs` (new structs + fns after `CreateTrigger`/`ScheduleInput`, ~line 288; tests in `mod tests`)

**Interfaces:**
- Produces:

```rust
/// PATCH body — the mutable surface ONLY. deny_unknown_fields is the
/// immutability enforcement: `agent`, `trigger_kind`, `connection`, etc.
/// are refused with 400, not silently ignored (serde's default would
/// otherwise accept-and-drop them, returning a lying 200).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTrigger {
    #[serde(default)] pub name: Option<String>,
    /// Some("") clears the template (valid only when the resolved state
    /// still passes the dead-config rule); omitted = unchanged.
    #[serde(default)] pub task_template: Option<String>,
    #[serde(default)] pub allow_task_override: Option<bool>,
    #[serde(default)] pub allow_workspace_override: Option<bool>,
    #[serde(default)] pub concurrency_policy: Option<String>,
    /// Some("") removes the signed-webhook callback; Some(url) sets/replaces
    /// it (mints a new secret, returned once); omitted = unchanged.
    #[serde(default)] pub callback_url: Option<String>,
    /// Schedule-kind subscriptions only. Partial: omitted fields keep the
    /// existing schedule's values (a cron-only PATCH must NOT reset
    /// timezone/missed policy to defaults).
    #[serde(default)] pub schedule: Option<ScheduleUpdate>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleUpdate {
    #[serde(default)] pub cron: Option<String>,
    #[serde(default)] pub timezone: Option<String>,
    #[serde(default)] pub missed_run_policy: Option<String>,
}

impl UpdateTrigger {
    /// True when the PATCH names nothing — the handler answers with the
    /// current state WITHOUT writing (an empty {} must not advance
    /// updated_at; the detail page's "as of" stamp would lie).
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.task_template.is_none()
            && self.allow_task_override.is_none()
            && self.allow_workspace_override.is_none()
            && self.concurrency_policy.is_none()
            && self.callback_url.is_none()
            && self.schedule.is_none()
    }
}

pub(crate) struct ResolvedUpdate {
    pub name: String,
    pub task_template: Option<String>,
    pub allow_task_override: bool,
    pub allow_workspace_override: bool,
    pub concurrency_policy: String,
}

fn resolve_update(
    current: &fluidbox_db::TriggerSubscriptionRow,
    req: &UpdateTrigger,
    render_ctx: Option<&std::collections::BTreeMap<String, String>>,
) -> Result<ResolvedUpdate, String>

/// Merge a partial schedule PATCH over the existing row → (cron, timezone,
/// missed_run_policy), all still to be validated by the caller.
fn merge_schedule(
    current: &fluidbox_db::ScheduleRow,
    upd: &ScheduleUpdate,
) -> (String, String, String)
```

- Consumes: `render_task_template` (triggers.rs:38), `ConcurrencyPolicy::parse` (already imported).

- [ ] **Step 1: Write the failing tests** (append inside `mod tests`):

```rust
    fn sub_row(kind: &str, template: Option<&str>, allow_task: bool) -> fluidbox_db::TriggerSubscriptionRow {
        fluidbox_db::TriggerSubscriptionRow {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            agent_id: Uuid::nil(),
            name: "n".into(),
            trigger_kind: kind.into(),
            pinned_revision_id: None,
            enabled: true,
            task_template: template.map(str::to_string),
            allow_task_override: allow_task,
            allow_workspace_override: false,
            autonomy: None,
            concurrency_policy: "allow".into(),
            budget_override: None,
            workspace_override: None,
            result_destinations: json!([]),
            connection_id: None,
            resource_selector: None,
            event_filter: None,
            event_publish: None,
            capability_bundles: None,
            authority_generation: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn upd() -> UpdateTrigger {
        UpdateTrigger {
            name: None,
            task_template: None,
            allow_task_override: None,
            allow_workspace_override: None,
            concurrency_policy: None,
            callback_url: None,
            schedule: None,
        }
    }

    #[test]
    fn update_trigger_refuses_unknown_fields() {
        // Immutability enforcement: agent/kind are not silently ignored.
        for body in [r#"{"agent":"other"}"#, r#"{"trigger_kind":"schedule"}"#] {
            assert!(serde_json::from_str::<UpdateTrigger>(body).is_err(), "{body}");
        }
        let ok: UpdateTrigger = serde_json::from_str(r#"{"name":"x"}"#).unwrap();
        assert!(!ok.is_empty());
        let empty: UpdateTrigger = serde_json::from_str("{}").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn resolve_update_keeps_omitted_fields() {
        let cur = sub_row("api", Some("do {{ticket}}"), false);
        let r = resolve_update(&cur, &upd(), None).unwrap();
        assert_eq!(r.name, "n");
        assert_eq!(r.task_template.as_deref(), Some("do {{ticket}}"));
        assert_eq!(r.concurrency_policy, "allow");
    }

    #[test]
    fn resolve_update_rejects_dead_config() {
        let cur = sub_row("api", Some("t"), false);
        let mut req = upd();
        req.task_template = Some("  ".into());
        assert!(resolve_update(&cur, &req, None).is_err());
        let cur = sub_row("api", Some("t"), true);
        let r = resolve_update(&cur, &req, None).unwrap();
        assert_eq!(r.task_template, None);
    }

    #[test]
    fn resolve_update_rejects_empty_name_and_bad_concurrency() {
        let cur = sub_row("api", Some("t"), false);
        let mut req = upd();
        req.name = Some("  ".into());
        assert!(resolve_update(&cur, &req, None).is_err());
        let mut req = upd();
        req.concurrency_policy = Some("sometimes".into());
        assert!(resolve_update(&cur, &req, None).is_err());
    }

    #[test]
    fn resolve_update_revalidates_template_against_kind_context() {
        let cur = sub_row("schedule", Some("sweep at {{fire_time}}"), false);
        let mut req = upd();
        req.task_template = Some("do {{ticket}}".into()); // not in schedule ctx
        let ctx = ctx(&[("fire_time", "2026-01-01T00:00:00Z")]);
        assert!(resolve_update(&cur, &req, Some(&ctx)).is_err());
        req.task_template = Some("sweep {{fire_time}} again".into());
        let r = resolve_update(&cur, &req, Some(&ctx)).unwrap();
        assert_eq!(r.task_template.as_deref(), Some("sweep {{fire_time}} again"));
        // A schedule can never clear its template (there is no caller).
        req.task_template = Some("".into());
        assert!(resolve_update(&cur, &req, Some(&ctx)).is_err());
    }

    #[test]
    fn merge_schedule_keeps_omitted_fields() {
        let row = fluidbox_db::ScheduleRow {
            id: Uuid::nil(),
            subscription_id: Uuid::nil(),
            cron: "0 9 * * 1-5".into(),
            timezone: "America/Chicago".into(),
            next_fire_at: None,
            missed_run_policy: "catch_up".into(),
            last_fired_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        // A cron-only PATCH must not reset timezone/missed policy.
        let upd = ScheduleUpdate { cron: Some("0 8 * * *".into()), timezone: None, missed_run_policy: None };
        let (cron, tz, missed) = merge_schedule(&row, &upd);
        assert_eq!((cron.as_str(), tz.as_str(), missed.as_str()), ("0 8 * * *", "America/Chicago", "catch_up"));
    }
```

(`sub_row` / the `ScheduleRow` literal need those structs' fields `pub` — they already are, fluidbox-db/src/lib.rs:3721 and :6890. If either gains fields, the compile error tells you what to add.)

- [ ] **Step 2: Run — expect compile failure:** `cargo test -p fluidbox-server resolve_update -- --nocapture`

- [ ] **Step 3: Implement** (structs from **Interfaces** verbatim, plus):

```rust
fn resolve_update(
    current: &fluidbox_db::TriggerSubscriptionRow,
    req: &UpdateTrigger,
    render_ctx: Option<&std::collections::BTreeMap<String, String>>,
) -> Result<ResolvedUpdate, String> {
    let name = match &req.name {
        None => current.name.clone(),
        Some(n) => {
            let n = n.trim();
            if n.is_empty() {
                return Err("name must not be empty".into());
            }
            n.to_string()
        }
    };
    let concurrency_policy = match &req.concurrency_policy {
        None => current.concurrency_policy.clone(),
        Some(c) => {
            if ConcurrencyPolicy::parse(c).is_none() {
                return Err("concurrency_policy must be allow | skip_if_running | replace".into());
            }
            c.clone()
        }
    };
    let allow_task_override = req.allow_task_override.unwrap_or(current.allow_task_override);
    let allow_workspace_override = req
        .allow_workspace_override
        .unwrap_or(current.allow_workspace_override);
    let task_template = match &req.task_template {
        None => current.task_template.clone(),
        Some(t) => {
            let t = t.trim();
            if t.is_empty() { None } else { Some(t.to_string()) }
        }
    };
    // The create-time dead-config rule holds across every edit.
    if task_template.is_none() && !allow_task_override {
        return Err("provide a task_template or set allow_task_override".into());
    }
    // Schedule/event kinds fire with no caller: the template must exist and
    // must render from the kind's sample context alone.
    if let Some(ctx) = render_ctx {
        let tpl = task_template.as_deref().ok_or_else(|| {
            format!(
                "a {} subscription needs a task_template (there is no caller)",
                current.trigger_kind
            )
        })?;
        render_task_template(tpl, ctx).map_err(|e| {
            format!(
                "task_template must render from the {} context ({}): {e}",
                current.trigger_kind,
                ctx.keys()
                    .map(|k| format!("{{{{{k}}}}}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        })?;
    }
    Ok(ResolvedUpdate {
        name,
        task_template,
        allow_task_override,
        allow_workspace_override,
        concurrency_policy,
    })
}

fn merge_schedule(
    current: &fluidbox_db::ScheduleRow,
    upd: &ScheduleUpdate,
) -> (String, String, String) {
    (
        upd.cron.as_deref().unwrap_or(&current.cron).trim().to_string(),
        upd.timezone
            .as_deref()
            .unwrap_or(&current.timezone)
            .to_string(),
        upd.missed_run_policy
            .as_deref()
            .unwrap_or(&current.missed_run_policy)
            .to_string(),
    )
}
```

- [ ] **Step 4: Tests pass:** `cargo test -p fluidbox-server -- resolve_update merge_schedule update_trigger_refuses` → 6 PASS. If clippy flags dead code before Task 4 wires the handler, add `#[allow(dead_code)]` on the new items temporarily and REMOVE it in Task 4. `cargo clippy -p fluidbox-server -- -D warnings`.

- [ ] **Step 5: Commit:** `git add crates/fluidbox-server/src/triggers.rs && git commit -m "feat(server): pure PATCH resolution for trigger subscriptions"`

---

### Task 3: Rust — atomic DB method `update_trigger_subscription` (subscription + schedule, one tx, stale-guard)

**Files:**
- Modify: `crates/fluidbox-db/src/lib.rs` (after `set_trigger_subscription_enabled` ~line 3908)

**Interfaces:**
- Produces:

```rust
/// What PATCH does to the callback destination: leave it alone, remove it,
/// or replace it with a freshly sealed secret. Owns its data — the sealed
/// bytes are produced inside the handler's match arm.
pub enum CallbackUpdate {
    Keep,
    Clear,
    Set { destinations: Value, sealed: Vec<u8>, key_version: i16 },
}

pub struct ScheduleConfigUpdate {
    pub cron: String,
    pub timezone: String,
    pub missed_run_policy: String,
    pub next_fire_at: DateTime<Utc>,
}

#[allow(clippy::too_many_arguments)]
pub async fn update_trigger_subscription(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    expect_updated_at: DateTime<Utc>,
    name: &str,
    task_template: Option<&str>,
    allow_task_override: bool,
    allow_workspace_override: bool,
    concurrency_policy: &str,
    callback: CallbackUpdate,
    schedule: Option<&ScheduleConfigUpdate>,
) -> sqlx::Result<Option<(TriggerSubscriptionRow, Option<ScheduleRow>)>>
```

Semantics the handler relies on:
- ONE `scoped_tx` for both writes. A schedule failure rolls the subscription back — a newly sealed callback secret is never committed unless the whole PATCH lands, so the one-time reveal in the response can never orphan.
- `expect_updated_at` is an optimistic-concurrency guard (`and updated_at = $x`); a stale or vanished row returns `Ok(None)` — the handler answers 409. Two concurrent PATCHes can no longer silently overwrite each other's fields (the full-row write makes lost updates otherwise easy).
- Any callback change (Set OR Clear) bumps `authority_generation`, so `subscription_secret` bindings frozen on the old secret fail closed.
- NULL sealed bytes bind key_version **1** — `callback_secret_key_version` is `CHECK (in (1, 2))` (migration 0014:51); the version is moot when the bytes are null, same convention as `seal.rs::Sealed::split`.
- `schedule: Some(_)` when no schedules row exists returns `Err(sqlx::Error::RowNotFound)` (rolls back) — the handler pre-validated the kind, so this only fires on genuine corruption/races.

- Consumes: `scoped_tx`, `SUBSCRIPTION_COLS`, `TriggerSubscriptionRow`, `ScheduleRow` (all existing).

No DB-free test exists for this (DB tests need `DATABASE_URL` and are owner-triggered); correctness is carried by the SQL shape below + compile + the drill in Task 10. Follow the file's existing `scoped_tx`/`__rls_out` idiom.

- [ ] **Step 1: Implement** (after `set_trigger_subscription_enabled`):

```rust
pub async fn update_trigger_subscription(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    expect_updated_at: DateTime<Utc>,
    name: &str,
    task_template: Option<&str>,
    allow_task_override: bool,
    allow_workspace_override: bool,
    concurrency_policy: &str,
    callback: CallbackUpdate,
    schedule: Option<&ScheduleConfigUpdate>,
) -> sqlx::Result<Option<(TriggerSubscriptionRow, Option<ScheduleRow>)>> {
    // key_version 1 when bytes are NULL: the column CHECKs in (1,2) and the
    // version is moot without bytes (Sealed::split's convention).
    let (cb_touched, cb_dests, cb_sealed, cb_kv): (bool, Value, Option<Vec<u8>>, i16) =
        match callback {
            CallbackUpdate::Keep => (false, Value::Array(vec![]), None, 1),
            CallbackUpdate::Clear => (true, Value::Array(vec![]), None, 1),
            CallbackUpdate::Set { destinations, sealed, key_version } => {
                (true, destinations, Some(sealed), key_version)
            }
        };
    let mut tx = scoped_tx(pool, scope).await?;

    let sub: Option<TriggerSubscriptionRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update trigger_subscriptions set
           name = $2, task_template = $3, allow_task_override = $4,
           allow_workspace_override = $5, concurrency_policy = $6,
           result_destinations = case when $7 then $8 else result_destinations end,
           callback_secret_sealed = case when $7 then $9 else callback_secret_sealed end,
           callback_secret_key_version =
             case when $7 then $10 else callback_secret_key_version end,
           authority_generation =
             authority_generation + case when $7 then 1 else 0 end,
           updated_at = now()
         where id = $1 and tenant_id = $11 and updated_at = $12
         returning {SUBSCRIPTION_COLS}"
    )))
    .bind(id)
    .bind(name)
    .bind(task_template)
    .bind(allow_task_override)
    .bind(allow_workspace_override)
    .bind(concurrency_policy)
    .bind(cb_touched)
    .bind(cb_dests)
    .bind(cb_sealed)
    .bind(cb_kv)
    .bind(scope.tenant_id())
    .bind(expect_updated_at)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(sub) = sub else {
        // Stale expect_updated_at or vanished row: nothing written, tx drops.
        return Ok(None);
    };

    let schedule_row = match schedule {
        None => None,
        Some(s) => Some(
            sqlx::query_as::<_, ScheduleRow>(
                "update schedules set cron = $2, timezone = $3,
                   missed_run_policy = $4, next_fire_at = $5, updated_at = now()
                 where subscription_id = $1
                   and exists (select 1 from trigger_subscriptions sub
                               where sub.id = $1 and sub.tenant_id = $6)
                 returning *",
            )
            .bind(id)
            .bind(&s.cron)
            .bind(&s.timezone)
            .bind(&s.missed_run_policy)
            .bind(s.next_fire_at)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?
            // A schedule-kind subscription without its schedules row is
            // corruption; error → the WHOLE tx (incl. the subscription
            // update above) rolls back.
            .ok_or(sqlx::Error::RowNotFound)?,
        ),
    };

    tx.commit().await?;
    Ok(Some((sub, schedule_row)))
}
```

- [ ] **Step 2: Compile clean:** `cargo clippy -p fluidbox-db -- -D warnings`.

- [ ] **Step 3: Commit:** `git add crates/fluidbox-db/src/lib.rs && git commit -m "feat(db): atomic subscription+schedule update with stale guard"`

---

### Task 4: Rust — `PATCH /v1/triggers/{id}` handler + route

**Files:**
- Modify: `crates/fluidbox-server/src/triggers.rs` (new `update` handler after `get`, ~line 721)
- Modify: `crates/fluidbox-server/src/main.rs:533` (route)

**Interfaces:**
- Consumes: Task 1's `contract_urls`/`ingress_path_for`; Task 2's `UpdateTrigger`/`ScheduleUpdate`/`resolve_update`/`merge_schedule`; Task 3's `update_trigger_subscription`/`CallbackUpdate`/`ScheduleConfigUpdate`; existing `schedule_context`, `connectors::{connector_for, sample_context}`, `egress::admit_url`, `seal::{Sealed, SealCtx, SealFamily}`, `random_hex_token`, `SECRET_PREFIX`, `CronSchedule`, `MissedRunPolicy`, `schedule_for_subscription`.
- Produces: `PATCH /v1/triggers/{id}` → `{ subscription, schedule, callback_secret, base_url, invoke_url, poll_url_template, ingress_url }`. `callback_secret` non-null ONLY when a new callback was set (shown once). Errors: 400 unknown/immutable field or validation, 404 unknown id, 409 concurrent edit (or name collision), 403 RBAC.

- [ ] **Step 1: Implement the handler** (after `get`). Note the extractor: `Json<Value>` + `from_value`, NOT `Json<UpdateTrigger>` — axum's rejection for a deserialization failure is a 422 with its own body; the immutable-field refusal must be OUR 400 naming the field:

```rust
/// PATCH — the mutable surface only: name, task_template, overrides,
/// concurrency_policy, callback_url, and (schedule kind) the clock. Trigger
/// kind and agent are immutable: UpdateTrigger is deny_unknown_fields, so a
/// PATCH naming them (or anything else) is a 400, never a silent no-op.
/// In-flight runs keep their frozen RunSpec; future firings use the updated
/// values — the platform's existing immutability model.
pub async fn update(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(raw): Json<Value>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_manage_subscriptions(&principal) {
        return Err(ApiError::Forbidden(
            "managing trigger subscriptions requires admin or owner".into(),
        ));
    }
    let req: UpdateTrigger = serde_json::from_value(raw).map_err(|e| {
        ApiError::BadRequest(format!(
            "invalid PATCH body ({e}). Mutable fields: name, task_template, \
             allow_task_override, allow_workspace_override, concurrency_policy, \
             callback_url, schedule{{cron,timezone,missed_run_policy}}. \
             Trigger kind and agent are immutable — create a new automation instead."
        ))
    })?;
    let scope = principal.scope();
    let current = fluidbox_db::get_trigger_subscription(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let existing_schedule =
        fluidbox_db::schedule_for_subscription(&state.pool, scope, id).await?;

    // An empty {} PATCH answers with current state, WITHOUT writing — the
    // "as of" stamp must not advance for a no-op.
    if req.is_empty() {
        let ingress_path = ingress_path_for(&state, scope, &current).await?;
        let mut body = serde_json::Map::new();
        body.insert("subscription".into(), serde_json::to_value(&current)?);
        body.insert("schedule".into(), serde_json::to_value(&existing_schedule)?);
        body.insert("callback_secret".into(), Value::Null);
        body.extend(contract_urls(&state.cfg.public_url, current.id, ingress_path.as_deref()));
        return Ok(Json(Value::Object(body)));
    }

    // The kind's no-caller render context, when it has one.
    let render_ctx = match current.trigger_kind.as_str() {
        "schedule" => Some(schedule_context("2026-01-01T00:00:00Z")),
        "event" => {
            let cid = current.connection_id.ok_or_else(|| {
                ApiError::Internal("event subscription has no connection".into())
            })?;
            let mut tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
            let conn = fluidbox_db::get_connection(&mut *tx, scope, cid)
                .await?
                .ok_or(ApiError::NotFound)?;
            tx.commit().await?;
            let connector = crate::connectors::connector_for(&conn.provider)
                .ok_or_else(|| {
                    ApiError::Internal(format!("provider '{}' has no connector", conn.provider))
                })?;
            Some(crate::connectors::sample_context(connector))
        }
        _ => None,
    };
    let resolved =
        resolve_update(&current, &req, render_ctx.as_ref()).map_err(ApiError::BadRequest)?;

    // Callback: same admission + sealing as create; any change bumps the
    // subscription's authority generation (Task 3 handles the bump).
    let (callback, secret_plain) = match req.callback_url.as_deref().map(str::trim) {
        None => (fluidbox_db::CallbackUpdate::Keep, None),
        Some("") => (fluidbox_db::CallbackUpdate::Clear, None),
        Some(url) => {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(ApiError::BadRequest("callback_url must be http(s)".into()));
            }
            crate::egress::admit_url(url, &state.egress_policy)
                .map_err(|e| ApiError::BadRequest(format!("callback_url rejected: {e}")))?;
            let sealer = state.sealer.as_ref().ok_or_else(|| {
                ApiError::BadRequest(
                    "signed callbacks are disabled: set FLUIDBOX_CREDENTIAL_KEY on the server"
                        .into(),
                )
            })?;
            let secret = random_hex_token(SECRET_PREFIX);
            let sealed = sealer
                .seal(
                    &secret,
                    crate::seal::SealCtx::new(
                        scope.tenant_id(),
                        crate::seal::SealFamily::SubscriptionCallbackSecret,
                    ),
                )
                .await?;
            let dests = serde_json::to_value(vec![ResultDestination::SignedWebhook {
                url: url.to_string(),
                binding_id: None,
            }])?;
            // Destructure the owned Sealed — do NOT call Sealed::split on a
            // temporary Option (it returns a borrow of the temporary and
            // does not compile).
            let crate::seal::Sealed { bytes, key_version } = sealed;
            (
                fluidbox_db::CallbackUpdate::Set {
                    destinations: dests,
                    sealed: bytes,
                    key_version,
                },
                Some(secret),
            )
        }
    };

    // Schedule: only meaningful on a schedule subscription; PARTIAL — omitted
    // fields keep the existing row's values (a cron-only PATCH must not
    // reset America/Chicago to UTC).
    let schedule_cfg = match &req.schedule {
        None => None,
        Some(s) => {
            if current.trigger_kind != "schedule" {
                return Err(ApiError::BadRequest(
                    "only schedule subscriptions carry a schedule".into(),
                ));
            }
            let row = existing_schedule.as_ref().ok_or_else(|| {
                ApiError::Internal("schedule subscription has no schedule row".into())
            })?;
            let (cron_expr, tz, missed) = merge_schedule(row, s);
            let cron = CronSchedule::parse(&cron_expr, &tz).map_err(ApiError::BadRequest)?;
            if MissedRunPolicy::parse(&missed).is_none() {
                return Err(ApiError::BadRequest(
                    "missed_run_policy must be skip | catch_up".into(),
                ));
            }
            let first = cron.next_fire_after(chrono::Utc::now()).ok_or_else(|| {
                ApiError::BadRequest("cron expression never fires in the future".into())
            })?;
            Some(fluidbox_db::ScheduleConfigUpdate {
                cron: cron_expr,
                timezone: tz,
                missed_run_policy: missed,
                next_fire_at: first,
            })
        }
    };

    let updated = fluidbox_db::update_trigger_subscription(
        &state.pool,
        scope,
        id,
        current.updated_at,
        &resolved.name,
        resolved.task_template.as_deref(),
        resolved.allow_task_override,
        resolved.allow_workspace_override,
        &resolved.concurrency_policy,
        callback,
        schedule_cfg.as_ref(),
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => ApiError::Conflict(format!(
            "a trigger named '{}' already exists",
            resolved.name
        )),
        _ => ApiError::Db(e),
    })?;
    let Some((sub, updated_schedule)) = updated else {
        // The stale-guard fired: someone else edited between our read and
        // write. Nothing was written; the one-time secret (if minted) was
        // never stored and dies here with this error.
        return Err(ApiError::Conflict(
            "the automation changed since it was loaded — reload and retry".into(),
        ));
    };

    let schedule = match updated_schedule {
        Some(row) => Some(row),
        None => fluidbox_db::schedule_for_subscription(&state.pool, scope, id).await?,
    };
    let ingress_path = ingress_path_for(&state, scope, &sub).await?;
    let mut body = serde_json::Map::new();
    body.insert("subscription".into(), serde_json::to_value(&sub)?);
    body.insert("schedule".into(), serde_json::to_value(&schedule)?);
    body.insert("callback_secret".into(), json!(secret_plain));
    body.extend(contract_urls(&state.cfg.public_url, sub.id, ingress_path.as_deref()));
    Ok(Json(Value::Object(body)))
}
```

(If `Sealed`'s fields aren't `pub`, check crates/fluidbox-server/src/seal.rs:139 — they are (`pub bytes`, `pub key_version`).)

- [ ] **Step 2: Register the route.** In `main.rs:533`:

```rust
        .route("/triggers/{id}", get(triggers::get).patch(triggers::update))
```

adding `patch` to the `axum::routing` import if absent.

- [ ] **Step 3: Remove any temporary `#[allow(dead_code)]` from Task 2.**

- [ ] **Step 4: Verify:** `cargo test -p fluidbox-server && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check` → green.

- [ ] **Step 5: Commit:** `git add crates/ && git commit -m "feat(server): PATCH /v1/triggers/{id} for the mutable subscription surface"`

---

### Task 5: Web — pure contract lib + tests

**Files:**
- Create: `apps/web/app/lib/automation-contract.ts`
- Create: `apps/web/app/lib/automation-contract.test.ts`
- Modify: `apps/web/app/components/RunComposer.tsx` (delete the local `SYSTEM_VARIABLES` at line 1709 and `templateVariables` at line 1715; import from the lib)

**Interfaces:**
- Produces (exact exports later tasks import):

```ts
export const SYSTEM_VARIABLES: Record<string, string[]>;
export function templateVariables(template: string | null): string[];
/** invalid: placeholders a no-caller kind (schedule/event) declares that the
 *  platform does NOT fill — save will refuse them; surfaced as errors. */
export function classifyVariables(kind: string, template: string | null): { caller: string[]; system: string[]; invalid: string[] };
export function contextExample(caller: string[]): string;
/** token null → $FLUIDBOX_TRIGGER_TOKEN in DOUBLE quotes (shell-expandable).
 *  hasTemplate false → the body carries "task" (a template-less automation
 *  requires the caller to send one; {} would 400 at invoke). */
export function buildCurl(opts: { invokeUrl: string; token: string | null; caller: string[]; hasTemplate: boolean }): string;
```

- [ ] **Step 1: Write the failing tests** (`automation-contract.test.ts`):

```ts
import { describe, expect, it } from "vitest";
import {
  buildCurl,
  classifyVariables,
  contextExample,
  SYSTEM_VARIABLES,
  templateVariables,
} from "./automation-contract";

describe("templateVariables", () => {
  it("extracts unique placeholder names", () => {
    expect(templateVariables("do {{ticket}} for {{ team }} re {{ticket}}")).toEqual([
      "ticket",
      "team",
    ]);
    expect(templateVariables(null)).toEqual([]);
  });
});

describe("classifyVariables", () => {
  it("api kind: everything is caller-supplied, nothing invalid", () => {
    const r = classifyVariables("api", "do {{ticket}}");
    expect(r).toEqual({ caller: ["ticket"], system: [], invalid: [] });
  });
  it("schedule kind: fire_time is system, anything else is invalid (no caller exists)", () => {
    const r = classifyVariables("schedule", "sweep {{fire_time}} for {{team}}");
    expect(r.system).toEqual(["fire_time"]);
    expect(r.caller).toEqual([]);
    expect(r.invalid).toEqual(["team"]);
  });
  it("event kind knows the full GitHub context, not just three names", () => {
    // Mirrors connectors/github.rs sample_context() — 12 variables.
    expect(SYSTEM_VARIABLES.event).toEqual([
      "repository", "pr_number", "pr_title", "pr_url", "pr_author",
      "head_sha", "head_ref", "base_sha", "base_ref", "action", "event", "fork",
    ]);
    const r = classifyVariables("event", "review {{pr_url}} by {{pr_author}} ({{oops}})");
    expect(r.system).toEqual(["pr_url", "pr_author"]);
    expect(r.invalid).toEqual(["oops"]);
  });
});

describe("buildCurl", () => {
  const url = "https://fb.example/v1/triggers/x/invoke";
  it("real token rides in single quotes", () => {
    expect(
      buildCurl({ invokeUrl: url, token: "fbx_trig_abc", caller: [], hasTemplate: true })
    ).toContain("-H 'Authorization: Bearer fbx_trig_abc'");
  });
  it("durable form uses DOUBLE quotes so the shell expands the variable", () => {
    const durable = buildCurl({ invokeUrl: url, token: null, caller: ["ticket"], hasTemplate: true });
    expect(durable).toContain('-H "Authorization: Bearer ${FLUIDBOX_TRIGGER_TOKEN}"');
    expect(durable).toContain('"ticket": "…"');
  });
  it("template-less automation sends a task, not {} (invoke would 400)", () => {
    const c = buildCurl({ invokeUrl: url, token: null, caller: [], hasTemplate: false });
    expect(c).toContain('"task"');
    expect(c).not.toContain("-d '{}'");
  });
});

describe("contextExample", () => {
  it("is {} with no caller variables", () => {
    expect(contextExample([])).toBe("{}");
    expect(contextExample(["a", "b"])).toBe('{"context": {"a": "…", "b": "…"}}');
  });
});
```

- [ ] **Step 2: Run — fail:** `cd apps/web && pnpm vitest run app/lib/automation-contract.test.ts` → module not found.

- [ ] **Step 3: Implement the lib:**

```ts
/** Pure integration-contract helpers shared by the composer preview, the
 *  one-time secrets modal, and the durable automation detail page. Keeping
 *  them here (tested, presentation-free) is what lets three surfaces render
 *  the SAME contract without drifting. */

/** Placeholders the platform fills in itself, per trigger kind. Anything
 *  else is the caller's (api kind) or refused at save (schedule/event fire
 *  with no caller). The event list mirrors connectors/github.rs
 *  sample_context() — keep them in lockstep. */
export const SYSTEM_VARIABLES: Record<string, string[]> = {
  schedule: ["fire_time"],
  event: [
    "repository", "pr_number", "pr_title", "pr_url", "pr_author",
    "head_sha", "head_ref", "base_sha", "base_ref", "action", "event", "fork",
  ],
  api: [],
};

export function templateVariables(template: string | null): string[] {
  if (!template) return [];
  const found = new Set<string>();
  for (const match of template.matchAll(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g)) {
    found.add(match[1]);
  }
  return [...found];
}

export function classifyVariables(
  kind: string,
  template: string | null
): { caller: string[]; system: string[]; invalid: string[] } {
  const systemNames = SYSTEM_VARIABLES[kind] ?? [];
  const declared = templateVariables(template);
  const system = declared.filter((name) => systemNames.includes(name));
  const rest = declared.filter((name) => !systemNames.includes(name));
  // schedule/event fire with no caller: an unknown placeholder can never be
  // filled and the server refuses it at save — that's an error, not a
  // caller variable.
  const noCaller = kind === "schedule" || kind === "event";
  return {
    system,
    caller: noCaller ? [] : rest,
    invalid: noCaller ? rest : [],
  };
}

export function contextExample(caller: string[]): string {
  if (caller.length === 0) return "{}";
  return `{"context": {${caller.map((name) => `"${name}": "…"`).join(", ")}}}`;
}

/** token null → the durable view: the secret is the caller's to hold, so
 *  the curl reads it from the environment — double quotes, or the shell
 *  ships the literal dollar text. hasTemplate false → the automation has no
 *  stored template (override-only), so invoke REQUIRES a task in the body. */
export function buildCurl(opts: {
  invokeUrl: string;
  token: string | null;
  caller: string[];
  hasTemplate: boolean;
}): string {
  const auth = opts.token
    ? `  -H 'Authorization: Bearer ${opts.token}' \\`
    : `  -H "Authorization: Bearer \${FLUIDBOX_TRIGGER_TOKEN}" \\`;
  const body = opts.hasTemplate
    ? contextExample(opts.caller)
    : `{"task": "…what this invocation should do…"}`;
  return [
    `curl -X POST '${opts.invokeUrl}' \\`,
    auth,
    `  -H 'Content-Type: application/json' \\`,
    `  -H 'Idempotency-Key: <your-unique-key>' \\`,
    `  -d '${body}'`,
  ].join("\n");
}
```

- [ ] **Step 4: Point RunComposer at the lib.** Delete `SYSTEM_VARIABLES` (RunComposer.tsx:1709-1713) and `templateVariables` (1715-1722); delete the hand-rolled `curl`/`contextExample` construction inside `ShowAutomationSecrets` (lines 1768-1779) and replace with:

```ts
  const { caller: callerVars, system: systemVars } = classifyVariables(kind, sub.task_template);
  const declared = [...callerVars, ...systemVars];
  const curl = buildCurl({
    invokeUrl,
    token: minted.token,
    caller: callerVars,
    hasTemplate: !!sub.task_template,
  });
```

adding the import `import { buildCurl, classifyVariables } from "../lib/automation-contract";`. (This JSX moves again in Task 6 — the point here is that the lib compiles in place of the deleted locals.)

- [ ] **Step 5: Verify:** `pnpm vitest run` and `pnpm build` → green.

- [ ] **Step 6: Commit:** `git add apps/web/app/lib/automation-contract.* apps/web/app/components/RunComposer.tsx && git commit -m "feat(web): extract pure automation-contract helpers"`

---

### Task 6: Web — shared `AutomationContract` component; secrets modal becomes secrets-ONLY

**Files:**
- Create: `apps/web/app/components/AutomationContract.tsx`
- Modify: `apps/web/app/components/RunComposer.tsx` (`CopyBlock` at 1724-1747 moves out; `ShowAutomationSecrets` at 1749-1926 shrinks to secrets + link)
- Modify: `apps/web/app/globals.css` (one new class)

**Interfaces:**
- Produces:

```tsx
export function CopyBlock({ label, value, hint }: { label: string; value: string; hint?: string });
export function AutomationContract({
  subscription,   // TriggerSubscription
  invokeUrl,      // string
  pollUrl,        // string
  ingressUrl,     // string | null
  token,          // string | null — null renders the ${FLUIDBOX_TRIGGER_TOKEN} form
  updatedAt,      // string | null — renders the "as of" stamp when given
}: {...});
export function TemplateChips({ kind, template }: { kind: string; template: string });
```

- Consumes: Task 5's lib; `TriggerSubscription` from `../lib/api`.

- [ ] **Step 1: Create `AutomationContract.tsx`.** Move `CopyBlock` verbatim from RunComposer (1724-1747). Build `AutomationContract` from the Endpoint / Variables / Request / Responses / Result-delivery JSX currently in `ShowAutomationSecrets` (lines 1822-1916), with these changes — the shipped file contains the real JSX, adapted, not references to it:
  - `sub` → `subscription`; `minted.ingress_url` → `ingressUrl`; the curl comes from `buildCurl({ invokeUrl, token, caller: callerVars, hasTemplate: !!subscription.task_template })`.
  - **Kind-aware sections:** `api` kind renders Endpoint (Invoke + Poll CopyBlocks) + Request (curl). `event` kind renders the Webhook-ingress CopyBlock (when `ingressUrl`) + a note ("Runs start from repository events — there is no API caller to authenticate."). `schedule` kind renders a note ("Runs start on the clock — there is no API caller.") — no invoke curl for either no-caller kind. Variables + Responses + Result-delivery render for all kinds.
  - The Variables section renders `invalid` names (from `classifyVariables`) with an error style and the caption "not available — save refuses this placeholder"; `caller` names say "you supply it in `context`"; `system` names say "filled in by fluidbox".
  - **Responses:** the success example becomes `<CopyBlock label="Success" value={responseExample} />`. The error rows become: `409` — "a run is already active and this automation is set to `{subscription.concurrency_policy}`"; `422` — "the Idempotency-Key was already used with a different request body" (the modal's old text claimed 409 for this — the server returns 422, triggers.rs:975); `400` — "an override this subscription does not allow"; `401` — "wrong token, or the token was revoked".
  - Result-delivery section renders when the subscription HAS a signed-webhook destination: `subscription.result_destinations.some((d) => d.kind === "signed_webhook")` — verify the discriminant with `grep -n "signed_webhook" apps/web/app/lib/api.ts crates/fluidbox-core/src/spec.rs` and match whatever serde emits.
  - Bottom: `{updatedAt && <p className="contract-stamp">Reflects the configuration as of {new Date(updatedAt).toLocaleString()}.</p>}`
  - Add `TemplateChips` (also consumed by Tasks 8 & 9):

```tsx
/** Live placeholder read-back under a template textarea: which {{names}}
 *  the caller supplies, which the platform fills, and which a no-caller
 *  kind can never fill (save will refuse those). */
export function TemplateChips({ kind, template }: { kind: string; template: string }) {
  const { caller, system, invalid } = classifyVariables(kind, template || null);
  if (caller.length === 0 && system.length === 0 && invalid.length === 0) return null;
  return (
    <div className="tpl-chips">
      {caller.map((name) => (
        <span key={name} className="tpl-chip caller" title="Caller supplies this in `context`">
          {`{{${name}}}`} · caller
        </span>
      ))}
      {system.map((name) => (
        <span key={name} className="tpl-chip system" title="Filled in by fluidbox">
          {`{{${name}}}`} · fluidbox
        </span>
      ))}
      {invalid.map((name) => (
        <span key={name} className="tpl-chip invalid" title="This trigger has no caller and fluidbox does not fill this name — saving will be refused">
          {`{{${name}}}`} · unknown
        </span>
      ))}
    </div>
  );
}
```

- [ ] **Step 2: Shrink `ShowAutomationSecrets` to secrets-only.** Per spec: the modal keeps the ModalShell chrome (title/sub/dirty/discard copy, lines 1795-1804), the **Secrets** section (1806-1820), and the footer. DELETE the Endpoint/Variables/Request/Responses/Result-delivery sections (1822-1916) — they do NOT reappear here via `AutomationContract`; the durable page is their home. In their place, one pointer block:

```tsx
        <section className="contract-section">
          <h4>Where everything else lives</h4>
          <p className="contract-note">
            The endpoint, request shape, variables, and response contract are always
            available at{" "}
            <Link className="link" href={`/automations/${sub.id}`} onClick={onClose}>
              Automations → {sub.name} → API
            </Link>
            {" "}— only the secrets above are shown once. Lost token? Rotate it there.
          </p>
        </section>
```

The now-dead locals (`curl`, `responseExample`, `declared`/`callerVars`/`systemVars`, `contextExample` remnants, `invokeUrl`/`pollUrl` if unused) get deleted; keep whichever the remaining JSX still needs. Update the modal `sub=` copy (line 1798) to: "The token and signing secret exist only in this response — they are stored hashed and sealed and can never be shown again. Everything else stays available on the automation's page."

- [ ] **Step 3: CSS** — append next to the existing `.contract-*` rules (grep `contract-note` in `apps/web/app/globals.css`), reusing whatever muted-text/border variables `.field-hint` and existing badges use:

```css
.contract-stamp { font-size: 12px; color: var(--muted); margin: 4px 0 0; }
.tpl-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.tpl-chip { font-family: var(--mono, monospace); font-size: 11px; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--border); }
.tpl-chip.system { opacity: 0.7; }
.tpl-chip.invalid { border-color: var(--err, #b3423f); color: var(--err, #b3423f); }
```

- [ ] **Step 4: Verify:** `pnpm build && pnpm vitest run` → green.

- [ ] **Step 5: Commit:** `git add apps/web && git commit -m "feat(web): shared AutomationContract; secrets modal is secrets-only"`

---

### Task 7: Web — types + `/automations/[id]` read-only detail page

**Files:**
- Modify: `apps/web/app/lib/api.ts` (TriggerSubscription at line 684: add `updated_at: string;` after `created_at`; add `TriggerDetail`)
- Modify: `apps/web/app/components/AutomationPanel.tsx` (export `AutomationActivity`; title links)
- Create: `apps/web/app/automations/[id]/page.tsx`
- Modify: `apps/web/app/globals.css`

**Interfaces:**
- Produces: route `/automations/{id}`; `api.ts` gains:

```ts
/** GET /v1/triggers/{id} — subscription + activity + the caller-facing URLs
 *  (server-derived from FLUIDBOX_PUBLIC_URL; the dashboard never builds hosts). */
export interface TriggerDetail {
  subscription: TriggerSubscription;
  schedule: Schedule | null;
  sessions: Session[];
  deliveries: ResultDelivery[];
  invocations: TriggerInvocation[];
  base_url: string;
  invoke_url: string;
  poll_url_template: string;
  ingress_url: string | null;
}
```

- Consumes: Task 6's `AutomationContract`, existing `ShowAutomationSecrets` + rotate endpoint, `AutomationActivity` (change `function AutomationActivity` to `export function AutomationActivity` at AutomationPanel.tsx:253), `apiGetCached` for the agent name.

- [ ] **Step 1: api.ts** — add `updated_at` to `TriggerSubscription` and the `TriggerDetail` interface. `Session`, `ResultDelivery`, `TriggerInvocation`, `Schedule` already exist in the file.

- [ ] **Step 2: Export `AutomationActivity`** (AutomationPanel.tsx:253) and link each row to the page — in `AutomationRow` (line 215) wrap the name:

```tsx
            <Link className="link" href={`/automations/${subscription.id}`}>
              <strong>{subscription.name}</strong>
            </Link>
```

and add an "Open →" link beside the "Activity" button:

```tsx
          <Link className="btn ghost sm" href={`/automations/${subscription.id}`}>
            Open →
          </Link>
```

(`Link` is already imported at line 4.)

- [ ] **Step 3: Create `apps/web/app/automations/[id]/page.tsx`.** (`apps/web/app/automations/page.tsx` redirects `/automations` → `/?view=automations`; a `[id]` sibling does not conflict.) Conventions this page MUST follow — both flagged by review against the codebase: `Shell` already wraps pages in `<main>` (Shell.tsx:33), so the page root is a `<div>`; and a refresh failure keeps the last good snapshot (the pattern at page.tsx:44) instead of blanking a loaded page:

```tsx
"use client";

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  Agent,
  apiGet,
  apiGetCached,
  apiPost,
  TriggerDetail,
  TriggerSubscription,
} from "../../lib/api";
import { AutomationContract } from "../../components/AutomationContract";
import { AutomationActivity } from "../../components/AutomationPanel";
import { MintedAutomation, ShowAutomationSecrets } from "../../components/RunComposer";
import { LoadingRows } from "../../components/bits";

export default function AutomationDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [detail, setDetail] = useState<TriggerDetail | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loadErr, setLoadErr] = useState("");
  const [actionErr, setActionErr] = useState("");
  const [minted, setMinted] = useState<MintedAutomation | null>(null);

  const load = useCallback(async () => {
    try {
      const [detailResponse, agentResponse] = await Promise.all([
        apiGet<TriggerDetail>(`/triggers/${id}`),
        apiGetCached<{ agents: Agent[] }>("/agents", { maxAgeMs: 15_000 }),
      ]);
      setDetail(detailResponse);
      setAgents(agentResponse.agents);
      setLoadErr("");
    } catch (error) {
      // Keep the last good snapshot; surface the failure without blanking.
      setLoadErr(String(error));
    }
  }, [id]);
  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async (subscription: TriggerSubscription) => {
    setActionErr("");
    try {
      await apiPost(`/triggers/${id}/${subscription.enabled ? "disable" : "enable"}`, {});
      await load();
    } catch (error) {
      setActionErr(String(error));
    }
  };

  const rotate = async (subscription: TriggerSubscription) => {
    setActionErr("");
    try {
      const response = await apiPost<{
        token: string;
        base_url: string | null;
        invoke_url: string | null;
        poll_url_template: string | null;
        ingress_url?: string | null;
      }>(`/triggers/${id}/rotate_token`, {});
      setMinted({
        subscription,
        token: response.token,
        callback_secret: null,
        rotated: true,
        base_url: response.base_url,
        invoke_url: response.invoke_url,
        poll_url_template: response.poll_url_template,
        ingress_url: response.ingress_url ?? null,
      });
    } catch (error) {
      setActionErr(String(error));
    }
  };

  if (!detail) {
    return (
      <div className="automation-detail">
        {loadErr ? <div className="err">{loadErr}</div> : <LoadingRows />}
      </div>
    );
  }
  const sub = detail.subscription;
  const agentName = agents.find((agent) => agent.id === sub.agent_id)?.name ?? null;
  return (
    <div className="automation-detail">
      <header className="automation-detail-head">
        <div>
          <div className="automation-title-line">
            <span className="automation-kind">
              {sub.trigger_kind === "schedule" ? "Schedule" : sub.trigger_kind === "event" ? "Event" : "API"}
            </span>
            <h1>{sub.name}</h1>
            <span className={`badge ${sub.enabled ? "ok" : ""}`}>
              {sub.enabled ? "enabled" : "disabled"}
            </span>
          </div>
          <p className="automation-intro">
            Runs{" "}
            {agentName ? (
              <Link className="link" href="/agents">
                <b>{agentName}</b>
              </Link>
            ) : (
              <span className="mono">{sub.agent_id.slice(0, 8)}</span>
            )}
            {detail.schedule?.next_fire_at && (
              <> · next run {new Date(detail.schedule.next_fire_at).toLocaleString()}</>
            )}
            {" · "}
            <Link className="link" href="/?view=automations">
              All automations
            </Link>
          </p>
        </div>
        <div className="automation-actions">
          <button className="btn ghost sm" type="button" onClick={() => void rotate(sub)}>
            Rotate token
          </button>
          <button className="btn sm" type="button" onClick={() => void toggle(sub)}>
            {sub.enabled ? "Disable" : "Enable"}
          </button>
        </div>
      </header>
      {loadErr && <div className="note">Refresh failed — showing the last loaded state. {loadErr}</div>}
      {actionErr && <div className="err">{actionErr}</div>}

      <section className="automation-detail-section">
        <h2>API</h2>
        <AutomationContract
          subscription={sub}
          invokeUrl={detail.invoke_url}
          pollUrl={detail.poll_url_template}
          ingressUrl={detail.ingress_url}
          token={null}
          updatedAt={sub.updated_at}
        />
      </section>

      {/* Configuration + Template sections land in Task 8. */}

      <section className="automation-detail-section">
        <h2>Activity</h2>
        <AutomationActivity id={sub.id} />
      </section>
      {minted && (
        <ShowAutomationSecrets
          minted={minted}
          onClose={() => {
            setMinted(null);
            void load();
          }}
        />
      )}
    </div>
  );
}
```

If `MintedAutomation` lacks an `ingress_url` field, it already has one (RunComposer.tsx:110) — pass it through. If `/agents` is not the agents route, grep `href="/agents"` in Sidebar.tsx and use whatever it uses.

- [ ] **Step 4: CSS** — append near the `.automation-panel` rules:

```css
.automation-detail { max-width: 880px; margin: 0 auto; padding: 24px 16px 64px; }
.automation-detail-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 8px; }
.automation-detail-head h1 { font-size: 20px; margin: 0; }
.automation-detail-section { margin-top: 28px; }
.automation-detail-section > h2 { font-size: 15px; margin: 0 0 10px; }
```

- [ ] **Step 5: Verify:** `pnpm build` green. First manual checkpoint (needs the dev stack — coordinate with the owner): create an API automation, close the secrets modal, open `/automations/{id}`, confirm the contract renders the `${FLUIDBOX_TRIGGER_TOKEN}` curl, copy works, Rotate shows the one-time modal, and a schedule automation shows NO invoke curl but does show variables + next-fire.

- [ ] **Step 6: Commit:** `git add apps/web && git commit -m "feat(web): durable /automations/{id} page with live API contract"`

---

### Task 8: Web — edit flows on the detail page (template + settings)

**Files:**
- Modify: `apps/web/app/automations/[id]/page.tsx`

**Interfaces:**
- Consumes: `apiPatch` (api.ts:138), Task 6's `TemplateChips`/`CopyBlock`, `ScheduleBuilder` from `../../components/ScheduleBuilder`.
- Produces: `PATCH /triggers/{id}` calls with bodies shaped like Task 4's `UpdateTrigger` (partial `schedule` object included).

- [ ] **Step 1: Template section** (between API and Activity):

```tsx
      <section className="automation-detail-section">
        <h2>Task template</h2>
        <TemplateSection detail={detail} onSaved={load} />
      </section>
```

```tsx
function TemplateSection({ detail, onSaved }: { detail: TriggerDetail; onSaved: () => Promise<void> }) {
  const sub = detail.subscription;
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(sub.task_template ?? "");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");

  const save = async () => {
    setSaving(true);
    setErr("");
    try {
      await apiPatch(`/triggers/${sub.id}`, { task_template: draft });
      setEditing(false);
      await onSaved();
    } catch (error) {
      setErr(String(error)); // server names the missing placeholder/context
    } finally {
      setSaving(false);
    }
  };

  if (!editing) {
    return (
      <div>
        {sub.task_template ? (
          <>
            <pre className="token">{sub.task_template}</pre>
            <TemplateChips kind={sub.trigger_kind} template={sub.task_template} />
          </>
        ) : (
          <p className="contract-note">
            No template — every invocation must supply its own task (task override is on).
          </p>
        )}
        <button
          className="btn ghost sm"
          type="button"
          onClick={() => {
            setDraft(sub.task_template ?? "");
            setEditing(true);
          }}
        >
          Edit template
        </button>
      </div>
    );
  }
  return (
    <div className="field">
      <textarea
        className="inp run-task-input"
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
      />
      <TemplateChips kind={sub.trigger_kind} template={draft} />
      <span className="field-hint">
        Future firings use the new template immediately; runs already in flight keep the
        configuration they started with.
      </span>
      {err && <div className="err">{err}</div>}
      <div className="automation-actions">
        <button className="btn primary sm" type="button" disabled={saving} onClick={() => void save()}>
          {saving ? "Saving…" : "Save template"}
        </button>
        <button className="btn ghost sm" type="button" disabled={saving} onClick={() => setEditing(false)}>
          Cancel
        </button>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Configuration section** (between API and Template). `SettingsSection` mirrors `TemplateSection`'s view/edit toggle. View mode: a `rows`-style list of name, autonomy, concurrency policy, task/workspace override flags, callback destination (`sub.result_destinations.find((d) => d.kind === "signed_webhook")?.url ?? "none"` — same discriminant as Task 6), and for schedule kind the cron/timezone/missed policy + next fire from `detail.schedule`. Edit mode: input for name (`inp`), checkboxes for the two overrides (`check`), select for concurrency (same three options as RunComposer.tsx:1504-1508), input for callback URL with the hint "Clearing removes the signed callback; changing it mints a NEW signing secret shown once", and for schedule kind `ScheduleBuilder` (cron/timezone) + missed-policy select (options from RunComposer.tsx:892-895). Save sends ONLY touched fields — and for schedules, only touched schedule keys (the PATCH schedule object is partial by design):

```tsx
    const body: Record<string, unknown> = {};
    if (name !== sub.name) body.name = name;
    if (allowTask !== sub.allow_task_override) body.allow_task_override = allowTask;
    if (allowWorkspace !== sub.allow_workspace_override) body.allow_workspace_override = allowWorkspace;
    if (concurrency !== sub.concurrency_policy) body.concurrency_policy = concurrency;
    if (callbackUrl !== initialCallbackUrl) body.callback_url = callbackUrl; // "" clears
    if (sub.trigger_kind === "schedule" && detail.schedule) {
      const scheduleBody: Record<string, string> = {};
      if (cron !== detail.schedule.cron) scheduleBody.cron = cron;
      if (timezone !== detail.schedule.timezone) scheduleBody.timezone = timezone;
      if (missed !== detail.schedule.missed_run_policy) scheduleBody.missed_run_policy = missed;
      if (Object.keys(scheduleBody).length > 0) body.schedule = scheduleBody;
    }
    if (Object.keys(body).length === 0) {
      setEditing(false);
      return; // nothing touched — do not send an empty PATCH
    }
    const response = await apiPatch<{ callback_secret: string | null }>(`/triggers/${sub.id}`, body);
    if (response.callback_secret) setNewSecret(response.callback_secret);
```

A 409 from the server means a concurrent edit — surface it verbatim (the message says reload and retry). When `callback_secret` returns, render it in a `CopyBlock` inside a dismissable note: "New callback signing secret — copy it now, it will not be shown again."

- [ ] **Step 3: Verify:** `pnpm build && pnpm vitest run` green. Manual: edit the template on a live automation → API section variables + curl update after save, "as of" stamp advances; cron-only schedule edit leaves the timezone untouched.

- [ ] **Step 4: Commit:** `git add apps/web && git commit -m "feat(web): edit template and settings on the automation detail page"`

---

### Task 9: Web — composer template box + pre-save API preview

**Files:**
- Modify: `apps/web/app/components/RunComposer.tsx` (label block 954-966; `templateHint` 758-763; `blockingIssue` 598-632; aside panel after the Guardrails SpecRow ~line 1619)
- Modify: `apps/web/app/globals.css`

**Interfaces:**
- Consumes: Task 5's `buildCurl`/`classifyVariables`, Task 6's `TemplateChips` (from `./AutomationContract`), `apiGetCached` (already imported in RunComposer).

- [ ] **Step 1: Relabel the template field** (replace lines 954-966):

```tsx
            <label className="field">
              <span className="lab">
                {mode === "once"
                  ? "What should the agent accomplish?"
                  : kind === "api"
                    ? "Task template — rendered for every API invocation"
                    : kind === "schedule"
                      ? "Task template — rendered at every scheduled firing"
                      : "Task template — rendered for every matching PR event"}
                {mode === "automation" && kind === "api" && allowTask && (
                  <span className="optional-label"> optional — callers may send their own task</span>
                )}
              </span>
              <textarea
                className="inp run-task-input"
                value={task}
                onChange={(event) => setTask(event.target.value)}
                placeholder={
                  mode === "once"
                    ? "Review the latest changes, identify regressions, and prepare a safe patch…"
                    : kind === "schedule"
                      ? "Sweep the queue as of {{fire_time}} and file a summary…"
                      : kind === "event"
                        ? "Review {{repository}} PR #{{pr_number}}: {{pr_title}}…"
                        : "Investigate {{ticket}} and report the root cause…"
                }
              />
              {mode === "automation" && <TemplateChips kind={kind} template={task} />}
              {mode === "automation" && <span className="field-hint">{templateHint}</span>}
            </label>
```

and tighten `templateHint` (758-763):

```tsx
  const templateHint =
    kind === "schedule"
      ? "Saved with the automation. {{fire_time}} is filled in at each firing; any other {{name}} is refused at save (a schedule has no caller to supply it)."
      : kind === "event"
        ? "Saved with the automation. Pull-request values ({{repository}}, {{pr_number}}, {{pr_title}}, {{pr_url}}, {{pr_author}}, …) are filled from the event; any other {{name}} is refused at save."
        : "Saved with the automation. Every {{name}} you add becomes a required context value the API caller sends on invoke.";
```

- [ ] **Step 2: `blockingIssue` gains the no-caller rule** (insert after the existing dead-config check at lines 614-616):

```tsx
      if (mode === "automation" && (kind === "schedule" || kind === "event") && !task.trim()) {
        return "This trigger fires without a caller — write the task template it should run.";
      }
```

- [ ] **Step 3: API preview card** in the aside, after the Guardrails `SpecRow` (~line 1619):

```tsx
            {!agentOnly && mode === "automation" && kind === "api" && !blockingIssue && (
              <ApiPreview task={task} allowTask={allowTask} />
            )}
```

with the component (place near `SpecRow` at the bottom). The base URL is SERVER truth — fetched from the list endpoint Task 1 extended, never derived from `window.location`:

```tsx
/** Pre-save preview of the integration contract. Deliberately labeled a
 *  preview: the id and token exist only after save, so those two are
 *  placeholders — but the base URL is the server's real answer. */
function ApiPreview({ task, allowTask }: { task: string; allowTask: boolean }) {
  const [copied, setCopied] = useState(false);
  const [baseUrl, setBaseUrl] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    apiGetCached<{ base_url?: string }>("/triggers", { maxAgeMs: 60_000 })
      .then((response) => {
        if (!cancelled && response.base_url) setBaseUrl(response.base_url);
      })
      .catch(() => {
        /* preview keeps the {base_url} placeholder */
      });
    return () => {
      cancelled = true;
    };
  }, []);
  const { caller } = classifyVariables("api", task || null);
  const hasTemplate = task.trim().length > 0;
  const curl = buildCurl({
    invokeUrl: `${baseUrl ?? "{base_url}"}/v1/triggers/{id-assigned-on-save}/invoke`,
    token: "<minted-on-save>",
    caller,
    hasTemplate: hasTemplate || !allowTask,
  });
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(curl);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard unavailable — the text is selectable either way */
    }
  };
  return (
    <div className="rc-api-preview">
      <div className="contract-head">
        <span className="rc-row-label">API preview</span>
        <button type="button" className="btn ghost sm" onClick={copy}>
          {copied ? "Copied" : "Copy preview"}
        </button>
      </div>
      <pre className="token rc-api-preview-curl">{curl}</pre>
      <span className="field-hint">
        The id and one-time token are minted when you save; the full contract then lives on
        the automation&apos;s page.
      </span>
    </div>
  );
}
```

Imports to add at the top of RunComposer: `buildCurl, classifyVariables` from `../lib/automation-contract` (buildCurl may already be there from Task 5); `TemplateChips` from `./AutomationContract`.

CSS:

```css
.rc-api-preview { margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); }
.rc-api-preview-curl { font-size: 11px; max-height: 140px; overflow: auto; }
```

- [ ] **Step 4: Verify:** `pnpm build && pnpm vitest run` green. Manual: Automation → API call → preview appears once valid (with the real base URL after the fetch lands), disappears on Schedule kind; chips update as you type `{{ticket}}`; typing `{{oops}}` on a Schedule automation shows the red "unknown" chip AND the save is blocked server-side if forced.

- [ ] **Step 5: Commit:** `git add apps/web && git commit -m "feat(web): self-explanatory template box + pre-save API preview"`

---

### Task 10: Full verification + lifecycle drill

**Files:** none new.

- [ ] **Step 1: Full hermetic verification** (NOT `just check` — dotenv):

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test -p fluidbox-core
cargo test -p fluidbox-server
cd apps/web && pnpm vitest run && pnpm build
```

All must pass; paste outputs in the report.

- [ ] **Step 2: Manual lifecycle drill** (needs the dev stack; coordinate with the owner before starting anything):
1. Configure Run → Automation → API call: new label, chips for `{{ticket}}`, API preview with the server's real base URL, "Copy preview" copies shell-valid curl.
2. Save → secrets modal shows ONLY token/secret + the link; follow it → `/automations/{id}`.
3. Contract shows `-H "Authorization: Bearer ${FLUIDBOX_TRIGGER_TOKEN}"`; export the env var and paste the copied curl VERBATIM into a shell → 200 (this is the finding-6 regression test).
4. Hard-refresh → identical (persistence).
5. Edit template (add `{{env}}`) → save → variables + curl show `env`, "as of" stamp advanced.
6. `PATCH {"agent":"x"}` via curl → 400 naming immutable fields; `PATCH {}` → 200 and the stamp did NOT advance.
7. Two tabs: edit in one, then save in the other → 409 "changed since it was loaded".
8. Settings: set a callback URL → new signing secret shown once; clear it → gone; check `authority_generation` bumped (visible in the DB or just trust the 200s).
9. Schedule automation: cron-only edit → timezone/missed policy unchanged, next-fire updated; template with `{{nope}}` → error naming the schedule context.
10. Event automation (if one exists): detail page shows ingress URL, no invoke curl; template chips know `{{pr_url}}`/`{{pr_author}}`.
11. Rotate token → one-time modal → close → page still shows placeholder form.

- [ ] **Step 3: Report results** to the owner, including anything skipped and why. Offer `scripts/governance-e2e.sh` / `just e2e` ONLY as an owner-triggered follow-up.

- [ ] **Step 4: Final commit if the drill produced fixes**, message `fix(web/server): lifecycle drill follow-ups for automation contract`.
