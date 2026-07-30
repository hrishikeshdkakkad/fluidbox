# Automation API Contract & Template Clarity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the automation API contract durable (always copyable from a new `/automations/{id}` page, live-rendered from the DB), add `PATCH /v1/triggers/{id}` for the mutable subset, and make the composer's task-template box self-explanatory.

**Architecture:** Backend: one URL helper shared by create/rotate/get/list, one pure update-resolution function + PATCH handler in `triggers.rs`, two new `fluidbox-db` methods (no migrations — all columns exist). Frontend: extract the contract-rendering logic into a pure lib (`automation-contract.ts`) + shared component (`AutomationContract.tsx`), consumed by a new detail page, a trimmed one-time-secrets modal, and a pre-save preview card in the composer.

**Tech Stack:** Rust (axum, sqlx, serde_json), Next.js 16 App Router (client components), vitest.

**Spec:** `docs/superpowers/specs/2026-07-29-automation-api-contract-design.md` — read it first.

## Global Constraints

- Backend is 100% Rust; the dashboard is presentation-only (all logic server-side or in pure, tested TS libs).
- Trigger token & callback secret are one-time: sha256-hashed / sealed at rest, NEVER re-shown. Recovery = rotation.
- Absolute URLs come ONLY from the server (`FLUIDBOX_PUBLIC_URL`); the dashboard must never derive hosts.
- Trigger kind and agent are immutable on PATCH (400 attempts are impossible by schema — the fields simply don't exist on the request struct).
- Tenant-owned DB methods take `TenantScope` and carry `tenant_id = $n` predicates (signature requirement).
- Do NOT run `just check` / `just e2e` / DB-backed tests (they need env or spend money; owner-triggered only). Verify with: `cargo test -p fluidbox-server`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all -- --check`, and in `apps/web`: `pnpm vitest run`, `pnpm build`.
- Next.js in this repo is newer than training data — check `node_modules/next/dist/docs/` if any App Router API surprises you. Existing pages (`apps/web/app/sessions/[id]/page.tsx`) are the pattern reference.
- Commit after every task. Commit trailer:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`

---

### Task 1: Rust — `contract_urls` helper + URL fields on GET/LIST

**Files:**
- Modify: `crates/fluidbox-server/src/triggers.rs` (helper near line 210; `create` ~line 668–681; `rotate_token` ~line 785–792; `get` ~line 698–721; `list` ~line 684–696; tests module at line 1115)
- Modify: `crates/fluidbox-server/src/main.rs` (no route change in this task)

**Interfaces:**
- Produces: `fn contract_urls(base: &str, sub_id: Uuid, ingress_path: Option<&str>) -> serde_json::Map<String, Value>` — keys `base_url`, `invoke_url`, `poll_url_template`, `ingress_url`. `GET /v1/triggers/{id}` response gains those four keys; `GET /v1/triggers` gains top-level `base_url`.
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

- [ ] **Step 3: Implement the helper** (place after `random_hex_token`, ~line 221):

```rust
/// Caller-facing URL block for a subscription's integration contract.
/// The control plane is the only party that knows its own public address
/// (the dashboard reaches it through a same-origin proxy), so create,
/// rotate, get, and list all hand these over rather than letting a client
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
```

- [ ] **Step 4: Test passes:** `cargo test -p fluidbox-server contract_urls_shapes` → PASS.

- [ ] **Step 5: Use it in `create` and `rotate_token`** (replace the hand-built duplicate blocks). In `create` (lines 668–681) replace the final `Ok(Json(json!({...})))` with:

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
    let mut body = serde_json::Map::new();
    body.insert("token".into(), json!(token));
    body.insert("revoked".into(), json!(revoked));
    body.extend(contract_urls(&state.cfg.public_url, sub.id, None));
    Ok(Json(Value::Object(body)))
```

- [ ] **Step 6: Add URLs to `get`.** Event subscriptions recompute their ingress path the same way `create` derived it (registration-level for seamless, per-connection otherwise). Replace the body of `get` after the four fetches (lines 717–720) with:

```rust
    // Recompute the ingress path for event subscriptions so the contract is
    // rebuildable forever, not a one-time artifact of the create response.
    let ingress_path = match (sub.trigger_kind.as_str(), sub.connection_id) {
        ("event", Some(cid)) => {
            let mut tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
            let conn = fluidbox_db::get_connection(&mut *tx, scope, cid).await?;
            tx.commit().await?;
            conn.and_then(|c| {
                crate::connectors::connector_for(&c.provider).map(|connector| {
                    match c.registration_id {
                        Some(rid) => format!("/v1/ingress/{connector}/app/{rid}"),
                        None => format!("/v1/ingress/{connector}/{cid}"),
                    }
                })
            })
        }
        _ => None,
    };
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

- [ ] **Step 8: Verify:** `cargo test -p fluidbox-server && cargo clippy -p fluidbox-server -- -D warnings` → all green. (If `get_connection`'s signature differs from `get_connection(&mut *tx, scope, cid)`, copy the exact call shape from `create` at triggers.rs:426.)

- [ ] **Step 9: Commit:** `git add crates/fluidbox-server/src/triggers.rs && git commit -m "feat(server): return contract URLs on trigger get/list"`

---

### Task 2: Rust — pure `resolve_update` + tests

**Files:**
- Modify: `crates/fluidbox-server/src/triggers.rs` (new struct + fn after `CreateTrigger`/`ScheduleInput`, ~line 288; tests in `mod tests`)

**Interfaces:**
- Produces:

```rust
#[derive(Deserialize)]
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
    /// Schedule-kind subscriptions only.
    #[serde(default)] pub schedule: Option<ScheduleInput>,
}

pub(crate) struct ResolvedUpdate {
    pub name: String,
    pub task_template: Option<String>,
    pub allow_task_override: bool,
    pub allow_workspace_override: bool,
    pub concurrency_policy: String,
}

/// Pure field resolution + validation for PATCH. `render_ctx` is the kind's
/// sample context for schedule/event subscriptions (the template must render
/// from it alone — there is no caller); None for api-kind (callers supply
/// context, unknown placeholders are theirs to fill).
fn resolve_update(
    current: &fluidbox_db::TriggerSubscriptionRow,
    req: &UpdateTrigger,
    render_ctx: Option<&BTreeMap<String, String>>,
) -> Result<ResolvedUpdate, String>
```

- Consumes: `render_task_template` (triggers.rs:38), `ConcurrencyPolicy::parse` (already imported).

- [ ] **Step 1: Write the failing tests** (append inside `mod tests`; the tests build a minimal `TriggerSubscriptionRow` via a helper):

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
    fn resolve_update_keeps_omitted_fields() {
        let cur = sub_row("api", Some("do {{ticket}}"), false);
        let r = resolve_update(&cur, &upd(), None).unwrap();
        assert_eq!(r.name, "n");
        assert_eq!(r.task_template.as_deref(), Some("do {{ticket}}"));
        assert_eq!(r.concurrency_policy, "allow");
    }

    #[test]
    fn resolve_update_rejects_dead_config() {
        // Clearing the template while override stays off = a subscription
        // that can never produce a task (mirrors the create-time rule).
        let cur = sub_row("api", Some("t"), false);
        let mut req = upd();
        req.task_template = Some("  ".into());
        assert!(resolve_update(&cur, &req, None).is_err());
        // …but clearing is fine when the caller may supply the task.
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
```

Note: `sub_row` needs `TriggerSubscriptionRow`'s fields to be `pub` — they already are (fluidbox-db/src/lib.rs:3721). If the struct gains fields between now and implementation, update the literal; the compile error tells you.

- [ ] **Step 2: Run — expect compile failure** (`UpdateTrigger`/`resolve_update` undefined):
`cargo test -p fluidbox-server resolve_update -- --nocapture`

- [ ] **Step 3: Implement** (after `ScheduleInput`, before `create`):

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
```

(Add `UpdateTrigger` + `ResolvedUpdate` exactly as in **Interfaces** above.)

- [ ] **Step 4: Tests pass:** `cargo test -p fluidbox-server resolve_update` → 4 PASS. Expect a dead-code warning on `UpdateTrigger.callback_url`/`schedule` until Task 4 — suppress nothing; the handler lands two tasks later, so if clippy blocks, add `#[allow(dead_code)]` on `resolve_update` temporarily and REMOVE it in Task 4. `cargo clippy -p fluidbox-server -- -D warnings`.

- [ ] **Step 5: Commit:** `git add crates/fluidbox-server/src/triggers.rs && git commit -m "feat(server): pure PATCH resolution for trigger subscriptions"`

---

### Task 3: Rust — DB methods `update_trigger_subscription` + `update_schedule_config`

**Files:**
- Modify: `crates/fluidbox-db/src/lib.rs` (after `set_trigger_subscription_enabled` ~line 3908; after `create_schedule` ~line 6931)

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

#[allow(clippy::too_many_arguments)]
pub async fn update_trigger_subscription(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    name: &str,
    task_template: Option<&str>,
    allow_task_override: bool,
    allow_workspace_override: bool,
    concurrency_policy: &str,
    callback: CallbackUpdate,
) -> sqlx::Result<Option<TriggerSubscriptionRow>>

pub async fn update_schedule_config(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    cron: &str,
    timezone: &str,
    missed_run_policy: &str,
    next_fire_at: DateTime<Utc>,
) -> sqlx::Result<Option<ScheduleRow>>
```

- Consumes: `scoped_tx`, `SUBSCRIPTION_COLS`, `TriggerSubscriptionRow`, `ScheduleRow` (all existing).

No DB-free test exists for these (DB tests need `DATABASE_URL` and are owner-triggered); correctness is carried by the SQL shape below + compile + the manual drill in Task 10. Follow the file's existing `scoped_tx`/`__rls_out` idiom exactly.

- [ ] **Step 1: Implement `update_trigger_subscription`** (after `set_trigger_subscription_enabled`):

```rust
/// Full-row update of the PATCH-mutable surface. The handler resolves final
/// values (current-or-requested) in Rust, so this sets every mutable column
/// unconditionally; the callback trio is guarded by a touched flag. Any
/// callback change (set OR clear) bumps authority_generation so
/// subscription_secret bindings frozen on the old secret fail closed.
pub async fn update_trigger_subscription(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    name: &str,
    task_template: Option<&str>,
    allow_task_override: bool,
    allow_workspace_override: bool,
    concurrency_policy: &str,
    callback: CallbackUpdate,
) -> sqlx::Result<Option<TriggerSubscriptionRow>> {
    let (cb_touched, cb_dests, cb_sealed, cb_kv): (bool, Value, Option<Vec<u8>>, i16) =
        match callback {
            CallbackUpdate::Keep => (false, Value::Array(vec![]), None, 0),
            CallbackUpdate::Clear => (true, Value::Array(vec![]), None, 0),
            CallbackUpdate::Set { destinations, sealed, key_version } => {
                (true, destinations, Some(sealed), key_version)
            }
        };
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
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
         where id = $1 and tenant_id = $11
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
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}
```

- [ ] **Step 2: Implement `update_schedule_config`** (after `create_schedule`):

```rust
/// Reconfigure the clock on a schedule subscription. next_fire_at is the
/// handler-computed first future firing of the NEW cron — the scheduler's
/// tick worker picks it up unchanged.
pub async fn update_schedule_config(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    cron: &str,
    timezone: &str,
    missed_run_policy: &str,
    next_fire_at: DateTime<Utc>,
) -> sqlx::Result<Option<ScheduleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "update schedules set cron = $2, timezone = $3, missed_run_policy = $4,
           next_fire_at = $5, updated_at = now()
         where subscription_id = $1
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $6)
         returning *",
    )
    .bind(subscription)
    .bind(cron)
    .bind(timezone)
    .bind(missed_run_policy)
    .bind(next_fire_at)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}
```

- [ ] **Step 3: Compile clean:** `cargo clippy -p fluidbox-db -- -D warnings` (expect a dead-code allowance not needed — `pub` items are exported).

- [ ] **Step 4: Commit:** `git add crates/fluidbox-db/src/lib.rs && git commit -m "feat(db): update methods for trigger subscription + schedule config"`

---

### Task 4: Rust — `PATCH /v1/triggers/{id}` handler + route

**Files:**
- Modify: `crates/fluidbox-server/src/triggers.rs` (new `update` handler after `get`, ~line 721)
- Modify: `crates/fluidbox-server/src/main.rs:533` (route)

**Interfaces:**
- Consumes: Task 2's `UpdateTrigger`/`resolve_update`, Task 3's `update_trigger_subscription`/`CallbackUpdate`/`update_schedule_config`, Task 1's `contract_urls`; existing `schedule_context`, `connectors::{connector_for, sample_context}`, `egress::admit_url`, `seal::{Sealed, SealCtx, SealFamily}`, `random_hex_token`, `SECRET_PREFIX`, `CronSchedule`, `MissedRunPolicy`.
- Produces: `PATCH /v1/triggers/{id}` → `{ subscription, schedule, callback_secret, base_url, invoke_url, poll_url_template, ingress_url }` (callback_secret non-null ONLY when a new callback was set — shown once, like create).

- [ ] **Step 1: Implement the handler** (after `get`):

```rust
/// PATCH — the mutable surface only: name, task_template, overrides,
/// concurrency_policy, callback_url, and (schedule kind) the clock. Trigger
/// kind and agent are deliberately absent: changing those is a new
/// automation. In-flight runs keep their frozen RunSpec; future firings use
/// the updated values — the platform's existing immutability model.
pub async fn update(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTrigger>,
) -> ApiResult<Json<Value>> {
    if !rbac::can_manage_subscriptions(&principal) {
        return Err(ApiError::Forbidden(
            "managing trigger subscriptions requires admin or owner".into(),
        ));
    }
    let scope = principal.scope();
    let current = fluidbox_db::get_trigger_subscription(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;

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
    // subscription's authority generation.
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
            let (cb_bytes, cb_kv) = crate::seal::Sealed::split(&Some(sealed));
            (
                fluidbox_db::CallbackUpdate::Set {
                    destinations: dests,
                    sealed: cb_bytes.expect("just sealed").to_vec(),
                    key_version: cb_kv,
                },
                Some(secret),
            )
        }
    };

    // Schedule reconfiguration is only meaningful on a schedule subscription.
    let schedule_update = match &req.schedule {
        None => None,
        Some(s) => {
            if current.trigger_kind != "schedule" {
                return Err(ApiError::BadRequest(
                    "only schedule subscriptions carry a schedule".into(),
                ));
            }
            let tz = s.timezone.as_deref().unwrap_or("UTC");
            let cron = CronSchedule::parse(&s.cron, tz).map_err(ApiError::BadRequest)?;
            let missed = s.missed_run_policy.as_deref().unwrap_or("skip");
            if MissedRunPolicy::parse(missed).is_none() {
                return Err(ApiError::BadRequest(
                    "missed_run_policy must be skip | catch_up".into(),
                ));
            }
            let first = cron.next_fire_after(chrono::Utc::now()).ok_or_else(|| {
                ApiError::BadRequest("cron expression never fires in the future".into())
            })?;
            Some((s.cron.trim().to_string(), tz.to_string(), missed.to_string(), first))
        }
    };

    let sub = fluidbox_db::update_trigger_subscription(
        &state.pool,
        scope,
        id,
        &resolved.name,
        resolved.task_template.as_deref(),
        resolved.allow_task_override,
        resolved.allow_workspace_override,
        &resolved.concurrency_policy,
        callback,
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => ApiError::Conflict(format!(
            "a trigger named '{}' already exists",
            resolved.name
        )),
        _ => ApiError::Db(e),
    })?
    .ok_or(ApiError::NotFound)?;

    let schedule = match schedule_update {
        Some((cron, tz, missed, first)) => {
            fluidbox_db::update_schedule_config(&state.pool, scope, id, &cron, &tz, &missed, first)
                .await?
        }
        None => fluidbox_db::schedule_for_subscription(&state.pool, scope, id).await?,
    };

    let mut body = serde_json::Map::new();
    body.insert("subscription".into(), serde_json::to_value(&sub)?);
    body.insert("schedule".into(), serde_json::to_value(&schedule)?);
    body.insert("callback_secret".into(), json!(secret_plain));
    body.extend(contract_urls(&state.cfg.public_url, sub.id, None));
    Ok(Json(Value::Object(body)))
}
```

**Seal-split note:** the `Sealed::split(&Some(sealed))` call mirrors create's handling at triggers.rs:614 (`let (cb_bytes, cb_kv) = crate::seal::Sealed::split(&secret_sealed);`). Check `Sealed::split`'s exact return types at crates/fluidbox-server/src/seal.rs before wiring — if it returns `(Option<&[u8]>, i16)` the `.to_vec()` above is right; adjust mechanically if the shapes differ. Also note the `update_trigger_subscription` call passes `callback` by VALUE (owned enum), not `.as_ref()`.

- [ ] **Step 2: Register the route.** In `main.rs:533` change:

```rust
        .route("/triggers/{id}", get(triggers::get).patch(triggers::update))
```

and add `patch` to the `axum::routing` import at the top of `main.rs` if absent.

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
export function classifyVariables(kind: string, template: string | null): { caller: string[]; system: string[] };
export function contextExample(caller: string[]): string;
/** token null → the $FLUIDBOX_TRIGGER_TOKEN placeholder (durable/revisit view). */
export function buildCurl(opts: { invokeUrl: string; token: string | null; caller: string[] }): string;
```

- [ ] **Step 1: Write the failing tests** (`automation-contract.test.ts`):

```ts
import { describe, expect, it } from "vitest";
import {
  buildCurl,
  classifyVariables,
  contextExample,
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
  it("splits caller vs system by trigger kind", () => {
    const { caller, system } = classifyVariables(
      "schedule",
      "sweep {{fire_time}} for {{team}}"
    );
    expect(system).toEqual(["fire_time"]);
    expect(caller).toEqual(["team"]);
  });
  it("api kind has no system variables", () => {
    expect(classifyVariables("api", "do {{ticket}}").caller).toEqual(["ticket"]);
    expect(classifyVariables("api", "do {{ticket}}").system).toEqual([]);
  });
});

describe("buildCurl", () => {
  it("uses the real token when given and a shell placeholder when not", () => {
    const url = "https://fb.example/v1/triggers/x/invoke";
    expect(buildCurl({ invokeUrl: url, token: "fbx_trig_abc", caller: [] })).toContain(
      "Bearer fbx_trig_abc"
    );
    const durable = buildCurl({ invokeUrl: url, token: null, caller: ["ticket"] });
    expect(durable).toContain("Bearer $FLUIDBOX_TRIGGER_TOKEN");
    expect(durable).toContain('"ticket": "…"');
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

- [ ] **Step 3: Implement the lib** (move the two definitions out of RunComposer verbatim, then add the two builders):

```ts
/** Pure integration-contract helpers shared by the composer preview, the
 *  one-time secrets modal, and the durable automation detail page. Keeping
 *  them here (tested, presentation-free) is what lets three surfaces render
 *  the SAME contract without drifting. */

/** Placeholders the platform fills in itself, per trigger kind. Anything else
 *  in the template is the caller's to supply in `context`. */
export const SYSTEM_VARIABLES: Record<string, string[]> = {
  schedule: ["fire_time"],
  event: ["repository", "pr_number", "pr_title"],
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
): { caller: string[]; system: string[] } {
  const systemNames = SYSTEM_VARIABLES[kind] ?? [];
  const declared = templateVariables(template);
  return {
    caller: declared.filter((name) => !systemNames.includes(name)),
    system: declared.filter((name) => systemNames.includes(name)),
  };
}

export function contextExample(caller: string[]): string {
  if (caller.length === 0) return "{}";
  return `{"context": {${caller.map((name) => `"${name}": "…"`).join(", ")}}}`;
}

/** token null → the durable view: the secret is the caller's to hold, so the
 *  curl carries a shell variable instead of pretending we can re-show it. */
export function buildCurl(opts: {
  invokeUrl: string;
  token: string | null;
  caller: string[];
}): string {
  return [
    `curl -X POST '${opts.invokeUrl}' \\`,
    `  -H 'Authorization: Bearer ${opts.token ?? "$FLUIDBOX_TRIGGER_TOKEN"}' \\`,
    `  -H 'Content-Type: application/json' \\`,
    `  -H 'Idempotency-Key: <your-unique-key>' \\`,
    `  -d '${contextExample(opts.caller)}'`,
  ].join("\n");
}
```

- [ ] **Step 4: Point RunComposer at the lib.** Delete `SYSTEM_VARIABLES` (RunComposer.tsx:1709-1713) and `templateVariables` (1715-1722); delete the hand-rolled `curl`/`contextExample` construction inside `ShowAutomationSecrets` (lines 1768-1779) and replace with:

```ts
  const { caller: callerVars, system: systemVars } = classifyVariables(kind, sub.task_template);
  const declared = [...callerVars, ...systemVars];
  const curl = buildCurl({ invokeUrl, token: minted.token, caller: callerVars });
```

adding the import `import { buildCurl, classifyVariables } from "../lib/automation-contract";`.

- [ ] **Step 5: Verify:** `pnpm vitest run` (all web tests) and `pnpm build` → green.

- [ ] **Step 6: Commit:** `git add apps/web/app/lib/automation-contract.* apps/web/app/components/RunComposer.tsx && git commit -m "feat(web): extract pure automation-contract helpers"`

---

### Task 6: Web — shared `AutomationContract` component; trim the secrets modal

**Files:**
- Create: `apps/web/app/components/AutomationContract.tsx`
- Modify: `apps/web/app/components/RunComposer.tsx` (`CopyBlock` at 1724-1747 moves out; `ShowAutomationSecrets` at 1749-1926 shrinks)
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
  token,          // string | null — null renders $FLUIDBOX_TRIGGER_TOKEN
  updatedAt,      // string | null — renders the "as of" stamp when given
}: {...});
```

- Consumes: Task 5's lib; `TriggerSubscription` from `../lib/api`.

- [ ] **Step 1: Create `AutomationContract.tsx`.** Move `CopyBlock` verbatim from RunComposer (1724-1747). Then move the Endpoint / Variables / Request / Responses / Result-delivery sections of `ShowAutomationSecrets` (lines 1822-1916 minus the secrets section) into:

```tsx
"use client";

import { useState } from "react";
import { TriggerSubscription } from "../lib/api";
import { buildCurl, classifyVariables } from "../lib/automation-contract";

/* CopyBlock: moved verbatim from RunComposer.tsx */

/** The durable integration contract, rendered live from the current
 *  subscription. Everything here is always recoverable; only the token is
 *  one-time (token=null renders the honest $FLUIDBOX_TRIGGER_TOKEN form). */
export function AutomationContract({
  subscription,
  invokeUrl,
  pollUrl,
  ingressUrl,
  token,
  updatedAt,
}: {
  subscription: TriggerSubscription;
  invokeUrl: string;
  pollUrl: string;
  ingressUrl: string | null;
  token: string | null;
  updatedAt: string | null;
}) {
  const kind = subscription.trigger_kind;
  const { caller: callerVars, system: systemVars } = classifyVariables(
    kind,
    subscription.task_template
  );
  const declared = [...callerVars, ...systemVars];
  const curl = buildCurl({ invokeUrl, token, caller: callerVars });
  const hasCallback = subscription.result_destinations.some(
    (destination) => destination.kind === "signed_webhook"
  );
  const responseExample = [
    "200 OK",
    JSON.stringify(
      {
        session_id: "019f…",
        status: "queued",
        replay: false,
        poll_url: `/v1/triggers/${subscription.id}/runs/{session_id}`,
      },
      null,
      2
    ),
  ].join("\n");

  return (
    <div className="contract">
      {/* Endpoint / Variables / Request / Responses / Result delivery
          sections: EXACTLY the JSX from ShowAutomationSecrets lines
          1822-1916, with these substitutions:
            minted.ingress_url  -> ingressUrl
            sub                 -> subscription
            the curl const      -> curl (above)
            minted.callback_secret && (Result delivery ...) -> hasCallback && (...)
          and WITHOUT the CopyBlock for the callback signing secret value
          (that block stays in the secrets modal; the signature-format
          CopyBlock here is fine — it contains no secret). */}
      {updatedAt && (
        <p className="contract-stamp">
          Reflects the configuration as of {new Date(updatedAt).toLocaleString()}.
        </p>
      )}
    </div>
  );
}
```

The comment block above is an instruction to YOU, the implementer — the shipped file must contain the real JSX moved from RunComposer, not the comment. `ResultDestination`-shaped objects in `result_destinations` use `kind: "signed_webhook"` — verify the exact discriminant with `grep -n "signed_webhook" apps/web/app/lib/api.ts crates/fluidbox-core/src/spec.rs` and match it.

- [ ] **Step 2: Shrink `ShowAutomationSecrets`.** It keeps: the ModalShell chrome (title/sub/dirty/discard copy, lines 1795-1804), the **Secrets** section (1806-1820), and gains a pointer + compact contract. Replace everything from line 1822 (`<section className="contract-section"><h4>Endpoint</h4>`) through 1916 with:

```tsx
        <AutomationContract
          subscription={sub}
          invokeUrl={invokeUrl}
          pollUrl={pollUrl}
          ingressUrl={minted.ingress_url ?? null}
          token={minted.token}
          updatedAt={null}
        />
        <p className="contract-note">
          Everything except the secrets above is always available at{" "}
          <Link className="link" href={`/automations/${sub.id}`}>
            Automations → {sub.name} → API
          </Link>
          . Lost token? Rotate it there.
        </p>
```

(`Link` is already imported in RunComposer. The `curl`/`responseExample`/variable derivations local to `ShowAutomationSecrets` are now dead — delete them. `pollUrl` stays as computed at line 1761.)

- [ ] **Step 3: CSS** — append to `apps/web/app/globals.css` next to the existing `.contract-*` rules (grep `contract-note` to find them):

```css
.contract-stamp {
  font-size: 12px;
  color: var(--muted, #888);
  margin: 4px 0 0;
}
```

(If the file uses different token names for muted text, copy whatever `.field-hint` uses.)

- [ ] **Step 4: Verify:** `pnpm build && pnpm vitest run` → green. Open nothing yet — the detail page arrives next task.

- [ ] **Step 5: Commit:** `git add apps/web && git commit -m "feat(web): shared AutomationContract; secrets modal shows secrets + pointer"`

---

### Task 7: Web — types + `/automations/[id]` read-only detail page

**Files:**
- Modify: `apps/web/app/lib/api.ts` (TriggerSubscription at line 684: add `updated_at: string;` after `created_at`; add the detail-response type below)
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

- Consumes: Task 6's `AutomationContract`, existing `ShowAutomationSecrets` + rotate endpoint, `AutomationActivity` (change `function AutomationActivity` to `export function AutomationActivity` in AutomationPanel.tsx:253).

- [ ] **Step 1: api.ts** — add `updated_at` to `TriggerSubscription` and the `TriggerDetail` interface above. `Session`, `ResultDelivery`, `TriggerInvocation`, `Schedule` already exist in the file.

- [ ] **Step 2: Export `AutomationActivity`** (AutomationPanel.tsx:253) and link each row title to the page — in `AutomationRow` (line 215) wrap the name:

```tsx
            <Link className="link" href={`/automations/${subscription.id}`}>
              <strong>{subscription.name}</strong>
            </Link>
```

(`Link` is already imported at line 4.) Add an "Open →" link beside the "Activity" button:

```tsx
          <Link className="btn ghost sm" href={`/automations/${subscription.id}`}>
            Open →
          </Link>
```

- [ ] **Step 3: Note the routing collision and resolve it.** `apps/web/app/automations/page.tsx` redirects `/automations` → `/?view=automations`; a `[id]` sibling does not conflict. Create `apps/web/app/automations/[id]/page.tsx`:

```tsx
"use client";

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, apiPost, TriggerDetail, TriggerSubscription } from "../../lib/api";
import { AutomationContract } from "../../components/AutomationContract";
import { MintedAutomation, ShowAutomationSecrets } from "../../components/RunComposer";
import { LoadingRows } from "../../components/bits";

export default function AutomationDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [detail, setDetail] = useState<TriggerDetail | null>(null);
  const [loadErr, setLoadErr] = useState("");
  const [actionErr, setActionErr] = useState("");
  const [minted, setMinted] = useState<MintedAutomation | null>(null);

  const load = useCallback(async () => {
    try {
      setDetail(await apiGet<TriggerDetail>(`/triggers/${id}`));
      setLoadErr("");
    } catch (error) {
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
      }>(`/triggers/${id}/rotate_token`, {});
      setMinted({
        subscription,
        token: response.token,
        callback_secret: null,
        rotated: true,
        base_url: response.base_url,
        invoke_url: response.invoke_url,
        poll_url_template: response.poll_url_template,
      });
    } catch (error) {
      setActionErr(String(error));
    }
  };

  if (loadErr) {
    return (
      <main className="page automation-detail">
        <div className="err">{loadErr}</div>
      </main>
    );
  }
  if (!detail) {
    return (
      <main className="page automation-detail">
        <LoadingRows />
      </main>
    );
  }
  const sub = detail.subscription;
  return (
    <main className="page automation-detail">
      <header className="automation-detail-head">
        <div>
          <span className="section-kicker">
            {sub.trigger_kind === "api"
              ? "API-invoked automation"
              : sub.trigger_kind === "schedule"
                ? "Scheduled automation"
                : "Event automation"}
          </span>
          <h1>{sub.name}</h1>
          <p className="automation-intro">
            Saved run configuration — every firing creates a normal governed run.{" "}
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
        <AutomationActivityBlock id={sub.id} />
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
    </main>
  );
}
```

with, at the bottom of the file:

```tsx
import { AutomationActivity } from "../../components/AutomationPanel";

function AutomationActivityBlock({ id }: { id: string }) {
  return <AutomationActivity id={id} />;
}
```

(Or import `AutomationActivity` directly in the header import block and use it inline — implementer's choice; keep imports at the top per lint.)

- [ ] **Step 4: CSS** — append (near `.automation-panel` rules):

```css
.automation-detail { max-width: 880px; margin: 0 auto; padding: 24px 16px 64px; }
.automation-detail-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 8px; }
.automation-detail-section { margin-top: 28px; }
.automation-detail-section > h2 { font-size: 15px; margin: 0 0 10px; }
```

Match the `main className` conventions of `apps/web/app/sessions/[id]/page.tsx` — if that page uses a different wrapper class than `page`, copy it.

- [ ] **Step 5: Verify:** `pnpm build` green. Then the first manual checkpoint (needs `just dev` running — ask the owner if it isn't): create an API automation, close the secrets modal, click into `/automations/{id}`, confirm the contract renders with `$FLUIDBOX_TRIGGER_TOKEN`, copy works, Rotate shows the one-time modal.

- [ ] **Step 6: Commit:** `git add apps/web && git commit -m "feat(web): durable /automations/{id} page with live API contract"`

---

### Task 8: Web — edit flows on the detail page (template + settings)

**Files:**
- Modify: `apps/web/app/automations/[id]/page.tsx`
- Modify: `apps/web/app/globals.css` (chips)

**Interfaces:**
- Consumes: `apiPatch` (api.ts:138), Task 5's `classifyVariables`, `ScheduleBuilder`/`parseCron`/`describeSchedule` from `../../components/ScheduleBuilder`.
- Produces: `PATCH /triggers/{id}` calls with bodies shaped like Task 4's `UpdateTrigger`; a `TemplateChips` component reused by Task 9.

- [ ] **Step 1: Add `TemplateChips`** to `AutomationContract.tsx` (exported — the composer reuses it):

```tsx
/** Live placeholder read-back: which {{names}} the caller supplies vs which
 *  the platform fills. Rendered under every template textarea so the
 *  template's contract is visible while typing. */
export function TemplateChips({ kind, template }: { kind: string; template: string }) {
  const { caller, system } = classifyVariables(kind, template || null);
  if (caller.length === 0 && system.length === 0) return null;
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
    </div>
  );
}
```

CSS:

```css
.tpl-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.tpl-chip { font-family: var(--mono, monospace); font-size: 11px; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--border, #333); }
.tpl-chip.system { opacity: 0.7; }
```

(Adopt the repo's actual CSS variable names — grep `--border` in globals.css and reuse whatever the existing chips/badges use.)

- [ ] **Step 2: Template section** on the detail page (between API and Activity):

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

- [ ] **Step 3: Configuration section** (between API and Template):

```tsx
      <section className="automation-detail-section">
        <h2>Configuration</h2>
        <SettingsSection detail={detail} onSaved={load} />
      </section>
```

`SettingsSection` mirrors `TemplateSection`'s view/edit toggle. View mode: a `rows`-style list of name, agent id (link `/agents` page style used elsewhere — plain text is fine), autonomy, concurrency policy, task/workspace override flags, callback destination (from `result_destinations[0]?.url`), and for schedule kind the cron/timezone/missed policy + next fire from `detail.schedule`. Edit mode: inputs for name (`inp`), checkboxes for the two overrides (`check`), select for concurrency (same options as RunComposer.tsx:1504-1508), input for callback URL (empty string = remove — mirror the PATCH semantics with a hint: "Clearing removes the signed callback; changing it mints a NEW signing secret shown once"), and for schedule kind the `ScheduleBuilder` (cron/timezone) + missed-policy select (options from RunComposer.tsx:892-895). Save builds the PATCH body with ONLY touched fields:

```tsx
    const body: Record<string, unknown> = {};
    if (name !== sub.name) body.name = name;
    if (allowTask !== sub.allow_task_override) body.allow_task_override = allowTask;
    if (allowWorkspace !== sub.allow_workspace_override) body.allow_workspace_override = allowWorkspace;
    if (concurrency !== sub.concurrency_policy) body.concurrency_policy = concurrency;
    if (callbackUrl !== initialCallbackUrl) body.callback_url = callbackUrl; // "" clears
    if (sub.trigger_kind === "schedule" && detail.schedule &&
        (cron !== detail.schedule.cron || timezone !== detail.schedule.timezone || missed !== detail.schedule.missed_run_policy)) {
      body.schedule = { cron, timezone, missed_run_policy: missed };
    }
    const response = await apiPatch<{ callback_secret: string | null }>(`/triggers/${sub.id}`, body);
    if (response.callback_secret) setNewSecret(response.callback_secret);
```

When `callback_secret` comes back, show it in a `CopyBlock` inside a dismissable note ("New callback signing secret — copy it now, it will not be shown again."). Import `CopyBlock` from `AutomationContract`.

- [ ] **Step 4: Verify:** `pnpm build && pnpm vitest run` green. Manual: edit the template on a live automation → the API section's variables + curl update after save and the "as of" stamp advances.

- [ ] **Step 5: Commit:** `git add apps/web && git commit -m "feat(web): edit template and settings on the automation detail page"`

---

### Task 9: Web — composer template box + pre-save API preview

**Files:**
- Modify: `apps/web/app/components/RunComposer.tsx` (label block 954-966; `templateHint` 758-763; `blockingIssue` 598-632; aside panel after the Guardrails SpecRow ~line 1619)
- Modify: `apps/web/app/globals.css`

**Interfaces:**
- Consumes: Task 5's `buildCurl`/`classifyVariables`, Task 8's `TemplateChips` (from `./AutomationContract`).

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

and tighten `templateHint` (758-763) to explain the mechanism once:

```tsx
  const templateHint =
    kind === "schedule"
      ? "Saved with the automation. {{fire_time}} is filled in at each firing; any other {{name}} is refused at save (a schedule has no caller to supply it)."
      : kind === "event"
        ? "Saved with the automation. {{repository}}, {{pr_number}}, {{pr_title}} are filled from the pull request; any other {{name}} is refused at save."
        : "Saved with the automation. Every {{name}} you add becomes a required context value the API caller sends on invoke.";
```

- [ ] **Step 2: `blockingIssue` gains the no-caller rule** (insert after the existing dead-config check at line 614-616):

```tsx
      if (mode === "automation" && (kind === "schedule" || kind === "event") && !task.trim()) {
        return "This trigger fires without a caller — write the task template it should run.";
      }
```

- [ ] **Step 3: API preview card** in the aside, after the Guardrails `SpecRow` (~line 1619):

```tsx
            {!agentOnly && mode === "automation" && kind === "api" && !blockingIssue && (
              <ApiPreview task={task} />
            )}
```

with the component (place near `SpecRow` at the bottom):

```tsx
/** Pre-save preview of the integration contract. Deliberately labeled a
 *  preview: the id and token exist only after save, so the copy carries
 *  placeholders — nobody should wire an integration to this text. */
function ApiPreview({ task }: { task: string }) {
  const [copied, setCopied] = useState(false);
  const { caller } = classifyVariables("api", task || null);
  const curl = buildCurl({
    invokeUrl: "{base_url}/v1/triggers/{id-assigned-on-save}/invoke",
    token: "<minted-on-save>",
    caller,
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
        The real URL and one-time token are minted when you save; the full contract then
        lives on the automation&apos;s page.
      </span>
    </div>
  );
}
```

Imports to add at the top of RunComposer: `buildCurl, classifyVariables` from `../lib/automation-contract`; `TemplateChips` from `./AutomationContract`.

CSS:

```css
.rc-api-preview { margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border, #333); }
.rc-api-preview-curl { font-size: 11px; max-height: 140px; overflow: auto; }
```

- [ ] **Step 4: Verify:** `pnpm build && pnpm vitest run` green. Manual: in the composer pick Automation → API call → watch the preview appear once name+template are valid, disappear on Schedule kind, chips update as you type `{{ticket}}`.

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

- [ ] **Step 2: Manual lifecycle drill** (needs the dev stack; coordinate with the owner before starting it — do not start `just dev`/DB yourself if anything is already running):
1. Configure Run → Automation → API call: template box shows the new label, chips appear for `{{ticket}}`, API preview card renders, "Copy preview" copies placeholder curl.
2. Save → secrets modal shows token + link "Automations → {name} → API".
3. Follow the link → `/automations/{id}`: contract with `$FLUIDBOX_TRIGGER_TOKEN`, every CopyBlock copies, "as of" stamp present.
4. Hard-refresh the page → identical (persistence).
5. Edit template (add `{{env}}`) → save → variables table + curl show `env`, stamp advanced.
6. Settings edit: flip concurrency to `skip_if_running` → save → view reflects it.
7. Rotate token → one-time modal again → close → contract still shows placeholder form.
8. Invoke with the real token (curl) → 200; confirms PATCH broke nothing at the invoke path.
9. Schedule-kind automation: edit cron via ScheduleBuilder → next-fire updates.
10. Negative: PATCH template to `{{nope}}` on the schedule automation → inline error naming the schedule context.

- [ ] **Step 3: Report results** to the owner, including anything skipped and why. Offer to run `scripts/governance-e2e.sh` / `just e2e` ONLY as an owner-triggered follow-up.

- [ ] **Step 4: Final commit if the drill produced fixes**, message `fix(web/server): lifecycle drill follow-ups for automation contract`.
