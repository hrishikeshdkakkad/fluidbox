//! Trigger subscriptions — what an invocation, a schedule, or an event fires.

use crate::schedules::ScheduleRow;
use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

// ─── Trigger subscriptions ────────────────────────────────────────────────

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
    pub concurrency_policy: String,
    pub budget_override: Option<Value>,
    pub workspace_override: Option<Value>,
    pub result_destinations: Value,
    /// Event subscriptions only (trigger_kind = 'event'); NULL otherwise.
    pub connection_id: Option<Uuid>,
    pub resource_selector: Option<Value>,
    pub event_filter: Option<Value>,
    pub event_publish: Option<Value>,
    /// Capability keep-list (bundle names; §3.5 narrowing). NULL = keep all
    /// bundles the resolved revision attaches; intersection is remove-only.
    pub capability_bundles: Option<Value>,
    /// Generation of the subscription's callback-secret authority (invariant 7,
    /// design :428-431): bumps on secret rotation so a `subscription_secret`
    /// binding freezing an older generation fails closed.
    pub authority_generation: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub(crate) const SUBSCRIPTION_COLS: &str =
    "id, tenant_id, agent_id, name, trigger_kind, pinned_revision_id, \
     enabled, task_template, allow_task_override, allow_workspace_override, autonomy, \
     concurrency_policy, budget_override, workspace_override, result_destinations, \
     connection_id, resource_selector, event_filter, event_publish, capability_bundles, \
     authority_generation, created_at, updated_at";

#[allow(clippy::too_many_arguments)]
pub async fn create_trigger_subscription(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
    name: &str,
    trigger_kind: &str,
    pinned_revision_id: Option<Uuid>,
    task_template: Option<&str>,
    allow_task_override: bool,
    allow_workspace_override: bool,
    autonomy: Option<&str>,
    concurrency_policy: &str,
    budget_override: Option<&Value>,
    workspace_override: Option<&Value>,
    result_destinations: &Value,
    callback_secret_sealed: Option<&[u8]>,
    callback_secret_key_version: i16,
    connection_id: Option<Uuid>,
    resource_selector: Option<&Value>,
    event_filter: Option<&Value>,
    event_publish: Option<&Value>,
    capability_bundles: Option<&Value>,
) -> sqlx::Result<TriggerSubscriptionRow> {
    let mut tx = scoped_tx(pool, scope).await?;
    let __rls_out = create_trigger_subscription_tx(
        &mut tx,
        scope.tenant_id(),
        agent_id,
        name,
        trigger_kind,
        pinned_revision_id,
        task_template,
        allow_task_override,
        allow_workspace_override,
        autonomy,
        concurrency_policy,
        budget_override,
        workspace_override,
        result_destinations,
        callback_secret_sealed,
        callback_secret_key_version,
        connection_id,
        resource_selector,
        event_filter,
        event_publish,
        capability_bundles,
    )
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// [`create_trigger_subscription`] inside a caller-owned transaction (the
/// recipes deploy engine's atomic stamp).
#[allow(clippy::too_many_arguments)]
pub async fn create_trigger_subscription_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    agent_id: Uuid,
    name: &str,
    trigger_kind: &str,
    pinned_revision_id: Option<Uuid>,
    task_template: Option<&str>,
    allow_task_override: bool,
    allow_workspace_override: bool,
    autonomy: Option<&str>,
    concurrency_policy: &str,
    budget_override: Option<&Value>,
    workspace_override: Option<&Value>,
    result_destinations: &Value,
    callback_secret_sealed: Option<&[u8]>,
    callback_secret_key_version: i16,
    connection_id: Option<Uuid>,
    resource_selector: Option<&Value>,
    event_filter: Option<&Value>,
    event_publish: Option<&Value>,
    capability_bundles: Option<&Value>,
) -> sqlx::Result<TriggerSubscriptionRow> {
    // Prove every referenced parent belongs to this tenant IN SQL (the handler
    // pre-validates too, but this is the relational backstop): the agent is
    // in-scope; a Some pinned_revision is a revision of THAT agent; a Some
    // connection is in-scope. A miss yields zero rows → fetch_one RowNotFound,
    // the same shape a not-in-scope agent already produced for other writes.
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into trigger_subscriptions
           (id, tenant_id, agent_id, name, trigger_kind, pinned_revision_id, task_template,
            allow_task_override, allow_workspace_override, autonomy, concurrency_policy,
            budget_override, workspace_override, result_destinations, callback_secret_sealed,
            connection_id, resource_selector, event_filter, event_publish, capability_bundles,
            callback_secret_key_version)
         select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21
         where exists (select 1 from agents a where a.id = $3 and a.tenant_id = $2)
           and ($6::uuid is null or exists (
                 select 1 from agent_revisions r where r.id = $6 and r.agent_id = $3))
           and ($16::uuid is null or exists (
                 select 1 from integration_connections c where c.id = $16 and c.tenant_id = $2))
         returning {SUBSCRIPTION_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(tenant_id)
    .bind(agent_id)
    .bind(name)
    .bind(trigger_kind)
    .bind(pinned_revision_id)
    .bind(task_template)
    .bind(allow_task_override)
    .bind(allow_workspace_override)
    .bind(autonomy)
    .bind(concurrency_policy)
    .bind(budget_override)
    .bind(workspace_override)
    .bind(result_destinations)
    .bind(callback_secret_sealed)
    .bind(connection_id)
    .bind(resource_selector)
    .bind(event_filter)
    .bind(event_publish)
    .bind(capability_bundles)
    .bind(callback_secret_key_version)
    .fetch_one(&mut **tx)
    .await?;
    Ok(__rls_out)
}

/// Enabled event subscriptions listening on a connection — the matcher's
/// candidate set.
pub async fn list_event_subscriptions(
    pool: &PgPool,
    scope: TenantScope,
    connection: Uuid,
) -> sqlx::Result<Vec<TriggerSubscriptionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {SUBSCRIPTION_COLS} from trigger_subscriptions
         where connection_id = $1 and trigger_kind = 'event' and enabled and tenant_id = $2
         order by created_at"
    )))
    .bind(connection)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_trigger_subscriptions(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<TriggerSubscriptionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {SUBSCRIPTION_COLS} from trigger_subscriptions
         where tenant_id = $1 order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_trigger_subscription(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<TriggerSubscriptionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {SUBSCRIPTION_COLS} from trigger_subscriptions where id = $1 and tenant_id = $2"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn set_trigger_subscription_enabled(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    enabled: bool,
) -> sqlx::Result<Option<TriggerSubscriptionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let __rls_out =
        set_trigger_subscription_enabled_tx(&mut tx, scope.tenant_id(), id, enabled).await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// [`set_trigger_subscription_enabled`] inside a caller-owned transaction —
/// recipe instance pause/resume flips every stamped subscription and the
/// instance status atomically.
pub async fn set_trigger_subscription_enabled_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    id: Uuid,
    enabled: bool,
) -> sqlx::Result<Option<TriggerSubscriptionRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update trigger_subscriptions set enabled = $2, updated_at = now()
         where id = $1 and tenant_id = $3 returning {SUBSCRIPTION_COLS}"
    )))
    .bind(id)
    .bind(enabled)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
}

/// What PATCH does to the callback destination: leave it alone, remove it,
/// or replace it with a freshly sealed secret. Owns its data — the sealed
/// bytes are produced inside the handler's match arm.
pub enum CallbackUpdate {
    Keep,
    Clear,
    Set {
        destinations: Value,
        sealed: Vec<u8>,
        key_version: i16,
    },
}

pub struct ScheduleConfigUpdate {
    pub cron: String,
    pub timezone: String,
    pub missed_run_policy: String,
    /// The `schedules.next_fire_at` column is nullable. `None` preserves the
    /// "no future fire" state: a cadence-neutral PATCH (e.g. missed_run_policy
    /// only) carries the existing row's clock through unchanged rather than
    /// resetting it, and that clock may itself be `None`.
    pub next_fire_at: Option<DateTime<Utc>>,
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
) -> sqlx::Result<Option<(TriggerSubscriptionRow, Option<ScheduleRow>)>> {
    // key_version 1 when bytes are NULL: the column CHECKs in (1,2) and the
    // version is moot without bytes (Sealed::split's convention).
    let (cb_touched, cb_dests, cb_sealed, cb_kv): (bool, Value, Option<Vec<u8>>, i16) =
        match callback {
            CallbackUpdate::Keep => (false, Value::Array(vec![]), None, 1),
            CallbackUpdate::Clear => (true, Value::Array(vec![]), None, 1),
            CallbackUpdate::Set {
                destinations,
                sealed,
                key_version,
            } => (true, destinations, Some(sealed), key_version),
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

/// The only reader of the sealed callback secret. Deliveries for in-flight
/// runs must still sign after a disable, so this does not require `enabled`.
pub async fn subscription_callback_secret_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select callback_secret_sealed, callback_secret_key_version from trigger_subscriptions
         where id = $1 and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Vec<u8>>, _>("callback_secret_sealed")
            .map(|b| (b, r.get::<i16, _>("callback_secret_key_version")))
    }))
}
