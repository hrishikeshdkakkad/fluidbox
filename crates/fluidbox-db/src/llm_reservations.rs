//! Durable LLM budget reservations.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use fluidbox_core::state::SessionStatus;
use sqlx::{PgPool, Row};
use uuid::Uuid;

// ─── LLM budget reservations (Phase E, #33; Gap 14) ───────────────────────
// Migration 0022. The facade's check-then-record budget was raceable: N
// concurrent requests all read the same remaining budget and all passed. These
// functions replace the check with a durable, request-ID-keyed ATOMIC admission
// so concurrent requests see each other's bookings. Every fn is tenant-scoped
// (`scoped_tx` + `tenant_id` predicate); the cross-tenant expiry sweep lives in
// `system_worker`.

/// One `llm_reservations` row (migration 0022).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LlmReservationRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub model: String,
    pub reserved_tokens: i64,
    pub reserved_cost_usd: Option<f64>,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Live (`state = 'reserved'`) reservation totals for one session — the spend that
/// is booked but not yet in `usage_entries`. The budget sweeper adds these to
/// `usage_totals` so its projection sees in-flight requests, not just settled ones.
#[derive(Debug, Clone, Copy, Default, sqlx::FromRow)]
pub struct ReservationTotals {
    pub tokens: i64,
    pub cost_usd: f64,
    pub active: i64,
}

/// The verdict of [`reserve_llm_budget`].
#[derive(Debug, Clone, PartialEq)]
pub enum ReserveOutcome {
    /// Booked. The caller owns the reservation and MUST settle it (charge on
    /// authoritative usage, release only on positively-proven non-dispatch).
    Reserved,
    /// The projection `recorded usage + live reservations + this request` exceeds
    /// the named budget. `active` is how many live reservations were counted —
    /// always ≥ 1, because a request with no competitors is admitted by the
    /// sole-claimant rule (see the fn docs).
    BudgetExceeded { budget: &'static str, active: i64 },
    /// Too many reservations already outstanding for this session.
    CeilingExceeded { active: i64, ceiling: i64 },
    /// The session stopped accepting work (or is not this tenant's) before the
    /// reservation could be booked.
    SessionTerminal,
}

/// Book a conservative maximum against a run's LLM budget, atomically.
///
/// TWO STATEMENTS, and both halves are load-bearing:
///
///   1. `select status from sessions … for update` — the SERIALIZER. A CTE alone
///      does NOT close the race: under READ COMMITTED two concurrent transactions
///      each take their own snapshot and neither sees the other's uncommitted
///      insert, so both would pass an identical guard. Locking the session row
///      first makes concurrent admissions for one session queue on that row, and
///      the SECOND statement then runs on a fresh command snapshot that includes
///      everything the previous holder committed. (A single statement would keep
///      the stale pre-lock snapshot for the rows it reads — the same hazard
///      `claim_tool_execution` and `set_sandbox_handle` document.) The lock is
///      held for one short statement and NEVER across the upstream model call, so
///      this is not "serialize requests per session", which design :1113-1115
///      forbids: parallel subagent calls still run in parallel, they just take
///      their bookings in a defined order.
///   2. ONE atomic CTE that computes recorded usage + live reservations + the
///      ceiling and inserts the row only if every guard passes — decision and
///      booking can never be separated by another writer.
///
/// LOCK ORDER: `sessions` (FOR UPDATE) → `llm_reservations`. Identical to
/// `claim_tool_execution` (`sessions` → `tool_execution_claims`) and to
/// cancellation (`transition_session` / `begin_finalization`, which also take the
/// session row first), so all four serialize on the same row in the same order and
/// no cycle can form. This tx never touches `approvals` and never calls
/// `append_event`, so it is disjoint from the approvals→sessions ordering the
/// decision sites use.
///
/// THE SOLE-CLAIMANT RULE (a deliberate refinement of the plan's literal
/// predicate). The budget arms are skipped when there are ZERO other live
/// reservations. Gap 14 is a CONCURRENCY race, and the pre-existing accumulated
/// check (`recorded usage >= budget`, unchanged, evaluated moments earlier in the
/// facade) has already ruled on whether the run may proceed at all. Without this
/// carve-out a run whose per-request conservative estimate alone exceeds its
/// remaining budget could never make a single request — it would be refused
/// forever with nothing in flight to drain, livelocking instead of stopping. The
/// terminal "this run is out of budget" verdict therefore stays where it already
/// lives (the accumulated check plus the budget sweeper, which now counts live
/// reservations and so still stops an over-projecting sole claimant — once,
/// cleanly, with a ledgered `BudgetExceeded`).
///
/// `budget_tokens` / `budget_cost` are the RunSpec's frozen caps (`None` = no
/// cap). `reserved_cost` is `None` for an unpriced model; NULL contributes 0 to
/// the cost projection, which is why the token arm carries the weight there.
#[allow(clippy::too_many_arguments)]
pub async fn reserve_llm_budget(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
    request_id: Uuid,
    model: &str,
    reserved_tokens: i64,
    reserved_cost: Option<f64>,
    ceiling: i64,
    budget_tokens: Option<i64>,
    budget_cost: Option<f64>,
    ttl_secs: i64,
) -> sqlx::Result<ReserveOutcome> {
    let mut tx = scoped_tx(pool, scope).await?;
    let locked: Option<(String,)> =
        sqlx::query_as("select status from sessions where id = $1 and tenant_id = $2 for update")
            .bind(session_id)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?;
    let Some((status,)) = locked else {
        return Ok(ReserveOutcome::SessionTerminal);
    };
    if !SessionStatus::parse(&status).is_some_and(|s| s.accepts_work()) {
        return Ok(ReserveOutcome::SessionTerminal);
    }
    let expires = Utc::now() + chrono::Duration::seconds(ttl_secs.max(1));
    let row = sqlx::query(
        "with used as (
             select coalesce(sum(input_tokens + output_tokens
                                 + cache_read_tokens + cache_write_tokens), 0)::bigint as tokens,
                    coalesce(sum(cost_usd), 0)::float8 as cost
               from usage_entries
              where session_id = $2
                and exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $3)
         ),
         active as (
             select coalesce(sum(reserved_tokens), 0)::bigint as tokens,
                    coalesce(sum(reserved_cost_usd), 0)::float8 as cost,
                    count(*)::bigint as n
               from llm_reservations
              where session_id = $2 and state = 'reserved'
                and exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $3)
         ),
         guard as (
             select a.n as active_n,
                    a.n < $8::bigint as under_ceiling,
                    ($9::bigint is null or a.n = 0
                       or u.tokens + a.tokens + $6::bigint <= $9::bigint) as under_tokens,
                    ($10::float8 is null or a.n = 0
                       or u.cost + a.cost + coalesce($7::float8, 0) <= $10::float8) as under_cost
               from used u, active a
         ),
         ins as (
             insert into llm_reservations
                 (id, tenant_id, session_id, model, reserved_tokens, reserved_cost_usd,
                  state, expires_at)
             select $1::uuid, $3::uuid, $2::uuid, $5::text, $6::bigint, $7::float8,
                    'reserved', $4::timestamptz
               from guard g
              where g.under_ceiling and g.under_tokens and g.under_cost
                and exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $3)
             returning id
         )
         select (select count(*) from ins)::bigint as inserted,
                g.active_n, g.under_ceiling, g.under_tokens, g.under_cost
           from guard g",
    )
    .bind(request_id)
    .bind(session_id)
    .bind(scope.tenant_id())
    .bind(expires)
    .bind(model)
    .bind(reserved_tokens)
    .bind(reserved_cost)
    .bind(ceiling)
    .bind(budget_tokens)
    .bind(budget_cost)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    let inserted: i64 = row.get("inserted");
    let active: i64 = row.get("active_n");
    let outcome = if inserted == 1 {
        ReserveOutcome::Reserved
    } else if !row.get::<bool, _>("under_ceiling") {
        ReserveOutcome::CeilingExceeded { active, ceiling }
    } else if !row.get::<bool, _>("under_tokens") {
        ReserveOutcome::BudgetExceeded {
            budget: "max_tokens",
            active,
        }
    } else if !row.get::<bool, _>("under_cost") {
        ReserveOutcome::BudgetExceeded {
            budget: "max_cost_usd",
            active,
        }
    } else {
        // Every guard passed but the insert's tenant/session predicate did not —
        // the session vanished or is not this tenant's. Fail closed.
        ReserveOutcome::SessionTerminal
    };
    Ok(outcome)
}

/// Settle a reservation as SPENT (CAS `reserved → charged`). The caller MUST have
/// already written the matching `usage_entries` row keyed `external_id = id`; this
/// only retires the booking so it stops being counted twice. Returns true iff this
/// call landed the transition (false = the sweeper already converted it).
pub async fn charge_llm_reservation(
    pool: &PgPool,
    scope: TenantScope,
    request_id: Uuid,
) -> sqlx::Result<bool> {
    cas_reservation_state(pool, scope, request_id, "charged").await
}

/// Settle a reservation as NEVER SPENT (CAS `reserved → released`). Legal ONLY on
/// positively-proven non-dispatch (design :1121) — a pre-send refusal or an
/// upstream 401, which the facade already treats as proof the request never
/// executed. "We could not parse usage" is NOT proof and must retain instead.
pub async fn release_llm_reservation(
    pool: &PgPool,
    scope: TenantScope,
    request_id: Uuid,
) -> sqlx::Result<bool> {
    cas_reservation_state(pool, scope, request_id, "released").await
}

async fn cas_reservation_state(
    pool: &PgPool,
    scope: TenantScope,
    request_id: Uuid,
    state: &str,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update llm_reservations set state = $3
          where id = $1 and tenant_id = $2 and state = 'reserved'",
    )
    .bind(request_id)
    .bind(scope.tenant_id())
    .bind(state)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() == 1)
}

/// Live reservation totals for one session (the budget sweeper's projection input,
/// and the tests' observation window).
pub async fn active_reservation_totals(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<ReservationTotals> {
    let mut tx = scoped_tx(pool, scope).await?;
    let out = sqlx::query_as(
        "select coalesce(sum(reserved_tokens), 0)::bigint as tokens,
                coalesce(sum(reserved_cost_usd), 0)::float8 as cost_usd,
                count(*)::bigint as active
           from llm_reservations
          where session_id = $1 and state = 'reserved'
            and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// Read one reservation by its request id (tests + operator introspection).
pub async fn get_llm_reservation(
    pool: &PgPool,
    scope: TenantScope,
    request_id: Uuid,
) -> sqlx::Result<Option<LlmReservationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let out = sqlx::query_as("select * from llm_reservations where id = $1 and tenant_id = $2")
        .bind(request_id)
        .bind(scope.tenant_id())
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(out)
}
