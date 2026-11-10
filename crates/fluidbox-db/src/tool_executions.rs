//! Durable brokered tool-execution claims.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use fluidbox_core::state::SessionStatus;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

// ─── Durable tool execution claims (Phase E, #33; Gap 11) ───────────────────
// The four-state (+ambiguous) claim that fences every brokered dispatch: exactly
// one send per (session, tool_call_id, input_digest), taken under the SAME
// sessions-row lock order as cancellation, refused once the session stops
// accepting work, carrying the settled outcome so a duplicate ADOPTS it.
// Migration 0019. Every fn is tenant-scoped (`scoped_tx` + `tenant_id` predicate);
// the cross-tenant stale-claim sweep lives in `system_worker`.

/// One `tool_execution_claims` row (migration 0019).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ToolExecutionClaimRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub tool_call_id: String,
    pub input_digest: String,
    pub state: String,
    pub attempt: i32,
    pub claimed_at: DateTime<Utc>,
    pub claim_expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result_digest: Option<String>,
    pub is_error: Option<bool>,
    pub result_content: Option<Value>,
    pub error_message: Option<String>,
}

/// The outcome of [`claim_tool_execution`]: whether THIS caller won the single
/// dispatch, found an existing claim to reconcile against, or hit a session that
/// no longer accepts work.
#[derive(Debug, Clone)]
pub enum ClaimOutcome {
    /// This caller inserted the claim and owns the one dispatch.
    Won { claim_id: Uuid },
    /// A claim already exists — the caller adopts a terminal outcome, re-claims a
    /// `failed_before_send` row, or polls a `claimed` one. Boxed (the row is large
    /// and this variant is the cold path).
    Existing(Box<ToolExecutionClaimRow>),
    /// The session stopped accepting work (cancelled/finalizing/terminal) before
    /// the claim could be taken — the brokered dispatch is refused.
    SessionTerminal,
}

/// Take (or find) the durable execution claim for one brokered dispatch. ONE
/// short transaction, NEVER held across the upstream HTTP call:
///   1. lock the sessions row `FOR UPDATE` (the cancellation lock order), then
///   2. re-read status in a SECOND statement (the [`crate::set_sandbox_handle`]
///      lock-then-read discipline — a single-statement predicate keeps a stale
///      command snapshot past a blocked lock, so a just-committed wind-down could
///      be missed) — refuse with [`ClaimOutcome::SessionTerminal`] if it no
///      longer `accepts_work()`, then
///   3. `insert … on conflict do nothing returning id` → [`ClaimOutcome::Won`],
///      else read the existing row → [`ClaimOutcome::Existing`].
///
/// LOCK-ORDER ANALYSIS (why this cannot deadlock with cancellation, the ledger,
/// or approvals — Phase E, #33):
///   - This tx acquires `sessions` (FOR UPDATE) → then `tool_execution_claims`
///     (INSERT/read). It NEVER touches `approvals` and NEVER calls `append_event`.
///     `reclaim_failed_before_send` uses the identical order.
///   - Cancellation (`transition_session`, `begin_finalization`) also takes the
///     SAME `sessions` row FOR UPDATE first. Two writers on one session therefore
///     SERIALIZE on that row: a cancel that commits first is SEEN here as
///     terminal (refuse); a claim that commits first means the dispatch was taken
///     under a proven-nonterminal snapshot. Same row, same order ⇒ no cycle.
///   - `append_event` (the ledger) locks `sessions` → `events` in a SEPARATE
///     transaction (record_brokered_exec runs AFTER this claim tx commits and
///     after `complete_tool_execution`, never nested). No tx ever holds a claim
///     row while waiting on `sessions`, so it can never block a cancel that holds
///     `sessions` while wanting a claim row — the classic cycle never forms.
///   - The stale-claim sweep (`system_worker`) updates claim rows + reads
///     `approvals`; it does NOT lock `sessions`, so it never waits on the lock
///     this tx holds. (Task 6's E12 nests `append_event` inside the approvals CAS
///     — approvals → sessions — which is a DIFFERENT resource pair; the claim tx's
///     never touching approvals keeps the two orderings disjoint.)
pub async fn claim_tool_execution(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
    tool_call_id: &str,
    input_digest: &str,
    ttl_secs: i64,
) -> sqlx::Result<ClaimOutcome> {
    let mut tx = scoped_tx(pool, scope).await?;
    let locked: Option<(String,)> =
        sqlx::query_as("select status from sessions where id = $1 and tenant_id = $2 for update")
            .bind(session_id)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?;
    let Some((status,)) = locked else {
        return Ok(ClaimOutcome::SessionTerminal);
    };
    if !SessionStatus::parse(&status).is_some_and(|s| s.accepts_work()) {
        return Ok(ClaimOutcome::SessionTerminal);
    }
    let expires = Utc::now() + chrono::Duration::seconds(ttl_secs.max(1));
    let won: Option<(Uuid,)> = sqlx::query_as(
        "insert into tool_execution_claims
             (tenant_id, session_id, tool_call_id, input_digest, state, claim_expires_at)
         values ($1, $2, $3, $4, 'claimed', $5)
         on conflict (session_id, tool_call_id, input_digest) do nothing
         returning id",
    )
    .bind(scope.tenant_id())
    .bind(session_id)
    .bind(tool_call_id)
    .bind(input_digest)
    .bind(expires)
    .fetch_optional(&mut *tx)
    .await?;
    let outcome = match won {
        Some((claim_id,)) => ClaimOutcome::Won { claim_id },
        None => {
            let row: ToolExecutionClaimRow = sqlx::query_as(
                "select * from tool_execution_claims
                 where session_id = $1 and tool_call_id = $2 and input_digest = $3
                   and tenant_id = $4",
            )
            .bind(session_id)
            .bind(tool_call_id)
            .bind(input_digest)
            .bind(scope.tenant_id())
            .fetch_one(&mut *tx)
            .await?;
            ClaimOutcome::Existing(Box::new(row))
        }
    };
    tx.commit().await?;
    Ok(outcome)
}

/// The outcome of [`complete_tool_execution`] (Phase E, #33; review I3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleOutcome {
    /// This dispatcher landed the `claimed → terminal` transition. Its locally
    /// computed result IS the durable one.
    Settled,
    /// The CAS lost: something else already made this claim terminal — in
    /// practice the stale-claim sweep, which moved an expired claim to
    /// `ambiguous` and ledgered that. The caller MUST answer from these durable
    /// columns, never from its own completion: the sweep's row is what every
    /// duplicate adopts and what the ledger says, so returning the local result
    /// would hand the original caller a success the audit trail contradicts.
    Superseded {
        state: String,
        result_content: Option<Value>,
        error_message: Option<String>,
    },
}

impl SettleOutcome {
    /// Did THIS caller land the transition? (The ledger writes on true only —
    /// a superseded dispatcher must not double-ledger the sweep's outcome.)
    pub fn settled(&self) -> bool {
        matches!(self, SettleOutcome::Settled)
    }
}

/// Settle a WON claim from `claimed` to a terminal state (CAS on
/// `state = 'claimed'`). `result_content` MUST be pre-capped by the caller
/// (reuse the broker's 256 KiB cap).
///
/// [`SettleOutcome::Settled`] iff this call landed the transition. A loser
/// (already swept to `ambiguous`, or a duplicate) gets
/// [`SettleOutcome::Superseded`] carrying the DURABLE row read in the SAME
/// transaction as the failed CAS — the claim is terminal by then, so that read
/// is stable, and it is the only answer the caller may return (review I3:
/// returning the local completion made the original caller see `succeeded`
/// while the ledger and every duplicate saw `ambiguous`). A vanished row (no
/// delete path exists for claims) degrades to `ambiguous`: we dispatched and
/// cannot prove the outcome, which is exactly what `ambiguous` means.
#[allow(clippy::too_many_arguments)]
pub async fn complete_tool_execution(
    pool: &PgPool,
    scope: TenantScope,
    claim_id: Uuid,
    state: &str,
    result_digest: Option<&str>,
    is_error: Option<bool>,
    result_content: Option<&Value>,
    error_message: Option<&str>,
) -> sqlx::Result<SettleOutcome> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update tool_execution_claims
            set state = $2, result_digest = $3, is_error = $4, result_content = $5,
                error_message = $6, completed_at = now()
          where id = $1 and tenant_id = $7 and state = 'claimed'",
    )
    .bind(claim_id)
    .bind(state)
    .bind(result_digest)
    .bind(is_error)
    .bind(result_content)
    .bind(error_message)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() == 1 {
        tx.commit().await?;
        return Ok(SettleOutcome::Settled);
    }
    // Lost the CAS → the row is ALREADY terminal. Read the durable outcome here,
    // inside the same transaction, so the caller can adopt it verbatim.
    let durable: Option<(String, Option<Value>, Option<String>)> = sqlx::query_as(
        "select state, result_content, error_message from tool_execution_claims
          where id = $1 and tenant_id = $2",
    )
    .bind(claim_id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(match durable {
        Some((state, result_content, error_message)) => SettleOutcome::Superseded {
            state,
            result_content,
            error_message,
        },
        None => SettleOutcome::Superseded {
            state: "ambiguous".to_string(),
            result_content: None,
            error_message: None,
        },
    })
}

/// The outcome of [`reclaim_failed_before_send`] (Phase E, #33; review I1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReclaimOutcome {
    /// This call won the re-claim: the row is `claimed` again and `attempt`
    /// carries the (bumped) number of the dispatch the caller now owns.
    Reclaimed { attempt: i32 },
    /// The row is still `failed_before_send` and has SPENT its attempt budget —
    /// no further dispatch may be taken for this `(session, tool_call_id,
    /// input_digest)`. The caller answers with a terminal-shaped tool error.
    Exhausted { attempt: i32 },
    /// Somebody else moved the row (a concurrent re-claim won it, a dispatcher
    /// re-settled it) or the session stopped accepting work — the caller polls.
    Lost,
}

/// Re-claim a `failed_before_send` row for a fresh dispatch — the ONLY
/// re-claimable state (positive proof nothing was sent). CAS
/// `failed_before_send → claimed`, `attempt + 1`, fresh expiry, and the result
/// columns reset, INSIDE the same sessions-`FOR UPDATE` nonterminal tx shape as
/// [`claim_tool_execution`].
///
/// **BOUNDED (review I1).** `max_attempts` caps the dispatches ONE claim row may
/// ever take: the CAS carries `attempt < $6`, so re-claiming is impossible past
/// the cap no matter how many handlers race. Without it a sandbox looping
/// `/tools/call` on one `tool_call_id` against a sick upstream re-claimed for
/// free forever — a breaker refusal charges no budget and emits no ledger event,
/// so each iteration cost only two exclusive `sessions`-row locks (this one plus
/// [`claim_tool_execution`]'s), taken on the very row `transition_session`,
/// `begin_finalization` and `append_event` need. The cap turns that unbounded
/// churn into a small constant, and `attempt` — previously written and read by
/// nothing — becomes the thing that bounds it.
///
/// HONEST SCOPE (review, minor): this function has NO reachable production caller
/// today. `images/runner-lib/broker-shim.mjs` mints a fresh `bkr_<uuid>`
/// `tool_call_id` for every MCP request, so a shipped runner never re-presents the
/// same `(tool_call_id, input_digest)` and never lands on an existing claim row.
/// The re-claimable property is therefore correct but VACUOUS in production; it
/// exists for a harness that does re-present an id (the runner contract permits
/// it, and `/permission`'s idempotency assumes it) and for the DB-gated tests.
/// Keep it — and keep it bounded.
pub async fn reclaim_failed_before_send(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
    tool_call_id: &str,
    input_digest: &str,
    ttl_secs: i64,
    max_attempts: i32,
) -> sqlx::Result<ReclaimOutcome> {
    let mut tx = scoped_tx(pool, scope).await?;
    let locked: Option<(String,)> =
        sqlx::query_as("select status from sessions where id = $1 and tenant_id = $2 for update")
            .bind(session_id)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?;
    let Some((status,)) = locked else {
        return Ok(ReclaimOutcome::Lost);
    };
    if !SessionStatus::parse(&status).is_some_and(|s| s.accepts_work()) {
        return Ok(ReclaimOutcome::Lost);
    }
    let expires = Utc::now() + chrono::Duration::seconds(ttl_secs.max(1));
    let reclaimed: Option<i32> = sqlx::query_scalar(
        "update tool_execution_claims
            set state = 'claimed', attempt = attempt + 1, claim_expires_at = $5,
                claimed_at = now(), completed_at = null, result_digest = null,
                is_error = null, result_content = null, error_message = null
          where session_id = $1 and tool_call_id = $2 and input_digest = $3
            and tenant_id = $4 and state = 'failed_before_send' and attempt < $6
        returning attempt",
    )
    .bind(session_id)
    .bind(tool_call_id)
    .bind(input_digest)
    .bind(scope.tenant_id())
    .bind(expires)
    .bind(max_attempts)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(attempt) = reclaimed {
        tx.commit().await?;
        return Ok(ReclaimOutcome::Reclaimed { attempt });
    }
    // Zero rows: either the cap is spent or somebody else moved the row. Tell the
    // two apart from the row itself so the caller can refuse TERMINALLY instead of
    // polling for 30 s on a claim that will never move again.
    let row: Option<(String, i32)> = sqlx::query_as(
        "select state, attempt from tool_execution_claims
          where session_id = $1 and tool_call_id = $2 and input_digest = $3 and tenant_id = $4",
    )
    .bind(session_id)
    .bind(tool_call_id)
    .bind(input_digest)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(match row {
        Some((state, attempt)) if state == "failed_before_send" && attempt >= max_attempts => {
            ReclaimOutcome::Exhausted { attempt }
        }
        _ => ReclaimOutcome::Lost,
    })
}

/// Read a claim by its natural key (the loser's bounded poll of an in-flight
/// `claimed` row, and the duplicate's adoption read).
pub async fn get_tool_execution(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
    tool_call_id: &str,
    input_digest: &str,
) -> sqlx::Result<Option<ToolExecutionClaimRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query_as(
        "select * from tool_execution_claims
         where session_id = $1 and tool_call_id = $2 and input_digest = $3 and tenant_id = $4",
    )
    .bind(session_id)
    .bind(tool_call_id)
    .bind(input_digest)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}
