//! Approvals and the tool-call intent registry they double as.

use crate::events::{append_event_in_tx, commit_and_mirror_events};
use crate::notify::APPROVALS_CHANNEL;
use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use fluidbox_core::event::{EventEnvelope, Redacted};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ApprovalRow {
    pub id: Uuid,
    pub session_id: Uuid,
    pub tool_call_id: String,
    pub tool: String,
    pub summary: String,
    pub input_digest: Option<String>,
    pub risk: Option<String>,
    pub scope: String,
    pub scope_key: String,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<String>,
}

// ─── Approvals & tool-call intents ────────────────────────────────────────
//
// Phase 6 gate hardening: the approvals table doubles as the INTENT registry.
// Every gate decision registers one row per (session_id, tool_call_id) —
// status 'intent' at registration, then either 'auto_allowed'/'auto_denied'
// (gate-decided) or the human approval lifecycle ('pending' → decided) when
// the verdict requires one. The row's (tool, input_digest) is the digest
// binding: a reused id must match it. tool_call_count counts these rows —
// unique persistent intents, never runner-posted events.

/// The full approvals column list as a literal, so every query below stays
/// a compile-time-audited static string (sqlx 0.9 SqlSafeStr).
macro_rules! approval_cols {
    () => {
        "id, session_id, tool_call_id, tool, summary, input_digest, risk, \
         scope, scope_key, status, requested_at, expires_at, decided_at, decided_by"
    };
}

/// Register a tool-call intent, idempotent by (session_id, tool_call_id).
/// Returns (row, inserted). When `inserted` is false the caller MUST compare
/// the row's (tool, input_digest) against the incoming call — a mismatch is
/// a protocol violation, never a re-attach.
pub async fn register_tool_intent(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    tool_call_id: &str,
    tool: &str,
    summary: &str,
    input_digest: &str,
) -> sqlx::Result<(ApprovalRow, bool)> {
    let mut tx = scoped_tx(pool, scope).await?;
    let inserted: Option<ApprovalRow> = sqlx::query_as(concat!(
        "insert into approvals
           (id, session_id, tool_call_id, tool, summary, input_digest, scope, scope_key,
            status, expires_at)
         select $1,$2,$3,$4,$5,$6,'once',$4,'intent', now()
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $7)
         on conflict (session_id, tool_call_id) do nothing
         returning ",
        approval_cols!()
    ))
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(tool_call_id)
    .bind(tool)
    .bind(summary)
    .bind(input_digest)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = inserted {
        tx.commit().await?;
        return Ok((row, true));
    }
    let existing: ApprovalRow = sqlx::query_as(concat!(
        "select ",
        approval_cols!(),
        " from approvals
         where session_id = $1 and tool_call_id = $2
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $3)"
    ))
    .bind(session)
    .bind(tool_call_id)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((existing, false))
}

/// Promote a registered intent into a pending human approval (the
/// RequireApproval path). Returns None when the row is no longer 'intent'
/// (a concurrent handler already promoted or the verdict landed) — the
/// caller re-reads and acts on the current status.
pub async fn promote_intent_to_pending(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    risk: Option<&str>,
    approval_scope: &str,
    scope_key: &str,
    ttl_secs: i64,
) -> sqlx::Result<Option<ApprovalRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(concat!(
        "update approvals
            set status = 'pending', risk = $2, scope = $3, scope_key = $4,
                expires_at = now() + make_interval(secs => $5)
          where id = $1 and status = 'intent'
            and exists (select 1 from sessions s
                        where s.id = approvals.session_id and s.tenant_id = $6)
          returning ",
        approval_cols!()
    ))
    .bind(id)
    .bind(risk)
    .bind(approval_scope)
    .bind(scope_key)
    .bind(ttl_secs as f64)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Record the gate's own verdict on an intent ('auto_allowed'/'auto_denied').
/// A compare-and-set guarded on status='intent': returns true iff THIS call
/// won the transition. A loser (another concurrent handler for the same
/// tool_call_id already moved the row, or a human decision landed) gets
/// false and must adopt the durable outcome instead of its locally-computed
/// verdict — that is what keeps one intent to one decision under races.
pub async fn record_intent_verdict(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    status: &str,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update approvals set status = $2, decided_at = now(), decided_by = 'gate'
         where id = $1 and status = 'intent'
           and exists (select 1 from sessions s
                       where s.id = approvals.session_id and s.tenant_id = $3)",
    )
    .bind(id)
    .bind(status)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

/// Decide a pending approval AND emit its canonical ledger events in ONE
/// transaction (Phase E, #33; Gap 13, plan E12). This is the single-emission fix:
/// before it, every awakened waiter emitted its own `approval.decided` +
/// `tool.decision`, so two handlers re-attached to one pending row double-ledgered
/// **inside a single process** (design :1058-1066) — a current bug, not merely a
/// multi-replica one. Now the DECISION CAS is the emitter: a loser of the CAS
/// affects zero rows and appends nothing, and waiters emit neither event.
///
/// `events` are pre-scrubbed by the caller (the `Redacted` newtype is
/// constructible only through `Redactor::scrub`, so the ledger invariant holds)
/// and are DISCARDED untouched when the CAS loses.
///
/// LOCK ORDER — BINDING (Phase E, #33): **approvals CAS FIRST, then
/// `append_event`** (which locks the `sessions` row to assign the gapless seq).
/// Every decision site in this codebase uses that order: this function, its
/// [`expire_approval_tx`] sibling, and the waiter timeout path (which calls this
/// one). See [`crate::claim_tool_execution`]'s LOCK-ORDER ANALYSIS for why this cannot
/// cycle with the claim/cancellation order: that transaction takes `sessions`
/// FIRST and then `tool_execution_claims`, and NEVER touches `approvals`, so the
/// two orderings operate on DISJOINT resource pairs — `{approvals, sessions}` here
/// versus `{sessions, tool_execution_claims}` there — and a cycle needs both
/// transactions to want each other's held resource.
///
/// The commit also `pg_notify`s [`APPROVALS_CHANNEL`] so waiters on OTHER replicas
/// wake immediately instead of riding the ≤2 s poll floor (which stays as the
/// missed-notify backstop).
pub async fn decide_approval_tx(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    status: &str,
    decided_by: &str,
    events: Vec<Redacted<EventEnvelope>>,
) -> sqlx::Result<Option<ApprovalRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let decided: Option<ApprovalRow> = sqlx::query_as(concat!(
        "update approvals set status = $2, decided_at = now(), decided_by = $3
         where id = $1 and status = 'pending'
           and exists (select 1 from sessions s
                       where s.id = approvals.session_id and s.tenant_id = $4)
         returning ",
        approval_cols!()
    ))
    .bind(id)
    .bind(status)
    .bind(decided_by)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = decided else {
        // Lost the CAS (already decided/expired, or another tenant). Nothing is
        // written and NOTHING is ledgered — that is the whole point.
        tx.commit().await?;
        return Ok(None);
    };
    let seqs = emit_and_notify(&mut tx, scope, id, &events).await?;
    commit_and_mirror_events(tx, scope, &events, &seqs).await?;
    Ok(Some(row))
}

/// Expire ONE pending approval past its deadline and emit its ledger events in
/// the same transaction — the cross-replica-safe expiry decision site (Phase E,
/// #33). Single-winner by the `status = 'pending' and expires_at < now()` CAS, so
/// N replicas sweeping the same row produce exactly one decision and one pair of
/// events. Same binding lock order as [`decide_approval_tx`].
pub async fn expire_approval_tx(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    events: Vec<Redacted<EventEnvelope>>,
) -> sqlx::Result<Option<ApprovalRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let expired: Option<ApprovalRow> = sqlx::query_as(concat!(
        "update approvals set status = 'expired', decided_at = now(), decided_by = 'timeout'
         where id = $1 and status = 'pending' and expires_at < now()
           and exists (select 1 from sessions s
                       where s.id = approvals.session_id and s.tenant_id = $2)
         returning ",
        approval_cols!()
    ))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = expired else {
        tx.commit().await?;
        return Ok(None);
    };
    let seqs = emit_and_notify(&mut tx, scope, id, &events).await?;
    commit_and_mirror_events(tx, scope, &events, &seqs).await?;
    Ok(Some(row))
}

/// Shared tail of every decision transaction: append the pre-scrubbed events (in
/// order, so `approval.decided` precedes `tool.decision` exactly as the old waiter
/// emission did) and announce the decision on [`APPROVALS_CHANNEL`]. Runs AFTER
/// the approvals CAS, inside its transaction — the binding lock order.
///
/// DELIBERATE BEHAVIOR CHANGE (Phase E, #33; review Minor E): the `?` below is
/// inside the decision's transaction, so a failed ledger append now ROLLS BACK THE
/// DECISION ITSELF — the approve/deny CAS and its audit rows commit together or
/// not at all, making the ledger a hard dependency of deciding an approval. That
/// is chosen fail-closed: a decision the timeline cannot prove is worse than a
/// decision that must be retried (the runner re-attaches to the still-pending row
/// and the human's verdict is re-appliable), and the previous split — CAS commits,
/// then a best-effort `ledger::record` swallows its error — could silently diverge
/// the audit trail from the durable verdict.
async fn emit_and_notify(
    tx: &mut sqlx::PgConnection,
    scope: TenantScope,
    approval_id: Uuid,
    events: &[Redacted<EventEnvelope>],
) -> sqlx::Result<Vec<i64>> {
    let mut seqs = Vec::with_capacity(events.len());
    for ev in events {
        seqs.push(append_event_in_tx(&mut *tx, scope, ev).await?);
    }
    sqlx::query("select pg_notify($1, $2)")
        .bind(APPROVALS_CHANNEL)
        .bind(approval_id.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(seqs)
}

/// Claim the RIGHT to ledger the post-approval-wait terminality deny AND emit it,
/// in ONE transaction, exactly once (Phase E, #33; plan E12 "M4"). The session can
/// terminalize DURING a minutes-long approval wait, in which case an approved call
/// must still be refused — but EVERY re-attached waiter computes that same
/// refusal, so the ledger write needs a single-winner CAS just like the
/// deterministic gate paths. `terminal_deny_at` (migration 0021) is that marker: it
/// is NOT a verdict (the human decision stays immutable in `status`), only a record
/// that the deny was ledgered. Returns true iff THIS caller won and emitted.
///
/// IN-TX BY THE SAME RULE AS ITS THREE SIBLINGS (review Minor A): the first cut
/// committed the marker and then called `ledger::record` in a separate,
/// error-swallowing transaction, so a crash (or a transient append failure) between
/// them lost the event PERMANENTLY — the marker blocks every other waiter from
/// emitting, and nothing ever re-emits. Appending inside the claim's own
/// transaction makes marker-and-event atomic: a failed append rolls the marker back
/// and the next waiter (or the runner's retry) re-claims and re-emits. Same
/// fail-closed trade as [`emit_and_notify`], and the same binding lock order
/// (approvals FIRST, then `append_event`'s `sessions` row lock).
///
/// No `pg_notify` here, unlike [`emit_and_notify`]: this is not a decision, so no
/// waiter is blocked on it — every waiter reaching this point has already left the
/// wait loop.
pub async fn claim_terminal_deny_tx(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    events: Vec<Redacted<EventEnvelope>>,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update approvals set terminal_deny_at = now()
         where id = $1 and terminal_deny_at is null
           and exists (select 1 from sessions s
                       where s.id = approvals.session_id and s.tenant_id = $2)",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() == 0 {
        // Lost the claim — another waiter already ledgered this deny. The events
        // are DISCARDED untouched, exactly as a lost decision CAS discards its own.
        tx.commit().await?;
        return Ok(false);
    }
    let mut seqs = Vec::with_capacity(events.len());
    for ev in &events {
        seqs.push(append_event_in_tx(&mut tx, scope, ev).await?);
    }
    commit_and_mirror_events(tx, scope, &events, &seqs).await?;
    Ok(true)
}

pub async fn get_approval(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<ApprovalRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(concat!(
        "select ",
        approval_cols!(),
        " from approvals
         where id = $1
           and exists (select 1 from sessions s
                       where s.id = approvals.session_id and s.tenant_id = $2)"
    ))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Human-lifecycle rows only: intent bookkeeping ('intent'/'auto_*') is the
/// gate's, not the approvals API's.
pub async fn session_approvals(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Vec<ApprovalRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(concat!(
        "select ",
        approval_cols!(),
        " from approvals
         where session_id = $1 and status not in ('intent','auto_allowed','auto_denied')
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)
         order by requested_at desc"
    ))
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The tenant-scoped approvals inbox (the org approval queue). The
/// cross-tenant expiry scan runs off [`crate::system_worker::expired_pending_approvals`];
/// this one is what a request handler shows an approver, and it never crosses a
/// tenant boundary.
pub async fn pending_approvals(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<ApprovalRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(concat!(
        "select ",
        approval_cols!(),
        " from approvals
         where status = 'pending'
           and exists (select 1 from sessions s
                       where s.id = approvals.session_id and s.tenant_id = $1)
         order by requested_at"
    ))
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Has this session already granted `approved_session` for this scope key?
pub async fn has_session_grant(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    scope_key: &str,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select exists(
           select 1 from approvals
           where session_id = $1 and scope_key = $2 and status = 'approved_session'
             and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $3)
         ) as granted",
    )
    .bind(session)
    .bind(scope_key)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.get::<bool, _>("granted"))
}
