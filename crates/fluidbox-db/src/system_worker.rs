//! System-worker repositories: the narrowly named, deliberately tenant-less
//! scans and lookups the parent design permits (`docs/plans/2026-07-14-
//! multi-user-mcp-control-plane-design.md`, "Database isolation": *"Generic
//! UUID-only methods are forbidden OUTSIDE narrowly named system-worker
//! repositories"*).
//!
//! Every row a lookup here returns carries `tenant_id`; the invariant is that a
//! caller constructs a [`TenantScope`](crate::TenantScope) from a VERIFIED
//! tenant id before touching any tenant-scoped repository. Nothing here decides
//! authorization — these are the trusted entry points that resolve which tenant
//! a bare id belongs to, never a bypass of the scoped surface.
//!
//! There are exactly THREE sanctioned categories of caller:
//!
//! (a) **Background workers that derive scope from the returned row.** The
//!     heartbeat watchdog, wall-clock budget sweeper, approval-expiry scan
//!     ([`expired_pending_approvals`] — READ ONLY since Phase E; the decision
//!     itself is the scoped, single-winner `expire_approval_tx` so it can emit
//!     its ledger events in the same transaction), the stale-execution-claim
//!     sweep ([`sweep_stale_execution_claims`], Gap 11 — CAS a crashed `claimed`
//!     row to `ambiguous` past its expiry), the expired-LLM-reservation sweep
//!     ([`sweep_expired_llm_reservations`], Gap 14 — convert a crashed booking into
//!     a conservative `usage_entries` row and CAS it to `charged`), the
//!     restart-recoverable finalize
//!     driver, the managed-sandbox reconciler, and the delivery worker
//!     ([`claim_due_deliveries`] — Phase E: the scan now STAMPS a per-row claim
//!     under `for update skip locked` so replicas take disjoint sets) each act on
//!     ids/status across ALL tenants by construction (a global scan), then scope
//!     every mutation to the `tenant_id` of the row they just fetched.
//!
//! (b) **Credential-verification bootstrap resolvers for UNAUTHENTICATED
//!     ingress/callbacks.** Webhook ingress (HMAC via [`get_connection`]),
//!     app-level GitHub ingress ([`get_github_app_registration`]), and the
//!     sealed-`state` connector/login OAuth callbacks arrive with no principal.
//!     The lookup runs BEFORE verification only to fetch the material the
//!     verification needs (the connection's sealed secret, the registration's
//!     webhook secret). A [`TenantScope`](crate::TenantScope) is constructed
//!     ONLY AFTER the signature/sealed-state verifies — the resolved row's
//!     tenant is not trusted as scope until then.
//!
//! (c) **Re-seal migration parity (Phase D, #32).** The envelope-sealing
//!     retirement gates and the (Task 2) re-seal job walk EVERY tenant's sealed
//!     rows — a global scan by construction. [`sealed_key_version_counts`]
//!     aggregates per-family legacy/envelope counts across all tenants (no
//!     tenant predicate) to prove 100% re-seal before the legacy key retires; it
//!     returns no credential material, only counts. The job's paged reader
//!     [`reseal_candidate_ids`] and per-row lock/CAS pair
//!     [`reseal_lock_row`]/[`reseal_write_row`] are cross-tenant by the same
//!     construction — they carry the row's `tenant_id` back out so the SERVER
//!     unseals/re-seals under the right per-tenant DEK; plaintext NEVER transits
//!     this crate (sealed bytes out, sealed bytes back in). [`dek_kek_census`] is
//!     the same category for KEK custody: which KEK(s) wrapped the stored DEKs is
//!     a deployment-wide question, and a GUC-less read of it would return zero
//!     rows and make the boot gate FAIL OPEN.
//!
//! (d) **Nothing else.** A request handler that carries a principal MUST use the
//!     scoped repositories (`get_session`, `get_connection`, … with a
//!     `TenantScope`), never these bare-id loaders.
//!
//! **GUC-bypass contract (Phase D, #32, #75).** Under the migration-0018 RLS
//! policies (ENABLE + FORCE on every tenant-owned table), a query with NO
//! `fluidbox.tenant_id` or `fluidbox.bypass` GUC sees ZERO rows — so EVERY function
//! in this module opens its transaction with [`crate::worker_tx`], which sets
//! `fluidbox.bypass = 'system_worker'` transaction-locally. That is the audited
//! bypass: the category lives IN the GUC value, and this is the ONLY module whose
//! functions legitimately span tenants.
//!
//! Be precise about the guarantee: `worker_tx` is `pub(crate)`, so the server crate
//! cannot ASSEMBLE a bypass ad-hoc — it must go through a function named below. That
//! is NOT the same as "the server can never hold a bypass-armed transaction": a few
//! entry points in this module ([`reseal_begin`], [`global_registration_tx`]) are
//! `pub` and deliberately HAND ONE OUT, because their callers drive a multi-statement
//! critical section (a row lock + CAS; an advisory lock + find-or-insert) that cannot
//! be expressed as a single call. The property is therefore "a short, named,
//! grep-able set of escape hatches, each with a documented consumer" — not
//! "unreachable". The bypass is deliberate and grep-able, not ambient: prove it by
//! running one of these queries WITHOUT `worker_tx` and it returns nothing (there is
//! a test for exactly that).
//!
//! ## The FULL bypass-bearing inventory (review L6)
//!
//! "The server reaches a bypass only through `system_worker`" was never literally
//! true: `crate` and `crate::identity` expose their own public functions that call
//! [`crate::worker_tx`] internally, for the pre-auth categories above. They stay
//! where they are (they belong to their repository's family, not to the worker
//! scans), so the honest guarantee is this ENUMERATION. `rg 'worker_tx\('` over
//! `crates/fluidbox-db/src` must yield exactly this set plus this module:
//!
//! * **`crate` (lib.rs)** — `ensure_default_tenant` (boot seed: the tenant's own id
//!   is not yet any GUC's tenant); `session_for_token`,
//!   `session_for_token_incl_revoked`, `extend_session_token`,
//!   `subscription_for_token` (token-DIGEST resolution — the tenant is unknown until
//!   the secret resolves); `claim_connector_oauth_flow`, `peek_connector_oauth_flow`,
//!   `claim_github_app_bootstrap`, `claim_github_app_flow` (one-time PRE-AUTH claims
//!   where a sealed `state` param or a browser-cookie hash inside the predicate IS
//!   the auth).
//! * **`crate::identity`** — `create_org`, `create_org_audited` (a brand-new tenant
//!   row plus its audit row; nothing can be scoped to a tenant that does not exist
//!   yet); `get_org_by_slug`, `list_orgs`, `active_idp_config` (pre-auth login
//!   routing — slug → org → active IdP, before any principal); `claim_login_flow`,
//!   `claim_pending_switch` (browser-bound one-time claims); `resolve_web_session`,
//!   `resolve_pat` (cookie/PAT digest resolution); `insert_audit_standalone` — ONLY
//!   on its `tenant_id: None` branch, which is a DEPLOYMENT-level operator row that
//!   belongs to no tenant (a rejected login, an admin refusal, a re-seal run); the
//!   `Some(tenant)` branch is scoped like any other write.
//! * **`crate::mcp_sessions`** (Phase F, Task 3) —
//!   `sweep_orphaned_upstream_sessions` ONLY: the deployment-wide GC that retires
//!   `mcp_upstream_sessions` rows whose run reached a terminal status a grace period
//!   ago. A category (a) global scan by construction (it must find rows a CRASHED
//!   replica left behind, across every tenant), returning each row's own `tenant_id`
//!   to the caller. Every other function in that module is `scoped_tx`.
//! * **everything in this module**, including the two `pub` tx hand-outs.
//!
//! Anything NOT on that list is scoped, and adding to it is a review event. The
//! authenticated GitHub-App flow MINT used to be here out of convenience — it holds
//! a verified tenant at all three call sites — and is now `scoped_tx`
//! ([`crate::create_github_app_flow`]); only the two CLAIMs remain pre-auth.
//!
//! These DB-resolved rows are just ONE of the documented ways a
//! [`TenantScope`](crate::TenantScope) is constructed without a principal
//! credential — see its type docs for the full, precise set (the two
//! credential-like exceptions keyed on a token/cookie digest; design-mandated
//! pre-auth org routing for login-flow creation plus the operator org-CRUD
//! surfaces; and the boot seed). None expose a tenant-owned resource without a
//! verified tenant id.

use crate::{
    GithubAppRegistrationRow, IntegrationConnectionRow, ResultDeliveryRow, ScheduleRow, SessionRow,
    TriggerSubscriptionRow,
};
use crate::{CONNECTION_COLS, GH_REG_COLS, SUBSCRIPTION_COLS};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Load a session by id with NO tenant predicate — the cross-tenant loader for
/// workers that hold only a bare session id sourced from a provider list
/// (`ExecutionProvider::list_managed`) or a global scan (a spawned run task, a
/// delivery row, a finalization intent). The returned row carries `tenant_id`,
/// from which the caller builds the `TenantScope` for every subsequent scoped
/// call. Request handlers must use the scoped [`get_session`](crate::get_session).
pub async fn get_session(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<SessionRow>> {
    let mut tx = crate::worker_tx(pool).await?;
    let out = sqlx::query_as("select * from sessions where id = $1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(out)
}

/// Load a connection by id with NO tenant predicate — the cross-tenant loader
/// for the UNAUTHENTICATED webhook ingress path (`POST /v1/ingress/...`), which
/// receives a bare connection id in the URL and no principal: the webhook
/// signature (verified against the connection's sealed secret) IS the auth, and
/// the connection's own `tenant_id` becomes the operative scope for the rest of
/// the delivery spine. Request handlers must use the scoped
/// [`get_connection`](crate::get_connection). Selects the same explicit column
/// list (never the sealed credential).
pub async fn get_connection(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    let mut tx = crate::worker_tx(pool).await?;
    let out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections where id = $1"
    )))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// Verification-material reader for the UNAUTHENTICATED per-connection webhook
/// ingress path: returns ONLY the connection's sealed webhook-secret bytes, by
/// bare id and with NO tenant predicate. It runs BEFORE verification so the
/// HMAC can be checked; a [`TenantScope`](crate::TenantScope) is constructed
/// from the (already resolved, status-checked) connection row's tenant only
/// AFTER the signature verifies. The scoped
/// [`connection_webhook_secret_sealed`](crate::connection_webhook_secret_sealed)
/// stays the reader for authenticated surfaces. `None` = no row / no secret.
pub async fn connection_webhook_secret_sealed(
    pool: &PgPool,
    connection_id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let mut tx = crate::worker_tx(pool).await?;
    let row: Option<(Option<Vec<u8>>, i16)> = sqlx::query_as(
        "select webhook_secret_sealed, webhook_secret_key_version
         from integration_connections where id = $1",
    )
    .bind(connection_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(|(s, v)| s.map(|s| (s, v))))
}

/// Load a trigger subscription by id with NO tenant predicate — the
/// cross-tenant loader for the scheduler, which holds only a bare
/// subscription id sourced from the global `due_schedules` scan. The returned
/// row carries `tenant_id`, from which the scheduler builds the `TenantScope`
/// for every subsequent scoped call (claim_invocation, mark_invocation_skipped,
/// create_run, advance_schedule). Request handlers must use the scoped
/// [`get_trigger_subscription`](crate::get_trigger_subscription).
pub async fn get_trigger_subscription(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<TriggerSubscriptionRow>> {
    let mut tx = crate::worker_tx(pool).await?;
    let out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {SUBSCRIPTION_COLS} from trigger_subscriptions where id = $1"
    )))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// Load a GitHub App registration by id with NO tenant predicate — the
/// cross-tenant loader for the UNAUTHENTICATED app-level webhook ingress
/// (`POST /v1/ingress/github/app/{registration_id}`), which receives a bare
/// registration id in the URL and no principal: the HMAC against the
/// registration's own sealed webhook secret IS the auth, and the
/// registration's `tenant_id` becomes the operative scope for the rest of the
/// delivery spine (exactly parallel to [`get_connection`] on the per-connection
/// ingress). Request handlers must use the scoped
/// [`get_github_app_registration`](crate::get_github_app_registration).
pub async fn get_github_app_registration(
    pool: &PgPool,
    id: Uuid,
) -> sqlx::Result<Option<GithubAppRegistrationRow>> {
    let mut tx = crate::worker_tx(pool).await?;
    let out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {GH_REG_COLS} from github_app_registrations where id = $1"
    )))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// Verification-material reader for the UNAUTHENTICATED app-level GitHub
/// ingress path: returns ONLY the registration's sealed webhook-secret bytes,
/// by bare id and with NO tenant predicate. Runs BEFORE verification (exactly
/// parallel to [`connection_webhook_secret_sealed`]); the registration's
/// tenant becomes the operative scope only AFTER the HMAC verifies. The scoped
/// [`github_app_registration_webhook_secret_sealed`](crate::github_app_registration_webhook_secret_sealed)
/// stays the reader for authenticated surfaces. `None` = no row / no secret.
pub async fn github_app_registration_webhook_secret_sealed(
    pool: &PgPool,
    registration_id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let mut tx = crate::worker_tx(pool).await?;
    let row: Option<(Option<Vec<u8>>, i16)> = sqlx::query_as(
        "select webhook_secret_sealed, webhook_secret_key_version
         from github_app_registrations where id = $1",
    )
    .bind(registration_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(|(s, v)| s.map(|s| (s, v))))
}

pub async fn sessions_in_status(pool: &PgPool, statuses: &[&str]) -> sqlx::Result<Vec<SessionRow>> {
    let list: Vec<String> = statuses.iter().map(|s| s.to_string()).collect();
    let mut tx = crate::worker_tx(pool).await?;
    let out = sqlx::query_as("select * from sessions where status = any($1)")
        .bind(&list)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(out)
}

/// Sessions stuck before launch. The orchestrator moves created →
/// provisioning → initializing in seconds (initializing: minutes at worst
/// for a big repo copy), so a stale row means the control plane died
/// mid-launch and nothing owns the session anymore.
///
/// Age is measured from `created_at` — a timestamp NOTHING refreshes. It used
/// to be `updated_at`, which every runner heartbeat bumps: a crash between
/// runner start and `set_sandbox_handle` left a heartbeating `initializing`
/// session this sweep could never age out (M5).
pub async fn stale_nonstarted_sessions(
    pool: &PgPool,
    max_age_mins: i32,
) -> sqlx::Result<Vec<SessionRow>> {
    let mut tx = crate::worker_tx(pool).await?;
    let out = sqlx::query_as(
        "select * from sessions
         where status = any($1) and created_at < now() - make_interval(mins => $2)",
    )
    .bind(vec![
        "created".to_string(),
        "provisioning".to_string(),
        "initializing".to_string(),
    ])
    .bind(max_age_mins)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// Every persisted finalization intent, oldest first — the restart-recovery
/// worklist. Status-blind BY DESIGN: an intent whose session is still ACTIVE
/// is the crash-between-persist-and-transition window (the wind-down state
/// never landed), and an intent whose session is already TERMINAL is cleanup
/// still owed (reap, workspace/archive removal, delivery reconciliation).
/// Both must be re-driven; the intent row is deleted only once nothing is
/// owed, so this list self-drains.
pub async fn pending_finalizations(pool: &PgPool) -> sqlx::Result<Vec<Uuid>> {
    let mut tx = crate::worker_tx(pool).await?;
    let rows: Vec<(Uuid,)> =
        sqlx::query_as("select session_id from session_finalizations order by created_at asc")
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// One pending approval past its deadline, plus the tenant its session belongs to
/// and the facts the ledger events need. The tenant rides the row so the caller
/// can decide it under a SCOPED transaction (`expire_approval_tx`) instead of
/// bulk-expiring cross-tenant.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ExpiredApprovalRow {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub session_id: Uuid,
    pub tool_call_id: String,
    pub tool: String,
}

/// Pending approvals whose deadline has passed — a cross-tenant READ scan; it
/// decides nothing (Phase E, #33; Gap 13).
///
/// Deliberately split from the write: the old shape was one bulk cross-tenant
/// UPDATE, which cannot emit the canonical `approval.decided` / `tool.decision`
/// events in its own transaction (the ledger only accepts `Redacted` envelopes the
/// SERVER builds per row, and each row belongs to a different tenant). The worker
/// now scans here and calls the scoped, single-winner `expire_approval_tx` per
/// row, so the expiry decision emits its events atomically like every other
/// decision site, and N replicas sweeping the same row still produce exactly ONE
/// decision — the CAS in that function is the winner test.
pub async fn expired_pending_approvals(
    pool: &PgPool,
    limit: i64,
) -> sqlx::Result<Vec<ExpiredApprovalRow>> {
    let mut tx = crate::worker_tx(pool).await?;
    let out = sqlx::query_as(
        "select s.tenant_id, a.id, a.session_id, a.tool_call_id, a.tool
           from approvals a join sessions s on s.id = a.session_id
          where a.status = 'pending' and a.expires_at < now()
          order by a.expires_at limit $1",
    )
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// One reservation the expiry sweep converted into a conservative charge.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SweptReservation {
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub request_id: Uuid,
    pub reserved_tokens: i64,
    pub reserved_cost_usd: Option<f64>,
}

/// Sweep expired LLM budget reservations (Phase E, #33; Gap 14): a `reserved` row
/// whose facade request died without reconciling never settles, so past its
/// `expires_at` it is CONVERTED — a conservative `usage_entries` row written under
/// `external_id = <request id>` with `source = 'reservation_timeout'`, then a CAS
/// to `charged`. Design :1122-1123: on crash/timeout with unknown provider usage
/// RETAIN the conservative charge, never assume zero.
///
/// IDEMPOTENT IN EITHER ORDER, which is the whole point of keying on the request
/// id. If the drain task recorded authoritative usage first, this insert hits the
/// partial-unique `usage_external` index and is a no-op (the real number wins) — the
/// CAS then finds no `reserved` row and returns nothing. If the sweep lands first,
/// a late drain's `add_usage` is the no-op and its `charge_llm_reservation` CAS
/// returns false. Neither path can double-charge.
///
/// `for update skip locked` makes two replicas' sweeps DISJOINT (the delivery-claim
/// discipline), and the whole conversion is ONE statement so a crash between the
/// usage row and the CAS is impossible. Cross-tenant by construction; every
/// returned row carries its own `tenant_id` so the caller ledgers under the right
/// scope. The reservation TTL is set well beyond the facade's upstream request
/// timeout, so an expired row means the process died — not that a request is slow.
pub async fn sweep_expired_llm_reservations(
    pool: &PgPool,
    now: DateTime<Utc>,
    limit: i64,
) -> sqlx::Result<Vec<SweptReservation>> {
    let mut tx = crate::worker_tx(pool).await?;
    let out = sqlx::query_as(
        "with expired as (
             select id, tenant_id, session_id, model, reserved_tokens, reserved_cost_usd
               from llm_reservations
              where state = 'reserved' and expires_at < $1
              order by expires_at
              limit $2
              for update skip locked
         ),
         ins as (
             insert into usage_entries
                 (id, session_id, model, input_tokens, output_tokens,
                  cache_read_tokens, cache_write_tokens, cost_usd, source, external_id)
             select gen_random_uuid(), e.session_id, e.model, 0, e.reserved_tokens, 0, 0,
                    e.reserved_cost_usd, 'reservation_timeout', e.id::text
               from expired e
             on conflict (external_id) where external_id is not null do nothing
         ),
         settled as (
             update llm_reservations r set state = 'charged'
               from expired e
              where r.id = e.id and r.state = 'reserved'
             returning r.tenant_id, r.session_id, r.id as request_id,
                       r.reserved_tokens, r.reserved_cost_usd
         )
         select tenant_id, session_id, request_id, reserved_tokens, reserved_cost_usd
           from settled",
    )
    .bind(now)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// Sweep stale execution claims (Phase E, #33; Gap 11): a `claimed` row whose
/// dispatcher crashed mid-flight never completes, so past its `claim_expires_at`
/// it is CAS'd to `ambiguous` (never retried — invariant 15). A cross-tenant
/// global scan like the other sweeps; each returned tuple carries its own
/// `tenant_id` so the caller ledgers the ambiguous outcome under the right scope.
/// The correlated subquery adopts the tool name from the owning intent row so the
/// `tool.brokered` audit event names the tool (NULL only if the intent is gone).
///
/// BOUNDED like the reservation sweep beside it (review, minor): `limit` +
/// `for update skip locked`. Unbounded it was still CORRECT under concurrency (the
/// `state = 'claimed'` CAS makes a double-sweep impossible), but a large backlog
/// turned one 10 s tick into a single unbounded UPDATE plus N SERIAL ledger writes
/// — the caller appends one `tool.brokered` per swept row, each its own
/// transaction — so the tick could outrun its own period. A slice per tick drains
/// at a steady rate instead; `order by claim_expires_at` keeps it FIFO so nothing
/// starves, and `skip locked` keeps two replicas' slices disjoint.
pub async fn sweep_stale_execution_claims(
    pool: &PgPool,
    now: DateTime<Utc>,
    limit: i64,
) -> sqlx::Result<Vec<(Uuid, Uuid, String, Option<String>)>> {
    let mut tx = crate::worker_tx(pool).await?;
    let rows: Vec<(Uuid, Uuid, String, Option<String>)> = sqlx::query_as(
        "with stale as (
             select id from tool_execution_claims
              where state = 'claimed' and claim_expires_at < $1
              order by claim_expires_at
              limit $2
              for update skip locked
         )
         update tool_execution_claims c
            set state = 'ambiguous', completed_at = now(),
                error_message = coalesce(c.error_message,
                    'execution claim expired — outcome unknown')
           from stale s
          where c.id = s.id and c.state = 'claimed'
        returning c.tenant_id, c.session_id, c.tool_call_id,
                  (select a.tool from approvals a
                    where a.session_id = c.session_id
                      and a.tool_call_id = c.tool_call_id) as tool",
    )
    .bind(now)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows)
}

/// Due work for the (single, sequential) scheduler worker — a cross-tenant
/// global scan, like the other system-worker queries. No row locking: there
/// is one scheduler task per server and firings are awaited one at a time. A
/// disabled subscription's schedule is not due and does NOT advance:
/// re-enabling turns the gap into a missed-run case, exactly like an outage.
/// Each row carries its subscription; the caller resolves the owning tenant
/// (via `get_trigger_subscription`) before firing through `create_run`.
pub async fn due_schedules(pool: &PgPool, limit: i64) -> sqlx::Result<Vec<ScheduleRow>> {
    let mut tx = crate::worker_tx(pool).await?;
    let out = sqlx::query_as(
        "select sc.* from schedules sc
         join trigger_subscriptions sub on sub.id = sc.subscription_id
         where sc.next_fire_at is not null and sc.next_fire_at <= now() and sub.enabled
         order by sc.next_fire_at limit $1",
    )
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

/// CLAIM due work for the delivery worker — a cross-tenant global scan that now
/// takes a per-row lease in the SAME transaction (Phase E, #33; Gap 13; design
/// :1079-1084). Previously an unlocked `select`: with two replicas both polled the
/// same due rows and both POSTed them.
///
/// `for update skip locked` inside the CTE is what makes the sets DISJOINT — a row
/// another replica is claiming in a concurrent transaction is skipped, never
/// waited on, so neither worker blocks. The claim is then stamped
/// (`claimed_by`/`claimed_until`) so the row stays off other replicas' scans for
/// `ttl_secs` even after this transaction commits; `mark_delivery_attempt` is
/// guarded on that owner and releases the claim.
///
/// A claim whose holder crashed simply expires (`claimed_until < now()`) and the
/// row returns to the pool — time-based takeover, the same discipline as the
/// finalization claim and the session lease, and for the same reason (advisory
/// locks are rejected: design :1067-1072).
///
/// This fences concurrent ATTEMPTS. Delivery remains at-least-once across crashes
/// (a crash between the external POST and `mark_delivery_attempt` re-attempts):
/// webhook receivers dedup on `x-fluidbox-delivery`, and the GitHub create path
/// closes its own crash window by reconcile-before-create against a deterministic
/// comment marker.
pub async fn claim_due_deliveries(
    pool: &PgPool,
    owner: Uuid,
    limit: i64,
    ttl_secs: i64,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    let mut tx = crate::worker_tx(pool).await?;
    let out = sqlx::query_as(
        "with due as (
             select id from result_deliveries
              where status = 'pending' and next_attempt_at <= now()
                and (claimed_until is null or claimed_until < now() or claimed_by = $1)
              order by next_attempt_at
              limit $2
              for update skip locked
         )
         update result_deliveries d
            set claimed_by = $1,
                claimed_until = now() + make_interval(secs => $3),
                updated_at = now()
           from due
          where d.id = due.id
         returning d.*",
    )
    .bind(owner)
    .bind(limit)
    .bind(ttl_secs.max(1) as f64)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

// ─── KEK custody census (Phase D, #32; category (c) above) ──────────────────

/// One distinct KEK found in `tenant_deks`, with a sample row to probe against.
/// `wrapped_dek` is already-WRAPPED key material (exactly what is stored) — this
/// crate never sees, and never returns, a plaintext key.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DekKekSample {
    pub kek_id: String,
    pub tenant_id: Uuid,
    pub version: i32,
    pub wrapped_dek: Vec<u8>,
}

/// The DISTINCT KEKs that wrapped the stored per-tenant DEKs, one sample row each
/// — the input to the server's boot-time KEK-compatibility gate.
///
/// BOOT-PATH CARVE-OUT, same shape as [`sealed_key_version_counts`]: "which KEK(s)
/// wrapped this deployment's DEKs" is a deployment-wide key-management question
/// asked with no principal, so it is cross-tenant by construction and rides the
/// audited system-worker bypass. Without the GUC, FORCE RLS returns ZERO rows and
/// the gate reads that as "no DEKs stored yet" — it would FAIL OPEN and boot a
/// deployment whose configured KEK cannot open any stored DEK, which is precisely
/// the split-key database the gate exists to prevent. It lives HERE, named, rather
/// than as ad-hoc SQL riding [`reseal_begin`]'s hand-out, so the bypass inventory
/// above stays complete.
pub async fn dek_kek_census(pool: &PgPool) -> sqlx::Result<Vec<DekKekSample>> {
    let mut tx = crate::worker_tx(pool).await?;
    let out = sqlx::query_as(
        "select distinct on (kek_id) kek_id, tenant_id, version, wrapped_dek
           from tenant_deks
          order by kek_id, tenant_id, version",
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

// ─── Re-seal migration parity (Phase D, #32; category (d) above) ────────────

/// Per-family sealed-row counts for the envelope re-seal (category (d)). One row
/// per sealed `table.column`; `legacy` = rows still v1, `envelope` = rows already
/// v2. Retirement is complete for a family when `legacy = 0`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FamilyKeyVersionCounts {
    pub family: String,
    pub legacy: i64,
    pub envelope: i64,
}

/// Count legacy (v1) vs envelope (v2) rows for every sealed column across ALL
/// tenants — the D4 retirement gates' input (a cross-tenant scan, no principal).
/// One `UNION ALL` over the thirteen sealed columns (the ten tenant-owned ones —
/// including both PKCE-verifier flow twins, `login_flows` and
/// `connector_oauth_flows` — Task 3's two deployment-global
/// `oauth_client_registrations` columns, and Task 5's
/// `tenant_llm_keys.litellm_key_sealed`); each family filters on its own
/// `<col> is not null` so NULL secrets never count. Returns counts only, never a
/// sealed byte. MUST stay in lockstep with `reseal::FAMILIES`, or a v1 row of an
/// uncounted family would escape both the re-seal job AND the retirement gate and
/// orphan when the legacy key retires.
pub async fn sealed_key_version_counts(pool: &PgPool) -> sqlx::Result<Vec<FamilyKeyVersionCounts>> {
    // BOOT-PATH CARVE-OUT (Phase D Task 6, plan resolution 2): the D4 retirement
    // gates call this BEFORE serving. It is a cross-tenant aggregate over every
    // sealed column; under RLS with no GUC it would count ZERO rows and fail OPEN
    // (retire the legacy key while v1 rows still exist). It rides the audited bypass
    // so the counts stay truthful. The remaining system_worker scans adopt worker_tx
    // in Task 7; this one is converted now because it gates boot.
    let mut tx = crate::worker_tx(pool).await?;
    let out = sqlx::query_as(
        "select 'integration_connections.credential_sealed' as family,
                count(*) filter (where credential_sealed is not null and credential_key_version = 1) as legacy,
                count(*) filter (where credential_sealed is not null and credential_key_version = 2) as envelope
           from integration_connections
         union all
         select 'integration_connections.webhook_secret_sealed',
                count(*) filter (where webhook_secret_sealed is not null and webhook_secret_key_version = 1),
                count(*) filter (where webhook_secret_sealed is not null and webhook_secret_key_version = 2)
           from integration_connections
         union all
         select 'integration_connections.client_secret_sealed',
                count(*) filter (where client_secret_sealed is not null and client_secret_key_version = 1),
                count(*) filter (where client_secret_sealed is not null and client_secret_key_version = 2)
           from integration_connections
         union all
         select 'trigger_subscriptions.callback_secret_sealed',
                count(*) filter (where callback_secret_sealed is not null and callback_secret_key_version = 1),
                count(*) filter (where callback_secret_sealed is not null and callback_secret_key_version = 2)
           from trigger_subscriptions
         union all
         select 'github_app_registrations.pem_sealed',
                count(*) filter (where pem_sealed is not null and pem_key_version = 1),
                count(*) filter (where pem_sealed is not null and pem_key_version = 2)
           from github_app_registrations
         union all
         select 'github_app_registrations.webhook_secret_sealed',
                count(*) filter (where webhook_secret_sealed is not null and webhook_secret_key_version = 1),
                count(*) filter (where webhook_secret_sealed is not null and webhook_secret_key_version = 2)
           from github_app_registrations
         union all
         select 'github_app_registrations.client_secret_sealed',
                count(*) filter (where client_secret_sealed is not null and client_secret_key_version = 1),
                count(*) filter (where client_secret_sealed is not null and client_secret_key_version = 2)
           from github_app_registrations
         union all
         select 'org_idp_configs.client_secret_sealed',
                count(*) filter (where client_secret_sealed is not null and client_secret_key_version = 1),
                count(*) filter (where client_secret_sealed is not null and client_secret_key_version = 2)
           from org_idp_configs
         union all
         select 'login_flows.pkce_verifier_sealed',
                count(*) filter (where pkce_verifier_sealed is not null and pkce_verifier_key_version = 1),
                count(*) filter (where pkce_verifier_sealed is not null and pkce_verifier_key_version = 2)
           from login_flows
         union all
         select 'connector_oauth_flows.pkce_verifier_sealed',
                count(*) filter (where pkce_verifier_sealed is not null and pkce_verifier_key_version = 1),
                count(*) filter (where pkce_verifier_sealed is not null and pkce_verifier_key_version = 2)
           from connector_oauth_flows
         union all
         select 'oauth_client_registrations.client_secret_sealed',
                count(*) filter (where client_secret_sealed is not null and client_secret_key_version = 1),
                count(*) filter (where client_secret_sealed is not null and client_secret_key_version = 2)
           from oauth_client_registrations
         union all
         select 'oauth_client_registrations.registration_access_token_sealed',
                count(*) filter (where registration_access_token_sealed is not null and registration_access_token_key_version = 1),
                count(*) filter (where registration_access_token_sealed is not null and registration_access_token_key_version = 2)
           from oauth_client_registrations
         union all
         select 'tenant_llm_keys.litellm_key_sealed',
                count(*) filter (where litellm_key_sealed is not null and litellm_key_key_version = 1),
                count(*) filter (where litellm_key_sealed is not null and litellm_key_key_version = 2)
           from tenant_llm_keys",
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(out)
}

// ─── Re-seal migration paging + per-row lock/CAS (Phase D, #32; category (c)) ──
//
// `table`/`column`/`version_column`/`key_column` in these three fns come
// EXCLUSIVELY from the server's compile-time `reseal::FAMILIES` const array (the
// thirteen sealed `table.column` pairs). They are never request data, so the
// `format!`-built SQL is injection-safe (the values — the paging cursor, the row
// key, the new sealed bytes — are all bound parameters). Keeping them dynamic (vs
// thirteen hand-written fns) lets one job loop walk every family; the server owns
// the crypto so the (table, column, SealFamily) mapping has exactly one home.
// `AssertSqlSafe` records the promise. `key_column` is the row's stable unique key
// the job pages/locks/CAS-writes by — `id` for every family EXCEPT
// `tenant_llm_keys`, which is keyed by its `tenant_id` primary key (no `id`
// column); it is a Uuid either way.

/// One page of keys for a sealed family still at v1, keyset-paged past `after`.
/// `WHERE <col> is not null and <col>_key_version = 1 and <key_column> > $after
/// ORDER BY <key_column>`. `key_column` is the family's row key (`id`, or
/// `tenant_id` for `tenant_llm_keys`); the returned Uuids feed `reseal_lock_row`.
///
/// The `_key_version = 1` predicate is what makes the whole job restart-safe and
/// idempotent: an already-re-sealed (v2) row is excluded, so a crash-and-restart
/// simply re-scans and skips finished rows — no cursor to persist. The
/// `<key_column> > $after` cursor is what guarantees FORWARD PROGRESS within a
/// pass: a row the job cannot re-seal (a corrupt blob / wrong legacy key) stays v1,
/// and without the cursor a pure `kv = 1` page would re-fetch it forever and wedge
/// the migration. Together: skip finished rows across restarts, never re-fetch a
/// bad row within a pass (a re-run re-attempts it from `after = nil`). Seed `after`
/// with the nil UUID (the minimum) and advance it to the last key of each page.
pub async fn reseal_candidate_ids(
    pool: &PgPool,
    table: &str,
    column: &str,
    version_column: &str,
    key_column: &str,
    after: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<Uuid>> {
    // Cross-tenant paging by construction — the re-seal job walks EVERY tenant's v1
    // rows for a family (category (c)); rides the audited system-worker bypass.
    let mut tx = crate::worker_tx(pool).await?;
    let rows: Vec<(Uuid,)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {key_column} from {table}
         where {column} is not null and {version_column} = 1 and {key_column} > $1
         order by {key_column} limit $2"
    )))
    .bind(after)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Open the per-row re-seal transaction with the audited system-worker bypass GUC
/// already set. The re-seal job locks + CAS-writes rows across EVERY tenant
/// (category (c)) and the server can't reach `worker_tx` (it is `pub(crate)`), so
/// this is the fluidbox-db entry point that keeps the audited bypass a single
/// grep-able choke point INSIDE this crate. The caller drives
/// [`reseal_lock_row`]/[`reseal_write_row`] on the returned tx (via `&mut *tx`) and
/// owns the commit/rollback — the lock and CAS semantics are unchanged; only the
/// GUC now rides the transaction so the `FOR UPDATE` and the CAS see the row under
/// FORCE RLS. Without it the lock read returns `None` (row "vanished") for every
/// row and the migration silently no-ops.
pub async fn reseal_begin(
    pool: &PgPool,
) -> sqlx::Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    crate::worker_tx(pool).await
}

/// Lock ONE candidate row and read its sealed bytes + companion version + tenant,
/// inside the caller's transaction (`SELECT … FOR UPDATE`; open it with
/// [`reseal_begin`] so the bypass GUC rides it). Returns the version so the caller
/// can re-check it is STILL 1 under the lock — the page read
/// [`reseal_candidate_ids`] was unlocked, so a concurrent writer may have
/// re-sealed the row since. `None` (outer) = the row vanished (deleted) between
/// paging and locking; `None` (inner, the bytes) = the column is now NULL. The
/// `tenant_id` is `Option<Uuid>` because a deployment-global family
/// (`oauth_client_registrations`, tenant_id NULL) re-seals under the DEPLOYMENT
/// tenant's DEK — the server resolves NULL → deployment tenant via
/// `Sealer::row_ctx` (plaintext never transits this crate).
///
/// The row lock plus the caller's CAS write ([`reseal_write_row`]) make a separate
/// oauth advisory lock unnecessary for the concurrent-rotation hot spot: a live
/// OAuth refresh rotation (which, with KMS on, itself writes a v2 blob) blocks on
/// this `FOR UPDATE` and, once the re-seal tx commits, overwrites with its own
/// fresh v2 seal — the re-sealed old token is superseded, never clobbering the
/// rotation and never restoring a stale refresh token.
pub async fn reseal_lock_row(
    tx: &mut sqlx::PgConnection,
    table: &str,
    column: &str,
    version_column: &str,
    key_column: &str,
    id: Uuid,
) -> sqlx::Result<Option<(Option<Vec<u8>>, i16, Option<Uuid>)>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {column}, {version_column}, tenant_id from {table}
         where {key_column} = $1 for update"
    )))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
}

/// CAS-write the re-sealed (v2) bytes for ONE row, flipping its companion version
/// 1 → 2 in the same `WHERE … and <col>_key_version = 1` predicate. Returns
/// rows-affected: 1 = re-sealed; 0 = a concurrent writer already moved it off v1
/// (the caller counts that as SKIPPED, never an error). Runs inside the caller's
/// transaction, holding the same row lock as [`reseal_lock_row`].
pub async fn reseal_write_row(
    tx: &mut sqlx::PgConnection,
    table: &str,
    column: &str,
    version_column: &str,
    key_column: &str,
    id: Uuid,
    new_sealed: &[u8],
) -> sqlx::Result<u64> {
    let res = sqlx::query(sqlx::AssertSqlSafe(format!(
        "update {table} set {column} = $2, {version_column} = 2
         where {key_column} = $1 and {version_column} = 1"
    )))
    .bind(id)
    .bind(new_sealed)
    .execute(&mut *tx)
    .await?;
    Ok(res.rows_affected())
}

// ─── (e) deployment-global OAuth client registrations ───────────────────────
// `oauth_client_registrations` v1 rows are ALWAYS global (`tenant_id NULL`): one
// deployment-wide client identity per (issuer, redirect_uri), shared by every
// tenant's dance. Migration 0018 lets any scope READ a global row but restricts
// INSERT/UPDATE/DELETE to tenant-or-bypass — a tenant-scoped transaction must not
// be able to mint a global row or mutate/retire one another tenant depends on. The
// DCR/CIMD resolution that legitimately writes them is principal-less by
// construction (it runs mid-dance, before any connection is active), so it takes
// the audited escape hatch here, exactly like every other cross-tenant writer.
//
// Reads are deliberately NOT wrapped: `find_client_registration`/`_by_id` are
// executor-generic and the SELECT policy already admits `tenant_id is null` from
// any scope.

/// Open the find-or-register transaction with the audited system-worker bypass GUC
/// already set — the drop-in for a bare `pool.begin()` in the DCR path, which takes
/// the registration advisory lock and then reads/inserts the GLOBAL row inside one
/// transaction. Without the GUC the insert is refused ("new row violates
/// row-level security policy") under 0018's `registration_insert` policy.
pub async fn global_registration_tx(
    pool: &PgPool,
) -> sqlx::Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    crate::worker_tx(pool).await
}

/// Insert the shared GLOBAL registration under the audited bypass — the pool-direct
/// counterpart of [`global_registration_tx`], for the CIMD arm (no advisory lock:
/// CIMD has no `/register` HTTP to serialize). Same `ON CONFLICT DO NOTHING`
/// semantics as [`crate::insert_client_registration`]: `None` means a concurrent
/// dance won and the caller re-selects.
pub async fn insert_global_registration(
    pool: &PgPool,
    new: crate::NewOauthClientRegistration<'_>,
) -> sqlx::Result<Option<crate::OauthClientRegistrationRow>> {
    let mut tx = crate::worker_tx(pool).await?;
    let out = crate::insert_client_registration(&mut *tx, new).await?;
    tx.commit().await?;
    Ok(out)
}

/// Bump `last_used_at` on a GLOBAL registration under the audited bypass. An UPDATE
/// filtered by RLS would silently affect zero rows, so this is a correctness fix as
/// well as an access one.
pub async fn touch_global_registration(pool: &PgPool, id: Uuid) -> sqlx::Result<()> {
    let mut tx = crate::worker_tx(pool).await?;
    crate::touch_client_registration(&mut *tx, id).await?;
    tx.commit().await
}

/// Delete a GLOBAL registration whose client the AS rejected (`invalid_client`
/// self-heal) under the audited bypass, so the next dance mints a fresh identity.
/// Without the GUC the DELETE is filtered to zero rows and the dead identity is
/// adopted forever.
pub async fn delete_global_registration(pool: &PgPool, id: Uuid) -> sqlx::Result<()> {
    let mut tx = crate::worker_tx(pool).await?;
    crate::delete_client_registration(&mut *tx, id).await?;
    tx.commit().await
}
