//! Durable upstream-MCP-session bookkeeping for CROSS-REPLICA teardown
//! (Phase F, Task 3; migration 0024).
//!
//! `fluidbox-server`'s per-run MCP session manager keeps `(run session, peer) →
//! upstream session` in an in-memory map on `AppState`, and Phase E said so
//! plainly: replica-local by design, cross-replica affinity deferred to Phase F.
//! The disclosed consequence was a leak — a run whose brokered calls landed on
//! replica A but which is FINALIZED on replica B produces no `DELETE` at all,
//! because B drains an empty map. This module is the durable half that lets ANY
//! replica tear down EVERY replica's upstream sessions for a run.
//!
//! # For teardown, never for adoption
//!
//! A replica NEVER adopts another replica's upstream session. Adoption would put
//! two replicas on one upstream session with no serialization and force a
//! JSON-RPC id-space change (the id counter is a per-entry in-process `u64`) —
//! all to save an `initialize` that MCP allows us to repeat. So rows are keyed by
//! OWNING REPLICA, every replica keeps initializing its own session exactly as
//! before, and the only cross-replica operation these rows enable is the terminal
//! `DELETE`.
//!
//! # No credential ever lands here
//!
//! A row carries routing state only: endpoint, upstream session id, negotiated
//! protocol version. The teardown `DELETE` carries the same authorization header a
//! live call would, and the server RE-RESOLVES it live at teardown (invariants 9
//! and 22). A revoked connection is exactly the case where no credential may be
//! sent, so the server skips that `DELETE` and leaves the row for
//! [`sweep_orphaned_upstream_sessions`] to retire.
//!
//! # Tenancy
//!
//! Every per-run function rides [`crate::scoped_tx`], so 0024's RLS policy is the
//! enforcing floor and the explicit `tenant_id = $n` predicate is defence in
//! depth. [`sweep_orphaned_upstream_sessions`] is the ONE exception and is a
//! genuine deployment-wide GC: it rides the audited [`crate::worker_tx`] bypass
//! and is enumerated in the `system_worker` module's bypass inventory.

use crate::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// `mcp_upstream_sessions.peer_kind` for the Phase C run-resource-binding path.
pub const PEER_BINDING: &str = "binding";
/// `mcp_upstream_sessions.peer_kind` for the legacy embedded-connection path.
pub const PEER_CONNECTION: &str = "connection";

/// `delete_outcome` after the server actually attempted the upstream `DELETE`.
/// Best-effort: the upstream's reply is not required and is not recorded.
pub const OUTCOME_DELETED: &str = "deleted";
/// `delete_outcome` after the deployment-wide GC retired a row WITHOUT attempting
/// the upstream `DELETE` (see [`sweep_orphaned_upstream_sessions`]).
pub const OUTCOME_SWEPT: &str = "swept";

/// The session statuses the sweeper treats as "this run is over". Bound into the
/// sweep predicate from ONE place and asserted against
/// [`fluidbox_core::state::SessionStatus::is_terminal`] by a unit test, so a new
/// terminal status cannot silently make the sweep blind to it.
///
/// Wind-down statuses (`cancelling`, `finalizing`) are deliberately EXCLUDED: the
/// run is still being driven, the terminal-teardown path has not run yet, and
/// retiring a row there would race the very code that is about to use it.
pub const TERMINAL_STATUSES: [&str; 4] = ["completed", "failed", "cancelled", "budget_exceeded"];

/// One `mcp_upstream_sessions` row (migration 0024).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UpstreamSessionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// The FLUIDBOX run session, not the upstream one.
    pub session_id: Uuid,
    pub peer_kind: String,
    pub peer_id: Uuid,
    pub replica: Uuid,
    /// The `Mcp-Session-Id` the upstream issued.
    pub upstream_session_id: String,
    pub endpoint_url: String,
    pub protocol_version: Option<String>,
    pub opened_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub delete_outcome: Option<String>,
}

/// What the server knows when an `initialize` hands back a session id.
#[derive(Debug, Clone)]
pub struct NewUpstreamSession<'a> {
    pub session_id: Uuid,
    pub peer_kind: &'a str,
    pub peer_id: Uuid,
    pub replica: Uuid,
    pub upstream_session_id: &'a str,
    pub endpoint_url: &'a str,
    pub protocol_version: Option<&'a str>,
}

/// One row the sweeper retired, carried back so the caller can log/ledger it.
#[derive(Debug, Clone, sqlx::FromRow, PartialEq, Eq)]
pub struct SweptUpstreamSession {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub endpoint_url: String,
}

/// Record (or refresh) the durable teardown row for one `(run session, peer,
/// this replica)`.
///
/// Called the moment an `initialize` yields a session id — NOT after the tool
/// call — so the window in which a crash can lose the row is a database round
/// trip rather than a whole upstream request. A sessionless upstream server
/// (no `Mcp-Session-Id`) is never passed here: there is nothing to `DELETE`, and
/// a row for it would be a sweep candidate that can never be satisfied.
///
/// The upsert is a RE-INITIALIZE, and that is why it resurrects a deleted row:
/// the 404-with-session path proves the previous upstream session is dead, so
/// overwriting its id leaks nothing, and clearing `deleted_at` is what stops a
/// re-initialized session from being considered already torn down.
pub async fn record_upstream_session(
    pool: &PgPool,
    scope: TenantScope,
    s: NewUpstreamSession<'_>,
) -> sqlx::Result<Uuid> {
    let mut tx = scoped_tx(pool, scope).await?;
    let (id,): (Uuid,) = sqlx::query_as(
        "insert into mcp_upstream_sessions
             (tenant_id, session_id, peer_kind, peer_id, replica,
              upstream_session_id, endpoint_url, protocol_version)
         values ($1, $2, $3, $4, $5, $6, $7, $8)
         on conflict (session_id, peer_kind, peer_id, replica) do update
             set upstream_session_id = excluded.upstream_session_id,
                 endpoint_url        = excluded.endpoint_url,
                 protocol_version    = excluded.protocol_version,
                 opened_at           = now(),
                 deleted_at          = null,
                 delete_outcome      = null
         returning id",
    )
    .bind(scope.tenant_id())
    .bind(s.session_id)
    .bind(s.peer_kind)
    .bind(s.peer_id)
    .bind(s.replica)
    .bind(s.upstream_session_id)
    .bind(s.endpoint_url)
    .bind(s.protocol_version)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Every still-undeleted upstream session one run opened, ON ANY REPLICA.
///
/// THE teardown query. Tenant-scoped (RLS floor + explicit predicate), ordered so
/// teardown is deterministic and a test can assert on position. The caller unions
/// this with its own in-memory registry entries and `DELETE`s the union.
pub async fn live_upstream_sessions(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
) -> sqlx::Result<Vec<UpstreamSessionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let rows: Vec<UpstreamSessionRow> = sqlx::query_as(
        "select * from mcp_upstream_sessions
          where session_id = $1 and tenant_id = $2 and deleted_at is null
          order by opened_at, id",
    )
    .bind(session_id)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows)
}

/// Stamp one row as torn down. `true` iff THIS call landed the transition (the
/// `deleted_at is null` predicate makes it a CAS, so a concurrent teardown on
/// another replica cannot double-stamp or overwrite an outcome).
///
/// Only ever called AFTER the upstream `DELETE` was actually attempted — never
/// optimistically. That is what makes `deleted_at is null` a truthful "still
/// leaked upstream" predicate rather than a hopeful one.
pub async fn mark_upstream_session_deleted(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    outcome: &str,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update mcp_upstream_sessions
            set deleted_at = now(), delete_outcome = $3
          where id = $1 and tenant_id = $2 and deleted_at is null",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .bind(outcome)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() == 1)
}

/// The deployment-wide GC: retire live rows whose run reached a TERMINAL status
/// at least a grace period ago.
///
/// # It RETIRES the row; it does NOT attempt the upstream `DELETE`. Why.
///
/// The run-terminal path already attempts every `DELETE` it is *allowed* to send,
/// and since Task 3 it sees EVERY replica's rows — so the crashed-replica case is
/// closed there, by the replica that finalizes the run, not here. What actually
/// reaches this sweeper is the residue:
///
///   1. rows whose credential could not be re-resolved (revoked connection, moved
///      `authorization_generation`, deactivated owner). Invariant 9 says we must
///      NOT send a credential in exactly those cases, so a retry from here could
///      never succeed — it would only re-resolve credentials on a timer;
///   2. rows written by a call that raced in behind the terminal drain;
///   3. rows whose run's terminal reconciler never completed a pass.
///
/// Dialing (1) forever is pointless, and dialing (2)/(3) from a background global
/// scan would need its own attempt counter, backoff and give-up state — a second
/// delivery system — or a wedged upstream gets dialed every tick by every replica.
/// It would also hand a hostile upstream a way to hold `MCP_DELETE_TIMEOUT` ×
/// batch connections open against a worker that runs under the cross-tenant
/// bypass.
///
/// THE TRADE, stated plainly: an upstream session we retire without a `DELETE`
/// stays allocated on the upstream server until IT expires the session on its own
/// schedule. That costs the upstream a session slot, never correctness here — and
/// it is strictly better than Phase E, where the same session leaked until the
/// owning replica's process exited.
///
/// Bounded batch + `for update skip locked`, the [`crate::system_worker`] sweep
/// shape, so N replicas ticking together take disjoint sets and one pass can never
/// outrun its own period.
pub async fn sweep_orphaned_upstream_sessions(
    pool: &PgPool,
    terminal_before: DateTime<Utc>,
    limit: i64,
) -> sqlx::Result<Vec<SweptUpstreamSession>> {
    let mut tx = crate::worker_tx(pool).await?;
    let rows: Vec<SweptUpstreamSession> = sqlx::query_as(
        "with orphaned as (
             select m.id from mcp_upstream_sessions m
              where m.deleted_at is null
                and exists (
                    select 1 from sessions s
                     where s.id = m.session_id
                       and s.status = any($1)
                       and coalesce(s.finished_at, s.updated_at) < $2
                )
              order by m.opened_at
              limit $3
              for update skip locked
         )
         update mcp_upstream_sessions m
            set deleted_at = now(), delete_outcome = $4
           from orphaned o
          where m.id = o.id and m.deleted_at is null
        returning m.id, m.tenant_id, m.session_id, m.endpoint_url",
    )
    .bind(TERMINAL_STATUSES.as_slice())
    .bind(terminal_before)
    .bind(limit)
    .bind(OUTCOME_SWEPT)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::state::SessionStatus;

    /// Every `SessionStatus` variant. The wildcard-free `match` is the point: a new
    /// variant fails to COMPILE here, which is what forces whoever adds it to decide
    /// whether the sweeper should see it.
    fn all_statuses() -> Vec<SessionStatus> {
        use SessionStatus::*;
        let all = vec![
            Created,
            Provisioning,
            Initializing,
            Running,
            AwaitingApproval,
            Cancelling,
            Finalizing,
            Completed,
            Failed,
            Cancelled,
            BudgetExceeded,
        ];
        for s in &all {
            match s {
                Created | Provisioning | Initializing | Running | AwaitingApproval | Cancelling
                | Finalizing | Completed | Failed | Cancelled | BudgetExceeded => {}
            }
        }
        all
    }

    // ─── Pure: sweeper eligibility ──────────────────────────────────────────

    #[test]
    fn the_sweep_status_list_is_exactly_cores_terminal_set() {
        // The sweeper's eligibility rule is "the run is over". `TERMINAL_STATUSES`
        // is that rule expressed as SQL bind values; `SessionStatus::is_terminal`
        // is the same rule expressed in the domain. If they drift, the sweeper
        // either never collects a real terminal state (leak forever) or collects a
        // LIVE run's session out from under it.
        for s in all_statuses() {
            assert_eq!(
                TERMINAL_STATUSES.contains(&s.as_str()),
                s.is_terminal(),
                "sweep eligibility for '{}' disagrees with SessionStatus::is_terminal",
                s.as_str()
            );
        }
    }

    #[test]
    fn wind_down_statuses_are_not_sweep_eligible() {
        // Stated separately because it is the dangerous direction: `cancelling` and
        // `finalizing` are the states in which the terminal teardown path is ABOUT
        // to read these rows. Sweeping them would retire a row the run-terminal
        // DELETE was seconds away from using.
        for s in [SessionStatus::Cancelling, SessionStatus::Finalizing] {
            assert!(s.is_winding_down());
            assert!(
                !TERMINAL_STATUSES.contains(&s.as_str()),
                "'{}' is still being driven — the sweeper must not retire its rows",
                s.as_str()
            );
        }
    }

    #[test]
    fn peer_kinds_and_outcomes_match_the_migration_vocabulary() {
        // 0024 CHECK-constrains peer_kind, so a typo here is a runtime insert
        // failure on a path that is best-effort and therefore only logged.
        assert_eq!((PEER_BINDING, PEER_CONNECTION), ("binding", "connection"));
        assert_eq!((OUTCOME_DELETED, OUTCOME_SWEPT), ("deleted", "swept"));
    }

    // ─── DB-backed (self-skipping) ──────────────────────────────────────────
    //
    // Every fixture uses its OWN throwaway tenant and asserts only on its own run
    // session. The sweep is a tenant-LESS global scan in a SHARED database, so the
    // #33 collision class applies: concurrent tests must never assert on the batch,
    // only on their own row's post-state.

    use crate::identity::create_org;
    use crate::test_connect;

    async fn throwaway_tenant(pool: &PgPool) -> TenantScope {
        let slug = format!("mcpsess-{}", Uuid::now_v7().simple());
        TenantScope::assume(create_org(pool, &slug, None).await.unwrap().id)
    }

    /// A `created` session in `scope`'s tenant (the standard agent/revision/policy
    /// fixture chain — `create_session` verifies both belong to the tenant in SQL).
    async fn seed_session(pool: &PgPool, scope: TenantScope) -> Uuid {
        let policy = crate::upsert_policy(
            pool,
            scope,
            "mcpsess",
            "name: mcpsess",
            &serde_json::json!({"name":"mcpsess"}),
        )
        .await
        .unwrap();
        let agent = crate::create_agent(pool, scope, "mcpsess-agent", None)
            .await
            .unwrap();
        let rev = crate::append_agent_revision(
            pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let repo = serde_json::json!({"kind":"none"});
        let empty = serde_json::json!({});
        crate::create_session(
            pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "mcpsess task",
            &repo,
            &empty,
            &empty,
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap()
        .id
    }

    fn new_session<'a>(
        run: Uuid,
        peer_id: Uuid,
        replica: Uuid,
        upstream: &'a str,
        url: &'a str,
    ) -> NewUpstreamSession<'a> {
        NewUpstreamSession {
            session_id: run,
            peer_kind: PEER_BINDING,
            peer_id,
            replica,
            upstream_session_id: upstream,
            endpoint_url: url,
            protocol_version: Some("2025-11-25"),
        }
    }

    /// Put a session in `status` and backdate its clocks by `secs_ago`.
    /// `finished_at` is stamped ONLY for a terminal status, exactly as the
    /// orchestrator's transition does — which is what makes an OLD non-terminal
    /// session (a long-running run) a real, distinguishable fixture.
    async fn age_session(
        pool: &PgPool,
        scope: TenantScope,
        run: Uuid,
        status: &str,
        secs_ago: i64,
    ) {
        let mut tx = scoped_tx(pool, scope).await.unwrap();
        sqlx::query(
            "update sessions
                set status = $4,
                    finished_at = case when $4 in ('completed','failed','cancelled','budget_exceeded')
                                       then now() - make_interval(secs => $3::double precision)
                                       else null end,
                    updated_at  = now() - make_interval(secs => $3::double precision)
              where id = $1 and tenant_id = $2",
        )
        .bind(run)
        .bind(scope.tenant_id())
        .bind(secs_ago as f64)
        .bind(status)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    async fn make_terminal(pool: &PgPool, scope: TenantScope, run: Uuid, finished_secs_ago: i64) {
        age_session(pool, scope, run, "completed", finished_secs_ago).await;
    }

    async fn row_by_upstream(
        pool: &PgPool,
        scope: TenantScope,
        run: Uuid,
        upstream: &str,
    ) -> UpstreamSessionRow {
        let mut tx = scoped_tx(pool, scope).await.unwrap();
        let row: UpstreamSessionRow = sqlx::query_as(
            "select * from mcp_upstream_sessions
              where session_id = $1 and tenant_id = $2 and upstream_session_id = $3",
        )
        .bind(run)
        .bind(scope.tenant_id())
        .bind(upstream)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        row
    }

    async fn cleanup(pool: &PgPool, scope: TenantScope) {
        let mut tx = crate::worker_tx(pool).await.unwrap();
        for stmt in [
            "delete from mcp_upstream_sessions where tenant_id = $1",
            "delete from sessions where tenant_id = $1",
            "delete from agents where tenant_id = $1",
            "delete from policies where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(stmt)
                .bind(scope.tenant_id())
                .execute(&mut *tx)
                .await
                .ok();
        }
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn two_replicas_rows_are_both_visible_to_a_third() {
        // THE point of the whole task: replica C, which made no calls at all, must
        // see BOTH A's and B's upstream sessions for the run.
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let run = seed_session(&pool, scope).await;
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let peer = Uuid::now_v7();
        record_upstream_session(
            &pool,
            scope,
            new_session(run, peer, a, "up-a", "http://a/mcp"),
        )
        .await
        .unwrap();
        record_upstream_session(
            &pool,
            scope,
            new_session(run, peer, b, "up-b", "http://b/mcp"),
        )
        .await
        .unwrap();

        let live = live_upstream_sessions(&pool, scope, run).await.unwrap();
        let mut ups: Vec<&str> = live
            .iter()
            .map(|r| r.upstream_session_id.as_str())
            .collect();
        ups.sort_unstable();
        assert_eq!(
            ups,
            vec!["up-a", "up-b"],
            "the same (run, peer) on two replicas is TWO upstream sessions, both owed a DELETE"
        );
        assert!(
            live.iter()
                .all(|r| r.protocol_version.as_deref() == Some("2025-11-25")),
            "the negotiated version rides the row (it is echoed on the DELETE)"
        );
        cleanup(&pool, scope).await;
    }

    #[tokio::test]
    async fn reinitialize_updates_the_row_in_place_and_revives_it() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let run = seed_session(&pool, scope).await;
        let (replica, peer) = (Uuid::now_v7(), Uuid::now_v7());
        let first = record_upstream_session(
            &pool,
            scope,
            new_session(run, peer, replica, "up-1", "http://a/mcp"),
        )
        .await
        .unwrap();
        // Tear it down, then re-initialize into the SAME slot (the 404-with-session
        // path): one row, new upstream id, live again.
        assert!(
            mark_upstream_session_deleted(&pool, scope, first, OUTCOME_DELETED)
                .await
                .unwrap()
        );
        assert!(live_upstream_sessions(&pool, scope, run)
            .await
            .unwrap()
            .is_empty());
        let second = record_upstream_session(
            &pool,
            scope,
            new_session(run, peer, replica, "up-2", "http://a/mcp"),
        )
        .await
        .unwrap();
        assert_eq!(
            first, second,
            "a re-initialize must reuse the slot, not grow the table"
        );
        let live = live_upstream_sessions(&pool, scope, run).await.unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].upstream_session_id, "up-2");
        assert!(
            live[0].deleted_at.is_none() && live[0].delete_outcome.is_none(),
            "a re-initialized session is NOT torn down — the revive must clear both columns"
        );
        cleanup(&pool, scope).await;
    }

    #[tokio::test]
    async fn marking_deleted_is_a_cas_and_removes_the_row_from_teardown() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let run = seed_session(&pool, scope).await;
        let id = record_upstream_session(
            &pool,
            scope,
            new_session(run, Uuid::now_v7(), Uuid::now_v7(), "up", "http://a/mcp"),
        )
        .await
        .unwrap();
        assert!(
            mark_upstream_session_deleted(&pool, scope, id, OUTCOME_DELETED)
                .await
                .unwrap(),
            "the first teardown lands the transition"
        );
        assert!(
            !mark_upstream_session_deleted(&pool, scope, id, OUTCOME_SWEPT)
                .await
                .unwrap(),
            "a second teardown (another replica, or the sweeper) must LOSE the CAS"
        );
        let row = row_by_upstream(&pool, scope, run, "up").await;
        assert_eq!(
            row.delete_outcome.as_deref(),
            Some(OUTCOME_DELETED),
            "the loser must not overwrite the winner's outcome"
        );
        assert!(live_upstream_sessions(&pool, scope, run)
            .await
            .unwrap()
            .is_empty());
        cleanup(&pool, scope).await;
    }

    #[tokio::test]
    async fn teardown_reads_are_tenant_scoped() {
        // The teardown query is keyed on a run session id that a worker resolved
        // cross-tenant. If the scope were decorative, a wrong-tenant scope would
        // still hand back another tenant's endpoints + upstream session ids.
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let victim = throwaway_tenant(&pool).await;
        let attacker = throwaway_tenant(&pool).await;
        let run = seed_session(&pool, victim).await;
        let id = record_upstream_session(
            &pool,
            victim,
            new_session(
                run,
                Uuid::now_v7(),
                Uuid::now_v7(),
                "secret-up",
                "http://victim/mcp",
            ),
        )
        .await
        .unwrap();

        assert!(
            live_upstream_sessions(&pool, attacker, run)
                .await
                .unwrap()
                .is_empty(),
            "another tenant's scope must not read this run's upstream sessions"
        );
        assert!(
            !mark_upstream_session_deleted(&pool, attacker, id, OUTCOME_DELETED)
                .await
                .unwrap(),
            "another tenant's scope must not be able to mark this row torn down"
        );
        assert_eq!(
            live_upstream_sessions(&pool, victim, run)
                .await
                .unwrap()
                .len(),
            1,
            "…and the owner still sees it (the cross-tenant call changed nothing)"
        );
        cleanup(&pool, victim).await;
        cleanup(&pool, attacker).await;
    }

    #[tokio::test]
    async fn migration_0024s_rls_triple_actually_binds_the_runtime_role() {
        // The fixture pool above carries the audited bypass GUC on every connection
        // and CI's base user is a superuser, so NOTHING in the other tests here
        // exercises 0024's RLS triple. This one opens its own NON-superuser
        // `SET ROLE fluidbox_runtime` connection — where the policy actually runs —
        // and proves all three parts: ENABLE+FORCE (the row is filtered), the
        // child-EXISTS policy (it is filtered by its PARENT session's tenant), and
        // the enumerated DML grant (the runtime role can still write it — without
        // the `do $$` block production would get "permission denied").
        use sqlx::{Connection, Executor};
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let victim = throwaway_tenant(&pool).await;
        let other = throwaway_tenant(&pool).await;
        let run = seed_session(&pool, victim).await;
        record_upstream_session(
            &pool,
            victim,
            new_session(
                run,
                Uuid::now_v7(),
                Uuid::now_v7(),
                "rls-up",
                "http://victim/mcp",
            ),
        )
        .await
        .unwrap();

        let mut rt = sqlx::PgConnection::connect(&url).await.expect("rt connect");
        rt.execute("set role fluidbox_runtime")
            .await
            .expect("set role");

        async fn count_as(rt: &mut sqlx::PgConnection, tenant: Uuid, run: Uuid) -> i64 {
            let mut tx = rt.begin().await.unwrap();
            sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
                .bind(tenant.to_string())
                .execute(&mut *tx)
                .await
                .unwrap();
            // Scoped to THIS fixture's run: a bare count would race every other
            // test in the shared CI database (#33 global-scan collision class).
            let (n,): (i64,) =
                sqlx::query_as("select count(*) from mcp_upstream_sessions where session_id = $1")
                    .bind(run)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            tx.rollback().await.ok();
            n
        }
        assert_eq!(
            count_as(&mut rt, victim.tenant_id(), run).await,
            1,
            "the owning tenant's GUC must see its own teardown row"
        );
        assert_eq!(
            count_as(&mut rt, other.tenant_id(), run).await,
            0,
            "RLS (not just the tenant_id predicate) must hide another tenant's teardown row"
        );

        // The enumerated DML grant: the runtime role writes the table in production.
        {
            let mut tx = rt.begin().await.unwrap();
            sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
                .bind(victim.tenant_id().to_string())
                .execute(&mut *tx)
                .await
                .unwrap();
            sqlx::query(
                "insert into mcp_upstream_sessions
                     (tenant_id, session_id, peer_kind, peer_id, replica,
                      upstream_session_id, endpoint_url)
                 values ($1, $2, 'connection', $3, $4, 'grant-probe', 'http://a/mcp')",
            )
            .bind(victim.tenant_id())
            .bind(run)
            .bind(Uuid::now_v7())
            .bind(Uuid::now_v7())
            .execute(&mut *tx)
            .await
            .expect("the runtime role must hold INSERT (0024's enumerated grant)");
            sqlx::query(
                "update mcp_upstream_sessions set deleted_at = now()
                  where session_id = $1 and upstream_session_id = 'grant-probe'",
            )
            .bind(run)
            .execute(&mut *tx)
            .await
            .expect("the runtime role must hold UPDATE (teardown stamps the row)");
            tx.rollback().await.ok();
        }
        rt.close().await.ok();
        cleanup(&pool, victim).await;
        cleanup(&pool, other).await;
    }

    #[tokio::test]
    async fn the_sweeper_retires_only_terminal_runs_past_the_grace_period() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        // The status predicate and the grace predicate must each be proved by a
        // fixture the OTHER one cannot save:
        //   long_run   — `running` for an HOUR. Old enough to clear the grace
        //                window, so ONLY the status predicate protects it. (A
        //                just-created session would survive on its `updated_at`
        //                alone and prove nothing — that exact hole let a mutation
        //                deleting `s.status = any($1)` pass an earlier revision of
        //                this test.)
        //   winddown   — `finalizing` for an hour: the state in which the terminal
        //                teardown is ABOUT to read these rows. The sharpest case.
        //   fresh_run  — terminal but inside the grace window: only the grace
        //                predicate protects it.
        //   stale_run  — terminal and past it: the only sweep candidate.
        let long_run = seed_session(&pool, scope).await;
        let winddown_run = seed_session(&pool, scope).await;
        let fresh_run = seed_session(&pool, scope).await;
        let stale_run = seed_session(&pool, scope).await;
        for (run, up) in [
            (long_run, "up-long"),
            (winddown_run, "up-winddown"),
            (fresh_run, "up-fresh"),
            (stale_run, "up-stale"),
        ] {
            record_upstream_session(
                &pool,
                scope,
                new_session(run, Uuid::now_v7(), Uuid::now_v7(), up, "http://a/mcp"),
            )
            .await
            .unwrap();
        }
        age_session(&pool, scope, long_run, "running", 3600).await;
        age_session(&pool, scope, winddown_run, "finalizing", 3600).await;
        make_terminal(&pool, scope, fresh_run, 0).await;
        make_terminal(&pool, scope, stale_run, 3600).await;

        // A tenant-LESS global scan in a shared DB: assert on OUR OWN rows only,
        // never on the returned batch (a concurrent test's rows ride in it).
        let cutoff = Utc::now() - chrono::Duration::seconds(900);
        sweep_orphaned_upstream_sessions(&pool, cutoff, 200)
            .await
            .unwrap();

        assert_eq!(
            live_upstream_sessions(&pool, scope, long_run)
                .await
                .unwrap()
                .len(),
            1,
            "a RUNNING session's upstream sessions must never be retired, however old the run is"
        );
        assert_eq!(
            live_upstream_sessions(&pool, scope, winddown_run)
                .await
                .unwrap()
                .len(),
            1,
            "a WINDING-DOWN session is still being driven — its teardown has not run yet"
        );
        assert_eq!(
            live_upstream_sessions(&pool, scope, fresh_run)
                .await
                .unwrap()
                .len(),
            1,
            "inside the grace period the terminal path still owns the teardown"
        );
        assert!(
            live_upstream_sessions(&pool, scope, stale_run)
                .await
                .unwrap()
                .is_empty(),
            "a terminal run past the grace period must be retired"
        );
        assert_eq!(
            row_by_upstream(&pool, scope, stale_run, "up-stale")
                .await
                .delete_outcome
                .as_deref(),
            Some(OUTCOME_SWEPT),
            "a swept row is labelled as such — it did NOT get an upstream DELETE"
        );
        cleanup(&pool, scope).await;
    }

    #[tokio::test]
    async fn the_sweeper_is_bounded_and_never_re_retires() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let run = seed_session(&pool, scope).await;
        for i in 0..3 {
            record_upstream_session(
                &pool,
                scope,
                new_session(
                    run,
                    Uuid::now_v7(),
                    Uuid::now_v7(),
                    &format!("up-{i}"),
                    "http://a/mcp",
                ),
            )
            .await
            .unwrap();
        }
        make_terminal(&pool, scope, run, 3600).await;
        let cutoff = Utc::now() - chrono::Duration::seconds(900);

        // limit=1 ⇒ at most one row per pass, so a backlog drains over ticks
        // instead of one pass outrunning its own period.
        sweep_orphaned_upstream_sessions(&pool, cutoff, 1)
            .await
            .unwrap();
        assert_eq!(
            live_upstream_sessions(&pool, scope, run)
                .await
                .unwrap()
                .len(),
            2,
            "the batch limit must bound one pass"
        );
        // Drain, then prove an already-retired row is not picked up again (the
        // `deleted_at is null` predicate is what keeps the scan's working set the
        // LIVE set rather than all history).
        for _ in 0..4 {
            sweep_orphaned_upstream_sessions(&pool, cutoff, 200)
                .await
                .unwrap();
        }
        assert!(live_upstream_sessions(&pool, scope, run)
            .await
            .unwrap()
            .is_empty());
        let again = sweep_orphaned_upstream_sessions(&pool, cutoff, 200)
            .await
            .unwrap();
        assert!(
            !again.iter().any(|r| r.session_id == run),
            "a retired row must never be swept twice"
        );
        cleanup(&pool, scope).await;
    }
}
