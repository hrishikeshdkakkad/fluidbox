//! fluidbox-db — sqlx repositories over Neon Postgres.
//!
//! Connection rule: the DIRECT (non-pooler) connection string. NOTIFY is
//! only a wakeup; the seq catch-up query is the delivery source of truth.

use chrono::{DateTime, Utc};
use fluidbox_core::event::{EventEnvelope, Redacted};
use fluidbox_core::state::SessionStatus;
use serde_json::Value;
use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub mod governance;
pub mod identity;
pub mod mcp_sessions;
pub mod seed;
pub mod system_worker;

/// A verified tenant context. Constructible ONLY via [`TenantScope::assume`],
/// which a caller may invoke only when it holds — or has just resolved — a
/// verified tenant identity: an authenticated principal's own tenant, or a
/// `tenant_id` read back from a DB row. The non-principal constructions are a
/// closed, documented set (design doc
/// `docs/plans/2026-07-17-idp-agnostic-identity-design.md`): (a) verified-
/// credential resolution — the two credential-like exceptions, keyed purely on
/// a secret digest (session/PAT token sha256; the pending-switch confirmation-
/// cookie hash); (b) DB-resolved worker rows (the `system_worker` cross-tenant
/// scans, each row carrying its own `tenant_id`); (c) design-mandated pre-auth
/// surfaces that expose no tenant-owned resource — slug → org routing for
/// login-flow creation only, and the operator org-CRUD endpoints; (d) the boot
/// seed. Every identity repository takes it right after the executor and
/// carries its id into a `tenant_id = $n` predicate, so tenant isolation is a
/// signature requirement, not a remember-to-filter convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantScope(Uuid);

impl TenantScope {
    /// Assert a verified tenant context. See the type docs for the documented
    /// set of constructions permitted to do so — do NOT call this with a
    /// tenant id the browser supplied.
    pub fn assume(tenant_id: Uuid) -> Self {
        Self(tenant_id)
    }

    pub fn tenant_id(&self) -> Uuid {
        self.0
    }
}

/// Who owns a connection (design :274-296). `Organization` connections are
/// visible to every member; `User` connections are one member's personal
/// custody. github_app connections are ALWAYS `Organization`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOwner {
    Organization,
    User(Uuid),
}

impl ConnectionOwner {
    /// (owner_type, owner_user_id) as stamped into the row.
    fn parts(&self) -> (&'static str, Option<Uuid>) {
        match self {
            ConnectionOwner::Organization => ("organization", None),
            ConnectionOwner::User(id) => ("user", Some(*id)),
        }
    }
}

/// The visibility lens for a connection listing (design :274-296): `All` sees
/// every connection in the tenant (operator / admin); `User` sees org-owned
/// connections plus only its OWN personal connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionViewer {
    All,
    User(Uuid),
}

impl ConnectionViewer {
    /// The user id whose personal rows are visible, or None for `All` — bound
    /// into the `$n is null or owner_type='organization' or owner_user_id=$n`
    /// predicate.
    fn user_id(&self) -> Option<Uuid> {
        match self {
            ConnectionViewer::All => None,
            ConnectionViewer::User(id) => Some(*id),
        }
    }
}

/// Neon suspends an idle compute after five minutes of inactivity and drops every
/// connection with it. `PoolSettings::idle_timeout_secs` is deliberately kept BELOW
/// this so the POOL retires an idle connection before the SERVER does: sqlx's
/// `test_before_acquire` would otherwise discover the corpse one round trip into
/// the next acquire, on the request that was unlucky enough to arrive first after a
/// quiet period. A test derives its assertion from this constant rather than
/// hardcoding four minutes, so raising the idle timeout past the autosuspend window
/// fails there instead of silently reintroducing the stall.
pub const NEON_AUTOSUSPEND_SECS: u64 = 5 * 60;

/// Application connection-pool sizing (Phase F). Every field here used to be either
/// a hardcoded literal at the one construction site or an sqlx default nobody had
/// chosen; they are a struct so the server can drive them from `FLUIDBOX_DB_*` and
/// so each one carries the reason it is what it is.
///
/// The pool is LAZY — `max_connections` is a ceiling, not an allocation, and with
/// `min_connections = 0` a quiet deployment holds no pooled connections at all — so
/// the cost of the ceiling is paid only by load that actually arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSettings {
    /// Hard ceiling on pooled connections for THIS replica. The deployment-wide
    /// figure is `replicas × (max_connections + 2)`; the `+ 2` is the pair of
    /// `PgListener` connections (`spawn_listener`, `spawn_approval_listener`),
    /// which live OUTSIDE the pool and are permanently open.
    pub max_connections: u32,
    /// Idle connections the pool keeps warm. 0 = "open on demand".
    pub min_connections: u32,
    /// How long a caller waits for a free connection before the request fails.
    /// This is the deployment's real back-pressure valve: with no concurrency
    /// layer in front of the listeners (see `main.rs`), a saturated pool sheds by
    /// timing out here rather than by queueing without bound.
    pub acquire_timeout_secs: u64,
    /// Retire a connection that has been idle this long. Kept under
    /// [`NEON_AUTOSUSPEND_SECS`].
    pub idle_timeout_secs: u64,
    /// Retire a connection this long after it was opened, however busy. Recycling
    /// bounds the server-side state a single long-lived session accumulates and
    /// gives a failed-over Neon endpoint a bounded window to take over the pool.
    pub max_lifetime_secs: u64,
}

impl Default for PoolSettings {
    /// The shipped production sizing.
    ///
    /// `max_connections = 25`: the old hardcoded 10 (which was simply sqlx's own
    /// default, never a decision) is the ceiling Phase F exists to remove — at the
    /// design's 300-concurrent-run target the per-run pollers alone issue hundreds
    /// of queries a second, and pool throughput is `max_connections / mean query
    /// time`, so 10 connections against a ~25 ms round trip to a remote Neon caps
    /// the whole replica at ~400 queries/second. 25 is chosen against the DATABASE,
    /// not against the run count: Neon's smallest compute (0.25 CU) allows 112
    /// connections, and the design's recommended shape is two to three API replicas,
    /// so `3 × (25 + 2) = 81` leaves real headroom for migrations, `psql`, and
    /// monitoring. A deployment on a larger compute should raise
    /// `FLUIDBOX_DB_MAX_CONNECTIONS` — the chart documents the tiers.
    ///
    /// `min_connections = 0` (sqlx's default, made explicit): a warm floor would
    /// hold connections open against a Neon compute that is trying to scale to
    /// zero. It is only half a saving — the two `PgListener` connections are always
    /// open anyway — but the pool should not be the thing that adds to it.
    ///
    /// `acquire_timeout_secs = 15` is UNCHANGED from the pre-Phase-F hardcode
    /// (sqlx's own default is 30). Shortening it would convert transient contention
    /// into 500s; lengthening it would let a slow database accumulate in-flight
    /// requests, which is precisely the memory-exhaustion path.
    ///
    /// `idle_timeout_secs = 240` REPLACES sqlx's 600: ten minutes is longer than
    /// [`NEON_AUTOSUSPEND_SECS`], so the old value guaranteed the pool would hand
    /// out connections the server had already closed. `max_lifetime_secs = 1800`
    /// keeps sqlx's default, chosen rather than inherited.
    fn default() -> Self {
        Self {
            max_connections: 25,
            min_connections: 0,
            acquire_timeout_secs: 15,
            idle_timeout_secs: 4 * 60,
            max_lifetime_secs: 30 * 60,
        }
    }
}

/// Build the sqlx pool options from [`PoolSettings`].
///
/// Split out of [`connect_with`] deliberately: `connect_with` runs migrations on a
/// real connection before it ever builds a pool, so NOTHING about the settings→sqlx
/// mapping can be exercised without a database — and a knob that is parsed,
/// validated, logged and then never handed to sqlx looks identical, at every other
/// layer, to one that works. This function is pure, so a test can assert each knob
/// actually lands (`PoolOptions` exposes getters for all five).
///
/// Every knob is set EXPLICITLY (Phase F): the four that used to ride sqlx's
/// defaults were never chosen, and two of them (`idle_timeout`, `max_connections`)
/// were actively wrong for a remote Neon at the design's concurrency target.
/// `test_before_acquire` is deliberately LEFT at sqlx's `true`: it costs a round
/// trip per acquire, but Neon's scale-to-zero closes connections underneath us and
/// handing out a dead one would surface as a spurious request failure.
pub fn pool_options(settings: PoolSettings) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(settings.max_connections)
        .min_connections(settings.min_connections)
        .acquire_timeout(std::time::Duration::from_secs(
            settings.acquire_timeout_secs,
        ))
        // `idle_timeout`/`max_lifetime` take `impl Into<Option<Duration>>`, and
        // sqlx DISABLES the cap only on `None` — a `Some(Duration::ZERO)` means
        // "expire immediately", so every returned connection is closed and the pool
        // never pools (a per-acquire reconnect storm against Neon). `0` is the
        // documented "no cap" value (validate_pool_settings and its test), so it
        // MUST map to `None`, not to `Duration::from_secs(0)`.
        .idle_timeout(disabled_when_zero(settings.idle_timeout_secs))
        .max_lifetime(disabled_when_zero(settings.max_lifetime_secs))
}

/// Map a "seconds, 0 = disabled" knob onto sqlx's `Option<Duration>` cap: `0`
/// becomes `None` (no cap), anything else the duration. Without this, `0` would
/// become `Some(Duration::ZERO)` — "expire on return", the opposite of "no cap".
fn disabled_when_zero(secs: u64) -> Option<std::time::Duration> {
    (secs > 0).then(|| std::time::Duration::from_secs(secs))
}

#[cfg(test)]
mod pool_option_tests {
    use super::*;
    use std::time::Duration;

    /// The `0 = no cap` semantics that `validate_pool_settings` documents must
    /// actually reach sqlx as `None`, not as `Some(Duration::ZERO)` (which sqlx
    /// reads as "expire immediately" → a reconnect storm). This asserts on the
    /// CONSTRUCTED `PgPoolOptions` getters — the layer the prior test never
    /// inspected — so deleting `disabled_when_zero` fails here.
    #[test]
    fn zero_lifetime_and_idle_map_to_no_cap_not_instant_expiry() {
        let zero = pool_options(PoolSettings {
            max_lifetime_secs: 0,
            idle_timeout_secs: 0,
            ..PoolSettings::default()
        });
        assert_eq!(zero.get_max_lifetime(), None, "0 lifetime must be NO cap");
        assert_eq!(zero.get_idle_timeout(), None, "0 idle must be NO cap");

        // A non-zero value still lands as that exact duration.
        let set = pool_options(PoolSettings {
            max_lifetime_secs: 1800,
            idle_timeout_secs: 240,
            ..PoolSettings::default()
        });
        assert_eq!(set.get_max_lifetime(), Some(Duration::from_secs(1800)));
        assert_eq!(set.get_idle_timeout(), Some(Duration::from_secs(240)));
    }
}

/// Connect the application pool with the DEFAULT sizing ([`PoolSettings::default`]).
///
/// Kept as a distinct entry point so the tests that only want "a migrated pool"
/// (and the crate's own `test_connect`) do not have to thread sizing they do not
/// care about. The server calls [`connect_with`].
pub async fn connect(database_url: &str, runtime_role: Option<&str>) -> anyhow::Result<PgPool> {
    connect_with(database_url, runtime_role, PoolSettings::default()).await
}

/// Connect the application pool, running migrations first.
///
/// Phase D (#32) splits the two identities the process used to conflate: DDL runs
/// on a one-shot OWNER connection (migrations need ownership, and the owner is not
/// subject to a not-yet-created runtime role), then the app pool is built. When
/// `runtime_role` is `Some` (`FLUIDBOX_RUNTIME_ROLE`), every pooled connection
/// `SET ROLE`s to that least-privilege NON-owner role via `after_connect`, so RLS
/// binds it by ordinary means (not just FORCE). Default (`None`) = single-role mode:
/// the owner runs everything and RLS still binds it via FORCE + the tenant GUC.
///
/// **What the SET ROLE split is and is NOT** (review M4). It narrows the authority
/// of the ordinary, fixed application queries this process issues: those run as a
/// non-owner with enumerated DML and no BYPASSRLS, so a missing `tenant_id`
/// predicate is contained by the policy rather than by convention. It is NOT a
/// credential boundary. `RESET ROLE` returns the SAME connection to the migration
/// owner, and the process still holds the owner `DATABASE_URL` and can open a
/// fresh owner connection whenever it likes — so against process compromise, or a
/// SQL-injection sink that can emit a second statement, the split buys nothing.
/// Genuine separation needs two DISTINCT connection strings: a migration-owner one
/// used only for DDL, and a runtime LOGIN role that owns no schema objects and
/// carries no bypass attributes. That is a deployment topology change, not this
/// function; it is deliberately not claimed here.
///
/// The role name is interpolated into `SET ROLE` (a SQL identifier, never a bind
/// parameter), so it is validated to a strict identifier shape. Boot then REFUSES
/// a configured-but-absent role with the exact `CREATE ROLE` fix, and re-runs the
/// migration's POSTURE validation ([`check_runtime_role_posture`]) — a role can be
/// altered, or re-granted to another principal, long after 0018 ran.
pub async fn connect_with(
    database_url: &str,
    runtime_role: Option<&str>,
    pool_settings: PoolSettings,
) -> anyhow::Result<PgPool> {
    use sqlx::Connection;
    // (1) Migrations + role verification on a one-shot OWNER connection, closed
    // before the app pool exists. DDL is never attempted under the runtime role.
    let mut owner = sqlx::PgConnection::connect(database_url).await?;
    if let Some(role) = runtime_role {
        validate_runtime_role_name(role).map_err(|e| anyhow::anyhow!(e))?;
        // Publish the deployment's chosen role name to migration 0018, which creates
        // + posture-validates + grants it. Session-level (`false`) so it survives
        // sqlx's per-migration transactions on this connection. Without it 0018
        // falls back to the single hardcoded `fluidbox_runtime`, which on a SHARED
        // cluster is a name collision with someone else's principal.
        sqlx::query("select set_config('fluidbox.runtime_role', $1, false)")
            .bind(role)
            .execute(&mut owner)
            .await?;
    }
    // `migrate!` BAKES the migrations directory into the binary at COMPILE time —
    // adding a .sql file only takes effect once this crate recompiles, so any
    // change under migrations/ must touch this file. Latest: 0024
    // (mcp_upstream_sessions — cross-replica teardown of upstream MCP sessions).
    // This line was stale at 0020 through all four Phase E migrations: the
    // mechanism still worked, because every one of them also edited this file for
    // its own reasons, but the note itself was a lie for four migrations running.
    // Nothing asserts it — treat it as a reminder, not a guarantee.
    sqlx::migrate!("../../migrations").run(&mut owner).await?;
    if let Some(role) = runtime_role {
        let exists: bool =
            sqlx::query_scalar("select exists(select 1 from pg_roles where rolname = $1)")
                .bind(role)
                .fetch_one(&mut owner)
                .await?;
        if !exists {
            owner.close().await.ok();
            anyhow::bail!(
                "FLUIDBOX_RUNTIME_ROLE='{role}' is set but the role does not exist — migration 0018 \
                 could not create it (managed hosts often restrict CREATE ROLE). Create it and grant \
                 the privileges, then restart:\n  \
                 CREATE ROLE {role} NOLOGIN;\n  \
                 GRANT {role} TO CURRENT_USER;\n  \
                 -- plus the table/function grants from migrations/0018_rls_enforcement.sql"
            );
        }
        if let Err(msg) = check_runtime_role_posture(&mut owner, role).await? {
            owner.close().await.ok();
            anyhow::bail!(msg);
        }
    }
    owner.close().await?;

    // (2) The application pool. In runtime-role mode every connection SET ROLEs on
    // acquisition; the tenant/bypass GUC (scoped_tx/worker_tx) then rides each tx.
    // Sizing comes from [`pool_options`], which is pure so the mapping can be
    // asserted without a database.
    let opts = pool_options(pool_settings);
    let pool = match runtime_role {
        Some(role) => {
            // Validated above to ^[a-z_][a-z0-9_]*$, so plain double-quoting is safe.
            // Leaked to `&'static str` (once per process): sqlx's after_connect future
            // must be 'static, so the SET ROLE text cannot borrow a stack local.
            let set_role: &'static str = Box::leak(format!("set role \"{role}\"").into_boxed_str());
            opts.after_connect(move |conn, _meta| {
                Box::pin(async move {
                    use sqlx::Executor;
                    conn.execute(set_role).await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await?
        }
        None => opts.connect(database_url).await?,
    };
    Ok(pool)
}

/// A configured runtime-role name is interpolated into `SET ROLE` DDL, so it is
/// validated to a strict lowercase SQL-identifier shape (`^[a-z_][a-z0-9_]*$`, ≤63
/// chars) and REFUSED otherwise — fail closed rather than build injectable DDL.
pub fn validate_runtime_role_name(role: &str) -> Result<(), String> {
    let ok = !role.is_empty()
        && role.len() <= 63
        && role
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_lowercase() || (i > 0 && b.is_ascii_digit()));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "FLUIDBOX_RUNTIME_ROLE='{role}' is not a valid role name (expected ^[a-z_][a-z0-9_]*$, ≤63 chars)"
        ))
    }
}

/// Re-run migration 0018's POSTURE validation of the configured runtime role at
/// every boot (review H1). Existence is not trust: PostgreSQL roles are
/// CLUSTER-global while the grants 0018 issues are DATABASE-local, so on a shared
/// cluster the name may belong to somebody else's principal — and even a role we
/// created can be `ALTER ROLE`d or re-`GRANT`ed after the migration ran.
///
/// Refuses on (a) unsafe attributes — LOGIN (the role is meant to be reachable
/// only via `SET ROLE` from our own connection), SUPERUSER/BYPASSRLS (policies
/// would be skipped, making the split theatre), CREATEROLE/CREATEDB/REPLICATION;
/// (b) any role it is a MEMBER of (inherited privileges we never granted);
/// (c) any member OTHER than the connecting user — that principal can `SET ROLE`
/// into it and then set `fluidbox.bypass`, i.e. read every tenant of this database.
///
/// Both membership questions read DIRECT `pg_auth_members` rows, not the transitive
/// closure. That is deliberate: a transitive path necessarily runs through a role
/// that is already an admin over the connecting user, so flagging it would refuse
/// every managed host whose owner sits beneath a platform admin group (Neon's
/// `neon_superuser`) while describing no capability that principal lacks.
///
/// `Ok(Ok(()))` = clean. `Ok(Err(message))` = a posture refusal with the fix named
/// (the caller decides whether that is a boot abort). `Err(_)` = the catalog query
/// itself failed.
pub async fn check_runtime_role_posture(
    conn: &mut sqlx::PgConnection,
    role: &str,
) -> sqlx::Result<Result<(), String>> {
    let attrs: Option<(bool, bool, bool, bool, bool, bool)> = sqlx::query_as(
        "select rolcanlogin, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication
           from pg_roles where rolname = $1",
    )
    .bind(role)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((login, super_, bypass, createrole, createdb, replication)) = attrs else {
        return Ok(Err(format!("role '{role}' does not exist")));
    };
    let bad: Vec<&str> = [
        (login, "LOGIN"),
        (super_, "SUPERUSER"),
        (bypass, "BYPASSRLS"),
        (createrole, "CREATEROLE"),
        (createdb, "CREATEDB"),
        (replication, "REPLICATION"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, n)| *n)
    .collect();
    if !bad.is_empty() {
        return Ok(Err(format!(
            "FLUIDBOX_RUNTIME_ROLE='{role}' carries unsafe attribute(s): {}. fluidbox refuses to \
             run its pool under it — LOGIN makes it an authenticable principal, and \
             SUPERUSER/BYPASSRLS make PostgreSQL skip every migration-0018 policy, so the role \
             split would enforce nothing. Fix:\n  \
             ALTER ROLE {role} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;\n\
             or set FLUIDBOX_RUNTIME_ROLE to a name this deployment owns.",
            bad.join(", ")
        )));
    }
    let inherits: Vec<String> = sqlx::query_scalar(
        "select distinct g.rolname from pg_auth_members m
           join pg_roles g on g.oid = m.roleid
           join pg_roles r on r.oid = m.member
          where r.rolname = $1 order by g.rolname",
    )
    .bind(role)
    .fetch_all(&mut *conn)
    .await?;
    if !inherits.is_empty() {
        return Ok(Err(format!(
            "FLUIDBOX_RUNTIME_ROLE='{role}' is a member of {}, so it silently inherits privileges \
             fluidbox never granted. A least-privilege runtime role must be a member of nothing. \
             Fix: REVOKE those memberships FROM {role}, or point FLUIDBOX_RUNTIME_ROLE at a \
             deployment-specific role.",
            inherits.join(", ")
        )));
    }
    let members: Vec<String> = sqlx::query_scalar(
        "select distinct mm.rolname from pg_auth_members m
           join pg_roles mm on mm.oid = m.member
           join pg_roles r on r.oid = m.roleid
          where r.rolname = $1 and mm.rolname <> current_user order by mm.rolname",
    )
    .bind(role)
    .fetch_all(&mut *conn)
    .await?;
    if !members.is_empty() {
        return Ok(Err(format!(
            "FLUIDBOX_RUNTIME_ROLE='{role}' is granted to {} — those principals can `SET ROLE \
             {role}`, then set `fluidbox.bypass` and read EVERY tenant in this database. \
             PostgreSQL roles are cluster-global while fluidbox's grants are database-local, so a \
             shared cluster turns one hardcoded role name into a shared credential. Fix: REVOKE \
             {role} FROM those roles, or set FLUIDBOX_RUNTIME_ROLE to a deployment-specific name.",
            members.join(", ")
        )));
    }
    Ok(Ok(()))
}

/// Prove the pool's EFFECTIVE role is actually bound by RLS, i.e. that migration
/// 0018's policies run at all (review M2).
///
/// PostgreSQL skips every policy for a SUPERUSER or a BYPASSRLS role. Neon's
/// default `neondb_owner`/`neon_superuser` credential is exactly that, and it is
/// the documented posture in this repo's own setup script — so a deployment that
/// leaves `FLUIDBOX_RUNTIME_ROLE` unset gets RLS ENABLED, FORCED, and silently
/// INERT. A later missing `tenant_id` predicate then returns every tenant's rows
/// instead of being contained, which is the entire failure RLS exists to stop.
///
/// This runs on a POOLED connection so it observes whatever `after_connect SET
/// ROLE` produced — `current_user`, not the role in `DATABASE_URL`. Attributes are
/// NOT inherited through membership, so reading them off `current_user` is the
/// only correct question to ask. The caller (server boot) makes it fatal in
/// multi-user mode and advisory otherwise.
pub async fn pool_role_bypasses_rls(pool: &PgPool) -> sqlx::Result<Option<String>> {
    let (user, bypasses): (String, bool) = sqlx::query_as(
        "select current_user::text,
                coalesce((select rolsuper or rolbypassrls from pg_roles
                           where rolname = current_user), false)",
    )
    .fetch_one(pool)
    .await?;
    Ok(bypasses.then_some(user))
}

/// Open a transaction with the tenant RLS GUC set (`fluidbox.tenant_id`),
/// transaction-local (`set_config(..., true)`) so it auto-resets on commit/rollback
/// and never leaks to the next borrower of a pooled connection. EVERY tenant-scoped
/// read/write rides one of these: the `where tenant_id = $n` predicate stays as
/// defense-in-depth, and the RLS policy (migration 0018) is the enforcing floor —
/// a buggy or absent predicate is still filtered by the policy (issue #75).
///
/// Single-statement reads acquire one too: `SET LOCAL`/`set_config(..., true)` only
/// takes effect inside a transaction, so the +1 round-trip is the cost of DB-enforced
/// isolation (accepted, plan D8). The returned tx is `'static` — it owns a pooled
/// connection — so callers keep the usual `&mut *tx` + `tx.commit()` shape.
pub async fn scoped_tx(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
        .bind(scope.tenant_id().to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Open a transaction with the audited system-worker bypass GUC set
/// (`fluidbox.bypass = 'system_worker'`), so the RLS policies' bypass arm lets a
/// genuine cross-tenant scan or a principal-less credential-digest resolution see
/// every tenant's rows. The category rides IN the GUC value — one grep-able choke
/// point rather than a distinct BYPASSRLS role (plan D8). Used by the `system_worker`
/// scans (Task 7) and the handful of lib.rs / identity.rs bootstrap resolvers that
/// have no scope by construction (token-digest resolution, pre-auth flow claims, the
/// boot seed's tenant upsert). That set is ENUMERATED in the `system_worker` module
/// docs — every named function outside this module that reaches a bypass is listed
/// there, so the inventory is grep-checkable rather than "somewhere in the crate".
pub(crate) async fn worker_tx(
    pool: &PgPool,
) -> sqlx::Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("select set_config('fluidbox.bypass', 'system_worker', true)")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// The TEST-FIXTURE lane (Phase D, #32): `connect()` plus the audited system-worker
/// bypass GUC (`fluidbox.bypass = 'system_worker'`) set at SESSION level on every
/// pooled connection. Compiled only for this crate's own `#[cfg(test)]` module.
///
/// Why it exists: migration 0018 ENABLEs + FORCEs RLS on 37 tables, and FORCE binds
/// the table OWNER too. A fixture writes and reads ACROSS tenants and predates any
/// [`TenantScope`], so on a plain pool every fixture INSERT is refused outright
/// ("new row violates row-level security policy") and every fixture SELECT/DELETE
/// silently matches ZERO rows — the second is the nastier failure, because a cleanup
/// helper then reports success while deleting nothing. Neither shape surfaces today:
/// CI connects as the superuser `postgres` (RLS skipped entirely) and Neon's default
/// role carries BYPASSRLS. This lane is what makes the suite work on an RLS-BOUND
/// owner, which is the posture 0018 exists for.
///
/// It does not weaken what the suite proves. RLS enforcement is asserted by the four
/// tests that open their OWN `SET ROLE fluidbox_runtime` connection or runtime-role
/// pool (`rls_enforces_tenant_isolation_under_runtime_role`,
/// `rls_system_worker_bypass_is_explicit`, `rls_reseal_helpers_work_under_worker_tx`,
/// and identity's `rls_identity_family_cross_tenant_isolation`) — none of which route
/// their ASSERTIONS through this pool — and end-to-end by the acceptance suites that
/// boot the server with `FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime`.
#[cfg(test)]
pub(crate) async fn test_connect(database_url: &str) -> anyhow::Result<PgPool> {
    use sqlx::Executor;
    // Migrations + role validation exactly as production does; the pool it builds is
    // closed immediately — only the migration side effect is wanted here.
    connect(database_url, None).await?.close().await;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(15))
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("set fluidbox.bypass = 'system_worker'")
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await?;
    Ok(pool)
}

pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(s.as_bytes()))
}

// ─── Rows ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct PolicyRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub version: i32,
    pub yaml_source: String,
    /// The EFFECTIVE policy: base yaml ++ `managed_overrides`. This — not
    /// `managed_overrides` — is what `run_service` freezes into a RunSpec, so
    /// every write to the overrides column must republish this.
    pub parsed: Value,
    /// UI-owned per-tool decisions (`Vec<fluidbox_core::policy::ToolOverride>`),
    /// kept out of the git-owned `yaml_source`. See migration 0010.
    pub managed_overrides: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct AgentRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct AgentRevisionRow {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub rev: i32,
    pub harness: String,
    pub runner_image: String,
    pub model: String,
    pub system_prompt: Option<String>,
    pub policy_id: Uuid,
    pub budgets: Value,
    pub capability_bundles: Value,
    /// Optional WorkspaceSpec jsonb — the agent's default workspace.
    pub default_workspace: Option<Value>,
    /// Brokered connection requirements (design :349-389): a validated
    /// `Vec<ConnectionRequirement>` jsonb (slot / connector / tools / mode).
    /// Append-only with the revision; validated app-side, never an FK
    /// (agent_revisions has no tenant column). Defaults to `[]`.
    pub connection_requirements: Value,
    pub created_at: DateTime<Utc>,
}

/// One version of a capability bundle (design §3.6): append-only like
/// agent revisions — publishing a change = a new (name, version) row. The
/// definition carries the photographed tool snapshots; definition_digest is
/// the supply-chain anchor frozen into RunSpecs.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct CapabilityBundleRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub version: i32,
    pub description: Option<String>,
    pub definition: Value,
    pub definition_digest: String,
    pub created_at: DateTime<Utc>,
}

/// Deliberately has NO credential fields: every query selects the explicit
/// `CONNECTION_COLS` list, so the sealed credential / client secret can
/// never ride along into an API response or log.
/// `connection_credential_sealed` / `connection_client_secret_sealed` are
/// the only readers. `oauth` carries NON-secret custody state (endpoints,
/// client identity, scopes, error note).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct IntegrationConnectionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider: String,
    pub external_account_id: String,
    pub display_name: String,
    pub granted_scopes: Value,
    pub resource_selection: Value,
    pub status: String,
    pub metadata: Value,
    pub auth_kind: String,
    pub oauth: Option<Value>,
    /// Typed custody linkage for seamless github_app connections: the pem +
    /// webhook secret live on the registration. NULL = legacy per-connection
    /// custody. Resolution fails closed — never falls back across kinds.
    pub registration_id: Option<Uuid>,
    /// Ownership (design :274-296): `organization` (visible to every member) or
    /// `user` (one member's personal custody); `owner_user_id` is set iff
    /// `owner_type='user'`. `created_by_user_id` records who connected it (null
    /// for system/admin-created rows). `authorization_generation` bumps on every
    /// re-consent/rotation so stale run bindings fail closed.
    pub owner_type: String,
    pub owner_user_id: Option<Uuid>,
    pub created_by_user_id: Option<Uuid>,
    pub authorization_generation: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct SessionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub agent_revision_id: Uuid,
    pub status: String,
    pub status_reason: Option<String>,
    pub autonomy: String,
    pub trust_tier: String,
    pub task: String,
    pub repo_source: Value,
    pub run_spec: Value,
    /// InvocationContext envelope (design §3.4). Null for pre-Phase-2 rows.
    pub trigger: Option<Value>,
    pub sandbox_handle: Option<Value>,
    pub budgets: Value,
    pub base_commit: Option<String>,
    pub result_summary: Option<String>,
    pub event_seq: i64,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    /// Who invoked this run (design "tenant/user audit fields"): the invocation
    /// class, and the authenticated user id when one exists (None for
    /// operator-token / trigger / schedule / webhook). Drives run visibility.
    pub invoked_by_kind: Option<String>,
    pub invoked_by_user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SessionRow {
    pub fn status_enum(&self) -> SessionStatus {
        SessionStatus::parse(&self.status).unwrap_or(SessionStatus::Failed)
    }
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct EventRow {
    pub event_id: Uuid,
    pub session_id: Uuid,
    pub seq: i64,
    pub actor: String,
    pub r#type: String,
    pub payload: Value,
    pub occurred_at: DateTime<Utc>,
}

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

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ArtifactRow {
    pub id: Uuid,
    pub session_id: Uuid,
    pub kind: String,
    pub name: String,
    pub content: String,
    pub content_type: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, sqlx::FromRow, serde::Serialize)]
pub struct UsageTotals {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
    pub cost_usd: f64,
    pub requests: i64,
}

// ─── Tenants ──────────────────────────────────────────────────────────────

pub async fn ensure_default_tenant(pool: &PgPool) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    // Boot bootstrap under the audited bypass: this writes/updates the `tenants`
    // registry ITSELF — possibly a pre-existing 'default' of unknown id via ON
    // CONFLICT (name) — so there is no tenant scope to key on, and the tenants RLS
    // policy's WITH CHECK would otherwise refuse the insert. The row IS the tenant.
    let mut tx = worker_tx(pool).await?;
    // Migration 0012 made `slug` NOT NULL; the boot tenant owns slug 'default'.
    // On a live DB the migration backfilled it already — this keeps a fresh DB
    // and any hand-edited row converged.
    let row = sqlx::query(
        "insert into tenants (id, name, slug) values ($1, 'default', 'default')
         on conflict (name) do update set slug = excluded.slug
         returning id",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let out = row.get("id");
    tx.commit().await?;
    Ok(out)
}

// ─── Policies ─────────────────────────────────────────────────────────────

/// Upsert a policy's AUTHORED yaml. Existing `managed_overrides` are preserved
/// and merged back into `parsed` — without this, the next `just policy-sync`
/// would silently drop every decision made in the Governance page.
///
/// Storage primitive: it merges, it does not judge. A caller that changes the
/// base rules under an existing override must `Policy::validate()` the merged
/// result BEFORE calling (the API layer does), because an override targeting a
/// rule that just grew `paths`/`shell` is invalid and cannot be caught here —
/// `fluidbox-db` has no error type to refuse with.
pub async fn upsert_policy(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    yaml_source: &str,
    parsed: &Value,
) -> sqlx::Result<PolicyRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "insert into policies (id, tenant_id, name, yaml_source, parsed)
         values ($1, $2, $3, $4, $5)
         on conflict (tenant_id, name) do update
           set yaml_source = excluded.yaml_source,
               parsed = jsonb_set(
                 excluded.parsed, '{managed_overrides}', policies.managed_overrides, true
               ),
               version = policies.version + 1,
               updated_at = now()
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(name)
    .bind(yaml_source)
    .bind(parsed)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Upsert ONE exact-name override, replacing any existing decision for that
/// tool. Bumps `version` and republishes `parsed`.
pub async fn set_policy_override(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    tool: &str,
    action: fluidbox_core::policy::RuleAction,
) -> sqlx::Result<PolicyRow> {
    let entry = serde_json::json!([{ "tool": tool, "action": action }]);
    write_policy_overrides(pool, scope, name, tool, &entry).await
}

/// Remove ONE override; the tool falls back to whatever the base rules say.
/// Bumps `version` and republishes `parsed`.
pub async fn clear_policy_override(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    tool: &str,
) -> sqlx::Result<PolicyRow> {
    write_policy_overrides(pool, scope, name, tool, &serde_json::json!([])).await
}

/// Drop every override for `tool`, then append `append` (a jsonb ARRAY — one
/// entry to set, empty to clear). Set and clear are the same write: filter out
/// the tool's old decision, optionally add the new one.
///
/// ONE statement, because `parsed` and `managed_overrides` disagreeing — even
/// between two round-trips — means a run evaluating a policy that no longer
/// exists. `run_service` reads `parsed`; an override written only to the column
/// would look saved in the UI and never fire.
async fn write_policy_overrides(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    tool: &str,
    append: &Value,
) -> sqlx::Result<PolicyRow> {
    let mut tx = scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(
        "with target as (
           select id,
                  coalesce(
                    (select jsonb_agg(e)
                       from jsonb_array_elements(managed_overrides) e
                      where e->>'tool' <> $3),
                    '[]'::jsonb
                  ) || $4::jsonb as overrides
             from policies
            where tenant_id = $1 and name = $2
         )
         update policies p
            set managed_overrides = t.overrides,
                parsed = jsonb_set(p.parsed, '{managed_overrides}', t.overrides, true),
                version = p.version + 1,
                updated_at = now()
           from target t
          where p.id = t.id
         returning p.*",
    )
    .bind(scope.tenant_id())
    .bind(name)
    .bind(tool)
    .bind(append)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Bootstrap a policy from a seed file only if it does not already exist.
/// Returns the existing or newly-inserted row — so UI edits (which bump the
/// version) are never clobbered by a later boot re-reading the disk YAML.
pub async fn seed_policy_if_absent(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    yaml_source: &str,
    parsed: &Value,
) -> sqlx::Result<(PolicyRow, bool)> {
    if let Some(existing) = get_policy_by_name(pool, scope, name).await? {
        return Ok((existing, false));
    }
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query_as(
        "insert into policies (id, tenant_id, name, yaml_source, parsed)
         values ($1, $2, $3, $4, $5)
         on conflict (tenant_id, name) do update set name = excluded.name
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(name)
    .bind(yaml_source)
    .bind(parsed)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((row, true))
}

pub async fn list_policies(pool: &PgPool, scope: TenantScope) -> sqlx::Result<Vec<PolicyRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from policies where tenant_id = $1 order by name")
        .bind(scope.tenant_id())
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_policy(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<PolicyRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from policies where id = $1 and tenant_id = $2")
        .bind(id)
        .bind(scope.tenant_id())
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_policy_by_name(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
) -> sqlx::Result<Option<PolicyRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from policies where tenant_id = $1 and name = $2")
        .bind(scope.tenant_id())
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Agents whose LATEST revision uses this policy — the blast radius an override
/// header must state. An older revision pointing here does not count: only the
/// latest revision governs future runs, so only it is at stake in an edit.
pub async fn policy_agents_using(
    pool: &PgPool,
    scope: TenantScope,
    policy_id: Uuid,
) -> sqlx::Result<i64> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_scalar(
        "select count(*) from agents a
          where a.tenant_id = $1
            and (
              select r.policy_id from agent_revisions r
               where r.agent_id = a.id
               order by r.rev desc
               limit 1
            ) = $2",
    )
    .bind(scope.tenant_id())
    .bind(policy_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The union of `mcp__<server>__<tool>` names an agent on this policy can call —
/// from BOTH attachment paths on the LATEST revision of every agent using it:
/// the photographed tools in its pinned (sandbox) capability bundles, AND the
/// `mcp__<slot>__<tool>` names in its brokered `connection_requirements` (Phase
/// C: converted agents carry brokered tools as requirements, not bundle pins, so
/// their governance-matrix rows keep appearing). Sorted and deduplicated: two
/// agents may pin the same bundle or require the same tool.
///
/// Reads the pins' bundle ids rather than resolving `name`/`version` — the pin is
/// exact by construction (§17 #7), so the id IS the photograph the frozen RunSpec
/// will carry; requirement tool names are the frozen contract directly.
pub async fn policy_mcp_tools(
    pool: &PgPool,
    scope: TenantScope,
    policy_id: Uuid,
) -> sqlx::Result<Vec<String>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let revs: Vec<(Value, Value)> = sqlx::query_as(
        "select r.capability_bundles, r.connection_requirements from agents a
           join lateral (
             select * from agent_revisions r2
              where r2.agent_id = a.id order by r2.rev desc limit 1
           ) r on true
          where a.tenant_id = $1 and r.policy_id = $2",
    )
    .bind(scope.tenant_id())
    .bind(policy_id)
    .fetch_all(&mut *tx)
    .await?;

    let mut out: Vec<String> = Vec::new();

    // Brokered requirement tools: `mcp__<slot>__<tool>` straight off the revision
    // — the requirement IS the frozen contract, there is no bundle to resolve.
    for (_, reqs) in &revs {
        let Some(arr) = reqs.as_array() else { continue };
        for req in arr {
            let Some(slot) = req.get("slot").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(tools) = req.get("required_tools").and_then(|v| v.as_array()) else {
                continue;
            };
            for t in tools {
                if let Some(tool) = t.as_str() {
                    out.push(format!("mcp__{slot}__{tool}"));
                }
            }
        }
    }

    // Sandbox-bundle tools: resolve each pin's bundle id to its photographed
    // `definition.servers[].tools[]`.
    let mut ids: Vec<Uuid> = Vec::new();
    for (pins, _) in &revs {
        let Some(arr) = pins.as_array() else { continue };
        for r in arr {
            if let Some(id) = r
                .get("id")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
            {
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    ids.dedup();

    if !ids.is_empty() {
        // Tenant-scoped: a pin can never reach across a tenant boundary.
        let defs: Vec<Value> = sqlx::query_scalar(
            "select definition from capability_bundles where tenant_id = $1 and id = any($2)",
        )
        .bind(scope.tenant_id())
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?;

        for def in &defs {
            let Some(servers) = def.get("servers").and_then(|v| v.as_array()) else {
                continue;
            };
            for s in servers {
                let Some(server) = s.get("name").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(tools) = s.get("tools").and_then(|v| v.as_array()) else {
                    continue;
                };
                for t in tools {
                    if let Some(tool) = t.get("name").and_then(|v| v.as_str()) {
                        out.push(format!("mcp__{server}__{tool}"));
                    }
                }
            }
        }
    }

    tx.commit().await?;
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

// ─── Agents & revisions ───────────────────────────────────────────────────

pub async fn create_agent(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    description: Option<&str>,
) -> sqlx::Result<AgentRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "insert into agents (id, tenant_id, name, description) values ($1,$2,$3,$4)
         on conflict (tenant_id, name) do update set description = excluded.description
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(name)
    .bind(description)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_agents(pool: &PgPool, scope: TenantScope) -> sqlx::Result<Vec<AgentRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from agents where tenant_id = $1 order by name")
        .bind(scope.tenant_id())
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_agent(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<AgentRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from agents where id = $1 and tenant_id = $2")
        .bind(id)
        .bind(scope.tenant_id())
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_agent_by_name(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
) -> sqlx::Result<Option<AgentRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from agents where tenant_id = $1 and name = $2")
        .bind(scope.tenant_id())
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Appends a new immutable revision (rev = max+1). Editing an agent is
/// always an append — never an update — by construction.
/// `capability_bundles` is the §17 #7 pin list (BundleRef json array): exact
/// versions resolved at attach time, never floating.
#[allow(clippy::too_many_arguments)]
pub async fn append_agent_revision(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
    harness: &str,
    runner_image: &str,
    model: &str,
    system_prompt: Option<&str>,
    policy_id: Uuid,
    budgets: &Value,
    default_workspace: Option<&Value>,
    capability_bundles: &Value,
    connection_requirements: &Value,
) -> sqlx::Result<AgentRevisionRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    // Revisions carry no tenant column of their own; the tenant boundary is the
    // parent agent — the insert only lands when the agent AND the referenced
    // policy both belong to the scope (a cross-tenant policy_id is proven
    // impossible in SQL, not just Rust-side). Zero rows → RowNotFound (the
    // existing contract for a not-in-scope agent), which callers already map to
    // a 404. `connection_requirements` is validated app-side (Task 2) before it
    // reaches here.
    let __rls_out = sqlx::query_as(
        "insert into agent_revisions
           (id, agent_id, rev, harness, runner_image, model, system_prompt, policy_id, budgets,
            default_workspace, capability_bundles, connection_requirements)
         select $1, $2,
           coalesce((select max(rev) from agent_revisions where agent_id = $2), 0) + 1,
           $3, $4, $5, $6, $7, $8, $9, $10, $11
         where exists (select 1 from agents a where a.id = $2 and a.tenant_id = $12)
           and exists (select 1 from policies p where p.id = $7 and p.tenant_id = $12)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(agent_id)
    .bind(harness)
    .bind(runner_image)
    .bind(model)
    .bind(system_prompt)
    .bind(policy_id)
    .bind(budgets)
    .bind(default_workspace)
    .bind(capability_bundles)
    .bind(connection_requirements)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn latest_revision(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
) -> sqlx::Result<Option<AgentRevisionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select r.* from agent_revisions r
         join agents a on a.id = r.agent_id
         where r.agent_id = $1 and a.tenant_id = $2
         order by r.rev desc limit 1",
    )
    .bind(agent_id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_revisions(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
) -> sqlx::Result<Vec<AgentRevisionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select r.* from agent_revisions r
         join agents a on a.id = r.agent_id
         where r.agent_id = $1 and a.tenant_id = $2
         order by r.rev desc",
    )
    .bind(agent_id)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_revision(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<AgentRevisionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select r.* from agent_revisions r
         join agents a on a.id = r.agent_id
         where r.id = $1 and a.tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

// ─── Capability bundles (Phase 5: the registry) ───────────────────────────

/// Appends a new immutable bundle version (version = max+1 within the
/// name). Publishing a change is always an append — never an update — by
/// construction, exactly like agent revisions.
pub async fn create_capability_bundle(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    description: Option<&str>,
    definition: &Value,
    definition_digest: &str,
) -> sqlx::Result<CapabilityBundleRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "insert into capability_bundles
           (id, tenant_id, name, version, description, definition, definition_digest)
         values ($1, $2, $3,
           coalesce((select max(version) from capability_bundles
                     where tenant_id = $2 and name = $3), 0) + 1,
           $4, $5, $6)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(name)
    .bind(description)
    .bind(definition)
    .bind(definition_digest)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_capability_bundles(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<CapabilityBundleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from capability_bundles where tenant_id = $1
         order by name, version desc",
    )
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_capability_bundle(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<CapabilityBundleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out =
        sqlx::query_as("select * from capability_bundles where id = $1 and tenant_id = $2")
            .bind(id)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn latest_capability_bundle(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
) -> sqlx::Result<Option<CapabilityBundleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from capability_bundles where tenant_id = $1 and name = $2
         order by version desc limit 1",
    )
    .bind(scope.tenant_id())
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_capability_bundle_version(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    version: i32,
) -> sqlx::Result<Option<CapabilityBundleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from capability_bundles
         where tenant_id = $1 and name = $2 and version = $3",
    )
    .bind(scope.tenant_id())
    .bind(name)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

// ─── Integration connections ──────────────────────────────────────────────

/// Every connection query selects this explicit column list (never `*`) so
/// the sealed credential / client secret can't ride along into a row.
const CONNECTION_COLS: &str = "id, tenant_id, provider, external_account_id, display_name, \
     granted_scopes, resource_selection, status, metadata, auth_kind, oauth, \
     registration_id, owner_type, owner_user_id, created_by_user_id, \
     authorization_generation, created_at, updated_at";

/// Auth flavor of a new connection. `static` seals the pasted secret now and
/// starts `active`; `oauth` starts `pending` with NO credential — the
/// callback exchange activates it with the sealed rotating refresh token.
pub struct ConnectionAuth<'a> {
    pub auth_kind: &'a str, // static | oauth
    pub status: &'a str,    // active | pending | suspended
    pub oauth: Option<&'a Value>,
    pub client_secret_sealed: Option<&'a [u8]>,
    /// Envelope key-version companion for `client_secret_sealed` (1 legacy, 2
    /// v2). Ignored when `client_secret_sealed` is None.
    pub client_secret_key_version: i16,
    /// Set only by the seamless github_app flows (custody on the
    /// registration); legacy/manual connections leave it NULL.
    pub registration_id: Option<Uuid>,
}

impl ConnectionAuth<'static> {
    pub fn static_active() -> Self {
        Self {
            auth_kind: "static",
            status: "active",
            oauth: None,
            client_secret_sealed: None,
            client_secret_key_version: 1,
            registration_id: None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create_connection(
    pool: &PgPool,
    scope: TenantScope,
    provider: &str,
    external_account_id: &str,
    display_name: &str,
    credential_sealed: Option<&[u8]>,
    credential_key_version: i16,
    granted_scopes: &Value,
    resource_selection: &Value,
    metadata: &Value,
    webhook_secret_sealed: Option<&[u8]>,
    webhook_secret_key_version: i16,
    auth: ConnectionAuth<'_>,
    owner: ConnectionOwner,
    created_by_user_id: Option<Uuid>,
) -> sqlx::Result<IntegrationConnectionRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    // owner_type/owner_user_id are stamped from `owner`; authorization_generation
    // starts at 1 (the column default) and bumps only on re-consent/rotation.
    // The `_key_version` companions ride beside each sealed column (1 legacy, 2
    // v2 envelope) so the reader can dispatch on open.
    let (owner_type, owner_user_id) = owner.parts();
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into integration_connections
           (id, tenant_id, provider, external_account_id, display_name, credential_sealed,
            granted_scopes, resource_selection, metadata, webhook_secret_sealed,
            auth_kind, status, oauth, client_secret_sealed, registration_id,
            owner_type, owner_user_id, created_by_user_id,
            credential_key_version, webhook_secret_key_version, client_secret_key_version)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
         returning {CONNECTION_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(provider)
    .bind(external_account_id)
    .bind(display_name)
    .bind(credential_sealed)
    .bind(granted_scopes)
    .bind(resource_selection)
    .bind(metadata)
    .bind(webhook_secret_sealed)
    .bind(auth.auth_kind)
    .bind(auth.status)
    .bind(auth.oauth)
    .bind(auth.client_secret_sealed)
    .bind(auth.registration_id)
    .bind(owner_type)
    .bind(owner_user_id)
    .bind(created_by_user_id)
    .bind(credential_key_version)
    .bind(webhook_secret_key_version)
    .bind(auth.client_secret_key_version)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_connections(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections
         where tenant_id = $1 order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

// Executor-generic so a caller holding the per-connection OAuth advisory lock
// can re-read THROUGH its own transaction (`&mut *tx`) instead of borrowing a
// SECOND pooled connection — the latter deadlocks the fixed-size pool under
// concurrent refreshes/callbacks. Existing `&PgPool` call sites are unchanged
// (`&PgPool: PgExecutor`).
pub async fn get_connection<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections where id = $1 and tenant_id = $2"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(exec)
    .await
}

pub async fn revoke_connection(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update integration_connections set status = 'revoked', updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $2
         returning {CONNECTION_COLS}"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// List connections through a visibility lens (design :274-296): `All` returns
/// every connection in the tenant; `User(id)` returns org-owned connections
/// plus only that user's personal connections. `list_connections` stays the
/// unfiltered internal/worker reader.
pub async fn list_connections_visible(
    pool: &PgPool,
    scope: TenantScope,
    viewer: ConnectionViewer,
) -> sqlx::Result<Vec<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections
         where tenant_id = $1
           and ($2::uuid is null or owner_type = 'organization' or owner_user_id = $2)
         order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .bind(viewer.user_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Read one connection through the same visibility lens as
/// [`list_connections_visible`] — returns None for another user's personal row.
pub async fn get_connection_visible(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    viewer: ConnectionViewer,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections
         where id = $1 and tenant_id = $2
           and ($3::uuid is null or owner_type = 'organization' or owner_user_id = $3)"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .bind(viewer.user_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Bump a connection's authorization generation (design :296) — called on every
/// re-consent/rotation so any run binding that froze the older generation fails
/// closed at the broker recheck. Returns the new generation, or None if the
/// connection is not in scope.
pub async fn bump_connection_generation(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<i32>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "update integration_connections
         set authorization_generation = authorization_generation + 1, updated_at = now()
         where id = $1 and tenant_id = $2
         returning authorization_generation",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.map(|r| r.get::<i32, _>("authorization_generation")))
}

/// Persist non-secret OAuth custody state (discovered endpoints, client
/// identity, pending bundle) before the connection is activated.
///
/// **Executor-generic on purpose, and the production caller MUST pass a
/// transaction that already holds this connection's OAuth advisory lock**
/// (`oauth::commit_start_epoch` — see `acquire_oauth_lock`). This write is the
/// tail of a read-modify-write that spans seconds of outbound discovery HTTP:
/// the bag it lands was assembled from a read taken BEFORE that HTTP, so it may
/// only be committed once the caller has proven — under the same lock the
/// activation path takes — that nothing re-authorized the connection meanwhile.
/// Riding the caller's lock-holding transaction makes the proof and the write
/// ONE atomic step. A standalone round trip on `&PgPool` (what this used to be)
/// leaves a window in which a SUPERSEDED start clobbers the winner's token
/// endpoint / client identity, so its refresh would authenticate to the wrong
/// endpoint under the wrong client (review #32).
///
/// The caller's bag REPLACES the stored one — except for
/// [`ACTIVATED_AT_KEY`], which is carried over unconditionally. That stamp is
/// owned by [`activate_connection_oauth`] and is half of its compare-and-swap
/// (review H2): an activation landing in the read-modify-write window would
/// otherwise have its stamp erased by a stale bag — handing a superseded sibling
/// flow a passing expectation. Belt-and-braces now that the write rides the
/// lock, and the only protection left for any caller that does not.
pub async fn update_connection_oauth<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
    oauth: &Value,
) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "update integration_connections
         set oauth = case
                 when jsonb_typeof($2::jsonb) = 'object'
                      and (oauth -> '{ACTIVATED_AT_KEY}') is not null
                 then jsonb_set($2::jsonb, '{{{ACTIVATED_AT_KEY}}}',
                                oauth -> '{ACTIVATED_AT_KEY}')
                 else $2::jsonb end,
             updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $3"
    )))
    .bind(id)
    .bind(oauth)
    .bind(scope.tenant_id())
    .execute(exec)
    .await?;
    Ok(())
}

/// The callback exchange completing: seal the rotating refresh token into
/// `credential_sealed` (the SAME custody column static bearers use), flip the
/// connection live, and — atomically in the SAME UPDATE — bump the authorization
/// generation on a RECONNECT (a re-consent from any non-`pending` status: the
/// account/issuer/audience may have changed, so any in-flight run bound to the
/// old generation must fail closed; design :294-296). The bump is decided from
/// the row's PRE-UPDATE `status` INSIDE the SET (`status <> 'pending'`) — under
/// the row lock the SET reads the OLD status, which IS the prior status at commit
/// time. This is deliberately NOT a caller-supplied boolean (B1): two first-
/// connect callbacks both reading `pending` before serializing on the oauth lock
/// would each pass `bump=false`; the second must still bump because by the time
/// it holds the lock the row is already `active`. First connect (from `pending`)
/// ⇒ no bump; reconnect (from `active`/`error`) ⇒ bump — all in ONE write, so no
/// crash window where a reconnected grant serves the OLD generation. The returned
/// row carries the FINAL generation the caller caches under.
///
/// **THE ACTIVATION IS A COMPARE-AND-SWAP** (Phase D review H2). The callback's
/// pre-exchange generation recheck is an optimization that avoids burning a code;
/// it is NOT the boundary, because the code exchange is a full HTTP round trip
/// during which a sibling flow can activate. TWO predicates make the write itself
/// the boundary, both frozen at the flow's START:
///   - `authorization_generation = expected_generation` — the flow row's frozen
///     generation. A sibling RECONNECT that landed first moved it, so the loser
///     matches zero rows instead of overwriting the newer refresh token.
///   - `activated_at < flow_started_at` — the connection's own last-activation
///     instant (stamped by this UPDATE, DB clock, never caller-supplied) against
///     the flow row's `created_at`. This is what covers FIRST connect, where the
///     `pending → active` activation deliberately does NOT bump the generation:
///     two callbacks racing on the same pending row both froze the same
///     generation, so the generation predicate alone cannot separate them. Every
///     successful activation stamps an instant strictly later than every
///     in-flight flow's `created_at`, so ONE activation invalidates every sibling
///     flow's expectation — including its own siblings' retries.
///
/// `None` therefore means "superseded / no longer activatable" (revoked, wrong
/// auth_kind, reauthorized, or already activated since this flow started); the
/// caller must tell the user to restart the connect flow, never retry blindly.
///
/// `activated_at` lives inside the `oauth` jsonb bag rather than its own column
/// because this wave may not add migrations; the bag is rewritten here from the
/// caller's value, so the stamp is applied SQL-side (`jsonb_set` +
/// `clock_timestamp()`) and cannot be forged or dropped by the caller.
// Executor-generic (see `get_connection`): the callback activation runs THROUGH
// the connection that holds the OAuth advisory lock, so the critical section
// uses exactly one pooled connection.
#[allow(clippy::too_many_arguments)]
pub async fn activate_connection_oauth<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
    sealed_refresh: &[u8],
    key_version: i16,
    oauth: &Value,
    granted_scopes: &Value,
    expected_generation: i32,
    flow_started_at: DateTime<Utc>,
) -> sqlx::Result<Option<IntegrationConnectionRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update integration_connections
         set credential_sealed = $2, credential_key_version = $6, granted_scopes = $4,
             oauth = jsonb_set(
                 case when jsonb_typeof($3::jsonb) = 'object' then $3::jsonb else '{{}}'::jsonb end,
                 '{{{ACTIVATED_AT_KEY}}}', to_jsonb(clock_timestamp())),
             status = 'active',
             authorization_generation =
                 authorization_generation + case when status <> 'pending' then 1 else 0 end,
             updated_at = now()
         where id = $1 and status <> 'revoked' and auth_kind = 'oauth' and tenant_id = $5
           and authorization_generation = $7
           and coalesce((oauth ->> '{ACTIVATED_AT_KEY}')::timestamptz, '-infinity'::timestamptz)
               < $8
         returning {CONNECTION_COLS}"
    )))
    .bind(id)
    .bind(sealed_refresh)
    .bind(oauth)
    .bind(granted_scopes)
    .bind(scope.tenant_id())
    .bind(key_version)
    .bind(expected_generation)
    .bind(flow_started_at)
    .fetch_optional(exec)
    .await
}

/// The `oauth` jsonb key carrying the connection's last successful OAuth
/// activation instant (DB clock). Written ONLY by [`activate_connection_oauth`],
/// read by its CAS predicate and by the callback's pre-exchange fast refusal.
pub const ACTIVATED_AT_KEY: &str = "activated_at";

/// Refresh-token rotation: one atomic overwrite (OAuth 2.1 MUST — old token
/// is gone the moment the new one lands). Active connections only, and ONLY
/// while the connection is still at `expected_generation` — a concurrent
/// reconnect that bumped the generation (and landed a NEW refresh token) must
/// NOT be clobbered by an in-flight refresh rotating the OLD grant's token
/// (that would restore a superseded grant). Returns false when the row was
/// revoked/errored OR reauthorized (generation moved) underneath the caller;
/// the refresh path treats a false as a stale mint and fails closed.
pub async fn rotate_connection_refresh<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
    sealed_new: &[u8],
    key_version: i16,
    expected_generation: i32,
) -> sqlx::Result<bool>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query(
        "update integration_connections
         set credential_sealed = $2, credential_key_version = $5, updated_at = now()
         where id = $1 and status = 'active' and auth_kind = 'oauth' and tenant_id = $3
           and authorization_generation = $4",
    )
    .bind(id)
    .bind(sealed_new)
    .bind(scope.tenant_id())
    .bind(expected_generation)
    .bind(key_version)
    .execute(exec)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// `invalid_grant`-class failure: the refresh token is dead, the connection
/// needs human re-consent. Everything downstream fails closed off the
/// status: `connection_credential_sealed` stops returning, run creation
/// refuses, the broker surfaces "reconnect".
pub async fn mark_connection_error<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
    note: &str,
) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "update integration_connections
         set status = 'error', updated_at = now(),
             oauth = jsonb_set(coalesce(oauth, '{}'::jsonb), '{error}', to_jsonb($2::text))
         where id = $1 and status = 'active' and tenant_id = $3",
    )
    .bind(id)
    .bind(note)
    .bind(scope.tenant_id())
    .execute(exec)
    .await
    .map(|_| ())
}

// (`set_connection_client_secret` retired in Phase D Task 3 (#32): DCR client
// secrets now live on the shared `oauth_client_registrations` row, not the
// connection. Pre-registered confidential secrets are still written per-connection
// at CREATE time via `ConnectionAuth.client_secret_sealed`, and read below.)

/// The only reader of the sealed client secret (confidential OAuth clients).
/// Client identity outlives token state — the dance needs it while the row
/// is still pending (first exchange) or errored (reconnect) — so any
/// non-revoked status qualifies.
pub async fn connection_client_secret_sealed<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query(
        "select client_secret_sealed, client_secret_key_version from integration_connections
         where id = $1 and status <> 'revoked' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(exec)
    .await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Vec<u8>>, _>("client_secret_sealed")
            .map(|b| (b, r.get::<i16, _>("client_secret_key_version")))
    }))
}

// ─── Reusable OAuth client registrations (Phase D Task 3, #32; design D6) ────
//
// A shared client identity keyed on (issuer, redirect_uri): the first OAuth
// connection to an authorization server registers (or resolves CIMD) once and
// every later connection to the same issuer reuses the row instead of minting
// its own per-connection DCR client. Pre-registered (operator-pasted) identities
// stay per-connection custody and get NO row.
//
// PLACEMENT (reviewer note): these are principal-less GLOBAL reads, but they are
// deliberately NOT in `system_worker` — that module is for cross-tenant scans of
// TENANT-owned data. Client registrations are deployment INFRASTRUCTURE (like
// `connector_catalog`'s global rows). v1 only ever WRITES `tenant_id NULL`; both
// lookups (`find_client_registration`, `find_client_registration_by_id`) FILTER
// `tenant_id is null`; `touch`/`delete` act on an already-resolved id. There is no
// tenant to scope by, so they live here beside the connection custody they serve,
// unscoped by construction. The nullable `tenant_id` + per-tenant partial unique
// are forward-compat only (migration 0015).

/// A shared OAuth client registration. Carries its sealed secret because every
/// read IS a credential resolution (unseal for token-endpoint auth) — the row is
/// internal deployment infrastructure and NEVER crosses an API boundary, so
/// unlike `IntegrationConnectionRow` it does not hide the sealed bytea behind a
/// dedicated reader (and is deliberately NOT `Serialize`).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OauthClientRegistrationRow {
    pub id: Uuid,
    /// NULL = deployment-global (v1 always). Present only for a future per-tenant
    /// client identity.
    pub tenant_id: Option<Uuid>,
    pub issuer: String,
    pub redirect_uri: String,
    pub source: String, // dcr | cimd | preregistered
    pub client_id: String,
    pub client_secret_sealed: Option<Vec<u8>>,
    pub client_secret_key_version: i16,
    pub registration_endpoint: Option<String>,
    pub registration_access_token_sealed: Option<Vec<u8>>,
    pub registration_access_token_key_version: i16,
    pub token_endpoint_auth_method: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Values for a new registration row. Sealed bytes are pre-sealed by the caller
/// (server owns the crypto); the companion key-versions ride beside them.
pub struct NewOauthClientRegistration<'a> {
    /// v1 always passes `None` (global). Present only for a future per-tenant row.
    pub tenant_id: Option<Uuid>,
    pub issuer: &'a str,
    pub redirect_uri: &'a str,
    pub source: &'a str, // dcr | cimd | preregistered
    pub client_id: &'a str,
    pub client_secret_sealed: Option<&'a [u8]>,
    pub client_secret_key_version: i16,
    pub registration_endpoint: Option<&'a str>,
    pub registration_access_token_sealed: Option<&'a [u8]>,
    pub registration_access_token_key_version: i16,
    pub token_endpoint_auth_method: Option<&'a str>,
}

/// Find the shared registration for an (issuer, redirect_uri). Global rows only
/// in v1 (`tenant_id is null`). Executor-generic so the DCR resolution can run it
/// THROUGH the advisory-lock-holding transaction (`&mut *tx`).
pub async fn find_client_registration<'e, E>(
    exec: E,
    issuer: &str,
    redirect_uri: &str,
) -> sqlx::Result<Option<OauthClientRegistrationRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "select * from oauth_client_registrations
         where tenant_id is null and issuer = $1 and redirect_uri = $2",
    )
    .bind(issuer)
    .bind(redirect_uri)
    .fetch_optional(exec)
    .await
}

/// Load one GLOBAL registration by id — the exchange/refresh path resolves the
/// identity the connection's `oauth.registration_id` points at. `and tenant_id is
/// null` is a v1 belt: a connection only ever stores a GLOBAL registration id, so
/// a non-global id fails closed to None rather than crossing into a future
/// per-tenant row.
pub async fn find_client_registration_by_id<'e, E>(
    exec: E,
    id: Uuid,
) -> sqlx::Result<Option<OauthClientRegistrationRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as("select * from oauth_client_registrations where id = $1 and tenant_id is null")
        .bind(id)
        .fetch_optional(exec)
        .await
}

/// Insert a shared registration. `ON CONFLICT DO NOTHING` returns `None` when a
/// concurrent connect already registered this (issuer, redirect_uri) — the caller
/// re-selects the winner (and abandons its own AS-side minted client). Global rows
/// only in v1 (`tenant_id NULL`); the partial unique enforces one per key.
pub async fn insert_client_registration<'e, E>(
    exec: E,
    new: NewOauthClientRegistration<'_>,
) -> sqlx::Result<Option<OauthClientRegistrationRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "insert into oauth_client_registrations
           (id, tenant_id, issuer, redirect_uri, source, client_id,
            client_secret_sealed, client_secret_key_version,
            registration_endpoint,
            registration_access_token_sealed, registration_access_token_key_version,
            token_endpoint_auth_method, last_used_at)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now())
         on conflict do nothing
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(new.tenant_id)
    .bind(new.issuer)
    .bind(new.redirect_uri)
    .bind(new.source)
    .bind(new.client_id)
    .bind(new.client_secret_sealed)
    .bind(new.client_secret_key_version)
    .bind(new.registration_endpoint)
    .bind(new.registration_access_token_sealed)
    .bind(new.registration_access_token_key_version)
    .bind(new.token_endpoint_auth_method)
    .fetch_optional(exec)
    .await
}

/// Mark a registration reused this dance (`last_used_at`).
pub async fn touch_client_registration<'e, E>(exec: E, id: Uuid) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("update oauth_client_registrations set last_used_at = now() where id = $1")
        .bind(id)
        .execute(exec)
        .await
        .map(|_| ())
}

/// Delete a registration whose client the AS rejected (`invalid_client` self-heal
/// at code exchange) so the next resolution mints a fresh one.
pub async fn delete_client_registration<'e, E>(exec: E, id: Uuid) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("delete from oauth_client_registrations where id = $1")
        .bind(id)
        .execute(exec)
        .await
        .map(|_| ())
}

/// Stable 64-bit advisory-lock key for a registration's (issuer, redirect_uri) —
/// mirrors [`oauth_lock_key`]'s fold-leading-8-bytes construction, over a sha256
/// of `issuer‖NUL‖redirect_uri` (the NUL separator keeps `a‖bc` ≠ `ab‖c`).
pub fn registration_lock_key(issuer: &str, redirect_uri: &str) -> i64 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(issuer.as_bytes());
    h.update([0u8]);
    h.update(redirect_uri.as_bytes());
    let d = h.finalize();
    i64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// Take a transaction-scoped advisory lock on (issuer, redirect_uri) — serializes
/// DCR across connects (and replicas) so the first connect registers and later
/// ones reuse, yielding ONE `/register` per issuer. Releases when `tx` commits or
/// drops; the caller holds it across the find → DCR HTTP → insert window.
pub async fn acquire_registration_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    issuer: &str,
    redirect_uri: &str,
) -> sqlx::Result<()> {
    sqlx::query("select pg_advisory_xact_lock($1)")
        .bind(registration_lock_key(issuer, redirect_uri))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

// ─── Connector OAuth flows (Phase D Task 4, #32 — invariant 20) ─────────────
//
// One-time server-side OAuth state rows, browser-bound like login_flows /
// github_app_flows. Replaces the stateless AEAD `state` param. The claim/peek
// fns are PRE-AUTH — keyed by `state_hash` (the opaque random the AS echoes back
// as `state`), which is the row's OWN authenticator (the row IS the auth, like a
// webhook signature). They take no `TenantScope`: the callback has no principal
// (a browser redirect can't carry the API token), and the verified tenant rides
// out ON the returned row. This mirrors how `claim_login_flow` (identity.rs)
// takes a raw id rather than a scope, for the same bootstrap reason.

/// A one-time connector-OAuth-flow row. NOT `Serialize` — it carries sealed key
/// material (`pkce_verifier_sealed`) and one-time secrets' hashes; nothing here
/// ever reaches an API response.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConnectorOauthFlowRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub connection_id: Uuid,
    pub initiated_by_user_id: Option<Uuid>,
    pub state_hash: String,
    pub browser_hash: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub metadata_digest: String,
    pub resource: String,
    pub redirect_uri: String,
    pub scopes: Value,
    pub challenge: String,
    pub challenge_method: String,
    pub client_registration_id: Option<Uuid>,
    pub client_id: String,
    pub pkce_verifier_sealed: Vec<u8>,
    pub pkce_verifier_key_version: i16,
    pub expected_generation: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

/// Values for a new flow row. The PKCE verifier is pre-sealed by the caller
/// (server owns the crypto); `ttl_secs` sets `expires_at = now() + ttl` DB-side so
/// the returned row's exact expiry seeds the boot token.
pub struct NewConnectorOauthFlow<'a> {
    pub connection_id: Uuid,
    pub initiated_by_user_id: Option<Uuid>,
    pub state_hash: &'a str,
    pub browser_hash: &'a str,
    pub issuer: &'a str,
    pub authorization_endpoint: &'a str,
    pub token_endpoint: &'a str,
    pub metadata_digest: &'a str,
    pub resource: &'a str,
    pub redirect_uri: &'a str,
    pub scopes: &'a Value,
    pub challenge: &'a str,
    pub challenge_method: &'a str,
    pub client_registration_id: Option<Uuid>,
    pub client_id: &'a str,
    pub pkce_verifier_sealed: &'a [u8],
    pub pkce_verifier_key_version: i16,
    pub expected_generation: i32,
    pub ttl_secs: i64,
}

/// Insert a one-time flow, returning the persisted row (its `id` + `expires_at`
/// seed the boot token). GC-on-insert (login_flows precedent) sweeps this tenant's
/// abandoned flows first — scoped to the inserting tenant so a per-request write
/// never touches another org's rows. Takes a `TenantScope` (the start principal's
/// verified tenant) which is stamped into `tenant_id` for the composite FK and a
/// future RLS `WITH CHECK`.
pub async fn insert_connector_oauth_flow(
    pool: &PgPool,
    scope: TenantScope,
    new: NewConnectorOauthFlow<'_>,
) -> sqlx::Result<ConnectorOauthFlowRow> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "delete from connector_oauth_flows
         where tenant_id = $1
           and ((consumed_at is null and expires_at < now())
                or expires_at < now() - interval '7 days')",
    )
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    let __rls_out = sqlx::query_as(
        "insert into connector_oauth_flows
           (id, tenant_id, connection_id, initiated_by_user_id, state_hash, browser_hash,
            issuer, authorization_endpoint, token_endpoint, metadata_digest, resource,
            redirect_uri, scopes, challenge, challenge_method, client_registration_id,
            client_id, pkce_verifier_sealed, pkce_verifier_key_version, expected_generation,
            expires_at)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
                 now() + make_interval(secs => $21::double precision))
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(new.connection_id)
    .bind(new.initiated_by_user_id)
    .bind(new.state_hash)
    .bind(new.browser_hash)
    .bind(new.issuer)
    .bind(new.authorization_endpoint)
    .bind(new.token_endpoint)
    .bind(new.metadata_digest)
    .bind(new.resource)
    .bind(new.redirect_uri)
    .bind(new.scopes)
    .bind(new.challenge)
    .bind(new.challenge_method)
    .bind(new.client_registration_id)
    .bind(new.client_id)
    .bind(new.pkce_verifier_sealed)
    .bind(new.pkce_verifier_key_version)
    .bind(new.expected_generation)
    .bind(new.ttl_secs as f64)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The one-time connector-OAuth-flow claim (invariant 20). Keyed by `state_hash`
/// (pre-auth — see the module note above). The cookie `browser_hash` sits INSIDE
/// the single-use predicate alongside `consumed_at is null` and `expires_at >
/// now()`: a leaked authorization URL WITHOUT the initiating browser's cookie
/// matches ZERO rows, so it can neither complete NOR burn the flow (design
/// :646-656). Returns the burned row on success.
pub async fn claim_connector_oauth_flow(
    pool: &PgPool,
    state_hash: &str,
    browser_hash: &str,
) -> sqlx::Result<Option<ConnectorOauthFlowRow>> {
    // Pre-auth credential-digest resolution (audited bypass): the go/callback legs
    // are UNAUTHENTICATED — the sealed `state` IS the auth — and this UPDATE is
    // keyed on the state/browser digests with NO principal until it resolves the
    // flow's tenant. It rides `worker_tx` for the same reason the lib.rs
    // token-digest resolvers do (the credential IS the key). No caller supplies a
    // scope; changing the executor-generic parameter to `pool` is compatible
    // (every call site passed a bare `&PgPool`).
    let mut tx = worker_tx(pool).await?;
    let __rls_out = sqlx::query_as(
        "update connector_oauth_flows set consumed_at = now()
         where state_hash = $1 and browser_hash = $2
           and consumed_at is null and expires_at > now()
         returning *",
    )
    .bind(state_hash)
    .bind(browser_hash)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Read a flow by `state_hash` WITHOUT mutating it (never consumes). Two callers:
/// (1) the go page checks liveness before it sets the cookie + redirects, and
/// (2) the callback, ONLY after a failed claim, splits "wrong browser" (row still
/// live but the cookie hash mismatched → 403, row UNBURNED) from
/// "unknown/expired/consumed" (→ 400 generic). Pre-auth, keyed by `state_hash`.
pub async fn peek_connector_oauth_flow(
    pool: &PgPool,
    state_hash: &str,
) -> sqlx::Result<Option<ConnectorOauthFlowRow>> {
    // Pre-auth credential-digest resolution (audited bypass), keyed by `state_hash`
    // with no principal — see `claim_connector_oauth_flow`. Never mutates.
    let mut tx = worker_tx(pool).await?;
    let __rls_out = sqlx::query_as("select * from connector_oauth_flows where state_hash = $1")
        .bind(state_hash)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

// ─── Per-tenant DEKs (Phase D envelope sealing, #32) ────────────────────────

/// One wrapped Data Encryption Key per `(tenant, version)`. `wrapped_dek` is the
/// DEK sealed by a KEK backend — NEVER the raw key. Not `Serialize`: it carries
/// wrapped key material. Keyed by a raw `tenant_id` (not a `TenantScope`): the
/// DEK orchestration in `kms::dek_for_seal`/`dek_for_open` already holds a
/// verified tenant from a `SealCtx`, and these are single-row keyed reads, not
/// cross-tenant scans.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantDekRow {
    pub tenant_id: Uuid,
    pub version: i32,
    pub kek_id: String,
    pub wrapped_dek: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

/// Read one tenant's DEK at a specific version (`None` if never minted).
pub async fn get_tenant_dek<'e, E>(
    exec: E,
    tenant_id: Uuid,
    version: i32,
) -> sqlx::Result<Option<TenantDekRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "select tenant_id, version, kek_id, wrapped_dek, created_at, retired_at
         from tenant_deks where tenant_id = $1 and version = $2",
    )
    .bind(tenant_id)
    .bind(version)
    .fetch_optional(exec)
    .await
}

/// The highest-version DEK for a tenant (a future rotation reads the current one).
pub async fn latest_tenant_dek<'e, E>(
    exec: E,
    tenant_id: Uuid,
) -> sqlx::Result<Option<TenantDekRow>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "select tenant_id, version, kek_id, wrapped_dek, created_at, retired_at
         from tenant_deks where tenant_id = $1 order by version desc limit 1",
    )
    .bind(tenant_id)
    .fetch_optional(exec)
    .await
}

/// Claim a `(tenant, version)` DEK row. `on conflict do nothing` makes the lazy
/// mint race-safe: two concurrent first-seals both attempt the insert, one wins,
/// and both callers re-read the winner (see `kms::dek_for_seal`).
pub async fn insert_tenant_dek<'e, E>(
    exec: E,
    tenant_id: Uuid,
    version: i32,
    kek_id: &str,
    wrapped_dek: &[u8],
) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "insert into tenant_deks (tenant_id, version, kek_id, wrapped_dek)
         values ($1, $2, $3, $4) on conflict (tenant_id, version) do nothing",
    )
    .bind(tenant_id)
    .bind(version)
    .bind(kek_id)
    .bind(wrapped_dek)
    .execute(exec)
    .await
    .map(|_| ())
}

// ─── Connector catalog ────────────────────────────────────────────────────

// ─── Connection tool snapshots ────────────────────────────────────────────

/// One append-only photograph of a brokered connection's `tools/list` (design
/// :298-318): versioned per (tenant, connection), carrying the tools + digest a
/// run freezes. Never carries a credential — only tool metadata.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ConnectionToolSnapshotRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub connection_id: Uuid,
    pub snapshot_version: i32,
    pub authorization_generation: i32,
    pub protocol_version: String,
    pub tools_json: Value,
    pub tools_digest: String,
    pub discovered_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Append a new snapshot (version = max+1 within (tenant, connection), exactly
/// like a bundle version). Executor-generic so it can run inside a caller's
/// transaction. The `exists` guard proves the connection is in scope AND still
/// at `authorization_generation` — a cross-tenant connection_id OR one whose
/// generation moved since discovery began (a concurrent reconnect) yields
/// RowNotFound, so a snapshot never lands stamped at a generation the connection
/// has already left (design :294-296, :306). The composite FK is the backstop.
pub async fn insert_connection_tool_snapshot<'e, E>(
    exec: E,
    scope: TenantScope,
    connection_id: Uuid,
    authorization_generation: i32,
    protocol_version: &str,
    tools_json: &Value,
    tools_digest: &str,
) -> sqlx::Result<ConnectionToolSnapshotRow>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "insert into connection_tool_snapshots
           (id, tenant_id, connection_id, snapshot_version, authorization_generation,
            protocol_version, tools_json, tools_digest)
         select $1, $2, $3,
           coalesce((select max(s.snapshot_version) from connection_tool_snapshots s
                     where s.tenant_id = $2 and s.connection_id = $3), 0) + 1,
           $4, $5, $6, $7
         where exists (select 1 from integration_connections c
                       where c.id = $3 and c.tenant_id = $2
                         and c.authorization_generation = $4)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(connection_id)
    .bind(authorization_generation)
    .bind(protocol_version)
    .bind(tools_json)
    .bind(tools_digest)
    .fetch_one(exec)
    .await
}

/// The newest snapshot for a connection, or None if it has never been
/// photographed.
pub async fn latest_connection_tool_snapshot(
    pool: &PgPool,
    scope: TenantScope,
    connection_id: Uuid,
) -> sqlx::Result<Option<ConnectionToolSnapshotRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from connection_tool_snapshots
         where tenant_id = $1 and connection_id = $2
         order by snapshot_version desc limit 1",
    )
    .bind(scope.tenant_id())
    .bind(connection_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Every snapshot for a connection, newest first.
pub async fn list_connection_tool_snapshots(
    pool: &PgPool,
    scope: TenantScope,
    connection_id: Uuid,
) -> sqlx::Result<Vec<ConnectionToolSnapshotRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from connection_tool_snapshots
         where tenant_id = $1 and connection_id = $2
         order by snapshot_version desc",
    )
    .bind(scope.tenant_id())
    .bind(connection_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// One specific snapshot version for a connection (the pin a run froze).
pub async fn get_connection_tool_snapshot(
    pool: &PgPool,
    scope: TenantScope,
    connection_id: Uuid,
    version: i32,
) -> sqlx::Result<Option<ConnectionToolSnapshotRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from connection_tool_snapshots
         where tenant_id = $1 and connection_id = $2 and snapshot_version = $3",
    )
    .bind(scope.tenant_id())
    .bind(connection_id)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// One catalog entry — GLOBAL (tenant-less) reference data, a superset of
/// the MCP registry's server.json. UNTRUSTED everywhere it is consumed:
/// tool_hints are policy-default seeds for display, never enforcement.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ConnectorCatalogRow {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub icon: Option<String>,
    pub description: Option<String>,
    pub categories: Value,
    pub tier: String,
    pub url: Option<String>,
    pub transport: String,
    pub auth_mode: String,
    pub auth_hints: Value,
    pub scopes: Value,
    pub egress: Value,
    pub tool_hints: Value,
    pub sandbox_launch: Option<Value>,
    /// {source, source_ref?, upstream_id?, imported_at?}. Curated seed rows
    /// carry {"source":"fluidbox"} and are never overwritten by an import
    /// (plan D4/D6). Imported reference rows carry an import source
    /// ("mcp-registry" | "open-connector") + pinned snapshot/commit so a future
    /// re-import can diff by (source, upstream_id).
    pub provenance: Value,
    /// NULL = GLOBAL reference row (curated `fluidbox` seeds + registry
    /// imports, visible to every tenant); Some = a tenant-owned custom (BYO)
    /// entry, visible only to that tenant and shadowing a same-slug global row
    /// (design :262-266).
    pub tenant_id: Option<Uuid>,
    /// Soft-disable: an unattributable custom row (migration 0013 could not
    /// place it under a single tenant) is disabled, never inherited by every
    /// tenant. Disabled rows are excluded from `list_catalog`/`get_catalog_by_slug`.
    pub disabled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Active catalog visible to a tenant: global-active ∪ tenant-active, with a
/// tenant custom row SHADOWING a same-slug global row (design :262-266).
pub async fn list_catalog(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<ConnectorCatalogRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from connector_catalog c
         where c.disabled_at is null
           and (c.tenant_id = $1
                or (c.tenant_id is null
                    and not exists (select 1 from connector_catalog t
                                    where t.tenant_id = $1 and t.slug = c.slug
                                      and t.disabled_at is null)))
         order by case tier when 'verified' then 0 when 'community' then 1 else 2 end, name",
    )
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Resolve one slug for a tenant: the tenant's custom row first, else the
/// global row; disabled rows excluded (design :262-266).
pub async fn get_catalog_by_slug(
    pool: &PgPool,
    scope: TenantScope,
    slug: &str,
) -> sqlx::Result<Option<ConnectorCatalogRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from connector_catalog
         where slug = $1 and disabled_at is null and (tenant_id = $2 or tenant_id is null)
         order by (tenant_id is not null) desc
         limit 1",
    )
    .bind(slug)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// API-added entries are always tier `custom` — verified/community are
/// curation judgements the API cannot self-award — and land tenant-scoped.
/// Returns None (→ 409 at the server) when the slug collides with a GLOBAL row;
/// a same-tenant duplicate is refused by the `connector_catalog_slug_tenant`
/// unique index (surfaced as an Err).
#[allow(clippy::too_many_arguments)]
pub async fn create_catalog_entry(
    pool: &PgPool,
    scope: TenantScope,
    slug: &str,
    name: &str,
    icon: Option<&str>,
    description: Option<&str>,
    categories: &Value,
    url: Option<&str>,
    transport: &str,
    auth_mode: &str,
    auth_hints: &Value,
    scopes: &Value,
    egress: &Value,
    tool_hints: &Value,
    sandbox_launch: Option<&Value>,
) -> sqlx::Result<Option<ConnectorCatalogRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    // tier AND provenance are forced 'custom': verified/community are curation
    // judgements the API cannot self-award, and a 'custom' provenance keeps a
    // user's BYO entry distinguishable from both the fluidbox seed and an
    // import (the generated import upsert only ever refreshes rows whose
    // provenance.source is an import source — 'mcp-registry' or 'open-connector'
    // — so it can never clobber this custom row; see the importer). The
    // `not exists (global)` guard fails closed on a global-slug collision — a
    // tenant can never mask a curated slug with a divergent definition.
    let __rls_out = sqlx::query_as(
        "insert into connector_catalog
           (id, tenant_id, slug, name, icon, description, categories, tier, url, transport,
            auth_mode, auth_hints, scopes, egress, tool_hints, sandbox_launch,
            provenance)
         select $1,$2,$3,$4,$5,$6,$7,'custom',$8,$9,$10,$11,$12,$13,$14,$15,
                 '{\"source\":\"custom\"}'
         where not exists (select 1 from connector_catalog g
                           where g.slug = $3 and g.tenant_id is null)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(slug)
    .bind(name)
    .bind(icon)
    .bind(description)
    .bind(categories)
    .bind(url)
    .bind(transport)
    .bind(auth_mode)
    .bind(auth_hints)
    .bind(scopes)
    .bind(egress)
    .bind(tool_hints)
    .bind(sandbox_launch)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Delete a tenant's custom catalog entry by slug (tenant rows only — a global
/// row is never touched). Used to roll back a just-created custom (BYO) entry
/// when its one-shot connect fails — custom entries are untrusted reference
/// data with no dependents until a bundle references them, so a hard delete is
/// safe. Returns the number of rows removed.
pub async fn delete_catalog_entry(
    pool: &PgPool,
    scope: TenantScope,
    slug: &str,
) -> sqlx::Result<u64> {
    let mut tx = scoped_tx(pool, scope).await?;
    let r = sqlx::query("delete from connector_catalog where slug = $1 and tenant_id = $2")
        .bind(slug)
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(r.rows_affected())
}

/// The only reader of the sealed credential. Returns None unless the
/// connection exists AND is active — a revoked connection can never again
/// produce a credential.
pub async fn connection_credential_sealed<'e, E>(
    exec: E,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query(
        "select credential_sealed, credential_key_version from integration_connections
         where id = $1 and status = 'active' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(exec)
    .await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Vec<u8>>, _>("credential_sealed")
            .map(|b| (b, r.get::<i16, _>("credential_key_version")))
    }))
}

/// The only reader of the sealed webhook secret (verified on every ingress
/// request). Active connections only — a revoked connection stops receiving.
pub async fn connection_webhook_secret_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select webhook_secret_sealed, webhook_secret_key_version from integration_connections
         where id = $1 and status = 'active' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Vec<u8>>, _>("webhook_secret_sealed")
            .map(|b| (b, r.get::<i16, _>("webhook_secret_key_version")))
    }))
}

// ─── Per-tenant LiteLLM virtual keys (Phase D, #32) ───────────────────────

/// The outcome of an insert-or-adopt of a tenant's virtual key: the winning row's
/// sealed bytes + companion version, and whether OUR insert is the one that
/// persisted. A mint race (two concurrent first-uses) resolves here — one insert
/// wins, the loser reads `we_won = false` + the winner's sealed key to adopt.
pub struct TenantLlmKeyInsert {
    pub sealed: Vec<u8>,
    pub key_version: i16,
    pub we_won: bool,
}

/// A tenant's virtual-key row as the RECOVERY path needs it: the sealed bytes
/// EXACTLY as stored (the compare-and-swap expectation — sealing is
/// nondeterministic, so only the bytes we read can be compared), the companion
/// version, and `minted_at` = when this key was created or last rotated.
///
/// `minted_at` is the DURABLE recovery cooldown (Phase D review H3): it survives
/// restarts and is shared by every replica, so a LiteLLM outage that keeps
/// rejecting keys cannot drive re-provisioning in a loop.
pub struct TenantLlmKeyRow {
    pub sealed: Vec<u8>,
    pub key_version: i16,
    pub minted_at: DateTime<Utc>,
}

/// Read a tenant's virtual-key row (sealed bytes + version + `minted_at`).
/// `None` = not yet minted. Tenant-scoped by the PK.
pub async fn tenant_llm_key_row(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Option<TenantLlmKeyRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(Vec<u8>, i16, DateTime<Utc>)> = sqlx::query_as(
        "select litellm_key_sealed, litellm_key_key_version, coalesce(rotated_at, created_at)
           from tenant_llm_keys where tenant_id = $1",
    )
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.map(|(sealed, key_version, minted_at)| TenantLlmKeyRow {
        sealed,
        key_version,
        minted_at,
    }))
}

/// Compare-and-swap a tenant's virtual key: replace it ONLY while the stored
/// sealed bytes are still `expected_sealed` (Phase D review M4). The reactive
/// recovery path reads the row, proves the key LiteLLM rejected is the CURRENT
/// one, mints a replacement, and lands it here — between the read and the write
/// an operator rotation (or another replica's recovery) may have installed a new
/// key, and blindly overwriting it would leak a live key and discard a
/// successful rotation. `false` = someone else swapped first; the caller must
/// drop its fresh mint and adopt the current key instead. Tenant-scoped by the PK.
pub async fn rotate_tenant_llm_key_cas(
    pool: &PgPool,
    scope: TenantScope,
    expected_sealed: &[u8],
    sealed: &[u8],
    key_version: i16,
    key_alias: &str,
    litellm_token_id: Option<&str>,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let r = sqlx::query(
        "update tenant_llm_keys
            set litellm_key_sealed = $2, litellm_key_key_version = $3, key_alias = $4,
                litellm_token_id = $5, rotated_at = now()
          where tenant_id = $1 and litellm_key_sealed = $6",
    )
    .bind(scope.tenant_id())
    .bind(sealed)
    .bind(key_version)
    .bind(key_alias)
    .bind(litellm_token_id)
    .bind(expected_sealed)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(r.rows_affected() == 1)
}

/// Read a tenant's sealed virtual key + companion version. `None` = not yet
/// minted. Tenant-scoped: keyed on the scope's tenant (the table's PK).
pub async fn tenant_llm_key_sealed(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(Vec<u8>, i16)> = sqlx::query_as(
        "select litellm_key_sealed, litellm_key_key_version from tenant_llm_keys
         where tenant_id = $1",
    )
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// Insert a tenant's freshly minted+sealed virtual key, or adopt the winner of a
/// mint race. `ON CONFLICT (tenant_id) DO NOTHING RETURNING` tells us whether our
/// row persisted; on a conflict we re-read the winner's sealed key so the caller
/// can adopt it (and drop its own orphaned LiteLLM key). Tenant-scoped by the PK.
pub async fn insert_tenant_llm_key(
    pool: &PgPool,
    scope: TenantScope,
    sealed: &[u8],
    key_version: i16,
    key_alias: &str,
    litellm_token_id: Option<&str>,
) -> sqlx::Result<TenantLlmKeyInsert> {
    let tenant_id = scope.tenant_id();
    let mut tx = scoped_tx(pool, scope).await?;
    let inserted: Option<(Vec<u8>, i16)> = sqlx::query_as(
        "insert into tenant_llm_keys
           (tenant_id, litellm_key_sealed, litellm_key_key_version, key_alias, litellm_token_id)
         values ($1, $2, $3, $4, $5)
         on conflict (tenant_id) do nothing
         returning litellm_key_sealed, litellm_key_key_version",
    )
    .bind(tenant_id)
    .bind(sealed)
    .bind(key_version)
    .bind(key_alias)
    .bind(litellm_token_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((s, v)) = inserted {
        tx.commit().await?;
        return Ok(TenantLlmKeyInsert {
            sealed: s,
            key_version: v,
            we_won: true,
        });
    }
    // Conflict: another minter won. Re-read the winner's sealed key to adopt.
    let (s, v): (Vec<u8>, i16) = sqlx::query_as(
        "select litellm_key_sealed, litellm_key_key_version from tenant_llm_keys
         where tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(TenantLlmKeyInsert {
        sealed: s,
        key_version: v,
        we_won: false,
    })
}

/// Drop a tenant's sealed virtual key so the next `ensure_tenant_key` MINTS a
/// fresh one. Teardown / manual-invalidation only.
///
/// NOT the reactive-401 recovery path any more (review M4): "evict + delete the
/// tenant's row" is unconditional, so a stale rejection (a request that presented
/// a key an operator had already rotated away) deleted the CURRENT row — losing a
/// live key and superseding a successful rotation. Recovery now compare-and-swaps
/// on the exact sealed bytes it read (`rotate_tenant_llm_key_cas`), which also
/// keeps `coalesce(rotated_at, created_at)` as its durable cooldown stamp — a
/// delete would reset that and re-open the loop. Tenant-scoped by the PK.
pub async fn delete_tenant_llm_key(pool: &PgPool, scope: TenantScope) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query("delete from tenant_llm_keys where tenant_id = $1")
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Swap a tenant's sealed virtual key for a freshly minted one (rotation),
/// bumping `rotated_at`. Returns the OLD sealed bytes + version so the caller can
/// retire the old key at LiteLLM; `None` = the tenant had no prior key (this
/// created it). Reads-old-then-upserts under a row lock so a concurrent rotate
/// can't lose the old value it must delete. Tenant-scoped by the PK.
pub async fn rotate_tenant_llm_key(
    pool: &PgPool,
    scope: TenantScope,
    sealed: &[u8],
    key_version: i16,
    key_alias: &str,
    litellm_token_id: Option<&str>,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let tenant_id = scope.tenant_id();
    let mut tx = scoped_tx(pool, scope).await?;
    let old: Option<(Vec<u8>, i16)> = sqlx::query_as(
        "select litellm_key_sealed, litellm_key_key_version from tenant_llm_keys
         where tenant_id = $1 for update",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    sqlx::query(
        "insert into tenant_llm_keys
           (tenant_id, litellm_key_sealed, litellm_key_key_version, key_alias, litellm_token_id)
         values ($1, $2, $3, $4, $5)
         on conflict (tenant_id) do update set
           litellm_key_sealed = excluded.litellm_key_sealed,
           litellm_key_key_version = excluded.litellm_key_key_version,
           key_alias = excluded.key_alias,
           litellm_token_id = excluded.litellm_token_id,
           rotated_at = now()",
    )
    .bind(tenant_id)
    .bind(sealed)
    .bind(key_version)
    .bind(key_alias)
    .bind(litellm_token_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(old)
}

// ─── GitHub App registrations & flows (Phase 5.6) ─────────────────────────

/// The App identity created via GitHub's manifest flow. Secrets (pem,
/// webhook secret, client secret) are NEVER selected by row queries — the
/// explicit column list below cannot leak them; the dedicated active-only
/// readers are the only accessors.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct GithubAppRegistrationRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub status: String, // pending | active | revoked
    pub target_kind: String,
    pub target_org: Option<String>,
    pub app_id: Option<String>,
    pub slug: Option<String>,
    pub name: Option<String>,
    pub client_id: Option<String>,
    pub html_url: Option<String>,
    pub owner_login: Option<String>,
    /// False = degraded: GitHub returned no webhook secret at conversion —
    /// fetch/publish work, event ingress cannot authenticate.
    pub has_webhook_secret: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const GH_REG_COLS: &str = "id, tenant_id, status, target_kind, target_org, app_id, slug, \
     name, client_id, html_url, owner_login, \
     (webhook_secret_sealed is not null) as has_webhook_secret, created_at, updated_at";

pub async fn create_github_app_registration(
    pool: &PgPool,
    scope: TenantScope,
    target_kind: &str,
    target_org: Option<&str>,
) -> sqlx::Result<GithubAppRegistrationRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "insert into github_app_registrations (id, tenant_id, target_kind, target_org)
         values ($1, $2, $3, $4)
         returning {GH_REG_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(target_kind)
    .bind(target_org)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_github_app_registrations(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<GithubAppRegistrationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {GH_REG_COLS} from github_app_registrations
         where tenant_id = $1 order by created_at desc"
    )))
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_github_app_registration(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<GithubAppRegistrationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {GH_REG_COLS} from github_app_registrations where id = $1 and tenant_id = $2"
    )))
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The manifest conversion landing: exactly ONE conversion may complete a
/// registration (`where status = 'pending'`); a racing second conversion
/// affects zero rows and its result is discarded by the caller.
#[allow(clippy::too_many_arguments)]
pub async fn activate_github_app_registration(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    app_id: &str,
    slug: &str,
    name: &str,
    client_id: Option<&str>,
    html_url: &str,
    owner_login: Option<&str>,
    pem_sealed: &[u8],
    pem_key_version: i16,
    webhook_secret_sealed: Option<&[u8]>,
    webhook_secret_key_version: i16,
    client_secret_sealed: Option<&[u8]>,
    client_secret_key_version: i16,
) -> sqlx::Result<Option<GithubAppRegistrationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update github_app_registrations
         set app_id = $2, slug = $3, name = $4, client_id = $5, html_url = $6,
             owner_login = $7, pem_sealed = $8, webhook_secret_sealed = $9,
             client_secret_sealed = $10, pem_key_version = $12,
             webhook_secret_key_version = $13, client_secret_key_version = $14,
             status = 'active', updated_at = now()
         where id = $1 and status = 'pending' and tenant_id = $11
         returning {GH_REG_COLS}"
    )))
    .bind(id)
    .bind(app_id)
    .bind(slug)
    .bind(name)
    .bind(client_id)
    .bind(html_url)
    .bind(owner_login)
    .bind(pem_sealed)
    .bind(webhook_secret_sealed)
    .bind(client_secret_sealed)
    .bind(scope.tenant_id())
    .bind(pem_key_version)
    .bind(webhook_secret_key_version)
    .bind(client_secret_key_version)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Revoke a registration AND its child connections in one transaction;
/// returns the affected connection ids so the caller can evict cached
/// installation tokens. Registrations are revoked, never deleted (the FK is
/// RESTRICT on purpose).
pub async fn revoke_github_app_registration(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<Vec<Uuid>>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let reg = sqlx::query(
        "update github_app_registrations set status = 'revoked', updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    if reg.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    // Scope the child cascade to the registration's own tenant too — the
    // composite FK already makes a cross-tenant child impossible, but the
    // predicate keeps the statement self-scoped (never a bare-id UPDATE).
    let rows = sqlx::query(
        "update integration_connections set status = 'revoked', updated_at = now()
         where registration_id = $1 and status <> 'revoked' and tenant_id = $2
         returning id",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(rows.iter().map(|r| r.get::<Uuid, _>("id")).collect()))
}

/// Active-only reader for the App signing key (same discipline as
/// `connection_credential_sealed`): a revoked registration can never again
/// produce a JWT.
pub async fn github_app_registration_pem_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select pem_sealed, pem_key_version from github_app_registrations
         where id = $1 and status = 'active' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Vec<u8>>, _>("pem_sealed")
            .map(|b| (b, r.get::<i16, _>("pem_key_version")))
    }))
}

/// Active-only reader for the app-level webhook secret (verified on every
/// app-level ingress request).
pub async fn github_app_registration_webhook_secret_sealed(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Vec<u8>, i16)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select webhook_secret_sealed, webhook_secret_key_version from github_app_registrations
         where id = $1 and status = 'active' and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Vec<u8>>, _>("webhook_secret_sealed")
            .map(|b| (b, r.get::<i16, _>("webhook_secret_key_version")))
    }))
}

/// Mint a one-time flow. Opportunistically sweeps this tenant's expired
/// unconsumed flows immediately, and consumed ones after a 7-day audit
/// window, so abandoned dances never accumulate.
///
/// TENANT-SCOPED (review L6). Minting is the AUTHENTICATED half of the GitHub-App
/// dance — all three call sites already hold a verified tenant (two admin-token'd
/// start endpoints via `principal.scope()`, and the manifest callback via the
/// scope it derives from the registration row it just resolved) — so it has no
/// business on the cross-tenant bypass. Only the two CLAIMs
/// ([`claim_github_app_bootstrap`], [`claim_github_app_flow`]) are genuinely
/// pre-auth: those arrive from GitHub/the browser with no principal, and the
/// one-time flow id + browser-cookie hash ARE the auth.
///
/// The insert derives its `registration_id` from a row selected under the scope,
/// so a caller cannot mint a flow against another tenant's registration even if
/// RLS is inert (a superuser/BYPASSRLS pool role); returns [`sqlx::Error::RowNotFound`]
/// when the registration is absent from this tenant.
pub async fn create_github_app_flow(
    pool: &PgPool,
    scope: TenantScope,
    registration_id: Uuid,
    purpose: &str,
    ttl_secs: i64,
) -> sqlx::Result<Uuid> {
    let mut tx = scoped_tx(pool, scope).await?;
    // Self-scoped sweep: only flows under THIS tenant's registrations (the RLS
    // child policy composes the same predicate; the EXISTS keeps it true without it).
    sqlx::query(
        "delete from github_app_flows f
         where ((f.consumed_at is null and f.expires_at < now())
                or f.expires_at < now() - interval '7 days')
           and exists (select 1 from github_app_registrations r
                        where r.id = f.registration_id and r.tenant_id = $1)",
    )
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    let id = Uuid::now_v7();
    let inserted = sqlx::query(
        "insert into github_app_flows (id, registration_id, purpose, expires_at)
         select $1, r.id, $3, now() + make_interval(secs => $4::double precision)
           from github_app_registrations r
          where r.id = $2 and r.tenant_id = $5",
    )
    .bind(id)
    .bind(registration_id)
    .bind(purpose)
    .bind(ttl_secs as f64)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() != 1 {
        tx.rollback().await.ok();
        return Err(sqlx::Error::RowNotFound);
    }
    tx.commit().await?;
    Ok(id)
}

/// The go page's one-time claim: binds a fresh browser cookie hash to the
/// flow. Exactly one browser can ever be bound.
pub async fn claim_github_app_bootstrap(
    pool: &PgPool,
    flow_id: Uuid,
    purpose: &str,
    browser_hash: &str,
) -> sqlx::Result<Option<Uuid>> {
    // Pre-auth bootstrap claim (browser cookie is the auth) — audited bypass.
    let mut tx = worker_tx(pool).await?;
    let row = sqlx::query(
        "update github_app_flows
         set bootstrap_consumed_at = now(), browser_hash = $3
         where id = $1 and purpose = $2 and bootstrap_consumed_at is null
           and expires_at > now()
         returning registration_id",
    )
    .bind(flow_id)
    .bind(purpose)
    .bind(browser_hash)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.map(|r| r.get::<Uuid, _>("registration_id")))
}

/// The callback/setup one-time claim. The browser-cookie hash sits INSIDE
/// the predicate: an attacker holding a leaked state parameter but not the
/// initiating browser's cookie cannot complete OR burn the flow.
pub async fn claim_github_app_flow(
    pool: &PgPool,
    flow_id: Uuid,
    purpose: &str,
    registration_id: Uuid,
    browser_hash: &str,
) -> sqlx::Result<bool> {
    // Pre-auth one-time claim (browser cookie inside the predicate) — audited bypass.
    let mut tx = worker_tx(pool).await?;
    let r = sqlx::query(
        "update github_app_flows
         set consumed_at = now()
         where id = $1 and purpose = $2 and registration_id = $3
           and consumed_at is null and bootstrap_consumed_at is not null
           and browser_hash = $4 and expires_at > now()",
    )
    .bind(flow_id)
    .bind(purpose)
    .bind(registration_id)
    .bind(browser_hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(r.rows_affected() == 1)
}

/// Insert a seamless installation connection ONLY if the installation has
/// never had a row of ANY status — the check rides inside the statement, so
/// an insert can never land just after a concurrent revoke (F‑6: revoked
/// rows revive only via approve, never via a fresh import racing in).
/// Returns None when any row (live or revoked) already exists; the caller
/// loops back through its existing-row path.
#[allow(clippy::too_many_arguments)]
pub async fn create_github_app_connection_if_absent(
    pool: &PgPool,
    scope: TenantScope,
    installation_id: &str,
    display_name: &str,
    metadata: &Value,
    status: &str,
    registration_id: Uuid,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        // github_app connections are ALWAYS organization-owned (system custody
        // via the registration) — owner_type is stamped explicitly, never a
        // per-user personal connection.
        "insert into integration_connections
           (id, tenant_id, provider, external_account_id, display_name, credential_sealed,
            granted_scopes, resource_selection, metadata, webhook_secret_sealed,
            auth_kind, status, oauth, client_secret_sealed, registration_id, owner_type)
         select $1, $2, 'github_app', $3, $4, null, '[]'::jsonb, '{{}}'::jsonb, $5, null,
                'static', $6, null, null, $7, 'organization'
         where not exists (
             select 1 from integration_connections
             where tenant_id = $2 and provider = 'github_app' and external_account_id = $3
         )
         returning {CONNECTION_COLS}"
    )))
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(installation_id)
    .bind(display_name)
    .bind(metadata)
    .bind(status)
    .bind(registration_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The single live connection row for a GitHub installation, preferring a
/// live row but surfacing a revoked one (callers refuse or route revival
/// through the explicit approve path — never a second row).
pub async fn get_github_app_connection_by_installation(
    pool: &PgPool,
    scope: TenantScope,
    installation_id: &str,
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "select {CONNECTION_COLS} from integration_connections
         where tenant_id = $1 and provider = 'github_app' and external_account_id = $2
         order by (status <> 'revoked') desc, created_at desc
         limit 1"
    )))
    .bind(scope.tenant_id())
    .bind(installation_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Guarded status transition: only fires when the current status is one of
/// `allowed_from`. Returns the fresh row on success.
pub async fn set_connection_status(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    status: &str,
    allowed_from: &[&str],
) -> sqlx::Result<Option<IntegrationConnectionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let from: Vec<String> = allowed_from.iter().map(|s| s.to_string()).collect();
    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update integration_connections set status = $2, updated_at = now()
         where id = $1 and status = any($3) and tenant_id = $4
         returning {CONNECTION_COLS}"
    )))
    .bind(id)
    .bind(status)
    .bind(&from)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Refresh the display metadata a setup/sync re-verification produced.
pub async fn refresh_connection_metadata(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    display_name: &str,
    metadata: &Value,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;

    sqlx::query(
        "update integration_connections
         set display_name = $2, metadata = $3, updated_at = now()
         where id = $1 and status <> 'revoked' and tenant_id = $4",
    )
    .bind(id)
    .bind(display_name)
    .bind(metadata)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

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

const SUBSCRIPTION_COLS: &str = "id, tenant_id, agent_id, name, trigger_kind, pinned_revision_id, \
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
    .bind(scope.tenant_id())
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
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
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

    let __rls_out = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "update trigger_subscriptions set enabled = $2, updated_at = now()
         where id = $1 and tenant_id = $3 returning {SUBSCRIPTION_COLS}"
    )))
    .bind(id)
    .bind(enabled)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
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

// ─── Run resource bindings ────────────────────────────────────────────────

/// One per-run resolved authority (design :391-463): what a run bound for a
/// requirement slot, frozen write-once. The tagged authority union is realized
/// as typed `connection_id`/`subscription_id` columns discriminated by
/// `authority_kind`; the CHECK constraints (migration 0013) enforce the shape.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct RunResourceBindingRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub requirement_slot: String,
    pub slot_kind: String,
    pub authority_kind: String,
    pub connection_id: Option<Uuid>,
    pub subscription_id: Option<Uuid>,
    pub authority_generation: Option<i32>,
    pub connection_owner_type: Option<String>,
    pub connection_owner_user_id: Option<Uuid>,
    pub snapshot_version: Option<i32>,
    pub effective_tools_json: Option<Value>,
    pub effective_tools_digest: Option<String>,
    pub resource_scope: Value,
    pub resolved_by_principal_kind: String,
    pub resolved_by_principal_id: Option<String>,
    pub binding_mode: String,
    pub created_at: DateTime<Utc>,
}

/// A binding to insert — [`RunResourceBindingRow`] minus the columns the writer
/// stamps (tenant_id from the scope, session_id from the run, created_at). The
/// `id` is pre-minted by the resolver so the frozen RunSpec can reference it.
#[derive(Debug, Clone)]
pub struct NewRunResourceBinding {
    pub id: Uuid,
    pub requirement_slot: String,
    pub slot_kind: String,
    pub authority_kind: String,
    pub connection_id: Option<Uuid>,
    pub subscription_id: Option<Uuid>,
    pub authority_generation: Option<i32>,
    pub connection_owner_type: Option<String>,
    pub connection_owner_user_id: Option<Uuid>,
    pub snapshot_version: Option<i32>,
    pub effective_tools_json: Option<Value>,
    pub effective_tools_digest: Option<String>,
    pub resource_scope: Value,
    pub resolved_by_principal_kind: String,
    pub resolved_by_principal_id: Option<String>,
    pub binding_mode: String,
}

/// Write a run's resolved bindings (plain multi-insert; write-once — the
/// `unique (tenant_id, session_id, slot_kind, requirement_slot)` key rejects a
/// second write for the same slot). Takes a `&mut PgConnection` so it runs
/// inside `create_session`'s transaction. The composite `(tenant_id, session_id)`
/// FK refuses a binding for a missing / other-tenant session.
pub async fn insert_run_resource_bindings(
    tx: &mut sqlx::PgConnection,
    scope: TenantScope,
    session_id: Uuid,
    rows: &[NewRunResourceBinding],
) -> sqlx::Result<()> {
    for b in rows {
        sqlx::query(
            "insert into run_resource_bindings
               (id, tenant_id, session_id, requirement_slot, slot_kind, authority_kind,
                connection_id, subscription_id, authority_generation, connection_owner_type,
                connection_owner_user_id, snapshot_version, effective_tools_json,
                effective_tools_digest, resource_scope, resolved_by_principal_kind,
                resolved_by_principal_id, binding_mode)
             values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
        )
        .bind(b.id)
        .bind(scope.tenant_id())
        .bind(session_id)
        .bind(&b.requirement_slot)
        .bind(&b.slot_kind)
        .bind(&b.authority_kind)
        .bind(b.connection_id)
        .bind(b.subscription_id)
        .bind(b.authority_generation)
        .bind(&b.connection_owner_type)
        .bind(b.connection_owner_user_id)
        .bind(b.snapshot_version)
        .bind(&b.effective_tools_json)
        .bind(&b.effective_tools_digest)
        .bind(&b.resource_scope)
        .bind(&b.resolved_by_principal_kind)
        .bind(&b.resolved_by_principal_id)
        .bind(&b.binding_mode)
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

/// One binding by id, tenant-scoped.
pub async fn get_run_resource_binding(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<RunResourceBindingRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out =
        sqlx::query_as("select * from run_resource_bindings where id = $1 and tenant_id = $2")
            .bind(id)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Every binding a run resolved, ordered by slot for stable display.
pub async fn session_resource_bindings(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
) -> sqlx::Result<Vec<RunResourceBindingRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from run_resource_bindings
         where session_id = $1 and tenant_id = $2
         order by slot_kind, requirement_slot",
    )
    .bind(session_id)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The one binding for a run's (slot_kind, requirement_slot) — the consumer's
/// lookup before a credentialed use.
pub async fn find_session_binding(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
    slot_kind: &str,
    slot: &str,
) -> sqlx::Result<Option<RunResourceBindingRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from run_resource_bindings
         where session_id = $1 and tenant_id = $2 and slot_kind = $3 and requirement_slot = $4",
    )
    .bind(session_id)
    .bind(scope.tenant_id())
    .bind(slot_kind)
    .bind(slot)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

// ─── Sessions ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn create_session(
    pool: &PgPool,
    scope: TenantScope,
    agent_id: Uuid,
    agent_revision_id: Uuid,
    autonomy: &str,
    trust_tier: &str,
    task: &str,
    repo_source: &Value,
    run_spec: &Value,
    budgets: &Value,
    trigger: Option<&Value>,
    invoked_by_kind: Option<&str>,
    invoked_by_user_id: Option<Uuid>,
    bind_invocation: Option<Uuid>,
    bind_dispatch: Option<Uuid>,
    bindings: &[NewRunResourceBinding],
) -> sqlx::Result<SessionRow> {
    let mut tx = scoped_tx(pool, scope).await?;
    // Prove the agent AND the pinned revision both belong to this tenant in SQL
    // (the run builder resolves them under scope first; this is the relational
    // backstop). A miss yields zero rows → fetch_one RowNotFound, surfaced via
    // `?` like any other create failure.
    let row: SessionRow = sqlx::query_as(
        "insert into sessions
           (id, tenant_id, agent_id, agent_revision_id, autonomy, trust_tier, task, repo_source, run_spec, budgets, trigger, invoked_by_kind, invoked_by_user_id)
         select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
         where exists (select 1 from agents a where a.id = $3 and a.tenant_id = $2)
           and exists (select 1 from agent_revisions r where r.id = $4 and r.agent_id = $3)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(agent_id)
    .bind(agent_revision_id)
    .bind(autonomy)
    .bind(trust_tier)
    .bind(task)
    .bind(repo_source)
    .bind(run_spec)
    .bind(budgets)
    .bind(trigger)
    .bind(invoked_by_kind)
    .bind(invoked_by_user_id)
    .fetch_one(&mut *tx)
    .await?;
    // Resolved run resource bindings are written INSIDE this transaction — a run
    // and the frozen record of what it resolved commit together, or not at all
    // (design :391-463; invariant 21). The composite FK refuses a binding whose
    // (tenant, session) does not match this session's.
    if !bindings.is_empty() {
        insert_run_resource_bindings(&mut tx, scope, row.id, bindings).await?;
    }
    // Atomic claim bind: the run and its idempotency claim commit together,
    // so a crash can never orphan a created run from its claim (which would
    // let the stale-claim takeover duplicate it).
    if let Some(invocation) = bind_invocation {
        // EXISTS-scoped through the owning subscription so the claim can only
        // bind an invocation in this session's tenant (matches the predicate
        // style in `mark_invocation_skipped`).
        sqlx::query(
            "update trigger_invocations set session_id = $2
             where id = $1
               and exists (select 1 from trigger_subscriptions sub
                           where sub.id = trigger_invocations.subscription_id
                             and sub.tenant_id = $3)",
        )
        .bind(invocation)
        .bind(row.id)
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    }
    // Same discipline for the event fan-out claim (level-2 dedup): the
    // dispatch row and the session commit together.
    if let Some(dispatch) = bind_dispatch {
        // EXISTS-scoped through the owning delivery → connection so the claim
        // can only bind a dispatch in this session's tenant (matches the
        // predicate style in `list_delivery_dispatches`).
        sqlx::query(
            "update trigger_dispatches set session_id = $2
             where id = $1
               and exists (select 1 from trigger_deliveries d
                           join integration_connections c on c.id = d.connection_id
                           where d.id = trigger_dispatches.delivery_id
                             and c.tenant_id = $3)",
        )
        .bind(dispatch)
        .bind(row.id)
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(row)
}

pub async fn get_session(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<SessionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from sessions where id = $1 and tenant_id = $2")
        .bind(id)
        .bind(scope.tenant_id())
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// List a tenant's sessions, newest first. `invoked_by` narrows to a single
/// user's runs (the run-visibility rule for a plain member); `None` returns
/// every session in the tenant (operator / `runs.read_all` holders).
pub async fn list_sessions(
    pool: &PgPool,
    scope: TenantScope,
    invoked_by: Option<Uuid>,
    limit: i64,
) -> sqlx::Result<Vec<SessionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from sessions
         where tenant_id = $1 and ($2::uuid is null or invoked_by_user_id = $2)
         order by created_at desc limit $3",
    )
    .bind(scope.tenant_id())
    .bind(invoked_by)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The single status writer. Validates the transition inside a transaction;
/// returns Ok(None) if the transition is not legal (caller decides whether
/// that is an error or a benign race).
pub async fn transition_session(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    next: SessionStatus,
    reason: Option<&str>,
) -> sqlx::Result<Option<(SessionStatus, SessionRow)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(String,)> =
        sqlx::query_as("select status from sessions where id = $1 and tenant_id = $2 for update")
            .bind(id)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?;
    let Some((current,)) = row else {
        return Ok(None);
    };
    let current = SessionStatus::parse(&current).unwrap_or(SessionStatus::Failed);
    if !current.can_transition_to(next) {
        tx.rollback().await.ok();
        return Ok(None);
    }
    let updated: SessionRow = sqlx::query_as(
        "update sessions set
            status = $2,
            status_reason = $3,
            updated_at = now(),
            started_at = case when $2 = 'running'
                              then coalesce(started_at, now()) else started_at end,
            finished_at = case when $2 in ('completed','failed','cancelled','budget_exceeded')
                               then now() else finished_at end
         where id = $1 and tenant_id = $4 returning *",
    )
    .bind(id)
    .bind(next.as_str())
    .bind(reason)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some((current, updated)))
}

/// The epoch-fenced sibling of [`transition_session`] (Phase E, #33; Gap 13).
/// Identical semantics plus ONE extra condition: the session's
/// `orchestrator_epoch` must still equal the epoch the caller acquired with its
/// lease. A driver that was paused, partitioned, or simply slow — and whose lease
/// another replica then stole — carries a STALE epoch, so its lifecycle mutation
/// matches zero rows and returns `Ok(None)` instead of overwriting the new
/// owner's work. The epoch is checked UNDER the same `for update` row lock the
/// status guard uses, so the fence and the state-machine check see one snapshot.
///
/// Deliberately a separate entry point rather than an `Option<i64>` parameter on
/// `transition_session`: request-side intent writes (cancel, `finalize_forced`,
/// `maybe_resume`) are NOT driver mutations and must stay unfenced — they are
/// idempotent CAS inserts whose whole job is to be accepted from any replica.
pub async fn transition_session_fenced(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    next: SessionStatus,
    reason: Option<&str>,
    expected_epoch: i64,
) -> sqlx::Result<Option<(SessionStatus, SessionRow)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(String, i64)> = sqlx::query_as(
        "select status, orchestrator_epoch from sessions
         where id = $1 and tenant_id = $2 for update",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((current, epoch)) = row else {
        return Ok(None);
    };
    if epoch != expected_epoch {
        tx.rollback().await.ok();
        return Ok(None);
    }
    let current = SessionStatus::parse(&current).unwrap_or(SessionStatus::Failed);
    if !current.can_transition_to(next) {
        tx.rollback().await.ok();
        return Ok(None);
    }
    let updated: SessionRow = sqlx::query_as(
        "update sessions set
            status = $2,
            status_reason = $3,
            updated_at = now(),
            started_at = case when $2 = 'running'
                              then coalesce(started_at, now()) else started_at end,
            finished_at = case when $2 in ('completed','failed','cancelled','budget_exceeded')
                               then now() else finished_at end
         where id = $1 and tenant_id = $4 and orchestrator_epoch = $5 returning *",
    )
    .bind(id)
    .bind(next.as_str())
    .bind(reason)
    .bind(scope.tenant_id())
    .bind(expected_epoch)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some((current, updated)))
}

/// Acquire, STEAL, or renew this replica's driver lease on one session, and
/// return the fencing epoch to carry (Phase E, #33; Gap 13; design :1067-1078).
///
/// Predicate — take it iff the lease is free, expired, or already mine:
/// `owner is null OR lease_until < now() OR owner = $me`. `None` means another
/// replica holds an UNEXPIRED lease: this driver must not mutate the session.
///
/// **The epoch increments ONLY on an owner CHANGE.** A renew by the same owner
/// keeps it, so a healthy driver's fence never moves under its own feet.
/// Re-taking a lease of OURS that merely lapsed (nobody stole it) also keeps the
/// epoch — the bump is gated on the owner actually changing. A takeover by a
/// DIFFERENT replica bumps it, which instantly invalidates every mutation the
/// previous holder had in flight. That asymmetry is what makes the epoch a
/// fencing TOKEN rather than a counter.
///
/// Time-based takeover, exactly like `claim_finalization` — NEVER a Postgres
/// advisory lock. The design rejects advisory locks here (`:1067-1072`): they are
/// tied to one connection, fragile under pool reconnects and Neon scale-to-zero,
/// and poorly observable. A lease column survives all three and is queryable.
/// Beneath this replica-scope fence the Kubernetes provider's UID-preconditioned
/// delete stays as the PROVIDER-scope fence.
pub async fn acquire_session_lease(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    owner: Uuid,
    ttl_secs: i64,
) -> sqlx::Result<Option<i64>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(i64,)> = sqlx::query_as(
        "update sessions set
            orchestrator_owner_id = $3,
            orchestrator_lease_until = now() + make_interval(secs => $4),
            orchestrator_epoch = case
                when orchestrator_owner_id is distinct from $3
                then orchestrator_epoch + 1 else orchestrator_epoch end,
            updated_at = now()
         where id = $1 and tenant_id = $2
           and (orchestrator_owner_id is null
                or orchestrator_lease_until is null
                or orchestrator_lease_until < now()
                or orchestrator_owner_id = $3)
         returning orchestrator_epoch",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .bind(owner)
    .bind(ttl_secs.max(1) as f64)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.map(|(e,)| e))
}

/// The session's current lease holder + fencing epoch — the read half of
/// [`acquire_session_lease`], used by tests and by side-effect guards that want to
/// confirm ownership without extending the lease.
pub async fn session_lease(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<(Option<Uuid>, Option<DateTime<Utc>>, i64)>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(Option<Uuid>, Option<DateTime<Utc>>, i64)> = sqlx::query_as(
        "select orchestrator_owner_id, orchestrator_lease_until, orchestrator_epoch
         from sessions where id = $1 and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// Attach the sandbox handle — REFUSED (returns false) unless the session is
/// still in an ACTIVE (pre-wind-down) state AND no finalization intent
/// exists: the intent is the single source of truth for ownership, and it
/// commits BEFORE the wind-down transition — a status-only fence would let a
/// launch attach a live sandbox inside that gap. The caller must terminate
/// the sandbox on refusal.
///
/// Deliberately a lock-then-check-then-update TRANSACTION, not one UPDATE:
/// a single statement's `not exists` subquery keeps the command snapshot
/// even after blocking on `begin_finalization`'s session row lock (Postgres
/// re-checks only the target tuple on unblock), so it could attach past a
/// just-committed intent. Taking the same row lock first and reading the
/// intent in a SECOND statement gets a fresh snapshot that must see it.
pub async fn set_sandbox_handle(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    handle: &Value,
) -> sqlx::Result<bool> {
    use fluidbox_core::state::SessionStatus;
    let mut tx = scoped_tx(pool, scope).await?;
    let locked: Option<(String,)> =
        sqlx::query_as("select status from sessions where id = $1 and tenant_id = $2 for update")
            .bind(id)
            .bind(scope.tenant_id())
            .fetch_optional(&mut *tx)
            .await?;
    let Some((status,)) = locked else {
        return Ok(false);
    };
    let active = SessionStatus::parse(&status).is_some_and(|s| s.accepts_work());
    if !active {
        return Ok(false);
    }
    // EXISTS-scoped through the owning session so the intent probe stays inside
    // this tenant (belt-and-braces: the row above is already locked and
    // tenant-checked; `session_finalizations` has no tenant column of its own).
    let (intent_exists,): (bool,) = sqlx::query_as(
        "select exists(
             select 1 from session_finalizations f
             where f.session_id = $1
               and exists (select 1 from sessions s
                           where s.id = f.session_id and s.tenant_id = $2))",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    if intent_exists {
        return Ok(false);
    }
    sqlx::query(
        "update sessions set sandbox_handle = $2, updated_at = now()
         where id = $1 and tenant_id = $3",
    )
    .bind(id)
    .bind(handle)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Adopt a DISCOVERED sandbox handle into a session atomically: only while no
/// handle is stored AND the session is still in an active (pre-wind-down)
/// status. The predicate is in the UPDATE itself, so the reconciler racing
/// `run()`'s own `set_sandbox_handle`, a concurrent cancel, or a terminal
/// transition can never overwrite a real handle or resurrect a closed
/// session. Returns whether the adoption landed.
pub async fn adopt_sandbox_handle(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    handle: &Value,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update sessions set sandbox_handle = $2, updated_at = now()
         where id = $1 and tenant_id = $3 and sandbox_handle is null
           and status in ('created','provisioning','initializing','running','awaiting_approval')",
    )
    .bind(id)
    .bind(handle)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

pub async fn set_base_commit(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    commit: &str,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update sessions set base_commit = $2, updated_at = now()
         where id = $1 and tenant_id = $3",
    )
    .bind(id)
    .bind(commit)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn set_result_summary(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    summary: &str,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update sessions set result_summary = $2, updated_at = now()
         where id = $1 and tenant_id = $3",
    )
    .bind(id)
    .bind(summary)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn heartbeat(pool: &PgPool, scope: TenantScope, id: Uuid) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update sessions set last_heartbeat_at = now(), updated_at = now()
         where id = $1 and tenant_id = $2",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

// ─── Durable finalization intent (K8s design 2026-07-15, migration 0011) ──

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FinalizationRow {
    pub session_id: Uuid,
    pub outcome: String,
    pub summary: Option<String>,
    pub reason: Option<String>,
    pub needs_quiesce: bool,
    pub quiesce_deadline: Option<DateTime<Utc>>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
}

/// The outcome of persisting a finalization intent.
#[derive(Debug)]
pub enum BeginFinalization {
    /// The intent is durably persisted (by this call or a previous one).
    /// `row` is the AUTHORITATIVE intent — a loser of the insert race
    /// receives the winner's row and must derive every wind-down decision
    /// (target state, quiesce, deadline) from it, never from its own
    /// arguments. `session_status` is the status observed under the lock.
    Persisted {
        row: FinalizationRow,
        created: bool,
        session_status: String,
    },
    /// The session is already terminal — no intent may be (re)created.
    AlreadyTerminal,
    /// The session does not exist.
    Missing,
}

/// Persist the intent to finalize a session (idempotent), in ONE transaction
/// that locks the session row: the terminal check, the quiesce computation,
/// and the insert all see the same snapshot, so a late caller can never
/// recreate an intent after terminalization, and `needs_quiesce`/deadline
/// always match the state they were derived from. Holding the session lock
/// also fences the conflict→select read: terminalization (and the intent
/// delete that follows it) updates the sessions row, so it cannot slip
/// between our conflict and our read of the winning row. The first writer
/// wins the outcome; a racing second caller receives the winner's row with
/// `created: false` and defers to it.
#[allow(clippy::too_many_arguments)]
pub async fn begin_finalization(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    outcome: &str,
    summary: Option<&str>,
    reason: Option<&str>,
    want_quiesce: bool,
    quiesce_deadline_secs: i64,
) -> sqlx::Result<BeginFinalization> {
    use fluidbox_core::state::SessionStatus;
    let mut tx = scoped_tx(pool, scope).await?;
    let locked: Option<(String, Option<Value>)> = sqlx::query_as(
        "select status, sandbox_handle from sessions where id = $1 and tenant_id = $2 for update",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((status, handle)) = locked else {
        return Ok(BeginFinalization::Missing);
    };
    if SessionStatus::parse(&status).is_some_and(|s| s.is_terminal()) {
        return Ok(BeginFinalization::AlreadyTerminal);
    }
    // Quiesce only makes sense while a runner is live to receive the
    // heartbeat signal — computed from the LOCKED snapshot, not the caller's
    // (possibly stale) read.
    let quiesce = want_quiesce
        && matches!(status.as_str(), "running" | "awaiting_approval")
        && handle.is_some();
    let deadline = quiesce.then(|| Utc::now() + chrono::Duration::seconds(quiesce_deadline_secs));
    let inserted: Option<FinalizationRow> = sqlx::query_as(
        "insert into session_finalizations
           (session_id, outcome, summary, reason, needs_quiesce, quiesce_deadline)
         values ($1,$2,$3,$4,$5,$6)
         on conflict (session_id) do nothing
         returning *",
    )
    .bind(session)
    .bind(outcome)
    .bind(summary)
    .bind(reason)
    .bind(quiesce)
    .bind(deadline)
    .fetch_optional(&mut *tx)
    .await?;
    let (row, created) = match inserted {
        Some(r) => (r, true),
        None => (
            sqlx::query_as("select * from session_finalizations where session_id = $1")
                .bind(session)
                .fetch_one(&mut *tx)
                .await?,
            false,
        ),
    };
    tx.commit().await?;
    Ok(BeginFinalization::Persisted {
        row,
        created,
        session_status: status,
    })
}

pub async fn get_finalization(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Option<FinalizationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from session_finalizations
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Claim a finalization for driving: succeeds when the row is unclaimed OR its
/// claim went stale (the previous driver crashed). Bumps `attempts` and stamps
/// `claimed_at`. A concurrent driver that loses the CAS gets None and backs
/// off — the finalizing→terminal transition is the ultimate single-winner
/// gate regardless, so a double-claim can never double-finalize.
pub async fn claim_finalization(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    stale_secs: i64,
) -> sqlx::Result<Option<FinalizationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "update session_finalizations
            set claimed_at = now(), attempts = attempts + 1
          where session_id = $1
            and (claimed_at is null or claimed_at < now() - make_interval(secs => $2))
            and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $3)
          returning *",
    )
    .bind(session)
    .bind(stale_secs as f64)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Release a driver's claim early — for DELIBERATE deferrals (e.g. the
/// provisioning settle window), so the finalize worker retries at its own
/// cadence instead of waiting out the stale-claim threshold.
pub async fn release_finalization_claim(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update session_finalizations set claimed_at = null
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_finalization(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "delete from session_finalizations
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

// ─── Cross-replica OAuth refresh serialization (K8s design 2026-07-15) ─────

/// Stable 64-bit advisory-lock key from a connection id. Postgres advisory
/// locks are keyed on `bigint`; we fold the uuid's leading 8 bytes.
pub fn oauth_lock_key(connection_id: Uuid) -> i64 {
    let b = connection_id.as_bytes();
    i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Take a transaction-scoped Postgres advisory lock keyed on a connection id,
/// on `tx`. Serializes OAuth refresh-token rotation ACROSS control-plane
/// replicas (a second replica can no longer double-rotate a refresh token
/// into `invalid_grant`) — replacing reliance on the in-process mutex. The
/// lock releases automatically when `tx` is committed or dropped, so the
/// caller holds `tx` across the refresh HTTP round-trip and the rotation
/// write, then commits.
pub async fn acquire_oauth_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    connection_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query("select pg_advisory_xact_lock($1)")
        .bind(oauth_lock_key(connection_id))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Idempotent artifact write: a crash-retry during finalization must not
/// accumulate duplicate diff rows. Replaces any existing (session, kind, name).
/// The stored diff artifact's content, if any — the finalizer's evidence
/// guard: a re-driven finalization must never overwrite a collected diff
/// with an `artifact_missing` marker (missing → collected upgrades are fine).
pub async fn diff_artifact_content(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Option<String>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(String,)> = sqlx::query_as(
        "select content from artifacts
         where session_id = $1 and kind = 'diff'
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)
         limit 1",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.map(|(c,)| c))
}

pub async fn upsert_artifact(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    kind: &str,
    name: &str,
    content: &str,
    content_type: &str,
) -> sqlx::Result<ArtifactRow> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "delete from artifacts
         where session_id = $1 and kind = $2 and name = $3
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $4)",
    )
    .bind(session)
    .bind(kind)
    .bind(name)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    let row: ArtifactRow = sqlx::query_as(
        "insert into artifacts (id, session_id, kind, name, content, content_type)
         select $1,$2,$3,$4,$5,$6
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $7)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(kind)
    .bind(name)
    .bind(content)
    .bind(content_type)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

// ─── Events (append-only; Redacted enforced at the type level) ────────────

pub async fn append_event(
    pool: &PgPool,
    scope: TenantScope,
    event: Redacted<EventEnvelope>,
) -> sqlx::Result<i64> {
    let mut tx = scoped_tx(pool, scope).await?;
    let seq = append_event_in_tx(&mut tx, scope, event).await?;
    tx.commit().await?;
    Ok(seq)
}

/// The LISTEN/NOTIFY channel a committed approval DECISION announces itself on
/// (Phase E, #33; Gap 13). Payload = the approval id, so every replica can wake
/// its own local waiters for that row. Deliberately separate from
/// `fluidbox_events` (payload `session:seq`): approvals key on the approval id,
/// and a listener that had to parse two payload shapes off one channel would be a
/// silent-misroute hazard. Like SSE, the NOTIFY is ONLY a wakeup — the wait loop's
/// ≤2 s poll re-read of Postgres stays the delivery truth (missed notifies, Neon
/// scale-to-zero).
pub const APPROVALS_CHANNEL: &str = "fluidbox_approvals";

/// `append_event` on an EXISTING transaction — the in-tx emission primitive the
/// approval decision transactions ride (Phase E, #33; Gap 13, plan E12), so the
/// canonical ledger event commits atomically with the decision CAS that produced
/// it and a loser of that CAS emits nothing.
///
/// The caller MUST already have set the tenant GUC on this connection
/// (`scoped_tx`) or the audited bypass (`worker_tx`): the plpgsql
/// `append_event(...)` is SECURITY INVOKER, so its `update sessions` +
/// `insert events` run under the caller's policies.
///
/// Gate: the `where exists(...)` guards the target list, so the side-effecting
/// function is NOT invoked on a scope miss (no seq bump, no NOTIFY) — zero rows →
/// `RowNotFound`.
async fn append_event_in_tx(
    tx: &mut sqlx::PgConnection,
    scope: TenantScope,
    event: Redacted<EventEnvelope>,
) -> sqlx::Result<i64> {
    let env = event.into_inner();
    let payload = serde_json::to_value(&env.body).unwrap_or(Value::Null);
    let type_name = env.body.type_name();
    let row = sqlx::query(
        "select append_event($1, $2, $3, $4, $5, $6) as seq
         where exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $7)",
    )
    .bind(env.session_id)
    .bind(env.event_id)
    .bind(env.actor.as_str())
    .bind(&type_name)
    .bind(&payload)
    .bind(env.occurred_at)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    match row {
        Some(r) => Ok(r.get::<i64, _>("seq")),
        None => Err(sqlx::Error::RowNotFound),
    }
}

pub async fn events_after(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    after_seq: i64,
    limit: i64,
) -> sqlx::Result<Vec<EventRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select event_id, session_id, seq, actor, type, payload, occurred_at
         from events
         where session_id = $1 and seq > $2
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $4)
         order by seq limit $3",
    )
    .bind(session)
    .bind(after_seq)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
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
/// one). See [`claim_tool_execution`]'s LOCK-ORDER ANALYSIS for why this cannot
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
    emit_and_notify(&mut tx, scope, id, events).await?;
    tx.commit().await?;
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
    emit_and_notify(&mut tx, scope, id, events).await?;
    tx.commit().await?;
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
    events: Vec<Redacted<EventEnvelope>>,
) -> sqlx::Result<()> {
    for ev in events {
        append_event_in_tx(&mut *tx, scope, ev).await?;
    }
    sqlx::query("select pg_notify($1, $2)")
        .bind(APPROVALS_CHANNEL)
        .bind(approval_id.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(())
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
    for ev in events {
        append_event_in_tx(&mut tx, scope, ev).await?;
    }
    tx.commit().await?;
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
///   2. re-read status in a SECOND statement (the [`set_sandbox_handle`]
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
/// cross-tenant expiry scan runs off [`system_worker::expired_pending_approvals`];
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

// ─── Artifacts ────────────────────────────────────────────────────────────

pub async fn add_artifact(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    kind: &str,
    name: &str,
    content: &str,
    content_type: &str,
) -> sqlx::Result<ArtifactRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "insert into artifacts (id, session_id, kind, name, content, content_type)
         select $1,$2,$3,$4,$5,$6
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $7)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(kind)
    .bind(name)
    .bind(content)
    .bind(content_type)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_artifacts(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Vec<ArtifactRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from artifacts
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)
         order by created_at",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_artifact(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<ArtifactRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from artifacts a
         where a.id = $1
           and exists (select 1 from sessions s where s.id = a.session_id and s.tenant_id = $2)",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

// ─── Usage ────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn add_usage(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    model: &str,
    input_tokens: i64,
    output_tokens: i64,
    cache_read: i64,
    cache_write: i64,
    cost_usd: Option<f64>,
    source: &str,
    external_id: Option<&str>,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "insert into usage_entries
           (id, session_id, model, input_tokens, output_tokens, cache_read_tokens,
            cache_write_tokens, cost_usd, source, external_id)
         select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $11)
         on conflict (external_id) where external_id is not null do nothing",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(model)
    .bind(input_tokens)
    .bind(output_tokens)
    .bind(cache_read)
    .bind(cache_write)
    .bind(cost_usd)
    .bind(source)
    .bind(external_id)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

pub async fn usage_totals(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<UsageTotals> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select coalesce(sum(input_tokens),0)::bigint as input_tokens,
                coalesce(sum(output_tokens),0)::bigint as output_tokens,
                coalesce(sum(cache_read_tokens),0)::bigint as cache_read_tokens,
                coalesce(sum(cache_write_tokens),0)::bigint as cache_write_tokens,
                coalesce(sum(cost_usd),0)::float8 as cost_usd,
                count(*)::bigint as requests
         from usage_entries
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Unique persistent tool-call INTENTS (one approvals row per tool_call_id)
/// — the budget's counting unit. Never derived from runner-posted events:
/// budget parity does not trust runner cooperation.
pub async fn tool_call_count(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<i64> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select count(*)::bigint as n from approvals
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.get::<i64, _>("n"))
}

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

// ─── Tokens ───────────────────────────────────────────────────────────────

/// Mint one audience-scoped session token (Gap 10, invariant 19). `audience` is
/// one of `control|tool|llm|workspace` (or `all` for a legacy single token) and
/// is enforced per-route by the auth extractors. A run mints FOUR of these, one
/// per audience, all sharing the `fbx_sess_` prefix (the Redactor scrubs by
/// prefix, so all four are covered).
pub async fn create_session_token(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    token_plain: &str,
    ttl_secs: i64,
    audience: &str,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, expires_at, audience)
         values ($1, $2, 'session', $3, $4, now() + make_interval(secs => $5), $6)",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(session)
    .bind(sha256_hex(token_plain))
    .bind(ttl_secs as f64)
    .bind(audience)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// What resolving a session token yields: the session it belongs to AND its
/// owning tenant. The tenant rides the credential so the caller (auth
/// extractor / facade / `/result`) can build a `TenantScope` without a second
/// query — the "bootstrap exception" pattern (token resolution keys purely on
/// the sha256, then hands back a verified tenant).
#[derive(Debug, Clone)]
pub struct SessionTokenAuth {
    pub session_id: Uuid,
    pub tenant_id: Uuid,
    /// Which routes this token opens (Gap 10): `control|tool|llm|workspace`, or
    /// the legacy `all` (pre-split tokens + e2e forgers via the column DEFAULT).
    /// The caller enforces it per-route (auth.rs `audience_allows`).
    pub audience: String,
    /// The workload identity this run's credentials were issued to (Gap 6, Phase F;
    /// `sessions.workload_addrs`, migration 0025) — the provider-reported source
    /// addresses of the sandbox. Carried on the CREDENTIAL so the internal gateway
    /// can check the socket peer without a second query: `/events` is the one
    /// internal route that never loads the session row, and a per-request query
    /// added only there would be a per-event round trip on the hottest path we
    /// have. Empty = unbindable (no provider-asserted identity, or a pre-0025 row).
    pub workload_addrs: Vec<String>,
}

/// Resolve a session token to its session IGNORING revoked_at/expiry — used
/// ONLY by /result to acknowledge an already-terminal session whose token was
/// revoked on the terminal transition (so a lost-response retry acks cleanly).
/// Every other endpoint uses the strict `session_for_token`. A completely
/// bogus token still returns None; a real token resolves to its own session,
/// and the caller gates the ack on that session being terminal.
pub async fn session_for_token_incl_revoked(
    pool: &PgPool,
    token_plain: &str,
) -> sqlx::Result<Option<SessionTokenAuth>> {
    // Credential-digest bootstrap resolution: keyed purely on the token sha256, with
    // NO tenant scope (the caller has no principal until this resolves the tenant).
    // Rides the audited bypass so api_tokens is visible across tenants — the digest
    // IS the credential (documented TenantScope bootstrap exception).
    let mut tx = worker_tx(pool).await?;
    let row = sqlx::query(
        "select t.session_id, t.tenant_id, t.audience, s.workload_addrs
           from api_tokens t
           left join sessions s on s.id = t.session_id
          where t.kind = 'session' and t.token_sha256 = $1",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(session_token_auth))
}

/// Shape one resolved `api_tokens` row (joined to its session) into
/// [`SessionTokenAuth`]. Shared by the strict and lenient resolvers so the two
/// can never drift on which columns they carry — the Gap-6 `workload_addrs` in
/// particular must ride BOTH, since `/result` uses the lenient one and is a
/// terminalizing route.
fn session_token_auth(r: sqlx::postgres::PgRow) -> Option<SessionTokenAuth> {
    r.get::<Option<Uuid>, _>("session_id")
        .map(|session_id| SessionTokenAuth {
            session_id,
            tenant_id: r.get::<Uuid, _>("tenant_id"),
            audience: r.get::<String, _>("audience"),
            // NULL (no provider-asserted identity, or a pre-0025 row) flattens to
            // the empty vec — the caller's "unbindable" case.
            workload_addrs: r
                .get::<Option<Vec<String>>, _>("workload_addrs")
                .unwrap_or_default(),
        })
}

/// Returns the session (and its tenant + audience) a valid (unexpired,
/// unrevoked) token belongs to.
pub async fn session_for_token(
    pool: &PgPool,
    token_plain: &str,
) -> sqlx::Result<Option<SessionTokenAuth>> {
    // Credential-digest bootstrap resolution (audited bypass) — see
    // `session_for_token_incl_revoked`.
    let mut tx = worker_tx(pool).await?;
    // Gap 6 (Phase F): the LEFT JOIN carries `sessions.workload_addrs` on the SAME
    // statement that was already resolving the credential. Cost is one extra
    // primary-key index probe inside an existing round trip — no new query, and no
    // per-request query added to `/events` (the one internal route that never
    // loads the session row). LEFT, not INNER: a session-less `api_tokens` row must
    // still resolve exactly as it did before, and be discarded by the same
    // `session_id`-is-null test.
    let row = sqlx::query(
        "select t.session_id, t.tenant_id, t.audience, s.workload_addrs
           from api_tokens t
           left join sessions s on s.id = t.session_id
          where t.kind = 'session' and t.token_sha256 = $1
            and t.revoked_at is null
            and (t.expires_at is null or t.expires_at > now())",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(session_token_auth))
}

/// Record the Gap-6 workload identity for a run (Phase F; migration 0025): the
/// provider-reported source addresses of the sandbox that this session's four
/// credentials were issued to. Written once, on the provisioning path, from data
/// the provider already held.
///
/// Deliberately NOT folded into `set_sandbox_handle`: the address is a SECURITY
/// fact with its own column and its own guard, and keeping the write explicit is
/// what lets the orchestrator order it BEFORE the handle attach (closing as much
/// of the "workload is running but its identity is not yet recorded" window as a
/// post-hoc capture can — see the call site).
///
/// Unconditional within the tenant: no status predicate, and a later write wins.
/// A workload that reports a NEW address (a reprovision) must be able to replace
/// the stale one, and refusing the write on a winding-down session would leave a
/// row whose recorded identity is a lie. Returns whether a row was touched.
pub async fn set_workload_addrs(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    addrs: &[String],
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update sessions set workload_addrs = $2, updated_at = now()
          where id = $1 and tenant_id = $3",
    )
    .bind(id)
    .bind(addrs)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() == 1)
}

/// Renew a session's tokens ahead of expiry. Gap 10 renewal contract: ONE renew
/// call (the runner presents its `control` token) extends EVERY live token for
/// that session — all four audiences move together in a single statement, so the
/// four never drift apart and the runner keeps one renew loop. Resolves the
/// session from the presented (unrevoked) token's digest, then bumps expiry on
/// all of that session's unrevoked session-kind rows. A revoked/bogus token
/// resolves no session ⇒ zero rows ⇒ `false` (never resurrects a revoked set).
pub async fn extend_session_token(
    pool: &PgPool,
    token_plain: &str,
    ttl_secs: i64,
) -> sqlx::Result<bool> {
    // Keyed on the token digest with no principal scope — audited bypass, like the
    // session-token resolvers above.
    let mut tx = worker_tx(pool).await?;
    let res = sqlx::query(
        "update api_tokens set expires_at = now() + make_interval(secs => $2)
         where kind = 'session' and revoked_at is null
           and session_id in (
             select session_id from api_tokens
              where kind = 'session' and token_sha256 = $1 and revoked_at is null
           )",
    )
    .bind(sha256_hex(token_plain))
    .bind(ttl_secs as f64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

/// Revoke every live session token for a session — called when the session
/// enters a terminal state so a still-running or wedged runner can no longer
/// authenticate to the facade or internal gateway (defense in depth beyond
/// the facade's own terminal-session refusal).
pub async fn revoke_session_tokens(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<u64> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update api_tokens set revoked_at = now()
         where kind = 'session' and session_id = $1 and revoked_at is null
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected())
}

// ─── Trigger invocations (Idempotency-Key) ────────────────────────────────

#[derive(Debug)]
pub enum InvocationClaim {
    /// We own this key — create the run, binding this claim atomically via
    /// create_session's bind_invocation param.
    Claimed { invocation_id: Uuid },
    /// This key already produced a run — return it (after digest check).
    Replay {
        session_id: Uuid,
        request_digest: String,
    },
    /// This key's firing was skipped (overlap | missed | error: …) — a
    /// terminal outcome; replays of the key return it forever.
    Skipped { reason: String },
    /// Another request holds the key mid-creation — caller should 409.
    InFlight,
}

/// Claim an idempotency key. Exactly one concurrent caller wins the insert;
/// a claim whose creation crashed (bound to no session) becomes re-claimable
/// after 60s so a dangling row can't wedge the key forever.
pub async fn claim_invocation(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    idempotency_key: &str,
    request_digest: &str,
) -> sqlx::Result<InvocationClaim> {
    let mut tx = scoped_tx(pool, scope).await?;
    let inserted = sqlx::query(
        "insert into trigger_invocations (id, subscription_id, idempotency_key, request_digest)
         select $1, $2, $3, $4
         where exists (select 1 from trigger_subscriptions where id = $2 and tenant_id = $5)
         on conflict (subscription_id, idempotency_key) do nothing
         returning id",
    )
    .bind(Uuid::now_v7())
    .bind(subscription)
    .bind(idempotency_key)
    .bind(request_digest)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = inserted {
        let invocation_id: Uuid = row.get("id");
        tx.commit().await?;
        return Ok(InvocationClaim::Claimed { invocation_id });
    }
    let existing = sqlx::query(
        "select id, session_id, request_digest, skip_reason, created_at from trigger_invocations
         where subscription_id = $1 and idempotency_key = $2
           and exists (select 1 from trigger_subscriptions where id = $1 and tenant_id = $3)",
    )
    .bind(subscription)
    .bind(idempotency_key)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    if let Some(session_id) = existing.get::<Option<Uuid>, _>("session_id") {
        let request_digest: String = existing.get("request_digest");
        tx.commit().await?;
        return Ok(InvocationClaim::Replay {
            session_id,
            request_digest,
        });
    }
    if let Some(reason) = existing.get::<Option<String>, _>("skip_reason") {
        tx.commit().await?;
        return Ok(InvocationClaim::Skipped { reason });
    }
    // Unbound claim: take it over only once it is stale (crashed creator).
    // Skipped rows are terminal — never stealable.
    let takeover = sqlx::query(
        "update trigger_invocations
            set created_at = now(), request_digest = $3
          where subscription_id = $1 and idempotency_key = $2
            and session_id is null and skip_reason is null
            and created_at < now() - interval '60 seconds'
            and exists (select 1 from trigger_subscriptions where id = $1 and tenant_id = $4)
          returning id",
    )
    .bind(subscription)
    .bind(idempotency_key)
    .bind(request_digest)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    let out = match takeover {
        Some(row) => InvocationClaim::Claimed {
            invocation_id: row.get("id"),
        },
        None => InvocationClaim::InFlight,
    };
    tx.commit().await?;
    Ok(out)
}

/// A skipped firing is the terminal state of its claim row: visibly
/// recorded, never re-claimable. Guarded on session_id so a bound run can
/// never be relabelled a skip.
pub async fn mark_invocation_skipped(
    pool: &PgPool,
    scope: TenantScope,
    invocation: Uuid,
    reason: &str,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update trigger_invocations set skip_reason = $2
         where id = $1 and session_id is null
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = trigger_invocations.subscription_id
                         and sub.tenant_id = $3)",
    )
    .bind(invocation)
    .bind(reason)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TriggerInvocationRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub idempotency_key: String,
    pub session_id: Option<Uuid>,
    pub skip_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub async fn list_subscription_invocations(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<TriggerInvocationRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select id, subscription_id, idempotency_key, session_id, skip_reason, created_at
         from trigger_invocations where subscription_id = $1
           and exists (select 1 from trigger_subscriptions where id = $1 and tenant_id = $3)
         order by created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Non-terminal runs of a subscription — the concurrency-policy input.
pub async fn active_subscription_sessions(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
) -> sqlx::Result<Vec<SessionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select s.* from sessions s
         join trigger_invocations i on i.session_id = s.id
         where i.subscription_id = $1 and s.tenant_id = $2
           and s.status not in ('completed','failed','cancelled','budget_exceeded')
         order by s.created_at",
    )
    .bind(subscription)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Free a claim whose run creation failed, so an immediate retry can re-try.
pub async fn release_invocation(
    pool: &PgPool,
    scope: TenantScope,
    invocation: Uuid,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "delete from trigger_invocations where id = $1 and session_id is null
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = trigger_invocations.subscription_id
                         and sub.tenant_id = $2)",
    )
    .bind(invocation)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn list_subscription_sessions(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<SessionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select s.* from sessions s
         join trigger_invocations i on i.session_id = s.id
         where i.subscription_id = $1 and s.tenant_id = $3
         order by s.created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Scopes the trigger-token polling endpoint to runs this subscription made.
pub async fn subscription_owns_session(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    session: Uuid,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select exists(
           select 1 from trigger_invocations ti
           join trigger_subscriptions sub on sub.id = ti.subscription_id
           where ti.subscription_id = $1 and ti.session_id = $2 and sub.tenant_id = $3
         ) as owned",
    )
    .bind(subscription)
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.get::<bool, _>("owned"))
}

// ─── Result deliveries ────────────────────────────────────────────────────

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

/// True if a delivery row exists for this session AND destination — the
/// per-destination idempotency check both enqueue paths (the terminal
/// transition and the claim-serialized reconciler) run before inserting:
/// a crash after destination A but before destination B is healed by
/// enqueueing exactly B, never duplicating A, and "some rows exist" is
/// never mistaken for "all destinations enqueued".
pub async fn result_delivery_exists_for(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    destination: &Value,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let (exists,): (bool,) = sqlx::query_as(
        "select exists(select 1 from result_deliveries
           where session_id = $1 and destination = $2
             and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $3))",
    )
    .bind(session)
    .bind(destination)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(exists)
}

/// True if the session already has a `run.result` ledger event — the
/// reconciler's exactly-once guard (emit-if-missing under the finalize
/// claim, which serializes drivers).
pub async fn has_run_result_event(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let (exists,): (bool,) = sqlx::query_as(
        "select exists(select 1 from events where session_id = $1 and type = 'run.result'
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2))",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(exists)
}

pub async fn enqueue_result_delivery(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    subscription: Option<Uuid>,
    destination: &Value,
) -> sqlx::Result<ResultDeliveryRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    // The session must be in scope AND — when a subscription is named — it must
    // belong to the SAME tenant (a cross-tenant subscription is proven
    // impossible here, not just Rust-side). A miss → fetch_one RowNotFound, the
    // existing not-in-scope-session shape.
    let __rls_out = sqlx::query_as(
        "insert into result_deliveries (id, session_id, subscription_id, destination)
         select $1, $2, $3, $4
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $5)
           and ($3::uuid is null or exists (
                 select 1 from trigger_subscriptions sub where sub.id = $3 and sub.tenant_id = $5))
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(subscription)
    .bind(destination)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// RE-STAMP this replica's claim on ONE delivery row, immediately before its
/// attempt (Phase E, #33; review I2). Returns true iff we still own it.
///
/// WHY THIS EXISTS. [`system_worker::claim_due_deliveries`] stamps a whole BATCH
/// at once, but the worker then attempts the rows SEQUENTIALLY: the last row of a
/// batch of 10 can sit unattempted for nine attempts' worth of wall clock, so a
/// TTL measured from the batch is long expired by the time its turn comes. Two
/// failures follow from that, and both are user-visible:
///   * another replica steals the row and delivers it AGAIN (a second GitHub
///     comment, a second webhook POST) — the exact duplicate the claim exists to
///     prevent; and
///   * whichever replica finishes second loses [`mark_delivery_attempt`]'s owner
///     guard, so `attempts` and `next_attempt_at` DO NOT MOVE. The row is
///     immediately due again, and with every replica overrunning its claim the
///     cycle repeats forever: the backoff never advances, `max_attempts` is never
///     reached, and the external side effect repeats on every pass.
///
/// Re-stamping per row makes the TTL measure ONE attempt instead of a whole batch,
/// which is what lets the caller size it against a single worst-case attempt.
///
/// STRICTLY OWNER-GUARDED, never a steal: if another replica already took the row
/// (`claimed_by` moved), this matches zero rows and the caller SKIPS it without
/// performing the external side effect — the new owner does it exactly once. The
/// CAS is atomic against a concurrent claim scan: whoever takes the row lock first
/// wins, and the loser's predicate no longer holds.
pub async fn extend_delivery_claim(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    owner: Uuid,
    ttl_secs: i64,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update result_deliveries
            set claimed_until = now() + make_interval(secs => $3),
                updated_at = now()
          where id = $1 and claimed_by = $2 and status = 'pending'
            and exists (select 1 from sessions s
                        where s.id = result_deliveries.session_id and s.tenant_id = $4)",
    )
    .bind(id)
    .bind(owner)
    .bind(ttl_secs.max(1) as f64)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

/// Record one attempt. ok → delivered; failure → attempts+1 and either
/// rescheduled (`retry_in_secs`) or terminally 'failed' at `max_attempts`.
///
/// GUARDED on the caller still holding the row's claim (Phase E, #33; Gap 13).
/// `owner` is the replica id that
/// [`system_worker::claim_due_deliveries`] stamped; a replica whose claim expired
/// and was stolen mid-attempt matches zero rows and gets `None`, so it can never
/// stomp the new owner's attempt counter or backoff. The claim is RELEASED here
/// (both columns nulled) so the next backoff window is open to any replica.
///
/// `None` IS A REAL FAILURE MODE, NOT A NO-OP (review I2): nothing was recorded,
/// so neither `attempts` nor `next_attempt_at` moved — the caller MUST log it
/// (see `deliveries::attempt`) and rely on the new owner to record the attempt it
/// is running. [`extend_delivery_claim`] makes this rare by re-stamping the claim
/// per attempt; it stays possible when an attempt outruns even that fresh TTL.
#[allow(clippy::too_many_arguments)]
pub async fn mark_delivery_attempt(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    owner: Uuid,
    ok: bool,
    error: Option<&str>,
    payload_digest: Option<&str>,
    retry_in_secs: i64,
    max_attempts: i32,
) -> sqlx::Result<Option<ResultDeliveryRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "update result_deliveries set
            attempts = attempts + 1,
            status = case when $2 then 'delivered'
                          when attempts + 1 >= $6 then 'failed'
                          else 'pending' end,
            delivered_at = case when $2 then now() else delivered_at end,
            last_error = $3,
            payload_digest = coalesce($4, payload_digest),
            next_attempt_at = now() + make_interval(secs => $5),
            claimed_by = null,
            claimed_until = null,
            updated_at = now()
         where id = $1 and claimed_by = $8
           and exists (select 1 from sessions s
                       where s.id = result_deliveries.session_id and s.tenant_id = $7)
         returning *",
    )
    .bind(id)
    .bind(ok)
    .bind(error)
    .bind(payload_digest)
    .bind(retry_in_secs as f64)
    .bind(max_attempts)
    .bind(scope.tenant_id())
    .bind(owner)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_session_deliveries(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from result_deliveries where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)
         order by created_at",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_subscription_deliveries(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<ResultDeliveryRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from result_deliveries where subscription_id = $1
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $3)
         order by created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

// ─── Schedules (Phase 3: the clock on a subscription) ────────────────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ScheduleRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub cron: String,
    pub timezone: String,
    pub next_fire_at: Option<DateTime<Utc>>,
    pub missed_run_policy: String,
    pub last_fired_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn create_schedule(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    cron: &str,
    timezone: &str,
    next_fire_at: DateTime<Utc>,
    missed_run_policy: &str,
) -> sqlx::Result<ScheduleRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "insert into schedules (id, subscription_id, cron, timezone, next_fire_at, missed_run_policy)
         select $1, $2, $3, $4, $5, $6
         where exists (select 1 from trigger_subscriptions where id = $2 and tenant_id = $7)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(subscription)
    .bind(cron)
    .bind(timezone)
    .bind(next_fire_at)
    .bind(missed_run_policy)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn schedule_for_subscription(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
) -> sqlx::Result<Option<ScheduleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from schedules where subscription_id = $1
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $2)",
    )
    .bind(subscription)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn schedules_for_tenant(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<ScheduleRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select sc.* from schedules sc
         join trigger_subscriptions sub on sub.id = sc.subscription_id
         where sub.tenant_id = $1",
    )
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// CAS advance: only moves the clock if next_fire_at is still the fire time
/// this worker processed — two workers can never double-advance past an
/// unhandled fire time.
pub async fn advance_schedule(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
    from: DateTime<Utc>,
    to: Option<DateTime<Utc>>,
    fired_at: Option<DateTime<Utc>>,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update schedules set
            next_fire_at = $2,
            last_fired_at = coalesce($3, last_fired_at),
            updated_at = now()
         where id = $1 and next_fire_at = $4
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = schedules.subscription_id and sub.tenant_id = $5)",
    )
    .bind(id)
    .bind(to)
    .bind(fired_at)
    .bind(from)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

pub async fn create_trigger_token(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    token_plain: &str,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "insert into api_tokens (id, tenant_id, kind, subscription_id, token_sha256)
         values ($1, $2, 'trigger', $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(subscription)
    .bind(sha256_hex(token_plain))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// What resolving a trigger token yields: the token row's id (the exact
/// invoking principal a trigger run freezes — design "The exact trigger token ID
/// is stored on each invocation"), the subscription it may invoke, AND its owning
/// tenant (the "bootstrap exception" pattern — keys on the sha256, hands back a
/// verified tenant).
#[derive(Debug, Clone, Copy)]
pub struct TriggerTokenAuth {
    pub token_id: Uuid,
    pub subscription_id: Uuid,
    pub tenant_id: Uuid,
}

/// Resolves a scoped trigger token to its id + subscription (and tenant). This is
/// the entire authority of the token — it can never satisfy Admin or
/// SessionAuth.
pub async fn subscription_for_token(
    pool: &PgPool,
    token_plain: &str,
) -> sqlx::Result<Option<TriggerTokenAuth>> {
    // Credential-digest bootstrap resolution (audited bypass): the trigger token's
    // sha256 is the only key; the verified tenant rides out on the returned row.
    let mut tx = worker_tx(pool).await?;
    let row = sqlx::query(
        "select id, subscription_id, tenant_id from api_tokens
         where kind = 'trigger' and token_sha256 = $1
           and revoked_at is null
           and (expires_at is null or expires_at > now())",
    )
    .bind(sha256_hex(token_plain))
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.and_then(|r| {
        r.get::<Option<Uuid>, _>("subscription_id")
            .map(|subscription_id| TriggerTokenAuth {
                token_id: r.get::<Uuid, _>("id"),
                subscription_id,
                tenant_id: r.get::<Uuid, _>("tenant_id"),
            })
    }))
}

/// Revocation recheck for a trigger-invoked run's frozen principal (design
/// :741/:748, invariant R2.2): the exact api_tokens row the run froze must still
/// exist, be a live trigger token (not revoked, not expired), and JOIN to a
/// subscription that still exists and is ENABLED. The token is subscription-
/// scoped by an immutable FK, so its subscription IS the run's subscription —
/// "still belongs to the run's subscription" is verified by that JOIN. Scoped to
/// the tenant on both rows. Returns false on any drift (fail closed).
pub async fn trigger_token_active(
    pool: &PgPool,
    scope: TenantScope,
    token_id: Uuid,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row = sqlx::query(
        "select exists (
             select 1
               from api_tokens t
               join trigger_subscriptions s
                 on s.id = t.subscription_id and s.tenant_id = t.tenant_id
              where t.id = $1 and t.tenant_id = $2 and t.kind = 'trigger'
                and t.revoked_at is null
                and (t.expires_at is null or t.expires_at > now())
                and s.enabled
         ) as ok",
    )
    .bind(token_id)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.get::<bool, _>("ok"))
}

/// Rotation support: kill every live token for the subscription.
pub async fn revoke_trigger_tokens(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
) -> sqlx::Result<u64> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update api_tokens set revoked_at = now()
         where kind = 'trigger' and subscription_id = $1 and revoked_at is null
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $2)",
    )
    .bind(subscription)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected())
}

// ─── LISTEN/NOTIFY wakeup hub ─────────────────────────────────────────────

/// Spawns the notify listener with a reconnect loop. Payloads are
/// (session_id, seq). Delivery is best-effort by design — every consumer
/// polls the seq catch-up query as the source of truth.
// ─── Event deliveries & dispatches (design §6.4) ──────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TriggerDeliveryRow {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub external_event_id: String,
    pub event_type: String,
    pub payload: Value,
    pub payload_digest: String,
    pub occurred_at: Option<DateTime<Utc>>,
    pub received_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TriggerDispatchRow {
    pub id: Uuid,
    pub delivery_id: Uuid,
    pub subscription_id: Uuid,
    pub session_id: Option<Uuid>,
    pub status: String,
    pub skip_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Level-1 dedup: store the delivery once; a retry returns the stored row
/// with `fresh = false` and the caller re-walks dispatch (which is itself
/// idempotent) — so a retry can only ever HEAL a partial fan-out.
#[allow(clippy::too_many_arguments)]
pub async fn insert_trigger_delivery(
    pool: &PgPool,
    scope: TenantScope,
    connection: Uuid,
    external_event_id: &str,
    event_type: &str,
    payload: &Value,
    payload_digest: &str,
    occurred_at: Option<DateTime<Utc>>,
) -> sqlx::Result<(TriggerDeliveryRow, bool)> {
    let mut tx = scoped_tx(pool, scope).await?;
    let inserted: Option<TriggerDeliveryRow> = sqlx::query_as(
        "insert into trigger_deliveries
           (id, connection_id, external_event_id, event_type, payload, payload_digest, occurred_at)
         select $1,$2,$3,$4,$5,$6,$7
         where exists (select 1 from integration_connections c where c.id = $2 and c.tenant_id = $8)
         on conflict (connection_id, external_event_id) do nothing
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(connection)
    .bind(external_event_id)
    .bind(event_type)
    .bind(payload)
    .bind(payload_digest)
    .bind(occurred_at)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = inserted {
        tx.commit().await?;
        return Ok((row, true));
    }
    let existing = sqlx::query_as(
        "select * from trigger_deliveries where connection_id = $1 and external_event_id = $2
           and exists (select 1 from integration_connections c where c.id = $1 and c.tenant_id = $3)",
    )
    .bind(connection)
    .bind(external_event_id)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((existing, false))
}

/// Level-2 dedup: claim the (delivery, subscription) slot. `None` means the
/// slot already produced its outcome (a bound run, a recorded skip/error, or
/// a fresh in-flight creation) — the caller fires nothing. Like
/// `claim_invocation`, an unbound `created` claim older than 60s is
/// stealable (crashed creator); skipped/errored rows are terminal.
pub async fn claim_trigger_dispatch(
    pool: &PgPool,
    scope: TenantScope,
    delivery: Uuid,
    subscription: Uuid,
) -> sqlx::Result<Option<TriggerDispatchRow>> {
    // Both the subscription AND the delivery's connection must sit in this
    // tenant (the delivery→connection→tenant join is the same proof
    // `list_delivery_dispatches` uses). A miss → zero rows → None, the existing
    // no-claim shape.
    let mut tx = scoped_tx(pool, scope).await?;
    let inserted: Option<TriggerDispatchRow> = sqlx::query_as(
        "insert into trigger_dispatches (id, delivery_id, subscription_id)
         select $1,$2,$3
         where exists (select 1 from trigger_subscriptions sub
                       where sub.id = $3 and sub.tenant_id = $4)
           and exists (select 1 from trigger_deliveries d
                       join integration_connections c on c.id = d.connection_id
                       where d.id = $2 and c.tenant_id = $4)
         on conflict (delivery_id, subscription_id) do nothing
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(delivery)
    .bind(subscription)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    if inserted.is_some() {
        tx.commit().await?;
        return Ok(inserted);
    }
    let __rls_out = sqlx::query_as(
        "update trigger_dispatches
            set created_at = now()
          where delivery_id = $1 and subscription_id = $2
            and session_id is null and status = 'created'
            and created_at < now() - interval '60 seconds'
            and exists (select 1 from trigger_subscriptions sub
                        where sub.id = $2 and sub.tenant_id = $3)
            and exists (select 1 from trigger_deliveries d
                        join integration_connections c on c.id = d.connection_id
                        where d.id = $1 and c.tenant_id = $3)
          returning *",
    )
    .bind(delivery)
    .bind(subscription)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Terminal bookkeeping for a claimed-but-not-run dispatch (skipped |
/// error). Guarded on session_id so a bound run can never be relabelled.
pub async fn mark_dispatch_outcome(
    pool: &PgPool,
    scope: TenantScope,
    dispatch: Uuid,
    status: &str,
    skip_reason: Option<&str>,
) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "update trigger_dispatches set status = $2, skip_reason = $3
         where id = $1 and session_id is null
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = trigger_dispatches.subscription_id and sub.tenant_id = $4)",
    )
    .bind(dispatch)
    .bind(status)
    .bind(skip_reason)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn list_delivery_dispatches(
    pool: &PgPool,
    scope: TenantScope,
    delivery: Uuid,
) -> sqlx::Result<Vec<TriggerDispatchRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from trigger_dispatches where delivery_id = $1
           and exists (select 1 from trigger_deliveries d
                       join integration_connections c on c.id = d.connection_id
                       where d.id = $1 and c.tenant_id = $2)
         order by created_at",
    )
    .bind(delivery)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_connection_deliveries(
    pool: &PgPool,
    scope: TenantScope,
    connection: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<TriggerDeliveryRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from trigger_deliveries where connection_id = $1
           and exists (select 1 from integration_connections c where c.id = $1 and c.tenant_id = $3)
         order by received_at desc limit $2",
    )
    .bind(connection)
    .bind(limit)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

// ─── External results (§17 #3: stable update-in-place identity) ───────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ExternalResultRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub kind: String,
    pub resource_key: String,
    pub external_id: String,
    pub external_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn get_external_result(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    kind: &str,
    resource_key: &str,
) -> sqlx::Result<Option<ExternalResultRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from external_results
         where subscription_id = $1 and kind = $2 and resource_key = $3
           and exists (select 1 from trigger_subscriptions sub
                       where sub.id = $1 and sub.tenant_id = $4)",
    )
    .bind(subscription)
    .bind(kind)
    .bind(resource_key)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn upsert_external_result(
    pool: &PgPool,
    scope: TenantScope,
    subscription: Uuid,
    kind: &str,
    resource_key: &str,
    external_id: &str,
    external_url: Option<&str>,
) -> sqlx::Result<ExternalResultRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "insert into external_results
           (id, subscription_id, kind, resource_key, external_id, external_url)
         select $1,$2,$3,$4,$5,$6
         where exists (select 1 from trigger_subscriptions sub
                       where sub.id = $2 and sub.tenant_id = $7)
         on conflict (subscription_id, kind, resource_key)
           do update set external_id = excluded.external_id,
                         external_url = excluded.external_url,
                         updated_at = now()
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(subscription)
    .bind(kind)
    .bind(resource_key)
    .bind(external_id)
    .bind(external_url)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The LISTEN/NOTIFY relay runs on its OWN connection (outside the app pool) and
/// needs NO tenant GUC: `LISTEN fluidbox_events` and the `pg_notify` payloads it
/// receives (`session_id:seq`) are not table reads, so RLS never applies here. The
/// notify is only a wakeup — the `seq` catch-up query that actually delivers events
/// rides the RLS-scoped `events_after` on the app pool (via the SSE handlers), so
/// this connection deliberately stays role-plain (it does not even need the runtime
/// role; it only LISTENs).
pub fn spawn_listener(database_url: String) -> tokio::sync::broadcast::Sender<(Uuid, i64)> {
    spawn_channel_listener(database_url, "fluidbox_events", |payload| {
        let (sid, seq) = payload.split_once(':')?;
        Some((Uuid::parse_str(sid).ok()?, seq.parse::<i64>().ok()?))
    })
}

/// The cross-replica approval-decision wakeup (Phase E, #33; Gap 13, plan E12).
/// Every committed decision transaction `pg_notify`s [`APPROVALS_CHANNEL`] with
/// the approval id; this listener relays it so EVERY replica can wake its own
/// local `/permission` waiters, not just the one that happened to serve the
/// decision request. Same discipline as `spawn_listener` above: a dedicated
/// connection outside the app pool, role-plain, LISTEN-only, auto-reconnecting.
///
/// It is a LATENCY optimization, never the correctness mechanism — the wait loop's
/// ≤2 s Postgres re-read stays the source of truth and the missed-notify /
/// scale-to-zero backstop, exactly as `events_after` does for SSE.
pub fn spawn_approval_listener(database_url: String) -> tokio::sync::broadcast::Sender<Uuid> {
    spawn_channel_listener(database_url, APPROVALS_CHANNEL, |payload| {
        Uuid::parse_str(payload).ok()
    })
}

/// The shared LISTEN relay both channels ride. Runs on its OWN connection (outside
/// the app pool) and needs NO tenant GUC: `LISTEN` and the `pg_notify` payloads it
/// receives are not table reads, so RLS never applies here (the RLS-scoped
/// catch-up queries that actually deliver run on the app pool). Undeliverable
/// payloads are dropped, and a dropped connection reconnects with a 3 s backoff —
/// a missed notify only costs the consumer's polling interval.
fn spawn_channel_listener<T, F>(
    database_url: String,
    channel: &'static str,
    parse: F,
) -> tokio::sync::broadcast::Sender<T>
where
    T: Clone + Send + 'static,
    F: Fn(&str) -> Option<T> + Send + 'static,
{
    let (tx, _) = tokio::sync::broadcast::channel::<T>(1024);
    let tx2 = tx.clone();
    tokio::spawn(async move {
        loop {
            match PgListener::connect(&database_url).await {
                Ok(mut listener) => {
                    if listener.listen(channel).await.is_err() {
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        continue;
                    }
                    tracing::info!("pg listener connected ({channel})");
                    loop {
                        match listener.recv().await {
                            Ok(n) => {
                                if let Some(v) = parse(n.payload()) {
                                    let _ = tx2.send(v);
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "pg listener ({channel}) dropped: {e}; reconnecting"
                                );
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("pg listener ({channel}) connect failed: {e}; retrying");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    });
    tx
}

// ─── Integration test (runs only when DATABASE_URL is set) ───────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::event::{Actor, EventBody, EventEnvelope, Redactor};

    // ─── Tenant-less global scans in a SHARED database (#33) ────────────────
    //
    // Every `system_worker` scan is a TENANT-LESS GLOBAL scan, and that is the
    // production contract: one worker tick sweeps every tenant on every replica,
    // and each returned row carries its own `tenant_id`/`session_id` so the
    // caller ledgers it under the right scope. Nothing below argues with that.
    //
    // But `cargo test` runs this module's tests CONCURRENTLY against ONE
    // database, so a scan issued by one test also sees — and converts, and
    // CLAIMS — the rows of every test running beside it. That produces two
    // distinct failures, both reproduced on a scratch Postgres:
    //
    //   * EXTRA rows. A sibling's expired row lands in my batch, so any assertion
    //     about the batch's LENGTH is really an assertion about the whole
    //     database. This is what broke CI: `sweep_converts_…` counted 2 and its
    //     sibling counted 0 — one sweep statement had converted BOTH tests'
    //     reservations (identical `usage_entries.created_at` to the microsecond,
    //     i.e. one transaction, across two different tenants).
    //     Cured by [`GLOBAL_SCAN`]-guarded helpers that FILTER every batch down to
    //     the rows the calling test owns.
    //
    //   * STOLEN rows. A sibling's scan converts/claims MY row in the window
    //     between my making it scannable and my own scan — measured at 3/6 runs
    //     for the stale-claim pair and 6/6 for the delivery trio — so filtering
    //     alone still leaves "my scan reported my row" flaky, and for the claim
    //     scans it also hands my row's LEASE to another owner id.
    //     Cured by [`GLOBAL_SCAN`].
    //
    // The tests are NOT serialized: they seed, reserve, assert and clean up
    // concurrently as before. Only the window in which one test's rows are
    // scannable-but-not-yet-scanned is mutually exclusive, and every scan runs
    // inside one — which is exactly the condition under which a global scan can
    // be reasoned about locally. `tenant_less_scans_go_through_the_scoped_helpers`
    // below keeps it that way.
    static GLOBAL_SCAN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// This session's slice of a global expired-reservation sweep. The sweep and
    /// its `Utc::now()` cutoff are the real ones — only the ROWS are narrowed, so
    /// every property the callers assert (what was converted, with which tokens,
    /// under which tenant/session, and that a second sweep reports nothing more)
    /// survives intact while a sibling tenant's booking in the same batch stops
    /// being this test's business. Call under a [`GLOBAL_SCAN`] guard taken before
    /// the reservation was expired.
    async fn sweep_reservations(
        pool: &PgPool,
        session: Uuid,
    ) -> Vec<system_worker::SweptReservation> {
        system_worker::sweep_expired_llm_reservations(pool, Utc::now(), 100)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.session_id == session)
            .collect()
    }

    /// This session's slice of a global stale-execution-claim sweep — same
    /// narrowing, same reasons, same guard discipline as [`sweep_reservations`].
    async fn sweep_stale_claims(
        pool: &PgPool,
        session: Uuid,
    ) -> Vec<(Uuid, Uuid, String, Option<String>)> {
        system_worker::sweep_stale_execution_claims(pool, Utc::now(), 200)
            .await
            .unwrap()
            .into_iter()
            .filter(|(_, s, _, _)| *s == session)
            .collect()
    }

    /// The rows THIS test enqueued that `owner` just claimed. The claim scan is
    /// the real one — `owner`, `limit` and `ttl_secs` reach it untouched, so the
    /// `limit`/`skip locked`/lease behaviour under test is unchanged — but a
    /// sibling test's delivery that happened to be due is not this test's row and
    /// is dropped from the answer. Call under a [`GLOBAL_SCAN`] guard taken before
    /// the deliveries were enqueued: unlike the sweeps, a stolen delivery is not
    /// merely unobserved, it is LEASED to another owner id, which no filter can
    /// undo.
    async fn claim_deliveries(
        pool: &PgPool,
        owner: Uuid,
        limit: i64,
        ttl_secs: i64,
        mine: &[Uuid],
    ) -> Vec<ResultDeliveryRow> {
        system_worker::claim_due_deliveries(pool, owner, limit, ttl_secs)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| mine.contains(&r.id))
            .collect()
    }

    /// Source guard for the #33 class, in the shape of the #32 one above: a scan
    /// with no tenant predicate must never be called bare from a test, because a
    /// bare call asserts about every OTHER test's rows and races them for their
    /// own. This is a source assertion, not a DB test — it runs without
    /// `DATABASE_URL`, so a re-added bare caller fails immediately instead of
    /// flaking one CI run in eight. Each needle is assembled from two halves so
    /// the guard is not itself an occurrence.
    #[test]
    fn tenant_less_scans_go_through_the_scoped_helpers() {
        let src = include_str!("lib.rs");
        for (needle, helper) in [
            (
                concat!("sweep_expired_llm", "_reservations("),
                "sweep_reservations",
            ),
            (
                concat!("sweep_stale_execution", "_claims("),
                "sweep_stale_claims",
            ),
            (concat!("claim_due", "_deliveries("), "claim_deliveries"),
            (
                concat!("expired_pending", "_approvals("),
                "the single containment-only caller",
            ),
        ] {
            let n = src.matches(needle).count();
            assert_eq!(
                n, 1,
                "`{needle}` must appear exactly ONCE in fluidbox-db — inside {helper} — \
                 found {n}. Route the new call through that helper and hold GLOBAL_SCAN \
                 from the moment your rows become scannable: a bare call counts every \
                 other test's rows into your batch and converts/claims them out of theirs."
            );
        }
    }

    /// The durable-finalizer DB contract (PR #47 fix batch 2 — H3/H5):
    /// single-winner intent under the session row lock, quiesce computed from
    /// the LOCKED snapshot, losers receive the winner's row, recovery sees
    /// intents on ACTIVE sessions, and a terminal session fences both intent
    /// re-creation and late sandbox-handle attachment.
    #[tokio::test]
    async fn finalization_intent_is_transactional_and_single_winner() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-finalize",
            "name: test-finalize",
            &serde_json::json!({"name": "test-finalize"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-finalize-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
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
        let mk = |title: &'static str| {
            create_session(
                &pool,
                scope,
                agent.id,
                rev.id,
                "supervised",
                "trusted",
                title,
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
        };
        let racer = mk("finalize-test race").await.unwrap();
        let fenced = mk("finalize-test fence").await.unwrap();

        use fluidbox_core::state::SessionStatus;
        // Advance the race session to running with a handle so the locked
        // snapshot computes a REAL quiesce for want_quiesce callers.
        for st in [
            SessionStatus::Provisioning,
            SessionStatus::Initializing,
            SessionStatus::Running,
        ] {
            transition_session(&pool, scope, racer.id, st, None)
                .await
                .unwrap();
        }
        let attached_active = set_sandbox_handle(
            &pool,
            scope,
            racer.id,
            &serde_json::json!({"external_id":"t","uid":"u"}),
        )
        .await
        .unwrap();

        // Genuinely concurrent: two connections race the insert under the
        // row lock — a cancel (wants quiesce) against a /result (does not).
        let (a, b) = tokio::join!(
            begin_finalization(
                &pool,
                scope,
                racer.id,
                "cancelled",
                None,
                Some("race"),
                true,
                30
            ),
            begin_finalization(
                &pool,
                scope,
                racer.id,
                "completed",
                Some("done"),
                None,
                false,
                30
            ),
        );
        let unpack = |r: sqlx::Result<BeginFinalization>| match r.unwrap() {
            BeginFinalization::Persisted {
                row,
                created,
                session_status,
            } => (row, created, session_status),
            other => panic!("expected Persisted, got {other:?}"),
        };
        let (row_a, created_a, status_a) = unpack(a);
        let (row_b, created_b, status_b) = unpack(b);

        // Recovery must see the intent while the session is still ACTIVE
        // (the crash-between-persist-and-transition window).
        let pending_while_active = system_worker::pending_finalizations(&pool).await.unwrap();

        // Claim semantics: one holder at a time; an early release (the
        // deliberate settle-defer path) re-opens it immediately, without
        // waiting out the stale threshold.
        let claim1 = claim_finalization(&pool, scope, racer.id, 420)
            .await
            .unwrap();
        let claim_held = claim_finalization(&pool, scope, racer.id, 420)
            .await
            .unwrap();
        release_finalization_claim(&pool, scope, racer.id)
            .await
            .unwrap();
        let claim_after_release = claim_finalization(&pool, scope, racer.id, 420)
            .await
            .unwrap();

        // Fence session: persist an intent, terminalize legally, release the
        // intent, then try to re-create it and to attach a handle late.
        let first_fence = begin_finalization(
            &pool,
            scope,
            fenced.id,
            "failed",
            None,
            Some("t"),
            false,
            30,
        )
        .await
        .unwrap();
        // The gap that matters: intent committed, wind-down transition NOT
        // yet applied — the session status still accepts work, but the
        // intent alone must fence a late attach.
        let attached_intent_gap = set_sandbox_handle(
            &pool,
            scope,
            fenced.id,
            &serde_json::json!({"external_id":"tg","uid":"ug"}),
        )
        .await
        .unwrap();
        transition_session(&pool, scope, fenced.id, SessionStatus::Finalizing, None)
            .await
            .unwrap();
        // Wind-down owns the session: a provisioning race may no longer
        // attach a handle.
        let attached_winddown = set_sandbox_handle(
            &pool,
            scope,
            fenced.id,
            &serde_json::json!({"external_id":"tw","uid":"uw"}),
        )
        .await
        .unwrap();
        transition_session(&pool, scope, fenced.id, SessionStatus::Failed, None)
            .await
            .unwrap();
        // Terminal + intent = cleanup still owed: recovery must see it.
        let pending_while_terminal = system_worker::pending_finalizations(&pool).await.unwrap();
        delete_finalization(&pool, scope, fenced.id).await.unwrap();
        let pending_after_release = system_worker::pending_finalizations(&pool).await.unwrap();
        let post_terminal =
            begin_finalization(&pool, scope, fenced.id, "cancelled", None, None, true, 30)
                .await
                .unwrap();
        let attached_terminal = set_sandbox_handle(
            &pool,
            scope,
            fenced.id,
            &serde_json::json!({"external_id":"t2","uid":"u2"}),
        )
        .await
        .unwrap();
        let missing = begin_finalization(
            &pool,
            scope,
            Uuid::now_v7(),
            "failed",
            None,
            None,
            false,
            30,
        )
        .await
        .unwrap();

        // Fixtures out BEFORE the assertions (session delete cascades to the
        // surviving intent).
        for id in [racer.id, fenced.id] {
            sqlx::query("delete from sessions where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(attached_active, "handle attach must succeed while active");
        assert!(
            created_a ^ created_b,
            "exactly one racer creates the intent (created_a={created_a}, created_b={created_b})"
        );
        assert_eq!(
            row_a.outcome, row_b.outcome,
            "both racers must hold the WINNER's row"
        );
        assert_eq!(row_a.needs_quiesce, row_b.needs_quiesce);
        let winner_is_cancel = row_a.outcome == "cancelled";
        assert_eq!(
            row_a.needs_quiesce, winner_is_cancel,
            "quiesce comes from the winning intent, derived from the locked snapshot"
        );
        assert_eq!(
            row_a.quiesce_deadline.is_some(),
            winner_is_cancel,
            "deadline exists iff the winner wanted quiesce"
        );
        assert_eq!(status_a, "running");
        assert_eq!(status_b, "running");
        assert!(
            pending_while_active.contains(&racer.id),
            "recovery must scan intents on ACTIVE sessions"
        );
        assert!(claim1.is_some(), "first claim must succeed");
        assert!(
            claim_held.is_none(),
            "a held claim must not be re-claimable"
        );
        assert!(
            claim_after_release.is_some(),
            "an early-released claim must be immediately re-claimable"
        );
        assert!(matches!(
            first_fence,
            BeginFinalization::Persisted { created: true, .. }
        ));
        assert!(
            !attached_intent_gap,
            "a committed intent must fence attach BEFORE the wind-down transition lands"
        );
        assert!(
            !attached_winddown,
            "a winding-down session must refuse a late sandbox handle"
        );
        assert!(
            pending_while_terminal.contains(&fenced.id),
            "recovery must see intents on TERMINAL sessions (cleanup owed)"
        );
        assert!(
            !pending_after_release.contains(&fenced.id),
            "a released intent leaves the recovery worklist"
        );
        assert!(
            matches!(post_terminal, BeginFinalization::AlreadyTerminal),
            "a terminal session must fence intent re-creation"
        );
        assert!(
            !attached_terminal,
            "a terminal session must refuse a late sandbox handle"
        );
        assert!(matches!(missing, BeginFinalization::Missing));
    }

    #[tokio::test]
    async fn append_event_assigns_gapless_seq_and_notifies() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        let policy = upsert_policy(
            &pool,
            scope,
            "test-seq",
            "name: test-seq",
            &serde_json::json!({"name": "test-seq"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-seq-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
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
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "t",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();

        let mut listener = PgListener::connect(&url).await.unwrap();
        listener.listen("fluidbox_events").await.unwrap();

        let redactor = Redactor::default();
        let mut seqs = Vec::new();
        for i in 0..3 {
            let env = EventEnvelope::new(
                session.id,
                Actor::System,
                EventBody::AgentMessage {
                    role: "assistant".into(),
                    text: format!("m{i}"),
                },
            );
            seqs.push(
                append_event(&pool, scope, redactor.scrub(env))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(seqs, vec![1, 2, 3]);

        let n = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .expect("notify within 5s")
            .expect("notify ok");
        assert!(n.payload().starts_with(&session.id.to_string()));

        let events = events_after(&pool, scope, session.id, 0, 10).await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].r#type, "agent.message");
    }

    #[tokio::test]
    async fn session_token_revoke_is_terminal_and_extend_cannot_resurrect() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-token",
            "name: test-token",
            &serde_json::json!({"name": "test-token"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-token-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "codex",
            "img:test",
            "gpt-5.4-mini",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "autonomous",
            "trusted",
            "t",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();

        // Gap 10: a run mints FOUR audience-scoped tokens. Mint two here + forge
        // a legacy (no-audience) row to exercise the whole contract.
        let control = format!("fbx_sess_{}", Uuid::now_v7().simple());
        let tool = format!("fbx_sess_{}", Uuid::now_v7().simple());
        create_session_token(&pool, scope, session.id, &control, 3600, "control")
            .await
            .unwrap();
        create_session_token(&pool, scope, session.id, &tool, 3600, "tool")
            .await
            .unwrap();

        // Audience is PERSISTED and RETURNED by the resolver.
        let a = session_for_token(&pool, &control).await.unwrap().unwrap();
        assert_eq!(a.session_id, session.id);
        assert_eq!(a.audience, "control");
        assert_eq!(
            session_for_token(&pool, &tool)
                .await
                .unwrap()
                .unwrap()
                .audience,
            "tool"
        );

        // A legacy row inserted WITHOUT an audience gets the column DEFAULT 'all'
        // (in-flight compat + the e2e forgers rely on this forever).
        let legacy = format!("fbx_sess_{}", Uuid::now_v7().simple());
        {
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query(
                "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, expires_at)
                 values ($1, $2, 'session', $3, $4, now() + interval '1 hour')",
            )
            .bind(Uuid::now_v7())
            .bind(tenant)
            .bind(session.id)
            .bind(sha256_hex(&legacy))
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        assert_eq!(
            session_for_token(&pool, &legacy)
                .await
                .unwrap()
                .unwrap()
                .audience,
            "all"
        );

        // Renew contract: presenting ONE token (control) extends EVERY token for
        // the session — the tool token we did NOT present must move too.
        let expiry = |sha: String| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
                    "select expires_at from api_tokens where token_sha256 = $1",
                )
                .bind(sha)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        // A SECOND session with its own control token. "Renew extends all" is
        // scoped to ONE session: without this, a renew that dropped the
        // `session_id in (…)` predicate and extended every live session token in
        // the table would pass every assertion above. Same tenant on purpose —
        // tenant scoping cannot be what saves us here.
        let other_session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "autonomous",
            "trusted",
            "t2",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();
        let other_control = format!("fbx_sess_{}", Uuid::now_v7().simple());
        create_session_token(
            &pool,
            scope,
            other_session.id,
            &other_control,
            3600,
            "control",
        )
        .await
        .unwrap();

        let tool_before = expiry(sha256_hex(&tool)).await;
        let other_before = expiry(sha256_hex(&other_control)).await;
        assert!(extend_session_token(&pool, &control, 7200).await.unwrap());
        let tool_after = expiry(sha256_hex(&tool)).await;
        assert!(
            tool_after > tool_before,
            "renewing via control must extend the tool token too (renew-extends-all)"
        );
        assert_eq!(
            expiry(sha256_hex(&other_control)).await,
            other_before,
            "a renew must NOT touch another session's tokens (extends-all is per-SESSION)"
        );

        // Terminal transition revokes ALL the session's tokens (control + tool +
        // legacy = 3) — every audience loses access at once, and only this
        // session's: the count excludes the other session's live token.
        assert_eq!(
            revoke_session_tokens(&pool, scope, session.id)
                .await
                .unwrap(),
            3
        );
        assert!(session_for_token(&pool, &control).await.unwrap().is_none());
        assert!(session_for_token(&pool, &tool).await.unwrap().is_none());
        assert!(
            session_for_token(&pool, &other_control)
                .await
                .unwrap()
                .is_some(),
            "another session's token must survive this session's terminal revoke"
        );
        // And a renew can never resurrect a revoked set.
        assert!(!extend_session_token(&pool, &control, 3600).await.unwrap());
        // Revoking again is a no-op (idempotent).
        assert_eq!(
            revoke_session_tokens(&pool, scope, session.id)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn intent_registry_digest_binding_and_lifecycle() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-intent",
            "name: test-intent",
            &serde_json::json!({"name": "test-intent"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-intent-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "codex",
            "img:test",
            "gpt-5.4-mini",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "t",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();

        // Registration is idempotent by (session, tool_call_id).
        let (row, inserted) =
            register_tool_intent(&pool, scope, session.id, "tc1", "Bash", "cat x", "digest-a")
                .await
                .unwrap();
        assert!(inserted);
        assert_eq!(row.status, "intent");
        assert_eq!(row.input_digest.as_deref(), Some("digest-a"));
        let (again, inserted2) =
            register_tool_intent(&pool, scope, session.id, "tc1", "Bash", "cat x", "digest-a")
                .await
                .unwrap();
        assert!(!inserted2);
        assert_eq!(again.id, row.id);
        // The caller compares digests — the registry hands back the stored
        // binding even on a mismatched retry.
        let (mismatch, inserted3) =
            register_tool_intent(&pool, scope, session.id, "tc1", "Bash", "cat y", "digest-B")
                .await
                .unwrap();
        assert!(!inserted3);
        assert_eq!(mismatch.input_digest.as_deref(), Some("digest-a"));

        // Gate verdicts stick, and the CAS reports who won.
        assert!(record_intent_verdict(&pool, scope, row.id, "auto_allowed")
            .await
            .unwrap());
        assert!(
            !record_intent_verdict(&pool, scope, row.id, "auto_denied")
                .await
                .unwrap(),
            "second verdict loses the CAS — the first stands"
        );
        let cur = get_approval(&pool, scope, row.id).await.unwrap().unwrap();
        assert_eq!(cur.status, "auto_allowed");
        // A decided intent can no longer be promoted into an approval.
        assert!(
            promote_intent_to_pending(&pool, scope, row.id, None, "once", "Bash", 600)
                .await
                .unwrap()
                .is_none()
        );

        // The approval lifecycle rides the SAME row when promotion wins.
        let (row2, _) = register_tool_intent(
            &pool, scope, session.id, "tc2", "Bash", "git push", "digest-c",
        )
        .await
        .unwrap();
        let promoted =
            promote_intent_to_pending(&pool, scope, row2.id, Some("high"), "once", "Bash", 600)
                .await
                .unwrap()
                .expect("first promotion wins");
        assert_eq!(promoted.status, "pending");
        assert!(promoted.expires_at > chrono::Utc::now());
        assert!(
            promote_intent_to_pending(&pool, scope, row2.id, Some("high"), "once", "Bash", 600)
                .await
                .unwrap()
                .is_none(),
            "second promotion is a no-op"
        );
        let decided = decide_approval_tx(&pool, scope, row2.id, "approved_once", "tester", vec![])
            .await
            .unwrap()
            .expect("pending row decides");
        assert_eq!(decided.status, "approved_once");
        assert!(
            !record_intent_verdict(&pool, scope, row2.id, "auto_denied")
                .await
                .unwrap(),
            "a human decision is never overwritten by a gate verdict"
        );
        let cur2 = get_approval(&pool, scope, row2.id).await.unwrap().unwrap();
        assert_eq!(cur2.status, "approved_once");

        // The budget counts unique intents; the approvals API hides gate
        // bookkeeping but keeps the human lifecycle.
        assert_eq!(tool_call_count(&pool, scope, session.id).await.unwrap(), 2);
        let visible = session_approvals(&pool, scope, session.id).await.unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].tool_call_id, "tc2");
    }

    #[tokio::test]
    async fn stale_nonstarted_sweep_finds_only_old_prelaunch_sessions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-stale",
            "name: test-stale",
            &serde_json::json!({"name": "test-stale"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-stale-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
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
        let fresh = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "stale-test fresh",
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
        .unwrap();
        let stale = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "stale-test old",
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
        .unwrap();
        // The sweep keys off created_at (heartbeat-proof; M5) — backdate that.
        let backdate =
            "update sessions set created_at = now() - interval '20 minutes' where id = $1";
        sqlx::query(backdate)
            .bind(stale.id)
            .execute(&pool)
            .await
            .unwrap();

        let sweep_created: Vec<Uuid> = system_worker::stale_nonstarted_sessions(&pool, 15)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();

        // The wind-down machine owns terminal entry: the pre-epic direct
        // created→failed edge must be REFUSED (Ok(None)), and terminalization
        // goes through finalizing. Neither a winding-down nor a terminal
        // session may be swept, however old.
        use fluidbox_core::state::SessionStatus;
        let direct_terminal =
            transition_session(&pool, scope, stale.id, SessionStatus::Failed, Some("test"))
                .await
                .unwrap();
        let to_finalizing = transition_session(
            &pool,
            scope,
            stale.id,
            SessionStatus::Finalizing,
            Some("test"),
        )
        .await
        .unwrap();
        sqlx::query(backdate)
            .bind(stale.id)
            .execute(&pool)
            .await
            .unwrap();
        let sweep_finalizing: Vec<Uuid> = system_worker::stale_nonstarted_sessions(&pool, 15)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();
        let to_failed =
            transition_session(&pool, scope, stale.id, SessionStatus::Failed, Some("test"))
                .await
                .unwrap();
        sqlx::query(backdate)
            .bind(stale.id)
            .execute(&pool)
            .await
            .unwrap();
        let sweep_terminal: Vec<Uuid> = system_worker::stale_nonstarted_sessions(&pool, 15)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();

        // Fixtures out BEFORE the assertions — a failed assertion must not
        // leak sessions into the shared tenant.
        for id in [fresh.id, stale.id] {
            sqlx::query("delete from sessions where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(
            sweep_created.contains(&stale.id),
            "old created session must be swept"
        );
        assert!(
            !sweep_created.contains(&fresh.id),
            "fresh session must not be swept"
        );
        assert!(
            direct_terminal.is_none(),
            "created→failed must be refused (no active→terminal edge)"
        );
        assert!(
            to_finalizing.is_some(),
            "created→finalizing must be legal (crash recovery finalizes from anywhere)"
        );
        assert!(
            !sweep_finalizing.contains(&stale.id),
            "winding-down session must not be swept"
        );
        assert!(to_failed.is_some(), "finalizing→failed must be legal");
        assert!(
            !sweep_terminal.contains(&stale.id),
            "terminal session must not be swept"
        );
    }

    #[tokio::test]
    async fn adopt_sandbox_handle_is_guarded() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-adopt",
            "name: test-adopt",
            &serde_json::json!({"name": "test-adopt"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-adopt-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
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
        let s = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "adopt-test",
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
        .unwrap();
        let discovered =
            serde_json::json!({"runtime":"kubernetes","external_id":"pod-x","attrs":{"uid":"u1"}});
        let real =
            serde_json::json!({"runtime":"kubernetes","external_id":"pod-x","attrs":{"uid":"u2"}});

        // Active + handle-less → adoption lands.
        let adopted = adopt_sandbox_handle(&pool, scope, s.id, &discovered)
            .await
            .unwrap();
        // A stored handle is never overwritten (run() won the race).
        set_sandbox_handle(&pool, scope, s.id, &real).await.unwrap();
        let overwrote = adopt_sandbox_handle(&pool, scope, s.id, &discovered)
            .await
            .unwrap();
        let kept: (Value,) = sqlx::query_as("select sandbox_handle from sessions where id = $1")
            .bind(s.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        // A winding-down session never re-acquires a handle.
        sqlx::query(
            "update sessions set sandbox_handle = null, status = 'finalizing' where id = $1",
        )
        .bind(s.id)
        .execute(&pool)
        .await
        .unwrap();
        let resurrected = adopt_sandbox_handle(&pool, scope, s.id, &discovered)
            .await
            .unwrap();

        // Fixtures out BEFORE the assertions.
        sqlx::query("delete from sessions where id = $1")
            .bind(s.id)
            .execute(&pool)
            .await
            .unwrap();

        assert!(adopted, "active handle-less session must adopt");
        assert!(!overwrote, "a stored handle must never be overwritten");
        assert_eq!(kept.0["attrs"]["uid"], "u2", "run()'s handle must survive");
        assert!(!resurrected, "a winding-down session must not adopt");
    }

    #[tokio::test]
    async fn connection_lifecycle_and_credential_isolation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        let sealed = b"nonce||ciphertext-not-a-real-secret".to_vec();
        let conn = create_connection(
            &pool,
            scope,
            "github",
            "test-account-42",
            "test-connection",
            Some(&sealed),
            1,
            &serde_json::json!(["repo"]),
            &serde_json::json!({}),
            &serde_json::json!({"test": true}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        // The row type/serialization can never leak the credential.
        let as_json = serde_json::to_value(&conn).unwrap();
        assert!(as_json.get("credential_sealed").is_none());
        assert!(!serde_json::to_string(&as_json)
            .unwrap()
            .contains("ciphertext-not-a-real-secret"));

        // Active connection yields the sealed bytes.
        let got = connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .expect("active connection has credential");
        assert_eq!(got, (sealed, 1), "legacy sealer stamps key_version 1");

        // Revocation is terminal for credential access.
        let revoked = revoke_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(revoked.status, "revoked");
        assert!(connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .is_none());
        // Idempotent second revoke: no row to update.
        assert!(revoke_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .is_none());

        sqlx::query("delete from integration_connections where id = $1")
            .bind(conn.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn trigger_subscription_lifecycle_token_and_secret_isolation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-trig",
            "name: test-trig",
            &serde_json::json!({"name": "test-trig"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-trig-agent", None)
            .await
            .unwrap();
        let _rev = append_agent_revision(
            &pool,
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

        let sealed = b"nonce||not-a-real-secret".to_vec();
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            "test-sub",
            "api",
            None,
            Some("Investigate {{ticket}}"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([{"kind": "signed_webhook", "url": "http://127.0.0.1:1/cb"}]),
            Some(&sealed),
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(sub.enabled);
        assert!(!sub.allow_task_override);

        // Row serialization can never leak the sealed secret.
        let as_json = serde_json::to_value(&sub).unwrap();
        assert!(as_json.get("callback_secret_sealed").is_none());

        // The single secret reader returns the sealed bytes.
        let got = subscription_callback_secret_sealed(&pool, scope, sub.id)
            .await
            .unwrap();
        assert_eq!(got, Some((sealed, 1)));

        // Trigger tokens: hashed at rest, resolvable, revocable.
        create_trigger_token(&pool, scope, sub.id, "fbx_trig_testtoken123")
            .await
            .unwrap();
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_testtoken123")
                .await
                .unwrap()
                .map(|a| a.subscription_id),
            Some(sub.id)
        );
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_wrong")
                .await
                .unwrap()
                .map(|a| a.subscription_id),
            None
        );
        let revoked = revoke_trigger_tokens(&pool, scope, sub.id).await.unwrap();
        assert_eq!(revoked, 1);
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_testtoken123")
                .await
                .unwrap()
                .map(|a| a.subscription_id),
            None
        );

        // Enable toggle.
        let off = set_trigger_subscription_enabled(&pool, scope, sub.id, false)
            .await
            .unwrap()
            .unwrap();
        assert!(!off.enabled);

        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn invocation_claims_are_idempotent_by_key() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-idem",
            "name: test-idem",
            &serde_json::json!({"name": "test-idem"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-idem-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
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
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            "test-idem-sub",
            "api",
            None,
            Some("t"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // First claim wins.
        let c1 = claim_invocation(&pool, scope, sub.id, "key-1", "digest-a")
            .await
            .unwrap();
        let InvocationClaim::Claimed { invocation_id } = c1 else {
            panic!("wanted Claimed, got {c1:?}")
        };

        // Same key while unbound → InFlight (a concurrent retry must wait).
        assert!(matches!(
            claim_invocation(&pool, scope, sub.id, "key-1", "digest-a")
                .await
                .unwrap(),
            InvocationClaim::InFlight
        ));

        // Bind atomically with session creation (same transaction), then
        // the same key replays that session.
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "t",
            &serde_json::json!({"kind":"scratch"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            Some(&serde_json::json!({"kind":"api"})),
            None,
            None,
            Some(invocation_id),
            None,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(session.trigger, Some(serde_json::json!({"kind":"api"})));
        let c3 = claim_invocation(&pool, scope, sub.id, "key-1", "digest-a")
            .await
            .unwrap();
        match c3 {
            InvocationClaim::Replay {
                session_id,
                request_digest,
            } => {
                assert_eq!(session_id, session.id);
                assert_eq!(request_digest, "digest-a");
            }
            other => panic!("wanted Replay, got {other:?}"),
        }

        // A released (failed-creation) claim frees the key immediately.
        let c4 = claim_invocation(&pool, scope, sub.id, "key-2", "digest-b")
            .await
            .unwrap();
        let InvocationClaim::Claimed {
            invocation_id: inv2,
        } = c4
        else {
            panic!()
        };
        release_invocation(&pool, scope, inv2).await.unwrap();
        assert!(matches!(
            claim_invocation(&pool, scope, sub.id, "key-2", "digest-b")
                .await
                .unwrap(),
            InvocationClaim::Claimed { .. }
        ));

        assert!(subscription_owns_session(&pool, scope, sub.id, session.id)
            .await
            .unwrap());
        let listed = list_subscription_sessions(&pool, scope, sub.id, 10)
            .await
            .unwrap();
        assert!(listed.iter().any(|s| s.id == session.id));

        sqlx::query("delete from sessions where id = $1")
            .bind(session.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn schedule_lifecycle_and_skip_claims() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let agent = create_agent(&pool, scope, "test-sched-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            &format!("test-sched-{}", Uuid::now_v7()),
            "schedule",
            None,
            Some("maintenance sweep"),
            false,
            false,
            None,
            "skip_if_running",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(sub.concurrency_policy, "skip_if_running");

        // Overdue schedule → due; disabled subscription → not due.
        let past = Utc::now() - chrono::Duration::seconds(1);
        let sched = create_schedule(&pool, scope, sub.id, "*/5 * * * * *", "UTC", past, "skip")
            .await
            .unwrap();
        assert!(system_worker::due_schedules(&pool, 50)
            .await
            .unwrap()
            .iter()
            .any(|s| s.id == sched.id));
        set_trigger_subscription_enabled(&pool, scope, sub.id, false)
            .await
            .unwrap();
        assert!(!system_worker::due_schedules(&pool, 50)
            .await
            .unwrap()
            .iter()
            .any(|s| s.id == sched.id));
        set_trigger_subscription_enabled(&pool, scope, sub.id, true)
            .await
            .unwrap();

        // Deterministic fire key: claim once, mark skipped, replay the skip.
        let key = "sched:2026-07-10T00:00:00Z";
        let claim = claim_invocation(&pool, scope, sub.id, key, "d1")
            .await
            .unwrap();
        let InvocationClaim::Claimed { invocation_id } = claim else {
            panic!("expected Claimed, got {claim:?}");
        };
        mark_invocation_skipped(&pool, scope, invocation_id, "missed")
            .await
            .unwrap();
        let again = claim_invocation(&pool, scope, sub.id, key, "d1")
            .await
            .unwrap();
        let InvocationClaim::Skipped { reason } = again else {
            panic!("expected Skipped, got {again:?}");
        };
        assert_eq!(reason, "missed");
        let inv = list_subscription_invocations(&pool, scope, sub.id, 10)
            .await
            .unwrap();
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0].skip_reason.as_deref(), Some("missed"));
        assert!(inv[0].session_id.is_none());

        // CAS advance: succeeds from the processed fire time, then refuses.
        // (`stored` is read back so both sides carry Postgres µs precision.)
        use chrono::SubsecRound;
        let stored = schedule_for_subscription(&pool, scope, sub.id)
            .await
            .unwrap()
            .unwrap()
            .next_fire_at
            .unwrap();
        let future = (Utc::now() + chrono::Duration::seconds(60)).trunc_subsecs(6);
        assert!(
            advance_schedule(&pool, scope, sched.id, stored, Some(future), None)
                .await
                .unwrap()
        );
        assert!(
            !advance_schedule(&pool, scope, sched.id, stored, Some(future), None)
                .await
                .unwrap()
        );
        let row = schedule_for_subscription(&pool, scope, sub.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.next_fire_at, Some(future));
        assert!(row.last_fired_at.is_none()); // skips never touch last_fired_at
        assert!(!system_worker::due_schedules(&pool, 50)
            .await
            .unwrap()
            .iter()
            .any(|s| s.id == sched.id));

        // Cleanup (cascades schedules + invocations).
        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn result_delivery_attempt_state_machine() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-del",
            "name: test-del",
            &serde_json::json!({"name": "test-del"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-del-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
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
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "t",
            &serde_json::json!({"kind":"scratch"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();

        // A due delivery is visible to every replica's claim scan, which in a test
        // process means every sibling test's scan too — so the enqueue and the
        // claim that must win it sit inside one GLOBAL_SCAN window, and the batch
        // is read back through the owning helper.
        let scan = GLOBAL_SCAN.lock().await;
        let dest = serde_json::json!({"kind": "signed_webhook", "url": "http://127.0.0.1:1/cb"});
        let d = enqueue_result_delivery(&pool, scope, session.id, None, &dest)
            .await
            .unwrap();
        assert_eq!(d.status, "pending");
        assert_eq!(d.attempts, 0);

        // Due immediately — and the poll now CLAIMS (Phase E): every attempt is
        // recorded by the replica that holds the row.
        let me = Uuid::now_v7();
        let due = claim_deliveries(&pool, me, 10, 300, &[d.id]).await;
        assert!(due.iter().any(|x| x.id == d.id));

        // Failure → still pending, attempts=1, pushed into the future (not due).
        let after = mark_delivery_attempt(
            &pool,
            scope,
            d.id,
            me,
            false,
            Some("connection refused"),
            None,
            30,
            3,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!((after.status.as_str(), after.attempts), ("pending", 1));
        assert!(!claim_deliveries(&pool, me, 50, 300, &[d.id])
            .await
            .iter()
            .any(|x| x.id == d.id));
        drop(scan);

        // Exhausting attempts → failed, terminal for the delivery only. Each
        // attempt re-claims first: recording one RELEASES the claim (so the next
        // backoff window is open to any replica), and the row is no longer due, so
        // the claim is re-stamped directly rather than via the due scan.
        stamp_delivery_claim(&pool, d.id, me).await;
        mark_delivery_attempt(&pool, scope, d.id, me, false, Some("refused"), None, 30, 3)
            .await
            .unwrap();
        stamp_delivery_claim(&pool, d.id, me).await;
        let last =
            mark_delivery_attempt(&pool, scope, d.id, me, false, Some("refused"), None, 30, 3)
                .await
                .unwrap()
                .unwrap();
        assert_eq!((last.status.as_str(), last.attempts), ("failed", 3));

        // Success path on a second delivery.
        let d2 = enqueue_result_delivery(&pool, scope, session.id, None, &dest)
            .await
            .unwrap();
        stamp_delivery_claim(&pool, d2.id, me).await;
        let okd =
            mark_delivery_attempt(&pool, scope, d2.id, me, true, None, Some("sha256:x"), 0, 3)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(okd.status, "delivered");
        assert!(okd.delivered_at.is_some());
        assert_eq!(okd.payload_digest.as_deref(), Some("sha256:x"));

        let listed = list_session_deliveries(&pool, scope, session.id)
            .await
            .unwrap();
        assert_eq!(listed.len(), 2);

        sqlx::query("delete from sessions where id = $1")
            .bind(session.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn revision_default_workspace_roundtrips() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-ws",
            "name: test-ws",
            &serde_json::json!({"name": "test-ws"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-ws-agent", None)
            .await
            .unwrap();

        let ws = serde_json::json!({
            "kind": "git_repository",
            "clone_url": "https://github.com/o/r.git",
            "ref": "main"
        });
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            Some(&ws),
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        assert_eq!(rev.default_workspace, Some(ws));

        // A revision without one stays None.
        let rev2 = append_agent_revision(
            &pool,
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
        assert!(rev2.default_workspace.is_none());

        sqlx::query("delete from agent_revisions where agent_id = $1")
            .bind(agent.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from agents where id = $1")
            .bind(agent.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn capability_bundles_are_append_only_and_refs_roundtrip() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let name = format!("test-bundle-{}", Uuid::now_v7());

        let def_v1 = serde_json::json!({"servers": [{
            "class": "sandbox", "name": "ws", "command": "node",
            "args": ["/opt/x.mjs"],
            "tools": [{"name": "count", "description": "d", "input_schema": {"type": "object"}}]
        }]});
        let v1 = create_capability_bundle(&pool, scope, &name, Some("first"), &def_v1, "sha256:a")
            .await
            .unwrap();
        assert_eq!(v1.version, 1);

        // Publishing again appends version 2 — the v1 row never mutates.
        let v2 = create_capability_bundle(&pool, scope, &name, None, &def_v1, "sha256:b")
            .await
            .unwrap();
        assert_eq!(v2.version, 2);
        assert_ne!(v1.id, v2.id);
        let v1_again = get_capability_bundle(&pool, scope, v1.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(v1_again.definition_digest, "sha256:a");
        assert_eq!(
            latest_capability_bundle(&pool, scope, &name)
                .await
                .unwrap()
                .unwrap()
                .id,
            v2.id
        );
        assert_eq!(
            get_capability_bundle_version(&pool, scope, &name, 1)
                .await
                .unwrap()
                .unwrap()
                .id,
            v1.id
        );

        // Revision pins (§17 #7) + subscription keep-list roundtrip as jsonb.
        let policy = upsert_policy(
            &pool,
            scope,
            "test-cap",
            "name: test-cap",
            &serde_json::json!({"name": "test-cap"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-cap-agent", None)
            .await
            .unwrap();
        let pins = serde_json::json!([{"id": v1.id, "name": name, "version": 1}]);
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &pins,
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        assert_eq!(rev.capability_bundles, pins);

        let keep = serde_json::json!([name]);
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            &format!("test-cap-sub-{}", Uuid::now_v7()),
            "api",
            None,
            Some("t"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            Some(&keep),
        )
        .await
        .unwrap();
        assert_eq!(sub.capability_bundles, Some(keep));

        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from agent_revisions where agent_id = $1")
            .bind(agent.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from agents where id = $1")
            .bind(agent.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from capability_bundles where tenant_id = $1 and name = $2")
            .bind(tenant)
            .bind(&name)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn connector_catalog_seeded_and_custom_entries_forced_custom_tier() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        // The curated seeds are GLOBAL (tenant_id null); any valid scope sees
        // them via the tenant-or-global reader.
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        // Migration 0007 seeds the curated set (API-only settle: the
        // migration IS the seed; no file, no boot sync).
        let rows = list_catalog(&pool, scope).await.unwrap();
        assert!(rows.len() >= 7, "expected ≥7 seeded entries");
        let notion = get_catalog_by_slug(&pool, scope, "notion")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(notion.auth_mode, "oauth");
        assert_eq!(notion.tier, "verified");
        assert!(notion.tenant_id.is_none(), "curated seeds are global");
        let sentry = get_catalog_by_slug(&pool, scope, "sentry")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sentry.auth_hints["header_name"], "Sentry-Bearer");
        assert_eq!(sentry.auth_hints["scheme"], "");
        let ws = get_catalog_by_slug(&pool, scope, "workspace-info")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ws.transport, "stdio");
        assert!(ws.sandbox_launch.is_some());
        // Slack seed is explicitly deferred to the Phase-7 vertical.
        assert!(get_catalog_by_slug(&pool, scope, "slack")
            .await
            .unwrap()
            .is_none());
        // Verified entries sort ahead of custom ones.
        assert_eq!(rows[0].tier, "verified");

        let slug = format!("test-cat-{}", Uuid::now_v7().simple());
        let row = create_catalog_entry(
            &pool,
            scope,
            &slug,
            "Test entry",
            None,
            Some("test"),
            &serde_json::json!(["test"]),
            Some("https://mcp.example.test/mcp"),
            "streamable_http",
            "api_key",
            &serde_json::json!({}),
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap()
        .expect("custom entry lands");
        assert_eq!(row.tier, "custom", "API entries can't self-award tiers");
        assert_eq!(
            row.provenance["source"], "custom",
            "API entries carry a 'custom' provenance, distinct from seed + import"
        );
        assert_eq!(
            row.tenant_id,
            Some(tenant),
            "custom entries are tenant-scoped"
        );
        // The curated seed rows keep the fluidbox provenance the 0009 backfill
        // gave them — the import upsert predicate keys off exactly this, so an
        // import can never clobber a hand-curated verified entry.
        let gh = get_catalog_by_slug(&pool, scope, "github")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(gh.provenance["source"], "fluidbox");
        // Same-tenant slug re-insert conflicts (the per-tenant unique index).
        assert!(create_catalog_entry(
            &pool,
            scope,
            &slug,
            "dup",
            None,
            None,
            &serde_json::json!([]),
            None,
            "streamable_http",
            "none",
            &serde_json::json!({}),
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .is_err());

        sqlx::query("delete from connector_catalog where slug = $1")
            .bind(&slug)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn oauth_connection_lifecycle_pending_activate_rotate_error() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        // Pending OAuth connection: no credential yet.
        let conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "mcp.example.test",
            "oauth-lifecycle-test",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({"base_url": "https://mcp.example.test"}),
            None,
            1,
            ConnectionAuth {
                auth_kind: "oauth",
                status: "pending",
                oauth: Some(&serde_json::json!({"resource": "https://mcp.example.test"})),
                client_secret_sealed: Some(b"sealed-client-secret"),
                client_secret_key_version: 1,
                registration_id: None,
            },
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        assert_eq!(conn.auth_kind, "oauth");
        assert_eq!(conn.status, "pending");
        // Pending = no credential, and the active-only reader refuses.
        assert!(connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .is_none());
        // …but client identity IS readable while pending (the dance needs it).
        assert_eq!(
            connection_client_secret_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .map(|t| t.0)
                .as_deref(),
            Some(b"sealed-client-secret".as_slice())
        );
        // Rotation refuses non-active rows.
        assert!(
            !rotate_connection_refresh(&pool, scope, conn.id, b"rt1", 1, 1)
                .await
                .unwrap()
        );

        // Callback exchange: seal refresh + activate. First connect (from
        // `pending`) ⇒ no bump — the bump is derived from the row's pre-update
        // status inside the UPDATE (B1), not a caller boolean.
        // `flow_a_started` stands in for the flow row's `created_at` (frozen at
        // START, before any activation). It is read from the DB clock, exactly
        // like the real `connector_oauth_flows.created_at default now()` — the
        // comparison is DB-clock vs DB-clock, never the test host's clock.
        let db_now = |pool: PgPool| async move {
            sqlx::query_scalar::<_, DateTime<Utc>>("select clock_timestamp()")
                .fetch_one(&pool)
                .await
                .unwrap()
        };
        let flow_a_started = db_now(pool.clone()).await;
        let row = activate_connection_oauth(
            &pool,
            scope,
            conn.id,
            b"sealed-rt-1",
            1,
            &serde_json::json!({"resource": "https://mcp.example.test", "client_id": "c1"}),
            &serde_json::json!(["read"]),
            1,
            flow_a_started,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(row.status, "active");
        assert_eq!(
            row.authorization_generation, 1,
            "first activation stays generation 1 (no bump)"
        );
        // H2: a SIBLING first-connect flow — same frozen generation, started
        // before the winner activated — is now refused by the write itself. Its
        // generation expectation is still satisfiable (pending → active does not
        // bump), so the activation instant is the only thing that separates them.
        assert!(
            activate_connection_oauth(
                &pool,
                scope,
                conn.id,
                b"sealed-rt-sibling",
                1,
                &serde_json::json!({"resource": "https://mcp.example.test"}),
                &serde_json::json!([]),
                1,
                flow_a_started,
            )
            .await
            .unwrap()
            .is_none(),
            "a first-connect sibling flow must not overwrite the grant that activated first"
        );
        assert_eq!(
            connection_credential_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .map(|t| t.0)
                .as_deref(),
            Some(b"sealed-rt-1".as_slice()),
            "the superseded sibling left the winner's refresh token untouched"
        );
        // H2: a flow START rewrites the oauth bag from a value it read BEFORE the
        // activation. The activation stamp must survive that read-modify-write —
        // erasing it would hand the superseded sibling a passing expectation.
        // In production this write now rides the start's lock-holding transaction
        // (#32), so the carry-over is belt-and-braces there; it stays the ONLY
        // protection for a caller that passes a bare pool, as here.
        update_connection_oauth(
            &pool,
            scope,
            conn.id,
            &serde_json::json!({"resource": "https://mcp.example.test", "issuer": "https://as"}),
        )
        .await
        .unwrap();
        let after_start = get_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap()
            .oauth
            .unwrap();
        assert!(
            after_start.get(ACTIVATED_AT_KEY).is_some(),
            "the activation stamp survives a flow-start bag rewrite"
        );
        assert_eq!(after_start["issuer"], "https://as", "the rest is replaced");
        assert!(
            activate_connection_oauth(
                &pool,
                scope,
                conn.id,
                b"sealed-rt-sibling-2",
                1,
                &serde_json::json!({"resource": "https://mcp.example.test"}),
                &serde_json::json!([]),
                1,
                flow_a_started,
            )
            .await
            .unwrap()
            .is_none(),
            "the sibling is still refused after a concurrent flow start"
        );
        assert_eq!(
            connection_credential_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .map(|t| t.0)
                .as_deref(),
            Some(b"sealed-rt-1".as_slice())
        );

        // Rotation is one atomic overwrite AT the current generation; the old
        // bytes are gone.
        assert!(
            rotate_connection_refresh(&pool, scope, conn.id, b"sealed-rt-2", 1, 1)
                .await
                .unwrap()
        );
        assert_eq!(
            connection_credential_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .map(|t| t.0)
                .as_deref(),
            Some(b"sealed-rt-2".as_slice())
        );
        // A rotation naming a stale (moved) generation is refused (R3.2): the
        // grant was reauthorized underneath the in-flight refresh.
        assert!(
            !rotate_connection_refresh(&pool, scope, conn.id, b"sealed-rt-stale", 1, 999)
                .await
                .unwrap(),
            "rotation at a superseded generation must fail closed"
        );

        // invalid_grant ⇒ error: the credential reader fails closed; the
        // error note lands in oauth jsonb for the dashboard.
        mark_connection_error(&pool, scope, conn.id, "invalid_grant: reconnect required")
            .await
            .unwrap();
        let row = get_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "error");
        assert!(row.oauth.unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("invalid_grant"));
        assert!(connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .is_none());

        // Reconnect path: activation works FROM error too, and bumps the
        // generation atomically (R1.3+R3.1) — the reconnect may be a new grant.
        // The bump is derived from the pre-update status (`error` <> `pending`).
        let flow_b_started = db_now(pool.clone()).await;
        // H2: a reconnect flow frozen at a STALE generation is refused by the
        // write, even though its start-time instant is fresh.
        assert!(
            activate_connection_oauth(
                &pool,
                scope,
                conn.id,
                b"sealed-rt-stale-gen",
                1,
                &serde_json::json!({"resource": "https://mcp.example.test"}),
                &serde_json::json!([]),
                999,
                flow_b_started,
            )
            .await
            .unwrap()
            .is_none(),
            "activation at a superseded generation must fail closed"
        );
        let row = activate_connection_oauth(
            &pool,
            scope,
            conn.id,
            b"sealed-rt-3",
            1,
            &serde_json::json!({"resource": "https://mcp.example.test"}),
            &serde_json::json!([]),
            1,
            flow_b_started,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(row.status, "active");
        assert_eq!(
            row.authorization_generation, 2,
            "reconnect bumps the generation in the same atomic activation"
        );

        // B1 regression: re-activating an ALREADY-active row bumps again — proving
        // the bump is derived from the row's live status under the lock, not from
        // a pre-lock read (two racing first-connects that both saw `pending`).
        // H2: it takes a flow that started AFTER the last activation and names the
        // now-current generation — i.e. a genuinely newer authorization, which is
        // exactly what the CAS admits (and the superseded ones above it refuses).
        let flow_c_started = db_now(pool.clone()).await;
        let row = activate_connection_oauth(
            &pool,
            scope,
            conn.id,
            b"sealed-rt-4",
            1,
            &serde_json::json!({"resource": "https://mcp.example.test"}),
            &serde_json::json!([]),
            2,
            flow_c_started,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            row.authorization_generation, 3,
            "activating the now-active row bumps again (status <> 'pending')"
        );
        // H2: replaying that same flow (its instant is now older than the
        // activation it just performed) matches nothing — one activation per flow,
        // enforced by the write, not only by the one-time claim.
        assert!(
            activate_connection_oauth(
                &pool,
                scope,
                conn.id,
                b"sealed-rt-replay",
                1,
                &serde_json::json!({"resource": "https://mcp.example.test"}),
                &serde_json::json!([]),
                3,
                flow_c_started,
            )
            .await
            .unwrap()
            .is_none(),
            "a flow cannot activate twice: its start instant is older than its own activation"
        );
        assert_eq!(
            connection_credential_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .map(|t| t.0)
                .as_deref(),
            Some(b"sealed-rt-4".as_slice())
        );

        sqlx::query("delete from integration_connections where id = $1")
            .bind(conn.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// `just policy-sync` force-pushes the AUTHORED yaml. It must not take the
    /// Governance page's per-tool decisions with it — and `parsed` (what
    /// `run_service` actually evaluates) must carry them on every write.
    #[tokio::test]
    async fn upsert_preserves_managed_overrides() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let yaml = "name: ov-test\ntools: []\n";
        let policy = fluidbox_core::policy::Policy::parse_yaml(yaml).unwrap();
        let parsed = serde_json::to_value(&policy).unwrap();
        upsert_policy(&pool, scope, "ov-test", yaml, &parsed)
            .await
            .unwrap();
        // Reset any override left behind by a previous (or crashed) run.
        clear_policy_override(&pool, scope, "ov-test", "mcp__x__y")
            .await
            .unwrap();

        set_policy_override(
            &pool,
            scope,
            "ov-test",
            "mcp__x__y",
            fluidbox_core::policy::RuleAction::Allow,
        )
        .await
        .unwrap();

        // A policy-sync re-push of the SAME yaml must not drop the override.
        let row = upsert_policy(&pool, scope, "ov-test", yaml, &parsed)
            .await
            .unwrap();
        let overrides: Vec<fluidbox_core::policy::ToolOverride> =
            serde_json::from_value(row.managed_overrides.clone()).unwrap();
        assert_eq!(overrides.len(), 1, "policy-sync dropped the override");
        assert_eq!(overrides[0].tool, "mcp__x__y");

        // …and `parsed` must carry it, because run_service evaluates from `parsed`.
        let effective: fluidbox_core::policy::Policy =
            serde_json::from_value(row.parsed.clone()).unwrap();
        assert_eq!(effective.managed_overrides.len(), 1);
        assert_eq!(
            effective.managed_overrides[0].action,
            fluidbox_core::policy::RuleAction::Allow
        );

        // Re-setting the SAME tool replaces, never duplicates.
        let row = set_policy_override(
            &pool,
            scope,
            "ov-test",
            "mcp__x__y",
            fluidbox_core::policy::RuleAction::Deny,
        )
        .await
        .unwrap();
        let effective: fluidbox_core::policy::Policy =
            serde_json::from_value(row.parsed.clone()).unwrap();
        assert_eq!(effective.managed_overrides.len(), 1);
        assert_eq!(
            effective.managed_overrides[0].action,
            fluidbox_core::policy::RuleAction::Deny
        );

        clear_policy_override(&pool, scope, "ov-test", "mcp__x__y")
            .await
            .unwrap();
        let row = get_policy_by_name(&pool, scope, "ov-test")
            .await
            .unwrap()
            .unwrap();
        let effective: fluidbox_core::policy::Policy =
            serde_json::from_value(row.parsed.clone()).unwrap();
        assert!(effective.managed_overrides.is_empty());
        let overrides: Vec<fluidbox_core::policy::ToolOverride> =
            serde_json::from_value(row.managed_overrides.clone()).unwrap();
        assert!(overrides.is_empty());
    }

    /// Only the LATEST revision governs future runs, so only it may count toward a
    /// policy's blast radius. Uses fresh policy names, so the shared default tenant's
    /// other agents cannot perturb the counts.
    #[tokio::test]
    async fn policy_agents_using_counts_only_latest_revisions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        let mk = |name: &str| format!("name: {name}\ntools: []\n");
        let (ya, yb) = (mk("pau-a"), mk("pau-b"));
        let pa = upsert_policy(
            &pool,
            scope,
            "pau-a",
            &ya,
            &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(&ya).unwrap()).unwrap(),
        )
        .await
        .unwrap();
        let pb = upsert_policy(
            &pool,
            scope,
            "pau-b",
            &yb,
            &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(&yb).unwrap()).unwrap(),
        )
        .await
        .unwrap();

        let agent = create_agent(&pool, scope, "pau-agent", None).await.unwrap();
        let budgets = serde_json::json!({});
        let pins = serde_json::json!([]);
        let reqs = serde_json::json!([]);
        let rev = |policy_id| {
            append_agent_revision(
                &pool,
                scope,
                agent.id,
                "claude-agent-sdk",
                "img",
                "claude-haiku-4-5",
                None,
                policy_id,
                &budgets,
                None,
                &pins,
                &reqs,
            )
        };

        rev(pa.id).await.unwrap();
        assert_eq!(policy_agents_using(&pool, scope, pa.id).await.unwrap(), 1);
        assert_eq!(policy_agents_using(&pool, scope, pb.id).await.unwrap(), 0);

        // Append a revision moving the agent to policy B: A drops to 0, B goes to 1.
        rev(pb.id).await.unwrap();
        assert_eq!(policy_agents_using(&pool, scope, pa.id).await.unwrap(), 0);
        assert_eq!(policy_agents_using(&pool, scope, pb.id).await.unwrap(), 1);
    }

    /// The matrix's MCP rows come from what the agents on this policy can actually
    /// call: the union of the photographed tools in the bundles pinned on their
    /// LATEST revisions — sorted, and deduplicated across agents sharing a bundle.
    #[tokio::test]
    async fn policy_mcp_tools_unions_pinned_bundle_tools() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        let yaml = "name: pmt-policy\ntools: []\n";
        let policy = upsert_policy(
            &pool,
            scope,
            "pmt-policy",
            yaml,
            &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(yaml).unwrap())
                .unwrap(),
        )
        .await
        .unwrap();

        // Tools are declared out of alphabetical order: the union must sort them.
        let bundle_name = format!("pmt-bundle-{}", Uuid::now_v7());
        let def = serde_json::json!({"servers": [{
            "class": "brokered", "name": "beta",
            "tools": [
                {"name": "zeta", "description": "d", "input_schema": {"type": "object"}},
                {"name": "alpha", "description": "d", "input_schema": {"type": "object"}}
            ]
        }]});
        let bundle = create_capability_bundle(&pool, scope, &bundle_name, None, &def, "sha256:pmt")
            .await
            .unwrap();
        let pins = serde_json::json!([
            { "id": bundle.id, "name": bundle.name, "version": bundle.version }
        ]);

        // Two agents share the bundle: the union deduplicates across them.
        let budgets = serde_json::json!({});
        for name in ["pmt-agent-a", "pmt-agent-b"] {
            let agent = create_agent(&pool, scope, name, None).await.unwrap();
            append_agent_revision(
                &pool,
                scope,
                agent.id,
                "claude-agent-sdk",
                "img",
                "claude-haiku-4-5",
                None,
                policy.id,
                &budgets,
                None,
                &pins,
                &serde_json::json!([]),
            )
            .await
            .unwrap();
        }

        assert_eq!(
            policy_mcp_tools(&pool, scope, policy.id).await.unwrap(),
            vec![
                "mcp__beta__alpha".to_string(),
                "mcp__beta__zeta".to_string()
            ]
        );

        // A policy nobody's latest revision points at contributes no tools.
        let empty_yaml = "name: pmt-empty\ntools: []\n";
        let empty = upsert_policy(
            &pool,
            scope,
            "pmt-empty",
            empty_yaml,
            &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(empty_yaml).unwrap())
                .unwrap(),
        )
        .await
        .unwrap();
        assert!(policy_mcp_tools(&pool, scope, empty.id)
            .await
            .unwrap()
            .is_empty());
    }

    /// Run migration 0013's legacy-bundle conversion RLS-BOUND — the ONLY
    /// sanctioned way for a test to invoke it (see the source guard
    /// `conversion_is_only_ever_invoked_rls_bound`).
    ///
    /// WHY (CI round 4, #32). The conversion is a deliberately tenant-LESS
    /// maintenance scan — `for v_agent in select id, tenant_id from agents` — and it
    /// allocates each appended revision's `rev` from a per-agent counter seeded by
    /// the current `max(rev)`. Called bare on the shared test database it therefore
    /// converts EVERY other test's agents as well as its own, and two calls in
    /// flight at the same moment both read `max(rev) = 1` and both insert rev 2: the
    /// loser waits on `agent_revisions_agent_id_rev_key` and dies with 23505. That
    /// is exactly how CI failed — the three conversion tests all ran within 300 ms
    /// of each other and one of them had its own agent converted out from under it.
    ///
    /// The confinement has to be RLS, because the function takes no tenant
    /// argument. A DEDICATED connection `SET ROLE`s to migration 0018's runtime role
    /// — CI's base user is the SUPERUSER `postgres`, for whom Postgres skips every
    /// policy, so the `SET ROLE` is what makes the policy run at all — and then sets
    /// `fluidbox.tenant_id`. The function is SECURITY INVOKER, so every read and
    /// write inside it is policy-filtered to `tenant`: a test can now only ever
    /// convert its own throwaway org, whatever else is running beside it.
    ///
    /// The connection is dedicated, never borrowed from the fixture pool, because
    /// `SET ROLE` is SESSION state and would ride a pooled connection back to the
    /// next borrower.
    ///
    /// `tenant: None` sets NO GUC at all. That is used once, on purpose, to prove
    /// the degraded mode of a GUC-less caller: zero visible `agents` rows means the
    /// loop body never runs, so the conversion is a silent NO-OP rather than a
    /// miscomputed append.
    async fn convert_legacy_bundles_rls_bound(url: &str, tenant: Option<Uuid>) {
        use sqlx::{Connection, Executor};
        let mut conn = sqlx::PgConnection::connect(url)
            .await
            .expect("conversion connection");
        conn.execute("set role fluidbox_runtime")
            .await
            .expect("set role fluidbox_runtime (migration 0018 creates + grants it)");
        let mut tx = conn.begin().await.expect("begin conversion tx");
        if let Some(t) = tenant {
            sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
                .bind(t.to_string())
                .execute(&mut *tx)
                .await
                .expect("tenant guc");
        }
        sqlx::query("select fluidbox_convert_legacy_bundles()")
            .execute(&mut *tx)
            .await
            .expect("conversion");
        tx.commit().await.expect("commit conversion tx");
        conn.close().await.ok();
    }

    /// Source guard for the CI-round-4 class (#32). The conversion is tenant-less
    /// and races on `max(rev)`, so ANY caller outside
    /// `convert_legacy_bundles_rls_bound` reintroduces the cross-test collision.
    /// This is a source assertion, not a DB test: it runs even without
    /// `DATABASE_URL`, so a re-added bare caller fails CI immediately instead of
    /// flaking. The needle is assembled from two halves so this guard is not itself
    /// an occurrence of it.
    #[test]
    fn conversion_is_only_ever_invoked_rls_bound() {
        let needle = concat!("select fluidbox_convert_legacy", "_bundles()");
        let n = include_str!("lib.rs").matches(needle).count();
        assert_eq!(
            n, 1,
            "`{needle}` must appear exactly ONCE in fluidbox-db (inside \
             convert_legacy_bundles_rls_bound) — found {n}. Route the new call through that \
             helper: a bare pool call converts every other test's agents and races them for \
             the next rev (23505 on agent_revisions_agent_id_rev_key)."
        );
    }

    /// Migration 0013 appendix (`fluidbox_convert_legacy_bundles`): a legacy
    /// agent whose LATEST revision pins a brokered bundle gets an APPENDED
    /// sandbox-only revision whose brokered servers became
    /// `connection_requirements`; its pinned subscription is repointed; and a
    /// second call is idempotent. Also proves the SQL-built requirement jsonb
    /// round-trips into typed `ConnectionRequirement`s (serde compatibility) and
    /// that `policy_mcp_tools` unions the converted requirement tools. Throwaway
    /// org; children-first cleanup BEFORE the asserts.
    #[tokio::test]
    async fn convert_legacy_bundles_appends_requirements_and_repoints() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);

        // Two brokered endpoints — one matches a tenant catalog row (slug hint),
        // one has no catalog row (slug null) — so the stored jsonb exercises BOTH
        // slug shapes and the reverse-match's tenant-first / unique-or-null rule.
        let gh_url = "https://mcp.github.test/mcp";
        let ln_url = "https://mcp.linear.test/mcp";

        // An org-owned mcp_http connection: the legacy world embedded its id in
        // the brokered server (Gap 3). The conversion DROPS that id — we build the
        // connection only for realism and to prove the conversion ignores it.
        let conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "mcp.github.test",
            "GitHub MCP",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({ "base_url": gh_url }),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        // A tenant-owned catalog row whose url == gh_url → reverse-match slug.
        sqlx::query(
            "insert into connector_catalog (id, slug, name, url, tenant_id, provenance)
             values ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::now_v7())
        .bind("github-mcp")
        .bind("GitHub MCP")
        .bind(gh_url)
        .bind(org.id)
        .bind(serde_json::json!({ "source": "custom" }))
        .execute(&pool)
        .await
        .unwrap();

        // A brokered bundle: two brokered servers (github matched, linear not);
        // github ships two tools in a deliberate order, linear one.
        let brokered_def = serde_json::json!({ "servers": [
            { "class": "brokered", "name": "github", "url": gh_url,
              "connection_id": conn.id,
              "tools": [
                { "name": "get_pull_request", "description": "d", "input_schema": {"type": "object"} },
                { "name": "create_review", "description": "d", "input_schema": {"type": "object"} }
              ] },
            { "class": "brokered", "name": "linear", "url": ln_url,
              "connection_id": conn.id,
              "tools": [
                { "name": "list_issues", "description": "d", "input_schema": {"type": "object"} }
              ] }
        ] });
        let brokered_bundle = create_capability_bundle(
            &pool,
            scope,
            "connectors",
            None,
            &brokered_def,
            "sha256:brk",
        )
        .await
        .unwrap();

        // A sandbox-only bundle: survives, re-pinned as sandbox-tools@1.
        let sandbox_def = serde_json::json!({ "servers": [
            { "class": "sandbox", "name": "ws", "command": "node", "args": ["/x.mjs"],
              "tools": [ { "name": "count", "description": "d", "input_schema": {"type": "object"} } ] }
        ] });
        let sandbox_bundle = create_capability_bundle(
            &pool,
            scope,
            "sandbox-tools",
            None,
            &sandbox_def,
            "sha256:sbx",
        )
        .await
        .unwrap();

        let policy = upsert_policy(
            &pool,
            scope,
            "conv-policy",
            "name: conv",
            &serde_json::json!({ "name": "conv" }),
        )
        .await
        .unwrap();

        let agent = create_agent(&pool, scope, "conv-agent", None)
            .await
            .unwrap();
        // rev 1 pins BOTH bundles as BundleRef objects (the live stored shape).
        let pins = serde_json::json!([
            { "id": brokered_bundle.id, "name": brokered_bundle.name, "version": brokered_bundle.version },
            { "id": sandbox_bundle.id, "name": sandbox_bundle.name, "version": sandbox_bundle.version }
        ]);
        let rev1 = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            Some("be helpful"),
            policy.id,
            &serde_json::json!({ "wall_clock_secs": 60 }),
            Some(&serde_json::json!({ "kind": "scratch" })),
            &pins,
            &serde_json::json!([]),
        )
        .await
        .unwrap();

        // A subscription pinned to rev 1 — must be repointed to the new revision.
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            "conv-sub",
            "api",
            Some(rev1.id),
            Some("do it"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // ── Convert (the DB test calls the function 0013 defined + already ran),
        // RLS-BOUND and confined to this org so it cannot reach — or race — the
        // other conversion tests' agents. ──
        convert_legacy_bundles_rls_bound(&url, Some(org.id)).await;

        let latest = latest_revision(&pool, scope, agent.id)
            .await
            .unwrap()
            .unwrap();
        let sub_after = get_trigger_subscription(&pool, scope, sub.id)
            .await
            .unwrap()
            .unwrap();
        let revs_after = list_revisions(&pool, scope, agent.id).await.unwrap();

        // Idempotence: a SECOND call must not append again.
        convert_legacy_bundles_rls_bound(&url, Some(org.id)).await;
        let revs_after2 = list_revisions(&pool, scope, agent.id).await.unwrap();
        let latest2 = latest_revision(&pool, scope, agent.id)
            .await
            .unwrap()
            .unwrap();

        // Governance union AND serde round-trip captured before cleanup.
        let mcp_tools = policy_mcp_tools(&pool, scope, policy.id).await.unwrap();
        let req_parse: Result<
            Vec<fluidbox_core::capability::ConnectionRequirement>,
            serde_json::Error,
        > = serde_json::from_value(latest.connection_requirements.clone());

        // ── Cleanup children-first BEFORE the asserts (throwaway org) ──
        for stmt in [
            "delete from run_resource_bindings where tenant_id = $1",
            "delete from connection_tool_snapshots where tenant_id = $1",
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from capability_bundles where tenant_id = $1",
            "delete from connector_catalog where tenant_id = $1",
            "delete from integration_connections where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org.id).execute(&pool).await.unwrap();
        }
        sqlx::query("delete from tenants where id = $1")
            .bind(org.id)
            .execute(&pool)
            .await
            .unwrap();

        // ── Asserts ──
        // A new immutable revision was appended at rev+1, copying the revision's
        // fields verbatim.
        assert_eq!(latest.rev, rev1.rev + 1, "conversion appends rev+1");
        assert_ne!(latest.id, rev1.id);
        assert_eq!(latest.harness, rev1.harness);
        assert_eq!(latest.runner_image, rev1.runner_image);
        assert_eq!(latest.model, rev1.model);
        assert_eq!(latest.system_prompt, rev1.system_prompt);
        assert_eq!(latest.policy_id, rev1.policy_id);
        assert_eq!(latest.budgets, rev1.budgets);
        assert_eq!(latest.default_workspace, rev1.default_workspace);

        // Only the sandbox-only bundle survives, re-pinned EXPLICITLY as an exact
        // BundleRef (version 1 IS the `name@1` pin run_service deserializes).
        assert_eq!(
            latest.capability_bundles,
            serde_json::json!([
                { "id": sandbox_bundle.id, "name": "sandbox-tools", "version": 1 }
            ]),
            "only the sandbox-only bundle survives, re-pinned name@1"
        );

        // Requirements EXACTLY as specified: bundle-pin then server order, tool
        // order preserved, binding_mode organization, slug matched then null.
        assert_eq!(
            latest.connection_requirements,
            serde_json::json!([
                { "slot": "github",
                  "connector": { "url": gh_url, "slug": "github-mcp" },
                  "required_tools": ["get_pull_request", "create_review"],
                  "binding_mode": "organization" },
                { "slot": "linear",
                  "connector": { "url": ln_url, "slug": null },
                  "required_tools": ["list_issues"],
                  "binding_mode": "organization" }
            ]),
            "requirements derived deterministically from the brokered servers"
        );

        // The SQL-built jsonb round-trips into typed requirements AND passes
        // validate_requirements — pins serde compatibility of both slug shapes.
        let reqs = req_parse.expect("stored requirements deserialize into ConnectionRequirement");
        fluidbox_core::capability::validate_requirements(&reqs)
            .expect("converted requirements are valid");
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].slot, "github");
        assert_eq!(reqs[0].connector.slug.as_deref(), Some("github-mcp"));
        assert_eq!(reqs[1].slot, "linear");
        assert_eq!(reqs[1].connector.slug, None);
        assert!(matches!(
            reqs[0].binding_mode,
            fluidbox_core::capability::BindingMode::Organization
        ));

        // The pinned subscription was repointed to the new revision.
        assert_eq!(
            sub_after.pinned_revision_id,
            Some(latest.id),
            "subscription repointed to the converted revision"
        );

        // Exactly one revision appended, and the second call added none.
        assert_eq!(revs_after.len(), 2, "exactly one revision appended");
        assert_eq!(
            revs_after2.len(),
            2,
            "second call is idempotent — no double-append"
        );
        assert_eq!(
            latest2.id, latest.id,
            "latest unchanged after idempotent re-run"
        );

        // policy_mcp_tools unions the converted requirement tools with the
        // surviving sandbox bundle's tools.
        for t in [
            "mcp__github__get_pull_request",
            "mcp__github__create_review",
            "mcp__linear__list_issues",
            "mcp__ws__count",
        ] {
            assert!(
                mcp_tools.contains(&t.to_string()),
                "policy_mcp_tools missing {t}"
            );
        }
    }

    /// Migration 0013 appendix — branch coverage the happy path above never
    /// reaches: (a) a brokered server with EMPTY tools is skipped while its
    /// bundle-mates still convert; (b) two pinned bundles whose brokered servers
    /// share an alias dedup to `slot` / `slot-2` in encounter order; (c) a SECOND
    /// agent in the same call also converts (both get new revisions); (d) an
    /// agent with NO subscription converts cleanly (nothing to repoint); (e) an
    /// unresolvable BundleRef object AND a non-numeric `name@abc` string pin
    /// (Finding 3) are both dropped without aborting, the other pins converting;
    /// (f) the RLS degraded mode — the same function on an RLS-bound connection with
    /// NO GUC converts NOTHING (a silent no-op, never a partial append).
    /// One conversion call (RLS-bound, confined to this org — see
    /// `convert_legacy_bundles_rls_bound`); throwaway org; children-first cleanup
    /// BEFORE asserts.
    #[tokio::test]
    async fn convert_legacy_bundles_covers_skip_dedup_multiagent_and_unresolvable() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);

        // Small builders so the fixtures read as data, not boilerplate.
        let brokered = |name: &str, url: &str, tools: &[&str]| -> serde_json::Value {
            let tools_json: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!(
                        { "name": t, "description": "d", "input_schema": {"type": "object"} }
                    )
                })
                .collect();
            serde_json::json!({ "class": "brokered", "name": name, "url": url, "tools": tools_json })
        };
        let sandbox = |name: &str| -> serde_json::Value {
            serde_json::json!({ "class": "sandbox", "name": name, "command": "node", "args": ["/x.mjs"],
                "tools": [ { "name": "count", "description": "d", "input_schema": {"type": "object"} } ] })
        };

        let policy = upsert_policy(
            &pool,
            scope,
            "cov-policy",
            "name: cov",
            &serde_json::json!({ "name": "cov" }),
        )
        .await
        .unwrap();

        // ── Agent A: a MIXED bundle (brokered-with-tools + brokered-EMPTY +
        // sandbox) then a second bundle re-using the `dup` alias, then two
        // unresolvable pins (a missing BundleRef object and a `ghost@abc`
        // string). No subscription. ──
        let dup_a_url = "https://a.dup.test/mcp";
        let dup_b_url = "https://b.dup.test/mcp";
        let bundle_dup_a = create_capability_bundle(
            &pool,
            scope,
            "dup-a",
            None,
            &serde_json::json!({ "servers": [
                brokered("dup", dup_a_url, &["a_one", "a_two"]),
                brokered("empty", "https://empty.test/mcp", &[]),
                sandbox("sbx"),
            ] }),
            "sha256:dupa",
        )
        .await
        .unwrap();
        let bundle_dup_b = create_capability_bundle(
            &pool,
            scope,
            "dup-b",
            None,
            &serde_json::json!({ "servers": [ brokered("dup", dup_b_url, &["b_one"]) ] }),
            "sha256:dupb",
        )
        .await
        .unwrap();

        let agent_a = create_agent(&pool, scope, "cov-agent-a", None)
            .await
            .unwrap();
        let pins_a = serde_json::json!([
            { "id": bundle_dup_a.id, "name": bundle_dup_a.name, "version": bundle_dup_a.version },
            { "id": bundle_dup_b.id, "name": bundle_dup_b.name, "version": bundle_dup_b.version },
            // (e) unresolvable BundleRef object — random id, no such bundle.
            { "id": Uuid::now_v7(), "name": "ghost", "version": 1 },
            // (Finding 3) non-numeric `name@N` string — must drop, not abort.
            "ghost@abc"
        ]);
        let rev_a1 = append_agent_revision(
            &pool,
            scope,
            agent_a.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            Some("be helpful"),
            policy.id,
            &serde_json::json!({ "wall_clock_secs": 60 }),
            None,
            &pins_a,
            &serde_json::json!([]),
        )
        .await
        .unwrap();

        // ── Agent B: a second agent with its own brokered pin and a pinned
        // subscription that must be repointed. ──
        let jira_url = "https://jira.test/mcp";
        let bundle_solo_b = create_capability_bundle(
            &pool,
            scope,
            "solo-b",
            None,
            &serde_json::json!({ "servers": [ brokered("jira", jira_url, &["search"]) ] }),
            "sha256:solob",
        )
        .await
        .unwrap();
        let agent_b = create_agent(&pool, scope, "cov-agent-b", None)
            .await
            .unwrap();
        let pins_b = serde_json::json!([
            { "id": bundle_solo_b.id, "name": bundle_solo_b.name, "version": bundle_solo_b.version }
        ]);
        let rev_b1 = append_agent_revision(
            &pool,
            scope,
            agent_b.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            Some("be helpful"),
            policy.id,
            &serde_json::json!({ "wall_clock_secs": 60 }),
            None,
            &pins_b,
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let sub_b = create_trigger_subscription(
            &pool,
            scope,
            agent_b.id,
            "cov-sub-b",
            "api",
            Some(rev_b1.id),
            Some("do it"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // ── (f) GUC guard, asserted below: the SAME function on an RLS-BOUND
        // connection with NEITHER GUC set sees zero `agents` rows, so its loop body
        // never runs and it converts NOTHING. Pinning that here keeps the degraded
        // mode honest — a GUC-less caller is a silent NO-OP, never a partial or
        // miscomputed append — and proves the confinement below is real RLS rather
        // than coincidence. ──
        convert_legacy_bundles_rls_bound(&url, None).await;
        let revs_a_gucless = list_revisions(&pool, scope, agent_a.id)
            .await
            .unwrap()
            .len();
        let revs_b_gucless = list_revisions(&pool, scope, agent_b.id)
            .await
            .unwrap()
            .len();

        // ── One conversion call processes BOTH agents (c) — RLS-BOUND and confined
        // to this org, so it can neither reach nor race the other conversion
        // tests' agents (they are in their own throwaway orgs). ──
        convert_legacy_bundles_rls_bound(&url, Some(org.id)).await;

        let latest_a = latest_revision(&pool, scope, agent_a.id)
            .await
            .unwrap()
            .unwrap();
        let latest_b = latest_revision(&pool, scope, agent_b.id)
            .await
            .unwrap()
            .unwrap();
        let revs_a = list_revisions(&pool, scope, agent_a.id).await.unwrap();
        let revs_b = list_revisions(&pool, scope, agent_b.id).await.unwrap();
        let sub_b_after = get_trigger_subscription(&pool, scope, sub_b.id)
            .await
            .unwrap()
            .unwrap();

        // ── Cleanup children-first BEFORE the asserts (throwaway org) ──
        for stmt in [
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from capability_bundles where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org.id).execute(&pool).await.unwrap();
        }
        sqlx::query("delete from tenants where id = $1")
            .bind(org.id)
            .execute(&pool)
            .await
            .unwrap();

        // ── Asserts ──
        // (f) The GUC-less call converted NOTHING: both agents still stood at their
        // single seed revision when the confined call ran. This is the fail-closed
        // direction of the RLS contract — invisible rows mean no work, not wrong work.
        assert_eq!(
            (revs_a_gucless, revs_b_gucless),
            (1, 1),
            "a GUC-less conversion must be a silent NO-OP (RLS hides every agent row)"
        );

        // (c) BOTH agents converted in the single call — each has exactly two
        // revisions, the new one appended at rev+1.
        assert_eq!(revs_a.len(), 2, "agent A converted (rev appended)");
        assert_eq!(revs_b.len(), 2, "agent B converted in the SAME call (c)");
        assert_eq!(latest_a.rev, rev_a1.rev + 1);
        assert_eq!(latest_b.rev, rev_b1.rev + 1);

        // (a)+(b)+(e)+Finding 3: agent A's requirements are EXACTLY the two
        // brokered servers that carried tools — `empty` skipped (a), sandbox
        // dropped, both unresolvable pins gone (e / Finding 3) — with the shared
        // alias dedup'd in encounter order: `dup` (from dup-a) then `dup-2`
        // (from dup-b), each connector.url proving which bundle it came from.
        assert_eq!(
            latest_a.connection_requirements,
            serde_json::json!([
                { "slot": "dup",
                  "connector": { "url": dup_a_url, "slug": null },
                  "required_tools": ["a_one", "a_two"],
                  "binding_mode": "organization" },
                { "slot": "dup-2",
                  "connector": { "url": dup_b_url, "slug": null },
                  "required_tools": ["b_one"],
                  "binding_mode": "organization" }
            ]),
            "empty-tools skipped, sandbox dropped, unresolvable pins dropped, alias dedup'd"
        );
        // The dedup'd shape still validates — proves the suffixed slot `dup-2`
        // is a legal server alias, and pins the exact slot names + suffix.
        let reqs_a: Vec<fluidbox_core::capability::ConnectionRequirement> =
            serde_json::from_value(latest_a.connection_requirements.clone())
                .expect("agent A requirements deserialize");
        fluidbox_core::capability::validate_requirements(&reqs_a)
            .expect("dedup'd requirements (incl. slot 'dup-2') are valid");
        let slots_a: Vec<&str> = reqs_a.iter().map(|r| r.slot.as_str()).collect();
        assert_eq!(slots_a, ["dup", "dup-2"], "alias dedup order: dup, dup-2");

        // (d)+(e): agent A pinned no surviving sandbox-only bundle and both
        // unresolvable pins were dropped, so the copied pin list is empty.
        assert_eq!(
            latest_a.capability_bundles,
            serde_json::json!([]),
            "no surviving pins (mixed bundle + unresolvable pins all dropped)"
        );

        // (c)+repoint: agent B has its single requirement, and its subscription
        // was repointed to the converted revision (repoint count where
        // applicable; agent A had no subscription to repoint — d).
        assert_eq!(
            latest_b.connection_requirements,
            serde_json::json!([
                { "slot": "jira",
                  "connector": { "url": jira_url, "slug": null },
                  "required_tools": ["search"],
                  "binding_mode": "organization" }
            ]),
            "agent B's lone brokered server became one requirement"
        );
        assert_eq!(
            sub_b_after.pinned_revision_id,
            Some(latest_b.id),
            "agent B's subscription repointed to its converted revision"
        );
    }

    /// Migration 0013 appendix — per-source-revision conversion + keep-list
    /// preserving repoints (R1.1/R1.2). Covers: (i) a subscription pinned to an
    /// OLDER brokered revision gets a copy carrying THAT revision's model/prompt
    /// while the latest converts separately; (ii) a sandbox-only latest above a
    /// pinned brokered old revision converts the pinned source and — append-only
    /// being sacred (A2) — the sandbox latest is CLONED (never rewritten) as the
    /// new `latest`; (iii) a restrictive keep-list narrows the derived
    /// requirements; (iv) an empty keep-list ⇒ zero requirements; (v) idempotence;
    /// (A1) FLOATING subscriptions — a restrictive/empty keep-list floater is
    /// pinned to a tailored copy, a NULL keep-list floater keeps floating.
    #[tokio::test]
    async fn convert_legacy_bundles_per_source_revision_and_keep_lists() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);

        let gh_url = "https://mcp.github.test/mcp";
        let stripe_url = "https://mcp.stripe.test/mcp";
        let q_url = "https://mcp.q.test/mcp";

        let brok_def = |srv: &str, url: &str, tool: &str| {
            serde_json::json!({ "servers": [
                { "class": "brokered", "name": srv, "url": url, "tools": [
                    { "name": tool, "description": "d", "input_schema": {"type": "object"} } ] } ] })
        };
        let sand_def = |srv: &str| {
            serde_json::json!({ "servers": [
                { "class": "sandbox", "name": srv, "command": "node", "args": ["/x.mjs"], "tools": [
                    { "name": "t", "description": "d", "input_schema": {"type": "object"} } ] } ] })
        };
        let pin = |b: &CapabilityBundleRow| serde_json::json!({ "id": b.id, "name": b.name, "version": b.version });
        let policy = upsert_policy(
            &pool,
            scope,
            "psr-policy",
            "name: psr",
            &serde_json::json!({ "name": "psr" }),
        )
        .await
        .unwrap();
        let mk_rev = |agent_id: Uuid, model: &'static str, prompt: &'static str, pins: Value| {
            let pool = pool.clone();
            let pid = policy.id;
            async move {
                append_agent_revision(
                    &pool,
                    scope,
                    agent_id,
                    "claude-agent-sdk",
                    "img:test",
                    model,
                    Some(prompt),
                    pid,
                    &serde_json::json!({ "wall_clock_secs": 60 }),
                    None,
                    &pins,
                    &serde_json::json!([]),
                )
                .await
                .unwrap()
            }
        };
        let mk_sub = |agent_id: Uuid, name: &'static str, rev: Uuid, keep: Option<Value>| {
            let pool = pool.clone();
            async move {
                create_trigger_subscription(
                    &pool,
                    scope,
                    agent_id,
                    name,
                    "api",
                    Some(rev),
                    Some("t"),
                    false,
                    false,
                    None,
                    "allow",
                    None,
                    None,
                    &serde_json::json!([]),
                    None,
                    1,
                    None,
                    None,
                    None,
                    None,
                    keep.as_ref(),
                )
                .await
                .unwrap()
            }
        };

        // ── Agent P: OLDER brokered rev1 (model p-old) + brokered-narrower latest
        // rev2 (model p-new); four subscriptions pinned to rev1 exercising NULL /
        // dedup / restrictive / empty keep-lists. ──
        let gh_b = create_capability_bundle(
            &pool,
            scope,
            "gh-bundle",
            None,
            &brok_def("github", gh_url, "get_pr"),
            "sha256:gh",
        )
        .await
        .unwrap();
        let stripe_b = create_capability_bundle(
            &pool,
            scope,
            "stripe-bundle",
            None,
            &brok_def("stripe", stripe_url, "charge"),
            "sha256:st",
        )
        .await
        .unwrap();
        let agent_p = create_agent(&pool, scope, "psr-agent-p", None)
            .await
            .unwrap();
        let p_rev1 = mk_rev(
            agent_p.id,
            "p-old",
            "old-prompt",
            serde_json::json!([pin(&gh_b), pin(&stripe_b)]),
        )
        .await;
        let p_rev2 = mk_rev(
            agent_p.id,
            "p-new",
            "new-prompt",
            serde_json::json!([pin(&gh_b)]),
        )
        .await;
        let sub_full = mk_sub(agent_p.id, "sub-full", p_rev1.id, None).await;
        let sub_full2 = mk_sub(agent_p.id, "sub-full2", p_rev1.id, None).await;
        let sub_gh = mk_sub(
            agent_p.id,
            "sub-gh",
            p_rev1.id,
            Some(serde_json::json!(["gh-bundle"])),
        )
        .await;
        let sub_empty = mk_sub(
            agent_p.id,
            "sub-empty",
            p_rev1.id,
            Some(serde_json::json!([])),
        )
        .await;

        // ── Agent Q: OLDER brokered rev1 (model q-old) + SANDBOX-ONLY latest rev2
        // (model q-new); one subscription pinned to rev1. ──
        let q_brok = create_capability_bundle(
            &pool,
            scope,
            "q-brok",
            None,
            &brok_def("qsrv", q_url, "q"),
            "sha256:qb",
        )
        .await
        .unwrap();
        let q_sand =
            create_capability_bundle(&pool, scope, "q-sand", None, &sand_def("qs"), "sha256:qs")
                .await
                .unwrap();
        let agent_q = create_agent(&pool, scope, "psr-agent-q", None)
            .await
            .unwrap();
        let q_rev1 = mk_rev(
            agent_q.id,
            "q-old",
            "q-old-prompt",
            serde_json::json!([pin(&q_brok)]),
        )
        .await;
        let q_rev2 = mk_rev(
            agent_q.id,
            "q-new",
            "q-new-prompt",
            serde_json::json!([pin(&q_sand)]),
        )
        .await;
        let sub_q = mk_sub(agent_q.id, "sub-q", q_rev1.id, None).await;

        // ── Agent R: brokered latest (gh + stripe) with FLOATING subscriptions
        // (pinned_revision_id NULL). A1: a floating sub whose NON-NULL keep-list
        // narrows the latest's brokered authority must be PINNED to a tailored
        // copy (the narrowing frozen); a NULL keep-list floater keeps floating. ──
        let agent_r = create_agent(&pool, scope, "psr-agent-r", None)
            .await
            .unwrap();
        let r_rev1 = mk_rev(
            agent_r.id,
            "r-latest",
            "r-prompt",
            serde_json::json!([pin(&gh_b), pin(&stripe_b)]),
        )
        .await;
        let mk_float = |agent_id: Uuid, name: &'static str, keep: Option<Value>| {
            let pool = pool.clone();
            async move {
                create_trigger_subscription(
                    &pool,
                    scope,
                    agent_id,
                    name,
                    "api",
                    None,
                    Some("t"),
                    false,
                    false,
                    None,
                    "allow",
                    None,
                    None,
                    &serde_json::json!([]),
                    None,
                    1,
                    None,
                    None,
                    None,
                    None,
                    keep.as_ref(),
                )
                .await
                .unwrap()
            }
        };
        let sub_float_gh = mk_float(
            agent_r.id,
            "float-gh",
            Some(serde_json::json!(["gh-bundle"])),
        )
        .await;
        let sub_float_empty =
            mk_float(agent_r.id, "float-empty", Some(serde_json::json!([]))).await;
        let sub_float_null = mk_float(agent_r.id, "float-null", None).await;

        // ── Convert, then re-convert for idempotence (v). RLS-BOUND and confined to
        // this org: the fixtures below are built across several statements, and an
        // unconfined conversion from a sibling test could otherwise repoint them
        // mid-build (or race this call for the next rev). ──
        convert_legacy_bundles_rls_bound(&url, Some(org.id)).await;

        let p_revs = list_revisions(&pool, scope, agent_p.id).await.unwrap();
        let p_latest = latest_revision(&pool, scope, agent_p.id)
            .await
            .unwrap()
            .unwrap();
        let q_revs = list_revisions(&pool, scope, agent_q.id).await.unwrap();
        let q_latest = latest_revision(&pool, scope, agent_q.id)
            .await
            .unwrap()
            .unwrap();
        let sub_full_a = get_trigger_subscription(&pool, scope, sub_full.id)
            .await
            .unwrap()
            .unwrap();
        let sub_full2_a = get_trigger_subscription(&pool, scope, sub_full2.id)
            .await
            .unwrap()
            .unwrap();
        let sub_gh_a = get_trigger_subscription(&pool, scope, sub_gh.id)
            .await
            .unwrap()
            .unwrap();
        let sub_empty_a = get_trigger_subscription(&pool, scope, sub_empty.id)
            .await
            .unwrap()
            .unwrap();
        let sub_q_a = get_trigger_subscription(&pool, scope, sub_q.id)
            .await
            .unwrap()
            .unwrap();
        let r_revs = list_revisions(&pool, scope, agent_r.id).await.unwrap();
        let r_latest = latest_revision(&pool, scope, agent_r.id)
            .await
            .unwrap()
            .unwrap();
        let sub_float_gh_a = get_trigger_subscription(&pool, scope, sub_float_gh.id)
            .await
            .unwrap()
            .unwrap();
        let sub_float_empty_a = get_trigger_subscription(&pool, scope, sub_float_empty.id)
            .await
            .unwrap()
            .unwrap();
        let sub_float_null_a = get_trigger_subscription(&pool, scope, sub_float_null.id)
            .await
            .unwrap()
            .unwrap();

        // Idempotence: a second run appends nothing and moves no pin.
        convert_legacy_bundles_rls_bound(&url, Some(org.id)).await;
        let p_revs2 = list_revisions(&pool, scope, agent_p.id).await.unwrap();
        let q_revs2 = list_revisions(&pool, scope, agent_q.id).await.unwrap();
        let r_revs2 = list_revisions(&pool, scope, agent_r.id).await.unwrap();
        let p_latest2 = latest_revision(&pool, scope, agent_p.id)
            .await
            .unwrap()
            .unwrap();
        let sub_full_b = get_trigger_subscription(&pool, scope, sub_full.id)
            .await
            .unwrap()
            .unwrap();

        // Snapshot the row a subscription now points at (by id) BEFORE cleanup.
        let rev_of = |revs: &[AgentRevisionRow], id: Option<Uuid>| {
            revs.iter().find(|r| Some(r.id) == id).cloned()
        };
        let full_copy = rev_of(&p_revs, sub_full_a.pinned_revision_id).unwrap();
        let gh_copy = rev_of(&p_revs, sub_gh_a.pinned_revision_id).unwrap();
        let empty_copy = rev_of(&p_revs, sub_empty_a.pinned_revision_id).unwrap();
        let q_copy = rev_of(&q_revs, sub_q_a.pinned_revision_id).unwrap();
        let float_gh_copy = rev_of(&r_revs, sub_float_gh_a.pinned_revision_id).unwrap();
        let float_empty_copy = rev_of(&r_revs, sub_float_empty_a.pinned_revision_id).unwrap();

        for stmt in [
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from capability_bundles where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org.id).execute(&pool).await.unwrap();
        }
        sqlx::query("delete from tenants where id = $1")
            .bind(org.id)
            .execute(&pool)
            .await
            .unwrap();

        let gh_req = serde_json::json!({ "slot": "github",
            "connector": { "url": gh_url, "slug": null },
            "required_tools": ["get_pr"], "binding_mode": "organization" });
        let stripe_req = serde_json::json!({ "slot": "stripe",
            "connector": { "url": stripe_url, "slug": null },
            "required_tools": ["charge"], "binding_mode": "organization" });
        let qsrv_req = serde_json::json!({ "slot": "qsrv",
            "connector": { "url": q_url, "slug": null },
            "required_tools": ["q"], "binding_mode": "organization" });

        // (i) the latest converts SEPARATELY with the NEW model + full (single) req;
        // the subscription copy carries the OLDER revision's model/prompt.
        assert_eq!(
            p_latest.model, "p-new",
            "latest is the converted NEW revision"
        );
        assert_ne!(
            p_latest.id, p_rev2.id,
            "the latest is the CONVERTED copy of rev2, not the original brokered rev2"
        );
        assert_eq!(p_latest.system_prompt.as_deref(), Some("new-prompt"));
        assert_eq!(
            p_latest.connection_requirements,
            serde_json::json!([gh_req]),
            "latest's full derivation keeps only github (rev2 pinned gh only)"
        );
        assert_eq!(
            full_copy.model, "p-old",
            "sub copy carries the OLD revision's model"
        );
        assert_eq!(full_copy.system_prompt.as_deref(), Some("old-prompt"));
        assert_eq!(
            full_copy.connection_requirements,
            serde_json::json!([gh_req, stripe_req]),
            "NULL keep-list ⇒ both brokered servers become requirements"
        );

        // dedup: two NULL-keep subs pinning the same old source share ONE copy.
        assert_eq!(
            sub_full_a.pinned_revision_id, sub_full2_a.pinned_revision_id,
            "subscriptions sharing (source, requirements) share one converted copy"
        );

        // (iii) restrictive keep-list ⇒ ONLY github; (iv) empty keep-list ⇒ none.
        assert_eq!(gh_copy.model, "p-old");
        assert_eq!(
            gh_copy.connection_requirements,
            serde_json::json!([gh_req]),
            "keep-list ['gh-bundle'] ⇒ ONLY github survives as a requirement"
        );
        assert_ne!(
            sub_gh_a.pinned_revision_id, sub_full_a.pinned_revision_id,
            "the narrowed sub gets its OWN copy, distinct from the full one"
        );
        assert_eq!(empty_copy.model, "p-old");
        assert_eq!(
            empty_copy.connection_requirements,
            serde_json::json!([]),
            "empty keep-list ⇒ zero requirements (removed authority not regained)"
        );

        // (ii) sandbox-only latest — APPEND-ONLY is sacred (A2). The ORIGINAL
        // rev2 is NEVER rewritten (keeps its rev + content); an exact CLONE is
        // APPENDED as the new `latest` so unpinned runs still resolve the
        // sandbox-only semantics. The pinned OLD brokered source still converts.
        let q_rev2_after = rev_of(&q_revs, Some(q_rev2.id)).unwrap();
        assert_eq!(
            q_rev2_after.rev, q_rev2.rev,
            "the ORIGINAL sandbox-only latest keeps its rev (never rewritten)"
        );
        assert_eq!(
            q_rev2_after.capability_bundles,
            serde_json::json!([pin(&q_sand)]),
            "the ORIGINAL sandbox-only latest keeps its content"
        );
        assert_ne!(
            q_latest.id, q_rev2.id,
            "the new latest is an APPENDED CLONE, not the rewritten original"
        );
        assert!(
            q_latest.rev > q_rev2_after.rev,
            "the clone is appended above the original"
        );
        assert_eq!(q_latest.model, "q-new");
        assert_eq!(
            q_latest.capability_bundles,
            serde_json::json!([pin(&q_sand)]),
            "the clone is content-identical to the sandbox-only latest"
        );
        assert_eq!(
            q_latest.connection_requirements,
            serde_json::json!([]),
            "the sandbox-only clone carries no brokered requirements"
        );
        assert_ne!(
            sub_q_a.pinned_revision_id,
            Some(q_rev1.id),
            "sub_q repointed off the legacy rev"
        );
        assert_ne!(sub_q_a.pinned_revision_id, Some(q_rev2.id));
        assert_eq!(
            q_copy.model, "q-old",
            "sub_q's copy carries the OLD revision model"
        );
        assert_eq!(
            q_copy.connection_requirements,
            serde_json::json!([qsrv_req]),
            "the pinned brokered source converted for the subscription"
        );

        // (v) idempotence: no second-run appends, no pin moved.
        assert_eq!(
            p_revs2.len(),
            p_revs.len(),
            "agent P: second run appends nothing"
        );
        assert_eq!(
            q_revs2.len(),
            q_revs.len(),
            "agent Q: second run appends nothing"
        );
        assert_eq!(
            p_latest2.id, p_latest.id,
            "agent P latest unchanged on re-run"
        );
        assert_eq!(
            sub_full_b.pinned_revision_id, sub_full_a.pinned_revision_id,
            "pin stable on re-run"
        );

        // (A1) FLOATING subscriptions.
        // The live latest is the FULL converted copy (both brokered → requirements).
        assert_ne!(
            r_latest.id, r_rev1.id,
            "agent R latest is the converted live copy, not the original brokered rev"
        );
        assert_eq!(
            r_latest.connection_requirements,
            serde_json::json!([gh_req, stripe_req]),
            "the live latest keeps BOTH brokered servers as requirements"
        );
        // A NULL keep-list floater keeps floating (no pin, still resolves latest).
        assert_eq!(
            sub_float_null_a.pinned_revision_id, None,
            "a NULL keep-list floater keeps floating (never pinned)"
        );
        // A restrictive keep-list floater is PINNED to a tailored copy — gh only.
        assert!(
            sub_float_gh_a.pinned_revision_id.is_some(),
            "a restrictive-keep-list floater is PINNED (its narrowing frozen)"
        );
        assert_eq!(
            float_gh_copy.connection_requirements,
            serde_json::json!([gh_req]),
            "float-gh keep-list ['gh-bundle'] ⇒ ONLY github survives as a requirement"
        );
        // An empty keep-list floater is PINNED to a zero-requirement copy.
        assert!(
            sub_float_empty_a.pinned_revision_id.is_some(),
            "an empty-keep-list floater is PINNED"
        );
        assert_eq!(
            float_empty_copy.connection_requirements,
            serde_json::json!([]),
            "float-empty keep-list [] ⇒ zero requirements (removed authority not regained)"
        );
        assert_eq!(
            r_revs2.len(),
            r_revs.len(),
            "agent R: second run appends nothing (idempotent)"
        );
    }

    /// Cross-tenant isolation (wave A): a session and its child rows created
    /// under tenant B are invisible to tenant A's scope. The tenant predicate
    /// now lives in SQL, so a cross-tenant id misses at the database — never
    /// via a Rust-side filter. Throwaway orgs; cleanup is children-first
    /// (tenant FKs are NO ACTION).
    #[tokio::test]
    async fn tenant_scope_isolates_sessions_and_children() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");

        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = identity::create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = identity::create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        // A full session fixture under B.
        let policy = upsert_policy(
            &pool,
            scope_b,
            "xt-policy",
            "name: xt",
            &serde_json::json!({"name":"xt"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope_b,
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
        let session = create_session(
            &pool,
            scope_b,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "xt",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
        )
        .await
        .unwrap();

        // Child rows under B's scope: an event, an artifact, usage, and a
        // human-visible (pending) approval.
        let redactor = Redactor::default();
        append_event(
            &pool,
            scope_b,
            redactor.scrub(EventEnvelope::new(
                session.id,
                Actor::System,
                EventBody::AgentMessage {
                    role: "assistant".into(),
                    text: "hi".into(),
                },
            )),
        )
        .await
        .unwrap();
        add_artifact(
            &pool,
            scope_b,
            session.id,
            "diff",
            "changes.patch",
            "x",
            "text/plain",
        )
        .await
        .unwrap();
        add_usage(
            &pool,
            scope_b,
            session.id,
            "m",
            1,
            1,
            0,
            0,
            Some(0.0),
            "test",
            None,
        )
        .await
        .unwrap();
        let (intent, _) = register_tool_intent(&pool, scope_b, session.id, "tc1", "Bash", "s", "d")
            .await
            .unwrap();
        promote_intent_to_pending(&pool, scope_b, intent.id, None, "once", "Bash", 600)
            .await
            .unwrap();

        // Negative — tenant A sees NONE of B's rows.
        let get_a = get_session(&pool, scope_a, session.id).await.unwrap();
        let events_a = events_after(&pool, scope_a, session.id, 0, 10)
            .await
            .unwrap();
        let approvals_a = session_approvals(&pool, scope_a, session.id).await.unwrap();
        let artifacts_a = list_artifacts(&pool, scope_a, session.id).await.unwrap();
        let usage_a = usage_totals(&pool, scope_a, session.id).await.unwrap();
        // Positive control — tenant B still reads its own session, approval, AND
        // every child family (events/artifacts/usage) under its OWNING scope, so
        // the negatives below prove a tenant boundary, not a globally-broken read.
        let get_b = get_session(&pool, scope_b, session.id).await.unwrap();
        let approvals_b = session_approvals(&pool, scope_b, session.id).await.unwrap();
        let events_b = events_after(&pool, scope_b, session.id, 0, 10)
            .await
            .unwrap();
        let artifacts_b = list_artifacts(&pool, scope_b, session.id).await.unwrap();
        let usage_b = usage_totals(&pool, scope_b, session.id).await.unwrap();

        // Cleanup, children-first, both orgs — BEFORE the assertions so a
        // failure never leaks throwaway fixtures.
        for stmt in [
            "delete from events where session_id in (select id from sessions where tenant_id = $1)",
            "delete from artifacts where session_id in (select id from sessions where tenant_id = $1)",
            "delete from approvals where session_id in (select id from sessions where tenant_id = $1)",
            "delete from usage_entries where session_id in (select id from sessions where tenant_id = $1)",
            "delete from api_tokens where session_id in (select id from sessions where tenant_id = $1)",
            "delete from session_finalizations where session_id in (select id from sessions where tenant_id = $1)",
            "delete from sessions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            sqlx::query(stmt)
                .bind(org_b.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(get_a.is_none(), "tenant A must not read B's session");
        assert!(events_a.is_empty(), "tenant A must see none of B's events");
        assert!(
            approvals_a.is_empty(),
            "tenant A must see none of B's approvals"
        );
        assert!(
            artifacts_a.is_empty(),
            "tenant A must see none of B's artifacts"
        );
        assert_eq!(
            usage_a.requests, 0,
            "tenant A totals zero usage for B's session"
        );
        assert!(get_b.is_some(), "tenant B still reads its own session");
        assert_eq!(
            approvals_b.len(),
            1,
            "tenant B sees its own pending approval"
        );
        assert_eq!(events_b.len(), 1, "tenant B reads its own event");
        assert_eq!(artifacts_b.len(), 1, "tenant B reads its own artifact");
        assert_eq!(usage_b.requests, 1, "tenant B totals its own usage");
    }

    /// Cross-tenant isolation for AGENTS: an agent created under B is invisible
    /// to A's scope at the database. Throwaway orgs; cleanup children-first
    /// BEFORE the asserts so a failure never leaks fixtures.
    #[tokio::test]
    async fn tenant_scope_isolates_agents() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();

        let read_a = get_agent(&pool, scope_a, agent.id).await.unwrap();
        let read_b = get_agent(&pool, scope_b, agent.id).await.unwrap();

        // Cleanup BEFORE the assertions, both orgs (tenant FKs are NO ACTION).
        sqlx::query("delete from agents where tenant_id = $1")
            .bind(org_b.id)
            .execute(&pool)
            .await
            .unwrap();
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(read_a.is_none(), "tenant A must not read B's agent");
        assert!(read_b.is_some(), "tenant B reads its own agent");
    }

    /// Cross-tenant isolation for POLICIES.
    #[tokio::test]
    async fn tenant_scope_isolates_policies() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let policy = upsert_policy(
            &pool,
            scope_b,
            "xt-policy",
            "name: xt",
            &serde_json::json!({"name":"xt"}),
        )
        .await
        .unwrap();

        let read_a = get_policy(&pool, scope_a, policy.id).await.unwrap();
        let read_b = get_policy(&pool, scope_b, policy.id).await.unwrap();

        sqlx::query("delete from policies where tenant_id = $1")
            .bind(org_b.id)
            .execute(&pool)
            .await
            .unwrap();
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(read_a.is_none(), "tenant A must not read B's policy");
        assert!(read_b.is_some(), "tenant B reads its own policy");
    }

    /// Cross-tenant isolation for CONNECTIONS: neither the row nor the sealed
    /// credential is reachable across the tenant boundary.
    #[tokio::test]
    async fn tenant_scope_isolates_connections() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let conn = create_connection(
            &pool,
            scope_b,
            "mcp_http",
            "acct",
            "disp",
            Some(&[1, 2, 3]),
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({"base_url":"https://x"}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        let get_a = get_connection(&pool, scope_a, conn.id).await.unwrap();
        let cred_a = connection_credential_sealed(&pool, scope_a, conn.id)
            .await
            .unwrap();
        let get_b = get_connection(&pool, scope_b, conn.id).await.unwrap();
        let cred_b = connection_credential_sealed(&pool, scope_b, conn.id)
            .await
            .unwrap();

        sqlx::query("delete from integration_connections where tenant_id = $1")
            .bind(org_b.id)
            .execute(&pool)
            .await
            .unwrap();
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(get_a.is_none(), "tenant A must not read B's connection");
        assert!(
            cred_a.is_none(),
            "tenant A must not read B's sealed credential"
        );
        assert!(get_b.is_some(), "tenant B reads its own connection");
        assert!(cred_b.is_some(), "tenant B reads its own sealed credential");
    }

    /// Cross-tenant isolation for TRIGGER SUBSCRIPTIONS.
    #[tokio::test]
    async fn tenant_scope_isolates_subscriptions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope_b,
            agent.id,
            "xt-sub",
            "api",
            None,
            Some("do {{x}}"),
            true,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let read_a = get_trigger_subscription(&pool, scope_a, sub.id)
            .await
            .unwrap();
        let read_b = get_trigger_subscription(&pool, scope_b, sub.id)
            .await
            .unwrap();

        // Children-first: subscriptions before agents.
        for stmt in [
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agents where tenant_id = $1",
        ] {
            sqlx::query(stmt)
                .bind(org_b.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(read_a.is_none(), "tenant A must not read B's subscription");
        assert!(read_b.is_some(), "tenant B reads its own subscription");
    }

    /// Cross-tenant isolation for SCHEDULES (looked up via their subscription).
    #[tokio::test]
    async fn tenant_scope_isolates_schedules() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope_b,
            agent.id,
            "xt-sub",
            "schedule",
            None,
            Some("do {{x}}"),
            true,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        create_schedule(
            &pool,
            scope_b,
            sub.id,
            "*/5 * * * * *",
            "UTC",
            chrono::Utc::now(),
            "skip",
        )
        .await
        .unwrap();

        let read_a = schedule_for_subscription(&pool, scope_a, sub.id)
            .await
            .unwrap();
        let read_b = schedule_for_subscription(&pool, scope_b, sub.id)
            .await
            .unwrap();

        // Children-first: schedules (via subscription) → subscriptions → agents.
        for stmt in [
            "delete from schedules where subscription_id in (select id from trigger_subscriptions where tenant_id = $1)",
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agents where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org_b.id).execute(&pool).await.unwrap();
        }
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(read_a.is_none(), "tenant A must not read B's schedule");
        assert!(read_b.is_some(), "tenant B reads its own schedule");
    }

    /// Cross-tenant isolation for EXTERNAL RESULTS (§17 #3 stable identity).
    #[tokio::test]
    async fn tenant_scope_isolates_external_results() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope_b,
            agent.id,
            "xt-sub",
            "api",
            None,
            Some("do {{x}}"),
            true,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        upsert_external_result(
            &pool,
            scope_b,
            sub.id,
            "github_pr_comment",
            "acme/x#1",
            "999",
            Some("https://u"),
        )
        .await
        .unwrap();

        let read_a = get_external_result(&pool, scope_a, sub.id, "github_pr_comment", "acme/x#1")
            .await
            .unwrap();
        let read_b = get_external_result(&pool, scope_b, sub.id, "github_pr_comment", "acme/x#1")
            .await
            .unwrap();

        // Children-first: external_results (via subscription) → subscriptions → agents.
        for stmt in [
            "delete from external_results where subscription_id in (select id from trigger_subscriptions where tenant_id = $1)",
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agents where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org_b.id).execute(&pool).await.unwrap();
        }
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(
            read_a.is_none(),
            "tenant A must not read B's external result"
        );
        assert!(read_b.is_some(), "tenant B reads its own external result");
    }

    // ─── Phase C (#31): ownership, snapshots, bindings, catalog scoping ──────

    /// Seed a user + active membership under `scope` (each with its own staged
    /// idp config, so callers need not thread one). Returns the user id — the
    /// FK target for a connection's `owner_user_id`/`created_by_user_id`.
    async fn seed_member(pool: &PgPool, scope: TenantScope, subject: &str) -> Uuid {
        let cfg_id = Uuid::now_v7();
        sqlx::query(
            "insert into org_idp_configs
               (id, tenant_id, generation, issuer, client_id, claim_mappings, status)
             values ($1, $2,
                     coalesce((select max(generation) from org_idp_configs where tenant_id = $2), 0) + 1,
                     $3, 'client-test', '{}'::jsonb, 'staged')",
        )
        .bind(cfg_id)
        .bind(scope.tenant_id())
        .bind(format!("https://idp.test/{subject}"))
        .execute(pool)
        .await
        .unwrap();
        let user_id = Uuid::now_v7();
        sqlx::query(
            "insert into users
               (id, tenant_id, idp_config_id, subject, email, email_normalized, email_verified, status)
             values ($1, $2, $3, $4, $5, $5, true, 'active')",
        )
        .bind(user_id)
        .bind(scope.tenant_id())
        .bind(cfg_id)
        .bind(subject)
        .bind(format!("{subject}@example.com"))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "insert into org_memberships (id, tenant_id, user_id, roles, status)
             values ($1, $2, $3, '{member}', 'active')",
        )
        .bind(Uuid::now_v7())
        .bind(scope.tenant_id())
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
        user_id
    }

    async fn cleanup_orgs(pool: &PgPool, stmts: &[&'static str], tenants: &[Uuid]) {
        for id in tenants {
            for &stmt in stmts {
                sqlx::query(stmt).bind(id).execute(pool).await.unwrap();
            }
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(pool)
                .await
                .unwrap();
        }
    }

    /// Owner-shape CHECK, ownership visibility lens, and generation bump.
    #[tokio::test]
    async fn phase_c_connection_ownership_and_visibility() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);
        let alice = seed_member(&pool, scope, "alice").await;
        let bob = seed_member(&pool, scope, "bob").await;

        // owner-shape CHECK: owner_type='user' with a NULL owner_user_id is
        // rejected by the DB (a half-populated owner is fail-closed).
        let bad_owner = sqlx::query(
            "insert into integration_connections
               (id, tenant_id, provider, external_account_id, display_name, owner_type)
             values ($1, $2, 'mcp_http', 'x', 'bad', 'user')",
        )
        .bind(Uuid::now_v7())
        .bind(org.id)
        .execute(&pool)
        .await;

        let org_conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct-org",
            "Org conn",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        let alice_conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct-alice",
            "Alice personal",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::User(alice),
            Some(alice),
        )
        .await
        .unwrap();

        // bob's lens sees the org connection but NOT alice's personal one.
        let bob_list = list_connections_visible(&pool, scope, ConnectionViewer::User(bob))
            .await
            .unwrap();
        let all_list = list_connections_visible(&pool, scope, ConnectionViewer::All)
            .await
            .unwrap();
        let bob_sees_alice =
            get_connection_visible(&pool, scope, alice_conn.id, ConnectionViewer::User(bob))
                .await
                .unwrap();
        let alice_sees_alice =
            get_connection_visible(&pool, scope, alice_conn.id, ConnectionViewer::User(alice))
                .await
                .unwrap();
        let bumped = bump_connection_generation(&pool, scope, org_conn.id)
            .await
            .unwrap();

        cleanup_orgs(
            &pool,
            &[
                "delete from integration_connections where tenant_id = $1",
                "delete from org_memberships where tenant_id = $1",
                "delete from users where tenant_id = $1",
                "delete from org_idp_configs where tenant_id = $1",
            ],
            &[org.id],
        )
        .await;

        assert!(
            bad_owner.is_err(),
            "user owner without owner_user_id rejected"
        );
        assert_eq!(org_conn.owner_type, "organization");
        assert_eq!(org_conn.authorization_generation, 1);
        assert_eq!(alice_conn.owner_type, "user");
        assert_eq!(alice_conn.owner_user_id, Some(alice));
        let bob_ids: Vec<Uuid> = bob_list.iter().map(|c| c.id).collect();
        assert!(
            bob_ids.contains(&org_conn.id),
            "bob sees the org connection"
        );
        assert!(
            !bob_ids.contains(&alice_conn.id),
            "bob must not see alice's personal connection"
        );
        assert_eq!(all_list.len(), 2, "All lens sees both connections");
        assert!(
            bob_sees_alice.is_none(),
            "bob cannot read alice's personal row"
        );
        assert!(alice_sees_alice.is_some(), "alice reads her own connection");
        assert_eq!(bumped, Some(2), "generation bumps 1 → 2");
    }

    /// Snapshots auto-increment per connection, are append-only, and are
    /// tenant-scoped.
    #[tokio::test]
    async fn phase_c_tool_snapshots_versioned_and_scoped() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = identity::create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = identity::create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let conn = create_connection(
            &pool,
            scope_a,
            "mcp_http",
            "acct-snap",
            "Snap conn",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        let s1 = insert_connection_tool_snapshot(
            &pool,
            scope_a,
            conn.id,
            1,
            "2025-06-18",
            &serde_json::json!([{"name": "t1"}]),
            "digest-1",
        )
        .await
        .unwrap();
        let s2 = insert_connection_tool_snapshot(
            &pool,
            scope_a,
            conn.id,
            1,
            "2025-06-18",
            &serde_json::json!([{"name": "t2"}]),
            "digest-2",
        )
        .await
        .unwrap();
        let latest = latest_connection_tool_snapshot(&pool, scope_a, conn.id)
            .await
            .unwrap();
        let listed = list_connection_tool_snapshots(&pool, scope_a, conn.id)
            .await
            .unwrap();
        let v1 = get_connection_tool_snapshot(&pool, scope_a, conn.id, 1)
            .await
            .unwrap();
        // Append-only: a duplicate (tenant, connection, version) is rejected.
        let dup = sqlx::query(
            "insert into connection_tool_snapshots
               (id, tenant_id, connection_id, snapshot_version, authorization_generation,
                protocol_version, tools_json, tools_digest)
             values ($1, $2, $3, 2, 1, 'p', '[]'::jsonb, 'd')",
        )
        .bind(Uuid::now_v7())
        .bind(org_a.id)
        .bind(conn.id)
        .execute(&pool)
        .await;
        // Cross-tenant: B cannot read A's snapshots.
        let latest_b = latest_connection_tool_snapshot(&pool, scope_b, conn.id)
            .await
            .unwrap();
        let get_b = get_connection_tool_snapshot(&pool, scope_b, conn.id, 1)
            .await
            .unwrap();

        cleanup_orgs(
            &pool,
            &[
                "delete from connection_tool_snapshots where tenant_id = $1",
                "delete from integration_connections where tenant_id = $1",
            ],
            &[org_a.id, org_b.id],
        )
        .await;

        assert_eq!(s1.snapshot_version, 1, "first snapshot is version 1");
        assert_eq!(
            s2.snapshot_version, 2,
            "version auto-increments per connection"
        );
        assert_eq!(latest.unwrap().snapshot_version, 2);
        assert_eq!(listed.len(), 2, "list returns every version, newest first");
        assert_eq!(listed[0].snapshot_version, 2);
        assert_eq!(v1.unwrap().tools_digest, "digest-1");
        assert!(
            dup.is_err(),
            "duplicate (tenant, connection, version) rejected"
        );
        assert!(latest_b.is_none(), "B cannot read A's snapshot (latest)");
        assert!(get_b.is_none(), "B cannot read A's snapshot (by version)");
    }

    /// A snapshot taken after a re-consent records the BUMPED authorization
    /// generation (design :294-296, :306) — the pin a run binding froze under
    /// the older generation stays distinguishable, so the broker recheck can
    /// fail it closed. (The live-MCP photograph itself is CI-e2e territory; this
    /// exercises the generation stamping the photograph relies on.)
    #[tokio::test]
    async fn phase_c_snapshot_records_bumped_generation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);

        let conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct-gen",
            "Gen conn",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        // First photograph stamps generation 1.
        let s1 = insert_connection_tool_snapshot(
            &pool,
            scope,
            conn.id,
            conn.authorization_generation,
            "2025-06-18",
            &serde_json::json!([{ "name": "t1" }]),
            "digest-1",
        )
        .await
        .unwrap();

        // Re-consent bumps the generation; a fresh photograph stamps the bumped
        // value (read off the connection's CURRENT generation, as the server does).
        let bumped = bump_connection_generation(&pool, scope, conn.id)
            .await
            .unwrap()
            .expect("connection in scope");
        let conn2 = get_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        let s2 = insert_connection_tool_snapshot(
            &pool,
            scope,
            conn.id,
            conn2.authorization_generation,
            "2025-06-18",
            &serde_json::json!([{ "name": "t2" }]),
            "digest-2",
        )
        .await
        .unwrap();

        cleanup_orgs(
            &pool,
            &[
                "delete from connection_tool_snapshots where tenant_id = $1",
                "delete from integration_connections where tenant_id = $1",
            ],
            &[org.id],
        )
        .await;

        assert_eq!(s1.authorization_generation, 1, "first snapshot is gen 1");
        assert_eq!(bumped, 2, "bump takes the connection to generation 2");
        assert_eq!(conn2.authorization_generation, 2);
        assert_eq!(
            s2.authorization_generation, 2,
            "snapshot records the BUMPED generation"
        );
        assert_eq!(
            s2.snapshot_version, 2,
            "snapshot version keeps auto-incrementing across a generation bump"
        );
    }

    /// Bindings commit atomically with the session, are tenant-scoped, and the
    /// authority/mcp CHECK constraints reject malformed shapes.
    #[tokio::test]
    async fn phase_c_run_resource_bindings_atomic_and_checks() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = identity::create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = identity::create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let mk_session = |scope: TenantScope, bindings: Vec<NewRunResourceBinding>| {
            let pool = pool.clone();
            async move {
                let policy = upsert_policy(
                    &pool,
                    scope,
                    "rb-policy",
                    "name: rb",
                    &serde_json::json!({"name":"rb"}),
                )
                .await
                .unwrap();
                let agent = create_agent(&pool, scope, "rb-agent", None).await.unwrap();
                let rev = append_agent_revision(
                    &pool,
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
                create_session(
                    &pool,
                    scope,
                    agent.id,
                    rev.id,
                    "supervised",
                    "trusted",
                    "rb",
                    &serde_json::json!({"kind":"none"}),
                    &serde_json::json!({}),
                    &serde_json::json!({}),
                    None,
                    None,
                    None,
                    None,
                    None,
                    &bindings,
                )
                .await
                .unwrap()
            }
        };

        let conn = create_connection(
            &pool,
            scope_a,
            "mcp_http",
            "acct-rb",
            "RB conn",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        let snap = insert_connection_tool_snapshot(
            &pool,
            scope_a,
            conn.id,
            conn.authorization_generation,
            "2025-06-18",
            &serde_json::json!([{"name": "t1"}]),
            "digest-1",
        )
        .await
        .unwrap();

        let mcp_binding = NewRunResourceBinding {
            id: Uuid::now_v7(),
            requirement_slot: "primary".into(),
            slot_kind: "mcp".into(),
            authority_kind: "connection".into(),
            connection_id: Some(conn.id),
            subscription_id: None,
            authority_generation: Some(conn.authorization_generation),
            connection_owner_type: Some(conn.owner_type.clone()),
            connection_owner_user_id: conn.owner_user_id,
            snapshot_version: Some(snap.snapshot_version),
            effective_tools_json: Some(serde_json::json!([{"name": "t1"}])),
            effective_tools_digest: Some("digest-1".into()),
            resource_scope: serde_json::json!({}),
            resolved_by_principal_kind: "operator".into(),
            resolved_by_principal_id: None,
            binding_mode: "organization".into(),
        };
        let session = mk_session(scope_a, vec![mcp_binding.clone()]).await;

        // Atomic: the binding is present under A immediately after the session.
        let a_bindings = session_resource_bindings(&pool, scope_a, session.id)
            .await
            .unwrap();
        let by_id = get_run_resource_binding(&pool, scope_a, mcp_binding.id)
            .await
            .unwrap();
        let found = find_session_binding(&pool, scope_a, session.id, "mcp", "primary")
            .await
            .unwrap();
        // Cross-tenant: B cannot read A's binding.
        let b_bindings = session_resource_bindings(&pool, scope_b, session.id)
            .await
            .unwrap();
        let by_id_b = get_run_resource_binding(&pool, scope_b, mcp_binding.id)
            .await
            .unwrap();

        // FK negative: a binding for another tenant's session is refused.
        let session_b = mk_session(scope_b, vec![]).await;
        let none_binding = |slot_kind: &str, authority_kind: &str| NewRunResourceBinding {
            id: Uuid::now_v7(),
            requirement_slot: "x".into(),
            slot_kind: slot_kind.into(),
            authority_kind: authority_kind.into(),
            connection_id: None,
            subscription_id: None,
            authority_generation: None,
            connection_owner_type: None,
            connection_owner_user_id: None,
            snapshot_version: None,
            effective_tools_json: None,
            effective_tools_digest: None,
            resource_scope: serde_json::json!({}),
            resolved_by_principal_kind: "system".into(),
            resolved_by_principal_id: None,
            binding_mode: "organization".into(),
        };
        let fk_bad = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session_b.id,
            &[none_binding("workspace_fetch", "none")],
        )
        .await;

        // Shape CHECK negatives (each on a valid in-scope session):
        // (a) mcp slot missing the snapshot fields. A FRESH requirement_slot is
        // mandatory: reusing "primary" would collide with mcp_binding on the
        // unique (tenant_id, session_id, slot_kind, requirement_slot) key, so the
        // insert would fail even if the mcp-shape CHECK regressed. With its own
        // slot the ONLY reason it can fail is run_resource_bindings_mcp_shape.
        let mut bad_mcp = mcp_binding.clone();
        bad_mcp.id = Uuid::now_v7();
        bad_mcp.requirement_slot = "shape-a".into();
        bad_mcp.snapshot_version = None;
        bad_mcp.effective_tools_json = None;
        bad_mcp.effective_tools_digest = None;
        let shape_a = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session.id,
            &[bad_mcp],
        )
        .await;
        // (b) connection authority missing its generation.
        let mut bad_gen = mcp_binding.clone();
        bad_gen.id = Uuid::now_v7();
        bad_gen.requirement_slot = "wf".into();
        bad_gen.slot_kind = "workspace_fetch".into();
        bad_gen.snapshot_version = None;
        bad_gen.effective_tools_json = None;
        bad_gen.effective_tools_digest = None;
        bad_gen.authority_generation = None;
        let shape_b = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session.id,
            &[bad_gen],
        )
        .await;
        // (c) none authority carrying a connection_id.
        let mut bad_none = none_binding("workspace_fetch", "none");
        bad_none.connection_id = Some(conn.id);
        let shape_c = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session.id,
            &[bad_none],
        )
        .await;
        // R1.5 FK negative: an mcp binding naming a NONEXISTENT snapshot version is
        // refused by the composite (tenant, connection, snapshot_version) FK.
        let mut bad_snap = mcp_binding.clone();
        bad_snap.id = Uuid::now_v7();
        bad_snap.requirement_slot = "fk-snap".into();
        bad_snap.snapshot_version = Some(999);
        let fk_snapshot = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session.id,
            &[bad_snap],
        )
        .await;

        cleanup_orgs(
            &pool,
            &[
                "delete from run_resource_bindings where tenant_id = $1",
                "delete from sessions where tenant_id = $1",
                "delete from connection_tool_snapshots where tenant_id = $1",
                "delete from integration_connections where tenant_id = $1",
                "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
                "delete from agents where tenant_id = $1",
                "delete from policies where tenant_id = $1",
            ],
            &[org_a.id, org_b.id],
        )
        .await;

        assert_eq!(
            a_bindings.len(),
            1,
            "the binding committed with the session"
        );
        assert_eq!(a_bindings[0].id, mcp_binding.id);
        assert_eq!(a_bindings[0].authority_kind, "connection");
        assert!(by_id.is_some(), "binding readable by id in scope");
        assert!(found.is_some(), "binding found by (slot_kind, slot)");
        assert!(b_bindings.is_empty(), "B cannot list A's bindings");
        assert!(by_id_b.is_none(), "B cannot read A's binding by id");
        assert!(
            fk_bad.is_err(),
            "binding for another tenant's session refused"
        );
        assert!(
            shape_a.is_err(),
            "mcp slot without snapshot fields rejected"
        );
        assert!(
            shape_b.is_err(),
            "connection authority without generation rejected"
        );
        assert!(
            shape_c.is_err(),
            "none authority with a connection_id rejected"
        );
        assert!(
            fk_snapshot.is_err(),
            "mcp binding naming a nonexistent snapshot version rejected (R1.5 FK)"
        );
    }

    /// R1.8: `create_session` writes the session, its resource bindings, AND its
    /// idempotency-claim bind in ONE transaction — a CHECK-violating binding must
    /// roll ALL of it back: no session, no binding, and the claim stays unbound.
    #[tokio::test]
    async fn create_session_rolls_back_on_check_violating_binding() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);

        let policy = upsert_policy(
            &pool,
            scope,
            "rb2",
            "name: rb2",
            &serde_json::json!({"name":"rb2"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "rb2-agent", None).await.unwrap();
        let rev = append_agent_revision(
            &pool,
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
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            "rb2-sub",
            "api",
            Some(rev.id),
            Some("t"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let InvocationClaim::Claimed { invocation_id } =
            claim_invocation(&pool, scope, sub.id, "idem-rollback", "digest")
                .await
                .unwrap()
        else {
            panic!("expected a fresh claim");
        };

        // authority_kind 'none' but carrying an authority_generation → violates
        // run_resource_bindings_authority_shape (no FK involved: all ids null).
        let bad = NewRunResourceBinding {
            id: Uuid::now_v7(),
            requirement_slot: "x".into(),
            slot_kind: "workspace_fetch".into(),
            authority_kind: "none".into(),
            connection_id: None,
            subscription_id: None,
            authority_generation: Some(1),
            connection_owner_type: None,
            connection_owner_user_id: None,
            snapshot_version: None,
            effective_tools_json: None,
            effective_tools_digest: None,
            resource_scope: serde_json::json!({}),
            resolved_by_principal_kind: "system".into(),
            resolved_by_principal_id: None,
            binding_mode: "organization".into(),
        };
        let result = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "rollback",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            Some(invocation_id),
            None,
            &[bad],
        )
        .await;

        let sessions: i64 = sqlx::query_scalar(
            "select count(*) from sessions where tenant_id = $1 and agent_id = $2",
        )
        .bind(org.id)
        .bind(agent.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let bindings: i64 =
            sqlx::query_scalar("select count(*) from run_resource_bindings where tenant_id = $1")
                .bind(org.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let claim_session: Option<Uuid> =
            sqlx::query_scalar("select session_id from trigger_invocations where id = $1")
                .bind(invocation_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        for stmt in [
            "delete from trigger_invocations where subscription_id in (select id from trigger_subscriptions where tenant_id = $1)",
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from run_resource_bindings where tenant_id = $1",
            "delete from sessions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org.id).execute(&pool).await.unwrap();
        }
        sqlx::query("delete from tenants where id = $1")
            .bind(org.id)
            .execute(&pool)
            .await
            .unwrap();

        assert!(
            result.is_err(),
            "create_session must fail on a CHECK-violating binding"
        );
        assert_eq!(sessions, 0, "no session row committed");
        assert_eq!(bindings, 0, "no binding row committed");
        assert_eq!(claim_session, None, "the idempotency claim stays unbound");
    }

    /// Custom catalog entries land tenant-scoped, are invisible to another org,
    /// and cannot mask a global slug.
    #[tokio::test]
    async fn phase_c_catalog_custom_entries_tenant_scoped() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = identity::create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = identity::create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let entry_slug = format!("xt-cat-{}", Uuid::now_v7().simple());
        let created = create_catalog_entry(
            &pool,
            scope_a,
            &entry_slug,
            "Tenant custom",
            None,
            None,
            &serde_json::json!([]),
            Some("https://mcp.example.test/mcp"),
            "streamable_http",
            "none",
            &serde_json::json!({}),
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();

        let a_sees = get_catalog_by_slug(&pool, scope_a, &entry_slug)
            .await
            .unwrap();
        let b_sees = get_catalog_by_slug(&pool, scope_b, &entry_slug)
            .await
            .unwrap();
        let a_list = list_catalog(&pool, scope_a).await.unwrap();
        let b_list = list_catalog(&pool, scope_b).await.unwrap();
        // A custom slug colliding with a GLOBAL seed ('github') is refused.
        let collision = create_catalog_entry(
            &pool,
            scope_a,
            "github",
            "Shadow",
            None,
            None,
            &serde_json::json!([]),
            Some("https://evil.example.test/mcp"),
            "streamable_http",
            "none",
            &serde_json::json!({}),
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();

        cleanup_orgs(
            &pool,
            &["delete from connector_catalog where tenant_id = $1"],
            &[org_a.id, org_b.id],
        )
        .await;

        let created = created.expect("custom entry lands");
        assert_eq!(created.tenant_id, Some(org_a.id));
        assert!(a_sees.is_some(), "A sees its own custom entry");
        assert!(b_sees.is_none(), "B cannot see A's custom entry");
        assert!(
            a_list.iter().any(|c| c.slug == entry_slug),
            "A's list includes its custom entry"
        );
        assert!(
            !b_list.iter().any(|c| c.slug == entry_slug),
            "B's list excludes A's custom entry"
        );
        assert!(collision.is_none(), "a global-slug collision is refused");
    }

    // ─── Phase D envelope sealing (#32) ─────────────────────────────────────

    async fn new_dek_org(pool: &PgPool) -> TenantScope {
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = crate::identity::create_org(pool, &slug, None)
            .await
            .unwrap();
        TenantScope::assume(org.id)
    }

    // Children-first cleanup (tenant FKs are NO ACTION): tenant_llm_keys +
    // tenant_deks + integration_connections before the tenant row.
    async fn cleanup_dek_tenant(pool: &PgPool, tenant: Uuid) {
        for stmt in [
            "delete from tenant_llm_keys where tenant_id = $1",
            "delete from tenant_deks where tenant_id = $1",
            "delete from integration_connections where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(stmt).bind(tenant).execute(pool).await.unwrap();
        }
    }

    #[tokio::test]
    async fn tenant_dek_get_insert_latest() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = new_dek_org(&pool).await;
        let tenant = scope.tenant_id();

        assert!(get_tenant_dek(&pool, tenant, 1).await.unwrap().is_none());
        assert!(latest_tenant_dek(&pool, tenant).await.unwrap().is_none());

        insert_tenant_dek(&pool, tenant, 1, "static:abc", b"wrapped-dek-1")
            .await
            .unwrap();
        let row = get_tenant_dek(&pool, tenant, 1)
            .await
            .unwrap()
            .expect("row");
        assert_eq!(row.version, 1);
        assert_eq!(row.kek_id, "static:abc");
        assert_eq!(row.wrapped_dek, b"wrapped-dek-1");
        assert!(row.retired_at.is_none());
        assert_eq!(
            latest_tenant_dek(&pool, tenant)
                .await
                .unwrap()
                .unwrap()
                .version,
            1
        );
        // A version that was never minted is None (open must fail closed on it).
        assert!(get_tenant_dek(&pool, tenant, 2).await.unwrap().is_none());

        cleanup_dek_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn tenant_dek_insert_race_one_row_wins() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = new_dek_org(&pool).await;
        let tenant = scope.tenant_id();

        // Concurrent first-mints for (tenant, 1) with DIFFERENT wrapped bytes:
        // `on conflict do nothing` means exactly ONE row lands, and every racer
        // that re-reads sees the SAME winner (kms::dek_for_seal relies on this to
        // converge concurrent first-seals on one DEK).
        let mut handles = vec![];
        for i in 0..6u8 {
            let p = pool.clone();
            handles.push(tokio::spawn(async move {
                insert_tenant_dek(&p, tenant, 1, "static:race", &[i; 16])
                    .await
                    .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let (n,): (i64,) =
            sqlx::query_as("select count(*) from tenant_deks where tenant_id = $1 and version = 1")
                .bind(tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(n, 1, "exactly one DEK row survives the race");
        let winner = get_tenant_dek(&pool, tenant, 1)
            .await
            .unwrap()
            .unwrap()
            .wrapped_dek;
        assert_eq!(
            get_tenant_dek(&pool, tenant, 1)
                .await
                .unwrap()
                .unwrap()
                .wrapped_dek,
            winner,
            "re-reads are stable — all racers unwrap the same DEK"
        );

        cleanup_dek_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn sealed_column_key_version_roundtrips_and_counts() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = new_dek_org(&pool).await;
        let tenant = scope.tenant_id();

        // A v2-marked credential + webhook secret round-trip their key_version.
        let v2 = create_connection(
            &pool,
            scope,
            "github",
            "kv-acct-v2",
            "kv-conn-v2",
            Some(b"env-cred"),
            2,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            Some(b"env-webhook"),
            2,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            connection_credential_sealed(&pool, scope, v2.id)
                .await
                .unwrap()
                .unwrap(),
            (b"env-cred".to_vec(), 2)
        );
        assert_eq!(
            connection_webhook_secret_sealed(&pool, scope, v2.id)
                .await
                .unwrap()
                .unwrap(),
            (b"env-webhook".to_vec(), 2)
        );

        // A legacy (v1) credential defaults its companion to 1.
        let v1 = create_connection(
            &pool,
            scope,
            "github",
            "kv-acct-v1",
            "kv-conn-v1",
            Some(b"legacy-cred"),
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            connection_credential_sealed(&pool, scope, v1.id)
                .await
                .unwrap()
                .unwrap(),
            (b"legacy-cred".to_vec(), 1)
        );

        // The retirement-gate counter sees both key-versions (global scan; other
        // tenants may add to the totals, so assert presence, not exact counts).
        let counts = crate::system_worker::sealed_key_version_counts(&pool)
            .await
            .unwrap();
        // THIRTEEN sealed columns today (Tasks 3/4/5 added the two
        // oauth_client_registrations twins, the connector_oauth_flows PKCE
        // verifier, and tenant_llm_keys). `reseal::FAMILIES` is the authority and
        // `reseal::tests::counts_and_families_cover_the_same_set` enforces
        // set-equality with this fn; here we only pin the shape.
        assert_eq!(counts.len(), 13, "one row per sealed column");
        let distinct: std::collections::BTreeSet<&str> =
            counts.iter().map(|c| c.family.as_str()).collect();
        assert_eq!(
            distinct.len(),
            counts.len(),
            "every counted family is distinct — no double-counted column"
        );
        let cred = counts
            .iter()
            .find(|c| c.family == "integration_connections.credential_sealed")
            .unwrap();
        assert!(cred.legacy >= 1 && cred.envelope >= 1);

        cleanup_dek_tenant(&pool, tenant).await;
    }

    // The re-seal job's DB mechanics (Task 2): keyset paging, the FOR UPDATE
    // lock/read, and the CAS write — exercised with arbitrary bytes (the DB
    // layer never sees plaintext; the crypto roundtrip is tested server-side).
    // Assertions are written to be robust against OTHER tenants sharing the
    // table (the test DB is shared): filter/relate to our own seeded ids only.
    #[tokio::test]
    async fn reseal_paging_lock_and_cas() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = new_dek_org(&pool).await;
        let tenant = scope.tenant_id();

        // Three v1 credential rows under a throwaway tenant.
        let mut ids = vec![];
        for i in 0..3 {
            let c = create_connection(
                &pool,
                scope,
                "custom",
                &format!("rs-acct-{i}"),
                &format!("rs-conn-{i}"),
                Some(format!("legacy-cred-{i}").as_bytes()),
                1,
                &serde_json::json!([]),
                &serde_json::json!({}),
                &serde_json::json!({}),
                None,
                1,
                ConnectionAuth::static_active(),
                ConnectionOwner::Organization,
                None,
            )
            .await
            .unwrap();
            ids.push(c.id);
        }
        ids.sort(); // reseal_candidate_ids orders by id

        let tbl = "integration_connections";
        let col = "credential_sealed";
        let ver = "credential_key_version";
        let key = "id"; // integration_connections is keyed by id

        // Keyset cursor: `id > after` is exclusive. After ids[0], a large page
        // includes ids[1]/ids[2] but never ids[0].
        let after0 =
            crate::system_worker::reseal_candidate_ids(&pool, tbl, col, ver, key, ids[0], 1000)
                .await
                .unwrap();
        assert!(!after0.contains(&ids[0]), "cursor is exclusive");
        assert!(after0.contains(&ids[1]) && after0.contains(&ids[2]));
        // After the last id, none of ours can appear (all <= ids[2]).
        let after_last =
            crate::system_worker::reseal_candidate_ids(&pool, tbl, col, ver, key, ids[2], 1000)
                .await
                .unwrap();
        assert!(ids.iter().all(|i| !after_last.contains(i)));
        // `limit` caps the page (≥1 v1 row exists past ids[0] — ids[1]).
        let capped =
            crate::system_worker::reseal_candidate_ids(&pool, tbl, col, ver, key, ids[0], 1)
                .await
                .unwrap();
        assert_eq!(capped.len(), 1, "limit bounds the page");

        // Lock + read one row inside a tx, then CAS the v2 bytes in.
        let mut tx = pool.begin().await.unwrap();
        let locked = crate::system_worker::reseal_lock_row(&mut tx, tbl, col, ver, key, ids[0])
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(locked.0.as_deref(), Some(b"legacy-cred-0".as_ref()));
        assert_eq!(locked.1, 1, "still v1 under the lock");
        assert_eq!(
            locked.2,
            Some(tenant),
            "carries the row's tenant for the seal ctx (Some for a tenant-owned family)"
        );
        let affected = crate::system_worker::reseal_write_row(
            &mut tx,
            tbl,
            col,
            ver,
            key,
            ids[0],
            b"v2-bytes",
        )
        .await
        .unwrap();
        assert_eq!(affected, 1, "CAS flips 1 → 2");
        tx.commit().await.unwrap();

        // The reader sees the new bytes at v2.
        assert_eq!(
            connection_credential_sealed(&pool, scope, ids[0])
                .await
                .unwrap()
                .unwrap(),
            (b"v2-bytes".to_vec(), 2)
        );

        // A second CAS on the now-v2 row is a no-op (a concurrent writer already
        // moved it off v1) — 0 rows, the caller counts it as skipped.
        let mut tx2 = pool.begin().await.unwrap();
        let noop = crate::system_worker::reseal_write_row(
            &mut tx2,
            tbl,
            col,
            ver,
            key,
            ids[0],
            b"v2-again",
        )
        .await
        .unwrap();
        assert_eq!(noop, 0, "CAS no-op when the row already left v1");
        tx2.commit().await.unwrap();

        // The re-sealed row drops out of the candidate predicate; the other two
        // remain (idempotent restart-safety: re-scans skip finished rows).
        let remaining = crate::system_worker::reseal_candidate_ids(
            &pool,
            tbl,
            col,
            ver,
            key,
            Uuid::nil(),
            1000,
        )
        .await
        .unwrap();
        assert!(!remaining.contains(&ids[0]));
        assert!(remaining.contains(&ids[1]) && remaining.contains(&ids[2]));

        cleanup_dek_tenant(&pool, tenant).await;
    }

    // Per-tenant LiteLLM virtual keys (Task 5): insert-or-adopt + rotate row
    // semantics, with ARBITRARY bytes (the crypto roundtrip is server-side).
    #[tokio::test]
    async fn tenant_llm_key_insert_adopt_and_rotate() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = new_dek_org(&pool).await;
        let tenant = scope.tenant_id();

        // Not minted yet.
        assert!(tenant_llm_key_sealed(&pool, scope).await.unwrap().is_none());
        assert!(tenant_llm_key_row(&pool, scope).await.unwrap().is_none());

        // First insert wins and returns our sealed bytes.
        let first = insert_tenant_llm_key(
            &pool,
            scope,
            b"sealed-v1-a",
            1,
            "fbx-tenant-x",
            Some("tok-a"),
        )
        .await
        .unwrap();
        assert!(first.we_won, "first insert wins");
        assert_eq!(first.sealed, b"sealed-v1-a");
        assert_eq!(first.key_version, 1);
        assert_eq!(
            tenant_llm_key_sealed(&pool, scope).await.unwrap().unwrap(),
            (b"sealed-v1-a".to_vec(), 1)
        );

        // A racing second insert loses (ON CONFLICT DO NOTHING) and ADOPTS the
        // winner's sealed bytes — its own minted key would be orphaned.
        let second = insert_tenant_llm_key(
            &pool,
            scope,
            b"sealed-v1-b",
            1,
            "fbx-tenant-x",
            Some("tok-b"),
        )
        .await
        .unwrap();
        assert!(!second.we_won, "second insert loses the race");
        assert_eq!(second.sealed, b"sealed-v1-a", "adopts the winner's key");
        // The stored row is unchanged (still the winner's).
        assert_eq!(
            tenant_llm_key_sealed(&pool, scope).await.unwrap().unwrap(),
            (b"sealed-v1-a".to_vec(), 1)
        );

        // Rotate: returns the OLD sealed for LiteLLM cleanup, swaps in the new,
        // bumps rotated_at, records the new companion version.
        let old = rotate_tenant_llm_key(
            &pool,
            scope,
            b"sealed-v2-c",
            2,
            "fbx-tenant-x",
            Some("tok-c"),
        )
        .await
        .unwrap();
        assert_eq!(old, Some((b"sealed-v1-a".to_vec(), 1)), "old key returned");
        assert_eq!(
            tenant_llm_key_sealed(&pool, scope).await.unwrap().unwrap(),
            (b"sealed-v2-c".to_vec(), 2)
        );
        let rotated_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("select rotated_at from tenant_llm_keys where tenant_id = $1")
                .bind(tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(rotated_at.is_some(), "rotate bumps rotated_at");

        // The row reader carries the CAS expectation + the durable cooldown
        // stamp (Phase D review H3/M4).
        let row = tenant_llm_key_row(&pool, scope).await.unwrap().unwrap();
        assert_eq!(row.sealed, b"sealed-v2-c");
        assert_eq!(row.key_version, 2);
        assert_eq!(
            row.minted_at,
            rotated_at.unwrap(),
            "minted_at is the rotation instant once rotated"
        );

        // M4: the recovery CAS only swaps while the stored bytes are still the
        // ones the caller read. A stale expectation (the key an in-flight request
        // presented, already rotated away) matches ZERO rows — the freshly
        // rotated key survives instead of being silently superseded.
        assert!(
            !rotate_tenant_llm_key_cas(
                &pool,
                scope,
                b"sealed-v1-a", // the pre-rotation key
                b"sealed-v3-stale",
                2,
                "fbx-tenant-x",
                None,
            )
            .await
            .unwrap(),
            "CAS against a superseded key must not swap"
        );
        assert_eq!(
            tenant_llm_key_sealed(&pool, scope).await.unwrap().unwrap(),
            (b"sealed-v2-c".to_vec(), 2),
            "the winning rotation is intact"
        );

        // …and it DOES swap when the expectation is the live key.
        assert!(rotate_tenant_llm_key_cas(
            &pool,
            scope,
            b"sealed-v2-c",
            b"sealed-v3-d",
            2,
            "fbx-tenant-x",
            Some("tok-d"),
        )
        .await
        .unwrap());
        assert_eq!(
            tenant_llm_key_sealed(&pool, scope).await.unwrap().unwrap(),
            (b"sealed-v3-d".to_vec(), 2)
        );

        cleanup_dek_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn tenant_llm_key_rotate_creates_when_absent() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = new_dek_org(&pool).await;
        let tenant = scope.tenant_id();

        // Rotate on a tenant with no key: nothing to delete (None), creates it.
        let old = rotate_tenant_llm_key(&pool, scope, b"sealed-new", 2, "fbx-tenant-y", None)
            .await
            .unwrap();
        assert_eq!(old, None, "no prior key to retire");
        assert_eq!(
            tenant_llm_key_sealed(&pool, scope).await.unwrap().unwrap(),
            (b"sealed-new".to_vec(), 2)
        );

        cleanup_dek_tenant(&pool, tenant).await;
    }

    // ─── OAuth client registrations (Phase D Task 3, #32) ───────────────────

    fn new_reg<'a>(
        tenant_id: Option<Uuid>,
        issuer: &'a str,
        redirect: &'a str,
        client_id: &'a str,
    ) -> NewOauthClientRegistration<'a> {
        NewOauthClientRegistration {
            tenant_id,
            issuer,
            redirect_uri: redirect,
            source: "dcr",
            client_id,
            client_secret_sealed: None,
            client_secret_key_version: 1,
            registration_endpoint: Some("https://as.test/register"),
            registration_access_token_sealed: None,
            registration_access_token_key_version: 1,
            token_endpoint_auth_method: Some("none"),
        }
    }

    // Two transactions inserting the SAME (issuer, redirect): exactly one row
    // lands and the loser's ON CONFLICT DO NOTHING yields None, so the caller
    // re-selects the winner (never a duplicate DCR client). Each `&pool` insert
    // is its own transaction.
    #[tokio::test]
    async fn client_registration_insert_race_keeps_one_row() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let issuer = format!("https://as-{}.test", Uuid::now_v7().simple());
        let redirect = "https://fbx.test/v1/oauth/callback";

        let first = insert_client_registration(&pool, new_reg(None, &issuer, redirect, "client-a"))
            .await
            .unwrap();
        assert!(first.is_some(), "first insert wins");
        assert!(
            first.as_ref().unwrap().last_used_at.is_some(),
            "last_used_at set"
        );

        // The loser conflicts on the global partial unique → None.
        let second =
            insert_client_registration(&pool, new_reg(None, &issuer, redirect, "client-b"))
                .await
                .unwrap();
        assert!(
            second.is_none(),
            "second insert conflicts (ON CONFLICT DO NOTHING)"
        );

        // Re-select returns the ONE winner, and there is exactly one row.
        let winner = find_client_registration(&pool, &issuer, redirect)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(winner.client_id, "client-a");
        let (n,): (i64,) = sqlx::query_as(
            "select count(*) from oauth_client_registrations
             where issuer = $1 and redirect_uri = $2",
        )
        .bind(&issuer)
        .bind(redirect)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 1);

        // by-id load + touch + delete round-trip.
        let by_id = find_client_registration_by_id(&pool, winner.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_id.client_id, "client-a");
        assert!(by_id.tenant_id.is_none(), "v1 rows are global");
        touch_client_registration(&pool, winner.id).await.unwrap();
        delete_client_registration(&pool, winner.id).await.unwrap();
        assert!(find_client_registration(&pool, &issuer, redirect)
            .await
            .unwrap()
            .is_none());
    }

    // The two partial uniques are INDEPENDENT: a global row (tenant_id NULL) and a
    // per-tenant row can share the same (issuer, redirect_uri); a second row within
    // the same scope conflicts; and the v1 reader sees ONLY the global row.
    #[tokio::test]
    async fn client_registration_partial_uniques_are_independent() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let tenant = org.id;
        let issuer = format!("https://as-{}.test", Uuid::now_v7().simple());
        let redirect = "https://fbx.test/v1/oauth/callback";

        let global =
            insert_client_registration(&pool, new_reg(None, &issuer, redirect, "g-client"))
                .await
                .unwrap();
        assert!(global.is_some(), "global row inserts");
        // A per-tenant row with the SAME key coexists (different partial index).
        let tenant_row =
            insert_client_registration(&pool, new_reg(Some(tenant), &issuer, redirect, "t-client"))
                .await
                .unwrap();
        assert!(
            tenant_row.is_some(),
            "a per-tenant row is independent of the same-key global row"
        );
        // A second GLOBAL row for the key conflicts.
        assert!(
            insert_client_registration(&pool, new_reg(None, &issuer, redirect, "g-dupe"))
                .await
                .unwrap()
                .is_none(),
            "a second global row for the key is refused"
        );
        // The v1 reader returns ONLY the global row (tenant_id is null).
        let found = find_client_registration(&pool, &issuer, redirect)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.client_id, "g-client");
        assert!(found.tenant_id.is_none());

        // Cleanup (registration rows before the tenant — FKs are NO ACTION).
        sqlx::query("delete from oauth_client_registrations where issuer = $1")
            .bind(&issuer)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from tenants where id = $1")
            .bind(tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    // The advisory lock serializes DCR per (issuer, redirect_uri): while one
    // transaction holds it, a second connection cannot take the SAME key but CAN
    // take a different one; it frees on transaction end. This is what collapses
    // concurrent connects to ONE `/register`.
    #[tokio::test]
    async fn registration_lock_serializes_same_key() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let issuer = format!("https://as-{}.test", Uuid::now_v7().simple());
        let redirect = "https://fbx.test/v1/oauth/callback";
        let key = registration_lock_key(&issuer, redirect);
        assert_ne!(
            key,
            registration_lock_key(&issuer, "https://other.test/cb"),
            "distinct (issuer, redirect) fold to distinct keys"
        );

        let mut tx1 = pool.begin().await.unwrap();
        acquire_registration_lock(&mut tx1, &issuer, redirect)
            .await
            .unwrap();
        // A second connection cannot take the held key, but a different key is free.
        let mut c2 = pool.acquire().await.unwrap();
        let (same,): (bool,) = sqlx::query_as("select pg_try_advisory_xact_lock($1)")
            .bind(key)
            .fetch_one(&mut *c2)
            .await
            .unwrap();
        assert!(!same, "same-key lock is held by tx1");
        let (other,): (bool,) = sqlx::query_as("select pg_try_advisory_xact_lock($1)")
            .bind(registration_lock_key(&issuer, "https://other.test/cb"))
            .fetch_one(&mut *c2)
            .await
            .unwrap();
        assert!(other, "a different (issuer, redirect) key is independent");
        drop(c2);

        // Releasing tx1 frees the key.
        tx1.rollback().await.unwrap();
        let mut tx3 = pool.begin().await.unwrap();
        let (freed,): (bool,) = sqlx::query_as("select pg_try_advisory_xact_lock($1)")
            .bind(key)
            .fetch_one(&mut *tx3)
            .await
            .unwrap();
        assert!(freed, "the lock is free after tx1 released");
        tx3.rollback().await.unwrap();
    }

    // ─── Connector OAuth flows (Phase D Task 4, #32 — invariant 20) ──────────

    // A flow-row template borrowing the caller's per-case hashes/scopes (one
    // shared lifetime); string/byte literals are 'static and coerce in.
    fn new_flow<'a>(
        connection_id: Uuid,
        expected_generation: i32,
        state_hash: &'a str,
        browser_hash: &'a str,
        scopes: &'a Value,
        ttl_secs: i64,
    ) -> NewConnectorOauthFlow<'a> {
        NewConnectorOauthFlow {
            connection_id,
            initiated_by_user_id: None,
            state_hash,
            browser_hash,
            issuer: "https://as.test",
            authorization_endpoint: "https://as.test/authorize",
            token_endpoint: "https://as.test/token",
            metadata_digest: "sha256:abc",
            resource: "https://mcp.test",
            redirect_uri: "https://fbx.test/v1/oauth/callback",
            scopes,
            challenge: "chal",
            challenge_method: "S256",
            client_registration_id: None,
            client_id: "client-1",
            pkce_verifier_sealed: &[1, 2, 3],
            pkce_verifier_key_version: 1,
            expected_generation,
            ttl_secs,
        }
    }

    // The full claim matrix: happy path consumes once; replay refused; a WRONG
    // browser_hash matches nothing AND leaves consumed_at null (then the right
    // browser still completes — the no-burn proof); expired refused; peek never
    // consumes; and the row FREEZES the connection's generation so a mid-flow
    // reconnect (bump) is detectable by the callback's coherence check.
    #[tokio::test]
    async fn connector_oauth_flow_claim_matrix() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);
        // A connection to satisfy the composite (tenant_id, connection_id) FK.
        let conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct",
            "disp",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({ "base_url": "https://x" }),
            None,
            1,
            ConnectionAuth {
                auth_kind: "oauth",
                status: "pending",
                oauth: None,
                client_secret_sealed: None,
                client_secret_key_version: 1,
                registration_id: None,
            },
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        let scopes = serde_json::json!(["read", "offline_access"]);
        let gen = conn.authorization_generation;
        let s_hash = sha256_hex("state-secret");
        let b_hash = sha256_hex("cookie-secret");

        // Insert returns the persisted row (its expires_at seeds the boot token).
        let row = insert_connector_oauth_flow(
            &pool,
            scope,
            new_flow(conn.id, gen, &s_hash, &b_hash, &scopes, 600),
        )
        .await
        .unwrap();
        assert_eq!(row.tenant_id, org.id);
        assert_eq!(row.connection_id, conn.id);
        assert!(row.consumed_at.is_none());
        assert!(row.expires_at > Utc::now());

        // peek returns the row and does NOT consume it.
        let peeked = peek_connector_oauth_flow(&pool, &s_hash)
            .await
            .unwrap()
            .expect("peek finds the live flow");
        assert_eq!(peeked.id, row.id);
        assert!(peeked.consumed_at.is_none(), "peek never consumes");
        assert_eq!(peeked.pkce_verifier_sealed, vec![1, 2, 3]);

        // WRONG browser_hash: matches nothing AND burns nothing.
        assert!(
            claim_connector_oauth_flow(&pool, &s_hash, &sha256_hex("attacker"))
                .await
                .unwrap()
                .is_none(),
            "wrong browser is refused"
        );
        let unburned = peek_connector_oauth_flow(&pool, &s_hash)
            .await
            .unwrap()
            .unwrap();
        assert!(
            unburned.consumed_at.is_none(),
            "a wrong-browser claim burns NOTHING (the no-burn proof)"
        );

        // RIGHT browser then still completes — consumes exactly once.
        let claimed = claim_connector_oauth_flow(&pool, &s_hash, &b_hash)
            .await
            .unwrap()
            .expect("the right browser claims after a wrong-browser attempt");
        assert_eq!(claimed.client_id, "client-1");
        assert_eq!(claimed.scopes, scopes);
        assert_eq!(claimed.expected_generation, conn.authorization_generation);
        assert!(claimed.consumed_at.is_some(), "claim consumes the row");

        // REPLAY (correct browser, second time) is refused.
        assert!(
            claim_connector_oauth_flow(&pool, &s_hash, &b_hash)
                .await
                .unwrap()
                .is_none(),
            "replay of a consumed flow is refused"
        );

        // Unknown state_hash: no claim, no peek row.
        assert!(
            claim_connector_oauth_flow(&pool, &sha256_hex("nope"), &b_hash)
                .await
                .unwrap()
                .is_none()
        );
        assert!(peek_connector_oauth_flow(&pool, &sha256_hex("nope"))
            .await
            .unwrap()
            .is_none());

        // Expired flow: claim refused; peek still SEES it (peek is a plain read,
        // it never filters — the caller classifies).
        let s_exp = sha256_hex("state-expired");
        insert_connector_oauth_flow(
            &pool,
            scope,
            new_flow(conn.id, gen, &s_exp, &b_hash, &scopes, -5),
        )
        .await
        .unwrap();
        assert!(
            claim_connector_oauth_flow(&pool, &s_exp, &b_hash)
                .await
                .unwrap()
                .is_none(),
            "an already-expired flow is refused"
        );
        assert!(
            peek_connector_oauth_flow(&pool, &s_exp)
                .await
                .unwrap()
                .is_some(),
            "peek never filters — it returns the expired row so the caller can 400"
        );

        // Generation drift: the row froze the connection's generation; a reconnect
        // bumps it, so the callback's `authorization_generation == expected_generation`
        // coherence check detects the drift and refuses.
        let s_gen = sha256_hex("state-gen");
        let gen_flow = insert_connector_oauth_flow(
            &pool,
            scope,
            new_flow(conn.id, gen, &s_gen, &b_hash, &scopes, 600),
        )
        .await
        .unwrap();
        let new_gen = bump_connection_generation(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        let fresh = get_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fresh.authorization_generation, new_gen);
        assert_ne!(
            fresh.authorization_generation, gen_flow.expected_generation,
            "a reconnect (generation bump) drifts past the flow's frozen expected_generation"
        );

        // Cleanup: children-first (FKs are NO ACTION) — flows, then the connection,
        // then the tenant.
        for stmt in [
            "delete from connector_oauth_flows where tenant_id = $1",
            "delete from integration_connections where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(stmt).bind(org.id).execute(&pool).await.unwrap();
        }
    }

    /// Phase D (#32, #75) — the RLS acceptance core. Proves DB-enforced tenant
    /// isolation, NOT the Rust `where tenant_id = $n` predicate: every assertion query
    /// OMITS the predicate on purpose (the buggy-predicate proof).
    ///
    /// TEST-ROLE GOTCHA (resolution 9): a Postgres SUPERUSER bypasses RLS entirely,
    /// even under FORCE — and CI's DB user is the superuser `postgres`. So the
    /// assertions run through a dedicated connection that `SET ROLE fluidbox_runtime`
    /// (the 0018 NON-owner role, `GRANT`ed to the owner so SET ROLE works on any
    /// Postgres). Only then does the policy actually run, so this proves the policy
    /// logic under the REAL runtime role regardless of the base user's privilege.
    /// Seeding runs under the audited bypass (`worker_tx`, on the `test_connect`
    /// fixture pool) so it works whether the base role is a superuser (RLS skipped)
    /// or the table owner under FORCE RLS — and the assertions below never touch
    /// that pool, so the bypass cannot leak into what they prove.
    /// `connect()` here applies migrations 0014-0018 from scratch — a failed 0018
    /// would fail this test at `.expect("connect")` (the migration smoke check).
    #[tokio::test]
    async fn rls_enforces_tenant_isolation_under_runtime_role() {
        use sqlx::{Connection, Executor};
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");

        // Two throwaway tenants + one session + one event each.
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        {
            let mut tx = worker_tx(&pool).await.unwrap();
            for id in [a, b] {
                let slug = format!("rls-{}", id.simple());
                sqlx::query("insert into tenants (id, name, slug) values ($1, $2, $3)")
                    .bind(id)
                    .bind(&slug)
                    .bind(&slug)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            tx.commit().await.unwrap();
        }
        for id in [a, b] {
            let scope = TenantScope::assume(id);
            let policy = upsert_policy(
                &pool,
                scope,
                "rls",
                "name: rls",
                &serde_json::json!({"name":"rls"}),
            )
            .await
            .unwrap();
            let agent = create_agent(&pool, scope, "rls-agent", None).await.unwrap();
            let rev = append_agent_revision(
                &pool,
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
            let session = create_session(
                &pool,
                scope,
                agent.id,
                rev.id,
                "supervised",
                "trusted",
                "rls task",
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
            .unwrap();
            // One event per session (a child-table row for the parent-composed policy).
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query(
                "insert into events (event_id, session_id, seq, actor, type, payload, occurred_at)
                 values ($1, $2, 1, 'system', 'rls.test', '{}'::jsonb, now())",
            )
            .bind(Uuid::now_v7())
            .bind(session.id)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }

        // Assert through the NON-superuser runtime role — otherwise RLS is bypassed.
        let mut rt = sqlx::PgConnection::connect(&url).await.expect("rt connect");
        rt.execute("set role fluidbox_runtime")
            .await
            .expect("set role");

        async fn count_as(
            rt: &mut sqlx::PgConnection,
            guc: Option<(&str, String)>,
            sql: &'static str,
        ) -> i64 {
            let mut tx = rt.begin().await.unwrap();
            if let Some((name, val)) = guc {
                sqlx::query("select set_config($1, $2, true)")
                    .bind(name)
                    .bind(val)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            let (n,): (i64,) = sqlx::query_as(sql).fetch_one(&mut *tx).await.unwrap();
            tx.rollback().await.ok();
            n
        }
        let a_str = a.to_string();
        let tid = "fluidbox.tenant_id";

        // (a) A-scope sees ONLY tenant A's session — with NO where clause (#75 proof).
        assert_eq!(
            count_as(
                &mut rt,
                Some((tid, a_str.clone())),
                "select count(*) from sessions"
            )
            .await,
            1,
            "A-scope must see only tenant A's session even without a predicate"
        );
        // (c) child table (events) follows the parent (sessions) policy.
        assert_eq!(
            count_as(
                &mut rt,
                Some((tid, a_str.clone())),
                "select count(*) from events"
            )
            .await,
            1,
            "A-scope sees only A's events (parent-composed EXISTS policy)"
        );
        // (f) tenants keys on its own id — A-scope sees exactly its own row.
        assert_eq!(
            count_as(
                &mut rt,
                Some((tid, a_str.clone())),
                "select count(*) from tenants"
            )
            .await,
            1,
            "A-scope sees exactly the tenants row whose id matches"
        );
        // (d) the audited bypass sees BOTH tenants' rows.
        assert!(
            count_as(
                &mut rt,
                Some(("fluidbox.bypass", "system_worker".into())),
                "select count(*) from sessions"
            )
            .await
                >= 2,
            "the system_worker bypass sees every tenant"
        );
        // (e) no GUC → zero rows on a policy'd table.
        assert_eq!(
            count_as(&mut rt, None, "select count(*) from sessions").await,
            0,
            "a transaction with no GUC sees nothing"
        );

        // (b) INSERT of a cross-tenant row is refused by WITH CHECK.
        let mut tx = rt.begin().await.unwrap();
        sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
            .bind(&a_str)
            .execute(&mut *tx)
            .await
            .unwrap();
        let res = sqlx::query(
            "insert into settings (tenant_id, key, value) values ($1, 'rls-check', '{}'::jsonb)",
        )
        .bind(b) // tenant B under the tenant-A GUC
        .execute(&mut *tx)
        .await;
        tx.rollback().await.ok();
        let err = res.expect_err("a cross-tenant insert must be refused by RLS WITH CHECK");
        assert!(
            err.to_string()
                .to_lowercase()
                .contains("row-level security"),
            "expected an RLS policy violation, got: {err}"
        );

        rt.close().await.ok();

        // Cleanup, children-first, under the bypass (FKs are NO ACTION; sessions
        // cascade events, agents cascade revisions).
        let mut tx = worker_tx(&pool).await.unwrap();
        for id in [a, b] {
            for stmt in [
                "delete from sessions where tenant_id = $1",
                "delete from agents where tenant_id = $1",
                "delete from policies where tenant_id = $1",
                "delete from tenants where id = $1",
            ] {
                sqlx::query(stmt).bind(id).execute(&mut *tx).await.ok();
            }
        }
        tx.commit().await.unwrap();
    }

    /// Seed a throwaway tenant + one `created` session, returning both ids. The
    /// tenant insert rides `worker_tx` (a new tenant id is no GUC's tenant); the
    /// policy/agent/revision/session ride the scoped repositories. Runs on the base
    /// pool (superuser bypasses RLS), so it is agnostic to the enforcement asserted.
    async fn seed_tenant_session(pool: &PgPool) -> (Uuid, Uuid) {
        let tenant = Uuid::now_v7();
        {
            let slug = format!("rls-sw-{}", tenant.simple());
            let mut tx = worker_tx(pool).await.unwrap();
            sqlx::query("insert into tenants (id, name, slug) values ($1, $2, $3)")
                .bind(tenant)
                .bind(&slug)
                .bind(&slug)
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            pool,
            scope,
            "rls",
            "name: rls",
            &serde_json::json!({"name":"rls"}),
        )
        .await
        .unwrap();
        let agent = create_agent(pool, scope, "rls-agent", None).await.unwrap();
        let rev = append_agent_revision(
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
        let session = create_session(
            pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "rls task",
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
        .unwrap();
        (tenant, session.id)
    }

    async fn cleanup_sw_tenant(pool: &PgPool, tenant: Uuid) {
        let mut tx = worker_tx(pool).await.unwrap();
        for stmt in [
            "delete from integration_connections where tenant_id = $1",
            "delete from sessions where tenant_id = $1",
            "delete from agents where tenant_id = $1",
            "delete from policies where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(stmt).bind(tenant).execute(&mut *tx).await.ok();
        }
        tx.commit().await.unwrap();
    }

    /// Phase D (#32, #75) — RLS wave B, system_worker bypass. Proves (b) the
    /// `system_worker` scans see cross-tenant rows THROUGH `worker_tx`, and (c) THE
    /// EXPLICITNESS PROOF: the identically-shaped query WITHOUT `worker_tx` (a plain
    /// runtime-role transaction, no GUC) sees ZERO rows — the bypass is a deliberate,
    /// grep-able choice, never ambient. The `system_worker` fns are exercised through
    /// a pool that `SET ROLE`s to the NON-owner `fluidbox_runtime` (a superuser would
    /// bypass RLS and make the test vacuous).
    #[tokio::test]
    async fn rls_system_worker_bypass_is_explicit() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (ta, sa) = seed_tenant_session(&pool).await;
        let (tb, sb) = seed_tenant_session(&pool).await;

        // Runtime-role pool: the system_worker fns' internal `worker_tx` runs as
        // fluidbox_runtime under FORCE RLS, so the bypass is actually exercised.
        let rt_pool = connect(&url, Some("fluidbox_runtime"))
            .await
            .expect("runtime pool");

        // (b) two representative cross-tenant scans see BOTH tenants' rows.
        let in_status = system_worker::sessions_in_status(&rt_pool, &["created"])
            .await
            .unwrap();
        assert_eq!(
            in_status
                .iter()
                .filter(|s| s.id == sa || s.id == sb)
                .count(),
            2,
            "sessions_in_status (worker_tx) must see BOTH tenants' sessions"
        );
        assert!(
            system_worker::get_session(&rt_pool, sa)
                .await
                .unwrap()
                .is_some(),
            "get_session (worker_tx) resolves tenant A's session cross-tenant"
        );
        assert!(
            system_worker::get_session(&rt_pool, sb)
                .await
                .unwrap()
                .is_some(),
            "get_session (worker_tx) resolves tenant B's session cross-tenant"
        );

        // (c) the SAME shape WITHOUT worker_tx (plain runtime-role tx, no GUC) → 0.
        let mut plain = rt_pool.begin().await.unwrap();
        let (n,): (i64,) = sqlx::query_as("select count(*) from sessions")
            .fetch_one(&mut *plain)
            .await
            .unwrap();
        plain.rollback().await.ok();
        assert_eq!(
            n, 0,
            "a plain runtime-role tx with no bypass GUC must see zero sessions — the bypass is explicit"
        );

        cleanup_sw_tenant(&pool, ta).await;
        cleanup_sw_tenant(&pool, tb).await;
    }

    /// Phase D (#32, #75) — RLS wave B, re-seal helpers under `worker_tx`. Seeds a
    /// v1 sealed connection, then drives the restructured lock/CAS path
    /// (`reseal_begin` → `reseal_lock_row` → `reseal_write_row`) as the NON-owner
    /// runtime role: the lock RESOLVES the row and its tenant, the CAS flips exactly
    /// one v1 row to v2, and — the explicitness half — the same lock WITHOUT
    /// `worker_tx` (a plain runtime tx) resolves nothing.
    #[tokio::test]
    async fn rls_reseal_helpers_work_under_worker_tx() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = Uuid::now_v7();
        {
            let slug = format!("rls-rs-{}", tenant.simple());
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query("insert into tenants (id, name, slug) values ($1, $2, $3)")
                .bind(tenant)
                .bind(&slug)
                .bind(&slug)
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        let scope = TenantScope::assume(tenant);
        let conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct",
            "disp",
            Some(&[9u8, 9, 9]),
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({ "base_url": "https://x" }),
            None,
            1,
            ConnectionAuth {
                // `integration_connections_auth_kind_shape` (0013) allows only
                // static | oauth | none; a pasted-secret connection is 'static'.
                auth_kind: "static",
                status: "active",
                oauth: None,
                client_secret_sealed: None,
                client_secret_key_version: 1,
                registration_id: None,
            },
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        let rt_pool = connect(&url, Some("fluidbox_runtime"))
            .await
            .expect("runtime pool");
        let (table, col, ver, key) = (
            "integration_connections",
            "credential_sealed",
            "credential_key_version",
            "id",
        );

        // lock + CAS-write through the restructured helpers (tx IS a worker_tx).
        let mut tx = system_worker::reseal_begin(&rt_pool).await.unwrap();
        let locked = system_worker::reseal_lock_row(&mut tx, table, col, ver, key, conn.id)
            .await
            .unwrap();
        let Some((Some(bytes), kv, tid)) = locked else {
            panic!("reseal_lock_row saw no row under worker_tx");
        };
        assert_eq!(kv, 1, "the seeded credential is v1");
        assert_eq!(tid, Some(tenant), "the lock returns the row's own tenant");
        let mut newbytes = bytes.clone();
        newbytes.push(2);
        let affected =
            system_worker::reseal_write_row(&mut tx, table, col, ver, key, conn.id, &newbytes)
                .await
                .unwrap();
        assert_eq!(
            affected, 1,
            "the CAS flips exactly one v1 row to v2 under worker_tx"
        );
        tx.commit().await.unwrap();

        // The companion version is now 2 (read back via the superuser base pool).
        let (after, kv2) = connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .expect("credential still present");
        assert_eq!(kv2, 2, "credential_key_version is 2 after the CAS");
        assert_eq!(after, newbytes, "the re-sealed bytes landed");

        // Explicitness: the SAME lock WITHOUT worker_tx (plain runtime tx) sees nothing.
        let mut plain = rt_pool.begin().await.unwrap();
        let none = system_worker::reseal_lock_row(&mut plain, table, col, ver, key, conn.id)
            .await
            .unwrap();
        plain.rollback().await.ok();
        assert!(
            none.is_none(),
            "without the bypass GUC the FOR UPDATE lock resolves no row — the reseal bypass is explicit"
        );

        let mut tx = worker_tx(&pool).await.unwrap();
        for stmt in [
            "delete from integration_connections where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(stmt).bind(tenant).execute(&mut *tx).await.ok();
        }
        tx.commit().await.unwrap();
    }

    /// Review M3: `auth_audit_log` INSERT now carries the SAME tenant floor as every
    /// other tenant-owned write. The old `with check (true)` let a transaction scoped
    /// to tenant A append a row stamped `tenant_id = B` — a forged entry in another
    /// tenant's permanent security history that, because the log is append-only, the
    /// runtime role could never retract.
    ///
    /// Asserted through the NON-superuser `fluidbox_runtime` role (a superuser skips
    /// policies and would make this vacuous). NOTHING is committed: an audit row
    /// cannot be deleted afterwards, so every case runs in its own rolled-back tx.
    #[tokio::test]
    async fn rls_audit_insert_carries_the_tenant_floor() {
        use sqlx::{Connection, Executor};
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        // Apply migrations (incl. the runtime role) then drop that pool immediately.
        connect(&url, None).await.expect("migrate").close().await;
        let mut rt = sqlx::PgConnection::connect(&url).await.expect("rt connect");
        rt.execute("set role fluidbox_runtime")
            .await
            .expect("set role");

        async fn try_insert(
            rt: &mut sqlx::PgConnection,
            guc: Option<(&str, String)>,
            tenant: Option<Uuid>,
        ) -> sqlx::Result<()> {
            let mut tx = rt.begin().await.unwrap();
            if let Some((name, val)) = guc {
                sqlx::query("select set_config($1, $2, true)")
                    .bind(name)
                    .bind(val)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            let res = sqlx::query(
                "insert into auth_audit_log (id, tenant_id, actor_kind, action, success)
                 values ($1, $2, 'operator', 'rls.m3.probe', true)",
            )
            .bind(Uuid::now_v7())
            .bind(tenant)
            .execute(&mut *tx)
            .await
            .map(|_| ());
            tx.rollback().await.ok();
            res
        }
        fn assert_rls_refusal(res: sqlx::Result<()>, what: &str) {
            let err = res
                .err()
                .unwrap_or_else(|| panic!("{what} must be refused"));
            assert!(
                err.to_string()
                    .to_lowercase()
                    .contains("row-level security"),
                "{what}: expected an RLS policy violation, got: {err}"
            );
        }

        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let tid = "fluidbox.tenant_id";
        let bypass = ("fluidbox.bypass", "system_worker".to_string());

        // In-tenant: the ordinary audited mutation, unchanged.
        try_insert(&mut rt, Some((tid, a.to_string())), Some(a))
            .await
            .expect("an in-tenant audit row must still insert");
        // THE FINDING: tenant A cannot write tenant B's history.
        assert_rls_refusal(
            try_insert(&mut rt, Some((tid, a.to_string())), Some(b)).await,
            "a cross-tenant audit insert",
        );
        // A scoped tx cannot forge a deployment-level (NULL-tenant) row either.
        assert_rls_refusal(
            try_insert(&mut rt, Some((tid, a.to_string())), None).await,
            "a NULL-tenant audit insert from a tenant-scoped tx",
        );
        // The old pool-direct path (no GUC at all) is now refused — which is why
        // standalone audits route through `identity::insert_audit_standalone`.
        assert_rls_refusal(
            try_insert(&mut rt, None, Some(a)).await,
            "an audit insert with no GUC",
        );
        // The audited bypass remains the one way to write deployment-level rows.
        try_insert(&mut rt, Some(bypass.clone()), None)
            .await
            .expect("the system_worker bypass must still write NULL-tenant rows");
        try_insert(&mut rt, Some(bypass), Some(b))
            .await
            .expect("the system_worker bypass writes any tenant's row");

        rt.close().await.ok();
    }

    /// Review H1: a runtime role is only trustworthy if its POSTURE is checked, not
    /// just its name. PostgreSQL roles are cluster-global while 0018's grants are
    /// database-local, so on a shared cluster the name may already belong to another
    /// principal — as LOGIN/BYPASSRLS, or granted to somebody else's owner, who could
    /// then `SET ROLE` in and set `fluidbox.bypass`. Each shape must REFUSE.
    ///
    /// Probe roles are uniquely named (tests run in parallel and roles are
    /// cluster-global) and dropped at the end.
    #[tokio::test]
    async fn runtime_role_posture_refuses_unsafe_roles() {
        use sqlx::Connection;
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        // Role DDL cannot take bind parameters; the names are locally generated
        // (`fbx_(probe|other)_<uuid-hex>`), never caller input.
        async fn ddl(c: &mut sqlx::PgConnection, sql: String) -> sqlx::Result<()> {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&mut *c)
                .await
                .map(|_| ())
        }
        let mut c = sqlx::PgConnection::connect(&url).await.expect("connect");
        let probe = format!("fbx_probe_{}", Uuid::now_v7().simple());
        let other = format!("fbx_other_{}", Uuid::now_v7().simple());
        if ddl(&mut c, format!("create role {probe} nologin"))
            .await
            .is_err()
        {
            eprintln!("skipping: this database role cannot CREATE ROLE");
            return;
        }
        ddl(&mut c, format!("create role {other} nologin"))
            .await
            .expect("create the second probe role");

        // A freshly created NOLOGIN role with no memberships is the clean posture.
        assert!(
            check_runtime_role_posture(&mut c, &probe)
                .await
                .unwrap()
                .is_ok(),
            "a NOLOGIN role that is a member of nothing must pass"
        );

        // (a) attributes. LOGIN is settable by any CREATEROLE holder; BYPASSRLS needs
        // superuser, so it is asserted only where the ALTER actually lands.
        ddl(&mut c, format!("alter role {probe} login"))
            .await
            .unwrap();
        let err = check_runtime_role_posture(&mut c, &probe)
            .await
            .unwrap()
            .expect_err("a LOGIN runtime role must be refused");
        assert!(
            err.contains("LOGIN"),
            "refusal must name the attribute: {err}"
        );
        ddl(&mut c, format!("alter role {probe} nologin"))
            .await
            .unwrap();
        if ddl(&mut c, format!("alter role {probe} bypassrls"))
            .await
            .is_ok()
        {
            let err = check_runtime_role_posture(&mut c, &probe)
                .await
                .unwrap()
                .expect_err("a BYPASSRLS runtime role must be refused");
            assert!(
                err.contains("BYPASSRLS"),
                "refusal must name the attribute: {err}"
            );
            ddl(&mut c, format!("alter role {probe} nobypassrls"))
                .await
                .unwrap();
        }

        // (b) THE SHARED-CLUSTER SHAPE: someone else can SET ROLE into it.
        ddl(&mut c, format!("grant {probe} to {other}"))
            .await
            .unwrap();
        let err = check_runtime_role_posture(&mut c, &probe)
            .await
            .unwrap()
            .expect_err("a runtime role granted to another principal must be refused");
        assert!(
            err.contains(&other),
            "refusal must name the foreign member: {err}"
        );
        ddl(&mut c, format!("revoke {probe} from {other}"))
            .await
            .unwrap();

        // (c) inherited privileges we never granted.
        ddl(&mut c, format!("grant {other} to {probe}"))
            .await
            .unwrap();
        let err = check_runtime_role_posture(&mut c, &probe)
            .await
            .unwrap()
            .expect_err("a runtime role inheriting another role must be refused");
        assert!(
            err.contains(&other),
            "refusal must name the inherited role: {err}"
        );
        ddl(&mut c, format!("revoke {other} from {probe}"))
            .await
            .unwrap();

        // A name that does not exist at all is a refusal, never a silent pass.
        assert!(check_runtime_role_posture(&mut c, "fbx_no_such_role_xyz")
            .await
            .unwrap()
            .is_err());

        for r in [&probe, &other] {
            ddl(&mut c, format!("drop role {r}")).await.ok();
        }
        c.close().await.ok();
    }

    /// Review M2: the boot gate reads the EFFECTIVE role of a pooled connection, so
    /// it observes `after_connect SET ROLE` rather than whatever `DATABASE_URL` says.
    /// Under the role split the answer must be "not bypassing" — that is the whole
    /// point of the split, and in multi-user mode boot refuses on anything else.
    #[tokio::test]
    async fn pool_role_bypasses_rls_reads_the_effective_role() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let rt_pool = connect(&url, Some("fluidbox_runtime"))
            .await
            .expect("runtime pool");
        assert_eq!(
            pool_role_bypasses_rls(&rt_pool).await.unwrap(),
            None,
            "a pool that SET ROLEs to fluidbox_runtime must be RLS-BOUND"
        );
        rt_pool.close().await;
    }

    // ─── Durable execution claims (Phase E, #33; Gap 11) ────────────────────
    // DB-backed; self-skip when DATABASE_URL is unset (CI proves them).

    /// Stamp a delivery row's claim directly (bypassing the due scan) so a test
    /// can record consecutive attempts without waiting out the backoff. Under
    /// `worker_tx` (RLS bypass), like the sweeps.
    async fn stamp_delivery_claim(pool: &PgPool, delivery_id: Uuid, owner: Uuid) {
        let mut tx = worker_tx(pool).await.unwrap();
        sqlx::query(
            "update result_deliveries
                set claimed_by = $2, claimed_until = now() + interval '5 minutes'
              where id = $1",
        )
        .bind(delivery_id)
        .bind(owner)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    /// Read the claim + backoff columns a delivery row does not expose on
    /// [`ResultDeliveryRow`] (they are coordination state, deliberately not part of
    /// the serialized API shape). Under `worker_tx`, like the sweeps.
    async fn delivery_claim_state(
        pool: &PgPool,
        delivery_id: Uuid,
    ) -> (
        Option<Uuid>,
        Option<DateTime<Utc>>,
        i32,
        DateTime<Utc>,
        String,
    ) {
        let mut tx = worker_tx(pool).await.unwrap();
        let row = sqlx::query(
            "select claimed_by, claimed_until, attempts, next_attempt_at, status
               from result_deliveries where id = $1",
        )
        .bind(delivery_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        (
            row.get("claimed_by"),
            row.get("claimed_until"),
            row.get("attempts"),
            row.get("next_attempt_at"),
            row.get("status"),
        )
    }

    /// Force a session's status (state-machine-bypassing) so a test can drive
    /// terminality directly. Under `worker_tx` (RLS bypass), like the sweeps.
    async fn force_session_status(pool: &PgPool, session_id: Uuid, status: &str) {
        let mut tx = worker_tx(pool).await.unwrap();
        sqlx::query("update sessions set status = $2 where id = $1")
            .bind(session_id)
            .bind(status)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn claim_won_completed_then_duplicate_adopts_without_redispatch() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);

        // Won.
        let claim_id =
            match claim_tool_execution(&pool, scope, session_id, "tc1", "sha256:aaa", 600)
                .await
                .unwrap()
            {
                ClaimOutcome::Won { claim_id } => claim_id,
                o => panic!("expected Won, got {o:?}"),
            };
        let result = serde_json::json!({
            "content": [{"type":"text","text":"the answer"}], "is_error": false
        });
        assert!(complete_tool_execution(
            &pool,
            scope,
            claim_id,
            "succeeded",
            Some("sha256:res"),
            Some(false),
            Some(&result),
            None,
        )
        .await
        .unwrap()
        .settled());

        // A duplicate for the SAME (session, tool_call_id, digest) adopts the
        // stored outcome — and, the false-green guard: the claim was NOT
        // re-dispatched (attempt stays 1; the stored result is byte-identical).
        // The LIVE single-upstream-request proof rides the hardening e2e (T9 §f).
        match claim_tool_execution(&pool, scope, session_id, "tc1", "sha256:aaa", 600)
            .await
            .unwrap()
        {
            ClaimOutcome::Existing(row) => {
                assert_eq!(row.state, "succeeded");
                assert_eq!(
                    row.attempt, 1,
                    "a duplicate must not re-dispatch (attempt stays 1)"
                );
                assert_eq!(
                    row.result_content.as_ref(),
                    Some(&result),
                    "the duplicate adopts the exact stored result"
                );
            }
            o => panic!("expected Existing(succeeded), got {o:?}"),
        }
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn claim_refuses_a_terminal_session() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        // Cancel-during-approval, brokered half: a terminal (or winding-down)
        // session refuses the claim in the same lock-holding tx as cancellation.
        force_session_status(&pool, session_id, "cancelled").await;
        assert!(
            matches!(
                claim_tool_execution(&pool, scope, session_id, "tc1", "sha256:aaa", 600)
                    .await
                    .unwrap(),
                ClaimOutcome::SessionTerminal
            ),
            "a cancelled session must refuse the claim"
        );
        // Winding-down also refuses.
        force_session_status(&pool, session_id, "finalizing").await;
        assert!(matches!(
            claim_tool_execution(&pool, scope, session_id, "tc2", "sha256:bbb", 600)
                .await
                .unwrap(),
            ClaimOutcome::SessionTerminal
        ));
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn reclaim_is_only_for_failed_before_send() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);

        // failed_before_send IS re-claimable (same row, attempt+1).
        let id = match claim_tool_execution(&pool, scope, session_id, "fbs", "sha256:1", 600)
            .await
            .unwrap()
        {
            ClaimOutcome::Won { claim_id } => claim_id,
            o => panic!("expected Won, got {o:?}"),
        };
        assert!(complete_tool_execution(
            &pool,
            scope,
            id,
            "failed_before_send",
            None,
            Some(false),
            None,
            Some("connect refused"),
        )
        .await
        .unwrap()
        .settled());
        assert_eq!(
            reclaim_failed_before_send(&pool, scope, session_id, "fbs", "sha256:1", 600, 3)
                .await
                .unwrap(),
            ReclaimOutcome::Reclaimed { attempt: 2 },
            "a failed_before_send row must be re-claimable"
        );
        let row = get_tool_execution(&pool, scope, session_id, "fbs", "sha256:1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "claimed");
        assert_eq!(row.attempt, 2, "a re-claim bumps attempt");

        // Every OTHER state refuses the re-claim.
        // 'claimed' (the row we just re-claimed).
        assert_eq!(
            reclaim_failed_before_send(&pool, scope, session_id, "fbs", "sha256:1", 600, 3)
                .await
                .unwrap(),
            ReclaimOutcome::Lost
        );
        // 'succeeded'.
        assert!(complete_tool_execution(
            &pool,
            scope,
            row.id,
            "succeeded",
            None,
            Some(false),
            None,
            None
        )
        .await
        .unwrap()
        .settled());
        assert_eq!(
            reclaim_failed_before_send(&pool, scope, session_id, "fbs", "sha256:1", 600, 3)
                .await
                .unwrap(),
            ReclaimOutcome::Lost
        );
        // 'ambiguous' (a separate claim).
        let id2 = match claim_tool_execution(&pool, scope, session_id, "amb", "sha256:2", 600)
            .await
            .unwrap()
        {
            ClaimOutcome::Won { claim_id } => claim_id,
            o => panic!("expected Won, got {o:?}"),
        };
        assert!(complete_tool_execution(
            &pool,
            scope,
            id2,
            "ambiguous",
            None,
            Some(true),
            None,
            None
        )
        .await
        .unwrap()
        .settled());
        assert_eq!(
            reclaim_failed_before_send(&pool, scope, session_id, "amb", "sha256:2", 600, 3)
                .await
                .unwrap(),
            ReclaimOutcome::Lost
        );
        cleanup_sw_tenant(&pool, tenant).await;
    }

    /// Review I1: the re-claim budget is BOUNDED. A client that keeps
    /// re-presenting one `(session, tool_call_id, input_digest)` against a sick
    /// upstream must stop winning re-claims at the cap — that is what stops the
    /// unmetered `sessions`-row lock churn — and the refusal must be
    /// DISTINGUISHABLE from losing a race, so the caller can answer terminally
    /// instead of polling a row that will never move again.
    #[tokio::test]
    async fn reclaim_is_capped_at_max_attempts() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        const CAP: i32 = 2;

        let id = match claim_tool_execution(&pool, scope, session_id, "cap", "sha256:c", 600)
            .await
            .unwrap()
        {
            ClaimOutcome::Won { claim_id } => claim_id,
            o => panic!("expected Won, got {o:?}"),
        };
        // Attempt 1 (the insert) failed before send → one re-claim is left.
        assert!(complete_tool_execution(
            &pool,
            scope,
            id,
            "failed_before_send",
            None,
            Some(true),
            None,
            Some("connect refused"),
        )
        .await
        .unwrap()
        .settled());
        assert_eq!(
            reclaim_failed_before_send(&pool, scope, session_id, "cap", "sha256:c", 600, CAP)
                .await
                .unwrap(),
            ReclaimOutcome::Reclaimed { attempt: 2 },
            "re-claims within the cap must still be granted"
        );
        // Attempt 2 also failed before send → the budget is spent.
        assert!(complete_tool_execution(
            &pool,
            scope,
            id,
            "failed_before_send",
            None,
            Some(true),
            None,
            Some("connect refused"),
        )
        .await
        .unwrap()
        .settled());
        assert_eq!(
            reclaim_failed_before_send(&pool, scope, session_id, "cap", "sha256:c", 600, CAP)
                .await
                .unwrap(),
            ReclaimOutcome::Exhausted { attempt: CAP },
            "past the cap the re-claim must be refused, not granted"
        );
        // …and refused WITHOUT churning the row: it stays exactly where the last
        // dispatch left it, so nothing accumulates per rejected retry.
        let row = get_tool_execution(&pool, scope, session_id, "cap", "sha256:c")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (row.state.as_str(), row.attempt),
            ("failed_before_send", CAP)
        );
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn stale_claim_sweep_marks_ambiguous() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let id = match claim_tool_execution(&pool, scope, session_id, "stale", "sha256:s", 600)
            .await
            .unwrap()
        {
            ClaimOutcome::Won { claim_id } => claim_id,
            o => panic!("expected Won, got {o:?}"),
        };
        // Force it past expiry, then sweep: a crashed dispatcher's claim → ambiguous.
        // The sweep is a tenant-less GLOBAL scan and the test beside this one
        // expires a claim of its own, so both halves of the GLOBAL_SCAN discipline
        // apply: guard from before the row is stale, read the batch session-scoped.
        let scan = GLOBAL_SCAN.lock().await;
        {
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query(
                "update tool_execution_claims set claim_expires_at = now() - interval '1 minute' where id = $1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let swept = sweep_stale_claims(&pool, session_id).await;
        drop(scan);
        assert!(
            swept
                .iter()
                .any(|(t, s, tc, _)| *t == tenant && *s == session_id && tc == "stale"),
            "the stale claim must be swept and returned with its tenant/session"
        );
        let row = get_tool_execution(&pool, scope, session_id, "stale", "sha256:s")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.state, "ambiguous",
            "a swept stale claim lands in ambiguous"
        );
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn late_complete_loses_to_a_sweep_flipped_row() {
        // T4 rider: a dispatcher that CASes `complete` AFTER the sweeper already
        // flipped its expired claim to `ambiguous` must LOSE — the CAS keys on
        // state='claimed', which the sweep changed. finish_won_claim relies on
        // this false to skip a second (double) tool.brokered ledger row.
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let id = match claim_tool_execution(&pool, scope, session_id, "late", "sha256:l", 600)
            .await
            .unwrap()
        {
            ClaimOutcome::Won { claim_id } => claim_id,
            o => panic!("expected Won, got {o:?}"),
        };
        // The sweeper wins the row (expire → sweep → ambiguous). Guarded even
        // though this test ignores the batch: an unguarded sweep here is what
        // STOLE the neighbouring test's stale claim (3 runs in 6 — GLOBAL_SCAN).
        let scan = GLOBAL_SCAN.lock().await;
        {
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query(
                "update tool_execution_claims set claim_expires_at = now() - interval '1 minute' where id = $1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        assert_eq!(
            sweep_stale_claims(&pool, session_id).await.len(),
            1,
            "this test's own claim is the one the sweep flipped"
        );
        drop(scan);
        // The dispatcher's late completion CAS finds no 'claimed' row → false.
        assert!(
            !complete_tool_execution(&pool, scope, id, "succeeded", None, Some(false), None, None)
                .await
                .unwrap()
                .settled(),
            "a late complete must lose to the sweep's ambiguous row"
        );
        // The durable truth stays `ambiguous` (the swept row was not overwritten).
        let row = get_tool_execution(&pool, scope, session_id, "late", "sha256:l")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "ambiguous");
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn claim_two_tx_race_yields_exactly_one_winner() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let pool2 = pool.clone();
        // Two concurrent transactions on the SAME natural key: the unique index +
        // `on conflict do nothing` make exactly one Win and one adopt (Existing).
        let (a, b) = tokio::join!(
            claim_tool_execution(&pool, scope, session_id, "race", "sha256:r", 600),
            claim_tool_execution(&pool2, scope, session_id, "race", "sha256:r", 600),
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        let mut wins = 0;
        let mut existings = 0;
        for o in [&a, &b] {
            match o {
                ClaimOutcome::Won { .. } => wins += 1,
                ClaimOutcome::Existing(_) => existings += 1,
                ClaimOutcome::SessionTerminal => {}
            }
        }
        assert_eq!(
            wins, 1,
            "exactly one concurrent claim wins the single dispatch"
        );
        assert_eq!(existings, 1, "the loser adopts the existing row");
        cleanup_sw_tenant(&pool, tenant).await;
    }

    // ─── Multi-replica coordination (Phase E, #33; Gap 13) ──────────────────
    // DB-backed; self-skip when DATABASE_URL is unset (CI proves them).

    /// Put an approvals row into `pending` the way the gate does (register the
    /// intent, then promote it), returning the row.
    async fn seed_pending_approval(
        pool: &PgPool,
        scope: TenantScope,
        session_id: Uuid,
        tool_call_id: &str,
        ttl_secs: i64,
    ) -> ApprovalRow {
        let (intent, inserted) = register_tool_intent(
            pool,
            scope,
            session_id,
            tool_call_id,
            "Bash",
            "git push",
            "sha256:args",
        )
        .await
        .unwrap();
        assert!(inserted, "fresh intent");
        promote_intent_to_pending(
            pool,
            scope,
            intent.id,
            Some("high"),
            "once",
            "Bash",
            ttl_secs,
        )
        .await
        .unwrap()
        .expect("promoted to pending")
    }

    /// Count this session's ledger rows by event type.
    async fn count_events(pool: &PgPool, scope: TenantScope, session_id: Uuid, ty: &str) -> usize {
        events_after(pool, scope, session_id, 0, 500)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.r#type == ty)
            .count()
    }

    fn decision_events(
        session_id: Uuid,
        approval_id: Uuid,
        decision: &str,
        decided_by: &str,
    ) -> Vec<Redacted<EventEnvelope>> {
        let r = Redactor::default();
        vec![
            r.scrub(EventEnvelope::new(
                session_id,
                Actor::Human,
                EventBody::ApprovalDecided {
                    approval_id,
                    tool_call_id: "tc-decide".into(),
                    decision: decision.into(),
                    decided_by: decided_by.into(),
                },
            )),
            r.scrub(EventEnvelope::new(
                session_id,
                Actor::System,
                EventBody::ToolDecision {
                    tool_call_id: "tc-decide".into(),
                    tool: "Bash".into(),
                    verdict: "allow".into(),
                    source: "human".into(),
                    original_verdict: None,
                    reason: Some(format!("human:{decided_by}")),
                },
            )),
        ]
    }

    /// **THE load-bearing Gap-13 test.** A decided approval ledgers EXACTLY ONE
    /// `approval.decided` and ONE `tool.decision`, no matter how many handlers are
    /// attached to the row.
    ///
    /// Why this would have FAILED before the change: emission used to live in
    /// `await_pending_decision`, which ran it UNCONDITIONALLY for every awakened
    /// waiter — and two waiters on one pending row is an ordinary occurrence (a
    /// `/permission` retry across a runner restart re-attaches while the first
    /// call still blocks; both the has-session-grant branch and the
    /// lost-the-promotion branch fall through to the same wait). Both would wake
    /// on one decision and both would append, giving 2 + 2 (design :1058-1066 —
    /// a single-process bug, not merely a multi-replica one). The events are now
    /// carried BY the decision CAS, so the sequence below — three deciders
    /// racing/retrying one row, exactly as N waiters would — writes one pair.
    #[tokio::test]
    async fn decided_approval_ledgers_exactly_one_pair_however_many_deciders() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let approval = seed_pending_approval(&pool, scope, session_id, "tc-decide", 600).await;

        // Two GENUINELY concurrent deciders (separate pool handles), each carrying
        // its own copy of the events — the shape two re-attached waiters had.
        let pool2 = pool.clone();
        let (a, b) = tokio::join!(
            decide_approval_tx(
                &pool,
                scope,
                approval.id,
                "approved_once",
                "human:alice",
                decision_events(session_id, approval.id, "approved_once", "alice"),
            ),
            decide_approval_tx(
                &pool2,
                scope,
                approval.id,
                "approved_once",
                "human:alice",
                decision_events(session_id, approval.id, "approved_once", "alice"),
            ),
        );
        let winners = [a.unwrap(), b.unwrap()]
            .iter()
            .filter(|o| o.is_some())
            .count();

        // A third, LATER decider (the waiter's own timeout CAS racing a human who
        // already won) must also emit nothing.
        let late = decide_approval_tx(
            &pool,
            scope,
            approval.id,
            "denied",
            "timeout",
            decision_events(session_id, approval.id, "denied", "timeout"),
        )
        .await
        .unwrap();

        let decided = count_events(&pool, scope, session_id, "approval.decided").await;
        let tool_dec = count_events(&pool, scope, session_id, "tool.decision").await;
        cleanup_sw_tenant(&pool, tenant).await;

        assert_eq!(winners, 1, "exactly one concurrent decider wins the CAS");
        assert!(
            late.is_none(),
            "a decider that lost the CAS decides nothing"
        );
        assert_eq!(
            decided, 1,
            "exactly ONE approval.decided per decided approval (was 1-per-waiter)"
        );
        assert_eq!(
            tool_dec, 1,
            "exactly ONE tool.decision per decided approval (was 1-per-waiter)"
        );
    }

    /// The expiry decision site obeys the same rule: single-winner CAS, one pair
    /// of events, and a loser (a human who decided first) writes nothing.
    #[tokio::test]
    async fn expiry_decision_is_single_winner_and_emits_once() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        // Already past its deadline.
        let approval = seed_pending_approval(&pool, scope, session_id, "tc-decide", -60).await;

        // Tenant-less global scan too, but the ONE that needs no GLOBAL_SCAN guard
        // (see the module note): since Phase E it only READS — the decision moved
        // to the scoped, single-winner `expire_approval_tx` below — so a sibling's
        // scan cannot take this row away, and asking whether MY approval is in the
        // batch is already immune to whatever else is in it.
        let scanned = system_worker::expired_pending_approvals(&pool, 100)
            .await
            .unwrap();
        let seen = scanned.iter().any(|r| r.id == approval.id);

        let pool2 = pool.clone();
        let (a, b) = tokio::join!(
            expire_approval_tx(
                &pool,
                scope,
                approval.id,
                decision_events(session_id, approval.id, "expired", "timeout"),
            ),
            expire_approval_tx(
                &pool2,
                scope,
                approval.id,
                decision_events(session_id, approval.id, "expired", "timeout"),
            ),
        );
        let winners = [a.unwrap(), b.unwrap()]
            .iter()
            .filter(|o| o.is_some())
            .count();
        let decided = count_events(&pool, scope, session_id, "approval.decided").await;
        let tool_dec = count_events(&pool, scope, session_id, "tool.decision").await;
        // The post-wait terminal deny: one winner, and (review Minor A) the event
        // now rides the claim's OWN transaction, so "won the marker" and "the event
        // exists" can no longer diverge. Two waiters, two event vectors, one event.
        let deny_event = || {
            vec![Redactor::default().scrub(EventEnvelope::new(
                session_id,
                Actor::System,
                EventBody::ToolDecision {
                    tool_call_id: "tc-decide".into(),
                    tool: "Bash".into(),
                    verdict: "deny".into(),
                    source: "session_terminal".into(),
                    original_verdict: Some("allow".into()),
                    reason: Some("session stopped accepting work during the approval wait".into()),
                },
            ))]
        };
        let m1 = claim_terminal_deny_tx(&pool, scope, approval.id, deny_event())
            .await
            .unwrap();
        let m2 = claim_terminal_deny_tx(&pool, scope, approval.id, deny_event())
            .await
            .unwrap();
        let after_deny = count_events(&pool, scope, session_id, "tool.decision").await;
        cleanup_sw_tenant(&pool, tenant).await;

        assert!(
            seen,
            "the cross-tenant scan finds an over-deadline approval"
        );
        assert_eq!(winners, 1, "exactly one replica expires the row");
        assert_eq!(decided, 1, "expiry ledgers ONE approval.decided");
        assert_eq!(tool_dec, 1, "expiry ledgers ONE tool.decision");
        assert!(m1, "the first terminal-deny claim wins");
        assert!(!m2, "a second waiter's terminal-deny claim emits nothing");
        assert_eq!(
            after_deny,
            tool_dec + 1,
            "the winning claim appended EXACTLY ONE tool.decision, in its own \
             transaction; the loser appended none"
        );
    }

    /// Lease steal matrix + the epoch's defining asymmetry: it moves ONLY on an
    /// owner change. Fresh / self-renew / held-by-another-unexpired / expired.
    #[tokio::test]
    async fn session_lease_steals_on_expiry_and_epoch_moves_only_on_owner_change() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());

        // (1) FRESH: no owner → acquired, epoch 0 → 1 (owner changed null → A).
        let e1 = acquire_session_lease(&pool, scope, session_id, a, 300)
            .await
            .unwrap();
        // (2) SELF-RENEW: same owner keeps the epoch (the fence must not move
        //     under a healthy driver's own feet).
        let e2 = acquire_session_lease(&pool, scope, session_id, a, 300)
            .await
            .unwrap();
        // (3) HELD BY ANOTHER, UNEXPIRED: refused outright.
        let held = acquire_session_lease(&pool, scope, session_id, b, 300)
            .await
            .unwrap();
        // (4) EXPIRED: force the deadline into the past, then B steals — epoch+1.
        {
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query(
                "update sessions set orchestrator_lease_until = now() - interval '1 minute'
                 where id = $1",
            )
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let e3 = acquire_session_lease(&pool, scope, session_id, b, 300)
            .await
            .unwrap();
        let after = session_lease(&pool, scope, session_id).await.unwrap();
        cleanup_sw_tenant(&pool, tenant).await;

        assert_eq!(
            e1,
            Some(1),
            "a fresh acquire is an owner change: epoch 0 → 1"
        );
        assert_eq!(e2, Some(1), "a self-renew must NOT move the epoch");
        assert_eq!(
            held, None,
            "an unexpired lease held by another replica is refused"
        );
        assert_eq!(
            e3,
            Some(2),
            "a steal after expiry is an owner change: epoch+1"
        );
        let (owner, _, epoch) = after.expect("session row");
        assert_eq!(owner, Some(b), "the steal recorded the new owner");
        assert_eq!(epoch, 2);
    }

    /// Source guards for the two Gap-13 SQL predicates whose behavioral tests are
    /// DB-gated (they self-skip without `DATABASE_URL`, so CI is where they run).
    /// These assert the predicates themselves, so deleting either one fails
    /// IMMEDIATELY — with or without a database — instead of silently passing a
    /// skipped suite. Needles are split so this guard is not itself an occurrence.
    #[test]
    fn coordination_sql_predicates_are_present() {
        let src = include_str!("lib.rs");

        // (1) The epoch is a FENCING TOKEN, not a counter: it moves only when the
        // owner changes. Drop the conditional and a healthy driver's own renew
        // invalidates its in-flight fence — every renew would look like a takeover.
        let epoch_guard = concat!("orchestrator_owner_id is distinct ", "from $3");
        assert!(
            src.contains(epoch_guard),
            "acquire_session_lease must bump orchestrator_epoch ONLY on an owner \
             change (`{epoch_guard}`); an unconditional bump makes a self-renew \
             fence the renewing driver out of its own session"
        );

        // (2) A delivery attempt is recorded only by the replica that HOLDS the
        // row's claim. Drop the guard and a replica whose claim expired mid-attempt
        // stomps the new owner's attempt counter and backoff.
        let claim_guard = concat!("where id = $1 and claimed_", "by = $8");
        assert!(
            src.contains(claim_guard),
            "mark_delivery_attempt must be owner-guarded (`{claim_guard}`) or two \
             replicas can both record attempts on one delivery row"
        );

        // (3) SKIP LOCKED is what makes two replicas' claimed sets DISJOINT; a
        // plain FOR UPDATE would serialize them onto the same rows instead.
        // Scoped to the STATEMENT (the prose above it mentions the clause too, so a
        // whole-file `contains` would be satisfied by the doc comment alone).
        let sw = include_str!("system_worker.rs");
        let stmt_start = sw.find("with due as (").expect("the claim CTE exists");
        let stmt_end = sw[stmt_start..]
            .find("returning d.*")
            .map(|i| stmt_start + i)
            .expect("the claim CTE returns its rows");
        let skip_locked = concat!("for update skip ", "locked");
        assert!(
            sw[stmt_start..stmt_end].contains(skip_locked),
            "claim_due_deliveries's CTE must use `{skip_locked}` so replicas take \
             disjoint slices rather than queueing on each other"
        );

        // (4) The claim scan must EXCLUDE rows another replica currently holds.
        // Without the `claimed_until` half, a replica re-picks a row it just lost
        // and re-runs the external side effect every 3 s tick (review I2); without
        // the `claimed_by = $1` half, our own re-stamped row becomes unreachable to
        // us on the very next pass.
        let scan_pred = "(claimed_until is null or claimed_until < now() or claimed_by = $1)";
        assert!(
            sw[stmt_start..stmt_end].contains(scan_pred),
            "claim_due_deliveries must skip rows another replica holds (`{scan_pred}`)"
        );

        // (5) The per-row re-stamp (review I2) is a strict OWNER CAS, never a
        // steal: a row taken over by another replica must match ZERO rows so the
        // caller skips it BEFORE performing the external side effect. Sliced to the
        // statement — the prose above it discusses `claimed_by` at length.
        let ext_start = src
            .find("pub async fn extend_delivery_claim(")
            .expect("the per-row claim re-stamp exists");
        let ext_end = src[ext_start..]
            .find(".bind(id)")
            .map(|i| ext_start + i)
            .expect("the re-stamp binds its row id");
        let restamp_stmt = &src[ext_start..ext_end];
        let owner_cas = concat!(
            "where id = $1 and claimed_by = $2 and ",
            "status = 'pending'"
        );
        assert!(
            restamp_stmt.contains(owner_cas),
            "extend_delivery_claim must be a strict owner CAS (`{owner_cas}`); a \
             predicate that also matches an EXPIRED claim held by someone else would \
             steal a row mid-flight and duplicate its external side effect"
        );
        let ttl_stamp = "claimed_until = now() + make_interval(secs => $3)";
        assert!(
            restamp_stmt.contains(ttl_stamp),
            "extend_delivery_claim must actually MOVE the deadline (`{ttl_stamp}`), \
             or the TTL still measures from the batch claim rather than this attempt"
        );
    }

    /// Source guard for the review-I1 re-claim CAP. The behavioral test
    /// (`reclaim_is_capped_at_max_attempts`) is DB-gated and self-skips without
    /// `DATABASE_URL`, so deleting the predicate would pass a skipped suite
    /// silently. Sliced to the STATEMENT — the doc comment above it explains the
    /// cap at length and would satisfy a whole-file `contains` on its own.
    #[test]
    fn the_reclaim_attempt_cap_predicate_is_present() {
        let src = include_str!("lib.rs");
        let start = src
            .find("pub async fn reclaim_failed_before_send(")
            .expect("the re-claim exists");
        let end = src[start..]
            .find(".bind(max_attempts)")
            .map(|i| start + i)
            .expect("the re-claim binds its cap");
        let stmt = &src[start..end];
        let cap = concat!("state = 'failed_before_send' and ", "attempt < $6");
        assert!(
            stmt.contains(cap),
            "reclaim_failed_before_send's CAS must carry the attempt cap (`{cap}`). \
             Without it a client looping /tools/call on ONE (tool_call_id, \
             input_digest) against a sick upstream re-claims forever — free of \
             budget, free of ledger, two exclusive sessions-row locks per \
             iteration on the row cancellation itself needs."
        );
    }

    /// I2, behaviorally: a LOST delivery claim must be caught by the per-row
    /// re-stamp (before the external side effect), because the alternative — the
    /// old owner discovering it at `mark_delivery_attempt` — silently drops the
    /// BACKOFF as well as the attempt record, leaving the row immediately due
    /// again in a ~3 s-tick loop that never reaches `max_attempts` and repeats the
    /// external effect every pass.
    #[tokio::test]
    async fn a_lost_delivery_claim_is_caught_before_the_attempt_and_freezes_no_backoff() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        // Enqueue → claim inside one GLOBAL_SCAN window: until the renewal below
        // lands, this row is due (then briefly leased for only 5 s) and any
        // sibling test's claim scan would take it out from under this one.
        let scan = GLOBAL_SCAN.lock().await;
        let dest = serde_json::json!({"kind": "signed_webhook", "url": "http://127.0.0.1:1/cb"});
        let row = enqueue_result_delivery(&pool, scope, session_id, None, &dest)
            .await
            .unwrap();
        let (mine, thief) = (Uuid::now_v7(), Uuid::now_v7());

        // Claimed by us with a DELIBERATELY short TTL (5 s) — the batch stamp the
        // worker starts from; the re-stamp then renews it for the attempt itself.
        let claimed = claim_deliveries(&pool, mine, 10, 5, &[row.id]).await;
        assert!(claimed.iter().any(|c| c.id == row.id), "we claimed the row");
        let before = delivery_claim_state(&pool, row.id).await;
        let renewed = extend_delivery_claim(&pool, scope, row.id, mine, 300)
            .await
            .unwrap();
        let after_renew = delivery_claim_state(&pool, row.id).await;
        drop(scan);

        // Now the thief takes it (as an expired-claim steal would).
        stamp_delivery_claim(&pool, row.id, thief).await;
        let restamp_after_theft = extend_delivery_claim(&pool, scope, row.id, mine, 300)
            .await
            .unwrap();
        // …and the old owner's attempt record is refused, changing NOTHING.
        let marked = mark_delivery_attempt(
            &pool,
            scope,
            row.id,
            mine,
            false,
            Some("stale replica"),
            None,
            30,
            6,
        )
        .await
        .unwrap();
        let after_theft = delivery_claim_state(&pool, row.id).await;
        cleanup_sw_tenant(&pool, tenant).await;

        assert!(renewed, "the holder re-stamps its own claim");
        assert_eq!(before.0, Some(mine), "the batch claim named us");
        assert!(
            after_renew.1 > before.1,
            "the re-stamp must MOVE the deadline (the TTL measures THIS attempt, \
             not the batch claim): {:?} → {:?}",
            before.1,
            after_renew.1
        );
        assert!(
            !restamp_after_theft,
            "a row taken over by another replica must fail the re-stamp — that is \
             the skip that stops the duplicate external call"
        );
        assert!(
            marked.is_none(),
            "the owner guard refuses the stale replica's attempt record"
        );
        assert_eq!(
            (after_theft.2, after_theft.3),
            (after_renew.2, after_renew.3),
            "a refused record leaves attempts AND next_attempt_at untouched — the \
             row stays immediately due, which is precisely why the re-stamp above \
             must catch this first"
        );
        assert_eq!(
            after_theft.0,
            Some(thief),
            "the thief still owns the row (nothing was stomped)"
        );
    }

    /// The fencing token does its job: a driver carrying a STALE epoch mutates
    /// nothing, while the current holder's identical call succeeds.
    #[tokio::test]
    async fn epoch_fence_rejects_a_stale_driver_and_admits_the_holder() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());

        let stale = acquire_session_lease(&pool, scope, session_id, a, 300)
            .await
            .unwrap()
            .unwrap();
        // A steals, stalls; B takes over (epoch moves) — A's token is now stale.
        {
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query(
                "update sessions set orchestrator_lease_until = now() - interval '1 minute'
                 where id = $1",
            )
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let fresh = acquire_session_lease(&pool, scope, session_id, b, 300)
            .await
            .unwrap()
            .unwrap();

        let by_stale = transition_session_fenced(
            &pool,
            scope,
            session_id,
            SessionStatus::Provisioning,
            Some("stale driver"),
            stale,
        )
        .await
        .unwrap();
        let by_holder = transition_session_fenced(
            &pool,
            scope,
            session_id,
            SessionStatus::Provisioning,
            Some("current holder"),
            fresh,
        )
        .await
        .unwrap();
        let status = get_session(&pool, scope, session_id)
            .await
            .unwrap()
            .map(|s| (s.status, s.status_reason));
        cleanup_sw_tenant(&pool, tenant).await;

        assert_ne!(stale, fresh, "a takeover must move the epoch");
        assert!(
            by_stale.is_none(),
            "a stale-epoch driver's lifecycle mutation must affect ZERO rows"
        );
        assert!(by_holder.is_some(), "the current lease holder proceeds");
        assert_eq!(
            status,
            Some(("provisioning".into(), Some("current holder".into()))),
            "only the holder's write landed"
        );
    }

    /// Two replicas polling one due-delivery backlog take DISJOINT sets, and a
    /// replica that no longer holds a row's claim cannot record its attempt.
    #[tokio::test]
    async fn delivery_claims_are_disjoint_and_attempts_are_owner_guarded() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());

        // The backlog these two replicas race for must be exactly the four rows
        // below — a sibling test's due delivery would otherwise eat replica A's
        // `limit` (the scan is FIFO by `next_attempt_at`, so an older foreign row
        // sorts FIRST) and leave A holding rows of a tenant this test cannot even
        // address. Enqueue and both claims therefore share one GLOBAL_SCAN window,
        // and each batch is read back through the owning helper.
        let scan = GLOBAL_SCAN.lock().await;
        let mut ids = Vec::new();
        for i in 0..4 {
            let d = enqueue_result_delivery(
                &pool,
                scope,
                session_id,
                None,
                &serde_json::json!({"kind":"signed_webhook","url":format!("https://x.test/{i}")}),
            )
            .await
            .unwrap();
            ids.push(d.id);
        }

        // Replica A claims two, replica B claims the rest: SKIP LOCKED + the
        // claim stamp make the sets disjoint (B cannot see A's claimed rows).
        let claimed_a = claim_deliveries(&pool, a, 2, 300, &ids).await;
        let claimed_b = claim_deliveries(&pool, b, 10, 300, &ids).await;
        drop(scan);
        let set_a: std::collections::HashSet<Uuid> = claimed_a.iter().map(|r| r.id).collect();
        let set_b: std::collections::HashSet<Uuid> = claimed_b.iter().map(|r| r.id).collect();
        let overlap = set_a.intersection(&set_b).count();

        // B cannot record an attempt on a row A holds.
        let stolen = mark_delivery_attempt(
            &pool,
            scope,
            *set_a.iter().next().unwrap(),
            b,
            false,
            Some("not mine"),
            None,
            30,
            3,
        )
        .await
        .unwrap();
        // A can, and doing so RELEASES the claim.
        let own_id = *set_a.iter().next().unwrap();
        let mine =
            mark_delivery_attempt(&pool, scope, own_id, a, false, Some("refused"), None, 30, 3)
                .await
                .unwrap();
        let released: Option<(Option<Uuid>,)> = {
            let mut tx = worker_tx(&pool).await.unwrap();
            let r = sqlx::query_as("select claimed_by from result_deliveries where id = $1")
                .bind(own_id)
                .fetch_optional(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            r
        };
        cleanup_sw_tenant(&pool, tenant).await;

        assert_eq!(set_a.len(), 2, "the limit bounds a replica's claimed slice");
        assert_eq!(set_b.len(), 2, "the other replica takes what is left");
        assert_eq!(overlap, 0, "two replicas never claim the same delivery row");
        assert!(
            stolen.is_none(),
            "a replica that does not hold the claim cannot record an attempt"
        );
        assert!(mine.is_some(), "the claim holder records its attempt");
        assert_eq!(
            released,
            Some((None,)),
            "recording an attempt releases the claim for the next backoff window"
        );
    }

    // ─── LLM budget reservations (Phase E, #33; Gap 14) ─────────────────────
    // DB-backed; self-skip when DATABASE_URL is unset (CI proves them). The
    // no-DB SOURCE GUARD below keeps the admission predicate mutation-provable
    // locally.

    /// The body of `reserve_llm_budget`, for the source guards below.
    fn reserve_llm_budget_body() -> &'static str {
        let src = include_str!("lib.rs");
        let start = src
            .find("pub async fn reserve_llm_budget(")
            .expect("reserve_llm_budget exists");
        let end = src[start..]
            .find("pub async fn charge_llm_reservation(")
            .map(|i| start + i)
            .expect("the next fn delimits the body");
        &src[start..end]
    }

    /// The admission statement is the whole fix, so its load-bearing predicates
    /// are asserted from source — a mutation that drops the ceiling guard or
    /// stops counting live reservations fails HERE, with no database.
    #[test]
    fn reserve_llm_budget_sql_keeps_its_load_bearing_predicates() {
        let body = reserve_llm_budget_body();
        for (needle, why) in [
            (
                "for update",
                "the sessions row lock is the SERIALIZER — a CTE alone cannot see a \
                 concurrent transaction's uncommitted reservation, so without this both \
                 racers pass the same guard (Gap 14 returns)",
            ),
            (
                "a.n < $8::bigint as under_ceiling",
                "the finite ceiling on concurrent reservations (design :1118)",
            ),
            (
                "u.tokens + a.tokens + $6::bigint <= $9::bigint",
                "the token projection must include LIVE RESERVATIONS, not just recorded usage",
            ),
            (
                "u.cost + a.cost + coalesce($7::float8, 0) <= $10::float8",
                "the cost projection must include LIVE RESERVATIONS, not just recorded usage",
            ),
        ] {
            assert!(
                body.contains(needle),
                "reserve_llm_budget's SQL lost `{needle}` — {why}"
            );
        }
    }

    /// `active` counts by STATE ALONE. Narrowing it with an expiry predicate
    /// (`… and expires_at > now()`) reopens an UNBUDGETED window between a
    /// reservation expiring and the sweeper converting it: the row would stop
    /// counting against the projection while its spend is still unsettled.
    ///
    /// Review I2: the first cut asserted the bare prefix
    /// `where session_id = $2 and state = 'reserved'`, which that exact mutation
    /// still CONTAINS — the guard passed on the drift it existed to catch. It now
    /// slices the whole `active` sub-select and pins the clause through its
    /// newline terminator, plus a direct refusal of any `expires_at` narrowing.
    #[test]
    fn reserve_llm_budget_counts_active_reservations_by_state_alone() {
        let body = reserve_llm_budget_body();
        let start = body.find("active as (").expect("the `active` CTE exists");
        let end = body[start..]
            .find("guard as (")
            .map(|i| start + i)
            .expect("the `guard` CTE delimits `active`");
        let active = &body[start..end];
        assert!(
            active.contains("where session_id = $2 and state = 'reserved'\n"),
            "the `active` sub-select's WHERE must END at `state = 'reserved'` — anything \
             appended to it (an expiry predicate above all) stops expired-but-unswept rows \
             counting, which is precisely the unbudgeted window this closes"
        );
        assert!(
            !active.contains("expires_at"),
            "`active` must not read expires_at AT ALL: expiry is the SWEEPER's business, \
             and every form of narrowing here reopens the same window"
        );
    }

    /// The SOLE-CLAIMANT carve-out (`a.n = 0`) — the most consequential deviation
    /// from the plan's literal predicate, and the reason a run whose per-request
    /// conservative estimate alone exceeds its remaining budget stops cleanly
    /// instead of livelocking: with nothing else in flight there is nothing to
    /// drain, so refusing forever would never become admitting. Its DB test
    /// discriminates but self-skips without `DATABASE_URL`; this rides every run.
    #[test]
    fn reserve_llm_budget_keeps_the_sole_claimant_carve_out() {
        let body = reserve_llm_budget_body();
        let start = body.find("guard as (").expect("the `guard` CTE exists");
        let end = body[start..]
            .find("ins as (")
            .map(|i| start + i)
            .expect("the `ins` CTE delimits `guard`");
        let guard = &body[start..end];
        for (needle, arm) in [
            ("($9::bigint is null or a.n = 0", "token"),
            ("($10::float8 is null or a.n = 0", "cost"),
        ] {
            assert!(
                guard.contains(needle),
                "the {arm} budget arm lost its `a.n = 0` sole-claimant disjunct — a lone \
                 request would then be refused by its own conservative estimate with no \
                 sibling to drain, livelocking the run instead of stopping it"
            );
        }
        // The carve-out is a DISJUNCT of the budget arms only — it must never
        // reach the ceiling guard, which has to bind even the first request.
        assert!(
            guard.contains("a.n < $8::bigint as under_ceiling"),
            "the ceiling arm must stay unconditional"
        );
    }

    /// Seed a session plus a scope, and give it a settled usage row so the
    /// projection has a non-zero `used` component.
    async fn seed_reservation_session(
        pool: &PgPool,
        used_tokens: i64,
    ) -> (Uuid, Uuid, TenantScope) {
        let (tenant, session_id) = seed_tenant_session(pool).await;
        let scope = TenantScope::assume(tenant);
        if used_tokens > 0 {
            add_usage(
                pool,
                scope,
                session_id,
                "claude-haiku-4-5",
                used_tokens,
                0,
                0,
                0,
                Some(0.01),
                "facade",
                None,
            )
            .await
            .unwrap();
        }
        (tenant, session_id, scope)
    }

    /// Reserve with the fixture's fixed model and TTL — the tests vary only the
    /// numbers they assert on.
    #[allow(clippy::too_many_arguments)]
    async fn reserve(
        pool: &PgPool,
        scope: TenantScope,
        session: Uuid,
        id: Uuid,
        tokens: i64,
        cost: Option<f64>,
        ceiling: i64,
        budget_tokens: Option<i64>,
        budget_cost: Option<f64>,
    ) -> ReserveOutcome {
        reserve_llm_budget(
            pool,
            scope,
            session,
            id,
            "claude-haiku-4-5",
            tokens,
            cost,
            ceiling,
            budget_tokens,
            budget_cost,
            600,
        )
        .await
        .unwrap()
    }

    /// Push a reservation's expiry into the past (what a crashed facade request
    /// looks like to the sweeper).
    async fn expire_reservation(pool: &PgPool, id: Uuid) {
        let mut tx = worker_tx(pool).await.unwrap();
        sqlx::query(
            "update llm_reservations set expires_at = now() - interval '1 minute' where id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn reserve_llm_budget_books_and_settles() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id, scope) = seed_reservation_session(&pool, 100).await;

        let req = Uuid::now_v7();
        assert_eq!(
            reserve(
                &pool,
                scope,
                session_id,
                req,
                500,
                Some(0.02),
                32,
                Some(10_000),
                Some(1.0)
            )
            .await,
            ReserveOutcome::Reserved
        );
        let totals = active_reservation_totals(&pool, scope, session_id)
            .await
            .unwrap();
        assert_eq!((totals.tokens, totals.active), (500, 1));

        // Charge is a one-way CAS: the second call finds no `reserved` row.
        assert!(charge_llm_reservation(&pool, scope, req).await.unwrap());
        assert!(!charge_llm_reservation(&pool, scope, req).await.unwrap());
        assert!(
            !release_llm_reservation(&pool, scope, req).await.unwrap(),
            "a charged reservation can never be released back"
        );
        let row = get_llm_reservation(&pool, scope, req)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "charged");
        let after = active_reservation_totals(&pool, scope, session_id)
            .await
            .unwrap();
        assert_eq!(
            (after.tokens, after.active),
            (0, 0),
            "a charged row stops being active"
        );

        // Release is the mirror image, on a fresh booking.
        let req2 = Uuid::now_v7();
        assert_eq!(
            reserve(
                &pool,
                scope,
                session_id,
                req2,
                500,
                Some(0.02),
                32,
                Some(10_000),
                Some(1.0)
            )
            .await,
            ReserveOutcome::Reserved
        );
        assert!(release_llm_reservation(&pool, scope, req2).await.unwrap());
        assert_eq!(
            get_llm_reservation(&pool, scope, req2)
                .await
                .unwrap()
                .unwrap()
                .state,
            "released"
        );
        assert_eq!(
            active_reservation_totals(&pool, scope, session_id)
                .await
                .unwrap()
                .active,
            0
        );
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn reserve_llm_budget_counts_recorded_usage_and_live_reservations() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        // 600 tokens already recorded against a 1000-token budget.
        let (tenant, session_id, scope) = seed_reservation_session(&pool, 600).await;

        // First booking fits: 600 recorded + 0 live + 300 = 900 <= 1000.
        assert_eq!(
            reserve(
                &pool,
                scope,
                session_id,
                Uuid::now_v7(),
                300,
                None,
                32,
                Some(1000),
                None
            )
            .await,
            ReserveOutcome::Reserved
        );
        // Second is individually small but 600 + 300 + 300 = 1200 > 1000. It is
        // refused ONLY because the LIVE reservation is counted — recorded usage
        // alone (600 + 300) would have passed.
        assert_eq!(
            reserve(
                &pool,
                scope,
                session_id,
                Uuid::now_v7(),
                300,
                None,
                32,
                Some(1000),
                None
            )
            .await,
            ReserveOutcome::BudgetExceeded {
                budget: "max_tokens",
                active: 1
            }
        );
        // The cost arm binds the same way, on its own.
        let (t2, s2, sc2) = seed_reservation_session(&pool, 0).await;
        assert_eq!(
            reserve(
                &pool,
                sc2,
                s2,
                Uuid::now_v7(),
                1,
                Some(0.90),
                32,
                None,
                Some(1.0)
            )
            .await,
            ReserveOutcome::Reserved
        );
        assert_eq!(
            reserve(
                &pool,
                sc2,
                s2,
                Uuid::now_v7(),
                1,
                Some(0.90),
                32,
                None,
                Some(1.0)
            )
            .await,
            ReserveOutcome::BudgetExceeded {
                budget: "max_cost_usd",
                active: 1
            }
        );
        // A run with NO caps is never refused by the budget arms.
        assert_eq!(
            reserve(
                &pool,
                sc2,
                s2,
                Uuid::now_v7(),
                1_000_000,
                Some(999.0),
                32,
                None,
                None
            )
            .await,
            ReserveOutcome::Reserved
        );
        cleanup_sw_tenant(&pool, tenant).await;
        cleanup_sw_tenant(&pool, t2).await;
    }

    /// The SOLE-CLAIMANT rule: with nothing else in flight the budget arms are
    /// skipped, so a lone request whose conservative estimate alone exceeds the
    /// remaining budget still gets to run (it would otherwise 429-livelock with
    /// nothing to drain). The moment a sibling exists, the projection binds.
    #[tokio::test]
    async fn reserve_llm_budget_admits_the_sole_claimant_then_binds() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id, scope) = seed_reservation_session(&pool, 900).await;
        // 900 recorded, budget 1000, this request alone wants 5000.
        assert_eq!(
            reserve(
                &pool,
                scope,
                session_id,
                Uuid::now_v7(),
                5000,
                None,
                32,
                Some(1000),
                None
            )
            .await,
            ReserveOutcome::Reserved,
            "a lone request is admitted — the accumulated check already ruled"
        );
        assert!(matches!(
            reserve(
                &pool,
                scope,
                session_id,
                Uuid::now_v7(),
                1,
                None,
                32,
                Some(1000),
                None
            )
            .await,
            ReserveOutcome::BudgetExceeded { .. }
        ));
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn reserve_llm_budget_enforces_the_concurrency_ceiling() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id, scope) = seed_reservation_session(&pool, 0).await;
        // Ceiling 2, no budget caps at all — only the ceiling can refuse.
        for _ in 0..2 {
            assert_eq!(
                reserve(
                    &pool,
                    scope,
                    session_id,
                    Uuid::now_v7(),
                    1,
                    None,
                    2,
                    None,
                    None
                )
                .await,
                ReserveOutcome::Reserved
            );
        }
        assert_eq!(
            reserve(
                &pool,
                scope,
                session_id,
                Uuid::now_v7(),
                1,
                None,
                2,
                None,
                None
            )
            .await,
            ReserveOutcome::CeilingExceeded {
                active: 2,
                ceiling: 2
            }
        );
        cleanup_sw_tenant(&pool, tenant).await;
    }

    /// THE GAP-14 ACCEPTANCE. Two genuinely concurrent transactions on separate
    /// connections, each individually inside the budget, jointly over it: exactly
    /// ONE may book. This is the race the facade's check-then-record budget lost
    /// every time.
    #[tokio::test]
    async fn reserve_llm_budget_two_tx_race_yields_exactly_one_winner() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id, scope) = seed_reservation_session(&pool, 0).await;
        let pool2 = pool.clone();
        // Budget 1000; each request books 600 — either alone fits, both do not.
        let (a, b) = tokio::join!(
            reserve(
                &pool,
                scope,
                session_id,
                Uuid::now_v7(),
                600,
                None,
                32,
                Some(1000),
                None
            ),
            reserve(
                &pool2,
                scope,
                session_id,
                Uuid::now_v7(),
                600,
                None,
                32,
                Some(1000),
                None
            ),
        );
        let wins = [&a, &b]
            .iter()
            .filter(|o| ***o == ReserveOutcome::Reserved)
            .count();
        assert_eq!(
            wins, 1,
            "exactly one concurrent reservation may take the shared budget (got {a:?} / {b:?})"
        );
        assert!(
            [&a, &b]
                .iter()
                .any(|o| matches!(o, ReserveOutcome::BudgetExceeded { .. })),
            "the loser is refused on the BUDGET, not on some other arm (got {a:?} / {b:?})"
        );
        let totals = active_reservation_totals(&pool, scope, session_id)
            .await
            .unwrap();
        assert_eq!(
            (totals.active, totals.tokens),
            (1, 600),
            "only the winner's booking exists"
        );
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn sweep_converts_expired_reservations_conservatively() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id, scope) = seed_reservation_session(&pool, 0).await;
        let req = Uuid::now_v7();
        reserve(
            &pool,
            scope,
            session_id,
            req,
            4242,
            Some(0.25),
            32,
            None,
            None,
        )
        .await;

        // The sweep is a tenant-less GLOBAL scan, so hold the scan guard from
        // before this booking can be swept until this test has swept it, and read
        // every batch through the session-scoped helper (see GLOBAL_SCAN).
        let _scan = GLOBAL_SCAN.lock().await;

        // A live reservation is NOT swept.
        assert!(sweep_reservations(&pool, session_id).await.is_empty());

        expire_reservation(&pool, req).await;
        let swept = sweep_reservations(&pool, session_id).await;
        assert_eq!(swept.len(), 1);
        assert_eq!(swept[0].reserved_tokens, 4242);
        assert_eq!(swept[0].session_id, session_id);
        assert_eq!(
            swept[0].tenant_id, tenant,
            "the swept row carries its OWN tenant — the worker ledgers the \
             conservative charge under exactly this scope"
        );

        // The conservative charge is now real, budget-visible usage…
        let totals = usage_totals(&pool, scope, session_id).await.unwrap();
        assert_eq!(totals.output_tokens, 4242);
        assert!((totals.cost_usd - 0.25).abs() < 1e-9);
        // …and the reservation is settled, so it is no longer double-counted.
        assert_eq!(
            get_llm_reservation(&pool, scope, req)
                .await
                .unwrap()
                .unwrap()
                .state,
            "charged"
        );
        assert_eq!(
            active_reservation_totals(&pool, scope, session_id)
                .await
                .unwrap()
                .active,
            0
        );
        // Idempotent: a second sweep of the same instant finds nothing.
        assert!(sweep_reservations(&pool, session_id).await.is_empty());
        drop(_scan);
        cleanup_sw_tenant(&pool, tenant).await;
    }

    /// The sweeper and a late drain settle the SAME request id, so `add_usage`'s
    /// `on conflict (external_id) do nothing` makes them idempotent in EITHER
    /// order — never a double charge, never a lost charge.
    #[tokio::test]
    async fn sweep_and_late_drain_are_idempotent_in_either_order() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");

        // Order A — sweeper first, drain late. The conservative charge stands;
        // the drain's real usage is the no-op and its CAS loses.
        let (ta, sa, sca) = seed_reservation_session(&pool, 0).await;
        let ra = Uuid::now_v7();
        reserve(&pool, sca, sa, ra, 5000, Some(0.50), 32, None, None).await;
        // Guarded + session-scoped like every other global-scan read (GLOBAL_SCAN):
        // the guard is taken before the booking becomes sweepable and released
        // once this test has swept it.
        let scan_a = GLOBAL_SCAN.lock().await;
        expire_reservation(&pool, ra).await;
        assert_eq!(sweep_reservations(&pool, sa).await.len(), 1);
        drop(scan_a);
        assert!(
            !add_usage(
                &pool,
                sca,
                sa,
                "claude-haiku-4-5",
                7,
                11,
                0,
                0,
                Some(0.001),
                "facade",
                Some(&ra.to_string()),
            )
            .await
            .unwrap(),
            "the late drain's usage row is refused by the external_id conflict"
        );
        assert!(
            !charge_llm_reservation(&pool, sca, ra).await.unwrap(),
            "the late drain's CAS finds an already-charged reservation"
        );
        let a = usage_totals(&pool, sca, sa).await.unwrap();
        assert_eq!(
            (a.requests, a.output_tokens, a.input_tokens),
            (1, 5000, 0),
            "exactly one usage row, and it is the conservative one"
        );

        // Order B — drain first, sweeper late. The REAL usage stands and the
        // sweeper's conservative row is the no-op.
        let (tb, sb, scb) = seed_reservation_session(&pool, 0).await;
        let rb = Uuid::now_v7();
        reserve(&pool, scb, sb, rb, 5000, Some(0.50), 32, None, None).await;
        assert!(add_usage(
            &pool,
            scb,
            sb,
            "claude-haiku-4-5",
            7,
            11,
            0,
            0,
            Some(0.001),
            "facade",
            Some(&rb.to_string()),
        )
        .await
        .unwrap());
        // …crash before the CAS: the row is still `reserved`, so the sweep runs.
        let scan_b = GLOBAL_SCAN.lock().await;
        expire_reservation(&pool, rb).await;
        assert_eq!(sweep_reservations(&pool, sb).await.len(), 1);
        drop(scan_b);
        let b = usage_totals(&pool, scb, sb).await.unwrap();
        assert_eq!(
            (b.requests, b.input_tokens, b.output_tokens),
            (1, 7, 11),
            "exactly one usage row, and the authoritative numbers won"
        );
        assert_eq!(
            get_llm_reservation(&pool, scb, rb)
                .await
                .unwrap()
                .unwrap()
                .state,
            "charged"
        );
        cleanup_sw_tenant(&pool, ta).await;
        cleanup_sw_tenant(&pool, tb).await;
    }
}
