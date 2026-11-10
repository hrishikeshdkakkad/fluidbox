//! Building the pool: settings, migrations on connect, and the runtime-role
//! posture checks that decide whether row-level security actually binds.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

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
    // change under migrations/ must touch this file. Latest: 0027
    // (recipes — catalog + versions + instances + object links, seeded v1 catalog).
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
