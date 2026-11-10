//! The tenant-scoping primitives: [`TenantScope`] and the two transaction
//! openers that set the RLS GUCs — the scoped one and the audited bypass.

use sqlx::PgPool;
use uuid::Uuid;

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
/// scans (Task 7) and the handful of crate-root / identity.rs bootstrap resolvers that
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
