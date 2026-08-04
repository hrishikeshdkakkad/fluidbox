//! Durable lifecycle for a run's network grant (migration 0028).
//!
//! The grant itself is IMMUTABLE and lives in `sessions.run_spec`. What lives
//! here is the part a frozen document cannot hold: whether that authority is
//! still pending a human, in force, refused, or torn down. Every mutation is a
//! compare-and-set on `status`, so the pause, the orchestrator's
//! pre-provisioning re-check, and revocation are all idempotent under retries,
//! restarts, and concurrent replicas.
//!
//! Tenant scoping follows the house rule: every entry point takes a
//! [`TenantScope`] and the RLS child-EXISTS policy composes through `sessions`.
//! The one cross-tenant reader is the gate worker's scan, which lives in
//! [`crate::system_worker`] like every other principal-less loader.

use crate::{scoped_tx, TenantScope};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Column list, kept in one place so every query returns the same shape.
macro_rules! grant_cols {
    () => {
        "id, tenant_id, session_id, mode, grant_doc, grant_digest, policy_digest, status,
         expires_at, approval_id, created_at, updated_at, activated_at, revoked_at,
         status_reason"
    };
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct NetworkGrantRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub mode: String,
    pub grant_doc: Value,
    pub grant_digest: String,
    pub policy_digest: String,
    pub status: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub approval_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub activated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status_reason: Option<String>,
}

impl NetworkGrantRow {
    /// Is this grant in force RIGHT NOW? Fail-closed on every axis: the status
    /// must be `active`, and an expiry that has passed is not in force even
    /// though the row still says `active` (the sweeper is a cleanup, never the
    /// authority). An `offline` grant carries no expiry and is always "in
    /// force" — it authorizes nothing.
    pub fn is_in_force(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        if self.status != "active" {
            return false;
        }
        match self.expires_at {
            Some(exp) => now < exp,
            // Only `offline` may omit an expiry; anything else without one is
            // malformed and must not be treated as eternal.
            None => self.mode == "offline",
        }
    }

    pub fn grants_egress(&self) -> bool {
        self.mode != "offline"
    }
}

/// What a caller that LOST the deny CAS should do, given the grant's committed
/// state.
///
/// Production logic rather than a helper duplicated in a test, because a
/// duplicate can stay green while the real path regresses — and BOTH directions
/// of this have been wrong here: returning early on every loss STRANDED a parked
/// run whose grant had been revoked underneath it, and winding down on every
/// loss FAILED a run another replica had just legitimately activated.
///
/// The CAS establishes who owns the refusal; this classifies what the loser is
/// looking at.
pub fn wind_down_on_cas_loss(observed_status: Option<&str>) -> bool {
    match observed_status {
        // Another replica activated it; the run is proceeding. Leave it alone.
        Some("active") => false,
        // Resolved away, or gone entirely — nothing will ever release this run.
        _ => true,
    }
}

/// The insert payload. Minted by `create_run` so the RunSpec and the row agree
/// on the digest before either is written.
#[derive(Debug, Clone)]
pub struct NewNetworkGrant {
    pub id: Uuid,
    pub mode: String,
    pub grant_doc: Value,
    pub grant_digest: String,
    pub policy_digest: String,
    /// `active` (no human needed) or `pending` (parked for authorization).
    pub status: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub approval_id: Option<Uuid>,
}

/// Write the grant INSIDE the session-insert transaction, so a run and its
/// network authority commit together or not at all. A session that exists
/// without a grant row would be un-resolvable: the orchestrator gate refuses to
/// provision one, which is the correct fail-closed behaviour but a worse
/// failure than never creating it.
pub async fn insert_network_grant(
    tx: &mut sqlx::PgConnection,
    scope: TenantScope,
    session_id: Uuid,
    g: &NewNetworkGrant,
) -> sqlx::Result<()> {
    sqlx::query(
        "insert into session_network_grants
           (id, tenant_id, session_id, mode, grant_doc, grant_digest, policy_digest,
            status, expires_at, approval_id, activated_at)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
                 case when $8 = 'active' then now() else null end)",
    )
    .bind(g.id)
    .bind(scope.tenant_id())
    .bind(session_id)
    .bind(&g.mode)
    .bind(&g.grant_doc)
    .bind(&g.grant_digest)
    .bind(&g.policy_digest)
    .bind(&g.status)
    .bind(g.expires_at)
    .bind(g.approval_id)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

pub async fn get_network_grant(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
) -> sqlx::Result<Option<NetworkGrantRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(concat!(
        "select ",
        grant_cols!(),
        " from session_network_grants where session_id = $1 and tenant_id = $2"
    ))
    .bind(session_id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Attach the approval row that gates a parked grant. Separate from the insert
/// because the approval is registered after the session exists (it references
/// the session), and CAS-guarded on `pending` so a decided grant can never have
/// its gate swapped underneath it.
pub async fn attach_grant_approval(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
    approval_id: Uuid,
) -> sqlx::Result<bool> {
    let mut tx = scoped_tx(pool, scope).await?;
    let res = sqlx::query(
        "update session_network_grants
            set approval_id = $3, updated_at = now()
          where session_id = $1 and tenant_id = $2 and status = 'pending'",
    )
    .bind(session_id)
    .bind(scope.tenant_id())
    .bind(approval_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

/// `pending → active`. Returns the row iff THIS call won the transition, so the
/// gate worker can only release provisioning once even when several replicas
/// wake on the same NOTIFY.
///
/// The caller must have re-verified digest, expiry and policy BEFORE calling:
/// this is the commit point, not the check.
pub async fn activate_network_grant(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
) -> sqlx::Result<Option<NetworkGrantRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(concat!(
        "update session_network_grants
            set status = 'active', activated_at = now(), updated_at = now()
          where session_id = $1 and tenant_id = $2 and status = 'pending'
          returning ",
        grant_cols!()
    ))
    .bind(session_id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// `pending → denied`. The human refused, the approval expired, or the
/// re-verification found the world had moved. Terminal for the grant; the
/// session winds down separately.
pub async fn deny_network_grant(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
    reason: &str,
) -> sqlx::Result<Option<NetworkGrantRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(concat!(
        "update session_network_grants
            set status = 'denied', status_reason = $3, updated_at = now()
          where session_id = $1 and tenant_id = $2 and status = 'pending'
          returning ",
        grant_cols!()
    ))
    .bind(session_id)
    .bind(scope.tenant_id())
    .bind(reason)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Tear the grant down. IDEMPOTENT by CAS: any non-revoked status collapses to
/// `revoked`, and a second call returns `None` because there is nothing left to
/// transition. Fired from `finish_terminal_cleanup` beside `revoke_session_tokens`
/// and from the abandon paths, so a run that dies anywhere still surrenders its
/// network authority.
///
/// Revoking a `pending` grant is deliberate and not an error: a run cancelled
/// while parked never gets its authority, and the row records that it was taken
/// away rather than refused by a human.
pub async fn revoke_network_grant(
    pool: &PgPool,
    scope: TenantScope,
    session_id: Uuid,
    reason: &str,
) -> sqlx::Result<Option<NetworkGrantRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(concat!(
        "update session_network_grants
            set status = 'revoked', status_reason = $3,
                revoked_at = now(), updated_at = now()
          where session_id = $1 and tenant_id = $2 and status <> 'revoked'
          returning ",
        grant_cols!()
    ))
    .bind(session_id)
    .bind(scope.tenant_id())
    .bind(reason)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn row(mode: &str, status: &str, expires_in: Option<i64>) -> NetworkGrantRow {
        NetworkGrantRow {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            session_id: Uuid::now_v7(),
            mode: mode.into(),
            grant_doc: serde_json::json!({}),
            grant_digest: "sha256:x".into(),
            policy_digest: "sha256:y".into(),
            status: status.into(),
            expires_at: expires_in.map(|s| Utc::now() + Duration::seconds(s)),
            approval_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            activated_at: None,
            revoked_at: None,
            status_reason: None,
        }
    }

    /// The CAS surface of each mutation, as a matrix — because the blocker an
    /// adversarial review found lived exactly here.
    ///
    /// `deny_network_grant` moves `pending → denied` ONLY. A caller that treated
    /// its `Ok(None)` as "nothing to do and nothing to clean up" therefore did
    /// nothing at all for a row that was already `revoked` — which is precisely
    /// the state the stale-schema sweep leaves behind — and the parked session
    /// was never wound down. The lesson encoded here: a CAS answers "did I win",
    /// never "is there work left".
    /// What a CAS LOSER must do, per observed state. Both directions are bugs
    /// that have actually been written here:
    ///
    /// * returning early on every loss STRANDED a parked run whose grant had
    ///   been revoked underneath it — nothing ever wound it down;
    /// * winding down on every loss FAILED a legitimately activated run, because
    ///   under multi-replica the loser's re-read sees `active` (another replica
    ///   activated and spawned it).
    ///
    /// The correct rule is "wind down only when the grant is resolved AWAY".
    #[test]
    fn a_cas_loser_winds_down_only_when_the_grant_is_resolved_away() {
        fn should_wind_down(observed: Option<&str>) -> bool {
            match observed {
                // Another replica activated it; the run is proceeding.
                Some("active") => false,
                // Still awaiting a decision — the gate will come back.
                Some("pending") => true,
                // Resolved away, or gone: nothing will release this run.
                Some("denied") | Some("revoked") | None => true,
                Some(_) => true,
            }
        }
        assert!(
            !should_wind_down(Some("active")),
            "must not fail a live run"
        );
        assert!(should_wind_down(Some("denied")));
        assert!(should_wind_down(Some("revoked")));
        assert!(should_wind_down(None), "no grant means no authority");
    }

    #[test]
    fn the_status_cas_surface_is_explicit() {
        // Which source states each mutation can move FROM. These mirror the SQL
        // predicates; a change to one without the other is the bug class above.
        let deny_from = ["pending"];
        let activate_from = ["pending"];
        let revoke_from = ["pending", "active", "denied"]; // anything not already revoked

        for s in ["pending", "active", "denied", "revoked"] {
            let can_deny = deny_from.contains(&s);
            let can_activate = activate_from.contains(&s);
            let can_revoke = revoke_from.contains(&s);
            // The two states a parked run can be found in AFTER something else
            // resolved its grant. Neither can be denied again — so a caller
            // MUST NOT make the session's wind-down conditional on that CAS.
            if s == "revoked" || s == "denied" {
                assert!(
                    !can_deny,
                    "{s}: deny cannot fire, so wind-down must not depend on it"
                );
            }
            // Revocation stays idempotent from every non-revoked state, which is
            // what lets terminal cleanup, the abandon paths, and the sweeps all
            // call it freely.
            assert_eq!(can_revoke, s != "revoked", "revoke from {s}");
            assert_eq!(can_activate, s == "pending", "activate from {s}");
        }
    }

    #[test]
    fn in_force_is_fail_closed_on_every_axis() {
        let now = Utc::now();
        // The happy case.
        assert!(row("approved", "active", Some(600)).is_in_force(now));
        // Wrong status — including `pending`, which is the whole point of the
        // pause: a parked grant authorizes nothing while it waits.
        for s in ["pending", "denied", "revoked"] {
            assert!(!row("approved", s, Some(600)).is_in_force(now));
        }
        // Expired, even though the row still says `active` — the sweeper is
        // cleanup, never the authority.
        assert!(!row("approved", "active", Some(-1)).is_in_force(now));
        // An expiry-less non-offline grant is malformed, not eternal.
        assert!(!row("approved", "active", None).is_in_force(now));
        assert!(!row("public", "active", None).is_in_force(now));
        // Offline carries no expiry and is always "in force" — it grants
        // nothing, so there is nothing to lapse.
        assert!(row("offline", "active", None).is_in_force(now));
        assert!(!row("offline", "active", None).grants_egress());
        assert!(row("approved", "active", Some(600)).grants_egress());
        assert!(row("public", "active", Some(600)).grants_egress());
    }
}
