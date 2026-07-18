//! Role → permission derivation (parent design lines 564-593, settled v1).
//!
//! The operator (admin token) implicitly holds every permission — it is the
//! break-glass deployment credential. A user's authority is its live
//! membership roles, rechecked on every request by the `Principal` extractor.
//! These are pure functions of a `Principal`; the gate calls them, the DB
//! query enforces the tenant boundary.

use crate::auth::Principal;
use crate::error::ApiError;
use fluidbox_db::{ConnectionViewer, SessionRow};
use uuid::Uuid;

pub fn has_role(principal: &Principal, role: &str) -> bool {
    principal.roles().iter().any(|r| r == role)
}

fn any_role(principal: &Principal, roles: &[&str]) -> bool {
    roles.iter().any(|r| has_role(principal, r))
}

/// May decide approvals whose call authority is organization-owned (a
/// subscription secret or org connection) — the `approver`/`admin`/`owner`
/// roles. Implies [`can_read_all_runs`] (you can always see the run you judge).
pub fn can_decide_org(principal: &Principal) -> bool {
    principal.is_operator() || any_role(principal, &["approver", "admin", "owner"])
}

/// May a plain member self-approve this approval under `approval.decide_own`
/// (parent design lines 564-579)? Only when the caller invoked the run AND the
/// call is credentialless: members may self-approve credentialless calls, but
/// every brokered MCP call carries org authority in Phase B and needs
/// `decide_org`. Brokered tools all wear the canonical `mcp__<server>__<tool>`
/// prefix; sandbox/builtin tools (Bash, Edit, …) are credentialless by
/// construction.
pub fn can_decide_own(principal: &Principal, invoked_by: Option<Uuid>, tool: &str) -> bool {
    principal.user_id().is_some() && invoked_by == principal.user_id() && !tool.starts_with("mcp__")
}

/// May read every run in the tenant (`runs.read_all`) — implied by
/// `approval.decide_org`, so the same role set.
pub fn can_read_all_runs(principal: &Principal) -> bool {
    principal.is_operator() || any_role(principal, &["approver", "admin", "owner"])
}

/// May manage trigger subscriptions (`subscriptions.manage`) — admin/owner.
pub fn can_manage_subscriptions(principal: &Principal) -> bool {
    principal.is_operator() || any_role(principal, &["admin", "owner"])
}

/// May manage the organization itself (membership roles, IdP config) — owner.
/// Consumed by the Task-5 break-glass / org-management routes.
#[allow(dead_code)]
pub fn can_manage_org(principal: &Principal) -> bool {
    principal.is_operator() || has_role(principal, "owner")
}

/// May mutate tenant resources (agents, policies, capability bundles,
/// connections, custom catalog entries, github app registrations) — admin/owner.
pub fn can_mutate_resources(principal: &Principal) -> bool {
    principal.is_operator() || any_role(principal, &["admin", "owner"])
}

/// May this principal create a PERSONAL (user-owned) connection? Any User
/// principal qualifies: the extractor liveness-gates every request, so the
/// principal's existence already proves an active membership — no elevated role
/// is required to hold one's own credential. The operator is excluded:
/// single-admin mode has no user identity to own a personal row, so the
/// operator creates organization connections only.
pub fn can_create_personal_connection(principal: &Principal) -> bool {
    principal.user_id().is_some()
}

/// The visibility lens for connection listings / per-connection reads (design
/// :274-296). EVERY user principal — plain member through owner — sees
/// organization connections plus only its OWN personal connections
/// (`User(user_id)`). Admin/owner roles get NO extra reach into other members'
/// personal rows: the Phase C acceptance bar is owner-only inspection ("neither
/// can select or inspect the other's personal connection"), and offboarding is
/// covered by membership deactivation (the broker owner-membership recheck),
/// not by admin visibility. Only the operator gets `All` — single-admin mode
/// has no user identity, and under REQUIRE_SSO the operator is confined to
/// /v1/admin anyway, so `All` never widens a real user's view.
pub fn connection_viewer(principal: &Principal) -> ConnectionViewer {
    match principal.user_id() {
        Some(uid) => ConnectionViewer::User(uid),
        None => ConnectionViewer::All,
    }
}

/// Enforce `run.read` after a tenant-scoped fetch has already proven the run
/// belongs to the caller's tenant. Operator / `runs.read_all` holders see every
/// run; a plain member sees only runs it invoked. A non-visible run is a 404
/// (its existence is not revealed), not a 403.
pub fn ensure_run_visible(principal: &Principal, session: &SessionRow) -> Result<(), ApiError> {
    if can_read_all_runs(principal) {
        return Ok(());
    }
    match principal.user_id() {
        Some(uid) if session.invoked_by_user_id == Some(uid) => Ok(()),
        _ => Err(ApiError::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthContext, UserPrincipal};
    use fluidbox_db::TenantScope;
    use uuid::Uuid;

    fn operator() -> Principal {
        Principal::Operator {
            scope: TenantScope::assume(Uuid::now_v7()),
        }
    }

    fn user(roles: &[&str]) -> Principal {
        Principal::User(UserPrincipal {
            tenant_id: Uuid::now_v7(),
            user_id: Uuid::now_v7(),
            membership_id: Uuid::now_v7(),
            roles: roles.iter().map(|r| r.to_string()).collect(),
            auth: AuthContext::Pat {
                token_id: Uuid::now_v7(),
            },
        })
    }

    #[test]
    fn operator_holds_every_permission() {
        let p = operator();
        assert!(can_decide_org(&p));
        assert!(can_read_all_runs(&p));
        assert!(can_manage_subscriptions(&p));
        assert!(can_manage_org(&p));
        assert!(can_mutate_resources(&p));
        assert!(p.user_id().is_none());
    }

    #[test]
    fn member_holds_no_elevated_permission() {
        let p = user(&["member"]);
        assert!(!can_decide_org(&p));
        assert!(!can_read_all_runs(&p));
        assert!(!can_manage_subscriptions(&p));
        assert!(!can_manage_org(&p));
        assert!(!can_mutate_resources(&p));
    }

    #[test]
    fn approver_reads_and_decides_but_does_not_manage_or_mutate() {
        let p = user(&["approver"]);
        assert!(can_decide_org(&p));
        assert!(can_read_all_runs(&p));
        assert!(!can_manage_subscriptions(&p));
        assert!(!can_manage_org(&p));
        assert!(!can_mutate_resources(&p));
    }

    #[test]
    fn admin_manages_and_mutates_but_is_not_owner() {
        let p = user(&["admin"]);
        assert!(can_decide_org(&p));
        assert!(can_read_all_runs(&p));
        assert!(can_manage_subscriptions(&p));
        assert!(can_mutate_resources(&p));
        assert!(!can_manage_org(&p));
    }

    #[test]
    fn member_self_approves_only_credentialless_calls() {
        let p = user(&["member"]);
        let mine = p.user_id();
        let other = Some(Uuid::now_v7());
        // Own run + credentialless (builtin) tool → allowed.
        assert!(can_decide_own(&p, mine, "Bash"));
        assert!(can_decide_own(&p, mine, "Edit"));
        // Own run + brokered MCP call → denied (org authority, needs decide_org).
        assert!(!can_decide_own(&p, mine, "mcp__github__create_issue"));
        // Someone else's run → denied regardless of tool.
        assert!(!can_decide_own(&p, other, "Bash"));
    }

    #[test]
    fn operator_has_no_own_user_so_decide_own_is_moot() {
        // Operator authorizes via can_decide_org; decide_own never applies
        // (no user identity to match the run's invoker).
        let p = operator();
        assert!(!can_decide_own(&p, None, "Bash"));
    }

    #[test]
    fn owner_holds_everything_a_user_can() {
        let p = user(&["owner"]);
        assert!(can_decide_org(&p));
        assert!(can_read_all_runs(&p));
        assert!(can_manage_subscriptions(&p));
        assert!(can_manage_org(&p));
        assert!(can_mutate_resources(&p));
    }

    #[test]
    fn only_the_operator_gets_all_connection_visibility() {
        // The operator (single-admin break-glass) sees every connection.
        assert!(matches!(
            connection_viewer(&operator()),
            ConnectionViewer::All
        ));
        // Every user principal — member through owner — is scoped to its own
        // personal rows (plus org rows the DB predicate always admits).
        for roles in [
            &["member"][..],
            &["approver"][..],
            &["admin"][..],
            &["owner"][..],
        ] {
            let p = user(roles);
            match connection_viewer(&p) {
                ConnectionViewer::User(uid) => assert_eq!(Some(uid), p.user_id()),
                ConnectionViewer::All => {
                    panic!("a user principal ({roles:?}) must never get All visibility")
                }
            }
        }
    }

    #[test]
    fn any_member_may_create_a_personal_connection_but_not_the_operator() {
        // The operator has no personal identity to own a personal row.
        assert!(!can_create_personal_connection(&operator()));
        // Every member — no elevated role required — may hold their own.
        for roles in [
            &["member"][..],
            &["approver"][..],
            &["admin"][..],
            &["owner"][..],
        ] {
            assert!(
                can_create_personal_connection(&user(roles)),
                "member {roles:?} should be able to create a personal connection"
            );
        }
    }
}
