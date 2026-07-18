//! Role → permission derivation (parent design lines 564-593, settled v1).
//!
//! The operator (admin token) implicitly holds every permission — it is the
//! break-glass deployment credential. A user's authority is its live
//! membership roles, rechecked on every request by the `Principal` extractor.
//! These are pure functions of a `Principal`; the gate calls them, the DB
//! query enforces the tenant boundary.

use crate::auth::Principal;
use crate::error::ApiError;
use fluidbox_db::SessionRow;
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
}
