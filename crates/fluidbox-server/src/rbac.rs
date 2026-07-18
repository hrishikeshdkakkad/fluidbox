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

/// The binding-authority facts the approval classifier needs — a DB-free
/// projection of the tool's `mcp`-slot `run_resource_bindings` row. `None` when
/// the approval's tool resolves to no binding: a non-mcp built-in (credentialless
/// by construction) or a legacy brokered call that predates Phase C bindings.
#[derive(Debug, Clone)]
pub struct ApprovalBindingFacts {
    pub authority_kind: String,
    pub owner_type: Option<String>,
    pub owner_user_id: Option<Uuid>,
}

impl ApprovalBindingFacts {
    pub fn from_binding(b: &fluidbox_db::RunResourceBindingRow) -> Self {
        Self {
            authority_kind: b.authority_kind.clone(),
            owner_type: b.connection_owner_type.clone(),
            owner_user_id: b.connection_owner_user_id,
        }
    }
}

/// The call authority an approval executes under (design :562-583). Phase C
/// ends Phase B's "every brokered call is org authority" premise: a brokered
/// call now runs under whichever connection its run bound — which may be one
/// member's personal grant.
#[derive(Debug, PartialEq, Eq)]
pub enum ApprovalAuthority {
    /// A user-owned (personal) connection — only its owner may decide.
    UserConnection { owner_user_id: Uuid },
    /// An org connection, a subscription secret, or a legacy brokered call —
    /// `approval.decide_org` authority.
    Organization,
    /// Credentialless (a non-mcp built-in tool) — `decide_own` / `decide_org`.
    Credentialless,
}

/// Why a decision was refused — the handler maps each to a message (the
/// personal-connection case is enriched with the connection's display name).
#[derive(Debug, PartialEq, Eq)]
pub enum ApprovalRefusal {
    /// A personal connection owned by another user (never decidable by any role).
    PersonalConnection { owner_user_id: Uuid },
    /// Org/subscription authority: needs `approval.decide_org`.
    NeedsOrg,
    /// Credentialless: needs `decide_own` (own run) or `decide_org`.
    NeedsOwnOrOrg,
}

/// Classify an approval's call authority from its tool name and (when brokered)
/// its resolved binding facts. Pure + DB-free — the caller loads the binding row
/// and projects it. A non-mcp tool is always credentialless; an mcp tool WITH a
/// binding uses that binding's authority union; an mcp tool with NO binding is a
/// pre-Phase-C brokered call and keeps Phase B's org-authority premise.
pub fn classify_approval_authority(
    tool: &str,
    binding: Option<&ApprovalBindingFacts>,
) -> ApprovalAuthority {
    if !tool.starts_with("mcp__") {
        return ApprovalAuthority::Credentialless;
    }
    match binding {
        Some(b) if b.authority_kind == "connection" && b.owner_type.as_deref() == Some("user") => {
            match b.owner_user_id {
                Some(owner_user_id) => ApprovalAuthority::UserConnection { owner_user_id },
                // Fail closed: a user-owned binding missing its owner id is
                // corruption — treat as org (the stricter path for a member).
                None => ApprovalAuthority::Organization,
            }
        }
        // Org connection / subscription_secret (or a "none"-authority mcp binding
        // that should never occur) → org authority.
        Some(_) => ApprovalAuthority::Organization,
        // A brokered call with no binding predates Phase C: Phase B governs it.
        None => ApprovalAuthority::Organization,
    }
}

/// Whether the principal may decide this approval — approve OR deny, symmetric
/// in v1 (design :564-583). Pure over the classified authority + the run's
/// invoker + the principal's identity and `decide_org` capability.
///
/// - **UserConnection:** ONLY the owner, and only on a run they invoked. NO role
///   — admin, owner, or the operator — may decide under another user's personal
///   connection (design :576-579); unattended personal delegation is omitted in
///   v1. The operator (no user identity) is therefore refused here too, but this
///   arm is unreachable in single-admin mode (personal ownership needs a User
///   principal) and the operator is confined to /v1/admin under REQUIRE_SSO —
///   so operator semantics are preserved in practice.
/// - **Organization:** `decide_org` (operator + approver/admin/owner) — Phase B.
/// - **Credentialless:** `decide_org`, else own-run self-approval — Phase B.
pub fn authorize_approval_decision(
    authority: &ApprovalAuthority,
    invoked_by_user_id: Option<Uuid>,
    principal_user_id: Option<Uuid>,
    principal_can_decide_org: bool,
) -> Result<(), ApprovalRefusal> {
    match authority {
        ApprovalAuthority::UserConnection { owner_user_id } => {
            let is_owner = principal_user_id == Some(*owner_user_id);
            let invoked_it = invoked_by_user_id == Some(*owner_user_id);
            if is_owner && invoked_it {
                Ok(())
            } else {
                Err(ApprovalRefusal::PersonalConnection {
                    owner_user_id: *owner_user_id,
                })
            }
        }
        ApprovalAuthority::Organization => {
            if principal_can_decide_org {
                Ok(())
            } else {
                Err(ApprovalRefusal::NeedsOrg)
            }
        }
        ApprovalAuthority::Credentialless => {
            if principal_can_decide_org {
                return Ok(());
            }
            let own_run = principal_user_id.is_some() && invoked_by_user_id == principal_user_id;
            if own_run {
                Ok(())
            } else {
                Err(ApprovalRefusal::NeedsOwnOrOrg)
            }
        }
    }
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

    // ── Approval authority classification + decision (Phase C, DB-free) ──────

    fn conn_facts(owner_type: &str, owner: Option<Uuid>) -> ApprovalBindingFacts {
        ApprovalBindingFacts {
            authority_kind: "connection".into(),
            owner_type: Some(owner_type.into()),
            owner_user_id: owner,
        }
    }

    #[test]
    fn classify_maps_tool_and_binding_to_authority() {
        let alice = Uuid::now_v7();
        // Non-mcp built-ins are credentialless regardless of any binding.
        assert_eq!(
            classify_approval_authority("Bash", None),
            ApprovalAuthority::Credentialless
        );
        // An mcp tool with no binding is a legacy brokered call → org (Phase B).
        assert_eq!(
            classify_approval_authority("mcp__github__create_issue", None),
            ApprovalAuthority::Organization
        );
        // An mcp tool bound to a user connection → that owner's personal authority.
        assert_eq!(
            classify_approval_authority(
                "mcp__github__create_issue",
                Some(&conn_facts("user", Some(alice)))
            ),
            ApprovalAuthority::UserConnection {
                owner_user_id: alice
            }
        );
        // An mcp tool bound to an org connection → org.
        assert_eq!(
            classify_approval_authority(
                "mcp__github__create_issue",
                Some(&conn_facts("organization", None))
            ),
            ApprovalAuthority::Organization
        );
        // A subscription_secret mcp binding (or a corrupt user binding missing
        // its owner id) fails closed to org.
        let sub_secret = ApprovalBindingFacts {
            authority_kind: "subscription_secret".into(),
            owner_type: None,
            owner_user_id: None,
        };
        assert_eq!(
            classify_approval_authority("mcp__x__y", Some(&sub_secret)),
            ApprovalAuthority::Organization
        );
        assert_eq!(
            classify_approval_authority("mcp__x__y", Some(&conn_facts("user", None))),
            ApprovalAuthority::Organization
        );
    }

    #[test]
    fn personal_connection_decidable_only_by_its_owner_who_invoked() {
        let alice = Uuid::now_v7();
        let bob = Uuid::now_v7();
        let authority = ApprovalAuthority::UserConnection {
            owner_user_id: alice,
        };
        // Alice (owner) on her own run → ok.
        assert!(authorize_approval_decision(&authority, Some(alice), Some(alice), false).is_ok());
        // Bob, even as decide_org (admin/owner), is refused under Alice's connection.
        assert_eq!(
            authorize_approval_decision(&authority, Some(alice), Some(bob), true),
            Err(ApprovalRefusal::PersonalConnection {
                owner_user_id: alice
            })
        );
        // The operator (no user identity) is refused too.
        assert_eq!(
            authorize_approval_decision(&authority, Some(alice), None, true),
            Err(ApprovalRefusal::PersonalConnection {
                owner_user_id: alice
            })
        );
        // Owner but a run she did NOT invoke → refused (both must hold).
        assert_eq!(
            authorize_approval_decision(&authority, Some(bob), Some(alice), false),
            Err(ApprovalRefusal::PersonalConnection {
                owner_user_id: alice
            })
        );
    }

    #[test]
    fn org_authority_needs_decide_org() {
        let mine = Uuid::now_v7();
        let a = ApprovalAuthority::Organization;
        // decide_org holder (operator / approver / admin / owner) → ok.
        assert!(authorize_approval_decision(&a, Some(mine), Some(mine), true).is_ok());
        // A plain member who invoked the run still cannot decide an org call.
        assert_eq!(
            authorize_approval_decision(&a, Some(mine), Some(mine), false),
            Err(ApprovalRefusal::NeedsOrg)
        );
    }

    #[test]
    fn credentialless_allows_own_run_or_decide_org() {
        let mine = Uuid::now_v7();
        let other = Uuid::now_v7();
        let a = ApprovalAuthority::Credentialless;
        // Member self-approves a credentialless call on their own run.
        assert!(authorize_approval_decision(&a, Some(mine), Some(mine), false).is_ok());
        // Someone else's run, no decide_org → refused.
        assert_eq!(
            authorize_approval_decision(&a, Some(other), Some(mine), false),
            Err(ApprovalRefusal::NeedsOwnOrOrg)
        );
        // decide_org holder decides any credentialless call.
        assert!(authorize_approval_decision(&a, Some(other), Some(mine), true).is_ok());
        // Operator (no user id) decides via decide_org.
        assert!(authorize_approval_decision(&a, Some(other), None, true).is_ok());
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
