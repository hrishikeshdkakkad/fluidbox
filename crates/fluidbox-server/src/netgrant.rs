//! Server-side network-grant resolution, the authorization pause, and
//! revocation.
//!
//! The pure order lives in `fluidbox_core::network`; this module is the wiring:
//! it assembles the request from the agent revision plus any downstream
//! narrowing, asks the domain for a verdict, and then takes one of three tails
//! — freeze-and-spawn, freeze-and-park, or refuse.
//!
//! **Freeze, then approve.** The grant is computed and frozen at session
//! creation; the approval gates whether provisioning proceeds. That ordering is
//! the only one consistent with RunSpec immutability, and it gives the approver
//! a stable digest to consent to (`approvals.input_digest == grant_digest`). A
//! policy edit between freeze and decision therefore cannot mutate the pending
//! grant — correct, but it means a slow approval could otherwise activate stale
//! authority, so [`reverify_before_release`] re-checks digest, expiry and policy
//! before provisioning is released. If the newer policy would forbid the run it
//! is DENIED and must be recreated, never silently substituted.

use crate::state::AppState;
use fluidbox_core::network::{
    resolve_network_grant, GrantResolution, NetworkGrant, NetworkRequest, ResolutionContext,
};
use fluidbox_db::network_grants::{NetworkGrantRow, NewNetworkGrant};
use fluidbox_db::TenantScope;
use uuid::Uuid;

/// The synthetic approval identity a parked grant uses. It rides the ordinary
/// approvals machinery — `register_tool_intent` → `promote_intent_to_pending` —
/// so idempotency comes free from `unique (session_id, tool_call_id)` and the
/// existing expiry worker reaps an unanswered pause with no new timer.
///
/// It is NOT a tool call and never reaches the permission gate: nothing in the
/// gate path can produce this `tool_call_id`, because a run parked here has no
/// sandbox to make tool calls from.
pub const GRANT_TOOL_CALL_ID: &str = "network-grant";
pub const GRANT_TOOL: &str = "network.grant";

/// Assemble the effective request: what the revision DECLARES, narrowed by any
/// downstream override. Narrowing is remove-only (`NetworkRequest::narrowed_by`),
/// so an override can shrink the mode, drop targets, or shorten the lifetime —
/// never the reverse.
///
/// A revision with no declaration is offline, which is what makes every
/// pre-existing agent keep its current behaviour exactly.
pub fn effective_request(
    revision_declaration: Option<&serde_json::Value>,
    per_run_override: Option<&NetworkRequest>,
) -> Result<NetworkRequest, String> {
    let declared = match revision_declaration {
        Some(v) if !v.is_null() => serde_json::from_value::<NetworkRequest>(v.clone())
            .map_err(|e| format!("agent revision has an unreadable network declaration: {e}"))?,
        _ => NetworkRequest::offline(),
    };
    Ok(declared.narrowed_by(per_run_override))
}

/// The row payload for a resolved grant, plus whether it must park.
#[derive(Debug)]
pub struct ResolvedGrant {
    pub grant: NetworkGrant,
    pub row: NewNetworkGrant,
    /// True when a human must authorize before provisioning.
    pub needs_authorization: bool,
}

/// Resolve, and shape the result for persistence. `Err` is the refusal tail —
/// the caller turns it into a 422 with the enumerated reason, having created
/// nothing.
pub fn resolve_for_run(
    request: &NetworkRequest,
    policy: &fluidbox_core::policy::Policy,
    ctx: &ResolutionContext,
) -> Result<ResolvedGrant, fluidbox_core::network::DenialReason> {
    let (grant, needs_authorization) = match resolve_network_grant(request, &policy.network, ctx) {
        GrantResolution::Active(g) => (g, false),
        GrantResolution::NeedsApproval(g) => (g, true),
        GrantResolution::Denied(reason) => return Err(reason),
    };
    let digest = grant.digest();
    Ok(ResolvedGrant {
        row: NewNetworkGrant {
            id: Uuid::now_v7(),
            mode: grant.mode.as_str().to_string(),
            grant_doc: serde_json::to_value(&grant).unwrap_or(serde_json::Value::Null),
            grant_digest: digest,
            policy_digest: grant.policy_digest.clone(),
            status: if needs_authorization {
                "pending".into()
            } else {
                "active".into()
            },
            expires_at: grant.expires_at,
            approval_id: None,
        },
        grant,
        needs_authorization,
    })
}

/// Park a run for network authorization: register the approval, promote it to
/// pending, and move the session to `awaiting_authorization`.
///
/// The approval rides the ordinary machinery with a synthetic
/// [`GRANT_TOOL_CALL_ID`], so `unique (session_id, tool_call_id)` gives
/// idempotency for free and the existing approval-expiry worker reaps an
/// unanswered pause without a new timer.
///
/// Ordering is deliberate: the approval is created and promoted BEFORE the
/// session moves. A crash between them leaves a `created` session with a
/// `pending` grant — which the gate worker and the orchestrator both treat as
/// not-yet-authorized, so the failure is a stalled run, never an unauthorized
/// one.
pub async fn park_for_authorization(
    state: &AppState,
    scope: TenantScope,
    session_id: Uuid,
    resolved: &ResolvedGrant,
    ttl_secs: u64,
) -> Result<(), crate::error::ApiError> {
    let summary = format!(
        "network access: {} to {}",
        resolved.grant.mode.as_str(),
        if resolved.grant.targets.is_empty() {
            "everything the deny wall permits".to_string()
        } else {
            resolved
                .grant
                .targets
                .iter()
                .map(|t| t.describe())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    let (approval, _created) = fluidbox_db::register_tool_intent(
        &state.pool,
        scope,
        session_id,
        GRANT_TOOL_CALL_ID,
        GRANT_TOOL,
        &summary,
        // The consent anchor: what the approver sees IS the digest that must
        // still describe the grant when provisioning is released.
        &resolved.row.grant_digest,
    )
    .await?;
    fluidbox_db::promote_intent_to_pending(
        &state.pool,
        scope,
        approval.id,
        Some("network"),
        "once",
        GRANT_TOOL,
        // Clamped before the cast: `default_ttl_secs` is an unbounded u64 and
        // `u64::MAX as i64` is -1, which would mint an already-expired approval
        // instead of a long one — turning "wait for a human" into "refuse
        // immediately".
        ttl_secs.min(MAX_APPROVAL_TTL_SECS) as i64,
    )
    .await?;
    fluidbox_db::network_grants::attach_grant_approval(&state.pool, scope, session_id, approval.id)
        .await?;
    fluidbox_db::transition_session(
        &state.pool,
        scope,
        session_id,
        fluidbox_core::state::SessionStatus::AwaitingAuthorization,
        Some("awaiting network grant authorization"),
    )
    .await?;
    Ok(())
}

/// Why a parked grant could not be released. Enumerated because these strings
/// are ledger reasons and metric label values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseRefusal {
    /// The stored grant is not the one that was authorized.
    DigestMismatch,
    /// It lapsed while waiting for a human.
    Expired,
    /// The governing policy changed, and re-resolution no longer permits it.
    PolicyMoved { code: &'static str },
    /// The grant row is gone, or in a status that cannot be released.
    NotPending,
    /// The schema of the stored grant is from a future version.
    UnknownSchema,
}

impl ReleaseRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::DigestMismatch => "grant_digest_mismatch",
            Self::Expired => "grant_expired",
            Self::PolicyMoved { .. } => "policy_moved",
            Self::NotPending => "grant_not_pending",
            Self::UnknownSchema => "grant_schema_unsupported",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::DigestMismatch => "the stored network grant does not match the digest that \
                 was authorized; the run must be recreated"
                .into(),
            Self::Expired => {
                "the network grant expired before it was authorized; the run must be recreated"
                    .into()
            }
            Self::PolicyMoved { code } => format!(
                "the governing policy changed while this grant awaited authorization and no \
                 longer permits it ({code}); the run must be recreated"
            ),
            Self::NotPending => "the network grant is no longer awaiting authorization".into(),
            Self::UnknownSchema => {
                "the stored network grant uses an unsupported schema version".into()
            }
        }
    }
}

/// Re-verify a parked grant against the world as it is NOW, immediately before
/// provisioning is released.
///
/// The frozen grant is authoritative for WHAT was authorized; this answers
/// whether that authorization is still safe to act on. It re-runs resolution
/// against the CURRENT policy: if the newer policy would forbid the run, the
/// grant is denied outright rather than silently substituted with something
/// narrower the approver never saw.
pub fn reverify_before_release(
    row: &NetworkGrantRow,
    current_policy: &fluidbox_core::policy::Policy,
    request: &NetworkRequest,
    ctx: &ResolutionContext,
) -> Result<NetworkGrant, ReleaseRefusal> {
    if row.status != "pending" {
        return Err(ReleaseRefusal::NotPending);
    }
    let grant: NetworkGrant =
        serde_json::from_value(row.grant_doc.clone()).map_err(|_| ReleaseRefusal::UnknownSchema)?;
    if !grant.schema_supported() {
        return Err(ReleaseRefusal::UnknownSchema);
    }
    // The digest is the consent anchor: it must still describe the stored grant.
    if grant.digest() != row.grant_digest {
        return Err(ReleaseRefusal::DigestMismatch);
    }
    if grant.is_expired(ctx.now) {
        return Err(ReleaseRefusal::Expired);
    }
    // …and it must still OUTLIVE the run it is about to govern. Resolution
    // guaranteed that at freeze time, but an approval pause spends the grant's
    // absolute lifetime without spending the run's budget — so a grant sized
    // exactly to the run can be released with minutes left and be swept away
    // mid-flight. Refusing here is the same fail-closed choice resolution
    // makes: never issue authority that will lapse under the work.
    if let (Some(exp), Some(wall)) = (grant.expires_at, ctx.run_wall_clock_secs) {
        let remaining = (exp - ctx.now).num_seconds();
        if remaining < wall as i64 {
            return Err(ReleaseRefusal::Expired);
        }
    }
    // Re-resolve against the CURRENT policy. An unchanged policy short-circuits
    // on the digest; a changed one has to produce at least as much authority as
    // was authorized, or the run is refused.
    if current_policy.network.digest() != grant.policy_digest {
        match resolve_network_grant(request, &current_policy.network, ctx) {
            GrantResolution::Denied(reason) => {
                return Err(ReleaseRefusal::PolicyMoved {
                    code: reason.code(),
                })
            }
            GrantResolution::Active(now_grant) | GrantResolution::NeedsApproval(now_grant) => {
                // The newer policy must still permit AT LEAST what was
                // authorized. A narrower one is a refusal, not a downgrade:
                // silently running with less network than the approver saw is
                // the failure mode nobody can debug.
                // Time is an authority dimension too. A policy that cut
                // `max_grant_secs` while the run was parked permits LESS than
                // was authorized, even when the mode and targets are identical
                // — activating the original grant would hand it the full
                // original lifetime under a policy that no longer allows it.
                let now_shorter = match (now_grant.expires_at, grant.expires_at) {
                    (Some(now_exp), Some(frozen_exp)) => now_exp < frozen_exp,
                    // A policy that would no longer bound the grant at all is
                    // not narrower; a frozen grant without an expiry is
                    // malformed and `is_expired` already refused it above.
                    _ => false,
                };
                // A deny ADDED while the run was parked permits less than was
                // authorized, and the frozen grant carries the OLD deny set —
                // so activating it would run under denies the operator has
                // since revoked their consent to.
                // "Grew" means the current policy denies something the frozen one
                // did NOT — judged by COVERAGE, not exact equality. Equality made
                // a strictly NARROWER replacement (`203.0.113.0/24` →
                // `203.0.113.7/32`) read as growth and refuse a release that was
                // plainly safe; case and port-splitting differences did the same.
                let denies_grew = now_grant
                    .denied
                    .iter()
                    .any(|d| !grant.denied.iter().any(|frozen| frozen.covers(d)));
                if now_grant.mode < grant.mode
                    || now_shorter
                    || denies_grew
                    || !grant.targets.iter().all(|t| {
                        now_grant
                            .targets
                            .iter()
                            .any(|allowed| allowed.covers(t) || allowed == t)
                    })
                {
                    return Err(ReleaseRefusal::PolicyMoved {
                        code: "narrowed_by_policy_edit",
                    });
                }
            }
        }
    }
    Ok(grant)
}

/// How many consecutive re-verification failures turn a parked run into a
/// refusal. Sized so a transient database blip (the gate ticks every 2 s) never
/// reaches it, while a permanent failure resolves in about a minute instead of
/// never.
const REVERIFY_MAX_ATTEMPTS: u32 = 30;

/// Ceiling on an authorization pause, applied before any `as i64` cast. A week
/// is far beyond any sensible approval window and keeps the arithmetic in range.
const MAX_APPROVAL_TTL_SECS: u64 = 7 * 24 * 3600;

/// A human authorized the grant: re-verify, activate, and release provisioning.
///
/// Everything here is CAS-guarded, so several replicas waking on the same
/// NOTIFY converge on one activation and one spawn. A re-verification failure
/// DENIES rather than releasing — stale authority is refused, never narrowed
/// and run anyway.
pub async fn release_authorized_grant(state: &AppState, scope: TenantScope, session_id: Uuid) {
    let Ok(Some(row)) =
        fluidbox_db::network_grants::get_network_grant(&state.pool, scope, session_id).await
    else {
        return;
    };
    // Re-resolve against the CURRENT policy and the CURRENT clock.
    let refusal = match reverify_context(state, scope, session_id, &row).await {
        Ok(None) => None,
        Ok(Some(r)) => Some(r),
        // A failure loading the world leaves the run parked and the next tick
        // retries — never release on a read we could not complete. But a
        // PERMANENT failure (a deleted policy, content that no longer parses)
        // would retry every two seconds forever, leaving an approved run wedged
        // with nothing in the audit trail explaining why. After a bounded
        // number of attempts it becomes a refusal, which is visible, terminal,
        // and still fail-closed.
        Err(e) => {
            let attempts = state.netgrant_reverify_failures.bump(session_id);
            tracing::warn!(
                "network grant re-verification for {session_id} failed (attempt {attempts}): {e}"
            );
            if attempts >= REVERIFY_MAX_ATTEMPTS {
                state.netgrant_reverify_failures.clear(session_id);
                refuse_parked_grant(
                    state,
                    scope,
                    session_id,
                    &format!(
                        "the governing policy could not be re-read after {attempts} attempts \
                         ({e}); refusing rather than leaving the run parked indefinitely"
                    ),
                )
                .await;
            }
            return;
        }
    };
    // The re-verification completed, whatever it decided — so the failure streak
    // is over. Clearing here (not only at the threshold) is what makes the
    // counter CONSECUTIVE rather than cumulative, and what stops it retaining an
    // entry for every session that ever had one transient blip.
    state.netgrant_reverify_failures.clear(session_id);
    if let Some(refusal) = refusal {
        state.metrics.network_grant_refusals.inc(refusal.code());
        refuse_parked_grant(state, scope, session_id, &refusal.message()).await;
        return;
    }
    match fluidbox_db::network_grants::activate_network_grant(&state.pool, scope, session_id).await
    {
        // We won the CAS: ours is the one spawn.
        //
        // The session is deliberately left in `awaiting_authorization` here:
        // `run()` owns the move to `provisioning` (the state machine has an
        // `AwaitingAuthorization → Provisioning` edge for exactly this), so
        // there is ONE writer of that transition. Doing it here as well would
        // make `run()`'s own transition lose the race against us and fail the
        // launch — which is precisely what it did before this comment existed.
        //
        // If the process dies between the CAS and the spawn, the grant is
        // active but nothing is running; the gate worker's scan covers that
        // window by re-spawning any parked session whose grant is already
        // active.
        Ok(Some(_)) => {
            state.metrics.network_grants.inc("active");
            if state.cfg.queueing_enabled() {
                // Authorization first, capacity second (design 2026-08-23
                // §4.3): the released run takes a queue slot like any other.
                // The alternative — letting an authorized run jump the queue —
                // would make the cap waivable by grant type and produce real
                // overshoot. The human latency has already been absorbed, and
                // the wait clock (`queued_at`) only starts here, so nothing
                // that waited on a person is charged for that wait.
                //
                // `run()`'s own grant gate still re-verifies authority at
                // provision time however long the queue wait was — that check
                // is deliberately independent of how the session got there.
                crate::orchestrator::transition(
                    state,
                    scope,
                    session_id,
                    fluidbox_core::state::SessionStatus::Queued,
                    Some("network grant authorized; waiting for a capacity slot"),
                )
                .await;
            } else {
                crate::orchestrator::spawn_run(state.clone(), session_id);
            }
        }
        // Another replica won, or the grant is no longer pending.
        Ok(None) => {}
        Err(e) => tracing::warn!("activating network grant for {session_id} failed: {e}"),
    }
}

/// Load what re-verification needs (the run's frozen request and the CURRENT
/// policy) and run it. `Ok(None)` = releasable.
async fn reverify_context(
    state: &AppState,
    scope: TenantScope,
    session_id: Uuid,
    row: &NetworkGrantRow,
) -> Result<Option<ReleaseRefusal>, String> {
    let session = fluidbox_db::get_session(&state.pool, scope, session_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "session vanished".to_string())?;
    let spec: fluidbox_core::spec::RunSpec =
        serde_json::from_value(session.run_spec.clone()).map_err(|e| e.to_string())?;
    // The CURRENT policy, not the frozen snapshot: the point of the re-check is
    // to notice that the world moved.
    // The CURRENT policy, not the frozen snapshot: the point of the re-check is
    // to notice that the world moved. An unreadable or missing one REFUSES —
    // falling back to the frozen policy would release under exactly the stale
    // authority this check exists to catch, and during a rolling deploy an
    // older replica that cannot parse a newer policy schema would do so
    // routinely.
    let current: fluidbox_core::policy::Policy =
        match fluidbox_db::latest_policy_version(&state.pool, scope, spec.policy_id)
            .await
            .map_err(|e| e.to_string())?
        {
            Some(v) => serde_json::from_value(v.content)
                .map_err(|e| format!("the current policy could not be read: {e}"))?,
            None => return Err("the governing policy has no versions".into()),
        };
    // The request that produced this grant, reconstructed from the frozen
    // authority itself: re-resolution must be asked the same question the
    // approver answered.
    let request = NetworkRequest {
        mode: spec.network.mode,
        targets: spec.network.targets.clone(),
        duration_secs: None,
    };
    let ctx = ResolutionContext {
        now: chrono::Utc::now(),
        run_wall_clock_secs: spec.budgets.max_wall_clock_secs,
        has_brokered_surfaces: !spec.brokered.is_empty(),
        enforcement_available: state.provider.network_enforcer().supports_egress_grants(),
    };
    Ok(reverify_before_release(row, &current, &request, &ctx).err())
}

/// The grant was refused — by a human, by expiry, or by re-verification. Mark
/// it denied and wind the session down; it never gets a sandbox.
pub async fn refuse_parked_grant(
    state: &AppState,
    scope: TenantScope,
    session_id: Uuid,
    reason: &str,
) {
    // The CAS moves `pending → denied` and therefore matches NOTHING when the
    // row has already moved on. Losing it does NOT tell you what to do — the
    // committed state does, and the two failure modes are opposites:
    //
    //   * returning early on every loss STRANDED a parked run whose grant had
    //     been revoked underneath it (nothing ever wound it down);
    //   * winding down on every loss FAILED a run another replica had just
    //     legitimately activated.
    //
    // So the CAS decides who LEDGERS the refusal, and a re-read decides the
    // session's fate. `finalize_forced` is idempotent, so repeating it where it
    // IS warranted is harmless.
    let denied = match fluidbox_db::network_grants::deny_network_grant(
        &state.pool,
        scope,
        session_id,
        reason,
    )
    .await
    {
        Ok(Some(row)) => {
            state.metrics.network_grants.inc("denied");
            Some(row)
        }
        // We lost the CAS. That is NOT one situation, and treating it as one is
        // a bug in both directions:
        //
        //   * `denied`/`revoked` — the grant is resolved away, nothing will ever
        //     release this run, so it must be wound down or it is stranded.
        //   * `active` — ANOTHER REPLICA ACTIVATED IT and the run is legitimately
        //     proceeding. Winding it down here would durably fail a run that was
        //     authorized, which is exactly what a naive "always finalize" does
        //     under the supported multi-replica topology.
        //
        // So re-read and decide. A read failure leaves it alone: not knowing the
        // state is different from knowing it is resolved.
        Ok(None) => {
            match fluidbox_db::network_grants::get_network_grant(&state.pool, scope, session_id)
                .await
            {
                Ok(observed) => {
                    let status = observed.as_ref().map(|g| g.status.as_str());
                    if !fluidbox_db::network_grants::wind_down_on_cas_loss(status) {
                        tracing::debug!(
                            session_id = %session_id,
                            "another replica activated this grant; leaving the run alone"
                        );
                        return;
                    }
                    None
                }
                Err(e) => {
                    // Visible rather than only logged: a persistent failure here
                    // is safe (nothing destructive is guessed) but it does stall
                    // resolution, and an operator should be able to see it.
                    state
                        .metrics
                        .network_grant_refusals
                        .inc("cas_reread_failed");
                    tracing::warn!("re-reading the grant for {session_id} failed: {e}");
                    return;
                }
            }
        }
        Err(e) => {
            // A failed READ is different: we do not know the grant's state, so
            // leave the session alone and let the next tick retry rather than
            // finalizing a run that might still be releasable.
            tracing::warn!("denying network grant for {session_id} failed: {e}");
            return;
        }
    };
    // Ledger only on the CAS win, so several replicas cannot each append a
    // refusal for the same grant.
    if let Some(row) = denied {
        crate::ledger::record(
            state,
            scope,
            session_id,
            fluidbox_core::event::Actor::System,
            fluidbox_core::event::EventBody::NetworkGrantRevoked {
                // The mode that was REFUSED — the reason says it was a refusal.
                // Reporting "denied" here would lose the one fact the event
                // exists to record: how much authority was on the table.
                mode: row.mode,
                reason: reason.to_string(),
            },
        )
        .await;
    }
    // A parked run has no sandbox and no runner, so there is nothing to
    // quiesce or collect — but it still winds down through the ordinary
    // terminal path, so the audit trail and result delivery behave like every
    // other refused run.
    crate::orchestrator::finalize_forced(state, session_id, "failed", reason).await;
}

/// Tear down the DATAPATH objects for a run's grant, then mark the row revoked.
///
/// Order matters and it is the opposite of what the DB-first version did:
/// containment first, bookkeeping second. A row that says `revoked` while the
/// CiliumNetworkPolicy still exists is not revocation — the run keeps its
/// reach. A provider failure therefore does NOT mark the row revoked, so the
/// sweep retries rather than recording a teardown that did not happen.
pub async fn revoke_enforcement(
    state: &AppState,
    scope: TenantScope,
    session_id: Uuid,
    reason: &str,
) -> bool {
    if let Err(e) = state.provider.revoke_network_policy(session_id).await {
        tracing::warn!("tearing down the network policy for {session_id} failed: {e}");
        return false;
    }
    revoke(state, scope, session_id, reason).await;
    true
}

/// Surrender a run's network authority. Idempotent by CAS, so it is safe from
/// `finish_terminal_cleanup`, the abandon paths, and a retry of either.
///
/// Errors are logged and swallowed on purpose: revocation rides terminal
/// cleanup, which must never fail a run that has already finished. The
/// datapath objects are torn down independently by the provider (and backstopped
/// by the reconcile sweep), so a lost row update delays bookkeeping, not
/// containment.
pub async fn revoke(state: &AppState, scope: TenantScope, session_id: Uuid, reason: &str) {
    match fluidbox_db::network_grants::revoke_network_grant(&state.pool, scope, session_id, reason)
        .await
    {
        Ok(Some(row)) => {
            state.metrics.network_grants.inc("revoked");
            if row.grants_egress() {
                tracing::info!(
                    session_id = %session_id,
                    mode = %row.mode,
                    "network grant revoked ({reason})"
                );
            }
            crate::ledger::record(
                state,
                scope,
                session_id,
                fluidbox_core::event::Actor::System,
                fluidbox_core::event::EventBody::NetworkGrantRevoked {
                    mode: row.mode,
                    reason: reason.to_string(),
                },
            )
            .await;
        }
        // Already revoked (or never existed): nothing to do, and not an error.
        Ok(None) => {}
        Err(e) => tracing::warn!("revoking network grant for {session_id} failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fluidbox_core::network::{
        FqdnPattern, L4Protocol, NetworkGrantMode, NetworkPolicy, PortSpec, TargetRule,
    };

    fn dns(name: &str, port: u16) -> TargetRule {
        TargetRule::dns(
            FqdnPattern::Exact { name: name.into() },
            vec![PortSpec::single(port)],
            L4Protocol::Tcp,
        )
    }

    fn wild(suffix: &str, port: u16) -> TargetRule {
        TargetRule::dns(
            FqdnPattern::Wildcard {
                suffix: suffix.into(),
            },
            vec![PortSpec::single(port)],
            L4Protocol::Tcp,
        )
    }

    fn ctx() -> ResolutionContext {
        ResolutionContext {
            now: Utc::now(),
            run_wall_clock_secs: Some(1800),
            has_brokered_surfaces: false,
            enforcement_available: true,
        }
    }

    fn policy_with(network: NetworkPolicy) -> fluidbox_core::policy::Policy {
        let mut p = fluidbox_core::policy::Policy::parse_yaml("name: p").unwrap();
        p.network = network;
        p
    }

    fn open_policy() -> fluidbox_core::policy::Policy {
        policy_with(NetworkPolicy {
            max_mode: NetworkGrantMode::Approved,
            allow: vec![wild("example.com", 443)],
            ..Default::default()
        })
    }

    fn approved_request() -> NetworkRequest {
        NetworkRequest {
            mode: NetworkGrantMode::Approved,
            targets: vec![dns("api.example.com", 443)],
            duration_secs: None,
        }
    }

    fn pending_row(grant: &NetworkGrant) -> NetworkGrantRow {
        NetworkGrantRow {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            session_id: Uuid::now_v7(),
            mode: grant.mode.as_str().into(),
            grant_doc: serde_json::to_value(grant).unwrap(),
            grant_digest: grant.digest(),
            policy_digest: grant.policy_digest.clone(),
            status: "pending".into(),
            expires_at: grant.expires_at,
            approval_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            activated_at: None,
            revoked_at: None,
            status_reason: None,
        }
    }

    #[test]
    fn a_revision_without_a_declaration_is_offline() {
        // Every agent that predates governed networking keeps exactly today's
        // behaviour: no declaration, no authority.
        assert_eq!(
            effective_request(None, None).unwrap(),
            NetworkRequest::offline()
        );
        assert_eq!(
            effective_request(Some(&serde_json::Value::Null), None).unwrap(),
            NetworkRequest::offline()
        );
        // A malformed declaration REFUSES rather than defaulting — silently
        // reading a corrupt declaration as "offline" would hide the corruption,
        // and reading it as anything else would be worse.
        assert!(effective_request(Some(&serde_json::json!({"mode": "nonsense"})), None).is_err());
    }

    #[test]
    fn a_per_run_override_can_only_narrow_the_declaration() {
        let declared = serde_json::to_value(NetworkRequest {
            mode: NetworkGrantMode::Public,
            targets: vec![wild("example.com", 443)],
            duration_secs: Some(3600),
        })
        .unwrap();
        // Narrowing works…
        let narrowed = effective_request(
            Some(&declared),
            Some(&NetworkRequest {
                mode: NetworkGrantMode::Approved,
                targets: vec![dns("api.example.com", 443)],
                duration_secs: Some(600),
            }),
        )
        .unwrap();
        assert_eq!(narrowed.mode, NetworkGrantMode::Approved);
        assert_eq!(narrowed.targets, vec![dns("api.example.com", 443)]);
        assert_eq!(narrowed.duration_secs, Some(600));
        // …and a target the revision never declared is dropped, not honoured.
        let widened = effective_request(
            Some(&declared),
            Some(&NetworkRequest {
                mode: NetworkGrantMode::Public,
                targets: vec![dns("evil.test", 443)],
                duration_secs: Some(99_999),
            }),
        )
        .unwrap();
        assert!(widened.targets.is_empty());
        assert_eq!(widened.duration_secs, Some(3600));
    }

    #[test]
    fn resolution_shapes_the_row_for_each_tail() {
        // Freeze-and-spawn: active row, no approval.
        let r = resolve_for_run(&approved_request(), &open_policy(), &ctx()).unwrap();
        assert!(!r.needs_authorization);
        assert_eq!(r.row.status, "active");
        assert_eq!(r.row.mode, "approved");
        assert_eq!(r.row.grant_digest, r.grant.digest());
        assert!(r.row.expires_at.is_some());

        // Freeze-and-park: same authority, pending row.
        let gated = policy_with(NetworkPolicy {
            require_approval: true,
            ..open_policy().network
        });
        let p = resolve_for_run(&approved_request(), &gated, &ctx()).unwrap();
        assert!(p.needs_authorization);
        assert_eq!(p.row.status, "pending");
        assert_eq!(p.grant.mode, r.grant.mode);
        assert_eq!(p.grant.targets, r.grant.targets);

        // Refuse: nothing is created, and the reason is enumerated.
        let denied = resolve_for_run(
            &approved_request(),
            &policy_with(NetworkPolicy::default()),
            &ctx(),
        )
        .unwrap_err();
        assert_eq!(denied.code(), "mode_ceiling");
    }

    #[test]
    fn release_reverification_catches_everything_that_moved() {
        let policy = policy_with(NetworkPolicy {
            require_approval: true,
            ..open_policy().network
        });
        let resolved = resolve_for_run(&approved_request(), &policy, &ctx()).unwrap();
        let row = pending_row(&resolved.grant);

        // The unchanged world releases.
        assert!(reverify_before_release(&row, &policy, &approved_request(), &ctx()).is_ok());

        // A tampered grant document no longer matches its consent digest.
        let mut tampered = row.clone();
        let mut wider = resolved.grant.clone();
        wider.targets.push(dns("evil.test", 443));
        tampered.grant_doc = serde_json::to_value(&wider).unwrap();
        assert_eq!(
            reverify_before_release(&tampered, &policy, &approved_request(), &ctx()),
            Err(ReleaseRefusal::DigestMismatch)
        );

        // Lapsed while waiting for a human.
        let late = ResolutionContext {
            now: Utc::now() + Duration::seconds(100_000),
            ..ctx()
        };
        assert_eq!(
            reverify_before_release(&row, &policy, &approved_request(), &late),
            Err(ReleaseRefusal::Expired)
        );

        // The policy moved and now forbids the run outright.
        let closed = policy_with(NetworkPolicy {
            max_mode: NetworkGrantMode::Offline,
            ..Default::default()
        });
        assert!(matches!(
            reverify_before_release(&row, &closed, &approved_request(), &ctx()),
            Err(ReleaseRefusal::PolicyMoved { .. })
        ));

        // The policy moved and now permits LESS than was authorized: refuse
        // rather than silently substituting a narrower grant.
        let narrower = policy_with(NetworkPolicy {
            max_mode: NetworkGrantMode::Approved,
            allow: vec![dns("other.example.com", 443)],
            require_approval: true,
            ..Default::default()
        });
        assert!(matches!(
            reverify_before_release(&row, &narrower, &approved_request(), &ctx()),
            Err(ReleaseRefusal::PolicyMoved { .. })
        ));

        // A grant that is no longer pending cannot be released twice.
        let decided = NetworkGrantRow {
            status: "active".into(),
            ..row.clone()
        };
        assert_eq!(
            reverify_before_release(&decided, &policy, &approved_request(), &ctx()),
            Err(ReleaseRefusal::NotPending)
        );

        // A future schema is refused, not guessed at.
        let mut future_doc = serde_json::to_value(&resolved.grant).unwrap();
        future_doc["schema_version"] = serde_json::json!(999);
        let future = NetworkGrantRow {
            grant_doc: future_doc,
            ..row.clone()
        };
        assert_eq!(
            reverify_before_release(&future, &policy, &approved_request(), &ctx()),
            Err(ReleaseRefusal::UnknownSchema)
        );
    }

    /// A policy that cut the grant DURATION while the run was parked permits
    /// less than was authorized, even with an identical mode and targets.
    /// Release used to compare only mode and targets, so the original grant —
    /// with its full original lifetime — was activated under a policy that no
    /// longer allowed it.
    /// A deny ADDED while the run was parked permits less than was authorized,
    /// and the frozen grant carries the OLD deny set — so releasing it would
    /// run under denies the operator has since withdrawn consent to.
    #[test]
    fn a_policy_that_adds_a_deny_refuses_release() {
        let policy = policy_with(NetworkPolicy {
            require_approval: true,
            ..open_policy().network
        });
        let resolved = resolve_for_run(&approved_request(), &policy, &ctx()).unwrap();
        let row = pending_row(&resolved.grant);
        let with_new_deny = policy_with(NetworkPolicy {
            deny: vec![TargetRule::cidr(
                "203.0.113.0/24".parse().unwrap(),
                vec![PortSpec::single(443)],
                L4Protocol::Tcp,
            )],
            ..policy.network.clone()
        });
        assert!(matches!(
            reverify_before_release(&row, &with_new_deny, &approved_request(), &ctx()),
            Err(ReleaseRefusal::PolicyMoved { .. })
        ));
        // FALSE-GREEN GUARD: an unchanged deny set still releases.
        assert!(reverify_before_release(&row, &policy, &approved_request(), &ctx()).is_ok());
    }

    /// The grant must still OUTLIVE the run at release, not merely be unexpired.
    /// An approval pause spends the grant's absolute lifetime without spending
    /// the run's budget, so a grant sized exactly to the run can be released
    /// with minutes left and then be swept away mid-flight.
    #[test]
    fn a_grant_too_short_for_the_remaining_run_refuses_release() {
        let policy = policy_with(NetworkPolicy {
            require_approval: true,
            max_grant_secs: Some(1800),
            ..open_policy().network
        });
        let resolved = resolve_for_run(&approved_request(), &policy, &ctx()).unwrap();
        let row = pending_row(&resolved.grant);
        // A long pause: most of the grant's life is gone, but it has not lapsed.
        let late = ResolutionContext {
            now: ctx().now + Duration::seconds(1500),
            run_wall_clock_secs: Some(1800),
            ..ctx()
        };
        assert!(!resolved.grant.is_expired(late.now), "not yet expired…");
        assert_eq!(
            reverify_before_release(&row, &policy, &approved_request(), &late),
            Err(ReleaseRefusal::Expired),
            "…but too short to cover the run it would govern"
        );
        // A short pause still releases.
        let prompt = ResolutionContext {
            now: ctx().now + Duration::seconds(10),
            run_wall_clock_secs: Some(1500),
            ..ctx()
        };
        assert!(reverify_before_release(&row, &policy, &approved_request(), &prompt).is_ok());
    }

    #[test]
    fn a_policy_that_shortens_the_grant_refuses_release() {
        let policy = policy_with(NetworkPolicy {
            require_approval: true,
            max_grant_secs: Some(7200),
            ..open_policy().network
        });
        let resolved = resolve_for_run(&approved_request(), &policy, &ctx()).unwrap();
        let row = pending_row(&resolved.grant);
        // Same mode, same targets, far shorter ceiling.
        let shortened = policy_with(NetworkPolicy {
            max_grant_secs: Some(300),
            ..policy.network.clone()
        });
        assert!(matches!(
            reverify_before_release(&row, &shortened, &approved_request(), &ctx()),
            Err(ReleaseRefusal::PolicyMoved { .. })
        ));
        // FALSE-GREEN GUARD: a policy that LENGTHENS it still releases, so this
        // cannot pass by refusing every duration change.
        let lengthened = policy_with(NetworkPolicy {
            max_grant_secs: Some(99_999),
            ..policy.network.clone()
        });
        assert!(reverify_before_release(&row, &lengthened, &approved_request(), &ctx()).is_ok());
    }

    #[test]
    fn a_policy_edit_that_only_widens_still_releases() {
        // The re-check must not be a policy-digest equality test: an operator
        // who WIDENS the policy while a grant waits should not have the run
        // refused, because the authorized authority is still permitted.
        let policy = policy_with(NetworkPolicy {
            require_approval: true,
            ..open_policy().network
        });
        let resolved = resolve_for_run(&approved_request(), &policy, &ctx()).unwrap();
        let row = pending_row(&resolved.grant);
        let widened = policy_with(NetworkPolicy {
            max_mode: NetworkGrantMode::Public,
            allow: vec![wild("example.com", 443), dns("extra.test", 443)],
            require_approval: true,
            ..Default::default()
        });
        assert_ne!(widened.network.digest(), resolved.grant.policy_digest);
        assert!(reverify_before_release(&row, &widened, &approved_request(), &ctx()).is_ok());
    }

    #[test]
    fn release_refusal_codes_are_bounded_and_distinct() {
        let all = [
            ReleaseRefusal::DigestMismatch,
            ReleaseRefusal::Expired,
            ReleaseRefusal::PolicyMoved { code: "x" },
            ReleaseRefusal::NotPending,
            ReleaseRefusal::UnknownSchema,
        ];
        let codes: std::collections::BTreeSet<_> = all.iter().map(|r| r.code()).collect();
        assert_eq!(codes.len(), all.len());
        for r in &all {
            assert!(!r.message().is_empty());
        }
    }
}
