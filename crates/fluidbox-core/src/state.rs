use serde::{Deserialize, Serialize};

/// Session lifecycle. `initializing` is the post-startup init phase: the
/// sandbox is up but the agent has not started — the orchestrator
/// materializes the workspace there, so init failures cost zero model spend.
///
/// `cancelling` and `finalizing` are the wind-down states (design
/// 2026-07-15, Phase 0): real, persisted, visible in the audit trail.
/// `cancelling` = waiting for the runner to quiesce (heartbeat-response
/// signal, 30 s deadline); `finalizing` = terminal artifact collection in
/// progress. EVERY terminal path rides them — the transition matrix has no
/// direct active→terminal edge, which is what makes "collect before
/// terminal" structural rather than disciplinary.
///
/// `awaiting_authorization` is the PRE-PROVISIONING pause (network grants):
/// the RunSpec is frozen and a human must authorize its network grant before
/// any sandbox exists. It is deliberately NOT a reuse of `awaiting_approval` —
/// that variant already has a `→ Running` edge, so reusing it would open
/// `Created → AwaitingApproval → Running` and skip init entirely.
/// `no_skipping_init` only checks DIRECT edges and would miss that transitive
/// bypass, which is exactly why this is its own variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Created,
    /// Frozen, parked, and waiting on a human to authorize the network grant.
    /// No sandbox, no runner, no tokens — nothing to reap, and nothing that
    /// can spend. The approval TTL is its only reaper.
    AwaitingAuthorization,
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
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::AwaitingAuthorization => "awaiting_authorization",
            Self::Provisioning => "provisioning",
            Self::Initializing => "initializing",
            Self::Running => "running",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Cancelling => "cancelling",
            Self::Finalizing => "finalizing",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::BudgetExceeded => "budget_exceeded",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "created" => Self::Created,
            "awaiting_authorization" => Self::AwaitingAuthorization,
            "provisioning" => Self::Provisioning,
            "initializing" => Self::Initializing,
            "running" => Self::Running,
            "awaiting_approval" => Self::AwaitingApproval,
            "cancelling" => Self::Cancelling,
            "finalizing" => Self::Finalizing,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "budget_exceeded" => Self::BudgetExceeded,
            _ => return None,
        })
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::BudgetExceeded
        )
    }

    /// On the way out: the durable finalizer owns the session. The facade,
    /// permission gate, broker, and token renew all refuse new work here —
    /// same as terminal, but the terminal transition (and its delivery
    /// enqueue) hasn't happened yet because collection hasn't finished.
    pub fn is_winding_down(&self) -> bool {
        matches!(self, Self::Cancelling | Self::Finalizing)
    }

    /// Accepting new agent work (facade calls, tool decisions, renewals).
    ///
    /// Written as a WILDCARD-FREE match, not the old
    /// `!is_terminal() && !is_winding_down()`. That negative form silently
    /// answered `true` for any variant nobody had classified — so a new state
    /// defaulted to "yes, this may spend money and call tools". Now a new
    /// variant fails to compile here and its author has to decide.
    /// `awaiting_authorization` is the first beneficiary: it is neither
    /// terminal nor winding down, so the old form would have admitted work for
    /// a session that has no sandbox at all.
    pub fn accepts_work(&self) -> bool {
        use SessionStatus::*;
        match self {
            Created | Provisioning | Initializing | Running | AwaitingApproval => true,
            // Parked before provisioning: no runner exists to do work, and no
            // token has been minted that could ask for any.
            AwaitingAuthorization => false,
            Cancelling | Finalizing => false,
            Completed | Failed | Cancelled | BudgetExceeded => false,
        }
    }

    /// The server is the single status writer; every write goes through this.
    pub fn can_transition_to(&self, next: SessionStatus) -> bool {
        use SessionStatus::*;
        if self.is_terminal() {
            return false;
        }
        matches!(
            (self, next),
            (Created, Provisioning)
                // The pre-provisioning authorization pause. There is
                // deliberately NO (AwaitingAuthorization, Running) edge: the
                // released session provisions like any other, so init can
                // never be skipped.
                | (Created, AwaitingAuthorization)
                | (AwaitingAuthorization, Provisioning)
                | (Provisioning, Initializing)
                | (Initializing, Running)
                | (Running, AwaitingApproval)
                | (AwaitingApproval, Running)
                // Wind-down entry: any active state can begin cancelling or
                // finalizing (crash recovery must be able to finalize a
                // session wherever the control plane left it). A parked
                // session winds down the same way when its grant is denied,
                // expires, or the run is cancelled.
                | (
                    Created
                        | AwaitingAuthorization
                        | Provisioning
                        | Initializing
                        | Running
                        | AwaitingApproval,
                    Cancelling | Finalizing,
                )
                // Quiesce resolved (runner stopped or deadline passed) →
                // collection phase.
                | (Cancelling, Finalizing)
                // Escape hatch: a finalizer that exhausts its retries can
                // terminalize from either wind-down state.
                | (Cancelling, Failed)
                // Collection done (or explicitly recorded missing) → the ONLY
                // door to terminal states. Delivery enqueue rides terminal
                // entry, so it structurally cannot race the artifact.
                | (Finalizing, Completed | Failed | Cancelled | BudgetExceeded)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::SessionStatus::{self, *};

    const ACTIVE: [SessionStatus; 6] = [
        Created,
        AwaitingAuthorization,
        Provisioning,
        Initializing,
        Running,
        AwaitingApproval,
    ];
    const TERMINAL: [SessionStatus; 4] = [Completed, Failed, Cancelled, BudgetExceeded];

    #[test]
    fn happy_path_transitions() {
        assert!(Created.can_transition_to(Provisioning));
        assert!(Provisioning.can_transition_to(Initializing));
        assert!(Initializing.can_transition_to(Running));
        assert!(Running.can_transition_to(AwaitingApproval));
        assert!(AwaitingApproval.can_transition_to(Running));
        assert!(Running.can_transition_to(Finalizing));
        assert!(Finalizing.can_transition_to(Completed));
    }

    #[test]
    fn terminal_states_are_sticky() {
        for s in TERMINAL {
            assert!(!s.can_transition_to(Running));
            assert!(!s.can_transition_to(Failed));
            assert!(!s.can_transition_to(Finalizing));
        }
    }

    #[test]
    fn no_direct_terminal_entry() {
        // Collect-before-terminal is STRUCTURAL: the only way into a
        // terminal state is through `finalizing` (or `cancelling → failed`
        // for the give-up path). A code path that forgets collection cannot
        // reach terminal.
        for s in ACTIVE {
            for t in TERMINAL {
                assert!(
                    !s.can_transition_to(t),
                    "{s:?} must not reach {t:?} without finalizing"
                );
            }
        }
    }

    #[test]
    fn every_nonterminal_can_reach_failed() {
        // A crashed control plane must be able to fail a session wherever it
        // was left — via the wind-down path (≤2 hops).
        for s in ACTIVE {
            assert!(s.can_transition_to(Finalizing), "{s:?} must wind down");
        }
        assert!(Cancelling.can_transition_to(Failed));
        assert!(Cancelling.can_transition_to(Finalizing));
        assert!(Finalizing.can_transition_to(Failed));
    }

    #[test]
    fn cancel_rides_cancelling() {
        for s in ACTIVE {
            assert!(s.can_transition_to(Cancelling), "{s:?} must be cancellable");
        }
        // …but the terminal `cancelled` only lands after collection.
        assert!(!Cancelling.can_transition_to(Cancelled));
        assert!(Finalizing.can_transition_to(Cancelled));
    }

    #[test]
    fn winding_down_refuses_new_work() {
        for s in [Cancelling, Finalizing] {
            assert!(s.is_winding_down());
            assert!(!s.accepts_work());
            assert!(!s.is_terminal());
            assert!(!s.can_transition_to(Running));
            assert!(!s.can_transition_to(AwaitingApproval));
        }
        // "Active" and "accepts work" were once the same set. They are not
        // any more: `awaiting_authorization` is active (it is neither terminal
        // nor winding down, so the sweepers and concurrency counters correctly
        // treat it as a live run) yet accepts NO work, because it is parked
        // before any sandbox or token exists. Everything else still coincides.
        for s in ACTIVE {
            if s == AwaitingAuthorization {
                assert!(!s.accepts_work());
                continue;
            }
            assert!(s.accepts_work());
        }
        for s in TERMINAL {
            assert!(!s.accepts_work());
        }
    }

    #[test]
    fn no_skipping_init() {
        assert!(!Provisioning.can_transition_to(Running));
        assert!(!Created.can_transition_to(Running));
        // The authorization pause is why this variant exists rather than a
        // reuse of `awaiting_approval`: that one HAS a `→ Running` edge, so
        // reusing it would have opened `Created → … → Running`, and this test
        // — which only inspects DIRECT edges — would not have caught it.
        assert!(!AwaitingAuthorization.can_transition_to(Running));
        assert!(!AwaitingAuthorization.can_transition_to(Initializing));
        // A released grant provisions like any other run.
        assert!(Created.can_transition_to(AwaitingAuthorization));
        assert!(AwaitingAuthorization.can_transition_to(Provisioning));
    }

    #[test]
    fn the_authorization_pause_holds_no_work_and_no_sandbox() {
        // Parked BEFORE provisioning: nothing exists that could spend money or
        // call a tool. `accepts_work` is a wildcard-free match precisely so
        // this variant had to be classified rather than defaulting to `true`.
        assert!(!AwaitingAuthorization.accepts_work());
        assert!(!AwaitingAuthorization.is_terminal());
        assert!(!AwaitingAuthorization.is_winding_down());
        // It can always be wound down — a denied or expired grant, or a cancel.
        assert!(AwaitingAuthorization.can_transition_to(Cancelling));
        assert!(AwaitingAuthorization.can_transition_to(Finalizing));
    }

    #[test]
    fn roundtrip_strings() {
        for s in [
            Created,
            AwaitingAuthorization,
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
        ] {
            assert_eq!(super::SessionStatus::parse(s.as_str()), Some(s));
        }
    }
}
