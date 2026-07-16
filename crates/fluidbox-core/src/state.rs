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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
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
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
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
    pub fn accepts_work(&self) -> bool {
        !self.is_terminal() && !self.is_winding_down()
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
                | (Provisioning, Initializing)
                | (Initializing, Running)
                | (Running, AwaitingApproval)
                | (AwaitingApproval, Running)
                // Wind-down entry: any active state can begin cancelling or
                // finalizing (crash recovery must be able to finalize a
                // session wherever the control plane left it).
                | (
                    Created | Provisioning | Initializing | Running | AwaitingApproval,
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

    const ACTIVE: [SessionStatus; 5] = [
        Created,
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
        for s in ACTIVE {
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
    }

    #[test]
    fn roundtrip_strings() {
        for s in [
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
        ] {
            assert_eq!(super::SessionStatus::parse(s.as_str()), Some(s));
        }
    }
}
