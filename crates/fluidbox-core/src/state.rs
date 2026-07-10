use serde::{Deserialize, Serialize};

/// Session lifecycle. `initializing` is the post-startup init phase: the
/// sandbox is up but the agent has not started — the orchestrator
/// materializes the workspace there, so init failures cost zero model spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Created,
    Provisioning,
    Initializing,
    Running,
    AwaitingApproval,
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

    /// The server is the single status writer; every write goes through this.
    pub fn can_transition_to(&self, next: SessionStatus) -> bool {
        use SessionStatus::*;
        if self.is_terminal() {
            return false;
        }
        matches!(
            (self, next),
            (Created, Provisioning)
                | (Created, Failed)
                | (Created, Cancelled)
                | (Provisioning, Initializing)
                | (Provisioning, Failed)
                | (Provisioning, Cancelled)
                | (Initializing, Running)
                | (Initializing, Failed)
                | (Initializing, Cancelled)
                | (Running, AwaitingApproval)
                | (Running, Completed)
                | (Running, Failed)
                | (Running, Cancelled)
                | (Running, BudgetExceeded)
                | (AwaitingApproval, Running)
                | (AwaitingApproval, Failed)
                | (AwaitingApproval, Cancelled)
                | (AwaitingApproval, BudgetExceeded)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::SessionStatus::*;

    #[test]
    fn happy_path_transitions() {
        assert!(Created.can_transition_to(Provisioning));
        assert!(Provisioning.can_transition_to(Initializing));
        assert!(Initializing.can_transition_to(Running));
        assert!(Running.can_transition_to(AwaitingApproval));
        assert!(AwaitingApproval.can_transition_to(Running));
        assert!(Running.can_transition_to(Completed));
    }

    #[test]
    fn terminal_states_are_sticky() {
        for s in [Completed, Failed, Cancelled, BudgetExceeded] {
            assert!(!s.can_transition_to(Running));
            assert!(!s.can_transition_to(Failed));
        }
    }

    #[test]
    fn any_nonterminal_state_can_fail() {
        // A crashed control plane must be able to fail a session wherever
        // it was left — Created included (the stalled-launch sweep).
        for s in [Created, Provisioning, Initializing, Running, AwaitingApproval] {
            assert!(s.can_transition_to(Failed), "{s:?} must be able to fail");
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
            Completed,
            Failed,
            Cancelled,
            BudgetExceeded,
        ] {
            assert_eq!(super::SessionStatus::parse(s.as_str()), Some(s));
        }
    }
}
