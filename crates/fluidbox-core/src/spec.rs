use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Who answers the permission question: a waiting human, or the policy's
/// pre-decided fallback. Autonomy never changes *whether* it is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Autonomy {
    #[default]
    Supervised,
    Autonomous,
}

impl Autonomy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Supervised => "supervised",
            Self::Autonomous => "autonomous",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    #[default]
    Trusted,
    ReadOnly,
}

/// Budgets frozen into the RunSpec. `max_wall_clock_secs: None` means the
/// run opted out of a wall-clock cap (long-running agents) — the other caps
/// then carry the weight.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Budgets {
    pub max_wall_clock_secs: Option<u64>,
    pub max_tokens: Option<u64>,
    pub max_cost_usd: Option<f64>,
    pub max_tool_calls: Option<u64>,
}

impl Default for Budgets {
    /// Last-resort fallback only — the seed policy (`policies/default.yaml`,
    /// pinned by `seed_policy_semantics`) is the source of truth for real
    /// deployments; keep these numbers matching it.
    fn default() -> Self {
        Self {
            max_wall_clock_secs: Some(1800),
            max_tokens: Some(1_000_000),
            max_cost_usd: Some(2.5),
            max_tool_calls: Some(100),
        }
    }
}

impl Budgets {
    /// Overlay: any cap set in `tighter` replaces ours only if it is
    /// actually tighter (a run may narrow its agent's budgets, never widen).
    pub fn tightened_by(&self, tighter: &Budgets) -> Budgets {
        fn min_opt<T: PartialOrd + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
            match (a, b) {
                (Some(x), Some(y)) => Some(if y < x { y } else { x }),
                (Some(x), None) => Some(x),
                (None, Some(y)) => Some(y),
                (None, None) => None,
            }
        }
        Budgets {
            max_wall_clock_secs: min_opt(self.max_wall_clock_secs, tighter.max_wall_clock_secs),
            max_tokens: min_opt(self.max_tokens, tighter.max_tokens),
            max_cost_usd: min_opt(self.max_cost_usd, tighter.max_cost_usd),
            max_tool_calls: min_opt(self.max_tool_calls, tighter.max_tool_calls),
        }
    }
}

/// Where the workspace comes from. MVP: a local path (copied — the agent can
/// never touch the original) or a git URL fetched control-plane-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepoSource {
    LocalPath { path: String },
    GitUrl { url: String, r#ref: Option<String> },
    None,
}

/// The immutable photograph of everything a run is allowed to be.
/// Frozen at session creation; audit rows point here forever.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSpec {
    pub agent_id: Uuid,
    pub agent_revision_id: Uuid,
    pub agent_name: String,
    pub harness: String,
    pub runner_image: String,
    pub model: String,
    pub system_prompt: Option<String>,
    pub task: String,
    pub repo: RepoSource,
    pub autonomy: Autonomy,
    pub trust_tier: TrustTier,
    pub budgets: Budgets,
    pub policy_id: Uuid,
    pub policy_version: i32,
    /// Full parsed policy snapshot — the run is governed by this exact
    /// document even if the policy row is edited later.
    pub policy_snapshot: crate::policy::Policy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_only_tighten() {
        let base = Budgets::default();
        let run = Budgets {
            max_wall_clock_secs: Some(60),
            max_tokens: None,
            max_cost_usd: Some(50.0), // wider — must NOT take effect
            max_tool_calls: Some(2),
        };
        let eff = base.tightened_by(&run);
        assert_eq!(eff.max_wall_clock_secs, Some(60));
        assert_eq!(eff.max_tokens, Some(1_000_000));
        assert_eq!(eff.max_cost_usd, Some(2.5));
        assert_eq!(eff.max_tool_calls, Some(2));
    }

    #[test]
    fn unlimited_wall_clock_survives_when_both_none() {
        let a = Budgets {
            max_wall_clock_secs: None,
            ..Default::default()
        };
        let b = Budgets {
            max_wall_clock_secs: None,
            ..Default::default()
        };
        assert_eq!(a.tightened_by(&b).max_wall_clock_secs, None);
    }
}
