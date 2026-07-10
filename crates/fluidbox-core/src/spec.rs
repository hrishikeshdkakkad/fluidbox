use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

/// Why a run exists (design doc §3.4) — the provider-neutral envelope frozen
/// into the RunSpec and stored on `sessions.trigger`. Phase 2 uses
/// `manual` and `api`; `schedule`/`event` arrive with later phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InvocationKind {
    #[default]
    Manual,
    Api,
    Schedule,
    Event,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvocationContext {
    pub kind: InvocationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<Uuid>,
    /// Human-attributable origin, e.g. "trigger:<subscription name>".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Caller-supplied structured context (untrusted external text — it is
    /// context, never system instruction).
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub attributes: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<DateTime<Utc>>,
}

impl Default for InvocationContext {
    /// The default an old frozen RunSpec deserializes to: a manual run.
    fn default() -> Self {
        Self {
            kind: InvocationKind::Manual,
            subscription_id: None,
            actor: None,
            attributes: Value::Null,
            received_at: None,
        }
    }
}

/// Where a run's canonical result is published (design doc §3.7). The run's
/// artifacts and ledger stay in fluidbox either way; publication is
/// asynchronous and independently retryable. Secrets are NOT part of the
/// destination — the signing secret stays sealed on the subscription.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResultDestination {
    SignedWebhook { url: String },
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

/// How a git checkout may be used. Frozen intent only in Phase 1: every
/// checkout is a fresh copy either way (the remote is never mutated by
/// running the agent); `ReadOnly` exists so later trust tiers can key off it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CheckoutMode {
    #[default]
    WritableCopy,
    ReadOnly,
}

/// Where the agent works (design doc §3.3). Optional context around an
/// unchanged agent definition — an agent is never inherently a "GitHub
/// agent". The credentialed fetch always happens control-plane-side; the
/// sandbox only ever sees the materialized copy.
///
/// Wire compat: M1 rows serialized `{"kind":"none"}` and
/// `{"kind":"local_path"}` — the aliases keep those frozen RunSpecs
/// deserializable forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkspaceSpec {
    /// Empty per-session directory; the agent still has somewhere to write.
    #[default]
    #[serde(alias = "none")]
    Scratch,
    /// Copy of a host directory; the original tree is never touched.
    #[serde(alias = "local_path")]
    LocalCopy { path: String },
    /// Exact ref/commit of a remote repository, fetched by the control plane
    /// with the connection's credential and mounted into the sandbox. The
    /// credential itself never appears here (or anywhere in the RunSpec).
    GitRepository {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        connection_id: Option<Uuid>,
        /// Provider-native name, e.g. "owner/name" for GitHub.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repository: Option<String>,
        clone_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        r#ref: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        commit_sha: Option<String>,
        #[serde(default)]
        checkout_mode: CheckoutMode,
    },
}

impl WorkspaceSpec {
    /// Resolution precedence (design §3.3): explicit invocation workspace,
    /// then agent revision default, then scratch. (Event-derived workspaces
    /// slot in above `explicit` when triggers arrive in a later phase.)
    pub fn resolve(explicit: Option<Self>, revision_default: Option<Self>) -> Self {
        explicit.or(revision_default).unwrap_or_default()
    }
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
    /// M1 rows serialized this field as `repo` — the alias keeps them valid.
    #[serde(alias = "repo")]
    pub workspace: WorkspaceSpec,
    pub autonomy: Autonomy,
    pub trust_tier: TrustTier,
    pub budgets: Budgets,
    pub policy_id: Uuid,
    pub policy_version: i32,
    /// Full parsed policy snapshot — the run is governed by this exact
    /// document even if the policy row is edited later.
    pub policy_snapshot: crate::policy::Policy,
    /// Why this run exists. `#[serde(default)]` keeps every pre-Phase-2
    /// frozen RunSpec deserializable (defaults to a manual invocation).
    #[serde(default)]
    pub invocation: InvocationContext,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_destinations: Vec<ResultDestination>,
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
    fn workspace_spec_deserializes_m1_wire_tags() {
        // Frozen M1 RunSpecs must stay readable forever.
        let old_none: WorkspaceSpec =
            serde_json::from_value(serde_json::json!({"kind":"none"})).unwrap();
        assert_eq!(old_none, WorkspaceSpec::Scratch);
        let old_local: WorkspaceSpec =
            serde_json::from_value(serde_json::json!({"kind":"local_path","path":"/x"})).unwrap();
        assert_eq!(old_local, WorkspaceSpec::LocalCopy { path: "/x".into() });
        // New wire names round-trip.
        let s = serde_json::to_value(WorkspaceSpec::Scratch).unwrap();
        assert_eq!(s["kind"], "scratch");
        let l = serde_json::to_value(WorkspaceSpec::LocalCopy { path: "/x".into() }).unwrap();
        assert_eq!(l["kind"], "local_copy");
    }

    #[test]
    fn git_repository_roundtrips_and_defaults() {
        let v = serde_json::json!({
            "kind": "git_repository",
            "clone_url": "https://github.com/o/r.git",
            "ref": "main"
        });
        let ws: WorkspaceSpec = serde_json::from_value(v).unwrap();
        let WorkspaceSpec::GitRepository {
            connection_id,
            clone_url,
            r#ref,
            commit_sha,
            checkout_mode,
            ..
        } = &ws
        else {
            panic!("wrong variant");
        };
        assert!(connection_id.is_none());
        assert_eq!(clone_url, "https://github.com/o/r.git");
        assert_eq!(r#ref.as_deref(), Some("main"));
        assert!(commit_sha.is_none());
        assert_eq!(*checkout_mode, CheckoutMode::WritableCopy);
        let back: WorkspaceSpec =
            serde_json::from_value(serde_json::to_value(&ws).unwrap()).unwrap();
        assert_eq!(back, ws);
    }

    #[test]
    fn workspace_resolution_precedence() {
        let explicit = WorkspaceSpec::LocalCopy { path: "/e".into() };
        let default = WorkspaceSpec::GitRepository {
            connection_id: None,
            repository: None,
            clone_url: "https://github.com/o/r.git".into(),
            r#ref: None,
            commit_sha: None,
            checkout_mode: CheckoutMode::default(),
        };
        // explicit invocation > revision default > scratch
        assert_eq!(
            WorkspaceSpec::resolve(Some(explicit.clone()), Some(default.clone())),
            explicit
        );
        assert_eq!(WorkspaceSpec::resolve(None, Some(default.clone())), default);
        assert_eq!(WorkspaceSpec::resolve(None, None), WorkspaceSpec::Scratch);
    }

    #[test]
    fn run_spec_repo_field_alias_keeps_m1_rows_valid() {
        // A frozen M1 RunSpec used the `repo` key; it must still deserialize.
        let old = serde_json::json!({
            "agent_id": Uuid::now_v7(),
            "agent_revision_id": Uuid::now_v7(),
            "agent_name": "a",
            "harness": "claude-agent-sdk",
            "runner_image": "img",
            "model": "m",
            "system_prompt": null,
            "task": "t",
            "repo": {"kind": "local_path", "path": "/x"},
            "autonomy": "supervised",
            "trust_tier": "trusted",
            "budgets": {"max_wall_clock_secs": 1, "max_tokens": 1, "max_cost_usd": 1.0, "max_tool_calls": 1},
            "policy_id": Uuid::now_v7(),
            "policy_version": 1,
            "policy_snapshot": {"name": "p"}
        });
        let spec: RunSpec = serde_json::from_value(old).unwrap();
        assert_eq!(
            spec.workspace,
            WorkspaceSpec::LocalCopy { path: "/x".into() }
        );
    }

    #[test]
    fn run_spec_without_invocation_defaults_to_manual() {
        // Every frozen M1/Phase-1 RunSpec lacks these fields — they must
        // deserialize forever, defaulting to a manual invocation.
        let old = serde_json::json!({
            "agent_id": Uuid::now_v7(), "agent_revision_id": Uuid::now_v7(),
            "agent_name": "a", "harness": "claude-agent-sdk", "runner_image": "img",
            "model": "m", "system_prompt": null, "task": "t",
            "workspace": {"kind": "scratch"},
            "autonomy": "supervised", "trust_tier": "trusted",
            "budgets": {"max_wall_clock_secs": 1, "max_tokens": 1, "max_cost_usd": 1.0, "max_tool_calls": 1},
            "policy_id": Uuid::now_v7(), "policy_version": 1,
            "policy_snapshot": {"name": "p"}
        });
        let spec: RunSpec = serde_json::from_value(old).unwrap();
        assert_eq!(spec.invocation.kind, InvocationKind::Manual);
        assert!(spec.invocation.subscription_id.is_none());
        assert!(spec.result_destinations.is_empty());
    }

    #[test]
    fn invocation_context_roundtrips_api_kind() {
        let sub = Uuid::now_v7();
        let ctx = InvocationContext {
            kind: InvocationKind::Api,
            subscription_id: Some(sub),
            actor: Some("trigger:nightly".into()),
            attributes: serde_json::json!({"context": {"ticket": "INC-42"}}),
            received_at: Some(chrono::Utc::now()),
        };
        let v = serde_json::to_value(&ctx).unwrap();
        assert_eq!(v["kind"], "api");
        let back: InvocationContext = serde_json::from_value(v).unwrap();
        assert_eq!(back.subscription_id, Some(sub));
    }

    #[test]
    fn result_destination_wire_shape() {
        let d = ResultDestination::SignedWebhook {
            url: "https://x.test/cb".into(),
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind": "signed_webhook", "url": "https://x.test/cb"})
        );
        let back: ResultDestination = serde_json::from_value(v).unwrap();
        assert_eq!(back, d);
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
