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
    /// Untrusted event source (e.g. a fork PR): the run may read and review
    /// but never write or reach for secrets — enforced at the permission
    /// gate via `policy::read_only_denial`, above any policy/subscription.
    ReadOnly,
}

impl TrustTier {
    /// Matches the serde wire form (and the `sessions.trust_tier` column).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::ReadOnly => "read_only",
        }
    }
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
    // ── kind = event only (design §3.4); all optional for wire compat ──
    /// Connector name, e.g. "github".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Provider delivery id — the level-1 dedup key, kept for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_event_id: Option<String>,
    /// Normalized, e.g. "pull_request.opened".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    /// Normalized resource identity, e.g. "acme/site#42".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// When the event happened at the provider (received_at = our clock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<DateTime<Utc>>,
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
            provider: None,
            external_event_id: None,
            event_type: None,
            resource: None,
            occurred_at: None,
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
    SignedWebhook {
        url: String,
        /// The run resource binding (`result_publish` slot, `subscription_secret`
        /// authority) that authorizes signing this callback (invariant 21).
        /// Resolved in `create_run` (Task 5); historical RunSpecs lack it (None).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding_id: Option<Uuid>,
    },
    /// One stable comment per (subscription, PR) — later events update it in
    /// place (§17 #3); posted under the App identity (§17 #1).
    /// (Explicit rename: snake_case would derive "git_hub_pr_comment".)
    #[serde(rename = "github_pr_comment")]
    GitHubPrComment {
        connection_id: Uuid,
        /// "owner/name"
        repository: String,
        pr_number: i64,
        /// The run resource binding (`result_publish` slot) that authorizes the
        /// publish (invariant 21). Resolved in `create_run` (Task 5); historical
        /// RunSpecs lack it (None).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding_id: Option<Uuid>,
    },
    /// One check run per head SHA under the stable name
    /// `fluidbox/<subscription>`; requires an App connection (§17 #1).
    #[serde(rename = "github_check")]
    GitHubCheck {
        connection_id: Uuid,
        repository: String,
        head_sha: String,
        /// The run resource binding (`result_publish` slot) that authorizes the
        /// publish (invariant 21). Resolved in `create_run` (Task 5); historical
        /// RunSpecs lack it (None).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding_id: Option<Uuid>,
    },
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
        /// The run resource binding (`workspace_fetch` slot) that authorizes the
        /// credentialed fetch (invariant 21). Resolved in `create_run` (Task 5)
        /// and consumed by the orchestrator; historical RunSpecs lack it (None).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding_id: Option<Uuid>,
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

/// A brokered MCP surface frozen into a run by binding resolution (Phase C,
/// design §"Run resource binding"). Replaces the Gap-3 embed of
/// `connection_id` inside a `capabilities` bundle server: the credential now
/// hangs off the `binding_id` (a `run_resource_bindings` row, `mcp` slot), and
/// the run's frozen tool contract is `tools` + `tools_digest`. The `slot` is
/// the local server alias — it prefixes `mcp__<slot>__<tool>` for the model —
/// and `url` is the brokered endpoint the control plane (never a sandbox)
/// calls. Written by `create_run` (Task 5); consumed by the gate/broker (Task 6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrokeredSurface {
    pub slot: String,
    pub url: String,
    pub binding_id: Uuid,
    pub snapshot_version: i32,
    pub tools: Vec<crate::capability::ToolSnapshot>,
    pub tools_digest: String,
}

/// Whether any brokered surface advertises `tool` under `server` (its slot
/// alias). Single source of truth for the slot/tool match, shared by
/// [`RunSpec::mcp_tool_available`] and
/// [`crate::capability::brokered_surface_denial`].
pub fn brokered_surfaces_have_tool(brokered: &[BrokeredSurface], server: &str, tool: &str) -> bool {
    brokered
        .iter()
        .any(|s| s.slot == server && s.tools.iter().any(|t| t.name == tool))
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
    /// Frozen capability bundles (design §3.6/§8): exact pinned versions
    /// with their photographed tool-schema snapshots. The permission gate
    /// consults ONLY this set — never the live registry or the live server.
    /// `#[serde(default)]` keeps every pre-Phase-5 frozen RunSpec
    /// deserializable (defaults to no capabilities).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<crate::capability::FrozenBundle>,
    /// Brokered MCP surfaces frozen by binding resolution (Phase C, design
    /// §"Run resource binding"): the connection-free successor to embedding a
    /// `connection_id` in a `capabilities` server (Gap 3). `#[serde(default)]`
    /// keeps every pre-Phase-C frozen RunSpec deserializable (defaults to no
    /// surfaces). Populated by `create_run` (Task 5); the gate consults it via
    /// [`RunSpec::mcp_tool_available`] alongside `capabilities`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub brokered: Vec<BrokeredSurface>,
}

impl RunSpec {
    /// The Phase C brokered surface bound to `server` (a `mcp__<slot>__*`
    /// alias is a requirement slot), if any. Slots are unique within a run, so
    /// at most one matches.
    pub fn find_brokered_surface(&self, server: &str) -> Option<&BrokeredSurface> {
        self.brokered.iter().find(|s| s.slot == server)
    }

    /// Availability across BOTH attachment paths — the legacy frozen
    /// `capabilities` bundles and the Phase C `brokered` surfaces. This is the
    /// union the permission gate consults; a tool in neither does not exist
    /// for this run (attach ≠ allow; not-attached = unavailable).
    pub fn mcp_tool_available(&self, server: &str, tool: &str) -> bool {
        crate::capability::find_tool(&self.capabilities, server, tool).is_some()
            || brokered_surfaces_have_tool(&self.brokered, server, tool)
    }
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
            binding_id: None,
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
        // Pre-Phase-5 rows also lack `capabilities` — empty forever.
        assert!(spec.capabilities.is_empty());
    }

    #[test]
    fn run_spec_capabilities_roundtrip_and_stay_optional() {
        use crate::capability::{CapabilityServer, FrozenBundle, ToolSnapshot};
        let bundle = FrozenBundle {
            id: Uuid::now_v7(),
            name: "kb-tools".into(),
            version: 2,
            definition_digest: "sha256:beef".into(),
            servers: vec![CapabilityServer::Brokered {
                name: "kb".into(),
                url: "https://mcp.example.test/mcp".into(),
                connection_id: None,
                identity: None,
                tools: vec![ToolSnapshot {
                    name: "kb_search".into(),
                    description: "search".into(),
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    annotations: None,
                }],
            }],
        };
        let v = serde_json::to_value(vec![bundle.clone()]).unwrap();
        let back: Vec<crate::capability::FrozenBundle> = serde_json::from_value(v).unwrap();
        assert_eq!(back, vec![bundle]);
        // An empty set serializes to nothing (skip_serializing_if) so old
        // consumers of run_spec json never see a new key for plain runs.
        let spec_json = serde_json::to_value(RunSpec {
            agent_id: Uuid::now_v7(),
            agent_revision_id: Uuid::now_v7(),
            agent_name: "a".into(),
            harness: "claude-agent-sdk".into(),
            runner_image: "img".into(),
            model: "m".into(),
            system_prompt: None,
            task: "t".into(),
            workspace: WorkspaceSpec::Scratch,
            autonomy: Autonomy::Supervised,
            trust_tier: TrustTier::Trusted,
            budgets: Budgets::default(),
            policy_id: Uuid::now_v7(),
            policy_version: 1,
            policy_snapshot: crate::policy::Policy::parse_yaml("name: p").unwrap(),
            invocation: InvocationContext::default(),
            result_destinations: vec![],
            capabilities: vec![],
            brokered: vec![],
        })
        .unwrap();
        assert!(spec_json.get("capabilities").is_none());
        // Pre-Phase-C rows also lack `brokered` — empty stays omitted forever.
        assert!(spec_json.get("brokered").is_none());
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
            ..Default::default()
        };
        let v = serde_json::to_value(&ctx).unwrap();
        assert_eq!(v["kind"], "api");
        let back: InvocationContext = serde_json::from_value(v).unwrap();
        assert_eq!(back.subscription_id, Some(sub));
    }

    #[test]
    fn invocation_context_event_fields_roundtrip_and_old_rows_stay_valid() {
        // Frozen Phase-2/3 contexts have none of the event fields — they must
        // deserialize forever with the fields absent.
        let old = serde_json::json!({
            "kind": "api",
            "subscription_id": Uuid::now_v7(),
            "actor": "trigger:x",
            "attributes": {"context": {}}
        });
        let ctx: InvocationContext = serde_json::from_value(old).unwrap();
        assert!(ctx.provider.is_none());
        assert!(ctx.external_event_id.is_none());
        assert!(ctx.event_type.is_none());
        assert!(ctx.resource.is_none());
        assert!(ctx.occurred_at.is_none());

        let ev = InvocationContext {
            kind: InvocationKind::Event,
            subscription_id: Some(Uuid::now_v7()),
            actor: Some("github:octocat".into()),
            attributes: serde_json::json!({"pr_number": 42}),
            received_at: Some(chrono::Utc::now()),
            provider: Some("github".into()),
            external_event_id: Some("delivery-1".into()),
            event_type: Some("pull_request.opened".into()),
            resource: Some("acme/site#42".into()),
            occurred_at: Some(chrono::Utc::now()),
        };
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["kind"], "event");
        assert_eq!(v["provider"], "github");
        assert_eq!(v["event_type"], "pull_request.opened");
        let back: InvocationContext = serde_json::from_value(v).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn github_result_destinations_wire_shape() {
        let cid = Uuid::now_v7();
        let comment = ResultDestination::GitHubPrComment {
            connection_id: cid,
            repository: "acme/site".into(),
            pr_number: 42,
            binding_id: None,
        };
        let v = serde_json::to_value(&comment).unwrap();
        assert_eq!(v["kind"], "github_pr_comment");
        assert_eq!(v["pr_number"], 42);
        assert_eq!(v["repository"], "acme/site");
        let back: ResultDestination = serde_json::from_value(v).unwrap();
        assert_eq!(back, comment);

        let check = ResultDestination::GitHubCheck {
            connection_id: cid,
            repository: "acme/site".into(),
            head_sha: "a".repeat(40),
            binding_id: None,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["kind"], "github_check");
        assert_eq!(v["head_sha"], "a".repeat(40));
        let back: ResultDestination = serde_json::from_value(v).unwrap();
        assert_eq!(back, check);
    }

    #[test]
    fn trust_tier_string_forms() {
        assert_eq!(TrustTier::Trusted.as_str(), "trusted");
        assert_eq!(TrustTier::ReadOnly.as_str(), "read_only");
        // as_str must match the serde wire form (sessions.trust_tier column
        // and the RunSpec json must agree).
        assert_eq!(
            serde_json::to_value(TrustTier::ReadOnly).unwrap(),
            serde_json::json!("read_only")
        );
    }

    #[test]
    fn result_destination_wire_shape() {
        let d = ResultDestination::SignedWebhook {
            url: "https://x.test/cb".into(),
            binding_id: None,
        };
        let v = serde_json::to_value(&d).unwrap();
        // binding_id is None → skip_serializing_if omits it: the wire shape is
        // byte-identical to a pre-Phase-C signed-webhook destination.
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

    // ─── Phase C: brokered surfaces + run binding fields ───────────────────

    fn sample_run_spec() -> RunSpec {
        RunSpec {
            agent_id: Uuid::now_v7(),
            agent_revision_id: Uuid::now_v7(),
            agent_name: "a".into(),
            harness: "claude-agent-sdk".into(),
            runner_image: "img".into(),
            model: "m".into(),
            system_prompt: None,
            task: "t".into(),
            workspace: WorkspaceSpec::Scratch,
            autonomy: Autonomy::Supervised,
            trust_tier: TrustTier::Trusted,
            budgets: Budgets::default(),
            policy_id: Uuid::now_v7(),
            policy_version: 1,
            policy_snapshot: crate::policy::Policy::parse_yaml("name: p").unwrap(),
            invocation: InvocationContext::default(),
            result_destinations: vec![],
            capabilities: vec![],
            brokered: vec![],
        }
    }

    #[test]
    fn historical_runspec_without_brokered_deserializes_and_unions() {
        // A frozen historical RunSpec: `capabilities` embeds a Brokered server
        // WITH connection_id (Gap 3), the workspace + result destination carry
        // NO binding_id, and there is NO `brokered` key. It must deserialize
        // forever, and the unified lookup must still find the legacy tool.
        let old = serde_json::json!({
            "agent_id": Uuid::now_v7(), "agent_revision_id": Uuid::now_v7(),
            "agent_name": "a", "harness": "claude-agent-sdk", "runner_image": "img",
            "model": "m", "system_prompt": null, "task": "t",
            "workspace": {
                "kind": "git_repository",
                "connection_id": Uuid::now_v7(),
                "clone_url": "https://github.com/o/r.git",
                "ref": "main"
            },
            "autonomy": "supervised", "trust_tier": "trusted",
            "budgets": {"max_wall_clock_secs": 1, "max_tokens": 1, "max_cost_usd": 1.0, "max_tool_calls": 1},
            "policy_id": Uuid::now_v7(), "policy_version": 1,
            "policy_snapshot": {"name": "p"},
            "result_destinations": [
                {"kind": "github_pr_comment", "connection_id": Uuid::now_v7(),
                 "repository": "o/r", "pr_number": 7}
            ],
            "capabilities": [{
                "id": Uuid::now_v7(), "name": "kb-tools", "version": 1,
                "definition_digest": "sha256:beef",
                "servers": [{
                    "class": "brokered", "name": "kb",
                    "url": "https://mcp.example.test/mcp",
                    "connection_id": Uuid::now_v7(),
                    "tools": [{"name": "kb_search", "description": "d",
                               "input_schema": {"type": "object"}}]
                }]
            }]
        });
        let spec: RunSpec = serde_json::from_value(old).unwrap();
        // `brokered` defaulted to empty (the key was absent).
        assert!(spec.brokered.is_empty());
        // The legacy embedded brokered tool is available via the union…
        assert!(spec.mcp_tool_available("kb", "kb_search"));
        // …but only its declared tools, and only its server.
        assert!(!spec.mcp_tool_available("kb", "kb_admin"));
        assert!(!spec.mcp_tool_available("ghost", "x"));
        // It is NOT a Phase C surface (that path is empty here).
        assert!(spec.find_brokered_surface("kb").is_none());
        // Historical workspace: binding_id absent → None; connection_id kept.
        let WorkspaceSpec::GitRepository {
            binding_id,
            connection_id,
            ..
        } = &spec.workspace
        else {
            panic!("wrong workspace variant");
        };
        assert!(binding_id.is_none());
        assert!(connection_id.is_some());
        // Historical result destination: binding_id absent → None.
        let ResultDestination::GitHubPrComment { binding_id, .. } = &spec.result_destinations[0]
        else {
            panic!("wrong destination variant");
        };
        assert!(binding_id.is_none());
    }

    #[test]
    fn new_runspec_with_brokered_surfaces_roundtrips() {
        use crate::capability::ToolSnapshot;
        let bid = Uuid::now_v7();
        let surface = BrokeredSurface {
            slot: "gh".into(),
            url: "https://mcp.github.test/mcp".into(),
            binding_id: bid,
            snapshot_version: 4,
            tools: vec![ToolSnapshot {
                name: "get_pr".into(),
                description: "get a pull request".into(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                annotations: None,
            }],
            tools_digest: "sha256:cafe".into(),
        };
        let mut spec = sample_run_spec();
        spec.brokered = vec![surface.clone()];

        let v = serde_json::to_value(&spec).unwrap();
        // Non-empty brokered surfaces serialize with their exact shape.
        assert_eq!(v["brokered"][0]["slot"], "gh");
        assert_eq!(v["brokered"][0]["snapshot_version"], 4);
        assert_eq!(v["brokered"][0]["url"], "https://mcp.github.test/mcp");
        assert_eq!(v["brokered"][0]["binding_id"], bid.to_string());

        let back: RunSpec = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(back.brokered, vec![surface]);
        // The unified lookup resolves the surface by its slot alias.
        assert!(back.mcp_tool_available("gh", "get_pr"));
        assert!(!back.mcp_tool_available("gh", "delete_repo"));
        assert_eq!(back.find_brokered_surface("gh").unwrap().binding_id, bid);
        assert!(back.find_brokered_surface("nope").is_none());
        // Value round-trip is stable.
        assert_eq!(serde_json::to_value(&back).unwrap(), v);
    }

    #[test]
    fn empty_capability_and_brokered_sets_deny_all_mcp() {
        // ReadOnly (and any nothing-attached run) freezes both sets empty:
        // every mcp__ name is unavailable, and the denial is produced.
        let spec = sample_run_spec();
        assert!(spec.capabilities.is_empty() && spec.brokered.is_empty());
        assert!(!spec.mcp_tool_available("kb", "kb_search"));
        assert!(crate::capability::brokered_surface_denial(
            &spec.brokered,
            &spec.capabilities,
            "mcp__kb__kb_search"
        )
        .is_some());
        // An empty `brokered` serializes to nothing (skip_serializing_if).
        let v = serde_json::to_value(&spec).unwrap();
        assert!(v.get("brokered").is_none());
    }
}
