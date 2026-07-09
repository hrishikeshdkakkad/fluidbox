use crate::spec::Autonomy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─── Policy document (YAML v0) ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefaults {
    /// Verdict when no rule matches. Fail-safe default: approve (ask a human).
    #[serde(default = "default_tool_action")]
    pub tool_action: RuleAction,
}

impl Default for PolicyDefaults {
    fn default() -> Self {
        Self { tool_action: default_tool_action() }
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
        Self { permitted: true, on_approval_rule: AutonomousFallback::default() }
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
                        reason: "requires human approval; run is autonomous (policy fallback: deny)"
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
        EvaluationOutcome { effective: original.clone(), original, autonomy_rewritten: false, matched_rule }
    }

    fn evaluate_supervised(&self, req: &ToolCallRequest) -> (Verdict, Option<usize>) {
        for (i, rule) in self.tools.iter().enumerate() {
            if !rule.r#match.iter().any(|m| tool_matches(m, &req.tool)) {
                continue;
            }
            return (self.apply_rule(rule, req), Some(i));
        }
        (self.finish(self.defaults.tool_action, None, &req.tool, None), None)
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
                    // than brick the run.
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
    matches!(command.as_bytes().get(p.len()), None | Some(b' ') | Some(b'\t'))
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
        ToolCallRequest { tool: tool.into(), input }
    }

    #[test]
    fn read_is_allowed() {
        let out = policy().evaluate(&req("Read", json!({"file_path": "/etc/passwd"})), Autonomy::Supervised);
        assert_eq!(out.effective, Verdict::Allow);
    }

    #[test]
    fn edit_inside_workspace_allowed_outside_escalates() {
        let p = policy();
        let inside = p.evaluate(&req("Edit", json!({"file_path": "/workspace/repo/a.py"})), Autonomy::Supervised);
        assert_eq!(inside.effective, Verdict::Allow);
        let outside = p.evaluate(&req("Edit", json!({"file_path": "/etc/hosts"})), Autonomy::Supervised);
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
        let ok = p.evaluate(&req("Bash", json!({"command": "git status"})), Autonomy::Supervised);
        assert_eq!(ok.effective, Verdict::Allow);
        let sneaky = p.evaluate(&req("Bash", json!({"command": "git statusx"})), Autonomy::Supervised);
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
        let allow = p.evaluate(&req("Read", json!({"file_path": "x"})), Autonomy::Autonomous);
        assert!(!allow.autonomy_rewritten);
        assert_eq!(allow.effective, Verdict::Allow);
        let deny = p.evaluate(&req("WebFetch", json!({})), Autonomy::Autonomous);
        assert!(!deny.autonomy_rewritten);
        assert!(matches!(deny.effective, Verdict::Deny { .. }));
    }

    #[test]
    fn bad_yaml_is_rejected() {
        assert!(Policy::parse_yaml("name: x\ntools:\n  - match: []\n    action: allow").is_err());
        assert!(Policy::parse_yaml(
            "name: x\ntools:\n  - match: [Bash]\n    action: allow\n    shell:\n      deny_regex: [\"(\"]"
        )
        .is_err());
    }
}
