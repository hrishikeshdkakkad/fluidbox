# Governance Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the governance model visible and controllable in the dashboard via a per-tool permissions matrix, without letting the UI flatten the policy's security engineering.

**Architecture:** The canonical tool vocabulary becomes data in `fluidbox-core`. `Policy` gains two pure derivations (`autonomy_summary()`, `tool_matrix()`) that reuse the gate's own matcher, plus a `managed_overrides` list — stored in its own jsonb column, never in the authored YAML — consulted *before* `tools` in first-match-wins. The server resolves every row's real status; the dashboard renders it and never parses YAML or resolves policy semantics.

**Tech Stack:** Rust (axum, sqlx, serde), Neon Postgres, Next.js (presentation-only).

Design doc: `docs/plans/2026-07-14-governance-page-design.md`. Read §3 (trust model) before Task 3.

## Global Constraints

- fluidbox-authored backend is **100% Rust**; the Next.js dashboard is **presentation-only (all logic in the Rust API)**. The dashboard MUST NOT parse YAML or resolve policy semantics.
- Database is **Neon Postgres**; use the DIRECT (non-`-pooler`) connection string.
- `just check` = fmt + clippy `-D warnings` + test + web build. This is the bar.
- `cargo test -p fluidbox-core` needs no DB. `cargo test -p fluidbox-db` needs `set -a; source .env; set +a` first, and no server running.
- **`sqlx::migrate!` bakes migration files at COMPILE time.** After adding `migrations/0010_*.sql`, run `touch crates/fluidbox-db/src/lib.rs` before rebuilding or the old baked set runs.
- Overrides are **exact tool names only** — never wildcards.
- Rules carrying `paths` or `shell` are **conditional** and can never be overridden — enforced server-side, not just in the UI.
- An override moves only the **policy** verdict. Trust tier, budgets, and frozen-capability availability sit above policy in `decide_tool_call` and must remain unreachable.
- Latest applied migration is `0009`. `0010` is free.
- Commit messages end with the repo's `Co-Authored-By` / `Claude-Session` trailers.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/fluidbox-core/src/tools.rs` | **Create.** The canonical tool vocabulary as data + `is_canonical` / `is_mcp`. |
| `crates/fluidbox-core/src/lib.rs` | **Modify.** `pub mod tools;` |
| `crates/fluidbox-core/src/policy.rs` | **Modify.** `ToolOverride`, `Policy.managed_overrides`, override precedence in `evaluate_supervised`, `AutonomySummary`, `ToolStatus`, `ConstraintSummary`, `autonomy_summary()`, `tool_matrix()`. |
| `migrations/0010_policy_managed_overrides.sql` | **Create.** The jsonb column. |
| `crates/fluidbox-db/src/lib.rs` | **Modify.** `PolicyRow.managed_overrides`, override-preserving upsert, `set_policy_override`, `clear_policy_override`, `policy_agents_using`, `policy_mcp_tools`. |
| `crates/fluidbox-server/src/api.rs` | **Modify.** Enrich `list_policies`; add `get_policy`, `put_policy_override`, `delete_policy_override`. |
| `crates/fluidbox-server/src/main.rs` | **Modify.** Three routes. |
| `apps/web/app/governance/page.tsx` | **Create.** Policy list. |
| `apps/web/app/governance/[name]/page.tsx` | **Create.** Detail page. |
| `apps/web/app/components/PermissionMatrix.tsx` | **Create.** The matrix (rows + controls). |
| `apps/web/app/components/Sidebar.tsx` | **Modify.** Nav item. |

---

### Task 1: Canonical tool vocabulary as data

**Files:**
- Create: `crates/fluidbox-core/src/tools.rs`
- Modify: `crates/fluidbox-core/src/lib.rs`
- Test: in `crates/fluidbox-core/src/tools.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `fluidbox_core::tools::{ToolDef, ToolGroup, CANONICAL, is_canonical, is_mcp}`.
  - `pub const CANONICAL: &[ToolDef]`
  - `pub fn is_canonical(name: &str) -> bool`
  - `pub fn is_mcp(name: &str) -> bool`

- [ ] **Step 1: Write the failing test**

Create `crates/fluidbox-core/src/tools.rs` with only the tests for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_is_enumerable_and_grouped() {
        assert!(is_canonical("Bash"));
        assert!(is_canonical("MultiEdit"));
        assert!(!is_canonical("mcp__cloudflare__kv_namespace_create"));
        assert!(!is_canonical("NotATool"));
        assert!(is_mcp("mcp__cloudflare__kv_namespace_create"));
        assert!(!is_mcp("Bash"));
        // No duplicates — the matrix would render a tool twice.
        let mut names: Vec<&str> = CANONICAL.iter().map(|t| t.name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate tool names in CANONICAL");
    }

    /// The vocabulary is a CONTRACT (CLAUDE.md): every name the seed policy
    /// governs must be enumerable here, or the Governance matrix silently
    /// omits a tool the policy has an opinion about.
    #[test]
    fn seed_policy_matches_are_all_known_tools() {
        let yaml = include_str!("../../../policies/default.yaml");
        let p = crate::policy::Policy::parse_yaml(yaml).expect("seed policy parses");
        for rule in &p.tools {
            for m in &rule.r#match {
                assert!(
                    is_canonical(m) || m.starts_with("mcp__"),
                    "policy matches {m:?}, which is neither canonical nor mcp__* — \
                     add it to CANONICAL or fix the policy"
                );
            }
        }
    }
}
```

Add to `crates/fluidbox-core/src/lib.rs`, alphabetically among the existing `pub mod` lines:

```rust
pub mod tools;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p fluidbox-core tools::`
Expected: FAIL — compile error, `cannot find value CANONICAL in this scope`.

- [ ] **Step 3: Write minimal implementation**

Prepend to `crates/fluidbox-core/src/tools.rs` (above the `mod tests`):

```rust
//! The canonical tool vocabulary — the contract every harness implements.
//!
//! Names/shapes crossing `/permission` MUST be these (CLAUDE.md): `Bash{command}`,
//! `Edit/Write/MultiEdit{file_path | edits[].file_path}`, `Read/Glob/Grep/LS`,
//! `mcp__<server>__<tool>`. Encoding that contract as DATA (rather than a comment)
//! makes it enumerable — the Governance matrix lists it, and
//! `seed_policy_matches_are_all_known_tools` fails when a harness adds a name
//! nobody registered.
//!
//! This lives in core, not `harness.rs`, because it is harness-INDEPENDENT:
//! `harness.rs` stays the registry of harness *specifics* (image/model defaults,
//! env extras). MCP tools are deliberately absent — they are discovered by
//! photographing capability bundles, never declared.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolGroup {
    Files,
    Search,
    Shell,
    Web,
    Meta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ToolDef {
    pub name: &'static str,
    pub group: ToolGroup,
}

pub const CANONICAL: &[ToolDef] = &[
    ToolDef { name: "Read", group: ToolGroup::Files },
    ToolDef { name: "Write", group: ToolGroup::Files },
    ToolDef { name: "Edit", group: ToolGroup::Files },
    ToolDef { name: "MultiEdit", group: ToolGroup::Files },
    ToolDef { name: "NotebookRead", group: ToolGroup::Files },
    ToolDef { name: "NotebookEdit", group: ToolGroup::Files },
    ToolDef { name: "Glob", group: ToolGroup::Search },
    ToolDef { name: "Grep", group: ToolGroup::Search },
    ToolDef { name: "LS", group: ToolGroup::Search },
    ToolDef { name: "Bash", group: ToolGroup::Shell },
    ToolDef { name: "BashOutput", group: ToolGroup::Shell },
    ToolDef { name: "KillShell", group: ToolGroup::Shell },
    ToolDef { name: "WebFetch", group: ToolGroup::Web },
    ToolDef { name: "WebSearch", group: ToolGroup::Web },
    ToolDef { name: "TodoWrite", group: ToolGroup::Meta },
    ToolDef { name: "Task", group: ToolGroup::Meta },
];

/// Is this an exact canonical tool name? (Not a matcher — no wildcards.)
pub fn is_canonical(name: &str) -> bool {
    CANONICAL.iter().any(|t| t.name == name)
}

/// Is this a brokered/sandbox MCP tool name (`mcp__<server>__<tool>`)?
pub fn is_mcp(name: &str) -> bool {
    name.starts_with("mcp__")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p fluidbox-core tools::`
Expected: PASS (2 tests). If `seed_policy_matches_are_all_known_tools` fails, the seed policy names a tool missing from `CANONICAL` — add it rather than weakening the test.

- [ ] **Step 5: Commit**

```bash
git add crates/fluidbox-core/src/tools.rs crates/fluidbox-core/src/lib.rs
git commit -m "feat(core): the canonical tool vocabulary as data

It was already a contract every harness must implement (CLAUDE.md), but it
lived in comments and string literals. As data it is enumerable (the
Governance matrix lists it) and testable — the drift test fails when the seed
policy names a tool nobody registered.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017mfjJE5FKtgc1rNvSZVVb9"
```

---

### Task 2: `AutonomySummary`

**Files:**
- Modify: `crates/fluidbox-core/src/policy.rs`
- Test: same file, in the existing `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: `Policy::autonomy_summary(&self) -> AutonomySummary` where
  `pub struct AutonomySummary { pub permitted: bool, pub default_fallback: AutonomousFallback, pub allow_overrides: usize, pub deny_overrides: usize }`

- [ ] **Step 1: Write the failing test**

Add inside `mod tests` in `crates/fluidbox-core/src/policy.rs`:

```rust
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

/// Only rules that can actually REACH RequireApproval may be counted. The seed
/// policy's Bash rule is `action: allow` + `shell.on_no_match: approve` — a
/// naive `action == Approve` test would MISS an on_autonomous added there and
/// undercount in the dangerous direction.
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
  # allow-not-approve and action is allow -> NOT counted (guards overcounting)
  - match: ["BashOutput"]
    action: allow
    shell: { on_no_match: allow }
    paths: { allow: ["/workspace/**"] }
    on_autonomous: allow
"#;
    let p = Policy::parse_yaml(yaml).expect("parses");
    let s = p.autonomy_summary();
    assert_eq!(s.allow_overrides, 3, "Bash (shell on_no_match) + mcp__* (action) + Write (paths.allow)");
    assert_eq!(s.deny_overrides, 0, "the deny override sits on an unreachable rule");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p fluidbox-core policy::tests::autonomy_summary`
Expected: FAIL — `no method named autonomy_summary found for struct Policy`.

- [ ] **Step 3: Write minimal implementation**

Add to `crates/fluidbox-core/src/policy.rs`, immediately above `impl Policy`'s `evaluate`:

```rust
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

/// Can this rule ever produce a RequireApproval verdict? Mirrors the THREE
/// routes in `apply_rule`. A rule that can never approve makes its
/// `on_autonomous` dead config — counting it would claim an exception that can
/// never fire.
fn can_require_approval(rule: &ToolRule) -> bool {
    // Shell constraints short-circuit apply_rule: it returns from inside that
    // branch on every path, so `paths` is dead for a shell rule. Returning
    // early (not OR-ing all three) is what stops a rule carrying BOTH from
    // being overcounted.
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
```

And inside `impl Policy`:

```rust
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p fluidbox-core policy::tests::autonomy_summary`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/fluidbox-core/src/policy.rs
git commit -m "feat(core): Policy::autonomy_summary

Counts only rules that can actually reach RequireApproval, mirroring
apply_rule: the seed policy's Bash rule is action:allow + shell.on_no_match:
approve, so a naive action==Approve test would miss an on_autonomous there and
undercount in the dangerous direction.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017mfjJE5FKtgc1rNvSZVVb9"
```

---

### Task 3: `managed_overrides` + override precedence in the engine

**Read `docs/plans/2026-07-14-governance-page-design.md` §3 before starting.** This task touches the security-critical evaluation path.

**Files:**
- Modify: `crates/fluidbox-core/src/policy.rs`
- Test: same file

**Interfaces:**
- Consumes: nothing.
- Produces: `pub struct ToolOverride { pub tool: String, pub action: RuleAction }`; `Policy.managed_overrides: Vec<ToolOverride>`.

- [ ] **Step 1: Write the failing test**

Add inside `mod tests`:

```rust
/// An explicit per-tool decision beats the general rules by construction —
/// without reordering anything the user authored.
#[test]
fn managed_override_precedes_the_general_rules() {
    let yaml = r#"
name: t
defaults: { tool_action: approve }
tools:
  - match: ["mcp__*"]
    action: approve
"#;
    let mut p = Policy::parse_yaml(yaml).expect("parses");
    let tool = "mcp__cloudflare__kv_namespaces_list";
    // Baseline: the wildcard rule asks.
    assert!(matches!(
        p.evaluate(&req(tool, json!({})), Autonomy::Supervised).effective,
        Verdict::RequireApproval { .. }
    ));
    // With an override, it allows — and no rule index is reported, because the
    // override replaced the rule (its on_autonomous no longer applies).
    p.managed_overrides.push(ToolOverride {
        tool: tool.into(),
        action: RuleAction::Allow,
    });
    let out = p.evaluate(&req(tool, json!({})), Autonomy::Supervised);
    assert_eq!(out.effective, Verdict::Allow);
    assert_eq!(out.matched_rule, None);
    // A sibling tool is untouched by the override.
    assert!(matches!(
        p.evaluate(&req("mcp__cloudflare__kv_namespace_create", json!({})), Autonomy::Supervised)
            .effective,
        Verdict::RequireApproval { .. }
    ));
}

/// Overrides are exact-name only: a click must never author a blanket rule.
#[test]
fn managed_override_does_not_wildcard_match() {
    let yaml = r#"
name: t
defaults: { tool_action: approve }
tools:
  - match: ["mcp__*"]
    action: approve
"#;
    let mut p = Policy::parse_yaml(yaml).expect("parses");
    p.managed_overrides.push(ToolOverride {
        tool: "mcp__*".into(),
        action: RuleAction::Allow,
    });
    // The literal string "mcp__*" is not a matcher — a real tool must not hit it.
    assert!(matches!(
        p.evaluate(&req("mcp__cloudflare__kv_namespaces_list", json!({})), Autonomy::Supervised)
            .effective,
        Verdict::RequireApproval { .. }
    ));
}

/// Policies stored before this column existed must deserialize unchanged.
#[test]
fn managed_overrides_defaults_to_empty_for_existing_policies() {
    let yaml = "name: t\ntools: []\n";
    let p = Policy::parse_yaml(yaml).expect("parses");
    assert!(p.managed_overrides.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p fluidbox-core policy::tests::managed_override`
Expected: FAIL — `cannot find struct ToolOverride`, `no field managed_overrides on Policy`.

- [ ] **Step 3: Write minimal implementation**

Add near `ToolRule` in `crates/fluidbox-core/src/policy.rs`:

```rust
/// A UI-owned, per-tool decision. Consulted BEFORE `tools` — an explicit
/// decision about one tool beats the general rules without reordering anything
/// the user authored. NEVER present in authored YAML: it is stored in its own
/// `policies.managed_overrides` column and merged into `parsed`.
///
/// `tool` is an EXACT name (never a matcher) — a wildcard here would be an
/// un-reviewable blanket rule authored by a click.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolOverride {
    pub tool: String,
    pub action: RuleAction,
}
```

Add the field to `pub struct Policy` (keep `#[serde(default)]` so every stored
`parsed` value and every authored YAML still deserializes):

```rust
    /// See `ToolOverride`. Populated from the DB column, never from YAML.
    #[serde(default)]
    pub managed_overrides: Vec<ToolOverride>,
```

Replace the body of `evaluate_supervised` with:

```rust
    fn evaluate_supervised(&self, req: &ToolCallRequest) -> (Verdict, Option<usize>) {
        // A managed override is an explicit decision about ONE exact tool; it
        // wins over the general rules. Exact equality (never `tool_matches`)
        // keeps a click from authoring a wildcard. No rule index: the override
        // replaced the rule, so the rule's on_autonomous must not apply.
        if let Some(o) = self.managed_overrides.iter().find(|o| o.tool == req.tool) {
            return (self.finish(o.action, None, &req.tool, None), None);
        }
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p fluidbox-core`
Expected: PASS — all tests, including the pre-existing `seed_policy_semantics` (the new field is additive and defaults empty).

- [ ] **Step 5: Commit**

```bash
git add crates/fluidbox-core/src/policy.rs
git commit -m "feat(core): managed per-tool overrides, consulted before the rules

Overrides are exact-name only and carry no paths/shell, so they are
unconditional by construction. matched_rule is None for an overridden tool: the
override replaced the rule, so the rule's on_autonomous no longer applies and
the autonomy fallback resolves to the policy default.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017mfjJE5FKtgc1rNvSZVVb9"
```

---

### Task 4: `tool_matrix()` — the static analysis

**Files:**
- Modify: `crates/fluidbox-core/src/policy.rs`
- Test: same file

**Interfaces:**
- Consumes: `ToolOverride` (Task 3).
- Produces: `Policy::tool_matrix(&self, tools: &[String]) -> Vec<(String, ToolStatus)>`, and

```rust
pub enum ToolStatus {
    Unconditional { action: RuleAction, rule: Option<usize> },
    Conditional { action: RuleAction, rule: usize, constraints: ConstraintSummary },
    Default { action: RuleAction },
    Overridden { action: RuleAction, underlying: Box<ToolStatus> },
}
pub struct ConstraintSummary {
    pub paths_allow: Vec<String>,
    pub paths_deny: Vec<String>,
    pub shell_allow_prefixes: Vec<String>,
    pub shell_deny_regex: Vec<String>,
    pub shell_on_no_match: Option<RuleAction>,
}
```

- [ ] **Step 1: Write the failing test**

Add inside `mod tests`:

```rust
/// The seed policy is the fixture because it exercises every case.
#[test]
fn tool_matrix_of_the_seed_policy() {
    let yaml = include_str!("../../../policies/default.yaml");
    let p = Policy::parse_yaml(yaml).expect("seed policy parses");
    let names: Vec<String> = ["Read", "Edit", "Bash", "WebFetch", "mcp__cloudflare__kv_list", "Frobnicate"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let m: std::collections::HashMap<String, ToolStatus> =
        p.tool_matrix(&names).into_iter().collect();

    // Unconditional rules are safe to control.
    assert!(matches!(m["Read"], ToolStatus::Unconditional { action: RuleAction::Allow, .. }));
    assert!(matches!(m["WebFetch"], ToolStatus::Unconditional { action: RuleAction::Deny, .. }));
    assert!(matches!(
        m["mcp__cloudflare__kv_list"],
        ToolStatus::Unconditional { action: RuleAction::Approve, .. }
    ));

    // Conditional rules must NOT be flattened: "Edit -> Allow" is false (it is
    // allow-in-/workspace, deny-for-.env, ask-elsewhere).
    match &m["Edit"] {
        ToolStatus::Conditional { constraints, .. } => {
            assert!(constraints.paths_allow.iter().any(|g| g.contains("/workspace")));
            assert!(constraints.paths_deny.iter().any(|g| g.contains(".env")));
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
    assert!(matches!(m["Frobnicate"], ToolStatus::Default { action: RuleAction::Approve }));
}

#[test]
fn tool_matrix_reports_overrides_over_the_underlying_status() {
    let yaml = include_str!("../../../policies/default.yaml");
    let mut p = Policy::parse_yaml(yaml).expect("parses");
    p.managed_overrides.push(ToolOverride {
        tool: "mcp__cloudflare__kv_list".into(),
        action: RuleAction::Allow,
    });
    let m: std::collections::HashMap<String, ToolStatus> = p
        .tool_matrix(&["mcp__cloudflare__kv_list".to_string()])
        .into_iter()
        .collect();
    match &m["mcp__cloudflare__kv_list"] {
        ToolStatus::Overridden { action, underlying } => {
            assert_eq!(*action, RuleAction::Allow);
            // The page shows what clearing the override would restore.
            assert!(matches!(
                **underlying,
                ToolStatus::Unconditional { action: RuleAction::Approve, .. }
            ));
        }
        other => panic!("expected Overridden, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p fluidbox-core policy::tests::tool_matrix`
Expected: FAIL — `no method named tool_matrix found for struct Policy`.

- [ ] **Step 3: Write minimal implementation**

Add to `crates/fluidbox-core/src/policy.rs`:

```rust
/// The display-only constraint payload of a conditional rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConstraintSummary {
    #[serde(default)]
    pub paths_allow: Vec<String>,
    #[serde(default)]
    pub paths_deny: Vec<String>,
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
        action: RuleAction,
        rule: usize,
        constraints: ConstraintSummary,
    },
    Default {
        action: RuleAction,
    },
    Overridden {
        action: RuleAction,
        underlying: Box<ToolStatus>,
    },
}

impl ToolStatus {
    /// Only unconditional rows may be overridden from the UI. The server
    /// enforces this too — never the UI alone.
    pub fn is_overridable(&self) -> bool {
        match self {
            ToolStatus::Unconditional { .. } | ToolStatus::Default { .. } => true,
            ToolStatus::Overridden { underlying, .. } => underlying.is_overridable(),
            ToolStatus::Conditional { .. } => false,
        }
    }
}
```

Inside `impl Policy`:

```rust
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
    if let Some(o) = self.managed_overrides.iter().find(|o| o.tool == tool) {
        return ToolStatus::Overridden {
            action: o.action,
            underlying: Box::new(self.base_tool_status(tool)),
        };
    }
    self.base_tool_status(tool)
}

fn base_tool_status(&self, tool: &str) -> ToolStatus {
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p fluidbox-core`
Expected: PASS — all tests.

- [ ] **Step 5: Commit**

```bash
git add crates/fluidbox-core/src/policy.rs
git commit -m "feat(core): Policy::tool_matrix — resolve each tool's real status

Conditional (paths/shell) rules are reported as such rather than flattened:
evaluate takes a ToolCallRequest WITH INPUT, so 'Edit -> Allow' is false. The
matrix reuses tool_matches so the page and the gate cannot disagree about which
rule wins.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017mfjJE5FKtgc1rNvSZVVb9"
```

---

### Task 5: Migration 0010 + override-preserving upsert

**This is the one place the separate-column design bites** (design §4.7): `upsert_policy` rebuilds `parsed` from YAML alone, so without the merge the next `just policy-sync` silently drops every override.

> **CARRY-FORWARD FROM TASK 3'S REVIEW — do not skip.** Task 3 added an invariant to
> `Policy::validate()` that refuses an override targeting a conditional (`paths`/`shell`)
> rule. That check is currently **dead on every production path**: `parse_yaml` only sees
> authored YAML, which never carries overrides. It only fires when something validates the
> **merged** policy. So every path here that produces a merged policy must
> `parse_yaml → assign managed_overrides → validate() → serialize` and refuse on error.
> If you merge without re-validating, Task 3's entire fix is inert and `just policy-sync`
> will happily ship a policy whose `shell.deny_regex` can never fire.
>
> Assign `managed_overrides`, never append — it is a known serde field, so YAML could
> author one and appending would create a duplicate.
>
> This is `fluidbox-db`, which cannot return an `ApiError`. Do the merge+validate in the
> **API layer** (`api::upsert_policy`, and the override write/clear handlers in Task 8),
> keeping the `fluidbox-db` functions as the storage primitives. Where the plan below shows
> SQL doing the `parsed` rebuild, the validated Policy value from the API layer is the
> source of truth for what gets written.

**Files:**
- Create: `migrations/0010_policy_managed_overrides.sql`
- Modify: `crates/fluidbox-db/src/lib.rs`
- Test: `crates/fluidbox-db/src/lib.rs` (`#[cfg(test)] mod tests`, real Neon)

**Interfaces:**
- Consumes: `fluidbox_core::policy::{Policy, ToolOverride, RuleAction}`.
- Produces:
  - `PolicyRow.managed_overrides: Value`
  - `pub async fn set_policy_override(pool, tenant, name: &str, tool: &str, action: RuleAction) -> sqlx::Result<PolicyRow>`
  - `pub async fn clear_policy_override(pool, tenant, name: &str, tool: &str) -> sqlx::Result<PolicyRow>`

- [ ] **Step 1: Write the failing test**

Add to `crates/fluidbox-db`'s `mod tests` (line ~2706). It self-skips without
`DATABASE_URL`, exactly like every other test in that module:

```rust
#[tokio::test]
async fn upsert_preserves_managed_overrides() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };
    let pool = connect(&url).await.expect("connect");
    let tenant = ensure_default_tenant(&pool).await.unwrap();
    let yaml = "name: ov-test\ntools: []\n";
    let policy = fluidbox_core::policy::Policy::parse_yaml(yaml).unwrap();
    let parsed = serde_json::to_value(&policy).unwrap();
    upsert_policy(&pool, tenant, "ov-test", yaml, &parsed).await.unwrap();

    set_policy_override(
        &pool, tenant, "ov-test", "mcp__x__y",
        fluidbox_core::policy::RuleAction::Allow,
    ).await.unwrap();

    // A policy-sync re-push of the SAME yaml must not drop the override.
    let row = upsert_policy(&pool, tenant, "ov-test", yaml, &parsed).await.unwrap();
    let overrides: Vec<fluidbox_core::policy::ToolOverride> =
        serde_json::from_value(row.managed_overrides.clone()).unwrap();
    assert_eq!(overrides.len(), 1, "policy-sync dropped the override");
    assert_eq!(overrides[0].tool, "mcp__x__y");

    // …and `parsed` must carry it, because run_service evaluates from `parsed`.
    let effective: fluidbox_core::policy::Policy =
        serde_json::from_value(row.parsed.clone()).unwrap();
    assert_eq!(effective.managed_overrides.len(), 1);

    clear_policy_override(&pool, tenant, "ov-test", "mcp__x__y").await.unwrap();
    let row = get_policy_by_name(&pool, tenant, "ov-test").await.unwrap().unwrap();
    let effective: fluidbox_core::policy::Policy =
        serde_json::from_value(row.parsed.clone()).unwrap();
    assert!(effective.managed_overrides.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
set -a; source .env; set +a
cargo test -p fluidbox-db upsert_preserves_managed_overrides
```
Expected: FAIL — `no field managed_overrides on PolicyRow`, `cannot find function set_policy_override`.

- [ ] **Step 3: Write minimal implementation**

Create `migrations/0010_policy_managed_overrides.sql`:

```sql
-- UI-owned, per-tool policy overrides (Governance page).
--
-- Deliberately NOT part of yaml_source: that column is the AUTHORED policy and
-- stays git-owned (its comments carry the §10 decision reasoning). Keeping
-- overrides in their own column means `just policy-sync` can keep force-pushing
-- the base rules while UI decisions survive — the two never contend.
alter table policies
  add column managed_overrides jsonb not null default '[]'::jsonb;
```

In `crates/fluidbox-db/src/lib.rs`, add to `PolicyRow`:

```rust
    pub managed_overrides: Value,
```

Replace `upsert_policy` with an override-preserving version:

```rust
/// Upsert a policy's AUTHORED yaml. Existing `managed_overrides` are preserved
/// and merged into `parsed` — without this, the next `just policy-sync` would
/// silently drop every override made in the Governance page.
pub async fn upsert_policy(
    pool: &PgPool,
    tenant: Uuid,
    name: &str,
    yaml_source: &str,
    parsed: &Value,
) -> sqlx::Result<PolicyRow> {
    sqlx::query_as(
        "insert into policies (id, tenant_id, name, yaml_source, parsed)
         values ($1, $2, $3, $4, $5)
         on conflict (tenant_id, name) do update
           set yaml_source = excluded.yaml_source,
               parsed = jsonb_set(
                 excluded.parsed, '{managed_overrides}', policies.managed_overrides, true
               ),
               version = policies.version + 1,
               updated_at = now()
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(name)
    .bind(yaml_source)
    .bind(parsed)
    .fetch_one(pool)
    .await
}

/// Upsert ONE exact-name override and rebuild `parsed` from it.
pub async fn set_policy_override(
    pool: &PgPool,
    tenant: Uuid,
    name: &str,
    tool: &str,
    action: fluidbox_core::policy::RuleAction,
) -> sqlx::Result<PolicyRow> {
    let entry = serde_json::json!({ "tool": tool, "action": action });
    sqlx::query_as(
        "update policies
            set managed_overrides = (
                  select coalesce(jsonb_agg(e), '[]'::jsonb)
                    from jsonb_array_elements(managed_overrides) e
                   where e->>'tool' <> $3
                ) || jsonb_build_array($4::jsonb),
                version = version + 1,
                updated_at = now()
          where tenant_id = $1 and name = $2
         returning *",
    )
    .bind(tenant)
    .bind(name)
    .bind(tool)
    .bind(&entry)
    .fetch_one(pool)
    .await
    .and_then(|row| sync_parsed(pool, row))?
    .await
}

/// Remove ONE override; the tool falls back to whatever the base rules say.
pub async fn clear_policy_override(
    pool: &PgPool,
    tenant: Uuid,
    name: &str,
    tool: &str,
) -> sqlx::Result<PolicyRow> {
    sqlx::query_as(
        "update policies
            set managed_overrides = (
                  select coalesce(jsonb_agg(e), '[]'::jsonb)
                    from jsonb_array_elements(managed_overrides) e
                   where e->>'tool' <> $3
                ),
                version = version + 1,
                updated_at = now()
          where tenant_id = $1 and name = $2
         returning *",
    )
    .bind(tenant)
    .bind(name)
    .bind(tool)
    .fetch_one(pool)
    .await
    .and_then(|row| sync_parsed(pool, row))?
    .await
}
```

Add the shared `parsed` re-sync (keeps `parsed` = base ++ overrides, which is what
`run_service` evaluates from):

```rust
/// `run_service` reads `parsed`, so every override write must republish it.
async fn sync_parsed(pool: &PgPool, row: PolicyRow) -> sqlx::Result<PolicyRow> {
    sqlx::query_as(
        "update policies
            set parsed = jsonb_set(parsed, '{managed_overrides}', $2, true)
          where id = $1
         returning *",
    )
    .bind(row.id)
    .bind(&row.managed_overrides)
    .fetch_one(pool)
    .await
}
```

> Simplify the two `.and_then(...)?.await` chains to plain sequential `await`s if
> the borrow checker objects — the requirement is only that each write updates
> `managed_overrides` and then re-syncs `parsed`.

- [ ] **Step 4: Run test to verify it passes**

```bash
touch crates/fluidbox-db/src/lib.rs   # sqlx::migrate! bakes files at COMPILE time
set -a; source .env; set +a
cargo test -p fluidbox-db upsert_preserves_managed_overrides
```
Expected: PASS. (Stop `just dev` first — the DB tests want no server running.)

- [ ] **Step 5: Commit**

```bash
git add migrations/0010_policy_managed_overrides.sql crates/fluidbox-db/src/lib.rs
git commit -m "feat(db): managed_overrides column, preserved across policy-sync

The authored yaml stays git-owned and is never rewritten by the UI; overrides
live in their own column and are merged into parsed on every write. upsert
merges existing overrides back in — without that, the next policy-sync silently
drops every override.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017mfjJE5FKtgc1rNvSZVVb9"
```

---

### Task 6: `agents_using` + the MCP tool union

**Files:**
- Modify: `crates/fluidbox-db/src/lib.rs`
- Test: same file (real Neon)

**Interfaces:**
- Produces:
  - `pub async fn policy_agents_using(pool, tenant, policy_id: Uuid) -> sqlx::Result<i64>`
  - `pub async fn policy_mcp_tools(pool, tenant, policy_id: Uuid) -> sqlx::Result<Vec<String>>`

- [ ] **Step 1: Write the failing test**

```rust
/// Only the LATEST revision governs future runs, so only it may count toward a
/// policy's blast radius. Uses fresh policy names, so the shared default tenant's
/// other agents cannot perturb the counts.
#[tokio::test]
async fn policy_agents_using_counts_only_latest_revisions() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };
    let pool = connect(&url).await.expect("connect");
    let tenant = ensure_default_tenant(&pool).await.unwrap();

    let mk = |name: &str| format!("name: {name}\ntools: []\n");
    let (ya, yb) = (mk("pau-a"), mk("pau-b"));
    let pa = upsert_policy(
        &pool, tenant, "pau-a", &ya,
        &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(&ya).unwrap()).unwrap(),
    ).await.unwrap();
    let pb = upsert_policy(
        &pool, tenant, "pau-b", &yb,
        &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(&yb).unwrap()).unwrap(),
    ).await.unwrap();

    let agent = create_agent(&pool, tenant, "pau-agent", None).await.unwrap();
    let budgets = serde_json::json!({});
    let pins = serde_json::json!([]);
    let rev = |policy_id| {
        append_agent_revision(
            &pool, agent.id, "claude-agent-sdk", "img", "claude-haiku-4-5", None,
            policy_id, &budgets, None, &pins,
        )
    };

    rev(pa.id).await.unwrap();
    assert_eq!(policy_agents_using(&pool, tenant, pa.id).await.unwrap(), 1);
    assert_eq!(policy_agents_using(&pool, tenant, pb.id).await.unwrap(), 0);

    // Append a revision moving the agent to policy B: A drops to 0, B goes to 1.
    rev(pb.id).await.unwrap();
    assert_eq!(policy_agents_using(&pool, tenant, pa.id).await.unwrap(), 0);
    assert_eq!(policy_agents_using(&pool, tenant, pb.id).await.unwrap(), 1);
}
```

> `create_agent` upserts on `(tenant, name)` and `append_agent_revision` appends,
> so the test is re-runnable: it re-establishes A as the latest revision before
> asserting.

- [ ] **Step 2: Run test to verify it fails**

```bash
set -a; source .env; set +a
cargo test -p fluidbox-db policy_agents_using
```
Expected: FAIL — `cannot find function policy_agents_using`.

- [ ] **Step 3: Write minimal implementation**

```rust
/// Agents whose LATEST revision uses this policy — the blast radius of an
/// override. An older revision pointing here does not count: only the latest
/// revision governs future runs.
pub async fn policy_agents_using(pool: &PgPool, tenant: Uuid, policy_id: Uuid) -> sqlx::Result<i64> {
    sqlx::query_scalar(
        "select count(*) from agents a
          where a.tenant_id = $1
            and (
              select r.policy_id from agent_revisions r
               where r.agent_id = a.id
               order by r.rev desc
               limit 1
            ) = $2",
    )
    .bind(tenant)
    .bind(policy_id)
    .fetch_one(pool)
    .await
}

/// The union of mcp__* tool names from the capability bundles pinned on the
/// LATEST revision of every agent using this policy. This is what makes a
/// connected server's tools appear in the matrix without anyone typing them.
pub async fn policy_mcp_tools(
    pool: &PgPool,
    tenant: Uuid,
    policy_id: Uuid,
) -> sqlx::Result<Vec<String>> {
    let pins: Vec<Value> = sqlx::query_scalar(
        "select r.capability_bundles from agents a
           join lateral (
             select * from agent_revisions r2
              where r2.agent_id = a.id order by r2.rev desc limit 1
           ) r on true
          where a.tenant_id = $1 and r.policy_id = $2",
    )
    .bind(tenant)
    .bind(policy_id)
    .fetch_all(pool)
    .await?;

    let mut ids: Vec<Uuid> = Vec::new();
    for p in &pins {
        if let Some(arr) = p.as_array() {
            for r in arr {
                if let Some(id) = r.get("id").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()) {
                    ids.push(id);
                }
            }
        }
    }
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Ok(vec![]);
    }

    let defs: Vec<Value> = sqlx::query_scalar(
        "select definition from capability_bundles where tenant_id = $1 and id = any($2)",
    )
    .bind(tenant)
    .bind(&ids)
    .fetch_all(pool)
    .await?;

    let mut out: Vec<String> = Vec::new();
    for def in &defs {
        let Some(servers) = def.get("servers").and_then(|v| v.as_array()) else { continue };
        for s in servers {
            let Some(server) = s.get("name").and_then(|v| v.as_str()) else { continue };
            let Some(tools) = s.get("tools").and_then(|v| v.as_array()) else { continue };
            for t in tools {
                if let Some(tool) = t.get("name").and_then(|v| v.as_str()) {
                    out.push(format!("mcp__{server}__{tool}"));
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
set -a; source .env; set +a
cargo test -p fluidbox-db policy_agents_using
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/fluidbox-db/src/lib.rs
git commit -m "feat(db): policy_agents_using + policy_mcp_tools

agents_using is the blast radius an override header must state; policy_mcp_tools
is the union that makes a connected server's photographed tools appear in the
matrix without anyone typing them.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017mfjJE5FKtgc1rNvSZVVb9"
```

---

### Task 7: API — enrich the list, add the detail route

**Files:**
- Modify: `crates/fluidbox-server/src/api.rs`
- Modify: `crates/fluidbox-server/src/main.rs`

**Interfaces:**
- Consumes: `Policy::{autonomy_summary, tool_matrix}`, `tools::CANONICAL`, `policy_agents_using`, `policy_mcp_tools`.
- Produces: `GET /v1/policies` (+`autonomy_summary`, +`agents_using`), `GET /v1/policies/{name}`.

- [ ] **Step 1: Write the failing test**

There is no HTTP test harness for `api.rs`; the e2e drives these over real HTTP. Verify by hand in Step 4 instead, then add the assertion to the e2e in Task 11.

- [ ] **Step 2: (skipped — see Step 1)**

- [ ] **Step 3: Write the implementation**

Replace `list_policies` in `crates/fluidbox-server/src/api.rs`:

```rust
pub async fn list_policies(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let rows = fluidbox_db::list_policies(&state.pool, state.tenant_id).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let policy: Policy = serde_json::from_value(row.parsed.clone())
            .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;
        let agents_using = fluidbox_db::policy_agents_using(&state.pool, state.tenant_id, row.id).await?;
        out.push(json!({
            "id": row.id,
            "name": row.name,
            "version": row.version,
            "updated_at": row.updated_at,
            "autonomy_summary": policy.autonomy_summary(),
            "agents_using": agents_using,
        }));
    }
    Ok(Json(json!({ "policies": out })))
}

/// The Governance page's detail payload. The dashboard renders this verbatim —
/// it never parses YAML and never resolves policy semantics.
pub async fn get_policy(
    _: Admin,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let row = fluidbox_db::get_policy_by_name(&state.pool, state.tenant_id, &name)
        .await?
        .ok_or(ApiError::NotFound)?;
    let policy: Policy = serde_json::from_value(row.parsed.clone())
        .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;

    let mut names: Vec<String> = fluidbox_core::tools::CANONICAL
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    names.extend(fluidbox_db::policy_mcp_tools(&state.pool, state.tenant_id, row.id).await?);

    let matrix: Vec<Value> = policy
        .tool_matrix(&names)
        .into_iter()
        .map(|(tool, status)| {
            let group = fluidbox_core::tools::CANONICAL
                .iter()
                .find(|t| t.name == tool)
                .map(|t| serde_json::to_value(t.group).unwrap_or(Value::Null))
                .unwrap_or(Value::Null);
            let server = tool
                .strip_prefix("mcp__")
                .and_then(|r| r.split_once("__"))
                .map(|(s, _)| s.to_string());
            json!({
                "tool": tool,
                "group": group,
                "server": server,
                "overridable": status.is_overridable(),
                "status": status,
            })
        })
        .collect();

    Ok(Json(json!({
        "policy": {
            "id": row.id,
            "name": row.name,
            "version": row.version,
            "updated_at": row.updated_at,
        },
        "agents_using": fluidbox_db::policy_agents_using(&state.pool, state.tenant_id, row.id).await?,
        "autonomy_summary": policy.autonomy_summary(),
        "defaults": policy.defaults,
        "budgets": policy.budgets,
        "approvals": policy.approvals,
        "egress": policy.egress,
        "matrix": matrix,
    })))
}
```

In `crates/fluidbox-server/src/main.rs`, beside the existing `/policies` route:

```rust
        .route("/policies/{name}", get(api::get_policy))
```

> Place it AFTER `.route("/policies/validate", …)` so the literal path wins over
> the `{name}` capture.

- [ ] **Step 4: Verify by hand**

```bash
just server   # in another shell
set -a; source .env; set +a
curl -s localhost:8787/v1/policies -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" | jq '.policies[0]'
curl -s localhost:8787/v1/policies/default -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" \
  | jq '{agents_using, autonomy_summary, edit: (.matrix[] | select(.tool=="Edit"))}'
```
Expected: `autonomy_summary` = `{permitted: true, default_fallback: "deny", allow_overrides: 0, deny_overrides: 0}`; the `Edit` row has `status.status == "conditional"` and `overridable == false`.

- [ ] **Step 5: Commit**

```bash
git add crates/fluidbox-server/src/api.rs crates/fluidbox-server/src/main.rs
git commit -m "feat(api): policy autonomy summary, agents_using, and the tool matrix

GET /v1/policies/{name} returns a fully-resolved matrix so the dashboard can
render governance without parsing YAML or resolving policy semantics.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017mfjJE5FKtgc1rNvSZVVb9"
```

---

### Task 8: API — override write + clear, with server-side refusal

**Files:**
- Modify: `crates/fluidbox-server/src/api.rs`
- Modify: `crates/fluidbox-server/src/main.rs`

**Interfaces:**
- Consumes: `set_policy_override`, `clear_policy_override`, `Policy::tool_matrix`, `ToolStatus::is_overridable`.
- Produces: `PUT /v1/policies/{name}/overrides/{tool}` `{action}`; `DELETE /v1/policies/{name}/overrides/{tool}`.

- [ ] **Step 1: Write the implementation**

```rust
#[derive(Deserialize)]
pub struct SetOverride {
    pub action: RuleAction,
}

/// The server enforces what the UI renders — never the UI alone. A conditional
/// rule's verdict depends on the path touched or the command run, so a flat
/// action cannot express it and flattening it would delete the rule's
/// paths.deny / shell constraints.
pub async fn put_policy_override(
    _: Admin,
    State(state): State<AppState>,
    Path((name, tool)): Path<(String, String)>,
    Json(req): Json<SetOverride>,
) -> ApiResult<Json<Value>> {
    let row = fluidbox_db::get_policy_by_name(&state.pool, state.tenant_id, &name)
        .await?
        .ok_or(ApiError::NotFound)?;
    let policy: Policy = serde_json::from_value(row.parsed.clone())
        .map_err(|e| ApiError::Internal(format!("bad stored policy: {e}")))?;

    // Exact names only — a wildcard override would be an un-reviewable blanket
    // rule authored by a click.
    if !fluidbox_core::tools::is_canonical(&tool) && !fluidbox_core::tools::is_mcp(&tool) {
        return Err(ApiError::BadRequest(format!(
            "'{tool}' is not a known tool — overrides take exact canonical or mcp__* names"
        )));
    }
    let status = policy
        .tool_matrix(std::slice::from_ref(&tool))
        .pop()
        .map(|(_, s)| s)
        .ok_or_else(|| ApiError::Internal("tool_matrix returned no row".into()))?;
    if !status.is_overridable() {
        return Err(ApiError::BadRequest(format!(
            "'{tool}' is governed by a conditional rule (paths/shell); its verdict depends on \
             the path touched or command run, so it cannot be set to a single action"
        )));
    }

    let row =
        fluidbox_db::set_policy_override(&state.pool, state.tenant_id, &name, &tool, req.action)
            .await?;
    Ok(Json(json!({ "policy": { "name": row.name, "version": row.version } })))
}

pub async fn delete_policy_override(
    _: Admin,
    State(state): State<AppState>,
    Path((name, tool)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    fluidbox_db::get_policy_by_name(&state.pool, state.tenant_id, &name)
        .await?
        .ok_or(ApiError::NotFound)?;
    let row =
        fluidbox_db::clear_policy_override(&state.pool, state.tenant_id, &name, &tool).await?;
    Ok(Json(json!({ "policy": { "name": row.name, "version": row.version } })))
}
```

In `main.rs`:

```rust
        .route(
            "/policies/{name}/overrides/{tool}",
            put(api::put_policy_override).delete(api::delete_policy_override),
        )
```

Add `put` to the `axum::routing` import list if absent.

- [ ] **Step 2: Verify the refusal by hand**

```bash
set -a; source .env; set +a
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"

# Conditional rule -> 400 (this is the guardrail)
curl -s -o /dev/null -w '%{http_code}\n' -X PUT localhost:8787/v1/policies/default/overrides/Edit \
  -H "$H" -H 'content-type: application/json' -d '{"action":"allow"}'   # expect 400

# Unknown tool -> 400
curl -s -o /dev/null -w '%{http_code}\n' -X PUT localhost:8787/v1/policies/default/overrides/Nope \
  -H "$H" -H 'content-type: application/json' -d '{"action":"allow"}'   # expect 400

# Unconditional -> 200, and it takes effect
curl -s -X PUT localhost:8787/v1/policies/default/overrides/WebFetch \
  -H "$H" -H 'content-type: application/json' -d '{"action":"allow"}' | jq
curl -s localhost:8787/v1/policies/default -H "$H" \
  | jq '.matrix[] | select(.tool=="WebFetch") | .status'   # expect status: "overridden"
curl -s -X DELETE localhost:8787/v1/policies/default/overrides/WebFetch -H "$H" | jq
```

- [ ] **Step 3: Commit**

```bash
git add crates/fluidbox-server/src/api.rs crates/fluidbox-server/src/main.rs
git commit -m "feat(api): per-tool policy override write + clear

Refuses conditional rules and unknown tools server-side: the server enforces
what the UI renders, never the UI alone.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017mfjJE5FKtgc1rNvSZVVb9"
```

---

### Task 9: Web — `/governance` list + nav

**Files:**
- Create: `apps/web/app/governance/page.tsx`
- Modify: `apps/web/app/components/Sidebar.tsx`

**Interfaces:**
- Consumes: `GET /v1/policies` → `{policies: [{id, name, version, agents_using, autonomy_summary}]}`.

> Read `apps/web/AGENTS.md` first: this is **not** the Next.js you know — check
> `node_modules/next/dist/docs/` before writing. Match the existing pages'
> fetch/`apiGet` helper and class conventions (`apps/web/app/lib/api.ts`,
> `apps/web/app/capabilities/page.tsx`).

- [ ] **Step 1: Write the page**

```tsx
"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet } from "../lib/api";

type AutonomySummary = {
  permitted: boolean;
  default_fallback: "allow" | "deny";
  allow_overrides: number;
  deny_overrides: number;
};
type PolicyRow = {
  id: string;
  name: string;
  version: number;
  agents_using: number;
  autonomy_summary: AutonomySummary;
};

export default function GovernancePage() {
  const [policies, setPolicies] = useState<PolicyRow[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    apiGet<{ policies: PolicyRow[] }>("/policies")
      .then((r) => setPolicies(r.policies))
      .catch((reason) => setErr(`Policies could not be loaded. ${String(reason)}`));
  }, []);

  return (
    <main className="stage">
      <div className="stage-heading">
        <span className="section-kicker">Governance</span>
        <h1>Policies</h1>
        <p>What your agents are allowed to do, and what happens when they ask.</p>
      </div>
      {err && <p className="error">{err}</p>}
      <ul className="policy-list">
        {policies.map((p) => (
          <li key={p.id}>
            <Link href={`/governance/${p.name}`} className="policy-row">
              <strong>{p.name}</strong>
              <span className="faint">v{p.version}</span>
              <span className="faint">
                {p.agents_using} {p.agents_using === 1 ? "agent" : "agents"}
              </span>
              <span className="faint">
                {p.autonomy_summary.permitted
                  ? `Unattended runs allowed · risky actions ${p.autonomy_summary.default_fallback === "deny" ? "denied" : "allowed"} by default`
                  : "Unattended runs not permitted"}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </main>
  );
}
```

- [ ] **Step 2: Add the nav item**

In `apps/web/app/components/Sidebar.tsx`, after the Activity link and before Settings, matching the existing `<Link>` pattern:

```tsx
          <Link className={pathname.startsWith("/governance") ? "active" : ""} href="/governance">
            Governance
          </Link>
```

- [ ] **Step 3: Verify**

```bash
just web
```
Open `http://localhost:3000/governance`. Expected: `default` listed with its version, agent count, and "risky actions denied by default".

- [ ] **Step 4: Commit**

```bash
git add apps/web/app/governance/page.tsx apps/web/app/components/Sidebar.tsx
git commit -m "feat(web): /governance policy list

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017mfjJE5FKtgc1rNvSZVVb9"
```

---

### Task 10: Web — the permissions matrix

**Files:**
- Create: `apps/web/app/components/PermissionMatrix.tsx`
- Create: `apps/web/app/governance/[name]/page.tsx`

**Interfaces:**
- Consumes: `GET /v1/policies/{name}`; `PUT|DELETE /v1/policies/{name}/overrides/{tool}`.

- [ ] **Step 1: Write the matrix component**

```tsx
"use client";

type Action = "allow" | "approve" | "deny";
type Status =
  | { status: "unconditional"; action: Action }
  | { status: "conditional"; action: Action; constraints: Constraints }
  | { status: "default"; action: Action }
  | { status: "overridden"; action: Action; underlying: Status };
type Constraints = {
  paths_allow: string[];
  paths_deny: string[];
  shell_allow_prefixes: string[];
  shell_deny_regex: string[];
  shell_on_no_match: Action | null;
};
export type Row = {
  tool: string;
  group: string | null;
  server: string | null;
  overridable: boolean;
  status: Status;
};

const VERB: Record<Action, string> = { allow: "Allow", approve: "Ask", deny: "Deny" };

/** Why a conditional rule is shown instead of offered as a control. */
function describe(c: Constraints): string {
  const parts: string[] = [];
  if (c.paths_allow.length) parts.push(`Allowed in ${c.paths_allow.join(", ")}`);
  if (c.paths_deny.length) parts.push(`never ${c.paths_deny.join(", ")}`);
  if (c.shell_allow_prefixes.length) parts.push(`allowed for ${c.shell_allow_prefixes.length} known-safe commands`);
  if (c.shell_deny_regex.length) parts.push(`${c.shell_deny_regex.length} blocked patterns`);
  if (c.shell_on_no_match) parts.push(`otherwise ${VERB[c.shell_on_no_match].toLowerCase()}`);
  return parts.join(" · ");
}

export function PermissionMatrix({
  rows,
  onSet,
  onClear,
}: {
  rows: Row[];
  onSet: (tool: string, action: Action) => void;
  onClear: (tool: string) => void;
}) {
  return (
    <ul className="matrix">
      {rows.map((row) => {
        const overridden = row.status.status === "overridden";
        const effective = row.status.action;
        return (
          <li key={row.tool} className="matrix-row">
            <span className="matrix-tool">{row.tool}</span>

            {row.status.status === "conditional" ? (
              // Never a control: evaluate() depends on the path touched or the
              // command run, so a flat action cannot express this — and setting
              // one would delete the rule's paths.deny / shell constraints.
              <span className="matrix-conditional faint">{describe(row.status.constraints)}</span>
            ) : (
              <fieldset className="matrix-choice">
                <legend className="sr-only">{row.tool}</legend>
                {(["allow", "approve", "deny"] as Action[]).map((a) => (
                  <label key={a} className={effective === a ? "on" : ""}>
                    <input
                      type="radio"
                      name={`perm-${row.tool}`}
                      value={a}
                      checked={effective === a}
                      onChange={() => onSet(row.tool, a)}
                    />
                    {VERB[a]}
                  </label>
                ))}
              </fieldset>
            )}

            {overridden && (
              <button type="button" className="matrix-clear" onClick={() => onClear(row.tool)}>
                Overridden — clear
              </button>
            )}
            {row.status.status === "default" && <span className="faint">policy default</span>}
          </li>
        );
      })}
    </ul>
  );
}
```

- [ ] **Step 2: Write the detail page**

```tsx
"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { apiDelete, apiGet, apiPut } from "../../lib/api";
import { PermissionMatrix, type Row } from "../../components/PermissionMatrix";

type Detail = {
  policy: { name: string; version: number };
  agents_using: number;
  autonomy_summary: {
    permitted: boolean;
    default_fallback: "allow" | "deny";
    allow_overrides: number;
    deny_overrides: number;
  };
  matrix: Row[];
};

export default function PolicyDetail() {
  const { name } = useParams<{ name: string }>();
  const [d, setD] = useState<Detail | null>(null);
  const [err, setErr] = useState("");

  const load = useCallback(() => {
    apiGet<Detail>(`/policies/${name}`)
      .then(setD)
      .catch((reason) => setErr(`This policy could not be loaded. ${String(reason)}`));
  }, [name]);

  useEffect(load, [load]);

  const onSet = async (tool: string, action: string) => {
    try {
      await apiPut(`/policies/${name}/overrides/${tool}`, { action });
      load();
    } catch (reason) {
      setErr(String(reason));
    }
  };
  const onClear = async (tool: string) => {
    try {
      await apiDelete(`/policies/${name}/overrides/${tool}`);
      load();
    } catch (reason) {
      setErr(String(reason));
    }
  };

  if (!d) return <main className="stage">{err ? <p className="error">{err}</p> : null}</main>;

  const a = d.autonomy_summary;
  const contrary = a.default_fallback === "deny" ? a.allow_overrides : a.deny_overrides;
  const contraryVerb = a.default_fallback === "deny" ? "allow" : "deny";

  return (
    <main className="stage">
      <div className="stage-heading">
        <span className="section-kicker">Governance</span>
        <h1>{d.policy.name}</h1>
        <p>
          Changes affect future runs of all {d.agents_using}{" "}
          {d.agents_using === 1 ? "agent" : "agents"} on this policy. Runs already in flight keep
          the policy they started with.
        </p>
      </div>
      {err && <p className="error">{err}</p>}

      <section className="panel">
        <h2>Unattended runs</h2>
        {a.permitted ? (
          <p>
            Allowed. When an action needs approval, it is{" "}
            <strong>{a.default_fallback === "deny" ? "denied" : "allowed"}</strong> automatically.
            {contrary > 0 && ` ${contrary} rule${contrary === 1 ? "" : "s"} ${contraryVerb} instead.`}
          </p>
        ) : (
          <p>Not permitted by this policy.</p>
        )}
      </section>

      <section className="panel">
        <h2>What agents may do</h2>
        <PermissionMatrix rows={d.matrix} onSet={onSet} onClear={onClear} />
      </section>
    </main>
  );
}
```

> If `apiPut` / `apiDelete` do not exist in `apps/web/app/lib/api.ts`, add them
> mirroring the existing `apiPost` (same admin-proxy path and error handling).

- [ ] **Step 3: Verify**

```bash
just dev
```
Open `http://localhost:3000/governance/default`. Expected: `Edit` and `Bash` render as read-only sentences with no control; `Read` / `WebFetch` / any `mcp__*` render live three-way controls; setting one shows "Overridden — clear"; clearing restores the base action.

- [ ] **Step 4: Commit**

```bash
git add apps/web/app/components/PermissionMatrix.tsx "apps/web/app/governance/[name]/page.tsx" apps/web/app/lib/api.ts
git commit -m "feat(web): the permissions matrix

Conditional rules render as sentences, never controls — a flat action cannot
express a verdict that depends on the path touched or command run, and offering
one would let a click delete paths.deny: **/.env.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017mfjJE5FKtgc1rNvSZVVb9"
```

---

### Task 11: e2e coverage + full check

**Files:**
- Modify: `scripts/e2e-capabilities.sh` (or a new `scripts/e2e-governance.sh` following its shape)

- [ ] **Step 1: Add the e2e assertions**

Following the existing `post`/`get` helper style in `scripts/e2e-lib.sh`, assert:

1. `GET /v1/policies/default` returns `autonomy_summary.default_fallback == "deny"`.
2. `PUT /v1/policies/default/overrides/Edit` → **400** (conditional rule refused).
3. `PUT /v1/policies/default/overrides/WebFetch {"action":"allow"}` → 200; the matrix row for `WebFetch` becomes `overridden`.
4. Re-POST `policies/default.yaml` to `/v1/policies` (the policy-sync path) → the `WebFetch` override **survives**.
5. `DELETE .../overrides/WebFetch` → 200; the row returns to `unconditional`/`deny`.

- [ ] **Step 2: Run the full bar**

```bash
just check
```
Expected: fmt clean, clippy clean (`-D warnings`), all tests pass, web builds.

- [ ] **Step 3: Commit**

```bash
git add scripts/
git commit -m "test(e2e): governance matrix — conditional refusal and override survival

Asserts the two failure modes that matter: a conditional rule cannot be
flattened, and policy-sync cannot silently drop an override.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017mfjJE5FKtgc1rNvSZVVb9"
```

---

## Self-Review

**Spec coverage:**

| Design §  | Task |
|---|---|
| §4.1 objects (migration, `ToolOverride`, `Policy.managed_overrides`) | 3, 5 |
| §4.2 vocabulary as data | 1 |
| §4.3 `tool_matrix` / `AutonomySummary` | 2, 4 |
| §4.4 which tools the page shows (CANONICAL ∪ bundle mcp tools) | 6, 7 |
| §4.5 evaluation change (overrides first) | 3 |
| §4.6 API (list enrich, detail, PUT/DELETE + refusals) | 7, 8 |
| §4.7 upsert merge | 5 |
| §4.8 dashboard (list, detail, matrix, blast-radius header) | 9, 10 |
| §5 threat table | 3 (exact-name), 4 (`is_overridable`), 8 (server-side refusal), 5 (override survival) |
| §6 testing | 1–6, 11 |

Not covered by a task, deliberately (design §4.9 / "Out of scope"): ledger enrichment, policy history/rollback, policy-sync changes, the wizard radio cards.

**Type consistency:** `AutonomySummary` fields (`permitted`, `default_fallback`, `allow_overrides`, `deny_overrides`) are identical in Tasks 2, 7, 9, 10. `ToolStatus` variants are `snake_case` on the wire (`#[serde(tag = "status")]`, Task 4) and matched as `"unconditional" | "conditional" | "default" | "overridden"` in Task 10. `RuleAction` serializes `allow | approve | deny` (existing `#[serde(rename_all = "snake_case")]`) and the web `Action` type matches. `set_policy_override` / `clear_policy_override` signatures are identical in Tasks 5 and 8.

**Known risk:** Task 5's `sync_parsed` chaining is written for clarity, not borrow-checker fidelity — the note there permits sequential awaits. The requirement is behavioural: every override write updates `managed_overrides` **and** republishes `parsed`, because `run_service` evaluates from `parsed`.
