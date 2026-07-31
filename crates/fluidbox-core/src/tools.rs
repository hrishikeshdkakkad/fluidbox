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
    ToolDef {
        name: "Read",
        group: ToolGroup::Files,
    },
    ToolDef {
        name: "Write",
        group: ToolGroup::Files,
    },
    ToolDef {
        name: "Edit",
        group: ToolGroup::Files,
    },
    ToolDef {
        name: "MultiEdit",
        group: ToolGroup::Files,
    },
    ToolDef {
        name: "NotebookRead",
        group: ToolGroup::Files,
    },
    ToolDef {
        name: "NotebookEdit",
        group: ToolGroup::Files,
    },
    ToolDef {
        name: "Glob",
        group: ToolGroup::Search,
    },
    ToolDef {
        name: "Grep",
        group: ToolGroup::Search,
    },
    ToolDef {
        name: "LS",
        group: ToolGroup::Search,
    },
    ToolDef {
        name: "Bash",
        group: ToolGroup::Shell,
    },
    ToolDef {
        name: "BashOutput",
        group: ToolGroup::Shell,
    },
    ToolDef {
        name: "KillShell",
        group: ToolGroup::Shell,
    },
    ToolDef {
        name: "WebFetch",
        group: ToolGroup::Web,
    },
    ToolDef {
        name: "WebSearch",
        group: ToolGroup::Web,
    },
    ToolDef {
        name: "TodoWrite",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "Task",
        group: ToolGroup::Meta,
    },
    // Tool-schema discovery. Registered because the gate can now SEE it: until
    // the Claude runner's PreToolUse hook landed, the CLI auto-approved this
    // class and the calls never reached /permission, so the vocabulary never
    // had to name it. Now every call arrives, the seed policy has an opinion
    // about it, and the Governance matrix must list that opinion.
    ToolDef {
        name: "ToolSearch",
        group: ToolGroup::Meta,
    },
    // ── The rest of the pinned Claude Code CLI's advertised surface ─────────
    //
    // Same second-order consequence as ToolSearch above, at scale. Making the
    // gate mandatory did not only change ENFORCEMENT, it changed WHICH NAMES
    // the control plane ever sees: 23 tools the CLI advertises used to be
    // auto-approved below `canUseTool` and so never needed a vocabulary entry.
    // They now all arrive at `/permission`, where an unregistered name is
    // un-enumerable (absent from the Governance matrix) and an ungoverned name
    // falls to `defaults.tool_action`. Registering them is what lets the seed
    // policy state a deliberate opinion per tool instead of one blanket
    // fallback. Grouped into the EXISTING five groups on purpose — a new
    // ToolGroup variant needs a matching label in the dashboard's
    // PermissionMatrix or the row renders unlabelled.
    //
    // The dispositions live in policies/default.yaml and are pinned by
    // `seed_policy_governs_the_advertised_surface` in policy.rs. Three classes:
    //   * observational (no side effect)         → allow
    //   * NESTING (spawns sub-execution)         → deny, see below
    //   * persistent/external side effect        → approve
    //
    // NESTING IS THE LOAD-BEARING ONE. `Agent`, `Task`, `Workflow`, `Skill` and
    // `TaskCreate` start execution whose nested tool calls may never surface as
    // top-level tool_use/tool_result blocks — so they would be neither routed
    // by the PreToolUse hook nor caught by the GateWitness tripwire, which
    // documents itself as "a knowingly incomplete detector" (contract.mjs). A
    // human approving one of these authorises an unbounded, unobserved tool
    // tree, which is why the seed DENIES them rather than asking.
    ToolDef {
        name: "Agent",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "Workflow",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "Skill",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "TaskCreate",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "TaskGet",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "TaskList",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "TaskOutput",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "TaskStop",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "TaskUpdate",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "SendMessage",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "AskUserQuestion",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "EnterPlanMode",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "ExitPlanMode",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "ReportFindings",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "Monitor",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "CronCreate",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "CronDelete",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "CronList",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "ScheduleWakeup",
        group: ToolGroup::Meta,
    },
    ToolDef {
        name: "PushNotification",
        group: ToolGroup::Meta,
    },
    // Egress-shaped: syncs to an external design service. Grouped with the
    // other network tools so the matrix shows it beside WebFetch/WebSearch.
    ToolDef {
        name: "DesignSync",
        group: ToolGroup::Web,
    },
    // Git worktree context switches. Shell, not Files: they create and move
    // between trees rather than editing a file, and `EnterWorktree` can put the
    // agent somewhere the Edit rule's `/workspace/**` assumption no longer
    // describes.
    ToolDef {
        name: "EnterWorktree",
        group: ToolGroup::Shell,
    },
    ToolDef {
        name: "ExitWorktree",
        group: ToolGroup::Shell,
    },
];

/// Tools that start execution whose nested tool calls the gate may never see.
///
/// Kept as data so the seed-policy test can assert the seed never `allow`s one,
/// and so a future harness that proves nested calls DO reach `/permission` has a
/// single place to revise. See the NESTING note in `CANONICAL`.
pub const NESTING: &[&str] = &["Agent", "Task", "Workflow", "Skill", "TaskCreate"];

/// Is this an exact canonical tool name? (Not a matcher — no wildcards.)
pub fn is_canonical(name: &str) -> bool {
    CANONICAL.iter().any(|t| t.name == name)
}

/// Is this a brokered/sandbox MCP tool name (`mcp__<server>__<tool>`)?
pub fn is_mcp(name: &str) -> bool {
    name.starts_with("mcp__")
}

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
