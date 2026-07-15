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
];

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
