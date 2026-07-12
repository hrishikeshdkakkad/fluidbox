//! Boot-time seeds: the default tenant, policies from `policies/*.yaml`,
//! and one curated agent definition (the Claude runner).

use crate::*;
use fluidbox_core::policy::Policy;
use std::path::Path;

pub struct SeedOutcome {
    pub tenant_id: Uuid,
    pub default_agent: String,
}

pub async fn run(
    pool: &PgPool,
    policies_dir: &Path,
    harness: &str,
    sandbox_image: &str,
    default_model: &str,
) -> anyhow::Result<SeedOutcome> {
    let tenant = ensure_default_tenant(pool).await?;

    // Policies from disk (idempotent upsert; version bumps on change).
    let mut default_policy_id = None;
    let mut default_policy_budgets = None;
    if policies_dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(policies_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|x| x == "yaml" || x == "yml")
                    .unwrap_or(false)
            })
            .collect();
        entries.sort_by_key(|e| e.path());
        for entry in entries {
            let yaml = std::fs::read_to_string(entry.path())?;
            match Policy::parse_yaml(&yaml) {
                Ok(policy) => {
                    let parsed = serde_json::to_value(&policy)?;
                    // Bootstrap only when absent — never clobber UI edits on reboot.
                    let (row, inserted) =
                        seed_policy_if_absent(pool, tenant, &policy.name, &yaml, &parsed).await?;
                    if inserted {
                        tracing::info!(policy = %policy.name, "seeded policy from disk");
                    } else {
                        tracing::debug!(policy = %policy.name, version = row.version, "policy exists; leaving UI-managed version intact");
                    }
                    if policy.name == "default" {
                        default_policy_id = Some(row.id);
                        default_policy_budgets = Some(policy.budgets.clone());
                    }
                }
                Err(e) => {
                    tracing::error!(file = %entry.path().display(), "invalid seed policy: {e}");
                }
            }
        }
    }

    let default_policy_id = match default_policy_id {
        Some(id) => id,
        None => {
            // Guarantee a fail-safe policy exists even with an empty dir.
            let p = Policy::parse_yaml("name: default").unwrap();
            seed_policy_if_absent(
                pool,
                tenant,
                "default",
                "name: default",
                &serde_json::to_value(&p)?,
            )
            .await?
            .0
            .id
        }
    };

    // The curated M1 agent: Claude Agent SDK harness, default policy.
    let agent = create_agent(
        pool,
        tenant,
        "claude-fixer",
        Some("General coding agent on the Claude Agent SDK. Reads, edits, runs tests."),
    )
    .await?;
    if latest_revision(pool, agent.id).await?.is_none() {
        // The seed policy's budgets are the source of truth for the curated
        // agent; Budgets::default() is only the no-policy fallback.
        let budgets = serde_json::to_value(default_policy_budgets.unwrap_or_default())?;
        append_agent_revision(
            pool,
            agent.id,
            harness,
            sandbox_image,
            default_model,
            None,
            default_policy_id,
            &budgets,
            None,
            &serde_json::json!([]),
        )
        .await?;
        tracing::info!("seeded agent claude-fixer rev 1");
    }

    Ok(SeedOutcome {
        tenant_id: tenant,
        default_agent: "claude-fixer".into(),
    })
}
