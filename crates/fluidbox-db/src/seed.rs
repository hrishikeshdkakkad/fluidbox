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
    // The boot seed owns the default tenant — a verified scope by construction.
    let scope = TenantScope::assume(tenant);

    // Policies from disk (seed-if-absent; an absent policy gets its identity
    // and version 1, author 'seed', in one transaction).
    seed_policies_from_dir(pool, scope, policies_dir).await?;

    // The default policy is resolved HERE, in ONE place, from the DATABASE —
    // not per-file while seeding. Both parts of that matter:
    //
    //   • ONE place, so every route into this line agrees: `default.yaml`
    //     present and valid, present but invalid (warned above), or absent
    //     entirely. Resolving it inside the seeding loop made it conditional
    //     on a `default.yaml` EXISTING, which silently handed the curated
    //     agent `Budgets::default()` whenever the file was not there — a
    //     ceiling nobody configured.
    //   • from the DATABASE, because what actually caps a run is the version
    //     the control plane will evaluate. On a fresh database that is the
    //     disk document; on an existing one (UI-edited, or a file we just
    //     warned about) only the stored version is true.
    //
    // `seed_policy_if_absent` is the no-op-or-bootstrap that guarantees a
    // fail-safe `default` exists even with an empty policies dir.
    let bare = Policy::parse_yaml("name: default").unwrap();
    let (default_policy, _) = seed_policy_if_absent(
        pool,
        scope,
        "default",
        "name: default",
        &serde_json::to_value(&bare)?,
    )
    .await?;
    let default_policy_id = default_policy.id;
    // A policy with zero versions is a bug, not a state (design §4.2). For
    // `default` it is a bug that would make EVERY run fail closed at
    // `create_run`, after provisioning — so refuse the boot instead, where the
    // message can name the row. `seed_policy_if_absent` cannot heal it: the
    // identity already exists, so it no-ops, and minting v1 from disk over
    // someone else's version-less policy would be a guess.
    let default_policy_budgets = latest_policy_version(pool, scope, default_policy_id)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "policy 'default' ({default_policy_id}) has no versions — every run on it \
                 would fail closed after provisioning; repair the row before booting"
            )
        })
        .and_then(|v| {
            serde_json::from_value::<Policy>(v.content)
                .map_err(|e| anyhow::anyhow!("stored default policy does not deserialize: {e}"))
        })?
        .budgets;

    // The curated M1 agent: Claude Agent SDK harness, default policy.
    let agent = create_agent(
        pool,
        scope,
        "claude-fixer",
        Some("General coding agent on the Claude Agent SDK. Reads, edits, runs tests."),
    )
    .await?;
    if latest_revision(pool, scope, agent.id).await?.is_none() {
        // The GOVERNING version's budgets are the source of truth for the
        // curated agent — resolved above, from the database, on every path.
        let budgets = serde_json::to_value(default_policy_budgets)?;
        append_agent_revision(
            pool,
            scope,
            agent.id,
            harness,
            sandbox_image,
            default_model,
            None,
            default_policy_id,
            &budgets,
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await?;
        tracing::info!("seeded agent claude-fixer rev 1");
    }

    Ok(SeedOutcome {
        tenant_id: tenant,
        default_agent: "claude-fixer".into(),
    })
}

/// The tier documents, COMPILED IN rather than read from disk.
///
/// Org creation must not read `policies/` at request time: that would couple an
/// API call to a readable directory on whichever replica happened to serve it,
/// and fail differently there than it does at boot. `include_str!` resolves at
/// build time, so the binary carries the same bytes the boot seeder ships.
/// `default` is included, and that is the point rather than an oversight.
///
/// Seeding a bare `name: default` here instead would hand every new org a
/// DIFFERENT and weaker default than the one on disk: `Read` would escalate to
/// a human, and `Agent`/`Task`/`Workflow` would become RequireApproval where
/// the shipped document hard-DENIES them — one approval click authorising an
/// unobserved nested tool tree. The boot path gets away with a bare fallback
/// only because `seed_policies_from_dir` has already applied `default.yaml`
/// before it runs; this path has no such predecessor.
pub const TIER_DOCUMENTS: &[(&str, &str)] = &[
    ("default", include_str!("../../../policies/default.yaml")),
    ("open", include_str!("../../../policies/open.yaml")),
    ("standard", include_str!("../../../policies/standard.yaml")),
    ("governed", include_str!("../../../policies/governed.yaml")),
];

/// Seed `default` plus the three tiers into ONE tenant.
///
/// A tenant with no policies is not merely empty — every run in it fails closed
/// at `create_run`, where the policy is resolved (`run_service.rs`, before the
/// session row and before any sandbox exists). `create_org` never seeded
/// anything, so each new org started in exactly that state; this closes it.
///
/// Idempotent by way of [`seed_policy_if_absent`]: calling it twice is a no-op,
/// and a tenant that already holds a policy of one of these names keeps the one
/// it has.
///
/// NOT ATOMIC, and worth knowing: each document is its own transaction, so a
/// mid-way failure leaves a partially-seeded tenant. Nothing here repairs that
/// — there is no re-seed endpoint today, and re-POSTing the slug returns 409.
/// Callers must treat a failure as needing operator attention, not as a state
/// the system heals on its own.
pub async fn seed_tiers_for_tenant(pool: &PgPool, scope: TenantScope) -> anyhow::Result<()> {
    for (name, yaml) in TIER_DOCUMENTS {
        // STRICT, matching `seed_policies_from_dir`. The lenient parser drops
        // unknown keys silently, so a typo like `paths.denyy` would seed a
        // WEAKER policy than the file appears to describe — and this path has
        // no operator watching it the way a boot log has.
        let parsed = Policy::parse_yaml_strict(yaml)
            .map_err(|e| anyhow::anyhow!("compiled-in policy '{name}' does not parse: {e}"))?;
        seed_policy_if_absent(pool, scope, name, yaml, &serde_json::to_value(&parsed)?).await?;
    }
    Ok(())
}

/// Seed every `*.yaml` in `policies_dir`.
///
/// Split out of [`run`] so the refusal rules below are testable against a
/// throwaway tenant: `run` itself owns the DEFAULT tenant, and a test that
/// seeded through it would write the curated agent into whatever database
/// `DATABASE_URL` points at.
///
/// Resolving the default policy is deliberately NOT this function's job — see
/// the comment in [`run`]: doing it per-file made it depend on a `default.yaml`
/// existing, which silently handed the curated agent `Budgets::default()`
/// whenever the file was absent.
pub async fn seed_policies_from_dir(
    pool: &PgPool,
    scope: TenantScope,
    policies_dir: &Path,
) -> anyhow::Result<()> {
    if !policies_dir.is_dir() {
        return Ok(());
    }
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
        let path = entry.path();
        let yaml = std::fs::read_to_string(&path)?;
        // The file's SUBJECT, extracted WITHOUT validating it.
        //
        // Not `Policy::parse_yaml`: that one also runs `validate()`, so a file
        // that is merely INVALID (`match: []`) — as opposed to unnameable —
        // would refuse the boot here, before the existence check below ever
        // ran. That is precisely the distinction this function exists to draw,
        // so the name has to come from a parse that judges nothing.
        //
        // "Names a policy" therefore means exactly: parses as YAML, and has a
        // top-level string `name`. A file that fails THAT cannot be reasoned
        // about at all, so it refuses regardless of what exists.
        let subject_name = serde_yaml::from_str::<serde_json::Value>(&yaml)
            .ok()
            .and_then(|v| {
                v.get("name")
                    .and_then(|n| n.as_str())
                    .map(|n| n.to_string())
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unreadable seed policy {}: it is not YAML with a top-level string `name`, \
                     so there is no policy to reason about",
                    path.display()
                )
            })?;
        // The static /v1/policies/* routes shadow /{name}; the API refuses
        // these names (api.rs::reject_reserved_name, off the same core
        // const) and a seed must not smuggle one in from disk.
        if fluidbox_core::policy::is_reserved_policy_name(&subject_name) {
            anyhow::bail!(
                "seed policy file {} uses the API-reserved name '{}' — the static \
                 /v1/policies/* routes shadow /{{name}}, so the policy would be \
                 unreachable by its own URL",
                path.display(),
                subject_name
            );
        }

        // STRICT is what may actually SEED: a typo'd key must never become a
        // silently-weaker version 1. The CONSEQUENCE, though, is scaled to what
        // is actually at stake — refusing a boot is itself an outage, and it
        // buys nothing when the file cannot write anything:
        //
        //   • policy ABSENT  — the file is its only source. Refuse the boot.
        //   • policy PRESENT — `seed_policy_if_absent` is already a no-op for
        //     it; the database's versions govern and the file writes NOTHING.
        //     Warn loudly and carry on.
        //
        // The existence check happens HERE, on the failure path only. That is
        // both cheaper (the happy path loses a query) and tighter: the answer
        // is read as late as possible, so a policy created by a racing replica
        // between the parse and this lookup is seen, not missed.
        match Policy::parse_yaml_strict(&yaml) {
            Ok(policy) => {
                let parsed = serde_json::to_value(&policy)?;
                // Bootstrap only when absent — never clobber UI edits on reboot.
                let (row, inserted) =
                    seed_policy_if_absent(pool, scope, &policy.name, &yaml, &parsed).await?;
                if inserted {
                    tracing::info!(policy = %policy.name, "seeded policy from disk");
                } else {
                    tracing::debug!(policy = %policy.name, id = %row.id, "policy exists; leaving UI-managed versions intact");
                }
            }
            Err(e) => {
                if get_policy_by_name(pool, scope, &subject_name)
                    .await?
                    .is_some()
                {
                    tracing::warn!(
                        policy = %subject_name,
                        file = %path.display(),
                        "seed policy file is INVALID and was NOT seeded: {e} — this policy \
                         already exists, so its database versions govern and the file writes \
                         nothing; repair it before it is needed on a fresh database"
                    );
                } else {
                    anyhow::bail!(
                        "invalid seed policy {}: {e} — policy '{}' does not exist yet, so this \
                         file is its ONLY source; repair it rather than boot a weaker policy \
                         than authored",
                        path.display(),
                        subject_name
                    );
                }
            }
        }
    }
    Ok(())
}
