//! Scenarios, and the shared fixture setup they all need.
//!
//! THE SCENARIO MATRIX IS HONEST ABOUT ITS GAPS. The design's Phase F names ten
//! load-test scenarios. Four are implemented here; six are NOT, and each of
//! those is a named `Gap` that refuses loudly with the specific reason and the
//! specific thing it would need. A harness that silently covers four of ten
//! while presenting a menu of ten is worse than one that covers four and says so
//! — `--list-scenarios` prints the whole table.

pub mod approvals;
pub mod concurrent;
pub mod connections;
pub mod upstream;

use crate::client::Http;
use crate::rng::Rng;
use anyhow::{anyhow, Result};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

pub struct Ctx {
    pub http: Http,
    pub pool: PgPool,
    pub rng: Rng,
    pub concurrency: usize,
    pub run_tag: String,
    pub json: bool,
    pub keep_fixtures: bool,
    pub seed: u64,
}

/// A run tag unique per invocation.
///
/// NOT derived from `--seed`: `api_tokens.token_sha256` is UNIQUE, so two runs
/// with the same seed against the same database would collide on the second
/// one's very first insert. The seed governs workload SHAPE (see `rng.rs`), the
/// tag governs row identity, and conflating the two would make `--seed` a
/// one-shot flag.
pub fn run_tag() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{now:x}{:x}", std::process::id())
}

// ─── Fixture setup (public API only — the RunSpec must be genuine) ───────────

/// The permissive policy the load scenarios run under: `Read`/`Glob`/`Grep`/`LS`
/// and every brokered tool are allowed, everything else is denied by the
/// default. One policy therefore drives BOTH the allow and the deny path, which
/// is what makes a mixed workload possible without a second agent.
pub fn allow_policy_yaml(name: &str) -> String {
    format!(
        "name: {name}
defaults:
  tool_action: deny
autonomy:
  permitted: true
  on_approval_rule: deny
tools:
  - match: [\"Read\", \"Glob\", \"Grep\", \"LS\"]
    action: allow
  - match: [\"mcp__*\"]
    action: allow
"
    )
}

/// The slow-approval policy: `Read` PAUSES for a human. `approval_ttl_secs` is a
/// parameter because the interesting boundary is whether the decision beats the
/// expiry, and a fixed TTL would make one of those two arms unreachable.
pub fn approve_policy_yaml(name: &str, ttl_secs: u64) -> String {
    format!(
        "name: {name}
defaults:
  tool_action: deny
autonomy:
  permitted: false
  on_approval_rule: deny
tools:
  - match: [\"Read\", \"Glob\", \"Grep\", \"LS\"]
    action: approve
    approval_ttl_secs: {ttl_secs}
"
    )
}

pub async fn ensure_policy(http: &Http, name: &str, yaml: &str) -> Result<()> {
    let a = http
        .admin_post(
            "setup.policy",
            "/v1/policies",
            json!({"name": name, "yaml": yaml}),
        )
        .await;
    if a.is_2xx() {
        Ok(())
    } else {
        Err(anyhow!(
            "creating policy '{name}' → {} {}",
            a.status,
            a.body
        ))
    }
}

/// Create an agent. `requirements` is the (possibly empty) list of
/// `connection_requirements`; an empty list is omitted entirely rather than sent
/// as `[]`, so the bare case exercises the same request shape a dashboard sends.
pub async fn ensure_agent(
    http: &Http,
    name: &str,
    policy: &str,
    requirements: Vec<serde_json::Value>,
) -> Result<String> {
    let mut body = json!({"name": name, "policy": policy});
    if !requirements.is_empty() {
        body["connection_requirements"] = json!(requirements);
    }
    let a = http.admin_post("setup.agent", "/v1/agents", body).await;
    if !a.is_2xx() {
        return Err(anyhow!("creating agent '{name}' → {} {}", a.status, a.body));
    }
    Ok(name.to_string())
}

/// How the template run's workspace is chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum TemplateWorkspace {
    /// A `local_copy` pointing at a path that does not exist. The run fails in
    /// `materialize_local`'s `!source.exists()` guard DURING `initializing` —
    /// before any base commit, sandbox handle or `started_at` — so it quiesces
    /// in about a second and NO SANDBOX IS EVER PROVISIONED. This is the default
    /// precisely because it makes "this harness does not launch containers" a
    /// property of the code path, not a promise.
    AbsentLocalPath,
    /// A real scratch workspace. `materialize_local` git-inits and commits, and
    /// the provider is then asked for a sandbox — i.e. THIS ONE CAN LAUNCH A
    /// CONTAINER. Gated behind `--allow-provisioning`.
    Scratch,
}

impl TemplateWorkspace {
    pub fn provisions(&self) -> bool {
        matches!(self, TemplateWorkspace::Scratch)
    }
    fn json(&self) -> serde_json::Value {
        match self {
            TemplateWorkspace::AbsentLocalPath => json!({
                "kind": "local_copy",
                "path": "/nonexistent-fluidbox-loadgen-template"
            }),
            TemplateWorkspace::Scratch => json!({"kind": "scratch"}),
        }
    }
}

/// Create the ONE genuine run whose frozen RunSpec every seeded clone inherits.
pub async fn create_template_run(
    http: &Http,
    agent: &str,
    workspace: TemplateWorkspace,
    tag: &str,
) -> Result<Uuid> {
    let a = http
        .admin_post(
            "setup.template_run",
            "/v1/sessions",
            json!({
                "agent": agent,
                "task": format!("fluidbox-loadgen template ({tag})"),
                "workspace": workspace.json(),
            }),
        )
        .await;
    if !a.is_2xx() {
        return Err(anyhow!(
            "creating the template run → {} {}",
            a.status,
            a.body
        ));
    }
    let id = a
        .str_at(&["session", "id"])
        .ok_or_else(|| anyhow!("template run response carried no session id: {}", a.body))?;
    Uuid::parse_str(&id).map_err(|e| anyhow!("template run id '{id}' is not a uuid: {e}"))
}

// ─── The scenario menu ──────────────────────────────────────────────────────

/// Every Phase F load-test scenario the design names, with its true status.
pub struct ScenarioEntry {
    pub name: &'static str,
    pub implemented: bool,
    pub summary: &'static str,
    /// For a gap: exactly what is missing. Empty for an implemented scenario.
    pub gap: &'static str,
}

pub const MATRIX: &[ScenarioEntry] = &[
    ScenarioEntry {
        name: "concurrent-sandboxes",
        implemented: true,
        summary: "N concurrent runs driving the permission gate (+ optional facade traffic). \
                  Design bullets: 60 / 150 / 300 concurrent sandboxes.",
        gap: "",
    },
    ScenarioEntry {
        name: "connections",
        implemented: true,
        summary: "Seed C saved connections through the public API (each one photographs a \
                  tool surface), then measure list latency at that size. Design bullet: \
                  1,500 saved connections.",
        gap: "",
    },
    ScenarioEntry {
        name: "upstream-failures",
        implemented: true,
        summary: "Drive brokered tool calls while an in-process fake upstream answers \
                  401 / 404 / 429 / 500 / JSON-RPC error / isError / slow, and read back the \
                  four-state execution-claim histogram. Design bullet: upstream 401/404/429/5xx.",
        gap: "",
    },
    ScenarioEntry {
        name: "slow-approvals",
        implemented: true,
        summary: "N gate calls that PAUSE for a human, decided after a configurable delay; \
                  measures blocked-handler occupancy and end-to-end approval latency. \
                  Design bullet: slow approvals.",
        gap: "",
    },
    ScenarioEntry {
        name: "oauth-refresh-storm",
        implemented: false,
        summary: "Design bullet: OAuth refresh storms.",
        gap: "NOT IMPLEMENTED. Needs a fake authorization server (RFC 9728 PRM + RFC 8414 \
              metadata + a token endpoint that rotates refresh tokens) and connections in \
              `auth_kind='oauth'` whose sealed refresh tokens are near expiry. The harness \
              can create neither today: OAuth connections are only reachable through the \
              browser-bound one-time `/v1/oauth/go` flow, whose `__Host-fbx_oauth_flow` \
              cookie is claimed inside the single-use predicate — a headless client cannot \
              complete it without either a browser or a DB-level forge of \
              `connector_oauth_flows` (including its AEAD-sealed PKCE verifier, which \
              needs the deployment's KEK).",
    },
    ScenarioEntry {
        name: "revocation-mid-run",
        implemented: false,
        summary: "Design bullet: connection revocation during active runs.",
        gap: "NOT IMPLEMENTED. The mechanism is cheap (POST /v1/connections/{id}/revoke while \
              brokered calls are in flight, then split the outcomes at the revocation \
              instant), but the ASSERTION is not: proving fail-closed requires correlating \
              each call's ledger `source='binding'` against the revocation's commit time, \
              and the harness has no clock shared with the deployment's transaction log. \
              Left out rather than shipped as a latency chart that proves nothing.",
    },
    ScenarioEntry {
        name: "broker-restart",
        implemented: false,
        summary: "Design bullet: broker restart during active sessions.",
        gap: "NOT IMPLEMENTED. Requires lifecycle control over the control-plane process \
              (SIGKILL mid-dispatch, then restart), which is the acceptance SCRIPT's job — \
              it owns the stack — not this harness's, which by contract only drives a \
              deployment it did not start. The home for it is a section of \
              scripts/scale-e2e.sh using the existing `_spawn`/`boot` helpers.",
    },
    ScenarioEntry {
        name: "reservation-race",
        implemented: false,
        summary: "Design bullet: parallel model calls across replicas that must not overspend \
                  a per-run budget.",
        gap: "NOT IMPLEMENTED. Needs TWO replica base URLs plus a fake LLM upstream that the \
              DEPLOYMENT (not the harness) is pointed at via LLM_UPSTREAM_URL, so that usage \
              can be metered deterministically; and the assertion is about the SUM of \
              `usage_entries` against the frozen budget, which only holds if the fake's token \
              counts are known. Both halves are boot-time configuration of the deployment, so \
              this belongs in scripts/scale-e2e.sh alongside the existing two-replica boot.",
    },
    ScenarioEntry {
        name: "db-failover",
        implemented: false,
        summary: "Design bullet: database failover.",
        gap: "NOT IMPLEMENTED. Requires a database the harness can fail over (a Neon branch \
              switch, a Patroni promotion, or a proxy that can drop the primary). Nothing in \
              this repository provisions one, and simulating it by killing a local postgres \
              would test pgpool behaviour that no deployment uses.",
    },
    ScenarioEntry {
        name: "tenant-fuzz",
        implemented: false,
        summary: "Design bullet: tenant-isolation fuzz / negative cases.",
        gap: "NOT IMPLEMENTED. Needs at least two tenants with real principals, which needs \
              FLUIDBOX_REQUIRE_SSO=1 and an OIDC provider — and under REQUIRE_SSO the admin \
              token this harness authenticates with is confined to /v1/admin/*, so the \
              harness cannot drive the data plane at all. The existing coverage lives in \
              scripts/identity-e2e.sh and the RLS negative tests, which connect as \
              `fluidbox_runtime`; extending THOSE is the right move, not adding a \
              single-tenant fuzzer here.",
    },
];

pub fn print_matrix() {
    println!("fluidbox-loadgen — Phase F scenario matrix");
    println!(
        "  (design: docs/plans/2026-07-14-multi-user-mcp-control-plane-design.md:1597-1613)\n"
    );
    let implemented = MATRIX.iter().filter(|e| e.implemented).count();
    println!(
        "  {implemented} of {} design scenarios are implemented.\n",
        MATRIX.len()
    );
    for e in MATRIX {
        let mark = if e.implemented { "IMPLEMENTED" } else { "GAP" };
        println!("  [{mark:^11}] {}", e.name);
        for line in wrap(e.summary, 92) {
            println!("                {line}");
        }
        if !e.gap.is_empty() {
            for line in wrap(&squeeze(e.gap), 92) {
                println!("                {line}");
            }
        }
        println!();
    }
}

/// Collapse the runs of whitespace a multi-line string literal leaves behind.
fn squeeze(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in squeeze(s).split(' ') {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

/// Refuse a named gap, printing what it would take.
pub fn refuse_gap(name: &str) -> anyhow::Error {
    match MATRIX.iter().find(|e| e.name == name) {
        Some(e) => anyhow!(
            "scenario '{name}' is a NAMED GAP, not a stub.\n\n  {}",
            squeeze(e.gap)
        ),
        None => anyhow!("unknown scenario '{name}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The matrix must cover every design bullet. If a scenario is added to the
    /// CLI without a matrix entry, `--list-scenarios` would under-report and the
    /// harness would be exactly the thing this crate refuses to be.
    #[test]
    fn every_matrix_entry_is_either_implemented_or_carries_a_reason() {
        assert_eq!(MATRIX.len(), 10, "the design names ten load-test scenarios");
        for e in MATRIX {
            if e.implemented {
                assert!(
                    e.gap.is_empty(),
                    "{}: an implemented scenario must not carry a gap note",
                    e.name
                );
            } else {
                assert!(
                    e.gap.contains("NOT IMPLEMENTED"),
                    "{}: a gap must say so in words",
                    e.name
                );
                assert!(
                    e.gap.len() > 120,
                    "{}: a gap note must state what is MISSING, not just that it is missing",
                    e.name
                );
            }
        }
    }

    #[test]
    fn scenario_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for e in MATRIX {
            assert!(seen.insert(e.name), "duplicate scenario name {}", e.name);
        }
    }

    #[test]
    fn only_the_scratch_template_can_provision() {
        assert!(!TemplateWorkspace::AbsentLocalPath.provisions());
        assert!(TemplateWorkspace::Scratch.provisions());
    }

    #[test]
    fn run_tags_do_not_repeat_within_a_process() {
        let a = run_tag();
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_ne!(a, run_tag());
    }

    #[test]
    fn the_policy_yamls_name_themselves() {
        // `POST /v1/policies` refuses a body whose `name` differs from the
        // YAML's — a mismatch here would fail every scenario at setup.
        assert!(allow_policy_yaml("lg-allow").starts_with("name: lg-allow\n"));
        assert!(approve_policy_yaml("lg-appr", 30).starts_with("name: lg-appr\n"));
        assert!(approve_policy_yaml("lg-appr", 30).contains("approval_ttl_secs: 30"));
    }
}
