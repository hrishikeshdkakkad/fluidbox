//! fluidbox-loadgen — the Phase F load-test harness.
//!
//! Drives a RUNNING fluidbox deployment and reports what happened: per-operation
//! latency percentiles, an error taxonomy, and the database-derived facts that
//! an HTTP response cannot tell you (which gate stage denied, what state each
//! durable execution claim settled in).
//!
//! Three properties shape every design decision in this crate:
//!
//!  * **It spends no model money.** Nothing here talks to a model provider. The
//!    only LLM traffic it can generate goes to the deployment's own facade,
//!    which forwards to whatever `LLM_UPSTREAM_URL` names — point that at a fake
//!    before using `--facade-calls-per-session`.
//!  * **N concurrent sandboxes do not require N containers.** See `seed.rs`.
//!  * **It refuses to run against anything that looks like production.** See
//!    `guard.rs`.

mod client;
mod fakes;
mod guard;
mod metrics;
mod report;
mod rng;
mod scenarios;
mod seed;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use guard::{host_of, production_signals, scheme_of, TargetFacts};
use scenarios::{Ctx, TemplateWorkspace};
use std::time::Duration;
use uuid::Uuid;

const ABOUT: &str = "Load-test harness for a running fluidbox control plane (Phase F).";

const LONG_ABOUT: &str = "\
Load-test harness for a running fluidbox control plane (Phase F).

WHAT IT MEASURES
  Per-operation latency percentiles (p50/p95/p99/max — never an average alone),
  a failure taxonomy that separates the deployment's own refusal shapes
  (wrong_audience, tenant_llm_keys_required, throttling, gate denials) from
  transport failures (timeout, refused connection), and — where the scenario has
  a database handle — the authoritative facts behind those answers: the ledger's
  gate-stage histogram and the four-state execution-claim distribution.

IT NEVER SPENDS MODEL MONEY
  This harness contacts exactly two things: the deployment under test, and (for
  the brokered scenarios) a fake MCP upstream it hosts itself on loopback. It
  never contacts a model provider. `--facade-calls-per-session` drives the
  deployment's LLM FACADE, which forwards to whatever that deployment's
  LLM_UPSTREAM_URL names — so point it at a fake gateway first. It defaults to 0.

IT DOES NOT LAUNCH SANDBOXES
  N concurrent runs are simulated by creating ONE genuine run through the public
  API (so the frozen RunSpec is real) and cloning its session row N times, minting
  the four audience-scoped tokens per clone. The template run uses a deliberately
  absent local_copy path, which fails during `initializing` before any sandbox is
  requested. `--template-workspace scratch` is the one path that can reach the
  provider, and it requires --allow-provisioning.

SAFETY
  The harness refuses to start when the target looks like production. See
  --force-unsafe-target below for exactly what that means.

  Note that the database URL is read from FLUIDBOX_LOADGEN_DATABASE_URL and
  DELIBERATELY NOT from DATABASE_URL: sourcing a project dotenv must never be
  enough to arm a tool that writes rows.

SCENARIOS
  Run `fluidbox-loadgen list-scenarios` for the full matrix, including the six
  design scenarios that are NAMED GAPS rather than implementations.";

const AFTER_HELP: &str = "\
LOOKS-LIKE-PRODUCTION (any one of these refuses the run unless --force-unsafe-target):
  * the control plane is at a non-loopback host;
  * the control plane is behind https;
  * the seeding database is at a non-loopback host (this is the one that matters:
    the seeding path INSERTs rows directly);
  * a routine /v1 read with the admin token was refused — either
    FLUIDBOX_REQUIRE_SSO=1, or the token is wrong.

EXAMPLES
  # the 60-concurrent capacity gate against a local deployment
  fluidbox-loadgen --database-url postgres://postgres:postgres@127.0.0.1:5432/fluidbox \\
      concurrent-sandboxes --sessions 60 --gate-calls-per-session 20

  # the 1,500-saved-connections bullet
  fluidbox-loadgen --database-url ... connections --count 1500 --list-reads 50

  # the upstream failure matrix
  fluidbox-loadgen --database-url ... upstream-failures --sessions 10 --calls-per-arm 5";

#[derive(Parser, Debug)]
#[command(
    name = "fluidbox-loadgen",
    version,
    about = ABOUT,
    long_about = LONG_ABOUT,
    after_long_help = AFTER_HELP
)]
struct Cli {
    /// Control-plane base URL.
    #[arg(long, global = true, default_value = "http://127.0.0.1:8787")]
    base_url: String,

    /// Admin bearer token for the /v1 plane.
    #[arg(long, global = true, env = "FLUIDBOX_ADMIN_TOKEN", default_value = "")]
    admin_token: String,

    /// Postgres URL used for the fast seeding path and for the
    /// database-derived facts.
    ///
    /// Read from FLUIDBOX_LOADGEN_DATABASE_URL and deliberately NOT from
    /// DATABASE_URL — sourcing a project dotenv must not be enough to arm a
    /// tool that writes rows.
    #[arg(
        long,
        global = true,
        env = "FLUIDBOX_LOADGEN_DATABASE_URL",
        default_value = ""
    )]
    database_url: String,

    /// RNG seed. Governs workload SHAPE (tool mix, matrix order), not row
    /// identity — see the crate docs.
    #[arg(long, global = true, default_value_t = 0x5EED)]
    seed: u64,

    /// Maximum in-flight requests from this process.
    #[arg(long, global = true, default_value_t = 64)]
    concurrency: usize,

    /// Per-request timeout.
    #[arg(long, global = true, default_value_t = 30)]
    timeout_secs: u64,

    /// Emit the report as JSON instead of a table.
    #[arg(long, global = true)]
    json: bool,

    /// Proceed even though the target raised a production signal.
    #[arg(long, global = true)]
    force_unsafe_target: bool,

    /// Permit a template workspace that can reach the sandbox provider.
    #[arg(long, global = true)]
    allow_provisioning: bool,

    /// Leave the seeded sessions/connections in the database.
    #[arg(long, global = true)]
    keep_fixtures: bool,

    /// Exit nonzero when more than this percentage of requests were unhealthy.
    /// Omit for a pure measurement run (always exits 0 on a completed run).
    #[arg(long, global = true)]
    max_unhealthy_pct: Option<f64>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print every Phase F design scenario with its true status.
    ListScenarios,

    /// N concurrent runs driving the permission gate (design: 60/150/300).
    ConcurrentSandboxes {
        #[arg(long, default_value_t = 60)]
        sessions: usize,
        #[arg(long, default_value_t = 10)]
        gate_calls_per_session: usize,
        /// Requires the deployment's LLM_UPSTREAM_URL to point at a FAKE.
        #[arg(long, default_value_t = 0)]
        facade_calls_per_session: usize,
        /// Reuse an existing settled session as the template (creates no run).
        #[arg(long)]
        template_session: Option<Uuid>,
        #[arg(long, value_enum, default_value_t = TemplateWorkspace::AbsentLocalPath)]
        template_workspace: TemplateWorkspace,
        #[arg(long, default_value = "claude-haiku-4-5")]
        model: String,
    },

    /// Seed C saved connections and time the list at that size (design: 1,500).
    Connections {
        #[arg(long, default_value_t = 1500)]
        count: usize,
        #[arg(long, default_value_t = 25)]
        list_reads: usize,
    },

    /// Brokered calls against an upstream answering 401/404/429/5xx/…
    UpstreamFailures {
        #[arg(long, default_value_t = 8)]
        sessions: usize,
        #[arg(long, default_value_t = 4)]
        calls_per_arm: usize,
        #[arg(long, value_enum, default_value_t = TemplateWorkspace::AbsentLocalPath)]
        template_workspace: TemplateWorkspace,
    },

    /// N gate calls that pause for a human, decided after a delay.
    SlowApprovals {
        #[arg(long, default_value_t = 60)]
        sessions: usize,
        #[arg(long, default_value_t = 10)]
        decide_after_secs: u64,
        #[arg(long, default_value_t = 120)]
        ttl_secs: u64,
        #[arg(long, value_enum, default_value_t = TemplateWorkspace::AbsentLocalPath)]
        template_workspace: TemplateWorkspace,
    },

    /// NAMED GAP — see `list-scenarios`.
    OauthRefreshStorm,
    /// NAMED GAP — see `list-scenarios`.
    RevocationMidRun,
    /// NAMED GAP — see `list-scenarios`.
    BrokerRestart,
    /// NAMED GAP — see `list-scenarios`.
    ReservationRace,
    /// NAMED GAP — see `list-scenarios`.
    DbFailover,
    /// NAMED GAP — see `list-scenarios`.
    TenantFuzz,
}

impl Cmd {
    fn name(&self) -> &'static str {
        match self {
            Cmd::ListScenarios => "list-scenarios",
            Cmd::ConcurrentSandboxes { .. } => "concurrent-sandboxes",
            Cmd::Connections { .. } => "connections",
            Cmd::UpstreamFailures { .. } => "upstream-failures",
            Cmd::SlowApprovals { .. } => "slow-approvals",
            Cmd::OauthRefreshStorm => "oauth-refresh-storm",
            Cmd::RevocationMidRun => "revocation-mid-run",
            Cmd::BrokerRestart => "broker-restart",
            Cmd::ReservationRace => "reservation-race",
            Cmd::DbFailover => "db-failover",
            Cmd::TenantFuzz => "tenant-fuzz",
        }
    }

    fn is_gap(&self) -> bool {
        matches!(
            self,
            Cmd::OauthRefreshStorm
                | Cmd::RevocationMidRun
                | Cmd::BrokerRestart
                | Cmd::ReservationRace
                | Cmd::DbFailover
                | Cmd::TenantFuzz
        )
    }

    fn template_workspace(&self) -> Option<TemplateWorkspace> {
        match self {
            Cmd::ConcurrentSandboxes {
                template_workspace, ..
            }
            | Cmd::UpstreamFailures {
                template_workspace, ..
            }
            | Cmd::SlowApprovals {
                template_workspace, ..
            } => Some(*template_workspace),
            _ => None,
        }
    }

    /// A one-paragraph statement of what running this will DO to the target.
    /// Printed before every run; there is no quiet mode.
    fn impact(&self) -> String {
        match self {
            Cmd::ConcurrentSandboxes {
                sessions,
                gate_calls_per_session,
                facade_calls_per_session,
                template_session,
                ..
            } => format!(
                "creates {} run(s) through the API, INSERTs {sessions} session rows and \
                 {} api_tokens rows directly, and issues {} internal requests. \
                 Ledger rows are appended per gate decision.",
                if template_session.is_some() { 0 } else { 1 },
                sessions * 4,
                sessions * (gate_calls_per_session + facade_calls_per_session)
            ),
            Cmd::Connections { count, list_reads } => format!(
                "creates {count} integration_connections rows through the API — each one \
                 seals a credential and PHOTOGRAPHS a tool surface into \
                 connection_tool_snapshots — then issues {list_reads} list reads."
            ),
            Cmd::UpstreamFailures {
                sessions,
                calls_per_arm,
                ..
            } => format!(
                "creates 1 catalog entry, 1 connection, 1 agent and 1 run through the API; \
                 INSERTs {sessions} session rows; issues {} brokered tool calls across 10 \
                 arms, each leaving a tool_execution_claims row. The final arm marks the \
                 harness's own connection status='error' by design.",
                sessions * calls_per_arm * 10
            ),
            Cmd::SlowApprovals {
                sessions,
                decide_after_secs,
                ..
            } => format!(
                "creates 1 run through the API, INSERTs {sessions} session rows, and parks \
                 {sessions} request handlers on the deployment for at least \
                 {decide_after_secs}s each before deciding their approvals."
            ),
            _ => "no effect (this scenario is a named gap).".into(),
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = real_main().await {
        eprintln!("\nfluidbox-loadgen: {e:#}");
        std::process::exit(1);
    }
}

async fn real_main() -> Result<()> {
    let cli = Cli::parse();

    if matches!(cli.cmd, Cmd::ListScenarios) {
        scenarios::print_matrix();
        return Ok(());
    }
    if cli.cmd.is_gap() {
        return Err(scenarios::refuse_gap(cli.cmd.name()));
    }

    // ── impact, stated before anything is touched ──────────────────────────
    eprintln!("fluidbox-loadgen — scenario '{}'", cli.cmd.name());
    eprintln!("  target      {}", cli.base_url);
    eprintln!("  impact      {}", cli.cmd.impact());
    eprintln!(
        "  model spend NONE — this harness never contacts a model provider{}",
        match &cli.cmd {
            Cmd::ConcurrentSandboxes {
                facade_calls_per_session,
                ..
            } if *facade_calls_per_session > 0 =>
                "; facade traffic is forwarded by the DEPLOYMENT to its own \
                 LLM_UPSTREAM_URL, which MUST be a fake",
            _ => "",
        }
    );

    // ── provisioning gate ──────────────────────────────────────────────────
    if let Some(ws) = cli.cmd.template_workspace() {
        if ws.provisions() && !cli.allow_provisioning {
            return Err(anyhow!(
                "--template-workspace scratch asks the deployment for a REAL SANDBOX \
                 (materialize_local commits a scratch repo, then the provider is asked to \
                 launch a container). Pass --allow-provisioning to accept that, or use the \
                 default --template-workspace absent-local-path, which fails during \
                 `initializing` and never reaches the provider."
            ));
        }
    }

    // ── the production guard ───────────────────────────────────────────────
    if cli.admin_token.is_empty() {
        return Err(anyhow!(
            "no admin token: pass --admin-token or set FLUIDBOX_ADMIN_TOKEN"
        ));
    }
    if cli.database_url.is_empty() {
        return Err(anyhow!(
            "no database URL: pass --database-url or set FLUIDBOX_LOADGEN_DATABASE_URL \
             (deliberately NOT DATABASE_URL). Every implemented scenario needs it — the \
             seeding fast path and the ledger/claim histograms are what make this a \
             measurement rather than a request generator."
        ));
    }

    let rec = metrics::shared_recorder();
    let http = client::Http::new(
        &cli.base_url,
        &cli.admin_token,
        Duration::from_secs(cli.timeout_secs),
        rec.clone(),
    )?;

    // ONE cheap probe: does the admin token open a routine /v1 read? A 401/403
    // means SSO-enforced or a wrong token; a transport failure means the target
    // is not there at all, which is reported separately because it is not a
    // production signal — it is a broken invocation.
    let probe = http.admin_get("guard.probe", "/v1/agents").await;
    if probe.status == 0 {
        return Err(anyhow!(
            "could not reach the control plane at {}: {}",
            cli.base_url,
            probe.body
        ));
    }
    let facts = TargetFacts {
        control_scheme: scheme_of(&cli.base_url),
        control_host: host_of(&cli.base_url).unwrap_or_default(),
        database_host: host_of(&cli.database_url),
        admin_token_opens_v1: Some(probe.is_2xx()),
    };
    let signals = production_signals(&facts);
    if !signals.is_empty() {
        eprintln!("\n  PRODUCTION SIGNALS:");
        for s in &signals {
            eprintln!("    * {}", s.explain());
        }
        if !cli.force_unsafe_target {
            return Err(anyhow!(
                "refusing to load-test this target ({} signal(s) above). \
                 Pass --force-unsafe-target if you are certain.",
                signals.len()
            ));
        }
        eprintln!("  --force-unsafe-target: proceeding anyway.\n");
    }

    // ── run ────────────────────────────────────────────────────────────────
    let pool = seed::connect(&cli.database_url, cli.concurrency.clamp(4, 32) as u32).await?;
    let mut ctx = Ctx {
        http,
        pool,
        rng: rng::Rng::new(cli.seed),
        concurrency: cli.concurrency,
        run_tag: scenarios::run_tag(),
        json: cli.json,
        keep_fixtures: cli.keep_fixtures,
        seed: cli.seed,
    };

    let (params, facts) = match cli.cmd {
        Cmd::ConcurrentSandboxes {
            sessions,
            gate_calls_per_session,
            facade_calls_per_session,
            template_session,
            template_workspace,
            ref model,
        } => {
            scenarios::concurrent::run(
                &mut ctx,
                scenarios::concurrent::Args {
                    sessions,
                    gate_calls_per_session,
                    facade_calls_per_session,
                    template_session,
                    template_workspace,
                    model: model.clone(),
                },
            )
            .await?
        }
        Cmd::Connections { count, list_reads } => {
            scenarios::connections::run(
                &mut ctx,
                scenarios::connections::Args { count, list_reads },
            )
            .await?
        }
        Cmd::UpstreamFailures {
            sessions,
            calls_per_arm,
            template_workspace,
        } => {
            scenarios::upstream::run(
                &mut ctx,
                scenarios::upstream::Args {
                    sessions,
                    calls_per_arm,
                    template_workspace,
                },
            )
            .await?
        }
        Cmd::SlowApprovals {
            sessions,
            decide_after_secs,
            ttl_secs,
            template_workspace,
        } => {
            scenarios::approvals::run(
                &mut ctx,
                scenarios::approvals::Args {
                    sessions,
                    decide_after_secs,
                    ttl_secs,
                    template_workspace,
                },
            )
            .await?
        }
        Cmd::ListScenarios
        | Cmd::OauthRefreshStorm
        | Cmd::RevocationMidRun
        | Cmd::BrokerRestart
        | Cmd::ReservationRace
        | Cmd::DbFailover
        | Cmd::TenantFuzz => {
            unreachable!("handled above")
        }
    };

    // ── report ─────────────────────────────────────────────────────────────
    let guard_lock = rec
        .lock()
        .map_err(|_| anyhow!("the recorder mutex was poisoned by a panicking task"))?;
    report::print(cli.cmd.name(), &params, &guard_lock, &facts, ctx.json);

    if let Some(limit) = cli.max_unhealthy_pct {
        let total = guard_lock.request_total();
        let bad = guard_lock.unhealthy_total();
        let pct = if total == 0 {
            0.0
        } else {
            100.0 * bad as f64 / total as f64
        };
        if pct > limit {
            return Err(anyhow!(
                "capacity gate FAILED: {pct:.2}% of {total} requests were unhealthy \
                 (--max-unhealthy-pct {limit})"
            ));
        }
        eprintln!("capacity gate passed: {pct:.2}% unhealthy of {total} (limit {limit}%)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// Every subcommand must appear in the scenario matrix under the SAME name,
    /// and its gap status must agree. Without this, a CLI verb could exist with
    /// no matrix entry (so `list-scenarios` would under-report it) or a matrix
    /// entry could claim "IMPLEMENTED" for a verb that refuses.
    #[test]
    fn every_cli_verb_agrees_with_the_scenario_matrix() {
        let verbs = [
            (
                Cmd::ConcurrentSandboxes {
                    sessions: 1,
                    gate_calls_per_session: 1,
                    facade_calls_per_session: 0,
                    template_session: None,
                    template_workspace: TemplateWorkspace::AbsentLocalPath,
                    model: "m".into(),
                },
                false,
            ),
            (
                Cmd::Connections {
                    count: 1,
                    list_reads: 1,
                },
                false,
            ),
            (
                Cmd::UpstreamFailures {
                    sessions: 1,
                    calls_per_arm: 1,
                    template_workspace: TemplateWorkspace::AbsentLocalPath,
                },
                false,
            ),
            (
                Cmd::SlowApprovals {
                    sessions: 1,
                    decide_after_secs: 1,
                    ttl_secs: 1,
                    template_workspace: TemplateWorkspace::AbsentLocalPath,
                },
                false,
            ),
            (Cmd::OauthRefreshStorm, true),
            (Cmd::RevocationMidRun, true),
            (Cmd::BrokerRestart, true),
            (Cmd::ReservationRace, true),
            (Cmd::DbFailover, true),
            (Cmd::TenantFuzz, true),
        ];
        assert_eq!(
            verbs.len(),
            scenarios::MATRIX.len(),
            "the CLI and the matrix must name the same set of scenarios"
        );
        for (cmd, expect_gap) in &verbs {
            let entry = scenarios::MATRIX
                .iter()
                .find(|e| e.name == cmd.name())
                .unwrap_or_else(|| panic!("CLI verb '{}' has no matrix entry", cmd.name()));
            assert_eq!(cmd.is_gap(), *expect_gap, "{}", cmd.name());
            assert_eq!(
                entry.implemented,
                !cmd.is_gap(),
                "{}: the matrix and the CLI disagree about whether this is implemented",
                cmd.name()
            );
        }
    }

    #[test]
    fn every_implemented_scenario_states_a_nonempty_impact() {
        let cmds = [
            Cmd::ConcurrentSandboxes {
                sessions: 60,
                gate_calls_per_session: 10,
                facade_calls_per_session: 0,
                template_session: None,
                template_workspace: TemplateWorkspace::AbsentLocalPath,
                model: "m".into(),
            },
            Cmd::Connections {
                count: 1500,
                list_reads: 25,
            },
            Cmd::UpstreamFailures {
                sessions: 8,
                calls_per_arm: 4,
                template_workspace: TemplateWorkspace::AbsentLocalPath,
            },
            Cmd::SlowApprovals {
                sessions: 60,
                decide_after_secs: 10,
                ttl_secs: 120,
                template_workspace: TemplateWorkspace::AbsentLocalPath,
            },
        ];
        for c in &cmds {
            let i = c.impact();
            assert!(
                i.len() > 40,
                "{}: impact summary is too thin: {i}",
                c.name()
            );
            assert!(
                !i.contains("named gap"),
                "{}: an implemented scenario claims to be a gap",
                c.name()
            );
        }
    }

    /// The provisioning flag must gate something REAL. If both template
    /// workspaces reported `provisions() == false`, `--allow-provisioning`
    /// would be a flag that can never fire — the exact "assertion that cannot
    /// fail" this repository treats as a defect.
    #[test]
    fn the_provisioning_gate_has_a_reachable_arm() {
        assert!(TemplateWorkspace::Scratch.provisions());
        assert!(!TemplateWorkspace::AbsentLocalPath.provisions());
    }
}
