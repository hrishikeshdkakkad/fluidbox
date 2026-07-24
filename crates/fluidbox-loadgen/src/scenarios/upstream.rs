//! The upstream-failure matrix: 401 / 404 / 429 / 5xx (and the two definitive
//! non-HTTP failures a real MCP server produces — a JSON-RPC error and an
//! `isError` result).
//!
//! WHAT IS ACTUALLY BEING MEASURED. Not "does the fake return 500" — that is
//! trivially true. The question Phase F asks is how the CONTROL PLANE behaves
//! when an upstream misbehaves under concurrency, and the answer lives in two
//! places: the shape of what the sandbox gets back (an `ok:true` envelope with
//! `is_error`, versus a protocol error), and the four-state execution claim
//! (`tool_execution_claims`, migration 0019) each intent left behind. A
//! definitive upstream response must be `failed_upstream` and TERMINAL; only a
//! positively-proven non-send may be `failed_before_send` and re-claimable.
//! Both are read back from the database per arm and printed.
//!
//! ARM ORDER IS LOAD-BEARING. `insufficient_scope` (SEP-835) is TERMINAL: it
//! sets the connection `status='error'`, after which every later arm would fail
//! closed on the status rather than on its own upstream behaviour. It therefore
//! runs LAST, unconditionally — the seeded RNG shuffles only the arms before it.

use crate::client::{bounded, Http};
use crate::fakes::{self, Mode};
use crate::report::{DbFacts, Params};
use crate::scenarios::{
    allow_policy_yaml, create_template_run, ensure_agent, ensure_policy, Ctx, TemplateWorkspace,
};
use crate::seed;
use anyhow::{anyhow, Result};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Args {
    pub sessions: usize,
    pub calls_per_arm: usize,
    pub template_workspace: TemplateWorkspace,
}

/// The matrix. `terminal_for_connection` marks the arms that poison the
/// connection for everything after them.
struct Arm {
    name: &'static str,
    mode: Mode,
    terminal_for_connection: bool,
}

fn arms() -> (Vec<Arm>, Vec<Arm>) {
    (
        vec![
            Arm {
                name: "ok",
                mode: Mode::Ok,
                terminal_for_connection: false,
            },
            Arm {
                name: "http_429",
                mode: Mode::Http(429),
                terminal_for_connection: false,
            },
            Arm {
                name: "http_500",
                mode: Mode::Http(500),
                terminal_for_connection: false,
            },
            Arm {
                name: "http_502",
                mode: Mode::Http(502),
                terminal_for_connection: false,
            },
            Arm {
                name: "http_404",
                mode: Mode::Http(404),
                terminal_for_connection: false,
            },
            Arm {
                name: "rpc_error",
                mode: Mode::RpcError,
                terminal_for_connection: false,
            },
            Arm {
                name: "is_error",
                mode: Mode::IsError,
                terminal_for_connection: false,
            },
            Arm {
                name: "slow_2s",
                mode: Mode::SlowMs(2000),
                terminal_for_connection: false,
            },
            Arm {
                name: "http_401",
                mode: Mode::Http(401),
                terminal_for_connection: false,
            },
        ],
        // Runs last, always.
        vec![Arm {
            name: "insufficient_scope_403",
            mode: Mode::InsufficientScope,
            terminal_for_connection: true,
        }],
    )
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<(Params, DbFacts)> {
    let tag = ctx.run_tag.clone();
    let token = format!("lg-upstream-{tag}");
    let fake = fakes::start(&token).await?;
    eprintln!("  fake MCP upstream at {}", fake.url);

    let result = drive(ctx, &args, &fake, &tag).await;
    fake.shutdown();
    result
}

async fn drive(
    ctx: &mut Ctx,
    args: &Args,
    fake: &fakes::FakeUpstream,
    tag: &str,
) -> Result<(Params, DbFacts)> {
    let slug = format!("lg-{tag}");
    let policy = format!("lg-allow-{tag}");
    let agent = format!("lg-brokered-{tag}");
    let slot = "lg";

    // ── catalog entry → connection (photographs the fake's tool surface) ────
    let a = ctx
        .http
        .admin_post(
            "setup.catalog",
            "/v1/catalog",
            json!({
                "slug": slug, "name": "loadgen fake", "transport": "streamable_http",
                "url": fake.url, "auth_mode": "api_key",
                "auth_hints": {"header_name": "authorization", "scheme": "Bearer"}
            }),
        )
        .await;
    if !a.is_2xx() {
        return Err(anyhow!("catalog create → {} {}", a.status, a.body));
    }
    let a = ctx
        .http
        .admin_post(
            "setup.connect",
            &format!("/v1/catalog/{slug}/connect"),
            json!({"token": fake.token, "display_name": format!("loadgen {tag}")}),
        )
        .await;
    let conn = a.str_at(&["connection", "id"]).ok_or_else(|| {
        anyhow!(
            "connecting the fake upstream failed ({} {}). This scenario needs the \
             dev-loopback egress seam open — boot the control plane with \
             FLUIDBOX_PUBLIC_URL=http://127.0.0.1:<its own port>.",
            a.status,
            a.body
        )
    })?;
    let conn_id = Uuid::parse_str(&conn)?;

    // ── agent whose revision REQUIRES both fake tools ───────────────────────
    // `required_tools` is the effective surface: a tool the fake advertises but
    // no requirement names is absent from `RunSpec.brokered[].tools` and would
    // be denied at the frozen-set stage before ever reaching the upstream — the
    // matrix would then measure the gate, not the upstream.
    ensure_policy(&ctx.http, &policy, &allow_policy_yaml(&policy)).await?;
    ensure_agent(
        &ctx.http,
        &agent,
        &policy,
        vec![json!({
            "slot": slot,
            "connector": {"url": fake.url, "slug": slug},
            "required_tools": fakes::TOOL_NAMES,
            "binding_mode": "organization"
        })],
    )
    .await?;

    let template = create_template_run(&ctx.http, &agent, args.template_workspace, tag).await?;
    eprintln!("  template run {template} created; waiting for it to settle…");
    seed::wait_settled(&ctx.pool, template, 300).await?;
    let template = seed::load_template(&ctx.pool, template).await?;
    let sessions = seed::seed_sessions(&ctx.pool, &template, args.sessions, tag).await?;
    let ids: Vec<Uuid> = sessions.iter().map(|s| s.id).collect();

    // ── the matrix ─────────────────────────────────────────────────────────
    let (mut shufflable, terminal) = arms();
    ctx.rng.shuffle(&mut shufflable);
    let mut facts = DbFacts::new();
    let mut order: Vec<&str> = Vec::new();

    for arm in shufflable.iter().chain(terminal.iter()) {
        fake.state.set_mode(arm.mode);
        order.push(arm.name);
        let prefix = format!("{tag}-{}-", arm.name);
        let mut jobs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> =
            Vec::new();
        for (si, s) in sessions.iter().enumerate() {
            for ci in 0..args.calls_per_arm {
                let http: Http = ctx.http.clone();
                let sid = s.id;
                let tok = s.tokens.tool.clone();
                let call_id = format!("{prefix}{si}-{ci}");
                let tool = format!("mcp__{slot}__{}", fakes::TOOL_NAMES[0]);
                jobs.push(Box::pin(async move {
                    http.session_post(
                        &format!("internal.tools_call[{}]", arm_label(&call_id)),
                        &format!("/internal/sessions/{sid}/tools/call"),
                        &tok,
                        json!({"tool_call_id": call_id, "tool": tool, "input": {"query": "load"}}),
                    )
                    .await;
                }));
            }
        }
        bounded(ctx.concurrency, jobs).await;
        facts.add(
            &format!("execution-claim states — arm '{}'", arm.name),
            seed::claim_states(&ctx.pool, &ids, &prefix).await?,
        );
        if arm.terminal_for_connection {
            let status: String =
                sqlx::query("select status from integration_connections where id = $1")
                    .bind(conn_id)
                    .fetch_one(&ctx.pool)
                    .await?
                    .try_get("status")?;
            facts.add(
                "connection status after the terminal arm (expected: error)",
                vec![(status, 1)],
            );
        }
    }

    facts.add(
        "ledger deny sources across the whole matrix",
        seed::deny_sources(&ctx.pool, &ids).await?,
    );

    let params = Params::new()
        .set("seed", ctx.seed)
        .set("run_tag", tag)
        .set("base_url", &ctx.http.base)
        .set("sessions_seeded", args.sessions)
        .set("calls_per_arm", args.calls_per_arm)
        .set("arms", order.join(" → "))
        .set("client_concurrency", ctx.concurrency)
        .set("connection", conn_id)
        .set(
            "fake_upstream_tool_calls",
            fake.state
                .tool_calls
                .load(std::sync::atomic::Ordering::Relaxed),
        );

    if !ctx.keep_fixtures {
        seed::cleanup_sessions(&ctx.pool, &ids).await?;
        seed::cleanup_connections(&ctx.pool, &[conn_id]).await?;
        eprintln!("  cleaned up the seeded sessions and the fake connection");
    }
    Ok((params, facts))
}

/// The arm name embedded in a call id, so every arm gets its own latency bucket
/// without threading a second string through the job closure.
fn arm_label(call_id: &str) -> String {
    // "<tag>-<arm>-<si>-<ci>" — the arm is everything between the first and the
    // last two dash-separated fields.
    let parts: Vec<&str> = call_id.split('-').collect();
    if parts.len() < 4 {
        return "unknown".into();
    }
    parts[1..parts.len() - 2].join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_labels_round_trip_out_of_a_call_id() {
        assert_eq!(arm_label("19abc123-http_500-7-2"), "http_500");
        assert_eq!(
            arm_label("19abc123-insufficient_scope_403-0-0"),
            "insufficient_scope_403"
        );
        assert_eq!(arm_label("short"), "unknown");
    }

    /// The terminal arm must be the ONLY one flagged, and it must not appear in
    /// the shufflable set — otherwise the seeded shuffle could place it first
    /// and every subsequent arm would measure a fail-closed status check.
    #[test]
    fn only_the_terminal_arm_is_terminal_and_it_is_never_shuffled() {
        let (shufflable, terminal) = arms();
        assert!(shufflable.iter().all(|a| !a.terminal_for_connection));
        assert_eq!(terminal.len(), 1);
        assert!(terminal[0].terminal_for_connection);
        let names: Vec<&str> = shufflable.iter().map(|a| a.name).collect();
        assert!(!names.contains(&terminal[0].name));
    }

    /// The design bullet names 401, 404, 429 and 5xx explicitly; a matrix that
    /// quietly dropped one would under-report while still looking complete.
    #[test]
    fn the_matrix_covers_every_status_the_design_names() {
        let (shufflable, terminal) = arms();
        let all: Vec<&str> = shufflable
            .iter()
            .chain(terminal.iter())
            .map(|a| a.name)
            .collect();
        for needed in ["http_401", "http_404", "http_429", "http_500"] {
            assert!(all.contains(&needed), "the matrix is missing {needed}");
        }
        assert!(all.iter().any(|n| n.starts_with("http_5")), "no 5xx arm");
    }
}
