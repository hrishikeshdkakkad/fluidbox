//! Concurrent-sandbox load: the 60 / 150 / 300 design bullets.
//!
//! Seeds N sessions from ONE genuine template run (`seed.rs`), then drives the
//! permission gate — and optionally the LLM facade — at a bounded concurrency,
//! reporting percentiles, an outcome taxonomy, and the ledger's authoritative
//! deny-source histogram.

use crate::client::{bounded, Http};
use crate::report::{DbFacts, Params};
use crate::scenarios::{
    allow_policy_yaml, create_template_run, ensure_agent, ensure_policy, Ctx, TemplateWorkspace,
};
use crate::seed;
use anyhow::Result;
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Args {
    pub sessions: usize,
    pub gate_calls_per_session: usize,
    pub facade_calls_per_session: usize,
    pub template_session: Option<Uuid>,
    pub template_workspace: TemplateWorkspace,
    pub model: String,
}

/// The workload's tool mix. Under the load policy `Read`/`Glob`/`Grep`/`LS`
/// ALLOW and everything else falls to the `deny` default, so this one list
/// drives both halves of the gate — a run that only ever asked for an allowed
/// tool would leave the denial path (CAS + ledger append + terminal-deny claim)
/// completely unmeasured, and that path does strictly more database work.
fn tool_mix() -> Vec<(&'static str, Value)> {
    vec![
        ("Read", json!({"file_path": "/workspace/README.md"})),
        ("Glob", json!({"pattern": "**/*.rs"})),
        ("Grep", json!({"pattern": "fn main"})),
        ("LS", json!({"path": "/workspace"})),
        // Denied by the policy default — the deny path, deliberately included.
        (
            "Write",
            json!({"file_path": "/workspace/out.txt", "content": "x"}),
        ),
        ("Bash", json!({"command": "echo hello"})),
    ]
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<(Params, DbFacts)> {
    let tag = ctx.run_tag.clone();
    let policy = format!("lg-allow-{tag}");
    let agent = format!("lg-agent-{tag}");

    // ── fixtures ────────────────────────────────────────────────────────────
    let template = match args.template_session {
        Some(id) => {
            eprintln!("  using the supplied template session {id} (no run is created)");
            id
        }
        None => {
            ensure_policy(&ctx.http, &policy, &allow_policy_yaml(&policy)).await?;
            ensure_agent(&ctx.http, &agent, &policy, vec![]).await?;
            let id = create_template_run(&ctx.http, &agent, args.template_workspace, &tag).await?;
            eprintln!("  template run {id} created; waiting for it to settle…");
            let status = seed::wait_settled(&ctx.pool, id, 300).await?;
            eprintln!("  template run settled ('{status}') — its RunSpec is now frozen and stable");
            id
        }
    };
    let template = seed::load_template(&ctx.pool, template).await?;

    eprintln!(
        "  seeding {} sessions + {} audience-scoped tokens…",
        args.sessions,
        args.sessions * 4
    );
    let sessions = seed::seed_sessions(&ctx.pool, &template, args.sessions, &tag).await?;
    let ids: Vec<Uuid> = sessions.iter().map(|s| s.id).collect();

    // ── the load ────────────────────────────────────────────────────────────
    let mut jobs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> = Vec::new();
    let mix = tool_mix();
    for (si, s) in sessions.iter().enumerate() {
        for ci in 0..args.gate_calls_per_session {
            // The tool is drawn from the seeded RNG, so the mix a run exercised
            // is replayable from the report's `seed` line.
            let (tool, input) = ctx
                .rng
                .pick(&mix)
                .cloned()
                .expect("tool_mix() is a non-empty literal");
            let http: Http = ctx.http.clone();
            let sid = s.id;
            let token = s.tokens.tool.clone();
            let call_id = format!("{tag}-g{si}-{ci}");
            jobs.push(Box::pin(async move {
                http.session_post(
                    "internal.permission",
                    &format!("/internal/sessions/{sid}/permission"),
                    &token,
                    json!({"tool_call_id": call_id, "tool": tool, "input": input}),
                )
                .await;
            }));
        }
        for _ in 0..args.facade_calls_per_session {
            let http: Http = ctx.http.clone();
            let token = s.tokens.llm.clone();
            let model = args.model.clone();
            jobs.push(Box::pin(async move {
                // The session is bound by the token, not by the path — the
                // facade resolves it from the bearer before it reads anything
                // else, which is exactly the ordering Gap 10 requires.
                http.session_post(
                    "internal.facade",
                    "/internal/llm/v1/messages",
                    &token,
                    json!({
                        "model": model,
                        "max_tokens": 16,
                        "messages": [{"role": "user", "content": "loadgen ping"}]
                    }),
                )
                .await;
            }));
        }
    }
    let total_jobs = jobs.len();
    eprintln!(
        "  driving {total_jobs} requests at concurrency {}…",
        ctx.concurrency
    );
    let started = std::time::Instant::now();
    bounded(ctx.concurrency, jobs).await;
    let wall = started.elapsed();

    // ── facts ───────────────────────────────────────────────────────────────
    let mut facts = DbFacts::new();
    facts.add(
        "ledger deny sources (events.payload->'data'->>'source')",
        seed::deny_sources(&ctx.pool, &ids).await?,
    );

    let params = Params::new()
        .set("seed", ctx.seed)
        .set("run_tag", &tag)
        .set("base_url", &ctx.http.base)
        .set("sessions_seeded", args.sessions)
        .set("gate_calls_per_session", args.gate_calls_per_session)
        .set("facade_calls_per_session", args.facade_calls_per_session)
        .set("requests_issued", total_jobs)
        .set("client_concurrency", ctx.concurrency)
        .set("template_session", template.id)
        .set("template_status_at_clone", &template.status)
        .set("wall_clock_secs", format!("{:.2}", wall.as_secs_f64()))
        .set(
            "throughput_req_per_sec",
            format!(
                "{:.1}",
                total_jobs as f64 / wall.as_secs_f64().max(0.000_001)
            ),
        );

    if !ctx.keep_fixtures {
        let n = seed::cleanup_sessions(&ctx.pool, &ids).await?;
        eprintln!("  cleaned up {n} seeded sessions (and their cascaded children)");
    } else {
        eprintln!(
            "  --keep-fixtures: {} seeded sessions LEFT IN THE DATABASE",
            ids.len()
        );
    }

    Ok((params, facts))
}
