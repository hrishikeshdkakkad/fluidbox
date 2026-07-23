//! Slow approvals.
//!
//! The design bullet is about OCCUPANCY. A supervised `/permission` call does
//! not return: it parks a request handler until a human decides or the approval
//! expires. At 300 concurrent runs that is 300 held connections, 300 axum tasks,
//! and — because Phase E made the decision emit its ledger events INSIDE the
//! deciding transaction and wake waiters over a `pg_notify` on
//! `fluidbox_approvals` — a burst of database work at the moment the decisions
//! land. What this scenario measures is how long those handlers hold, and
//! whether the deployment answers all of them.
//!
//! The two arms differ only in the delay:
//!   * `delay < ttl` — the decision wins; handlers wake on the notify and the
//!     verdict is an allow.
//!   * `delay > ttl` — the expiry worker wins; handlers wake on the ≤2 s poll
//!     floor and the verdict is a deny. Reaching that arm is why the TTL is a
//!     parameter rather than a constant.
//!
//! DISCOVERY IS FROM THE DATABASE, THE DECISION IS THROUGH THE API. Pending
//! approval ids for THIS run's seeded sessions are read with a direct query
//! (precise, and it cannot pick up an operator's unrelated pending work), but
//! each decision goes through `POST /v1/approvals/{id}/decision` so the real
//! path — RBAC, the CAS, the in-transaction ledger append, the cross-replica
//! notify — is the thing under load.

use crate::client::{bounded, Http};
use crate::report::{DbFacts, Params};
use crate::scenarios::{
    approve_policy_yaml, create_template_run, ensure_agent, ensure_policy, Ctx, TemplateWorkspace,
};
use crate::seed;
use anyhow::Result;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Args {
    pub sessions: usize,
    /// How long the "human" takes before deciding.
    pub decide_after_secs: u64,
    /// The policy's `approval_ttl_secs`. Set it BELOW `decide_after_secs` to
    /// drive the expiry arm instead.
    pub ttl_secs: u64,
    pub template_workspace: TemplateWorkspace,
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<(Params, DbFacts)> {
    let tag = ctx.run_tag.clone();
    let policy = format!("lg-approve-{tag}");
    let agent = format!("lg-appr-agent-{tag}");

    ensure_policy(
        &ctx.http,
        &policy,
        &approve_policy_yaml(&policy, args.ttl_secs),
    )
    .await?;
    ensure_agent(&ctx.http, &agent, &policy, vec![]).await?;
    let template = create_template_run(&ctx.http, &agent, args.template_workspace, &tag).await?;
    eprintln!("  template run {template} created; waiting for it to settle…");
    seed::wait_settled(&ctx.pool, template, 300).await?;
    let template = seed::load_template(&ctx.pool, template).await?;
    let sessions = seed::seed_sessions(&ctx.pool, &template, args.sessions, &tag).await?;
    let ids: Vec<Uuid> = sessions.iter().map(|s| s.id).collect();

    // ── fire the blocking gate calls (they do NOT return yet) ───────────────
    let mut jobs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> = Vec::new();
    for (si, s) in sessions.iter().enumerate() {
        let http: Http = ctx.http.clone();
        let sid = s.id;
        let tok = s.tokens.tool.clone();
        let call_id = format!("{tag}-appr-{si}");
        jobs.push(Box::pin(async move {
            http.session_post(
                "internal.permission[blocking]",
                &format!("/internal/sessions/{sid}/permission"),
                &tok,
                json!({
                    "tool_call_id": call_id,
                    "tool": "Read",
                    "input": {"file_path": "/workspace/README.md"}
                }),
            )
            .await;
        }));
    }
    // The gate calls must be IN FLIGHT while the decider runs, so this is the
    // one place the harness does not await its own bounded runner first. The
    // concurrency bound still applies: `bounded` is driven concurrently with the
    // decider by `tokio::join!`.
    let concurrency = ctx.concurrency;
    let gate = bounded(concurrency, jobs);

    let decider = decide_after(
        ctx.http.clone(),
        ctx.pool.clone(),
        ids.clone(),
        args.decide_after_secs,
        args.sessions,
    );

    let started = std::time::Instant::now();
    let (_, decided) = tokio::join!(gate, decider);
    let wall = started.elapsed();
    let decided = decided?;

    // ── facts ───────────────────────────────────────────────────────────────
    let mut facts = DbFacts::new();
    let rows = sqlx::query(
        "select status, count(*) as n from approvals where session_id = any($1) group by 1 order by 2 desc",
    )
    .bind(&ids)
    .fetch_all(&ctx.pool)
    .await?;
    facts.add(
        "approvals by final status",
        rows.into_iter()
            .map(|r| Ok((r.try_get::<String, _>("status")?, r.try_get::<i64, _>("n")?)))
            .collect::<Result<Vec<_>>>()?,
    );
    facts.add(
        "ledger deny sources (an expired approval denies with source='approval')",
        seed::deny_sources(&ctx.pool, &ids).await?,
    );

    let params = Params::new()
        .set("seed", ctx.seed)
        .set("run_tag", &tag)
        .set("base_url", &ctx.http.base)
        .set("sessions_seeded", args.sessions)
        .set("blocking_gate_calls", args.sessions)
        .set("decide_after_secs", args.decide_after_secs)
        .set("approval_ttl_secs", args.ttl_secs)
        .set(
            "arm",
            if args.decide_after_secs < args.ttl_secs {
                "decision-wins (delay < ttl)"
            } else {
                "expiry-wins (delay >= ttl)"
            },
        )
        .set("approvals_decided_via_api", decided)
        .set("client_concurrency", concurrency)
        .set("wall_clock_secs", format!("{:.2}", wall.as_secs_f64()));

    if !ctx.keep_fixtures {
        seed::cleanup_sessions(&ctx.pool, &ids).await?;
        eprintln!("  cleaned up {} seeded sessions", ids.len());
    }
    Ok((params, facts))
}

/// Sleep, then decide every pending approval belonging to this run, through the
/// public API. Returns how many decisions the API accepted.
async fn decide_after(
    http: Http,
    pool: sqlx::PgPool,
    ids: Vec<Uuid>,
    delay_secs: u64,
    expected: usize,
) -> Result<usize> {
    tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
    let mut decided = 0usize;
    // Poll rather than read once: the gate calls are still landing, so the set
    // of pending rows grows for a moment after the delay elapses. The deadline
    // stops this from spinning forever when an arm is EXPECTED to expire
    // instead of being decided.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while decided < expected && std::time::Instant::now() < deadline {
        let rows = sqlx::query(
            "select id from approvals where session_id = any($1) and status = 'pending'",
        )
        .bind(&ids)
        .fetch_all(&pool)
        .await?;
        if rows.is_empty() {
            // Nothing pending: either every one is decided/expired, or none has
            // been created yet. A short sleep covers both without a busy loop.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if decided > 0 {
                break;
            }
            continue;
        }
        let mut jobs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>> =
            Vec::new();
        for r in rows {
            let id: Uuid = r.try_get("id")?;
            let http = http.clone();
            jobs.push(Box::pin(async move {
                http.admin_post(
                    "api.decide_approval",
                    &format!("/v1/approvals/{id}/decision"),
                    json!({"decision": "approved_once"}),
                )
                .await
                .is_2xx()
            }));
        }
        decided += bounded(16, jobs).await.into_iter().filter(|ok| *ok).count();
    }
    Ok(decided)
}
