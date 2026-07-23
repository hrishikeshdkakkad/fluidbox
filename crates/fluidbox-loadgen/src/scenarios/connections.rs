//! The 1,500-saved-connections design bullet.
//!
//! Connections are created through the PUBLIC API, not seeded into the database,
//! and that is the whole point. A `POST /v1/connections` does real work per row:
//! it SSRF-admits the base URL, seals the credential under the tenant's DEK, and
//! then SYNCHRONOUSLY photographs the upstream's tool surface into
//! `connection_tool_snapshots` (`snapshots::photograph_connection`). A row
//! INSERTed straight into the table would have no snapshot, no sealed
//! credential, and no key version — it would inflate a `count(*)` and measure
//! nothing.
//!
//! Two things are therefore measured: the per-create latency distribution
//! (sealing + photograph + two inserts, under concurrency), and the LIST latency
//! at the target size — which is the query an operator's dashboard runs and the
//! one that has to stay usable at 1,500 rows under RLS.

use crate::client::{bounded, Http};
use crate::fakes;
use crate::report::{DbFacts, Params};
use crate::scenarios::Ctx;
use crate::seed;
use anyhow::{anyhow, Result};
use serde_json::json;
use sqlx::Row;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Args {
    pub count: usize,
    /// How many `GET /v1/connections` reads to time once the table is at size.
    pub list_reads: usize,
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<(Params, DbFacts)> {
    let tag = ctx.run_tag.clone();
    let token = format!("lg-upstream-{tag}");
    let fake = fakes::start(&token).await?;
    eprintln!(
        "  fake MCP upstream at {} (loopback; the deployment must be able to dial it)",
        fake.url
    );

    // Prove reachability with ONE create before firing `count` of them: if the
    // deployment cannot dial the fake (no dev-loopback egress seam), every
    // create fails identically and the latency table would be a chart of
    // refusals with no label saying so.
    let (probe, why) = create_one(&ctx.http, &fake.url, &token, &format!("{tag}-probe-0")).await;
    let Some(first_id) = probe else {
        let url = fake.url.clone();
        fake.shutdown();
        return Err(anyhow!(
            "the deployment could not create a connection against the harness's own fake \
             upstream at {url} (outcome: {why}). This scenario needs the dev-loopback egress \
             seam open — boot the control plane with \
             FLUIDBOX_PUBLIC_URL=http://127.0.0.1:<its own port>."
        ));
    };

    let created: Arc<Mutex<Vec<Uuid>>> = Arc::new(Mutex::new(vec![first_id]));
    let remaining = args.count.saturating_sub(1);
    eprintln!(
        "  creating {remaining} more connections at concurrency {}…",
        ctx.concurrency
    );
    let mut jobs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> = Vec::new();
    for i in 0..remaining {
        let http: Http = ctx.http.clone();
        let url = fake.url.clone();
        let tok = token.clone();
        let name = format!("{tag}-{}", i + 1);
        let sink = created.clone();
        jobs.push(Box::pin(async move {
            if let (Some(id), _) = create_one(&http, &url, &tok, &name).await {
                if let Ok(mut g) = sink.lock() {
                    g.push(id);
                }
            }
        }));
    }
    let started = std::time::Instant::now();
    bounded(ctx.concurrency, jobs).await;
    let create_wall = started.elapsed();

    let ids: Vec<Uuid> = created.lock().map(|g| g.clone()).unwrap_or_default();

    // The table's real size, not the harness's opinion of it: an operator's
    // deployment may already hold connections, and the list latency below is a
    // property of the TOTAL, so both numbers are reported.
    let total_rows: i64 = sqlx::query("select count(*) as n from integration_connections")
        .fetch_one(&ctx.pool)
        .await?
        .try_get("n")?;

    eprintln!(
        "  timing {} list reads with {total_rows} connections in the table…",
        args.list_reads
    );
    let mut list_jobs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> =
        Vec::new();
    for _ in 0..args.list_reads {
        let http: Http = ctx.http.clone();
        list_jobs.push(Box::pin(async move {
            http.admin_get("api.list_connections", "/v1/connections")
                .await;
        }));
    }
    bounded(ctx.concurrency.min(16), list_jobs).await;

    let mut facts = DbFacts::new();
    facts.add(
        "connection rows",
        vec![
            ("created_by_this_run".into(), ids.len() as i64),
            ("requested".into(), args.count as i64),
            ("total_in_table".into(), total_rows),
        ],
    );
    let snaps: i64 = sqlx::query(
        "select count(*) as n from connection_tool_snapshots where connection_id = any($1)",
    )
    .bind(&ids)
    .fetch_one(&ctx.pool)
    .await?
    .try_get("n")?;
    facts.add(
        "connection_tool_snapshots photographed for this run's connections",
        vec![("rows".into(), snaps)],
    );

    let params = Params::new()
        .set("seed", ctx.seed)
        .set("run_tag", &tag)
        .set("base_url", &ctx.http.base)
        .set("connections_requested", args.count)
        .set("connections_created", ids.len())
        .set("connections_in_table_after", total_rows)
        .set("list_reads", args.list_reads)
        .set("client_concurrency", ctx.concurrency)
        .set(
            "create_wall_clock_secs",
            format!("{:.2}", create_wall.as_secs_f64()),
        )
        .set(
            "fake_upstream_requests",
            fake.state.hits.load(std::sync::atomic::Ordering::Relaxed),
        );

    if !ctx.keep_fixtures {
        let n = seed::cleanup_connections(&ctx.pool, &ids).await?;
        eprintln!("  cleaned up {n} seeded connections");
    } else {
        eprintln!(
            "  --keep-fixtures: {} connections LEFT IN THE DATABASE",
            ids.len()
        );
    }
    fake.shutdown();
    Ok((params, facts))
}

/// Returns the created id (when it worked) and the classified outcome either
/// way — the caller's failure message names WHY, which is the difference
/// between "the egress seam is closed" and "the deployment throttled us".
async fn create_one(http: &Http, url: &str, token: &str, name: &str) -> (Option<Uuid>, String) {
    let a = http
        .admin_post(
            "api.create_connection",
            "/v1/connections",
            json!({
                "provider": "mcp_http",
                "display_name": format!("loadgen {name}"),
                "base_url": url,
                "token": token,
                "header_name": "authorization",
                "scheme": "Bearer",
                "auth_kind": "static",
                "owner": "organization",
            }),
        )
        .await;
    let id = a
        .str_at(&["connection", "id"])
        .and_then(|s| Uuid::parse_str(&s).ok());
    (id, a.outcome.label())
}
