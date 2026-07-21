//! The fast path: N concurrent sandboxes without N containers.
//!
//! WHY THIS EXISTS. Simulating 300 concurrent sandboxes by provisioning 300
//! containers measures the container runtime, costs real money, and cannot run
//! in CI. But the control plane's concurrency surface — the permission gate, the
//! LLM facade, the broker, the approval machinery — does not know or care that a
//! sandbox exists. It sees exactly two things:
//!
//!   * a `sessions` row in a status that `accepts_work()`, and
//!   * an `api_tokens` row whose `token_sha256` matches a plaintext bearer.
//!
//! `scripts/hardening-e2e.sh:1159` (`forge_running`) established that recipe. It
//! is, however, far too slow at this scale: it creates EVERY run through the
//! public API and then waits for provisioning to fail and the finalizer to
//! quiesce — on the order of a second per run at best, ~140 s per run when the
//! workspace materialized (see that script's `create_run` comment). At 300 runs
//! that is not a load test, it is a coffee break.
//!
//! THE FAST PATH: create ONE run properly through `POST /v1/sessions` so the
//! RunSpec is GENUINE — frozen policy snapshot, frozen brokered surfaces, frozen
//! schemas, real budgets — then clone that row N times directly and mint the
//! four audience-scoped tokens per clone. Two statements total, regardless of N.
//!
//! WHAT THE CLONES INHERIT AND WHY IT IS SOUND. Every column that governs a gate
//! decision (`run_spec`, `budgets`, `autonomy`, `trust_tier`, `agent_revision_id`,
//! `tenant_id`) is copied VERBATIM from the template, so a clone is governed by
//! the same frozen photograph the real run was. The columns deliberately NOT
//! copied are the lifecycle ones: `status` is forced to `running`, and
//! `started_at` / `last_heartbeat_at` stay NULL so the heartbeat watchdog and the
//! wall-clock budget sweeper have nothing of theirs to reap (the same property
//! `forge_running` relies on). No clone ever had a sandbox handle, so the
//! boot-time orphan reap has nothing to do either.
//!
//! WHAT IT DOES NOT SIMULATE is stated in the crate docs and in the report
//! footer — this seeds the control plane's view of N runs, not N sandboxes.

use anyhow::{anyhow, Context, Result};
use sqlx::postgres::{PgPoolOptions, PgQueryResult};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// The four audiences migration 0020 defines. `all` is deliberately absent: it
/// is the column DEFAULT (the in-flight-compat legacy token), and a harness that
/// used it would be testing the compatibility path instead of the real one.
pub const AUDIENCES: [&str; 4] = ["llm", "tool", "control", "workspace"];

#[derive(Clone, Debug)]
pub struct Tokens {
    pub llm: String,
    pub tool: String,
    pub control: String,
    pub workspace: String,
}

#[derive(Clone, Debug)]
pub struct SeededSession {
    pub id: Uuid,
    pub tokens: Tokens,
}

/// Connect a pool that carries the audited cross-tenant bypass on every
/// connection.
///
/// Migration 0018 `ENABLE`s and `FORCE`s RLS on every tenant-owned table, and
/// `FORCE` binds even the table owner — so without a GUC a fixture read returns
/// zero rows and a fixture INSERT is refused outright. The harness sets
/// `fluidbox.bypass = 'system_worker'`, the same audited escape hatch
/// `fluidbox-db::worker_tx` uses, session-level in `after_connect`. This is a
/// TEST FIXTURE writing test rows; it is named here rather than hidden so that
/// grepping the tree for the bypass still finds every user of it.
pub async fn connect(database_url: &str, max_conns: u32) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(max_conns.max(2))
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("set fluidbox.bypass = 'system_worker'")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
        .context("connecting the seeding pool")
}

/// The quiescent point `forge_running` waits for: terminal AND the finalization
/// intent cleared. Anything earlier and a background worker may still write the
/// row we are about to photograph.
pub async fn wait_settled(pool: &PgPool, session: Uuid, deadline_secs: u64) -> Result<String> {
    let start = std::time::Instant::now();
    let mut last = String::new();
    while start.elapsed().as_secs() < deadline_secs {
        let row = sqlx::query(
            "select s.status,
                    (select count(*) from session_finalizations f where f.session_id = s.id) as fin
               from sessions s where s.id = $1",
        )
        .bind(session)
        .fetch_optional(pool)
        .await?;
        let Some(row) = row else {
            return Err(anyhow!("template session {session} does not exist"));
        };
        let status: String = row.try_get("status")?;
        let fin: i64 = row.try_get("fin")?;
        last = status.clone();
        if matches!(
            status.as_str(),
            "completed" | "failed" | "cancelled" | "budget_exceeded"
        ) && fin == 0
        {
            return Ok(status);
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Err(anyhow!(
        "template session {session} did not settle within {deadline_secs}s (last status '{last}')"
    ))
}

/// Every field a clone needs, read once.
#[derive(Clone, Debug)]
pub struct Template {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub status: String,
}

pub async fn load_template(pool: &PgPool, session: Uuid) -> Result<Template> {
    let row = sqlx::query("select id, tenant_id, status from sessions where id = $1")
        .bind(session)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow!("template session {session} does not exist"))?;
    Ok(Template {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        status: row.try_get("status")?,
    })
}

/// Clone `count` sessions from `template` and mint 4 audience-scoped tokens for
/// each. Two statements, one transaction.
///
/// `run_tag` namespaces the token plaintexts so a report can be tied back to the
/// rows it produced; it must be unique per run (`api_tokens.token_sha256` is
/// UNIQUE, so a repeated tag against the same database is an insert failure, not
/// a silent overwrite).
pub async fn seed_sessions(
    pool: &PgPool,
    template: &Template,
    count: usize,
    run_tag: &str,
) -> Result<Vec<SeededSession>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let ids: Vec<Uuid> = (0..count).map(|_| Uuid::now_v7()).collect();
    let sessions: Vec<SeededSession> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| SeededSession {
            id: *id,
            tokens: Tokens {
                llm: token_plaintext(run_tag, i, "llm"),
                tool: token_plaintext(run_tag, i, "tool"),
                control: token_plaintext(run_tag, i, "control"),
                workspace: token_plaintext(run_tag, i, "workspace"),
            },
        })
        .collect();

    let mut tx = pool.begin().await?;

    // (1) The session clones. Every governing column comes from the template
    // row via a CROSS JOIN, so there is exactly one source of truth for the
    // frozen RunSpec and no opportunity for the harness to invent one.
    let inserted: PgQueryResult = sqlx::query(
        "insert into sessions (id, tenant_id, agent_id, agent_revision_id, status, status_reason,
                               autonomy, trust_tier, task, repo_source, run_spec, budgets)
         select x.id, t.tenant_id, t.agent_id, t.agent_revision_id, 'running', $3,
                t.autonomy, t.trust_tier, t.task, t.repo_source, t.run_spec, t.budgets
           from unnest($1::uuid[]) as x(id)
           cross join (select tenant_id, agent_id, agent_revision_id, autonomy, trust_tier,
                              task, repo_source, run_spec, budgets
                         from sessions where id = $2) as t",
    )
    .bind(&ids)
    .bind(template.id)
    .bind(format!(
        "fluidbox-loadgen fixture ({run_tag}); cloned from {} — never provisioned a sandbox",
        template.id
    ))
    .execute(&mut *tx)
    .await
    .context("cloning template sessions")?;
    if inserted.rows_affected() as usize != count {
        return Err(anyhow!(
            "seeded {} session rows, expected {count} — the template row may have vanished",
            inserted.rows_affected()
        ));
    }

    // (2) The audience-scoped tokens: the same row shape the orchestrator mints
    // (kind 'session', token_sha256 = sha256(plaintext)) plus 0020's `audience`.
    let mut tok_session: Vec<Uuid> = Vec::with_capacity(count * 4);
    let mut tok_sha: Vec<String> = Vec::with_capacity(count * 4);
    let mut tok_aud: Vec<String> = Vec::with_capacity(count * 4);
    for s in &sessions {
        for aud in AUDIENCES {
            tok_session.push(s.id);
            tok_sha.push(sha256_hex(
                s.token_for(aud).expect("AUDIENCES is exhaustive"),
            ));
            tok_aud.push(aud.to_string());
        }
    }
    let minted: PgQueryResult = sqlx::query(
        "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, audience, expires_at)
         select gen_random_uuid(), $4, 'session', s.session_id, s.sha, s.aud, now() + interval '4 hours'
           from unnest($1::uuid[], $2::text[], $3::text[]) as s(session_id, sha, aud)",
    )
    .bind(&tok_session)
    .bind(&tok_sha)
    .bind(&tok_aud)
    .bind(template.tenant_id)
    .execute(&mut *tx)
    .await
    .context("minting audience-scoped session tokens")?;
    if minted.rows_affected() as usize != count * 4 {
        return Err(anyhow!(
            "minted {} token rows, expected {}",
            minted.rows_affected(),
            count * 4
        ));
    }

    tx.commit().await?;
    Ok(sessions)
}

impl SeededSession {
    pub fn token_for(&self, audience: &str) -> Option<&str> {
        match audience {
            "llm" => Some(&self.tokens.llm),
            "tool" => Some(&self.tokens.tool),
            "control" => Some(&self.tokens.control),
            "workspace" => Some(&self.tokens.workspace),
            _ => None,
        }
    }
}

/// Delete seeded fixtures. `sessions` is the only table named: every child that
/// a seeded run can acquire (`api_tokens`, `events`, `tool_execution_claims`,
/// `llm_reservations`, `run_resource_bindings`, `session_finalizations`,
/// `mcp_upstream_sessions`, `trigger_dispatches`) carries `on delete cascade`
/// from its migration, and `github_events` is `on delete set null`.
pub async fn cleanup_sessions(pool: &PgPool, ids: &[Uuid]) -> Result<u64> {
    if ids.is_empty() {
        return Ok(0);
    }
    let r = sqlx::query("delete from sessions where id = any($1)")
        .bind(ids)
        .execute(pool)
        .await
        .context("deleting seeded sessions")?;
    Ok(r.rows_affected())
}

/// Delete seeded connections. `connection_tool_snapshots` and
/// `run_resource_bindings` cascade (0013); `trigger_deliveries` cascades (0005);
/// `connector_oauth_flows` (0016) does NOT cascade but a seeded static
/// connection never creates one.
pub async fn cleanup_connections(pool: &PgPool, ids: &[Uuid]) -> Result<u64> {
    if ids.is_empty() {
        return Ok(0);
    }
    let r = sqlx::query("delete from integration_connections where id = any($1)")
        .bind(ids)
        .execute(pool)
        .await
        .context("deleting seeded connections")?;
    Ok(r.rows_affected())
}

/// The authoritative gate-stage histogram, read from the LEDGER rather than
/// inferred from a denial's prose.
///
/// `events.payload` is the adjacently-tagged `EventBody`, so every body field
/// sits under `->'data'` — reading `payload->>'source'` at the top level yields
/// SQL NULL and silently counts zero (the exact mistake documented at
/// `scripts/hardening-e2e.sh`'s `decision_source`).
pub async fn deny_sources(pool: &PgPool, ids: &[Uuid]) -> Result<Vec<(String, i64)>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "select coalesce(payload->'data'->>'source', '<null>') as source,
                count(*) as n
           from events
          where session_id = any($1)
            and type = 'tool.decision'
            and payload->'data'->>'verdict' = 'deny'
          group by 1 order by 2 desc",
    )
    .bind(ids)
    .fetch_all(pool)
    .await
    .context("reading the ledger's deny-source histogram")?;
    rows.into_iter()
        .map(|r| Ok((r.try_get("source")?, r.try_get("n")?)))
        .collect()
}

/// The four-state execution-claim histogram for one arm of a failure matrix,
/// selected by `tool_call_id` prefix (migration 0019).
pub async fn claim_states(
    pool: &PgPool,
    ids: &[Uuid],
    tool_call_prefix: &str,
) -> Result<Vec<(String, i64)>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "select state, count(*) as n
           from tool_execution_claims
          where session_id = any($1) and tool_call_id like $2
          group by 1 order by 2 desc",
    )
    .bind(ids)
    .bind(format!("{tool_call_prefix}%"))
    .fetch_all(pool)
    .await
    .context("reading the execution-claim state histogram")?;
    rows.into_iter()
        .map(|r| Ok((r.try_get("state")?, r.try_get("n")?)))
        .collect()
}

pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// The `fbx_sess_` prefix is not cosmetic: `event.rs`'s Redactor scrubs it, so a
/// harness token that leaked into a ledger payload would be redacted exactly
/// like a real one.
fn token_plaintext(run_tag: &str, idx: usize, audience: &str) -> String {
    format!("fbx_sess_lg_{run_tag}_{idx}_{audience}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Matches `fluidbox-db::sha256_hex` — the digest the token resolver
    /// compares against. A mismatch here makes every seeded token a 401.
    #[test]
    fn sha256_matches_the_servers_digest_of_a_known_string() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn token_plaintexts_are_unique_per_session_and_audience_and_carry_the_redacted_prefix() {
        let mut seen = std::collections::HashSet::new();
        for idx in 0..8 {
            for aud in AUDIENCES {
                let t = token_plaintext("tag1", idx, aud);
                assert!(
                    t.starts_with("fbx_sess_"),
                    "{t} must carry the scrubbed prefix"
                );
                assert!(seen.insert(t), "token plaintexts must not collide");
            }
        }
        // A different run tag must not collide with the first — this is what
        // keeps a re-run from tripping api_tokens' UNIQUE token_sha256.
        for idx in 0..8 {
            for aud in AUDIENCES {
                assert!(seen.insert(token_plaintext("tag2", idx, aud)));
            }
        }
    }

    #[test]
    fn token_for_covers_exactly_the_four_audiences() {
        let s = SeededSession {
            id: Uuid::nil(),
            tokens: Tokens {
                llm: "a".into(),
                tool: "b".into(),
                control: "c".into(),
                workspace: "d".into(),
            },
        };
        for aud in AUDIENCES {
            assert!(s.token_for(aud).is_some(), "{aud} must resolve");
        }
        assert!(
            s.token_for("all").is_none(),
            "'all' is the legacy default, not a scoped audience"
        );
        assert!(s.token_for("nonsense").is_none());
    }
}
