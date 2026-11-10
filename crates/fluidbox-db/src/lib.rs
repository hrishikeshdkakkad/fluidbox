//! fluidbox-db — sqlx repositories over Neon Postgres.
//!
//! Connection rule: the DIRECT (non-pooler) connection string. NOTIFY is
//! only a wakeup; the seq catch-up query is the delivery source of truth.

pub mod governance;
pub mod identity;
pub mod mcp_sessions;
pub mod network_grants;
pub mod recipes;
pub mod seed;
pub mod system_worker;

mod event_log;

mod agents;
mod approvals;
mod artifacts;
mod capability_bundles;
mod catalog;
mod connections;
mod connector_oauth;
mod events;
mod finalizations;
mod github_app;
mod llm_reservations;
mod notify;
mod policies;
mod pool;
mod result_deliveries;
mod run_resource_bindings;
mod schedules;
mod scope;
mod sessions;
mod tenants;
mod tokens;
mod tool_executions;
mod tool_snapshots;
mod trigger_deliveries;
mod trigger_invocations;
mod trigger_subscriptions;
mod usage;

pub use agents::*;
pub use approvals::*;
pub use artifacts::*;
pub use capability_bundles::*;
pub use catalog::*;
pub use connections::*;
pub use connector_oauth::*;
pub use events::*;
pub use finalizations::*;
pub use github_app::*;
pub use llm_reservations::*;
pub use notify::*;
pub use policies::*;
pub use pool::*;
pub use result_deliveries::*;
pub use run_resource_bindings::*;
pub use schedules::*;
pub use scope::*;
pub use sessions::*;
pub use tenants::*;
pub use tokens::*;
pub use tool_executions::*;
pub use tool_snapshots::*;
pub use trigger_deliveries::*;
pub use trigger_invocations::*;
pub use trigger_subscriptions::*;
pub use usage::*;

// ─── Integration test (runs only when DATABASE_URL is set) ───────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use fluidbox_core::event::{Actor, EventBody, EventEnvelope, Redacted, Redactor};
    use fluidbox_core::state::SessionStatus;
    use serde_json::Value;
    use sqlx::postgres::{PgListener, PgPoolOptions};
    use sqlx::{PgPool, Row};
    use uuid::Uuid;

    // ─── Tenant-less global scans in a SHARED database (#33) ────────────────
    //
    // Every `system_worker` scan is a TENANT-LESS GLOBAL scan, and that is the
    // production contract: one worker tick sweeps every tenant on every replica,
    // and each returned row carries its own `tenant_id`/`session_id` so the
    // caller ledgers it under the right scope. Nothing below argues with that.
    //
    // But `cargo test` runs this module's tests CONCURRENTLY against ONE
    // database, so a scan issued by one test also sees — and converts, and
    // CLAIMS — the rows of every test running beside it. That produces two
    // distinct failures, both reproduced on a scratch Postgres:
    //
    //   * EXTRA rows. A sibling's expired row lands in my batch, so any assertion
    //     about the batch's LENGTH is really an assertion about the whole
    //     database. This is what broke CI: `sweep_converts_…` counted 2 and its
    //     sibling counted 0 — one sweep statement had converted BOTH tests'
    //     reservations (identical `usage_entries.created_at` to the microsecond,
    //     i.e. one transaction, across two different tenants).
    //     Cured by [`GLOBAL_SCAN`]-guarded helpers that FILTER every batch down to
    //     the rows the calling test owns.
    //
    //   * STOLEN rows. A sibling's scan converts/claims MY row in the window
    //     between my making it scannable and my own scan — measured at 3/6 runs
    //     for the stale-claim pair and 6/6 for the delivery trio — so filtering
    //     alone still leaves "my scan reported my row" flaky, and for the claim
    //     scans it also hands my row's LEASE to another owner id.
    //     Cured by [`GLOBAL_SCAN`].
    //
    // The tests are NOT serialized: they seed, reserve, assert and clean up
    // concurrently as before. Only the window in which one test's rows are
    // scannable-but-not-yet-scanned is mutually exclusive, and every scan runs
    // inside one — which is exactly the condition under which a global scan can
    // be reasoned about locally. `tenant_less_scans_go_through_the_scoped_helpers`
    // below keeps it that way.
    static GLOBAL_SCAN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// This session's slice of a global expired-reservation sweep. The sweep and
    /// its `Utc::now()` cutoff are the real ones — only the ROWS are narrowed, so
    /// every property the callers assert (what was converted, with which tokens,
    /// under which tenant/session, and that a second sweep reports nothing more)
    /// survives intact while a sibling tenant's booking in the same batch stops
    /// being this test's business. Call under a [`GLOBAL_SCAN`] guard taken before
    /// the reservation was expired.
    async fn sweep_reservations(
        pool: &PgPool,
        session: Uuid,
    ) -> Vec<system_worker::SweptReservation> {
        system_worker::sweep_expired_llm_reservations(pool, Utc::now(), 100)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.session_id == session)
            .collect()
    }

    /// This session's slice of a global stale-execution-claim sweep — same
    /// narrowing, same reasons, same guard discipline as [`sweep_reservations`].
    async fn sweep_stale_claims(
        pool: &PgPool,
        session: Uuid,
    ) -> Vec<(Uuid, Uuid, String, Option<String>)> {
        system_worker::sweep_stale_execution_claims(pool, Utc::now(), 200)
            .await
            .unwrap()
            .into_iter()
            .filter(|(_, s, _, _)| *s == session)
            .collect()
    }

    /// The rows THIS test enqueued that `owner` just claimed. The claim scan is
    /// the real one — `owner`, `limit` and `ttl_secs` reach it untouched, so the
    /// `limit`/`skip locked`/lease behaviour under test is unchanged — but a
    /// sibling test's delivery that happened to be due is not this test's row and
    /// is dropped from the answer. Call under a [`GLOBAL_SCAN`] guard taken before
    /// the deliveries were enqueued: unlike the sweeps, a stolen delivery is not
    /// merely unobserved, it is LEASED to another owner id, which no filter can
    /// undo.
    async fn claim_deliveries(
        pool: &PgPool,
        owner: Uuid,
        limit: i64,
        ttl_secs: i64,
        mine: &[Uuid],
    ) -> Vec<ResultDeliveryRow> {
        system_worker::claim_due_deliveries(pool, owner, limit, ttl_secs)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| mine.contains(&r.id))
            .collect()
    }

    /// Source guard for the #33 class, in the shape of the #32 one above: a scan
    /// with no tenant predicate must never be called bare from a test, because a
    /// bare call asserts about every OTHER test's rows and races them for their
    /// own. This is a source assertion, not a DB test — it runs without
    /// `DATABASE_URL`, so a re-added bare caller fails immediately instead of
    /// flaking one CI run in eight. Each needle is assembled from two halves so
    /// the guard is not itself an occurrence.
    #[test]
    fn tenant_less_scans_go_through_the_scoped_helpers() {
        let src = include_str!("lib.rs");
        for (needle, helper) in [
            (
                concat!("sweep_expired_llm", "_reservations("),
                "sweep_reservations",
            ),
            (
                concat!("sweep_stale_execution", "_claims("),
                "sweep_stale_claims",
            ),
            (concat!("claim_due", "_deliveries("), "claim_deliveries"),
            (
                concat!("expired_pending", "_approvals("),
                "the single containment-only caller",
            ),
        ] {
            let n = src.matches(needle).count();
            assert_eq!(
                n, 1,
                "`{needle}` must appear exactly ONCE in fluidbox-db — inside {helper} — \
                 found {n}. Route the new call through that helper and hold GLOBAL_SCAN \
                 from the moment your rows become scannable: a bare call counts every \
                 other test's rows into your batch and converts/claims them out of theirs."
            );
        }
    }

    /// The durable-finalizer DB contract (PR #47 fix batch 2 — H3/H5):
    /// single-winner intent under the session row lock, quiesce computed from
    /// the LOCKED snapshot, losers receive the winner's row, recovery sees
    /// intents on ACTIVE sessions, and a terminal session fences both intent
    /// re-creation and late sandbox-handle attachment.
    #[tokio::test]
    async fn finalization_intent_is_transactional_and_single_winner() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-finalize",
            "name: test-finalize",
            &serde_json::json!({"name": "test-finalize"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-finalize-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        let repo = serde_json::json!({"kind":"none"});
        let empty = serde_json::json!({});
        let mk = |title: &'static str| {
            create_session(
                &pool,
                scope,
                agent.id,
                rev.id,
                "supervised",
                "trusted",
                title,
                &repo,
                &empty,
                &empty,
                None,
                None,
                None,
                None,
                None,
                &[],
                None,
            )
        };
        let racer = mk("finalize-test race").await.unwrap();
        let fenced = mk("finalize-test fence").await.unwrap();

        use fluidbox_core::state::SessionStatus;
        // Advance the race session to running with a handle so the locked
        // snapshot computes a REAL quiesce for want_quiesce callers.
        for st in [
            SessionStatus::Provisioning,
            SessionStatus::Initializing,
            SessionStatus::Running,
        ] {
            transition_session(&pool, scope, racer.id, st, None)
                .await
                .unwrap();
        }
        let attached_active = set_sandbox_handle(
            &pool,
            scope,
            racer.id,
            &serde_json::json!({"external_id":"t","uid":"u"}),
        )
        .await
        .unwrap();

        // Genuinely concurrent: two connections race the insert under the
        // row lock — a cancel (wants quiesce) against a /result (does not).
        let (a, b) = tokio::join!(
            begin_finalization(
                &pool,
                scope,
                racer.id,
                "cancelled",
                None,
                Some("race"),
                true,
                30
            ),
            begin_finalization(
                &pool,
                scope,
                racer.id,
                "completed",
                Some("done"),
                None,
                false,
                30
            ),
        );
        let unpack = |r: sqlx::Result<BeginFinalization>| match r.unwrap() {
            BeginFinalization::Persisted {
                row,
                created,
                session_status,
            } => (row, created, session_status),
            other => panic!("expected Persisted, got {other:?}"),
        };
        let (row_a, created_a, status_a) = unpack(a);
        let (row_b, created_b, status_b) = unpack(b);

        // Recovery must see the intent while the session is still ACTIVE
        // (the crash-between-persist-and-transition window).
        let pending_while_active = system_worker::pending_finalizations(&pool).await.unwrap();

        // Claim semantics: one holder at a time; an early release (the
        // deliberate settle-defer path) re-opens it immediately, without
        // waiting out the stale threshold.
        let claim1 = claim_finalization(&pool, scope, racer.id, 420)
            .await
            .unwrap();
        let claim_held = claim_finalization(&pool, scope, racer.id, 420)
            .await
            .unwrap();
        release_finalization_claim(&pool, scope, racer.id)
            .await
            .unwrap();
        let claim_after_release = claim_finalization(&pool, scope, racer.id, 420)
            .await
            .unwrap();

        // Fence session: persist an intent, terminalize legally, release the
        // intent, then try to re-create it and to attach a handle late.
        let first_fence = begin_finalization(
            &pool,
            scope,
            fenced.id,
            "failed",
            None,
            Some("t"),
            false,
            30,
        )
        .await
        .unwrap();
        // The gap that matters: intent committed, wind-down transition NOT
        // yet applied — the session status still accepts work, but the
        // intent alone must fence a late attach.
        let attached_intent_gap = set_sandbox_handle(
            &pool,
            scope,
            fenced.id,
            &serde_json::json!({"external_id":"tg","uid":"ug"}),
        )
        .await
        .unwrap();
        transition_session(&pool, scope, fenced.id, SessionStatus::Finalizing, None)
            .await
            .unwrap();
        // Wind-down owns the session: a provisioning race may no longer
        // attach a handle.
        let attached_winddown = set_sandbox_handle(
            &pool,
            scope,
            fenced.id,
            &serde_json::json!({"external_id":"tw","uid":"uw"}),
        )
        .await
        .unwrap();
        transition_session(&pool, scope, fenced.id, SessionStatus::Failed, None)
            .await
            .unwrap();
        // Terminal + intent = cleanup still owed: recovery must see it.
        let pending_while_terminal = system_worker::pending_finalizations(&pool).await.unwrap();
        delete_finalization(&pool, scope, fenced.id).await.unwrap();
        let pending_after_release = system_worker::pending_finalizations(&pool).await.unwrap();
        let post_terminal =
            begin_finalization(&pool, scope, fenced.id, "cancelled", None, None, true, 30)
                .await
                .unwrap();
        let attached_terminal = set_sandbox_handle(
            &pool,
            scope,
            fenced.id,
            &serde_json::json!({"external_id":"t2","uid":"u2"}),
        )
        .await
        .unwrap();
        let missing = begin_finalization(
            &pool,
            scope,
            Uuid::now_v7(),
            "failed",
            None,
            None,
            false,
            30,
        )
        .await
        .unwrap();

        // Fixtures out BEFORE the assertions (session delete cascades to the
        // surviving intent).
        for id in [racer.id, fenced.id] {
            sqlx::query("delete from sessions where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(attached_active, "handle attach must succeed while active");
        assert!(
            created_a ^ created_b,
            "exactly one racer creates the intent (created_a={created_a}, created_b={created_b})"
        );
        assert_eq!(
            row_a.outcome, row_b.outcome,
            "both racers must hold the WINNER's row"
        );
        assert_eq!(row_a.needs_quiesce, row_b.needs_quiesce);
        let winner_is_cancel = row_a.outcome == "cancelled";
        assert_eq!(
            row_a.needs_quiesce, winner_is_cancel,
            "quiesce comes from the winning intent, derived from the locked snapshot"
        );
        assert_eq!(
            row_a.quiesce_deadline.is_some(),
            winner_is_cancel,
            "deadline exists iff the winner wanted quiesce"
        );
        assert_eq!(status_a, "running");
        assert_eq!(status_b, "running");
        assert!(
            pending_while_active.contains(&racer.id),
            "recovery must scan intents on ACTIVE sessions"
        );
        assert!(claim1.is_some(), "first claim must succeed");
        assert!(
            claim_held.is_none(),
            "a held claim must not be re-claimable"
        );
        assert!(
            claim_after_release.is_some(),
            "an early-released claim must be immediately re-claimable"
        );
        assert!(matches!(
            first_fence,
            BeginFinalization::Persisted { created: true, .. }
        ));
        assert!(
            !attached_intent_gap,
            "a committed intent must fence attach BEFORE the wind-down transition lands"
        );
        assert!(
            !attached_winddown,
            "a winding-down session must refuse a late sandbox handle"
        );
        assert!(
            pending_while_terminal.contains(&fenced.id),
            "recovery must see intents on TERMINAL sessions (cleanup owed)"
        );
        assert!(
            !pending_after_release.contains(&fenced.id),
            "a released intent leaves the recovery worklist"
        );
        assert!(
            matches!(post_terminal, BeginFinalization::AlreadyTerminal),
            "a terminal session must fence intent re-creation"
        );
        assert!(
            !attached_terminal,
            "a terminal session must refuse a late sandbox handle"
        );
        assert!(matches!(missing, BeginFinalization::Missing));
    }

    #[tokio::test]
    async fn append_event_assigns_gapless_seq_and_notifies() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        let policy = upsert_policy(
            &pool,
            scope,
            "test-seq",
            "name: test-seq",
            &serde_json::json!({"name": "test-seq"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-seq-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "t",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        let mut listener = PgListener::connect(&url).await.unwrap();
        listener.listen("fluidbox_events").await.unwrap();

        let redactor = Redactor::default();
        let mut seqs = Vec::new();
        for i in 0..3 {
            let env = EventEnvelope::new(
                session.id,
                Actor::System,
                EventBody::AgentMessage {
                    role: "assistant".into(),
                    text: format!("m{i}"),
                },
            );
            seqs.push(
                append_event(&pool, scope, redactor.scrub(env))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(seqs, vec![1, 2, 3]);

        let n = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .expect("notify within 5s")
            .expect("notify ok");
        assert!(n.payload().starts_with(&session.id.to_string()));

        let events = events_after(&pool, scope, session.id, 0, 10).await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].r#type, "agent.message");
    }

    #[tokio::test]
    async fn session_token_revoke_is_terminal_and_extend_cannot_resurrect() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-token",
            "name: test-token",
            &serde_json::json!({"name": "test-token"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-token-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "codex",
            "img:test",
            "gpt-5.4-mini",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "autonomous",
            "trusted",
            "t",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        // Gap 10: a run mints FOUR audience-scoped tokens. Mint two here + forge
        // a legacy (no-audience) row to exercise the whole contract.
        let control = format!("fbx_sess_{}", Uuid::now_v7().simple());
        let tool = format!("fbx_sess_{}", Uuid::now_v7().simple());
        create_session_token(&pool, scope, session.id, &control, 3600, "control")
            .await
            .unwrap();
        create_session_token(&pool, scope, session.id, &tool, 3600, "tool")
            .await
            .unwrap();

        // Audience is PERSISTED and RETURNED by the resolver.
        let a = session_for_token(&pool, &control).await.unwrap().unwrap();
        assert_eq!(a.session_id, session.id);
        assert_eq!(a.audience, "control");
        assert_eq!(
            session_for_token(&pool, &tool)
                .await
                .unwrap()
                .unwrap()
                .audience,
            "tool"
        );

        // A legacy row inserted WITHOUT an audience gets the column DEFAULT 'all'
        // (in-flight compat + the e2e forgers rely on this forever).
        let legacy = format!("fbx_sess_{}", Uuid::now_v7().simple());
        {
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query(
                "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, expires_at)
                 values ($1, $2, 'session', $3, $4, now() + interval '1 hour')",
            )
            .bind(Uuid::now_v7())
            .bind(tenant)
            .bind(session.id)
            .bind(sha256_hex(&legacy))
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        assert_eq!(
            session_for_token(&pool, &legacy)
                .await
                .unwrap()
                .unwrap()
                .audience,
            "all"
        );

        // Renew contract: presenting ONE token (control) extends EVERY token for
        // the session — the tool token we did NOT present must move too.
        let expiry = |sha: String| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
                    "select expires_at from api_tokens where token_sha256 = $1",
                )
                .bind(sha)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        // A SECOND session with its own control token. "Renew extends all" is
        // scoped to ONE session: without this, a renew that dropped the
        // `session_id in (…)` predicate and extended every live session token in
        // the table would pass every assertion above. Same tenant on purpose —
        // tenant scoping cannot be what saves us here.
        let other_session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "autonomous",
            "trusted",
            "t2",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
        )
        .await
        .unwrap();
        let other_control = format!("fbx_sess_{}", Uuid::now_v7().simple());
        create_session_token(
            &pool,
            scope,
            other_session.id,
            &other_control,
            3600,
            "control",
        )
        .await
        .unwrap();

        let tool_before = expiry(sha256_hex(&tool)).await;
        let other_before = expiry(sha256_hex(&other_control)).await;
        assert!(extend_session_token(&pool, &control, 7200).await.unwrap());
        let tool_after = expiry(sha256_hex(&tool)).await;
        assert!(
            tool_after > tool_before,
            "renewing via control must extend the tool token too (renew-extends-all)"
        );
        assert_eq!(
            expiry(sha256_hex(&other_control)).await,
            other_before,
            "a renew must NOT touch another session's tokens (extends-all is per-SESSION)"
        );

        // Terminal transition revokes ALL the session's tokens (control + tool +
        // legacy = 3) — every audience loses access at once, and only this
        // session's: the count excludes the other session's live token.
        assert_eq!(
            revoke_session_tokens(&pool, scope, session.id)
                .await
                .unwrap(),
            3
        );
        assert!(session_for_token(&pool, &control).await.unwrap().is_none());
        assert!(session_for_token(&pool, &tool).await.unwrap().is_none());
        assert!(
            session_for_token(&pool, &other_control)
                .await
                .unwrap()
                .is_some(),
            "another session's token must survive this session's terminal revoke"
        );
        // And a renew can never resurrect a revoked set.
        assert!(!extend_session_token(&pool, &control, 3600).await.unwrap());
        // Revoking again is a no-op (idempotent).
        assert_eq!(
            revoke_session_tokens(&pool, scope, session.id)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn intent_registry_digest_binding_and_lifecycle() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-intent",
            "name: test-intent",
            &serde_json::json!({"name": "test-intent"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-intent-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "codex",
            "img:test",
            "gpt-5.4-mini",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "t",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        // Registration is idempotent by (session, tool_call_id).
        let (row, inserted) =
            register_tool_intent(&pool, scope, session.id, "tc1", "Bash", "cat x", "digest-a")
                .await
                .unwrap();
        assert!(inserted);
        assert_eq!(row.status, "intent");
        assert_eq!(row.input_digest.as_deref(), Some("digest-a"));
        let (again, inserted2) =
            register_tool_intent(&pool, scope, session.id, "tc1", "Bash", "cat x", "digest-a")
                .await
                .unwrap();
        assert!(!inserted2);
        assert_eq!(again.id, row.id);
        // The caller compares digests — the registry hands back the stored
        // binding even on a mismatched retry.
        let (mismatch, inserted3) =
            register_tool_intent(&pool, scope, session.id, "tc1", "Bash", "cat y", "digest-B")
                .await
                .unwrap();
        assert!(!inserted3);
        assert_eq!(mismatch.input_digest.as_deref(), Some("digest-a"));

        // Gate verdicts stick, and the CAS reports who won.
        assert!(record_intent_verdict(&pool, scope, row.id, "auto_allowed")
            .await
            .unwrap());
        assert!(
            !record_intent_verdict(&pool, scope, row.id, "auto_denied")
                .await
                .unwrap(),
            "second verdict loses the CAS — the first stands"
        );
        let cur = get_approval(&pool, scope, row.id).await.unwrap().unwrap();
        assert_eq!(cur.status, "auto_allowed");
        // A decided intent can no longer be promoted into an approval.
        assert!(
            promote_intent_to_pending(&pool, scope, row.id, None, "once", "Bash", 600)
                .await
                .unwrap()
                .is_none()
        );

        // The approval lifecycle rides the SAME row when promotion wins.
        let (row2, _) = register_tool_intent(
            &pool, scope, session.id, "tc2", "Bash", "git push", "digest-c",
        )
        .await
        .unwrap();
        let promoted =
            promote_intent_to_pending(&pool, scope, row2.id, Some("high"), "once", "Bash", 600)
                .await
                .unwrap()
                .expect("first promotion wins");
        assert_eq!(promoted.status, "pending");
        assert!(promoted.expires_at > chrono::Utc::now());
        assert!(
            promote_intent_to_pending(&pool, scope, row2.id, Some("high"), "once", "Bash", 600)
                .await
                .unwrap()
                .is_none(),
            "second promotion is a no-op"
        );
        let decided = decide_approval_tx(&pool, scope, row2.id, "approved_once", "tester", vec![])
            .await
            .unwrap()
            .expect("pending row decides");
        assert_eq!(decided.status, "approved_once");
        assert!(
            !record_intent_verdict(&pool, scope, row2.id, "auto_denied")
                .await
                .unwrap(),
            "a human decision is never overwritten by a gate verdict"
        );
        let cur2 = get_approval(&pool, scope, row2.id).await.unwrap().unwrap();
        assert_eq!(cur2.status, "approved_once");

        // The budget counts unique intents; the approvals API hides gate
        // bookkeeping but keeps the human lifecycle.
        assert_eq!(tool_call_count(&pool, scope, session.id).await.unwrap(), 2);
        let visible = session_approvals(&pool, scope, session.id).await.unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].tool_call_id, "tc2");
    }

    #[tokio::test]
    async fn stale_nonstarted_sweep_finds_only_old_prelaunch_sessions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-stale",
            "name: test-stale",
            &serde_json::json!({"name": "test-stale"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-stale-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        let repo = serde_json::json!({"kind":"none"});
        let empty = serde_json::json!({});
        let fresh = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "stale-test fresh",
            &repo,
            &empty,
            &empty,
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
        )
        .await
        .unwrap();
        let stale = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "stale-test old",
            &repo,
            &empty,
            &empty,
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
        )
        .await
        .unwrap();
        // The sweep keys off created_at (heartbeat-proof; M5) — backdate that.
        let backdate =
            "update sessions set created_at = now() - interval '20 minutes' where id = $1";
        sqlx::query(backdate)
            .bind(stale.id)
            .execute(&pool)
            .await
            .unwrap();

        let sweep_created: Vec<Uuid> = system_worker::stale_nonstarted_sessions(&pool, 15)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();

        // The wind-down machine owns terminal entry: the pre-epic direct
        // created→failed edge must be REFUSED (Ok(None)), and terminalization
        // goes through finalizing. Neither a winding-down nor a terminal
        // session may be swept, however old.
        use fluidbox_core::state::SessionStatus;
        let direct_terminal =
            transition_session(&pool, scope, stale.id, SessionStatus::Failed, Some("test"))
                .await
                .unwrap();
        let to_finalizing = transition_session(
            &pool,
            scope,
            stale.id,
            SessionStatus::Finalizing,
            Some("test"),
        )
        .await
        .unwrap();
        sqlx::query(backdate)
            .bind(stale.id)
            .execute(&pool)
            .await
            .unwrap();
        let sweep_finalizing: Vec<Uuid> = system_worker::stale_nonstarted_sessions(&pool, 15)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();
        let to_failed =
            transition_session(&pool, scope, stale.id, SessionStatus::Failed, Some("test"))
                .await
                .unwrap();
        sqlx::query(backdate)
            .bind(stale.id)
            .execute(&pool)
            .await
            .unwrap();
        let sweep_terminal: Vec<Uuid> = system_worker::stale_nonstarted_sessions(&pool, 15)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();

        // Fixtures out BEFORE the assertions — a failed assertion must not
        // leak sessions into the shared tenant.
        for id in [fresh.id, stale.id] {
            sqlx::query("delete from sessions where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(
            sweep_created.contains(&stale.id),
            "old created session must be swept"
        );
        assert!(
            !sweep_created.contains(&fresh.id),
            "fresh session must not be swept"
        );
        assert!(
            direct_terminal.is_none(),
            "created→failed must be refused (no active→terminal edge)"
        );
        assert!(
            to_finalizing.is_some(),
            "created→finalizing must be legal (crash recovery finalizes from anywhere)"
        );
        assert!(
            !sweep_finalizing.contains(&stale.id),
            "winding-down session must not be swept"
        );
        assert!(to_failed.is_some(), "finalizing→failed must be legal");
        assert!(
            !sweep_terminal.contains(&stale.id),
            "terminal session must not be swept"
        );
    }

    #[tokio::test]
    async fn adopt_sandbox_handle_is_guarded() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-adopt",
            "name: test-adopt",
            &serde_json::json!({"name": "test-adopt"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-adopt-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        let repo = serde_json::json!({"kind":"none"});
        let empty = serde_json::json!({});
        let s = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "adopt-test",
            &repo,
            &empty,
            &empty,
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
        )
        .await
        .unwrap();
        let discovered =
            serde_json::json!({"runtime":"kubernetes","external_id":"pod-x","attrs":{"uid":"u1"}});
        let real =
            serde_json::json!({"runtime":"kubernetes","external_id":"pod-x","attrs":{"uid":"u2"}});

        // Active + handle-less → adoption lands.
        let adopted = adopt_sandbox_handle(&pool, scope, s.id, &discovered)
            .await
            .unwrap();
        // A stored handle is never overwritten (run() won the race).
        set_sandbox_handle(&pool, scope, s.id, &real).await.unwrap();
        let overwrote = adopt_sandbox_handle(&pool, scope, s.id, &discovered)
            .await
            .unwrap();
        let kept: (Value,) = sqlx::query_as("select sandbox_handle from sessions where id = $1")
            .bind(s.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        // A winding-down session never re-acquires a handle.
        sqlx::query(
            "update sessions set sandbox_handle = null, status = 'finalizing' where id = $1",
        )
        .bind(s.id)
        .execute(&pool)
        .await
        .unwrap();
        let resurrected = adopt_sandbox_handle(&pool, scope, s.id, &discovered)
            .await
            .unwrap();

        // Fixtures out BEFORE the assertions.
        sqlx::query("delete from sessions where id = $1")
            .bind(s.id)
            .execute(&pool)
            .await
            .unwrap();

        assert!(adopted, "active handle-less session must adopt");
        assert!(!overwrote, "a stored handle must never be overwritten");
        assert_eq!(kept.0["attrs"]["uid"], "u2", "run()'s handle must survive");
        assert!(!resurrected, "a winding-down session must not adopt");
    }

    #[tokio::test]
    async fn connection_lifecycle_and_credential_isolation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        let sealed = b"nonce||ciphertext-not-a-real-secret".to_vec();
        let conn = create_connection(
            &pool,
            scope,
            "github",
            "test-account-42",
            "test-connection",
            Some(&sealed),
            1,
            &serde_json::json!(["repo"]),
            &serde_json::json!({}),
            &serde_json::json!({"test": true}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        // The row type/serialization can never leak the credential.
        let as_json = serde_json::to_value(&conn).unwrap();
        assert!(as_json.get("credential_sealed").is_none());
        assert!(!serde_json::to_string(&as_json)
            .unwrap()
            .contains("ciphertext-not-a-real-secret"));

        // Active connection yields the sealed bytes.
        let got = connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .expect("active connection has credential");
        assert_eq!(got, (sealed, 1), "legacy sealer stamps key_version 1");

        // Revocation is terminal for credential access.
        let revoked = revoke_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(revoked.status, "revoked");
        assert!(connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .is_none());
        // Idempotent second revoke: no row to update.
        assert!(revoke_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .is_none());

        sqlx::query("delete from integration_connections where id = $1")
            .bind(conn.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn trigger_subscription_lifecycle_token_and_secret_isolation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-trig",
            "name: test-trig",
            &serde_json::json!({"name": "test-trig"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-trig-agent", None)
            .await
            .unwrap();
        let _rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();

        let sealed = b"nonce||not-a-real-secret".to_vec();
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            "test-sub",
            "api",
            None,
            Some("Investigate {{ticket}}"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([{"kind": "signed_webhook", "url": "http://127.0.0.1:1/cb"}]),
            Some(&sealed),
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(sub.enabled);
        assert!(!sub.allow_task_override);

        // Row serialization can never leak the sealed secret.
        let as_json = serde_json::to_value(&sub).unwrap();
        assert!(as_json.get("callback_secret_sealed").is_none());

        // The single secret reader returns the sealed bytes.
        let got = subscription_callback_secret_sealed(&pool, scope, sub.id)
            .await
            .unwrap();
        assert_eq!(got, Some((sealed, 1)));

        // Trigger tokens: hashed at rest, resolvable, revocable.
        create_trigger_token(&pool, scope, sub.id, "fbx_trig_testtoken123")
            .await
            .unwrap();
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_testtoken123")
                .await
                .unwrap()
                .map(|a| a.subscription_id),
            Some(sub.id)
        );
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_wrong")
                .await
                .unwrap()
                .map(|a| a.subscription_id),
            None
        );
        let revoked = revoke_trigger_tokens(&pool, scope, sub.id).await.unwrap();
        assert_eq!(revoked, 1);
        assert_eq!(
            subscription_for_token(&pool, "fbx_trig_testtoken123")
                .await
                .unwrap()
                .map(|a| a.subscription_id),
            None
        );

        // Enable toggle.
        let off = set_trigger_subscription_enabled(&pool, scope, sub.id, false)
            .await
            .unwrap()
            .unwrap();
        assert!(!off.enabled);

        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn invocation_claims_are_idempotent_by_key() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-idem",
            "name: test-idem",
            &serde_json::json!({"name": "test-idem"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-idem-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            "test-idem-sub",
            "api",
            None,
            Some("t"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // First claim wins.
        let c1 = claim_invocation(&pool, scope, sub.id, "key-1", "digest-a")
            .await
            .unwrap();
        let InvocationClaim::Claimed { invocation_id } = c1 else {
            panic!("wanted Claimed, got {c1:?}")
        };

        // Same key while unbound → InFlight (a concurrent retry must wait).
        assert!(matches!(
            claim_invocation(&pool, scope, sub.id, "key-1", "digest-a")
                .await
                .unwrap(),
            InvocationClaim::InFlight
        ));

        // Bind atomically with session creation (same transaction), then
        // the same key replays that session.
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "t",
            &serde_json::json!({"kind":"scratch"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            Some(&serde_json::json!({"kind":"api"})),
            None,
            None,
            Some(invocation_id),
            None,
            &[],
            None,
        )
        .await
        .unwrap();
        assert_eq!(session.trigger, Some(serde_json::json!({"kind":"api"})));
        let c3 = claim_invocation(&pool, scope, sub.id, "key-1", "digest-a")
            .await
            .unwrap();
        match c3 {
            InvocationClaim::Replay {
                session_id,
                request_digest,
            } => {
                assert_eq!(session_id, session.id);
                assert_eq!(request_digest, "digest-a");
            }
            other => panic!("wanted Replay, got {other:?}"),
        }

        // A released (failed-creation) claim frees the key immediately.
        let c4 = claim_invocation(&pool, scope, sub.id, "key-2", "digest-b")
            .await
            .unwrap();
        let InvocationClaim::Claimed {
            invocation_id: inv2,
        } = c4
        else {
            panic!()
        };
        release_invocation(&pool, scope, inv2).await.unwrap();
        assert!(matches!(
            claim_invocation(&pool, scope, sub.id, "key-2", "digest-b")
                .await
                .unwrap(),
            InvocationClaim::Claimed { .. }
        ));

        assert!(subscription_owns_session(&pool, scope, sub.id, session.id)
            .await
            .unwrap());
        let listed = list_subscription_sessions(&pool, scope, sub.id, 10)
            .await
            .unwrap();
        assert!(listed.iter().any(|s| s.id == session.id));

        sqlx::query("delete from sessions where id = $1")
            .bind(session.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn schedule_lifecycle_and_skip_claims() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let agent = create_agent(&pool, scope, "test-sched-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            &format!("test-sched-{}", Uuid::now_v7()),
            "schedule",
            None,
            Some("maintenance sweep"),
            false,
            false,
            None,
            "skip_if_running",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(sub.concurrency_policy, "skip_if_running");

        // Overdue schedule → due; disabled subscription → not due.
        let past = Utc::now() - chrono::Duration::seconds(1);
        let sched = create_schedule(&pool, scope, sub.id, "*/5 * * * * *", "UTC", past, "skip")
            .await
            .unwrap();
        assert!(system_worker::due_schedules(&pool, 50)
            .await
            .unwrap()
            .iter()
            .any(|s| s.id == sched.id));
        set_trigger_subscription_enabled(&pool, scope, sub.id, false)
            .await
            .unwrap();
        assert!(!system_worker::due_schedules(&pool, 50)
            .await
            .unwrap()
            .iter()
            .any(|s| s.id == sched.id));
        set_trigger_subscription_enabled(&pool, scope, sub.id, true)
            .await
            .unwrap();

        // Deterministic fire key: claim once, mark skipped, replay the skip.
        let key = "sched:2026-07-10T00:00:00Z";
        let claim = claim_invocation(&pool, scope, sub.id, key, "d1")
            .await
            .unwrap();
        let InvocationClaim::Claimed { invocation_id } = claim else {
            panic!("expected Claimed, got {claim:?}");
        };
        mark_invocation_skipped(&pool, scope, invocation_id, "missed")
            .await
            .unwrap();
        let again = claim_invocation(&pool, scope, sub.id, key, "d1")
            .await
            .unwrap();
        let InvocationClaim::Skipped { reason } = again else {
            panic!("expected Skipped, got {again:?}");
        };
        assert_eq!(reason, "missed");
        let inv = list_subscription_invocations(&pool, scope, sub.id, 10)
            .await
            .unwrap();
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0].skip_reason.as_deref(), Some("missed"));
        assert!(inv[0].session_id.is_none());

        // CAS advance: succeeds from the processed fire time, then refuses.
        // (`stored` is read back so both sides carry Postgres µs precision.)
        use chrono::SubsecRound;
        let stored = schedule_for_subscription(&pool, scope, sub.id)
            .await
            .unwrap()
            .unwrap()
            .next_fire_at
            .unwrap();
        let future = (Utc::now() + chrono::Duration::seconds(60)).trunc_subsecs(6);
        assert!(
            advance_schedule(&pool, scope, sched.id, stored, Some(future), None)
                .await
                .unwrap()
        );
        assert!(
            !advance_schedule(&pool, scope, sched.id, stored, Some(future), None)
                .await
                .unwrap()
        );
        let row = schedule_for_subscription(&pool, scope, sub.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.next_fire_at, Some(future));
        assert!(row.last_fired_at.is_none()); // skips never touch last_fired_at
        assert!(!system_worker::due_schedules(&pool, 50)
            .await
            .unwrap()
            .iter()
            .any(|s| s.id == sched.id));

        // Cleanup (cascades schedules + invocations).
        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn result_delivery_attempt_state_machine() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-del",
            "name: test-del",
            &serde_json::json!({"name": "test-del"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-del-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "t",
            &serde_json::json!({"kind":"scratch"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        // A due delivery is visible to every replica's claim scan, which in a test
        // process means every sibling test's scan too — so the enqueue and the
        // claim that must win it sit inside one GLOBAL_SCAN window, and the batch
        // is read back through the owning helper.
        let scan = GLOBAL_SCAN.lock().await;
        let dest = serde_json::json!({"kind": "signed_webhook", "url": "http://127.0.0.1:1/cb"});
        let d = enqueue_result_delivery(&pool, scope, session.id, None, &dest)
            .await
            .unwrap();
        assert_eq!(d.status, "pending");
        assert_eq!(d.attempts, 0);

        // Due immediately — and the poll now CLAIMS (Phase E): every attempt is
        // recorded by the replica that holds the row.
        let me = Uuid::now_v7();
        let due = claim_deliveries(&pool, me, 10, 300, &[d.id]).await;
        assert!(due.iter().any(|x| x.id == d.id));

        // Failure → still pending, attempts=1, pushed into the future (not due).
        let after = mark_delivery_attempt(
            &pool,
            scope,
            d.id,
            me,
            false,
            Some("connection refused"),
            None,
            30,
            3,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!((after.status.as_str(), after.attempts), ("pending", 1));
        assert!(!claim_deliveries(&pool, me, 50, 300, &[d.id])
            .await
            .iter()
            .any(|x| x.id == d.id));
        drop(scan);

        // Exhausting attempts → failed, terminal for the delivery only. Each
        // attempt re-claims first: recording one RELEASES the claim (so the next
        // backoff window is open to any replica), and the row is no longer due, so
        // the claim is re-stamped directly rather than via the due scan.
        stamp_delivery_claim(&pool, d.id, me).await;
        mark_delivery_attempt(&pool, scope, d.id, me, false, Some("refused"), None, 30, 3)
            .await
            .unwrap();
        stamp_delivery_claim(&pool, d.id, me).await;
        let last =
            mark_delivery_attempt(&pool, scope, d.id, me, false, Some("refused"), None, 30, 3)
                .await
                .unwrap()
                .unwrap();
        assert_eq!((last.status.as_str(), last.attempts), ("failed", 3));

        // Success path on a second delivery.
        let d2 = enqueue_result_delivery(&pool, scope, session.id, None, &dest)
            .await
            .unwrap();
        stamp_delivery_claim(&pool, d2.id, me).await;
        let okd =
            mark_delivery_attempt(&pool, scope, d2.id, me, true, None, Some("sha256:x"), 0, 3)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(okd.status, "delivered");
        assert!(okd.delivered_at.is_some());
        assert_eq!(okd.payload_digest.as_deref(), Some("sha256:x"));

        let listed = list_session_deliveries(&pool, scope, session.id)
            .await
            .unwrap();
        assert_eq!(listed.len(), 2);

        sqlx::query("delete from sessions where id = $1")
            .bind(session.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn revision_default_workspace_roundtrips() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            &pool,
            scope,
            "test-ws",
            "name: test-ws",
            &serde_json::json!({"name": "test-ws"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-ws-agent", None)
            .await
            .unwrap();

        let ws = serde_json::json!({
            "kind": "git_repository",
            "clone_url": "https://github.com/o/r.git",
            "ref": "main"
        });
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            Some(&ws),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        assert_eq!(rev.default_workspace, Some(ws));

        // A revision without one stays None.
        let rev2 = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        assert!(rev2.default_workspace.is_none());

        sqlx::query("delete from agent_revisions where agent_id = $1")
            .bind(agent.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from agents where id = $1")
            .bind(agent.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn capability_bundles_are_append_only_and_refs_roundtrip() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);
        let name = format!("test-bundle-{}", Uuid::now_v7());

        let def_v1 = serde_json::json!({"servers": [{
            "class": "sandbox", "name": "ws", "command": "node",
            "args": ["/opt/x.mjs"],
            "tools": [{"name": "count", "description": "d", "input_schema": {"type": "object"}}]
        }]});
        let v1 = create_capability_bundle(&pool, scope, &name, Some("first"), &def_v1, "sha256:a")
            .await
            .unwrap();
        assert_eq!(v1.version, 1);

        // Publishing again appends version 2 — the v1 row never mutates.
        let v2 = create_capability_bundle(&pool, scope, &name, None, &def_v1, "sha256:b")
            .await
            .unwrap();
        assert_eq!(v2.version, 2);
        assert_ne!(v1.id, v2.id);
        let v1_again = get_capability_bundle(&pool, scope, v1.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(v1_again.definition_digest, "sha256:a");
        assert_eq!(
            latest_capability_bundle(&pool, scope, &name)
                .await
                .unwrap()
                .unwrap()
                .id,
            v2.id
        );
        assert_eq!(
            get_capability_bundle_version(&pool, scope, &name, 1)
                .await
                .unwrap()
                .unwrap()
                .id,
            v1.id
        );

        // Revision pins (§17 #7) + subscription keep-list roundtrip as jsonb.
        let policy = upsert_policy(
            &pool,
            scope,
            "test-cap",
            "name: test-cap",
            &serde_json::json!({"name": "test-cap"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "test-cap-agent", None)
            .await
            .unwrap();
        let pins = serde_json::json!([{"id": v1.id, "name": name, "version": 1}]);
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &pins,
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        assert_eq!(rev.capability_bundles, pins);

        let keep = serde_json::json!([name]);
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            &format!("test-cap-sub-{}", Uuid::now_v7()),
            "api",
            None,
            Some("t"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            Some(&keep),
        )
        .await
        .unwrap();
        assert_eq!(sub.capability_bundles, Some(keep));

        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from agent_revisions where agent_id = $1")
            .bind(agent.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from agents where id = $1")
            .bind(agent.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from capability_bundles where tenant_id = $1 and name = $2")
            .bind(tenant)
            .bind(&name)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn connector_catalog_seeded_and_custom_entries_forced_custom_tier() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        // The curated seeds are GLOBAL (tenant_id null); any valid scope sees
        // them via the tenant-or-global reader.
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        // Migration 0007 seeds the curated set (API-only settle: the
        // migration IS the seed; no file, no boot sync).
        let rows = list_catalog(&pool, scope).await.unwrap();
        assert!(rows.len() >= 7, "expected ≥7 seeded entries");
        let notion = get_catalog_by_slug(&pool, scope, "notion")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(notion.auth_mode, "oauth");
        assert_eq!(notion.tier, "verified");
        assert!(notion.tenant_id.is_none(), "curated seeds are global");
        let sentry = get_catalog_by_slug(&pool, scope, "sentry")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sentry.auth_hints["header_name"], "Sentry-Bearer");
        assert_eq!(sentry.auth_hints["scheme"], "");
        let ws = get_catalog_by_slug(&pool, scope, "workspace-info")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ws.transport, "stdio");
        assert!(ws.sandbox_launch.is_some());
        // Slack seed is explicitly deferred to the Phase-7 vertical.
        assert!(get_catalog_by_slug(&pool, scope, "slack")
            .await
            .unwrap()
            .is_none());
        // Verified entries sort ahead of custom ones.
        assert_eq!(rows[0].tier, "verified");

        let slug = format!("test-cat-{}", Uuid::now_v7().simple());
        let row = create_catalog_entry(
            &pool,
            scope,
            &slug,
            "Test entry",
            None,
            Some("test"),
            &serde_json::json!(["test"]),
            Some("https://mcp.example.test/mcp"),
            "streamable_http",
            "api_key",
            &serde_json::json!({}),
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap()
        .expect("custom entry lands");
        assert_eq!(row.tier, "custom", "API entries can't self-award tiers");
        assert_eq!(
            row.provenance["source"], "custom",
            "API entries carry a 'custom' provenance, distinct from seed + import"
        );
        assert_eq!(
            row.tenant_id,
            Some(tenant),
            "custom entries are tenant-scoped"
        );
        // The curated seed rows keep the fluidbox provenance the 0009 backfill
        // gave them — the import upsert predicate keys off exactly this, so an
        // import can never clobber a hand-curated verified entry.
        let gh = get_catalog_by_slug(&pool, scope, "github")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(gh.provenance["source"], "fluidbox");
        // Same-tenant slug re-insert conflicts (the per-tenant unique index).
        assert!(create_catalog_entry(
            &pool,
            scope,
            &slug,
            "dup",
            None,
            None,
            &serde_json::json!([]),
            None,
            "streamable_http",
            "none",
            &serde_json::json!({}),
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .is_err());

        sqlx::query("delete from connector_catalog where slug = $1")
            .bind(&slug)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn oauth_connection_lifecycle_pending_activate_rotate_error() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        // Pending OAuth connection: no credential yet.
        let conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "mcp.example.test",
            "oauth-lifecycle-test",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({"base_url": "https://mcp.example.test"}),
            None,
            1,
            ConnectionAuth {
                auth_kind: "oauth",
                status: "pending",
                oauth: Some(&serde_json::json!({"resource": "https://mcp.example.test"})),
                client_secret_sealed: Some(b"sealed-client-secret"),
                client_secret_key_version: 1,
                registration_id: None,
            },
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        assert_eq!(conn.auth_kind, "oauth");
        assert_eq!(conn.status, "pending");
        // Pending = no credential, and the active-only reader refuses.
        assert!(connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .is_none());
        // …but client identity IS readable while pending (the dance needs it).
        assert_eq!(
            connection_client_secret_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .map(|t| t.0)
                .as_deref(),
            Some(b"sealed-client-secret".as_slice())
        );
        // Rotation refuses non-active rows.
        assert!(
            !rotate_connection_refresh(&pool, scope, conn.id, b"rt1", 1, 1)
                .await
                .unwrap()
        );

        // Callback exchange: seal refresh + activate. First connect (from
        // `pending`) ⇒ no bump — the bump is derived from the row's pre-update
        // status inside the UPDATE (B1), not a caller boolean.
        // `flow_a_started` stands in for the flow row's `created_at` (frozen at
        // START, before any activation). It is read from the DB clock, exactly
        // like the real `connector_oauth_flows.created_at default now()` — the
        // comparison is DB-clock vs DB-clock, never the test host's clock.
        let db_now = |pool: PgPool| async move {
            sqlx::query_scalar::<_, DateTime<Utc>>("select clock_timestamp()")
                .fetch_one(&pool)
                .await
                .unwrap()
        };
        let flow_a_started = db_now(pool.clone()).await;
        let row = activate_connection_oauth(
            &pool,
            scope,
            conn.id,
            b"sealed-rt-1",
            1,
            &serde_json::json!({"resource": "https://mcp.example.test", "client_id": "c1"}),
            &serde_json::json!(["read"]),
            1,
            flow_a_started,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(row.status, "active");
        assert_eq!(
            row.authorization_generation, 1,
            "first activation stays generation 1 (no bump)"
        );
        // H2: a SIBLING first-connect flow — same frozen generation, started
        // before the winner activated — is now refused by the write itself. Its
        // generation expectation is still satisfiable (pending → active does not
        // bump), so the activation instant is the only thing that separates them.
        assert!(
            activate_connection_oauth(
                &pool,
                scope,
                conn.id,
                b"sealed-rt-sibling",
                1,
                &serde_json::json!({"resource": "https://mcp.example.test"}),
                &serde_json::json!([]),
                1,
                flow_a_started,
            )
            .await
            .unwrap()
            .is_none(),
            "a first-connect sibling flow must not overwrite the grant that activated first"
        );
        assert_eq!(
            connection_credential_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .map(|t| t.0)
                .as_deref(),
            Some(b"sealed-rt-1".as_slice()),
            "the superseded sibling left the winner's refresh token untouched"
        );
        // H2: a flow START rewrites the oauth bag from a value it read BEFORE the
        // activation. The activation stamp must survive that read-modify-write —
        // erasing it would hand the superseded sibling a passing expectation.
        // In production this write now rides the start's lock-holding transaction
        // (#32), so the carry-over is belt-and-braces there; it stays the ONLY
        // protection for a caller that passes a bare pool, as here.
        update_connection_oauth(
            &pool,
            scope,
            conn.id,
            &serde_json::json!({"resource": "https://mcp.example.test", "issuer": "https://as"}),
        )
        .await
        .unwrap();
        let after_start = get_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap()
            .oauth
            .unwrap();
        assert!(
            after_start.get(ACTIVATED_AT_KEY).is_some(),
            "the activation stamp survives a flow-start bag rewrite"
        );
        assert_eq!(after_start["issuer"], "https://as", "the rest is replaced");
        assert!(
            activate_connection_oauth(
                &pool,
                scope,
                conn.id,
                b"sealed-rt-sibling-2",
                1,
                &serde_json::json!({"resource": "https://mcp.example.test"}),
                &serde_json::json!([]),
                1,
                flow_a_started,
            )
            .await
            .unwrap()
            .is_none(),
            "the sibling is still refused after a concurrent flow start"
        );
        assert_eq!(
            connection_credential_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .map(|t| t.0)
                .as_deref(),
            Some(b"sealed-rt-1".as_slice())
        );

        // Rotation is one atomic overwrite AT the current generation; the old
        // bytes are gone.
        assert!(
            rotate_connection_refresh(&pool, scope, conn.id, b"sealed-rt-2", 1, 1)
                .await
                .unwrap()
        );
        assert_eq!(
            connection_credential_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .map(|t| t.0)
                .as_deref(),
            Some(b"sealed-rt-2".as_slice())
        );
        // A rotation naming a stale (moved) generation is refused (R3.2): the
        // grant was reauthorized underneath the in-flight refresh.
        assert!(
            !rotate_connection_refresh(&pool, scope, conn.id, b"sealed-rt-stale", 1, 999)
                .await
                .unwrap(),
            "rotation at a superseded generation must fail closed"
        );

        // invalid_grant ⇒ error: the credential reader fails closed; the
        // error note lands in oauth jsonb for the dashboard.
        mark_connection_error(&pool, scope, conn.id, "invalid_grant: reconnect required")
            .await
            .unwrap();
        let row = get_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "error");
        assert!(row.oauth.unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("invalid_grant"));
        assert!(connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .is_none());

        // Reconnect path: activation works FROM error too, and bumps the
        // generation atomically (R1.3+R3.1) — the reconnect may be a new grant.
        // The bump is derived from the pre-update status (`error` <> `pending`).
        let flow_b_started = db_now(pool.clone()).await;
        // H2: a reconnect flow frozen at a STALE generation is refused by the
        // write, even though its start-time instant is fresh.
        assert!(
            activate_connection_oauth(
                &pool,
                scope,
                conn.id,
                b"sealed-rt-stale-gen",
                1,
                &serde_json::json!({"resource": "https://mcp.example.test"}),
                &serde_json::json!([]),
                999,
                flow_b_started,
            )
            .await
            .unwrap()
            .is_none(),
            "activation at a superseded generation must fail closed"
        );
        let row = activate_connection_oauth(
            &pool,
            scope,
            conn.id,
            b"sealed-rt-3",
            1,
            &serde_json::json!({"resource": "https://mcp.example.test"}),
            &serde_json::json!([]),
            1,
            flow_b_started,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(row.status, "active");
        assert_eq!(
            row.authorization_generation, 2,
            "reconnect bumps the generation in the same atomic activation"
        );

        // B1 regression: re-activating an ALREADY-active row bumps again — proving
        // the bump is derived from the row's live status under the lock, not from
        // a pre-lock read (two racing first-connects that both saw `pending`).
        // H2: it takes a flow that started AFTER the last activation and names the
        // now-current generation — i.e. a genuinely newer authorization, which is
        // exactly what the CAS admits (and the superseded ones above it refuses).
        let flow_c_started = db_now(pool.clone()).await;
        let row = activate_connection_oauth(
            &pool,
            scope,
            conn.id,
            b"sealed-rt-4",
            1,
            &serde_json::json!({"resource": "https://mcp.example.test"}),
            &serde_json::json!([]),
            2,
            flow_c_started,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            row.authorization_generation, 3,
            "activating the now-active row bumps again (status <> 'pending')"
        );
        // H2: replaying that same flow (its instant is now older than the
        // activation it just performed) matches nothing — one activation per flow,
        // enforced by the write, not only by the one-time claim.
        assert!(
            activate_connection_oauth(
                &pool,
                scope,
                conn.id,
                b"sealed-rt-replay",
                1,
                &serde_json::json!({"resource": "https://mcp.example.test"}),
                &serde_json::json!([]),
                3,
                flow_c_started,
            )
            .await
            .unwrap()
            .is_none(),
            "a flow cannot activate twice: its start instant is older than its own activation"
        );
        assert_eq!(
            connection_credential_sealed(&pool, scope, conn.id)
                .await
                .unwrap()
                .map(|t| t.0)
                .as_deref(),
            Some(b"sealed-rt-4".as_slice())
        );

        sqlx::query("delete from integration_connections where id = $1")
            .bind(conn.id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// Version-lifecycle fixtures use their OWN throwaway tenant (the #33
    /// collision class): version numbers are per policy, but name collisions on
    /// the shared default tenant would make `create_policy` duplicate-name
    /// assertions racy across parallel tests.
    async fn throwaway_policy_tenant(pool: &PgPool) -> TenantScope {
        let slug = format!("pol-{}", Uuid::now_v7().simple());
        TenantScope::assume(
            crate::identity::create_org(pool, &slug, None)
                .await
                .unwrap()
                .id,
        )
    }

    fn policy_json(name: &str) -> Value {
        serde_json::to_value(
            fluidbox_core::policy::Policy::parse_yaml(&format!("name: {name}")).unwrap(),
        )
        .unwrap()
    }

    /// The import path (`POST /v1/policies` wire semantics): the identity row is
    /// created once; every import APPENDS an immutable version with author
    /// 'api'. Nothing UPDATEs a stored version row (design: publishing appends;
    /// history is append-only).
    #[tokio::test]
    async fn policy_imports_append_immutable_versions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_policy_tenant(&pool).await;
        let content = policy_json("imp");

        let p1 = upsert_policy(&pool, scope, "imp", "name: imp", &content)
            .await
            .unwrap();
        let v1 = latest_policy_version(&pool, scope, p1.id)
            .await
            .unwrap()
            .expect("import mints a version");
        assert_eq!((v1.version, v1.author.as_str()), (1, "api"));
        assert_eq!(v1.yaml_source.as_deref(), Some("name: imp"));

        // A second import of CHANGED content appends — same identity row.
        let mut changed = content.clone();
        changed["defaults"]["tool_action"] = serde_json::json!("deny");
        let p2 = upsert_policy(&pool, scope, "imp", "name: imp # v2", &changed)
            .await
            .unwrap();
        assert_eq!(p2.id, p1.id, "import must never mint a second identity");
        let v2 = latest_policy_version(&pool, scope, p1.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(v2.version, 2);

        // v1 is immutable: still readable, byte-identical content.
        let v1_again = get_policy_version(&pool, scope, p1.id, 1)
            .await
            .unwrap()
            .expect("old versions stay readable");
        assert_eq!(v1_again.content, content);
        assert_eq!(
            list_policy_versions(&pool, scope, p1.id)
                .await
                .unwrap()
                .iter()
                .map(|v| v.version)
                .collect::<Vec<_>>(),
            vec![2, 1],
            "listing is newest-first"
        );
    }

    /// `latest_policy_version` picks the HIGHEST version, never the newest
    /// `created_at` (design §6) — a skewed clock cannot reorder history.
    #[tokio::test]
    async fn latest_policy_version_picks_highest_version_not_newest_created_at() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_policy_tenant(&pool).await;
        let policy = upsert_policy(&pool, scope, "lat", "name: lat", &policy_json("lat"))
            .await
            .unwrap();
        append_policy_version(
            &pool,
            scope,
            policy.id,
            None,
            NewPolicyVersion {
                content: &policy_json("lat"),
                yaml_source: None,
                summary: Some("second"),
                author: "ui",
                author_user_id: None,
            },
        )
        .await
        .unwrap();
        // Backdate v2 BEHIND v1: the version number must still win.
        let mut tx = scoped_tx(&pool, scope).await.unwrap();
        sqlx::query(
            "update policy_versions set created_at = created_at - interval '1 day'
              where policy_id = $1 and version = 2",
        )
        .bind(policy.id)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let latest = latest_policy_version(&pool, scope, policy.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.version, 2);
        assert_eq!(latest.summary.as_deref(), Some("second"));
    }

    /// Revert is publishing the TARGET's content forward as a new version —
    /// never mutating or deleting a row (design §3). The db layer sees it as an
    /// ordinary append whose content equals the target's.
    #[tokio::test]
    async fn revert_appends_a_new_version_with_the_targets_content() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_policy_tenant(&pool).await;
        let v1_content = policy_json("rev");
        let policy = upsert_policy(&pool, scope, "rev", "name: rev", &v1_content)
            .await
            .unwrap();
        let mut v2_content = v1_content.clone();
        v2_content["defaults"]["tool_action"] = serde_json::json!("deny");
        for (content, summary) in [(&v2_content, "tighten"), (&v1_content, "revert to v1")] {
            append_policy_version(
                &pool,
                scope,
                policy.id,
                None,
                NewPolicyVersion {
                    content,
                    yaml_source: None,
                    summary: Some(summary),
                    author: "ui",
                    author_user_id: Some(Uuid::now_v7()),
                },
            )
            .await
            .unwrap();
        }
        let v3 = latest_policy_version(&pool, scope, policy.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(v3.version, 3);
        assert_eq!(v3.content, v1_content, "the revert carries v1's content");
        assert_eq!(
            get_policy_version(&pool, scope, policy.id, 2)
                .await
                .unwrap()
                .unwrap()
                .content,
            v2_content,
            "the reverted-over version is untouched"
        );
    }

    /// The optimistic guard: publishing from a stale head writes NOTHING and
    /// reports the head that moved — two editors loading the same version
    /// cannot silently overwrite each other's intent, and a post-commit retry
    /// of one's own publish is inert.
    #[tokio::test]
    async fn append_with_a_stale_base_version_writes_nothing() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_policy_tenant(&pool).await;
        let content = policy_json("cas");
        let policy = upsert_policy(&pool, scope, "cas", "name: cas", &content)
            .await
            .unwrap();
        let v = NewPolicyVersion {
            content: &content,
            yaml_source: None,
            summary: Some("editor A"),
            author: "ui",
            author_user_id: None,
        };
        // Editor A publishes from v1 → v2.
        assert!(matches!(
            append_policy_version(&pool, scope, policy.id, Some(1), v)
                .await
                .unwrap(),
            AppendPolicyVersion::Appended(_)
        ));
        // Editor B still holds v1: refused, told where the head is.
        let out = append_policy_version(&pool, scope, policy.id, Some(1), v)
            .await
            .unwrap();
        let AppendPolicyVersion::Stale { head } = out else {
            panic!("a stale base must be refused, got {out:?}");
        };
        assert_eq!(head, 2);
        assert_eq!(
            list_policy_versions(&pool, scope, policy.id)
                .await
                .unwrap()
                .len(),
            2,
            "the refused publish must write nothing"
        );
    }

    /// A byte-equal YAML import appends nothing (`appended = false`) — a
    /// re-run loadgen/CI setup cannot inflate the history — while changed
    /// content appends as ever.
    #[tokio::test]
    async fn identical_import_is_a_no_op() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_policy_tenant(&pool).await;
        let content = policy_json("noop");
        let (_, v1, appended) =
            import_policy_yaml(&pool, scope, "noop", "name: noop", &content, None)
                .await
                .unwrap();
        assert!(appended);
        assert_eq!(v1.version, 1);
        let (_, v_again, appended_again) =
            import_policy_yaml(&pool, scope, "noop", "name: noop", &content, None)
                .await
                .unwrap();
        assert!(!appended_again, "identical content must not mint a version");
        assert_eq!(v_again.version, 1, "the existing head is returned");
    }

    /// Boot seeding mints exactly one v1 (author 'seed') and NEVER clobbers —
    /// a second boot (or a racing replica) leaves one identity and one version.
    #[tokio::test]
    async fn seed_policy_if_absent_mints_v1_once() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_policy_tenant(&pool).await;
        let content = policy_json("sd");
        let (p1, inserted) = seed_policy_if_absent(&pool, scope, "sd", "name: sd", &content)
            .await
            .unwrap();
        assert!(inserted);
        let (p2, inserted_again) = seed_policy_if_absent(&pool, scope, "sd", "name: sd", &content)
            .await
            .unwrap();
        assert!(!inserted_again, "a re-boot must not re-seed");
        assert_eq!(p1.id, p2.id);
        let versions = list_policy_versions(&pool, scope, p1.id).await.unwrap();
        assert_eq!(versions.len(), 1, "one boot-seeded version, ever");
        assert_eq!(versions[0].author, "seed");
        assert_eq!(versions[0].yaml_source.as_deref(), Some("name: sd"));
    }

    /// Boot seeding refuses PROPORTIONALLY. A strict-parse failure means the
    /// file cannot be trusted to mint version 1 — but whether that should stop
    /// a control plane from booting depends entirely on whether the file was
    /// ever going to write anything:
    ///
    ///   • policy ABSENT  → the file is its only source     → refuse the boot
    ///   • policy PRESENT → `seed_policy_if_absent` no-ops  → warn and carry on
    ///
    /// Getting this backwards means a repo with one stale policy file takes the
    /// whole deployment down on upgrade, over a file whose policy the database
    /// already governs.
    #[tokio::test]
    async fn seeding_refuses_only_when_the_file_is_the_policys_only_source() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_policy_tenant(&pool).await;
        let dir = std::env::temp_dir().join(format!("fbx-seed-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("default.yaml");
        async fn budgets_of(
            pool: &PgPool,
            scope: TenantScope,
            name: &str,
        ) -> Option<fluidbox_core::spec::Budgets> {
            let row = get_policy_by_name(pool, scope, name).await.unwrap()?;
            let v = latest_policy_version(pool, scope, row.id).await.unwrap()?;
            Some(
                serde_json::from_value::<fluidbox_core::policy::Policy>(v.content)
                    .unwrap()
                    .budgets,
            )
        }
        // `permited` is the misspelling that would otherwise silently leave
        // autonomy.permitted at its permissive default.
        let typo = "name: default\nautonomy:\n  permited: false\n";

        // 1. ABSENT + invalid → the boot refuses, naming the policy and why.
        std::fs::write(&file, typo).unwrap();
        let err = crate::seed::seed_policies_from_dir(&pool, scope, &dir)
            .await
            .expect_err("an unseeded policy's only source must not be silently skipped");
        let msg = err.to_string();
        assert!(msg.contains("permited"), "names the typo: {msg}");
        assert!(msg.contains("ONLY source"), "says why it is fatal: {msg}");
        assert!(
            budgets_of(&pool, scope, "default").await.is_none(),
            "a refused seed writes nothing"
        );

        // 2. Valid → seeds.
        std::fs::write(&file, "name: default\nbudgets:\n  max_tokens: 1234\n").unwrap();
        crate::seed::seed_policies_from_dir(&pool, scope, &dir)
            .await
            .expect("a valid seed file seeds");
        assert_eq!(
            budgets_of(&pool, scope, "default")
                .await
                .unwrap()
                .max_tokens,
            Some(1234)
        );

        // 3. PRESENT + invalid → boots, and appends nothing.
        std::fs::write(&file, typo).unwrap();
        crate::seed::seed_policies_from_dir(&pool, scope, &dir)
            .await
            .expect("an invalid file for an EXISTING policy must not stop the boot");
        let id = get_policy_by_name(&pool, scope, "default")
            .await
            .unwrap()
            .unwrap()
            .id;
        assert_eq!(
            list_policy_versions(&pool, scope, id).await.unwrap().len(),
            1,
            "the invalid file appended nothing"
        );
        assert_eq!(
            budgets_of(&pool, scope, "default")
                .await
                .unwrap()
                .max_tokens,
            Some(1234),
            "the stored version still governs"
        );

        // 4. A file that is STRUCTURALLY VALID YAML but an INVALID POLICY
        //    (empty `match`) names its policy perfectly well — so it must take
        //    the present/absent branch, NOT the unnameable one. `parse_yaml`
        //    would have refused it outright (it validates), which is exactly
        //    the trap this case exists to pin.
        std::fs::write(
            &file,
            "name: default\ntools:\n- match: []\n  action: allow\n",
        )
        .unwrap();
        crate::seed::seed_policies_from_dir(&pool, scope, &dir)
            .await
            .expect("an INVALID-but-nameable file for an existing policy still boots");
        // …and the same file for a policy that does NOT exist refuses.
        std::fs::write(
            dir.join("other.yaml"),
            "name: other\ntools:\n- match: []\n  action: allow\n",
        )
        .unwrap();
        let err = crate::seed::seed_policies_from_dir(&pool, scope, &dir)
            .await
            .expect_err("absent policy, invalid file");
        assert!(err.to_string().contains("ONLY source"), "{err}");
        std::fs::remove_file(dir.join("other.yaml")).unwrap();

        // 5. A file that names NO policy cannot be reasoned about at all.
        std::fs::write(&file, "just a bare string").unwrap();
        let err = crate::seed::seed_policies_from_dir(&pool, scope, &dir)
            .await
            .expect_err("an unnameable file must refuse");
        assert!(err.to_string().contains("unreadable"), "{err}");

        // 6. A route-reserved name must never arrive from disk either.
        std::fs::write(&file, "name: default\n").unwrap();
        std::fs::write(dir.join("clone.yaml"), "name: clone\n").unwrap();
        let err = crate::seed::seed_policies_from_dir(&pool, scope, &dir)
            .await
            .expect_err("a reserved name must refuse");
        assert!(err.to_string().contains("reserved"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `author` is a CLOSED set at the DATABASE level, not just in prose: the
    /// dashboard renders one label per channel and falls back to "dashboard",
    /// so an unconstrained column would let a typo mis-attribute a version in
    /// the audit trail — silently, and forever (the row is immutable).
    #[tokio::test]
    async fn policy_version_author_is_constrained_to_the_known_channels() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_policy_tenant(&pool).await;
        let content = policy_json("auth");
        let policy = upsert_policy(&pool, scope, "auth", "name: auth", &content)
            .await
            .unwrap();
        // Every channel the application actually writes is accepted.
        for author in ["seed", "api", "ui", "import"] {
            append_policy_version(
                &pool,
                scope,
                policy.id,
                None,
                NewPolicyVersion {
                    content: &content,
                    yaml_source: None,
                    summary: Some(author),
                    author,
                    author_user_id: None,
                },
            )
            .await
            .unwrap_or_else(|e| panic!("author {author:?} must be accepted: {e}"));
        }
        let err = append_policy_version(
            &pool,
            scope,
            policy.id,
            None,
            NewPolicyVersion {
                content: &content,
                yaml_source: None,
                summary: Some("typo"),
                author: "iu",
                author_user_id: None,
            },
        )
        .await
        .expect_err("an unknown channel must be refused by the CHECK constraint");
        let is_check_violation = matches!(
            &err,
            sqlx::Error::Database(db) if db.code().as_deref() == Some("23514")
        );
        assert!(is_check_violation, "expected 23514, got {err:?}");
    }

    /// Deleting a policy cascades its whole history — proven AS THE RUNTIME
    /// ROLE, because that role deliberately has NO delete grant on
    /// `policy_versions` (append-only is a database property). The cascade
    /// works anyway: postgres runs referential actions with the referencing
    /// table owner's privileges, and RI bypasses RLS. If that ever stopped
    /// being true, `delete_policy` would fail closed in RLS deployments only —
    /// exactly the kind of split-brain this test exists to prevent.
    #[tokio::test]
    async fn deleting_a_policy_cascades_its_versions_under_the_runtime_role() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        use sqlx::Executor;
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_policy_tenant(&pool).await;
        let content = policy_json("del");
        let policy = upsert_policy(&pool, scope, "del", "name: del", &content)
            .await
            .unwrap();
        for n in 0..2 {
            append_policy_version(
                &pool,
                scope,
                policy.id,
                None,
                NewPolicyVersion {
                    content: &content,
                    yaml_source: None,
                    summary: Some(&format!("v{n}")),
                    author: "ui",
                    author_user_id: None,
                },
            )
            .await
            .unwrap();
        }
        assert_eq!(
            list_policy_versions(&pool, scope, policy.id)
                .await
                .unwrap()
                .len(),
            3
        );

        let as_runtime = PgPoolOptions::new()
            .max_connections(1)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    conn.execute("set role fluidbox_runtime").await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .expect("runtime-role pool");
        let mut tx = as_runtime.begin().await.unwrap();
        sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
            .bind(scope.tenant_id().to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("delete from policies where id = $1")
            .bind(policy.id)
            .execute(&mut *tx)
            .await
            .expect("the runtime role may delete its own policy");
        let (left,): (i64,) =
            sqlx::query_as("select count(*) from policy_versions where policy_id = $1")
                .bind(policy.id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(left, 0, "the composite FK cascade took the history with it");
        tx.commit().await.unwrap();
        assert!(get_policy(&pool, scope, policy.id).await.unwrap().is_none());

        // …and RLS is genuinely engaged on this pool, not merely the grants: a
        // stranger's policy is invisible to the delete, so it removes ZERO
        // rows instead of erroring. Without this the test above would still
        // pass on a pool that bypassed RLS entirely, which is exactly the
        // false-green `test_connect` would have given us.
        let other = throwaway_policy_tenant(&pool).await;
        let theirs = upsert_policy(&pool, other, "rt2", "name: rt2", &content)
            .await
            .unwrap();
        let mut tx = as_runtime.begin().await.unwrap();
        sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
            .bind(scope.tenant_id().to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        let affected = sqlx::query("delete from policies where id = $1")
            .bind(theirs.id)
            .execute(&mut *tx)
            .await
            .expect("RLS hides the row; it does not error")
            .rows_affected();
        assert_eq!(
            affected, 0,
            "a stranger's policy must be invisible to DELETE"
        );
        tx.commit().await.unwrap();
        assert!(
            get_policy(&pool, other, theirs.id).await.unwrap().is_some(),
            "and it is still there"
        );
    }

    /// The delete guard: ANY agent revision naming a policy blocks it, not just
    /// the latest one. Revisions are immutable, so a historical revision must
    /// keep resolving its policy — `policy_agents_using` (which counts only
    /// LATEST revisions) is therefore NOT the right question here, and this
    /// test pins the difference.
    #[tokio::test]
    async fn deleting_a_policy_named_by_any_revision_is_refused() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_policy_tenant(&pool).await;
        let old = upsert_policy(&pool, scope, "old", "name: old", &policy_json("old"))
            .await
            .unwrap();
        let new = upsert_policy(&pool, scope, "new", "name: new", &policy_json("new"))
            .await
            .unwrap();
        let agent = create_agent(&pool, scope, "a", None).await.unwrap();
        let budgets = serde_json::json!({});
        for policy_id in [old.id, new.id] {
            append_agent_revision(
                &pool,
                scope,
                agent.id,
                "claude-agent-sdk",
                "img:test",
                "claude-haiku-4-5",
                None,
                policy_id,
                &budgets,
                None,
                &serde_json::json!([]),
                &serde_json::json!([]),
                None,
            )
            .await
            .unwrap();
        }
        // `old` is nobody's LATEST revision …
        assert_eq!(policy_agents_using(&pool, scope, old.id).await.unwrap(), 0);
        // … and is still undeletable, because rev 1 is immutable and names it.
        assert_eq!(
            delete_policy(&pool, scope, old.id).await.unwrap(),
            DeletePolicy::InUse { revisions: 1 },
        );
        assert_eq!(
            delete_policy(&pool, scope, new.id).await.unwrap(),
            DeletePolicy::InUse { revisions: 1 },
        );
        // An unreferenced policy in the same tenant deletes cleanly, and a
        // second delete of the same id is NotFound rather than an error.
        let free = upsert_policy(&pool, scope, "free", "name: free", &policy_json("free"))
            .await
            .unwrap();
        assert_eq!(
            delete_policy(&pool, scope, free.id).await.unwrap(),
            DeletePolicy::Deleted
        );
        assert_eq!(
            delete_policy(&pool, scope, free.id).await.unwrap(),
            DeletePolicy::NotFound
        );

        // `api.rs::delete_policy` maps THIS constraint name — and only it — to
        // a 409 for the count-then-delete race. A rename would silently turn
        // that race into a 500, and no other test would notice.
        let (fk,): (i64,) = sqlx::query_as(
            "select count(*) from pg_constraint
              where conname = 'agent_revisions_policy_id_fkey'
                and conrelid = 'agent_revisions'::regclass
                and confrelid = 'policies'::regclass",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            fk, 1,
            "agent_revisions_policy_id_fkey is the constraint api.rs keys its 409 on"
        );
    }

    /// A policy is only deletable BY ITS OWN TENANT: `delete_policy` scoped to a
    /// stranger answers NotFound and leaves the row standing (the `TenantScope`
    /// signature plus the `tenant_id` predicate, checked rather than assumed).
    #[tokio::test]
    async fn deleting_another_tenants_policy_is_not_found() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (a, b) = (
            throwaway_policy_tenant(&pool).await,
            throwaway_policy_tenant(&pool).await,
        );
        let mine = upsert_policy(&pool, a, "x", "name: x", &policy_json("x"))
            .await
            .unwrap();
        assert_eq!(
            delete_policy(&pool, b, mine.id).await.unwrap(),
            DeletePolicy::NotFound
        );
        assert!(get_policy(&pool, a, mine.id).await.unwrap().is_some());
        assert_eq!(
            list_policy_versions(&pool, a, mine.id).await.unwrap().len(),
            1,
            "a stranger's refused delete took no history with it"
        );
    }

    /// `create_policy` (the clone/blank path) mints identity + v1 in one
    /// transaction and refuses a duplicate name via unique(tenant_id, name).
    #[tokio::test]
    async fn create_policy_duplicate_name_is_refused() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_policy_tenant(&pool).await;
        let content = policy_json("dup");
        let v = NewPolicyVersion {
            content: &content,
            yaml_source: None,
            summary: None,
            author: "ui",
            author_user_id: None,
        };
        let (policy, v1) = create_policy(&pool, scope, "dup", v).await.unwrap();
        assert_eq!(v1.version, 1);
        assert_eq!(v1.policy_id, policy.id);
        let err = create_policy(&pool, scope, "dup", v)
            .await
            .expect_err("duplicate name must be refused");
        let is_unique_violation = matches!(
            &err,
            sqlx::Error::Database(db) if db.code().as_deref() == Some("23505")
        );
        assert!(is_unique_violation, "expected 23505, got {err:?}");
    }

    /// The 0026 UPGRADE HARNESS: the only place the fold runs against LEGACY
    /// data. A fresh test database never exercises the backfill (the seed runs
    /// after all migrations), so this test builds a scratch database migrated
    /// ONLY through 0025, plants pre-0026 rows — a policy with
    /// `managed_overrides` and two sessions whose frozen snapshots carry the
    /// legacy key — applies the full chain, and asserts:
    ///   1. exactly one version row per policy, overrides folded to HEAD rules
    ///      in stored order, legacy key stripped, odometer/yaml preserved;
    ///   2. `sessions.run_spec` is BYTE-IDENTICAL, terminal and running alike
    ///      (the engine's fold-on-deserialize is the compat path — the
    ///      migration must never rewrite a frozen RunSpec);
    ///   3. the legacy columns are gone.
    #[tokio::test]
    async fn migration_0026_folds_legacy_policies_and_never_touches_runspecs() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("connect admin");
        let suffix = Uuid::now_v7().simple().to_string();
        let dbname = format!("fbx_mig26_{suffix}");
        let create = format!("create database {dbname}");
        sqlx::raw_sql(sqlx::AssertSqlSafe(create))
            .execute(&admin)
            .await
            .expect("create scratch db");

        // postgres://…/<db>[?params] → same server, scratch db.
        let (base, params) = match url.split_once('?') {
            Some((b, p)) => (b, Some(p)),
            None => (url.as_str(), None),
        };
        let (prefix, _) = base.rsplit_once('/').expect("url has a db path");
        let scratch_url = match params {
            Some(p) => format!("{prefix}/{dbname}?{p}"),
            None => format!("{prefix}/{dbname}"),
        };
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        let staged = std::env::temp_dir().join(format!("fbx-mig26-{suffix}"));
        std::fs::create_dir_all(&staged).unwrap();

        // Everything that can FAIL runs in a spawned task, so a panicking
        // assertion arrives here as a `JoinError` instead of unwinding past
        // the cleanup below. Without this, the first regression leaks a
        // database — on the configured server, which per CLAUDE.md is real
        // Neon — and every rerun leaks another onto a dirtier server. The
        // panic is re-raised verbatim after cleanup, so the failure still
        // reads exactly as it would have.
        let body = tokio::spawn({
            let (scratch_url, src, staged) = (scratch_url.clone(), src.clone(), staged.clone());
            async move {
        // Stage migrations 0001..0025 into a temp dir and run them — the
        // public Migrator::new path, so bookkeeping rows are real and the
        // full chain below applies exactly 0026.
        for entry in std::fs::read_dir(&src).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let version: u32 = name.split('_').next().unwrap_or("0").parse().unwrap_or(0);
            if (1..=25).contains(&version) {
                std::fs::copy(entry.path(), staged.join(&name)).unwrap();
            }
        }
        let scratch = PgPoolOptions::new()
            .max_connections(2)
            .connect(&scratch_url)
            .await
            .expect("connect scratch");
        sqlx::migrate::Migrator::new(staged.clone())
            .await
            .expect("staged migrator")
            .run(&scratch)
            .await
            .expect("migrate through 0025");

        // ── Legacy rows, in the 0025 schema ──────────────────────────────
        let tenant = Uuid::now_v7();
        let (policy_id, agent_id, rev_id) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let parsed = serde_json::json!({
            "name": "legacy",
            "defaults": {"tool_action": "approve"},
            "tools": [{"match": ["WebFetch"], "action": "deny"}],
            "managed_overrides": [
                {"tool": "WebFetch", "action": "allow"},
                // A TRAILING-WILDCARD entry: refused by the retired API's
                // validate(), but a migration does not get to assume the write
                // path held. Exact-equality matching made it unreachable, so
                // 0026 drops it (with a warning) instead of folding it into a
                // rule that WOULD match the whole namespace.
                {"tool": "mcp__*", "action": "allow"},
                // A `*` that is NOT trailing is not a wildcard to
                // `tool_matches` either, so it must be KEPT and folded to an
                // exact-equality rule — the drop is precise, not a blanket
                // "contains a star".
                {"tool": "fo*o", "action": "approve"},
                {"tool": "Read", "action": "deny"},
            ],
        });
        let overrides = parsed["managed_overrides"].clone();
        let snapshot_spec = serde_json::json!({
            "policy_snapshot": parsed,
            "task": "legacy run",
        });
        sqlx::query("insert into tenants (id, name, slug) values ($1, $2, $2)")
            .bind(tenant)
            .bind(format!("mig26-{suffix}"))
            .execute(&scratch)
            .await
            .unwrap();
        sqlx::query(
            "insert into policies (id, tenant_id, name, version, yaml_source, parsed, managed_overrides)
             values ($1, $2, 'legacy', 7, 'name: legacy', $3, $4)",
        )
        .bind(policy_id)
        .bind(tenant)
        .bind(&parsed)
        .bind(&overrides)
        .execute(&scratch)
        .await
        .unwrap();
        // A second policy WITHOUT overrides: its authored YAML still describes
        // its content, so the fold must PRESERVE it (only folded policies null
        // theirs — stored YAML must never describe a different policy than the
        // canonical content beside it).
        let plain_id = Uuid::now_v7();
        sqlx::query(
            "insert into policies (id, tenant_id, name, version, yaml_source, parsed, managed_overrides)
             values ($1, $2, 'legacy-plain', 2, 'name: legacy-plain', $3, '[]'::jsonb)",
        )
        .bind(plain_id)
        .bind(tenant)
        .bind(serde_json::json!({"name": "legacy-plain", "tools": []}))
        .execute(&scratch)
        .await
        .unwrap();
        sqlx::query("insert into agents (id, tenant_id, name) values ($1, $2, 'legacy-agent')")
            .bind(agent_id)
            .bind(tenant)
            .execute(&scratch)
            .await
            .unwrap();
        sqlx::query(
            "insert into agent_revisions (id, agent_id, rev, harness, runner_image, model, policy_id, budgets)
             values ($1, $2, 1, 'claude-agent-sdk', 'img:test', 'claude-haiku-4-5', $3, '{}')",
        )
        .bind(rev_id)
        .bind(agent_id)
        .bind(policy_id)
        .execute(&scratch)
        .await
        .unwrap();
        for (sid, status) in [(Uuid::now_v7(), "running"), (Uuid::now_v7(), "completed")] {
            sqlx::query(
                "insert into sessions (id, tenant_id, agent_id, agent_revision_id, status, task,
                                       repo_source, run_spec, budgets)
                 values ($1, $2, $3, $4, $5, 'legacy task', '{\"kind\":\"none\"}', $6, '{}')",
            )
            .bind(sid)
            .bind(tenant)
            .bind(agent_id)
            .bind(rev_id)
            .bind(status)
            .bind(&snapshot_spec)
            .execute(&scratch)
            .await
            .unwrap();
        }
        let specs_before: Vec<(Uuid, String)> =
            sqlx::query_as("select id, run_spec::text from sessions order by id")
                .fetch_all(&scratch)
                .await
                .unwrap();

        // ── Apply the full chain (exactly 0026) ──────────────────────────
        sqlx::migrate::Migrator::new(src.clone())
            .await
            .expect("full migrator")
            .run(&scratch)
            .await
            .expect("apply 0026");

        // 1. One folded version, odometer + yaml preserved, key stripped.
        let (version, content, yaml, author): (i32, serde_json::Value, Option<String>, String) =
            sqlx::query_as(
                "select version, content, yaml_source, author from policy_versions
                  where policy_id = $1",
            )
            .bind(policy_id)
            .fetch_one(&scratch)
            .await
            .unwrap();
        assert_eq!((version, author.as_str()), (7, "import"));
        assert_eq!(
            yaml, None,
            "a FOLDED policy's stored YAML would describe a different policy \
             than its content — export must regenerate from the folded truth"
        );
        assert!(content.get("managed_overrides").is_none(), "key stripped");
        let (plain_yaml,): (Option<String>,) =
            sqlx::query_as("select yaml_source from policy_versions where policy_id = $1")
                .bind(plain_id)
                .fetch_one(&scratch)
                .await
                .unwrap();
        assert_eq!(
            plain_yaml.as_deref(),
            Some("name: legacy-plain"),
            "an un-folded policy keeps its authored YAML (and its comments)"
        );
        assert_eq!(
            content["tools"],
            serde_json::json!([
                {"match": ["WebFetch"], "action": "allow"},
                {"match": ["fo*o"], "action": "approve"},
                {"match": ["Read"], "action": "deny"},
                {"match": ["WebFetch"], "action": "deny"},
            ]),
            "overrides fold to HEAD rules in stored order, authored rules after — \
             and the WILDCARD entry between them is DROPPED, never folded into a \
             namespace-wide rule"
        );
        let folded: fluidbox_core::policy::Policy =
            serde_json::from_value(content.clone()).expect("folded content is a valid Policy");
        assert_eq!(folded.tools.len(), 4);
        // The migration's SQL fold and the engine's deserialize-time fold must
        // be the SAME transform, or a MIGRATED policy and a still-FROZEN
        // snapshot of it would resolve differently — the exact split this
        // whole design exists to avoid.
        //
        // Compared after both have been through the engine, not as raw jsonb:
        // the SQL fold writes terse rule objects (`{match, action}`) while
        // serde emits every optional field as an explicit null. Those are the
        // same document to every reader that matters, and `Policy`'s own
        // canonical serialization is the arbiter of that.
        let via_engine: fluidbox_core::policy::Policy =
            serde_json::from_value(parsed.clone()).expect("legacy blob deserializes");
        assert_eq!(
            serde_json::to_value(&via_engine).unwrap(),
            serde_json::to_value(&folded).unwrap(),
            "0026's SQL fold and fluidbox-core's deserialize-time fold disagree; an \
             in-flight run would not keep the semantics its snapshot froze"
        );

        // 2. Frozen RunSpecs untouched — byte for byte, terminal AND running.
        let specs_after: Vec<(Uuid, String)> =
            sqlx::query_as("select id, run_spec::text from sessions order by id")
                .fetch_all(&scratch)
                .await
                .unwrap();
        assert_eq!(
            specs_before, specs_after,
            "0026 must never rewrite a frozen RunSpec — the engine's \
             fold-on-deserialize is the compat path"
        );

        // 3. The legacy columns are gone.
        let (survivors,): (i64,) = sqlx::query_as(
            "select count(*) from information_schema.columns
              where table_name = 'policies'
                and column_name in ('parsed', 'yaml_source', 'managed_overrides', 'version')",
        )
        .fetch_one(&scratch)
        .await
        .unwrap();
        assert_eq!(survivors, 0);
        scratch.close().await;
            }
        })
        .await;

        // Cleanup runs on BOTH paths.
        let drop_db = format!("drop database {dbname} with (force)");
        sqlx::raw_sql(sqlx::AssertSqlSafe(drop_db))
            .execute(&admin)
            .await
            .expect("drop scratch db");
        let _ = std::fs::remove_dir_all(&staged);
        // …and only then does the failure surface, unchanged.
        if let Err(e) = body {
            if e.is_panic() {
                std::panic::resume_unwind(e.into_panic());
            }
            panic!("migration 0026 harness task did not run to completion: {e}");
        }
    }

    /// The 0026 grant claim, proven AS THE RUNTIME ROLE (test_connect's pool
    /// carries the system_worker bypass, so it proves nothing about RLS or
    /// grants): under `fluidbox_runtime` + a tenant GUC, tenant A reads its own
    /// versions and ZERO of tenant B's, and UPDATE/DELETE are permission-denied
    /// — append-only is a database property, not an application convention.
    #[tokio::test]
    async fn policy_versions_are_append_only_and_isolated_under_the_runtime_role() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        use sqlx::Executor;
        let pool = test_connect(&url).await.expect("connect");
        let (a, b) = (
            throwaway_policy_tenant(&pool).await,
            throwaway_policy_tenant(&pool).await,
        );
        let pa = upsert_policy(&pool, a, "rt", "name: rt", &policy_json("rt"))
            .await
            .unwrap();
        let pb = upsert_policy(&pool, b, "rt", "name: rt", &policy_json("rt"))
            .await
            .unwrap();

        let as_runtime = PgPoolOptions::new()
            .max_connections(1)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    conn.execute("set role fluidbox_runtime").await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .expect("runtime-role pool");
        let mut tx = as_runtime.begin().await.unwrap();
        sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
            .bind(a.tenant_id().to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        let (own, foreign): (i64, i64) = (
            sqlx::query_scalar("select count(*) from policy_versions where policy_id = $1")
                .bind(pa.id)
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            // B's CAPTURED policy id, queried DIRECTLY: a join through
            // `policies` would be hidden by the PARENT's RLS and false-green
            // even if policy_versions itself leaked.
            sqlx::query_scalar("select count(*) from policy_versions where policy_id = $1")
                .bind(pb.id)
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
        );
        assert_eq!(
            (own, foreign),
            (1, 0),
            "RLS: own rows visible, no stranger's"
        );
        let update_err =
            sqlx::query("update policy_versions set summary = 'x' where policy_id = $1")
                .bind(pa.id)
                .execute(&mut *tx)
                .await
                .expect_err("UPDATE must be permission-denied");
        assert!(
            update_err.to_string().contains("permission denied"),
            "{update_err}"
        );
        tx.rollback().await.unwrap();
        // A failed statement poisons the tx; DELETE gets its own.
        let mut tx = as_runtime.begin().await.unwrap();
        sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
            .bind(a.tenant_id().to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        let delete_err = sqlx::query("delete from policy_versions where policy_id = $1")
            .bind(pa.id)
            .execute(&mut *tx)
            .await
            .expect_err("DELETE must be permission-denied");
        assert!(
            delete_err.to_string().contains("permission denied"),
            "{delete_err}"
        );
        tx.rollback().await.unwrap();
    }

    /// TWO racing boots (the multi-replica case the row lock exists for) mint
    /// exactly one seed version between them.
    #[tokio::test]
    async fn concurrent_seeds_mint_exactly_one_version() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_policy_tenant(&pool).await;
        let content = policy_json("race");
        let (r1, r2) = tokio::join!(
            seed_policy_if_absent(&pool, scope, "race", "name: race", &content),
            seed_policy_if_absent(&pool, scope, "race", "name: race", &content),
        );
        let (p1, _) = r1.unwrap();
        let (p2, _) = r2.unwrap();
        assert_eq!(p1.id, p2.id, "one identity");
        assert_eq!(
            list_policy_versions(&pool, scope, p1.id)
                .await
                .unwrap()
                .len(),
            1,
            "one seed version between the racers"
        );
    }

    /// Version rows never leak across tenants: the same policy name in two
    /// tenants is two histories, and one scope cannot read the other's.
    #[tokio::test]
    async fn policy_versions_never_leak_between_tenants() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (a, b) = (
            throwaway_policy_tenant(&pool).await,
            throwaway_policy_tenant(&pool).await,
        );
        let pa = upsert_policy(&pool, a, "shared", "name: shared", &policy_json("shared"))
            .await
            .unwrap();
        let pb = upsert_policy(&pool, b, "shared", "name: shared", &policy_json("shared"))
            .await
            .unwrap();
        assert_ne!(pa.id, pb.id);
        assert!(
            latest_policy_version(&pool, b, pa.id)
                .await
                .unwrap()
                .is_none(),
            "tenant B must not resolve tenant A's versions"
        );
        assert!(get_policy_version(&pool, b, pa.id, 1)
            .await
            .unwrap()
            .is_none());
        assert!(list_policy_versions(&pool, b, pa.id)
            .await
            .unwrap()
            .is_empty());
    }

    /// Only the LATEST revision governs future runs, so only it may count toward a
    /// policy's blast radius. Uses fresh policy names, so the shared default tenant's
    /// other agents cannot perturb the counts.
    #[tokio::test]
    async fn policy_agents_using_counts_only_latest_revisions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        let mk = |name: &str| format!("name: {name}\ntools: []\n");
        let (ya, yb) = (mk("pau-a"), mk("pau-b"));
        let pa = upsert_policy(
            &pool,
            scope,
            "pau-a",
            &ya,
            &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(&ya).unwrap()).unwrap(),
        )
        .await
        .unwrap();
        let pb = upsert_policy(
            &pool,
            scope,
            "pau-b",
            &yb,
            &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(&yb).unwrap()).unwrap(),
        )
        .await
        .unwrap();

        let agent = create_agent(&pool, scope, "pau-agent", None).await.unwrap();
        let budgets = serde_json::json!({});
        let pins = serde_json::json!([]);
        let reqs = serde_json::json!([]);
        let rev = |policy_id| {
            append_agent_revision(
                &pool,
                scope,
                agent.id,
                "claude-agent-sdk",
                "img",
                "claude-haiku-4-5",
                None,
                policy_id,
                &budgets,
                None,
                &pins,
                &reqs,
                None,
            )
        };

        rev(pa.id).await.unwrap();
        assert_eq!(policy_agents_using(&pool, scope, pa.id).await.unwrap(), 1);
        assert_eq!(policy_agents_using(&pool, scope, pb.id).await.unwrap(), 0);

        // Append a revision moving the agent to policy B: A drops to 0, B goes to 1.
        rev(pb.id).await.unwrap();
        assert_eq!(policy_agents_using(&pool, scope, pa.id).await.unwrap(), 0);
        assert_eq!(policy_agents_using(&pool, scope, pb.id).await.unwrap(), 1);
    }

    /// The matrix's MCP rows come from what the agents on this policy can actually
    /// call: the union of the photographed tools in the bundles pinned on their
    /// LATEST revisions — sorted, and deduplicated across agents sharing a bundle.
    #[tokio::test]
    async fn policy_mcp_tools_unions_pinned_bundle_tools() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let scope = TenantScope::assume(tenant);

        let yaml = "name: pmt-policy\ntools: []\n";
        let policy = upsert_policy(
            &pool,
            scope,
            "pmt-policy",
            yaml,
            &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(yaml).unwrap())
                .unwrap(),
        )
        .await
        .unwrap();

        // Tools are declared out of alphabetical order: the union must sort them.
        let bundle_name = format!("pmt-bundle-{}", Uuid::now_v7());
        let def = serde_json::json!({"servers": [{
            "class": "brokered", "name": "beta",
            "tools": [
                {"name": "zeta", "description": "d", "input_schema": {"type": "object"}},
                {"name": "alpha", "description": "d", "input_schema": {"type": "object"}}
            ]
        }]});
        let bundle = create_capability_bundle(&pool, scope, &bundle_name, None, &def, "sha256:pmt")
            .await
            .unwrap();
        let pins = serde_json::json!([
            { "id": bundle.id, "name": bundle.name, "version": bundle.version }
        ]);

        // Two agents share the bundle: the union deduplicates across them.
        let budgets = serde_json::json!({});
        for name in ["pmt-agent-a", "pmt-agent-b"] {
            let agent = create_agent(&pool, scope, name, None).await.unwrap();
            append_agent_revision(
                &pool,
                scope,
                agent.id,
                "claude-agent-sdk",
                "img",
                "claude-haiku-4-5",
                None,
                policy.id,
                &budgets,
                None,
                &pins,
                &serde_json::json!([]),
                None,
            )
            .await
            .unwrap();
        }

        assert_eq!(
            policy_mcp_tools(&pool, scope, policy.id).await.unwrap(),
            vec![
                "mcp__beta__alpha".to_string(),
                "mcp__beta__zeta".to_string()
            ]
        );

        // A policy nobody's latest revision points at contributes no tools.
        let empty_yaml = "name: pmt-empty\ntools: []\n";
        let empty = upsert_policy(
            &pool,
            scope,
            "pmt-empty",
            empty_yaml,
            &serde_json::to_value(fluidbox_core::policy::Policy::parse_yaml(empty_yaml).unwrap())
                .unwrap(),
        )
        .await
        .unwrap();
        assert!(policy_mcp_tools(&pool, scope, empty.id)
            .await
            .unwrap()
            .is_empty());
    }

    /// Run migration 0013's legacy-bundle conversion RLS-BOUND — the ONLY
    /// sanctioned way for a test to invoke it (see the source guard
    /// `conversion_is_only_ever_invoked_rls_bound`).
    ///
    /// WHY (CI round 4, #32). The conversion is a deliberately tenant-LESS
    /// maintenance scan — `for v_agent in select id, tenant_id from agents` — and it
    /// allocates each appended revision's `rev` from a per-agent counter seeded by
    /// the current `max(rev)`. Called bare on the shared test database it therefore
    /// converts EVERY other test's agents as well as its own, and two calls in
    /// flight at the same moment both read `max(rev) = 1` and both insert rev 2: the
    /// loser waits on `agent_revisions_agent_id_rev_key` and dies with 23505. That
    /// is exactly how CI failed — the three conversion tests all ran within 300 ms
    /// of each other and one of them had its own agent converted out from under it.
    ///
    /// The confinement has to be RLS, because the function takes no tenant
    /// argument. A DEDICATED connection `SET ROLE`s to migration 0018's runtime role
    /// — CI's base user is the SUPERUSER `postgres`, for whom Postgres skips every
    /// policy, so the `SET ROLE` is what makes the policy run at all — and then sets
    /// `fluidbox.tenant_id`. The function is SECURITY INVOKER, so every read and
    /// write inside it is policy-filtered to `tenant`: a test can now only ever
    /// convert its own throwaway org, whatever else is running beside it.
    ///
    /// The connection is dedicated, never borrowed from the fixture pool, because
    /// `SET ROLE` is SESSION state and would ride a pooled connection back to the
    /// next borrower.
    ///
    /// `tenant: None` sets NO GUC at all. That is used once, on purpose, to prove
    /// the degraded mode of a GUC-less caller: zero visible `agents` rows means the
    /// loop body never runs, so the conversion is a silent NO-OP rather than a
    /// miscomputed append.
    async fn convert_legacy_bundles_rls_bound(url: &str, tenant: Option<Uuid>) {
        use sqlx::{Connection, Executor};
        let mut conn = sqlx::PgConnection::connect(url)
            .await
            .expect("conversion connection");
        conn.execute("set role fluidbox_runtime")
            .await
            .expect("set role fluidbox_runtime (migration 0018 creates + grants it)");
        let mut tx = conn.begin().await.expect("begin conversion tx");
        if let Some(t) = tenant {
            sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
                .bind(t.to_string())
                .execute(&mut *tx)
                .await
                .expect("tenant guc");
        }
        sqlx::query("select fluidbox_convert_legacy_bundles()")
            .execute(&mut *tx)
            .await
            .expect("conversion");
        tx.commit().await.expect("commit conversion tx");
        conn.close().await.ok();
    }

    /// Source guard for the CI-round-4 class (#32). The conversion is tenant-less
    /// and races on `max(rev)`, so ANY caller outside
    /// `convert_legacy_bundles_rls_bound` reintroduces the cross-test collision.
    /// This is a source assertion, not a DB test: it runs even without
    /// `DATABASE_URL`, so a re-added bare caller fails CI immediately instead of
    /// flaking. The needle is assembled from two halves so this guard is not itself
    /// an occurrence of it.
    #[test]
    fn conversion_is_only_ever_invoked_rls_bound() {
        let needle = concat!("select fluidbox_convert_legacy", "_bundles()");
        let n = include_str!("lib.rs").matches(needle).count();
        assert_eq!(
            n, 1,
            "`{needle}` must appear exactly ONCE in fluidbox-db (inside \
             convert_legacy_bundles_rls_bound) — found {n}. Route the new call through that \
             helper: a bare pool call converts every other test's agents and races them for \
             the next rev (23505 on agent_revisions_agent_id_rev_key)."
        );
    }

    /// Migration 0013 appendix (`fluidbox_convert_legacy_bundles`): a legacy
    /// agent whose LATEST revision pins a brokered bundle gets an APPENDED
    /// sandbox-only revision whose brokered servers became
    /// `connection_requirements`; its pinned subscription is repointed; and a
    /// second call is idempotent. Also proves the SQL-built requirement jsonb
    /// round-trips into typed `ConnectionRequirement`s (serde compatibility) and
    /// that `policy_mcp_tools` unions the converted requirement tools. Throwaway
    /// org; children-first cleanup BEFORE the asserts.
    /// A tenant with NO policies is not merely empty: every run in it fails
    /// closed at `create_run`, AFTER provisioning. `create_org` seeded nothing,
    /// so every new org started in exactly that state. Throwaway org, and the
    /// cleanup runs BEFORE the asserts so a failure cannot leak a tenant into a
    /// database that already carries a thousand fixtures.
    #[tokio::test]
    async fn seed_tiers_for_tenant_gives_a_new_org_a_usable_policy_set() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);

        crate::seed::seed_tiers_for_tenant(&pool, scope)
            .await
            .unwrap();
        // Called twice on purpose: this runs on a path an operator can retry,
        // so a second call must be a no-op rather than a second version.
        crate::seed::seed_tiers_for_tenant(&pool, scope)
            .await
            .unwrap();

        let mut found: Vec<(&str, bool, Option<i32>)> = Vec::new();
        for name in ["default", "unrestricted", "standard", "governed"] {
            match get_policy_by_name(&pool, scope, name).await.unwrap() {
                Some(p) => {
                    let v = latest_policy_version(&pool, scope, p.id)
                        .await
                        .unwrap()
                        .map(|v| v.version);
                    found.push((name, true, v));
                }
                None => found.push((name, false, None)),
            }
        }

        // Children first — tenant FKs are NO ACTION, nothing cascades.
        for stmt in [
            "delete from policy_versions where tenant_id = $1",
            "delete from policies where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            let _ = sqlx::query(stmt).bind(org.id).execute(&pool).await;
        }

        for (name, present, version) in found {
            assert!(present, "new org is missing policy '{name}'");
            assert_eq!(
                version,
                Some(1),
                "policy '{name}' must have exactly version 1 — a missing version fails \
                 every run closed, and a second version means seeding was not idempotent"
            );
        }
    }

    #[tokio::test]
    async fn convert_legacy_bundles_appends_requirements_and_repoints() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);

        // Two brokered endpoints — one matches a tenant catalog row (slug hint),
        // one has no catalog row (slug null) — so the stored jsonb exercises BOTH
        // slug shapes and the reverse-match's tenant-first / unique-or-null rule.
        let gh_url = "https://mcp.github.test/mcp";
        let ln_url = "https://mcp.linear.test/mcp";

        // An org-owned mcp_http connection: the legacy world embedded its id in
        // the brokered server (Gap 3). The conversion DROPS that id — we build the
        // connection only for realism and to prove the conversion ignores it.
        let conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "mcp.github.test",
            "GitHub MCP",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({ "base_url": gh_url }),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        // A tenant-owned catalog row whose url == gh_url → reverse-match slug.
        sqlx::query(
            "insert into connector_catalog (id, slug, name, url, tenant_id, provenance)
             values ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::now_v7())
        .bind("github-mcp")
        .bind("GitHub MCP")
        .bind(gh_url)
        .bind(org.id)
        .bind(serde_json::json!({ "source": "custom" }))
        .execute(&pool)
        .await
        .unwrap();

        // A brokered bundle: two brokered servers (github matched, linear not);
        // github ships two tools in a deliberate order, linear one.
        let brokered_def = serde_json::json!({ "servers": [
            { "class": "brokered", "name": "github", "url": gh_url,
              "connection_id": conn.id,
              "tools": [
                { "name": "get_pull_request", "description": "d", "input_schema": {"type": "object"} },
                { "name": "create_review", "description": "d", "input_schema": {"type": "object"} }
              ] },
            { "class": "brokered", "name": "linear", "url": ln_url,
              "connection_id": conn.id,
              "tools": [
                { "name": "list_issues", "description": "d", "input_schema": {"type": "object"} }
              ] }
        ] });
        let brokered_bundle = create_capability_bundle(
            &pool,
            scope,
            "connectors",
            None,
            &brokered_def,
            "sha256:brk",
        )
        .await
        .unwrap();

        // A sandbox-only bundle: survives, re-pinned as sandbox-tools@1.
        let sandbox_def = serde_json::json!({ "servers": [
            { "class": "sandbox", "name": "ws", "command": "node", "args": ["/x.mjs"],
              "tools": [ { "name": "count", "description": "d", "input_schema": {"type": "object"} } ] }
        ] });
        let sandbox_bundle = create_capability_bundle(
            &pool,
            scope,
            "sandbox-tools",
            None,
            &sandbox_def,
            "sha256:sbx",
        )
        .await
        .unwrap();

        let policy = upsert_policy(
            &pool,
            scope,
            "conv-policy",
            "name: conv",
            &serde_json::json!({ "name": "conv" }),
        )
        .await
        .unwrap();

        let agent = create_agent(&pool, scope, "conv-agent", None)
            .await
            .unwrap();
        // rev 1 pins BOTH bundles as BundleRef objects (the live stored shape).
        let pins = serde_json::json!([
            { "id": brokered_bundle.id, "name": brokered_bundle.name, "version": brokered_bundle.version },
            { "id": sandbox_bundle.id, "name": sandbox_bundle.name, "version": sandbox_bundle.version }
        ]);
        let rev1 = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            Some("be helpful"),
            policy.id,
            &serde_json::json!({ "wall_clock_secs": 60 }),
            Some(&serde_json::json!({ "kind": "scratch" })),
            &pins,
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();

        // A subscription pinned to rev 1 — must be repointed to the new revision.
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            "conv-sub",
            "api",
            Some(rev1.id),
            Some("do it"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // ── Convert (the DB test calls the function 0013 defined + already ran),
        // RLS-BOUND and confined to this org so it cannot reach — or race — the
        // other conversion tests' agents. ──
        convert_legacy_bundles_rls_bound(&url, Some(org.id)).await;

        let latest = latest_revision(&pool, scope, agent.id)
            .await
            .unwrap()
            .unwrap();
        let sub_after = get_trigger_subscription(&pool, scope, sub.id)
            .await
            .unwrap()
            .unwrap();
        let revs_after = list_revisions(&pool, scope, agent.id).await.unwrap();

        // Idempotence: a SECOND call must not append again.
        convert_legacy_bundles_rls_bound(&url, Some(org.id)).await;
        let revs_after2 = list_revisions(&pool, scope, agent.id).await.unwrap();
        let latest2 = latest_revision(&pool, scope, agent.id)
            .await
            .unwrap()
            .unwrap();

        // Governance union AND serde round-trip captured before cleanup.
        let mcp_tools = policy_mcp_tools(&pool, scope, policy.id).await.unwrap();
        let req_parse: Result<
            Vec<fluidbox_core::capability::ConnectionRequirement>,
            serde_json::Error,
        > = serde_json::from_value(latest.connection_requirements.clone());

        // ── Cleanup children-first BEFORE the asserts (throwaway org) ──
        for stmt in [
            "delete from run_resource_bindings where tenant_id = $1",
            "delete from connection_tool_snapshots where tenant_id = $1",
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from capability_bundles where tenant_id = $1",
            "delete from connector_catalog where tenant_id = $1",
            "delete from integration_connections where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org.id).execute(&pool).await.unwrap();
        }
        sqlx::query("delete from tenants where id = $1")
            .bind(org.id)
            .execute(&pool)
            .await
            .unwrap();

        // ── Asserts ──
        // A new immutable revision was appended at rev+1, copying the revision's
        // fields verbatim.
        assert_eq!(latest.rev, rev1.rev + 1, "conversion appends rev+1");
        assert_ne!(latest.id, rev1.id);
        assert_eq!(latest.harness, rev1.harness);
        assert_eq!(latest.runner_image, rev1.runner_image);
        assert_eq!(latest.model, rev1.model);
        assert_eq!(latest.system_prompt, rev1.system_prompt);
        assert_eq!(latest.policy_id, rev1.policy_id);
        assert_eq!(latest.budgets, rev1.budgets);
        assert_eq!(latest.default_workspace, rev1.default_workspace);

        // Only the sandbox-only bundle survives, re-pinned EXPLICITLY as an exact
        // BundleRef (version 1 IS the `name@1` pin run_service deserializes).
        assert_eq!(
            latest.capability_bundles,
            serde_json::json!([
                { "id": sandbox_bundle.id, "name": "sandbox-tools", "version": 1 }
            ]),
            "only the sandbox-only bundle survives, re-pinned name@1"
        );

        // Requirements EXACTLY as specified: bundle-pin then server order, tool
        // order preserved, binding_mode organization, slug matched then null.
        assert_eq!(
            latest.connection_requirements,
            serde_json::json!([
                { "slot": "github",
                  "connector": { "url": gh_url, "slug": "github-mcp" },
                  "required_tools": ["get_pull_request", "create_review"],
                  "binding_mode": "organization" },
                { "slot": "linear",
                  "connector": { "url": ln_url, "slug": null },
                  "required_tools": ["list_issues"],
                  "binding_mode": "organization" }
            ]),
            "requirements derived deterministically from the brokered servers"
        );

        // The SQL-built jsonb round-trips into typed requirements AND passes
        // validate_requirements — pins serde compatibility of both slug shapes.
        let reqs = req_parse.expect("stored requirements deserialize into ConnectionRequirement");
        fluidbox_core::capability::validate_requirements(&reqs)
            .expect("converted requirements are valid");
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].slot, "github");
        assert_eq!(reqs[0].connector.slug.as_deref(), Some("github-mcp"));
        assert_eq!(reqs[1].slot, "linear");
        assert_eq!(reqs[1].connector.slug, None);
        assert!(matches!(
            reqs[0].binding_mode,
            fluidbox_core::capability::BindingMode::Organization
        ));

        // The pinned subscription was repointed to the new revision.
        assert_eq!(
            sub_after.pinned_revision_id,
            Some(latest.id),
            "subscription repointed to the converted revision"
        );

        // Exactly one revision appended, and the second call added none.
        assert_eq!(revs_after.len(), 2, "exactly one revision appended");
        assert_eq!(
            revs_after2.len(),
            2,
            "second call is idempotent — no double-append"
        );
        assert_eq!(
            latest2.id, latest.id,
            "latest unchanged after idempotent re-run"
        );

        // policy_mcp_tools unions the converted requirement tools with the
        // surviving sandbox bundle's tools.
        for t in [
            "mcp__github__get_pull_request",
            "mcp__github__create_review",
            "mcp__linear__list_issues",
            "mcp__ws__count",
        ] {
            assert!(
                mcp_tools.contains(&t.to_string()),
                "policy_mcp_tools missing {t}"
            );
        }
    }

    /// Migration 0013 appendix — branch coverage the happy path above never
    /// reaches: (a) a brokered server with EMPTY tools is skipped while its
    /// bundle-mates still convert; (b) two pinned bundles whose brokered servers
    /// share an alias dedup to `slot` / `slot-2` in encounter order; (c) a SECOND
    /// agent in the same call also converts (both get new revisions); (d) an
    /// agent with NO subscription converts cleanly (nothing to repoint); (e) an
    /// unresolvable BundleRef object AND a non-numeric `name@abc` string pin
    /// (Finding 3) are both dropped without aborting, the other pins converting;
    /// (f) the RLS degraded mode — the same function on an RLS-bound connection with
    /// NO GUC converts NOTHING (a silent no-op, never a partial append).
    /// One conversion call (RLS-bound, confined to this org — see
    /// `convert_legacy_bundles_rls_bound`); throwaway org; children-first cleanup
    /// BEFORE asserts.
    #[tokio::test]
    async fn convert_legacy_bundles_covers_skip_dedup_multiagent_and_unresolvable() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);

        // Small builders so the fixtures read as data, not boilerplate.
        let brokered = |name: &str, url: &str, tools: &[&str]| -> serde_json::Value {
            let tools_json: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!(
                        { "name": t, "description": "d", "input_schema": {"type": "object"} }
                    )
                })
                .collect();
            serde_json::json!({ "class": "brokered", "name": name, "url": url, "tools": tools_json })
        };
        let sandbox = |name: &str| -> serde_json::Value {
            serde_json::json!({ "class": "sandbox", "name": name, "command": "node", "args": ["/x.mjs"],
                "tools": [ { "name": "count", "description": "d", "input_schema": {"type": "object"} } ] })
        };

        let policy = upsert_policy(
            &pool,
            scope,
            "cov-policy",
            "name: cov",
            &serde_json::json!({ "name": "cov" }),
        )
        .await
        .unwrap();

        // ── Agent A: a MIXED bundle (brokered-with-tools + brokered-EMPTY +
        // sandbox) then a second bundle re-using the `dup` alias, then two
        // unresolvable pins (a missing BundleRef object and a `ghost@abc`
        // string). No subscription. ──
        let dup_a_url = "https://a.dup.test/mcp";
        let dup_b_url = "https://b.dup.test/mcp";
        let bundle_dup_a = create_capability_bundle(
            &pool,
            scope,
            "dup-a",
            None,
            &serde_json::json!({ "servers": [
                brokered("dup", dup_a_url, &["a_one", "a_two"]),
                brokered("empty", "https://empty.test/mcp", &[]),
                sandbox("sbx"),
            ] }),
            "sha256:dupa",
        )
        .await
        .unwrap();
        let bundle_dup_b = create_capability_bundle(
            &pool,
            scope,
            "dup-b",
            None,
            &serde_json::json!({ "servers": [ brokered("dup", dup_b_url, &["b_one"]) ] }),
            "sha256:dupb",
        )
        .await
        .unwrap();

        let agent_a = create_agent(&pool, scope, "cov-agent-a", None)
            .await
            .unwrap();
        let pins_a = serde_json::json!([
            { "id": bundle_dup_a.id, "name": bundle_dup_a.name, "version": bundle_dup_a.version },
            { "id": bundle_dup_b.id, "name": bundle_dup_b.name, "version": bundle_dup_b.version },
            // (e) unresolvable BundleRef object — random id, no such bundle.
            { "id": Uuid::now_v7(), "name": "ghost", "version": 1 },
            // (Finding 3) non-numeric `name@N` string — must drop, not abort.
            "ghost@abc"
        ]);
        let rev_a1 = append_agent_revision(
            &pool,
            scope,
            agent_a.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            Some("be helpful"),
            policy.id,
            &serde_json::json!({ "wall_clock_secs": 60 }),
            None,
            &pins_a,
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();

        // ── Agent B: a second agent with its own brokered pin and a pinned
        // subscription that must be repointed. ──
        let jira_url = "https://jira.test/mcp";
        let bundle_solo_b = create_capability_bundle(
            &pool,
            scope,
            "solo-b",
            None,
            &serde_json::json!({ "servers": [ brokered("jira", jira_url, &["search"]) ] }),
            "sha256:solob",
        )
        .await
        .unwrap();
        let agent_b = create_agent(&pool, scope, "cov-agent-b", None)
            .await
            .unwrap();
        let pins_b = serde_json::json!([
            { "id": bundle_solo_b.id, "name": bundle_solo_b.name, "version": bundle_solo_b.version }
        ]);
        let rev_b1 = append_agent_revision(
            &pool,
            scope,
            agent_b.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            Some("be helpful"),
            policy.id,
            &serde_json::json!({ "wall_clock_secs": 60 }),
            None,
            &pins_b,
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        let sub_b = create_trigger_subscription(
            &pool,
            scope,
            agent_b.id,
            "cov-sub-b",
            "api",
            Some(rev_b1.id),
            Some("do it"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // ── (f) GUC guard, asserted below: the SAME function on an RLS-BOUND
        // connection with NEITHER GUC set sees zero `agents` rows, so its loop body
        // never runs and it converts NOTHING. Pinning that here keeps the degraded
        // mode honest — a GUC-less caller is a silent NO-OP, never a partial or
        // miscomputed append — and proves the confinement below is real RLS rather
        // than coincidence. ──
        convert_legacy_bundles_rls_bound(&url, None).await;
        let revs_a_gucless = list_revisions(&pool, scope, agent_a.id)
            .await
            .unwrap()
            .len();
        let revs_b_gucless = list_revisions(&pool, scope, agent_b.id)
            .await
            .unwrap()
            .len();

        // ── One conversion call processes BOTH agents (c) — RLS-BOUND and confined
        // to this org, so it can neither reach nor race the other conversion
        // tests' agents (they are in their own throwaway orgs). ──
        convert_legacy_bundles_rls_bound(&url, Some(org.id)).await;

        let latest_a = latest_revision(&pool, scope, agent_a.id)
            .await
            .unwrap()
            .unwrap();
        let latest_b = latest_revision(&pool, scope, agent_b.id)
            .await
            .unwrap()
            .unwrap();
        let revs_a = list_revisions(&pool, scope, agent_a.id).await.unwrap();
        let revs_b = list_revisions(&pool, scope, agent_b.id).await.unwrap();
        let sub_b_after = get_trigger_subscription(&pool, scope, sub_b.id)
            .await
            .unwrap()
            .unwrap();

        // ── Cleanup children-first BEFORE the asserts (throwaway org) ──
        for stmt in [
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from capability_bundles where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org.id).execute(&pool).await.unwrap();
        }
        sqlx::query("delete from tenants where id = $1")
            .bind(org.id)
            .execute(&pool)
            .await
            .unwrap();

        // ── Asserts ──
        // (f) The GUC-less call converted NOTHING: both agents still stood at their
        // single seed revision when the confined call ran. This is the fail-closed
        // direction of the RLS contract — invisible rows mean no work, not wrong work.
        assert_eq!(
            (revs_a_gucless, revs_b_gucless),
            (1, 1),
            "a GUC-less conversion must be a silent NO-OP (RLS hides every agent row)"
        );

        // (c) BOTH agents converted in the single call — each has exactly two
        // revisions, the new one appended at rev+1.
        assert_eq!(revs_a.len(), 2, "agent A converted (rev appended)");
        assert_eq!(revs_b.len(), 2, "agent B converted in the SAME call (c)");
        assert_eq!(latest_a.rev, rev_a1.rev + 1);
        assert_eq!(latest_b.rev, rev_b1.rev + 1);

        // (a)+(b)+(e)+Finding 3: agent A's requirements are EXACTLY the two
        // brokered servers that carried tools — `empty` skipped (a), sandbox
        // dropped, both unresolvable pins gone (e / Finding 3) — with the shared
        // alias dedup'd in encounter order: `dup` (from dup-a) then `dup-2`
        // (from dup-b), each connector.url proving which bundle it came from.
        assert_eq!(
            latest_a.connection_requirements,
            serde_json::json!([
                { "slot": "dup",
                  "connector": { "url": dup_a_url, "slug": null },
                  "required_tools": ["a_one", "a_two"],
                  "binding_mode": "organization" },
                { "slot": "dup-2",
                  "connector": { "url": dup_b_url, "slug": null },
                  "required_tools": ["b_one"],
                  "binding_mode": "organization" }
            ]),
            "empty-tools skipped, sandbox dropped, unresolvable pins dropped, alias dedup'd"
        );
        // The dedup'd shape still validates — proves the suffixed slot `dup-2`
        // is a legal server alias, and pins the exact slot names + suffix.
        let reqs_a: Vec<fluidbox_core::capability::ConnectionRequirement> =
            serde_json::from_value(latest_a.connection_requirements.clone())
                .expect("agent A requirements deserialize");
        fluidbox_core::capability::validate_requirements(&reqs_a)
            .expect("dedup'd requirements (incl. slot 'dup-2') are valid");
        let slots_a: Vec<&str> = reqs_a.iter().map(|r| r.slot.as_str()).collect();
        assert_eq!(slots_a, ["dup", "dup-2"], "alias dedup order: dup, dup-2");

        // (d)+(e): agent A pinned no surviving sandbox-only bundle and both
        // unresolvable pins were dropped, so the copied pin list is empty.
        assert_eq!(
            latest_a.capability_bundles,
            serde_json::json!([]),
            "no surviving pins (mixed bundle + unresolvable pins all dropped)"
        );

        // (c)+repoint: agent B has its single requirement, and its subscription
        // was repointed to the converted revision (repoint count where
        // applicable; agent A had no subscription to repoint — d).
        assert_eq!(
            latest_b.connection_requirements,
            serde_json::json!([
                { "slot": "jira",
                  "connector": { "url": jira_url, "slug": null },
                  "required_tools": ["search"],
                  "binding_mode": "organization" }
            ]),
            "agent B's lone brokered server became one requirement"
        );
        assert_eq!(
            sub_b_after.pinned_revision_id,
            Some(latest_b.id),
            "agent B's subscription repointed to its converted revision"
        );
    }

    /// Migration 0013 appendix — per-source-revision conversion + keep-list
    /// preserving repoints (R1.1/R1.2). Covers: (i) a subscription pinned to an
    /// OLDER brokered revision gets a copy carrying THAT revision's model/prompt
    /// while the latest converts separately; (ii) a sandbox-only latest above a
    /// pinned brokered old revision converts the pinned source and — append-only
    /// being sacred (A2) — the sandbox latest is CLONED (never rewritten) as the
    /// new `latest`; (iii) a restrictive keep-list narrows the derived
    /// requirements; (iv) an empty keep-list ⇒ zero requirements; (v) idempotence;
    /// (A1) FLOATING subscriptions — a restrictive/empty keep-list floater is
    /// pinned to a tailored copy, a NULL keep-list floater keeps floating.
    #[tokio::test]
    async fn convert_legacy_bundles_per_source_revision_and_keep_lists() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);

        let gh_url = "https://mcp.github.test/mcp";
        let stripe_url = "https://mcp.stripe.test/mcp";
        let q_url = "https://mcp.q.test/mcp";

        let brok_def = |srv: &str, url: &str, tool: &str| {
            serde_json::json!({ "servers": [
                { "class": "brokered", "name": srv, "url": url, "tools": [
                    { "name": tool, "description": "d", "input_schema": {"type": "object"} } ] } ] })
        };
        let sand_def = |srv: &str| {
            serde_json::json!({ "servers": [
                { "class": "sandbox", "name": srv, "command": "node", "args": ["/x.mjs"], "tools": [
                    { "name": "t", "description": "d", "input_schema": {"type": "object"} } ] } ] })
        };
        let pin = |b: &CapabilityBundleRow| serde_json::json!({ "id": b.id, "name": b.name, "version": b.version });
        let policy = upsert_policy(
            &pool,
            scope,
            "psr-policy",
            "name: psr",
            &serde_json::json!({ "name": "psr" }),
        )
        .await
        .unwrap();
        let mk_rev = |agent_id: Uuid, model: &'static str, prompt: &'static str, pins: Value| {
            let pool = pool.clone();
            let pid = policy.id;
            async move {
                append_agent_revision(
                    &pool,
                    scope,
                    agent_id,
                    "claude-agent-sdk",
                    "img:test",
                    model,
                    Some(prompt),
                    pid,
                    &serde_json::json!({ "wall_clock_secs": 60 }),
                    None,
                    &pins,
                    &serde_json::json!([]),
                    None,
                )
                .await
                .unwrap()
            }
        };
        let mk_sub = |agent_id: Uuid, name: &'static str, rev: Uuid, keep: Option<Value>| {
            let pool = pool.clone();
            async move {
                create_trigger_subscription(
                    &pool,
                    scope,
                    agent_id,
                    name,
                    "api",
                    Some(rev),
                    Some("t"),
                    false,
                    false,
                    None,
                    "allow",
                    None,
                    None,
                    &serde_json::json!([]),
                    None,
                    1,
                    None,
                    None,
                    None,
                    None,
                    keep.as_ref(),
                )
                .await
                .unwrap()
            }
        };

        // ── Agent P: OLDER brokered rev1 (model p-old) + brokered-narrower latest
        // rev2 (model p-new); four subscriptions pinned to rev1 exercising NULL /
        // dedup / restrictive / empty keep-lists. ──
        let gh_b = create_capability_bundle(
            &pool,
            scope,
            "gh-bundle",
            None,
            &brok_def("github", gh_url, "get_pr"),
            "sha256:gh",
        )
        .await
        .unwrap();
        let stripe_b = create_capability_bundle(
            &pool,
            scope,
            "stripe-bundle",
            None,
            &brok_def("stripe", stripe_url, "charge"),
            "sha256:st",
        )
        .await
        .unwrap();
        let agent_p = create_agent(&pool, scope, "psr-agent-p", None)
            .await
            .unwrap();
        let p_rev1 = mk_rev(
            agent_p.id,
            "p-old",
            "old-prompt",
            serde_json::json!([pin(&gh_b), pin(&stripe_b)]),
        )
        .await;
        let p_rev2 = mk_rev(
            agent_p.id,
            "p-new",
            "new-prompt",
            serde_json::json!([pin(&gh_b)]),
        )
        .await;
        let sub_full = mk_sub(agent_p.id, "sub-full", p_rev1.id, None).await;
        let sub_full2 = mk_sub(agent_p.id, "sub-full2", p_rev1.id, None).await;
        let sub_gh = mk_sub(
            agent_p.id,
            "sub-gh",
            p_rev1.id,
            Some(serde_json::json!(["gh-bundle"])),
        )
        .await;
        let sub_empty = mk_sub(
            agent_p.id,
            "sub-empty",
            p_rev1.id,
            Some(serde_json::json!([])),
        )
        .await;

        // ── Agent Q: OLDER brokered rev1 (model q-old) + SANDBOX-ONLY latest rev2
        // (model q-new); one subscription pinned to rev1. ──
        let q_brok = create_capability_bundle(
            &pool,
            scope,
            "q-brok",
            None,
            &brok_def("qsrv", q_url, "q"),
            "sha256:qb",
        )
        .await
        .unwrap();
        let q_sand =
            create_capability_bundle(&pool, scope, "q-sand", None, &sand_def("qs"), "sha256:qs")
                .await
                .unwrap();
        let agent_q = create_agent(&pool, scope, "psr-agent-q", None)
            .await
            .unwrap();
        let q_rev1 = mk_rev(
            agent_q.id,
            "q-old",
            "q-old-prompt",
            serde_json::json!([pin(&q_brok)]),
        )
        .await;
        let q_rev2 = mk_rev(
            agent_q.id,
            "q-new",
            "q-new-prompt",
            serde_json::json!([pin(&q_sand)]),
        )
        .await;
        let sub_q = mk_sub(agent_q.id, "sub-q", q_rev1.id, None).await;

        // ── Agent R: brokered latest (gh + stripe) with FLOATING subscriptions
        // (pinned_revision_id NULL). A1: a floating sub whose NON-NULL keep-list
        // narrows the latest's brokered authority must be PINNED to a tailored
        // copy (the narrowing frozen); a NULL keep-list floater keeps floating. ──
        let agent_r = create_agent(&pool, scope, "psr-agent-r", None)
            .await
            .unwrap();
        let r_rev1 = mk_rev(
            agent_r.id,
            "r-latest",
            "r-prompt",
            serde_json::json!([pin(&gh_b), pin(&stripe_b)]),
        )
        .await;
        let mk_float = |agent_id: Uuid, name: &'static str, keep: Option<Value>| {
            let pool = pool.clone();
            async move {
                create_trigger_subscription(
                    &pool,
                    scope,
                    agent_id,
                    name,
                    "api",
                    None,
                    Some("t"),
                    false,
                    false,
                    None,
                    "allow",
                    None,
                    None,
                    &serde_json::json!([]),
                    None,
                    1,
                    None,
                    None,
                    None,
                    None,
                    keep.as_ref(),
                )
                .await
                .unwrap()
            }
        };
        let sub_float_gh = mk_float(
            agent_r.id,
            "float-gh",
            Some(serde_json::json!(["gh-bundle"])),
        )
        .await;
        let sub_float_empty =
            mk_float(agent_r.id, "float-empty", Some(serde_json::json!([]))).await;
        let sub_float_null = mk_float(agent_r.id, "float-null", None).await;

        // ── Convert, then re-convert for idempotence (v). RLS-BOUND and confined to
        // this org: the fixtures below are built across several statements, and an
        // unconfined conversion from a sibling test could otherwise repoint them
        // mid-build (or race this call for the next rev). ──
        convert_legacy_bundles_rls_bound(&url, Some(org.id)).await;

        let p_revs = list_revisions(&pool, scope, agent_p.id).await.unwrap();
        let p_latest = latest_revision(&pool, scope, agent_p.id)
            .await
            .unwrap()
            .unwrap();
        let q_revs = list_revisions(&pool, scope, agent_q.id).await.unwrap();
        let q_latest = latest_revision(&pool, scope, agent_q.id)
            .await
            .unwrap()
            .unwrap();
        let sub_full_a = get_trigger_subscription(&pool, scope, sub_full.id)
            .await
            .unwrap()
            .unwrap();
        let sub_full2_a = get_trigger_subscription(&pool, scope, sub_full2.id)
            .await
            .unwrap()
            .unwrap();
        let sub_gh_a = get_trigger_subscription(&pool, scope, sub_gh.id)
            .await
            .unwrap()
            .unwrap();
        let sub_empty_a = get_trigger_subscription(&pool, scope, sub_empty.id)
            .await
            .unwrap()
            .unwrap();
        let sub_q_a = get_trigger_subscription(&pool, scope, sub_q.id)
            .await
            .unwrap()
            .unwrap();
        let r_revs = list_revisions(&pool, scope, agent_r.id).await.unwrap();
        let r_latest = latest_revision(&pool, scope, agent_r.id)
            .await
            .unwrap()
            .unwrap();
        let sub_float_gh_a = get_trigger_subscription(&pool, scope, sub_float_gh.id)
            .await
            .unwrap()
            .unwrap();
        let sub_float_empty_a = get_trigger_subscription(&pool, scope, sub_float_empty.id)
            .await
            .unwrap()
            .unwrap();
        let sub_float_null_a = get_trigger_subscription(&pool, scope, sub_float_null.id)
            .await
            .unwrap()
            .unwrap();

        // Idempotence: a second run appends nothing and moves no pin.
        convert_legacy_bundles_rls_bound(&url, Some(org.id)).await;
        let p_revs2 = list_revisions(&pool, scope, agent_p.id).await.unwrap();
        let q_revs2 = list_revisions(&pool, scope, agent_q.id).await.unwrap();
        let r_revs2 = list_revisions(&pool, scope, agent_r.id).await.unwrap();
        let p_latest2 = latest_revision(&pool, scope, agent_p.id)
            .await
            .unwrap()
            .unwrap();
        let sub_full_b = get_trigger_subscription(&pool, scope, sub_full.id)
            .await
            .unwrap()
            .unwrap();

        // Snapshot the row a subscription now points at (by id) BEFORE cleanup.
        let rev_of = |revs: &[AgentRevisionRow], id: Option<Uuid>| {
            revs.iter().find(|r| Some(r.id) == id).cloned()
        };
        let full_copy = rev_of(&p_revs, sub_full_a.pinned_revision_id).unwrap();
        let gh_copy = rev_of(&p_revs, sub_gh_a.pinned_revision_id).unwrap();
        let empty_copy = rev_of(&p_revs, sub_empty_a.pinned_revision_id).unwrap();
        let q_copy = rev_of(&q_revs, sub_q_a.pinned_revision_id).unwrap();
        let float_gh_copy = rev_of(&r_revs, sub_float_gh_a.pinned_revision_id).unwrap();
        let float_empty_copy = rev_of(&r_revs, sub_float_empty_a.pinned_revision_id).unwrap();

        for stmt in [
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from capability_bundles where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org.id).execute(&pool).await.unwrap();
        }
        sqlx::query("delete from tenants where id = $1")
            .bind(org.id)
            .execute(&pool)
            .await
            .unwrap();

        let gh_req = serde_json::json!({ "slot": "github",
            "connector": { "url": gh_url, "slug": null },
            "required_tools": ["get_pr"], "binding_mode": "organization" });
        let stripe_req = serde_json::json!({ "slot": "stripe",
            "connector": { "url": stripe_url, "slug": null },
            "required_tools": ["charge"], "binding_mode": "organization" });
        let qsrv_req = serde_json::json!({ "slot": "qsrv",
            "connector": { "url": q_url, "slug": null },
            "required_tools": ["q"], "binding_mode": "organization" });

        // (i) the latest converts SEPARATELY with the NEW model + full (single) req;
        // the subscription copy carries the OLDER revision's model/prompt.
        assert_eq!(
            p_latest.model, "p-new",
            "latest is the converted NEW revision"
        );
        assert_ne!(
            p_latest.id, p_rev2.id,
            "the latest is the CONVERTED copy of rev2, not the original brokered rev2"
        );
        assert_eq!(p_latest.system_prompt.as_deref(), Some("new-prompt"));
        assert_eq!(
            p_latest.connection_requirements,
            serde_json::json!([gh_req]),
            "latest's full derivation keeps only github (rev2 pinned gh only)"
        );
        assert_eq!(
            full_copy.model, "p-old",
            "sub copy carries the OLD revision's model"
        );
        assert_eq!(full_copy.system_prompt.as_deref(), Some("old-prompt"));
        assert_eq!(
            full_copy.connection_requirements,
            serde_json::json!([gh_req, stripe_req]),
            "NULL keep-list ⇒ both brokered servers become requirements"
        );

        // dedup: two NULL-keep subs pinning the same old source share ONE copy.
        assert_eq!(
            sub_full_a.pinned_revision_id, sub_full2_a.pinned_revision_id,
            "subscriptions sharing (source, requirements) share one converted copy"
        );

        // (iii) restrictive keep-list ⇒ ONLY github; (iv) empty keep-list ⇒ none.
        assert_eq!(gh_copy.model, "p-old");
        assert_eq!(
            gh_copy.connection_requirements,
            serde_json::json!([gh_req]),
            "keep-list ['gh-bundle'] ⇒ ONLY github survives as a requirement"
        );
        assert_ne!(
            sub_gh_a.pinned_revision_id, sub_full_a.pinned_revision_id,
            "the narrowed sub gets its OWN copy, distinct from the full one"
        );
        assert_eq!(empty_copy.model, "p-old");
        assert_eq!(
            empty_copy.connection_requirements,
            serde_json::json!([]),
            "empty keep-list ⇒ zero requirements (removed authority not regained)"
        );

        // (ii) sandbox-only latest — APPEND-ONLY is sacred (A2). The ORIGINAL
        // rev2 is NEVER rewritten (keeps its rev + content); an exact CLONE is
        // APPENDED as the new `latest` so unpinned runs still resolve the
        // sandbox-only semantics. The pinned OLD brokered source still converts.
        let q_rev2_after = rev_of(&q_revs, Some(q_rev2.id)).unwrap();
        assert_eq!(
            q_rev2_after.rev, q_rev2.rev,
            "the ORIGINAL sandbox-only latest keeps its rev (never rewritten)"
        );
        assert_eq!(
            q_rev2_after.capability_bundles,
            serde_json::json!([pin(&q_sand)]),
            "the ORIGINAL sandbox-only latest keeps its content"
        );
        assert_ne!(
            q_latest.id, q_rev2.id,
            "the new latest is an APPENDED CLONE, not the rewritten original"
        );
        assert!(
            q_latest.rev > q_rev2_after.rev,
            "the clone is appended above the original"
        );
        assert_eq!(q_latest.model, "q-new");
        assert_eq!(
            q_latest.capability_bundles,
            serde_json::json!([pin(&q_sand)]),
            "the clone is content-identical to the sandbox-only latest"
        );
        assert_eq!(
            q_latest.connection_requirements,
            serde_json::json!([]),
            "the sandbox-only clone carries no brokered requirements"
        );
        assert_ne!(
            sub_q_a.pinned_revision_id,
            Some(q_rev1.id),
            "sub_q repointed off the legacy rev"
        );
        assert_ne!(sub_q_a.pinned_revision_id, Some(q_rev2.id));
        assert_eq!(
            q_copy.model, "q-old",
            "sub_q's copy carries the OLD revision model"
        );
        assert_eq!(
            q_copy.connection_requirements,
            serde_json::json!([qsrv_req]),
            "the pinned brokered source converted for the subscription"
        );

        // (v) idempotence: no second-run appends, no pin moved.
        assert_eq!(
            p_revs2.len(),
            p_revs.len(),
            "agent P: second run appends nothing"
        );
        assert_eq!(
            q_revs2.len(),
            q_revs.len(),
            "agent Q: second run appends nothing"
        );
        assert_eq!(
            p_latest2.id, p_latest.id,
            "agent P latest unchanged on re-run"
        );
        assert_eq!(
            sub_full_b.pinned_revision_id, sub_full_a.pinned_revision_id,
            "pin stable on re-run"
        );

        // (A1) FLOATING subscriptions.
        // The live latest is the FULL converted copy (both brokered → requirements).
        assert_ne!(
            r_latest.id, r_rev1.id,
            "agent R latest is the converted live copy, not the original brokered rev"
        );
        assert_eq!(
            r_latest.connection_requirements,
            serde_json::json!([gh_req, stripe_req]),
            "the live latest keeps BOTH brokered servers as requirements"
        );
        // A NULL keep-list floater keeps floating (no pin, still resolves latest).
        assert_eq!(
            sub_float_null_a.pinned_revision_id, None,
            "a NULL keep-list floater keeps floating (never pinned)"
        );
        // A restrictive keep-list floater is PINNED to a tailored copy — gh only.
        assert!(
            sub_float_gh_a.pinned_revision_id.is_some(),
            "a restrictive-keep-list floater is PINNED (its narrowing frozen)"
        );
        assert_eq!(
            float_gh_copy.connection_requirements,
            serde_json::json!([gh_req]),
            "float-gh keep-list ['gh-bundle'] ⇒ ONLY github survives as a requirement"
        );
        // An empty keep-list floater is PINNED to a zero-requirement copy.
        assert!(
            sub_float_empty_a.pinned_revision_id.is_some(),
            "an empty-keep-list floater is PINNED"
        );
        assert_eq!(
            float_empty_copy.connection_requirements,
            serde_json::json!([]),
            "float-empty keep-list [] ⇒ zero requirements (removed authority not regained)"
        );
        assert_eq!(
            r_revs2.len(),
            r_revs.len(),
            "agent R: second run appends nothing (idempotent)"
        );
    }

    /// Cross-tenant isolation (wave A): a session and its child rows created
    /// under tenant B are invisible to tenant A's scope. The tenant predicate
    /// now lives in SQL, so a cross-tenant id misses at the database — never
    /// via a Rust-side filter. Throwaway orgs; cleanup is children-first
    /// (tenant FKs are NO ACTION).
    #[tokio::test]
    async fn tenant_scope_isolates_sessions_and_children() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");

        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = identity::create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = identity::create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        // A full session fixture under B.
        let policy = upsert_policy(
            &pool,
            scope_b,
            "xt-policy",
            "name: xt",
            &serde_json::json!({"name":"xt"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();
        let rev = append_agent_revision(
            &pool,
            scope_b,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        let session = create_session(
            &pool,
            scope_b,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "xt",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        // Child rows under B's scope: an event, an artifact, usage, and a
        // human-visible (pending) approval.
        let redactor = Redactor::default();
        append_event(
            &pool,
            scope_b,
            redactor.scrub(EventEnvelope::new(
                session.id,
                Actor::System,
                EventBody::AgentMessage {
                    role: "assistant".into(),
                    text: "hi".into(),
                },
            )),
        )
        .await
        .unwrap();
        add_artifact(
            &pool,
            scope_b,
            session.id,
            "diff",
            "changes.patch",
            "x",
            "text/plain",
        )
        .await
        .unwrap();
        add_usage(
            &pool,
            scope_b,
            session.id,
            "m",
            1,
            1,
            0,
            0,
            Some(0.0),
            "test",
            None,
        )
        .await
        .unwrap();
        let (intent, _) = register_tool_intent(&pool, scope_b, session.id, "tc1", "Bash", "s", "d")
            .await
            .unwrap();
        promote_intent_to_pending(&pool, scope_b, intent.id, None, "once", "Bash", 600)
            .await
            .unwrap();

        // Negative — tenant A sees NONE of B's rows.
        let get_a = get_session(&pool, scope_a, session.id).await.unwrap();
        let events_a = events_after(&pool, scope_a, session.id, 0, 10)
            .await
            .unwrap();
        let approvals_a = session_approvals(&pool, scope_a, session.id).await.unwrap();
        let artifacts_a = list_artifacts(&pool, scope_a, session.id).await.unwrap();
        let usage_a = usage_totals(&pool, scope_a, session.id).await.unwrap();
        // Positive control — tenant B still reads its own session, approval, AND
        // every child family (events/artifacts/usage) under its OWNING scope, so
        // the negatives below prove a tenant boundary, not a globally-broken read.
        let get_b = get_session(&pool, scope_b, session.id).await.unwrap();
        let approvals_b = session_approvals(&pool, scope_b, session.id).await.unwrap();
        let events_b = events_after(&pool, scope_b, session.id, 0, 10)
            .await
            .unwrap();
        let artifacts_b = list_artifacts(&pool, scope_b, session.id).await.unwrap();
        let usage_b = usage_totals(&pool, scope_b, session.id).await.unwrap();

        // Cleanup, children-first, both orgs — BEFORE the assertions so a
        // failure never leaks throwaway fixtures.
        for stmt in [
            "delete from events where session_id in (select id from sessions where tenant_id = $1)",
            "delete from artifacts where session_id in (select id from sessions where tenant_id = $1)",
            "delete from approvals where session_id in (select id from sessions where tenant_id = $1)",
            "delete from usage_entries where session_id in (select id from sessions where tenant_id = $1)",
            "delete from api_tokens where session_id in (select id from sessions where tenant_id = $1)",
            "delete from session_finalizations where session_id in (select id from sessions where tenant_id = $1)",
            "delete from sessions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            sqlx::query(stmt)
                .bind(org_b.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(get_a.is_none(), "tenant A must not read B's session");
        assert!(events_a.is_empty(), "tenant A must see none of B's events");
        assert!(
            approvals_a.is_empty(),
            "tenant A must see none of B's approvals"
        );
        assert!(
            artifacts_a.is_empty(),
            "tenant A must see none of B's artifacts"
        );
        assert_eq!(
            usage_a.requests, 0,
            "tenant A totals zero usage for B's session"
        );
        assert!(get_b.is_some(), "tenant B still reads its own session");
        assert_eq!(
            approvals_b.len(),
            1,
            "tenant B sees its own pending approval"
        );
        assert_eq!(events_b.len(), 1, "tenant B reads its own event");
        assert_eq!(artifacts_b.len(), 1, "tenant B reads its own artifact");
        assert_eq!(usage_b.requests, 1, "tenant B totals its own usage");
    }

    /// Cross-tenant isolation for AGENTS: an agent created under B is invisible
    /// to A's scope at the database. Throwaway orgs; cleanup children-first
    /// BEFORE the asserts so a failure never leaks fixtures.
    #[tokio::test]
    async fn tenant_scope_isolates_agents() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();

        let read_a = get_agent(&pool, scope_a, agent.id).await.unwrap();
        let read_b = get_agent(&pool, scope_b, agent.id).await.unwrap();

        // Cleanup BEFORE the assertions, both orgs (tenant FKs are NO ACTION).
        sqlx::query("delete from agents where tenant_id = $1")
            .bind(org_b.id)
            .execute(&pool)
            .await
            .unwrap();
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(read_a.is_none(), "tenant A must not read B's agent");
        assert!(read_b.is_some(), "tenant B reads its own agent");
    }

    /// Cross-tenant isolation for POLICIES.
    #[tokio::test]
    async fn tenant_scope_isolates_policies() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let policy = upsert_policy(
            &pool,
            scope_b,
            "xt-policy",
            "name: xt",
            &serde_json::json!({"name":"xt"}),
        )
        .await
        .unwrap();

        let read_a = get_policy(&pool, scope_a, policy.id).await.unwrap();
        let read_b = get_policy(&pool, scope_b, policy.id).await.unwrap();

        sqlx::query("delete from policies where tenant_id = $1")
            .bind(org_b.id)
            .execute(&pool)
            .await
            .unwrap();
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(read_a.is_none(), "tenant A must not read B's policy");
        assert!(read_b.is_some(), "tenant B reads its own policy");
    }

    /// Cross-tenant isolation for CONNECTIONS: neither the row nor the sealed
    /// credential is reachable across the tenant boundary.
    #[tokio::test]
    async fn tenant_scope_isolates_connections() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let conn = create_connection(
            &pool,
            scope_b,
            "mcp_http",
            "acct",
            "disp",
            Some(&[1, 2, 3]),
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({"base_url":"https://x"}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        let get_a = get_connection(&pool, scope_a, conn.id).await.unwrap();
        let cred_a = connection_credential_sealed(&pool, scope_a, conn.id)
            .await
            .unwrap();
        let get_b = get_connection(&pool, scope_b, conn.id).await.unwrap();
        let cred_b = connection_credential_sealed(&pool, scope_b, conn.id)
            .await
            .unwrap();

        sqlx::query("delete from integration_connections where tenant_id = $1")
            .bind(org_b.id)
            .execute(&pool)
            .await
            .unwrap();
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(get_a.is_none(), "tenant A must not read B's connection");
        assert!(
            cred_a.is_none(),
            "tenant A must not read B's sealed credential"
        );
        assert!(get_b.is_some(), "tenant B reads its own connection");
        assert!(cred_b.is_some(), "tenant B reads its own sealed credential");
    }

    /// Cross-tenant isolation for TRIGGER SUBSCRIPTIONS.
    #[tokio::test]
    async fn tenant_scope_isolates_subscriptions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope_b,
            agent.id,
            "xt-sub",
            "api",
            None,
            Some("do {{x}}"),
            true,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let read_a = get_trigger_subscription(&pool, scope_a, sub.id)
            .await
            .unwrap();
        let read_b = get_trigger_subscription(&pool, scope_b, sub.id)
            .await
            .unwrap();

        // Children-first: subscriptions before agents.
        for stmt in [
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agents where tenant_id = $1",
        ] {
            sqlx::query(stmt)
                .bind(org_b.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(read_a.is_none(), "tenant A must not read B's subscription");
        assert!(read_b.is_some(), "tenant B reads its own subscription");
    }

    /// Cross-tenant isolation for SCHEDULES (looked up via their subscription).
    #[tokio::test]
    async fn tenant_scope_isolates_schedules() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope_b,
            agent.id,
            "xt-sub",
            "schedule",
            None,
            Some("do {{x}}"),
            true,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        create_schedule(
            &pool,
            scope_b,
            sub.id,
            "*/5 * * * * *",
            "UTC",
            chrono::Utc::now(),
            "skip",
        )
        .await
        .unwrap();

        let read_a = schedule_for_subscription(&pool, scope_a, sub.id)
            .await
            .unwrap();
        let read_b = schedule_for_subscription(&pool, scope_b, sub.id)
            .await
            .unwrap();

        // Children-first: schedules (via subscription) → subscriptions → agents.
        for stmt in [
            "delete from schedules where subscription_id in (select id from trigger_subscriptions where tenant_id = $1)",
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agents where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org_b.id).execute(&pool).await.unwrap();
        }
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(read_a.is_none(), "tenant A must not read B's schedule");
        assert!(read_b.is_some(), "tenant B reads its own schedule");
    }

    /// Cross-tenant isolation for EXTERNAL RESULTS (§17 #3 stable identity).
    #[tokio::test]
    async fn tenant_scope_isolates_external_results() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org_a = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let org_b = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let agent = create_agent(&pool, scope_b, "xt-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope_b,
            agent.id,
            "xt-sub",
            "api",
            None,
            Some("do {{x}}"),
            true,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        upsert_external_result(
            &pool,
            scope_b,
            sub.id,
            "github_pr_comment",
            "acme/x#1",
            "999",
            Some("https://u"),
        )
        .await
        .unwrap();

        let read_a = get_external_result(&pool, scope_a, sub.id, "github_pr_comment", "acme/x#1")
            .await
            .unwrap();
        let read_b = get_external_result(&pool, scope_b, sub.id, "github_pr_comment", "acme/x#1")
            .await
            .unwrap();

        // Children-first: external_results (via subscription) → subscriptions → agents.
        for stmt in [
            "delete from external_results where subscription_id in (select id from trigger_subscriptions where tenant_id = $1)",
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agents where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org_b.id).execute(&pool).await.unwrap();
        }
        for id in [org_a.id, org_b.id] {
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert!(
            read_a.is_none(),
            "tenant A must not read B's external result"
        );
        assert!(read_b.is_some(), "tenant B reads its own external result");
    }

    // ─── Phase C (#31): ownership, snapshots, bindings, catalog scoping ──────

    /// Seed a user + active membership under `scope` (each with its own staged
    /// idp config, so callers need not thread one). Returns the user id — the
    /// FK target for a connection's `owner_user_id`/`created_by_user_id`.
    async fn seed_member(pool: &PgPool, scope: TenantScope, subject: &str) -> Uuid {
        let cfg_id = Uuid::now_v7();
        sqlx::query(
            "insert into org_idp_configs
               (id, tenant_id, generation, issuer, client_id, claim_mappings, status)
             values ($1, $2,
                     coalesce((select max(generation) from org_idp_configs where tenant_id = $2), 0) + 1,
                     $3, 'client-test', '{}'::jsonb, 'staged')",
        )
        .bind(cfg_id)
        .bind(scope.tenant_id())
        .bind(format!("https://idp.test/{subject}"))
        .execute(pool)
        .await
        .unwrap();
        let user_id = Uuid::now_v7();
        sqlx::query(
            "insert into users
               (id, tenant_id, idp_config_id, subject, email, email_normalized, email_verified, status)
             values ($1, $2, $3, $4, $5, $5, true, 'active')",
        )
        .bind(user_id)
        .bind(scope.tenant_id())
        .bind(cfg_id)
        .bind(subject)
        .bind(format!("{subject}@example.com"))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "insert into org_memberships (id, tenant_id, user_id, roles, status)
             values ($1, $2, $3, '{member}', 'active')",
        )
        .bind(Uuid::now_v7())
        .bind(scope.tenant_id())
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
        user_id
    }

    async fn cleanup_orgs(pool: &PgPool, stmts: &[&'static str], tenants: &[Uuid]) {
        for id in tenants {
            for &stmt in stmts {
                sqlx::query(stmt).bind(id).execute(pool).await.unwrap();
            }
            sqlx::query("delete from tenants where id = $1")
                .bind(id)
                .execute(pool)
                .await
                .unwrap();
        }
    }

    /// Owner-shape CHECK, ownership visibility lens, and generation bump.
    #[tokio::test]
    async fn phase_c_connection_ownership_and_visibility() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);
        let alice = seed_member(&pool, scope, "alice").await;
        let bob = seed_member(&pool, scope, "bob").await;

        // owner-shape CHECK: owner_type='user' with a NULL owner_user_id is
        // rejected by the DB (a half-populated owner is fail-closed).
        let bad_owner = sqlx::query(
            "insert into integration_connections
               (id, tenant_id, provider, external_account_id, display_name, owner_type)
             values ($1, $2, 'mcp_http', 'x', 'bad', 'user')",
        )
        .bind(Uuid::now_v7())
        .bind(org.id)
        .execute(&pool)
        .await;

        let org_conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct-org",
            "Org conn",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        let alice_conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct-alice",
            "Alice personal",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::User(alice),
            Some(alice),
        )
        .await
        .unwrap();

        // bob's lens sees the org connection but NOT alice's personal one.
        let bob_list = list_connections_visible(&pool, scope, ConnectionViewer::User(bob))
            .await
            .unwrap();
        let all_list = list_connections_visible(&pool, scope, ConnectionViewer::All)
            .await
            .unwrap();
        let bob_sees_alice =
            get_connection_visible(&pool, scope, alice_conn.id, ConnectionViewer::User(bob))
                .await
                .unwrap();
        let alice_sees_alice =
            get_connection_visible(&pool, scope, alice_conn.id, ConnectionViewer::User(alice))
                .await
                .unwrap();
        let bumped = bump_connection_generation(&pool, scope, org_conn.id)
            .await
            .unwrap();

        cleanup_orgs(
            &pool,
            &[
                "delete from integration_connections where tenant_id = $1",
                "delete from org_memberships where tenant_id = $1",
                "delete from users where tenant_id = $1",
                "delete from org_idp_configs where tenant_id = $1",
            ],
            &[org.id],
        )
        .await;

        assert!(
            bad_owner.is_err(),
            "user owner without owner_user_id rejected"
        );
        assert_eq!(org_conn.owner_type, "organization");
        assert_eq!(org_conn.authorization_generation, 1);
        assert_eq!(alice_conn.owner_type, "user");
        assert_eq!(alice_conn.owner_user_id, Some(alice));
        let bob_ids: Vec<Uuid> = bob_list.iter().map(|c| c.id).collect();
        assert!(
            bob_ids.contains(&org_conn.id),
            "bob sees the org connection"
        );
        assert!(
            !bob_ids.contains(&alice_conn.id),
            "bob must not see alice's personal connection"
        );
        assert_eq!(all_list.len(), 2, "All lens sees both connections");
        assert!(
            bob_sees_alice.is_none(),
            "bob cannot read alice's personal row"
        );
        assert!(alice_sees_alice.is_some(), "alice reads her own connection");
        assert_eq!(bumped, Some(2), "generation bumps 1 → 2");
    }

    /// Snapshots auto-increment per connection, are append-only, and are
    /// tenant-scoped.
    #[tokio::test]
    async fn phase_c_tool_snapshots_versioned_and_scoped() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = identity::create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = identity::create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let conn = create_connection(
            &pool,
            scope_a,
            "mcp_http",
            "acct-snap",
            "Snap conn",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        let s1 = insert_connection_tool_snapshot(
            &pool,
            scope_a,
            conn.id,
            1,
            "2025-06-18",
            &serde_json::json!([{"name": "t1"}]),
            "digest-1",
        )
        .await
        .unwrap();
        let s2 = insert_connection_tool_snapshot(
            &pool,
            scope_a,
            conn.id,
            1,
            "2025-06-18",
            &serde_json::json!([{"name": "t2"}]),
            "digest-2",
        )
        .await
        .unwrap();
        let latest = latest_connection_tool_snapshot(&pool, scope_a, conn.id)
            .await
            .unwrap();
        let listed = list_connection_tool_snapshots(&pool, scope_a, conn.id)
            .await
            .unwrap();
        let v1 = get_connection_tool_snapshot(&pool, scope_a, conn.id, 1)
            .await
            .unwrap();
        // Append-only: a duplicate (tenant, connection, version) is rejected.
        let dup = sqlx::query(
            "insert into connection_tool_snapshots
               (id, tenant_id, connection_id, snapshot_version, authorization_generation,
                protocol_version, tools_json, tools_digest)
             values ($1, $2, $3, 2, 1, 'p', '[]'::jsonb, 'd')",
        )
        .bind(Uuid::now_v7())
        .bind(org_a.id)
        .bind(conn.id)
        .execute(&pool)
        .await;
        // Cross-tenant: B cannot read A's snapshots.
        let latest_b = latest_connection_tool_snapshot(&pool, scope_b, conn.id)
            .await
            .unwrap();
        let get_b = get_connection_tool_snapshot(&pool, scope_b, conn.id, 1)
            .await
            .unwrap();

        cleanup_orgs(
            &pool,
            &[
                "delete from connection_tool_snapshots where tenant_id = $1",
                "delete from integration_connections where tenant_id = $1",
            ],
            &[org_a.id, org_b.id],
        )
        .await;

        assert_eq!(s1.snapshot_version, 1, "first snapshot is version 1");
        assert_eq!(
            s2.snapshot_version, 2,
            "version auto-increments per connection"
        );
        assert_eq!(latest.unwrap().snapshot_version, 2);
        assert_eq!(listed.len(), 2, "list returns every version, newest first");
        assert_eq!(listed[0].snapshot_version, 2);
        assert_eq!(v1.unwrap().tools_digest, "digest-1");
        assert!(
            dup.is_err(),
            "duplicate (tenant, connection, version) rejected"
        );
        assert!(latest_b.is_none(), "B cannot read A's snapshot (latest)");
        assert!(get_b.is_none(), "B cannot read A's snapshot (by version)");
    }

    /// A snapshot taken after a re-consent records the BUMPED authorization
    /// generation (design :294-296, :306) — the pin a run binding froze under
    /// the older generation stays distinguishable, so the broker recheck can
    /// fail it closed. (The live-MCP photograph itself is CI-e2e territory; this
    /// exercises the generation stamping the photograph relies on.)
    #[tokio::test]
    async fn phase_c_snapshot_records_bumped_generation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);

        let conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct-gen",
            "Gen conn",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        // First photograph stamps generation 1.
        let s1 = insert_connection_tool_snapshot(
            &pool,
            scope,
            conn.id,
            conn.authorization_generation,
            "2025-06-18",
            &serde_json::json!([{ "name": "t1" }]),
            "digest-1",
        )
        .await
        .unwrap();

        // Re-consent bumps the generation; a fresh photograph stamps the bumped
        // value (read off the connection's CURRENT generation, as the server does).
        let bumped = bump_connection_generation(&pool, scope, conn.id)
            .await
            .unwrap()
            .expect("connection in scope");
        let conn2 = get_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        let s2 = insert_connection_tool_snapshot(
            &pool,
            scope,
            conn.id,
            conn2.authorization_generation,
            "2025-06-18",
            &serde_json::json!([{ "name": "t2" }]),
            "digest-2",
        )
        .await
        .unwrap();

        cleanup_orgs(
            &pool,
            &[
                "delete from connection_tool_snapshots where tenant_id = $1",
                "delete from integration_connections where tenant_id = $1",
            ],
            &[org.id],
        )
        .await;

        assert_eq!(s1.authorization_generation, 1, "first snapshot is gen 1");
        assert_eq!(bumped, 2, "bump takes the connection to generation 2");
        assert_eq!(conn2.authorization_generation, 2);
        assert_eq!(
            s2.authorization_generation, 2,
            "snapshot records the BUMPED generation"
        );
        assert_eq!(
            s2.snapshot_version, 2,
            "snapshot version keeps auto-incrementing across a generation bump"
        );
    }

    /// Bindings commit atomically with the session, are tenant-scoped, and the
    /// authority/mcp CHECK constraints reject malformed shapes.
    #[tokio::test]
    async fn phase_c_run_resource_bindings_atomic_and_checks() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = identity::create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = identity::create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let mk_session = |scope: TenantScope, bindings: Vec<NewRunResourceBinding>| {
            let pool = pool.clone();
            async move {
                let policy = upsert_policy(
                    &pool,
                    scope,
                    "rb-policy",
                    "name: rb",
                    &serde_json::json!({"name":"rb"}),
                )
                .await
                .unwrap();
                let agent = create_agent(&pool, scope, "rb-agent", None).await.unwrap();
                let rev = append_agent_revision(
                    &pool,
                    scope,
                    agent.id,
                    "claude-agent-sdk",
                    "img:test",
                    "claude-haiku-4-5",
                    None,
                    policy.id,
                    &serde_json::json!({}),
                    None,
                    &serde_json::json!([]),
                    &serde_json::json!([]),
                    None,
                )
                .await
                .unwrap();
                create_session(
                    &pool,
                    scope,
                    agent.id,
                    rev.id,
                    "supervised",
                    "trusted",
                    "rb",
                    &serde_json::json!({"kind":"none"}),
                    &serde_json::json!({}),
                    &serde_json::json!({}),
                    None,
                    None,
                    None,
                    None,
                    None,
                    &bindings,
                    None,
                )
                .await
                .unwrap()
            }
        };

        let conn = create_connection(
            &pool,
            scope_a,
            "mcp_http",
            "acct-rb",
            "RB conn",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        let snap = insert_connection_tool_snapshot(
            &pool,
            scope_a,
            conn.id,
            conn.authorization_generation,
            "2025-06-18",
            &serde_json::json!([{"name": "t1"}]),
            "digest-1",
        )
        .await
        .unwrap();

        let mcp_binding = NewRunResourceBinding {
            id: Uuid::now_v7(),
            requirement_slot: "primary".into(),
            slot_kind: "mcp".into(),
            authority_kind: "connection".into(),
            connection_id: Some(conn.id),
            subscription_id: None,
            authority_generation: Some(conn.authorization_generation),
            connection_owner_type: Some(conn.owner_type.clone()),
            connection_owner_user_id: conn.owner_user_id,
            snapshot_version: Some(snap.snapshot_version),
            effective_tools_json: Some(serde_json::json!([{"name": "t1"}])),
            effective_tools_digest: Some("digest-1".into()),
            resource_scope: serde_json::json!({}),
            resolved_by_principal_kind: "operator".into(),
            resolved_by_principal_id: None,
            binding_mode: "organization".into(),
        };
        let session = mk_session(scope_a, vec![mcp_binding.clone()]).await;

        // Atomic: the binding is present under A immediately after the session.
        let a_bindings = session_resource_bindings(&pool, scope_a, session.id)
            .await
            .unwrap();
        let by_id = get_run_resource_binding(&pool, scope_a, mcp_binding.id)
            .await
            .unwrap();
        let found = find_session_binding(&pool, scope_a, session.id, "mcp", "primary")
            .await
            .unwrap();
        // Cross-tenant: B cannot read A's binding.
        let b_bindings = session_resource_bindings(&pool, scope_b, session.id)
            .await
            .unwrap();
        let by_id_b = get_run_resource_binding(&pool, scope_b, mcp_binding.id)
            .await
            .unwrap();

        // FK negative: a binding for another tenant's session is refused.
        let session_b = mk_session(scope_b, vec![]).await;
        let none_binding = |slot_kind: &str, authority_kind: &str| NewRunResourceBinding {
            id: Uuid::now_v7(),
            requirement_slot: "x".into(),
            slot_kind: slot_kind.into(),
            authority_kind: authority_kind.into(),
            connection_id: None,
            subscription_id: None,
            authority_generation: None,
            connection_owner_type: None,
            connection_owner_user_id: None,
            snapshot_version: None,
            effective_tools_json: None,
            effective_tools_digest: None,
            resource_scope: serde_json::json!({}),
            resolved_by_principal_kind: "system".into(),
            resolved_by_principal_id: None,
            binding_mode: "organization".into(),
        };
        let fk_bad = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session_b.id,
            &[none_binding("workspace_fetch", "none")],
        )
        .await;

        // Shape CHECK negatives (each on a valid in-scope session):
        // (a) mcp slot missing the snapshot fields. A FRESH requirement_slot is
        // mandatory: reusing "primary" would collide with mcp_binding on the
        // unique (tenant_id, session_id, slot_kind, requirement_slot) key, so the
        // insert would fail even if the mcp-shape CHECK regressed. With its own
        // slot the ONLY reason it can fail is run_resource_bindings_mcp_shape.
        let mut bad_mcp = mcp_binding.clone();
        bad_mcp.id = Uuid::now_v7();
        bad_mcp.requirement_slot = "shape-a".into();
        bad_mcp.snapshot_version = None;
        bad_mcp.effective_tools_json = None;
        bad_mcp.effective_tools_digest = None;
        let shape_a = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session.id,
            &[bad_mcp],
        )
        .await;
        // (b) connection authority missing its generation.
        let mut bad_gen = mcp_binding.clone();
        bad_gen.id = Uuid::now_v7();
        bad_gen.requirement_slot = "wf".into();
        bad_gen.slot_kind = "workspace_fetch".into();
        bad_gen.snapshot_version = None;
        bad_gen.effective_tools_json = None;
        bad_gen.effective_tools_digest = None;
        bad_gen.authority_generation = None;
        let shape_b = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session.id,
            &[bad_gen],
        )
        .await;
        // (c) none authority carrying a connection_id.
        let mut bad_none = none_binding("workspace_fetch", "none");
        bad_none.connection_id = Some(conn.id);
        let shape_c = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session.id,
            &[bad_none],
        )
        .await;
        // R1.5 FK negative: an mcp binding naming a NONEXISTENT snapshot version is
        // refused by the composite (tenant, connection, snapshot_version) FK.
        let mut bad_snap = mcp_binding.clone();
        bad_snap.id = Uuid::now_v7();
        bad_snap.requirement_slot = "fk-snap".into();
        bad_snap.snapshot_version = Some(999);
        let fk_snapshot = insert_run_resource_bindings(
            &mut pool.acquire().await.unwrap(),
            scope_a,
            session.id,
            &[bad_snap],
        )
        .await;

        cleanup_orgs(
            &pool,
            &[
                "delete from run_resource_bindings where tenant_id = $1",
                "delete from sessions where tenant_id = $1",
                "delete from connection_tool_snapshots where tenant_id = $1",
                "delete from integration_connections where tenant_id = $1",
                "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
                "delete from agents where tenant_id = $1",
                "delete from policies where tenant_id = $1",
            ],
            &[org_a.id, org_b.id],
        )
        .await;

        assert_eq!(
            a_bindings.len(),
            1,
            "the binding committed with the session"
        );
        assert_eq!(a_bindings[0].id, mcp_binding.id);
        assert_eq!(a_bindings[0].authority_kind, "connection");
        assert!(by_id.is_some(), "binding readable by id in scope");
        assert!(found.is_some(), "binding found by (slot_kind, slot)");
        assert!(b_bindings.is_empty(), "B cannot list A's bindings");
        assert!(by_id_b.is_none(), "B cannot read A's binding by id");
        assert!(
            fk_bad.is_err(),
            "binding for another tenant's session refused"
        );
        assert!(
            shape_a.is_err(),
            "mcp slot without snapshot fields rejected"
        );
        assert!(
            shape_b.is_err(),
            "connection authority without generation rejected"
        );
        assert!(
            shape_c.is_err(),
            "none authority with a connection_id rejected"
        );
        assert!(
            fk_snapshot.is_err(),
            "mcp binding naming a nonexistent snapshot version rejected (R1.5 FK)"
        );
    }

    /// R1.8: `create_session` writes the session, its resource bindings, AND its
    /// idempotency-claim bind in ONE transaction — a CHECK-violating binding must
    /// roll ALL of it back: no session, no binding, and the claim stays unbound.
    #[tokio::test]
    async fn create_session_rolls_back_on_check_violating_binding() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = identity::create_org(&pool, &slug, None).await.unwrap();
        let scope = TenantScope::assume(org.id);

        let policy = upsert_policy(
            &pool,
            scope,
            "rb2",
            "name: rb2",
            &serde_json::json!({"name":"rb2"}),
        )
        .await
        .unwrap();
        let agent = create_agent(&pool, scope, "rb2-agent", None).await.unwrap();
        let rev = append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            "rb2-sub",
            "api",
            Some(rev.id),
            Some("t"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let InvocationClaim::Claimed { invocation_id } =
            claim_invocation(&pool, scope, sub.id, "idem-rollback", "digest")
                .await
                .unwrap()
        else {
            panic!("expected a fresh claim");
        };

        // authority_kind 'none' but carrying an authority_generation → violates
        // run_resource_bindings_authority_shape (no FK involved: all ids null).
        let bad = NewRunResourceBinding {
            id: Uuid::now_v7(),
            requirement_slot: "x".into(),
            slot_kind: "workspace_fetch".into(),
            authority_kind: "none".into(),
            connection_id: None,
            subscription_id: None,
            authority_generation: Some(1),
            connection_owner_type: None,
            connection_owner_user_id: None,
            snapshot_version: None,
            effective_tools_json: None,
            effective_tools_digest: None,
            resource_scope: serde_json::json!({}),
            resolved_by_principal_kind: "system".into(),
            resolved_by_principal_id: None,
            binding_mode: "organization".into(),
        };
        let result = create_session(
            &pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "rollback",
            &serde_json::json!({"kind":"none"}),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            None,
            None,
            Some(invocation_id),
            None,
            &[bad],
            None,
        )
        .await;

        let sessions: i64 = sqlx::query_scalar(
            "select count(*) from sessions where tenant_id = $1 and agent_id = $2",
        )
        .bind(org.id)
        .bind(agent.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let bindings: i64 =
            sqlx::query_scalar("select count(*) from run_resource_bindings where tenant_id = $1")
                .bind(org.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let claim_session: Option<Uuid> =
            sqlx::query_scalar("select session_id from trigger_invocations where id = $1")
                .bind(invocation_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        for stmt in [
            "delete from trigger_invocations where subscription_id in (select id from trigger_subscriptions where tenant_id = $1)",
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from run_resource_bindings where tenant_id = $1",
            "delete from sessions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            sqlx::query(stmt).bind(org.id).execute(&pool).await.unwrap();
        }
        sqlx::query("delete from tenants where id = $1")
            .bind(org.id)
            .execute(&pool)
            .await
            .unwrap();

        assert!(
            result.is_err(),
            "create_session must fail on a CHECK-violating binding"
        );
        assert_eq!(sessions, 0, "no session row committed");
        assert_eq!(bindings, 0, "no binding row committed");
        assert_eq!(claim_session, None, "the idempotency claim stays unbound");
    }

    /// Custom catalog entries land tenant-scoped, are invisible to another org,
    /// and cannot mask a global slug.
    #[tokio::test]
    async fn phase_c_catalog_custom_entries_tenant_scoped() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let slug_a = format!("t-{}", Uuid::now_v7().simple());
        let slug_b = format!("t-{}", Uuid::now_v7().simple());
        let org_a = identity::create_org(&pool, &slug_a, None).await.unwrap();
        let org_b = identity::create_org(&pool, &slug_b, None).await.unwrap();
        let scope_a = TenantScope::assume(org_a.id);
        let scope_b = TenantScope::assume(org_b.id);

        let entry_slug = format!("xt-cat-{}", Uuid::now_v7().simple());
        let created = create_catalog_entry(
            &pool,
            scope_a,
            &entry_slug,
            "Tenant custom",
            None,
            None,
            &serde_json::json!([]),
            Some("https://mcp.example.test/mcp"),
            "streamable_http",
            "none",
            &serde_json::json!({}),
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();

        let a_sees = get_catalog_by_slug(&pool, scope_a, &entry_slug)
            .await
            .unwrap();
        let b_sees = get_catalog_by_slug(&pool, scope_b, &entry_slug)
            .await
            .unwrap();
        let a_list = list_catalog(&pool, scope_a).await.unwrap();
        let b_list = list_catalog(&pool, scope_b).await.unwrap();
        // A custom slug colliding with a GLOBAL seed ('github') is refused.
        let collision = create_catalog_entry(
            &pool,
            scope_a,
            "github",
            "Shadow",
            None,
            None,
            &serde_json::json!([]),
            Some("https://evil.example.test/mcp"),
            "streamable_http",
            "none",
            &serde_json::json!({}),
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();

        cleanup_orgs(
            &pool,
            &["delete from connector_catalog where tenant_id = $1"],
            &[org_a.id, org_b.id],
        )
        .await;

        let created = created.expect("custom entry lands");
        assert_eq!(created.tenant_id, Some(org_a.id));
        assert!(a_sees.is_some(), "A sees its own custom entry");
        assert!(b_sees.is_none(), "B cannot see A's custom entry");
        assert!(
            a_list.iter().any(|c| c.slug == entry_slug),
            "A's list includes its custom entry"
        );
        assert!(
            !b_list.iter().any(|c| c.slug == entry_slug),
            "B's list excludes A's custom entry"
        );
        assert!(collision.is_none(), "a global-slug collision is refused");
    }

    // ─── Phase D envelope sealing (#32) ─────────────────────────────────────

    async fn new_dek_org(pool: &PgPool) -> TenantScope {
        let slug = format!("t-{}", Uuid::now_v7().simple());
        let org = crate::identity::create_org(pool, &slug, None)
            .await
            .unwrap();
        TenantScope::assume(org.id)
    }

    // Children-first cleanup (tenant FKs are NO ACTION): tenant_llm_keys +
    // tenant_deks + integration_connections before the tenant row.
    async fn cleanup_dek_tenant(pool: &PgPool, tenant: Uuid) {
        for stmt in [
            "delete from tenant_llm_keys where tenant_id = $1",
            "delete from tenant_deks where tenant_id = $1",
            "delete from integration_connections where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(stmt).bind(tenant).execute(pool).await.unwrap();
        }
    }

    #[tokio::test]
    async fn tenant_dek_get_insert_latest() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = new_dek_org(&pool).await;
        let tenant = scope.tenant_id();

        assert!(get_tenant_dek(&pool, tenant, 1).await.unwrap().is_none());
        assert!(latest_tenant_dek(&pool, tenant).await.unwrap().is_none());

        insert_tenant_dek(&pool, tenant, 1, "static:abc", b"wrapped-dek-1")
            .await
            .unwrap();
        let row = get_tenant_dek(&pool, tenant, 1)
            .await
            .unwrap()
            .expect("row");
        assert_eq!(row.version, 1);
        assert_eq!(row.kek_id, "static:abc");
        assert_eq!(row.wrapped_dek, b"wrapped-dek-1");
        assert!(row.retired_at.is_none());
        assert_eq!(
            latest_tenant_dek(&pool, tenant)
                .await
                .unwrap()
                .unwrap()
                .version,
            1
        );
        // A version that was never minted is None (open must fail closed on it).
        assert!(get_tenant_dek(&pool, tenant, 2).await.unwrap().is_none());

        cleanup_dek_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn tenant_dek_insert_race_one_row_wins() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = new_dek_org(&pool).await;
        let tenant = scope.tenant_id();

        // Concurrent first-mints for (tenant, 1) with DIFFERENT wrapped bytes:
        // `on conflict do nothing` means exactly ONE row lands, and every racer
        // that re-reads sees the SAME winner (kms::dek_for_seal relies on this to
        // converge concurrent first-seals on one DEK).
        let mut handles = vec![];
        for i in 0..6u8 {
            let p = pool.clone();
            handles.push(tokio::spawn(async move {
                insert_tenant_dek(&p, tenant, 1, "static:race", &[i; 16])
                    .await
                    .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let (n,): (i64,) =
            sqlx::query_as("select count(*) from tenant_deks where tenant_id = $1 and version = 1")
                .bind(tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(n, 1, "exactly one DEK row survives the race");
        let winner = get_tenant_dek(&pool, tenant, 1)
            .await
            .unwrap()
            .unwrap()
            .wrapped_dek;
        assert_eq!(
            get_tenant_dek(&pool, tenant, 1)
                .await
                .unwrap()
                .unwrap()
                .wrapped_dek,
            winner,
            "re-reads are stable — all racers unwrap the same DEK"
        );

        cleanup_dek_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn sealed_column_key_version_roundtrips_and_counts() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = new_dek_org(&pool).await;
        let tenant = scope.tenant_id();

        // A v2-marked credential + webhook secret round-trip their key_version.
        let v2 = create_connection(
            &pool,
            scope,
            "github",
            "kv-acct-v2",
            "kv-conn-v2",
            Some(b"env-cred"),
            2,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            Some(b"env-webhook"),
            2,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            connection_credential_sealed(&pool, scope, v2.id)
                .await
                .unwrap()
                .unwrap(),
            (b"env-cred".to_vec(), 2)
        );
        assert_eq!(
            connection_webhook_secret_sealed(&pool, scope, v2.id)
                .await
                .unwrap()
                .unwrap(),
            (b"env-webhook".to_vec(), 2)
        );

        // A legacy (v1) credential defaults its companion to 1.
        let v1 = create_connection(
            &pool,
            scope,
            "github",
            "kv-acct-v1",
            "kv-conn-v1",
            Some(b"legacy-cred"),
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({}),
            None,
            1,
            ConnectionAuth::static_active(),
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            connection_credential_sealed(&pool, scope, v1.id)
                .await
                .unwrap()
                .unwrap(),
            (b"legacy-cred".to_vec(), 1)
        );

        // The retirement-gate counter sees both key-versions (global scan; other
        // tenants may add to the totals, so assert presence, not exact counts).
        let counts = crate::system_worker::sealed_key_version_counts(&pool)
            .await
            .unwrap();
        // THIRTEEN sealed columns today (Tasks 3/4/5 added the two
        // oauth_client_registrations twins, the connector_oauth_flows PKCE
        // verifier, and tenant_llm_keys). `reseal::FAMILIES` is the authority and
        // `reseal::tests::counts_and_families_cover_the_same_set` enforces
        // set-equality with this fn; here we only pin the shape.
        assert_eq!(counts.len(), 13, "one row per sealed column");
        let distinct: std::collections::BTreeSet<&str> =
            counts.iter().map(|c| c.family.as_str()).collect();
        assert_eq!(
            distinct.len(),
            counts.len(),
            "every counted family is distinct — no double-counted column"
        );
        let cred = counts
            .iter()
            .find(|c| c.family == "integration_connections.credential_sealed")
            .unwrap();
        assert!(cred.legacy >= 1 && cred.envelope >= 1);

        cleanup_dek_tenant(&pool, tenant).await;
    }

    // The re-seal job's DB mechanics (Task 2): keyset paging, the FOR UPDATE
    // lock/read, and the CAS write — exercised with arbitrary bytes (the DB
    // layer never sees plaintext; the crypto roundtrip is tested server-side).
    // Assertions are written to be robust against OTHER tenants sharing the
    // table (the test DB is shared): filter/relate to our own seeded ids only.
    #[tokio::test]
    async fn reseal_paging_lock_and_cas() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = new_dek_org(&pool).await;
        let tenant = scope.tenant_id();

        // Three v1 credential rows under a throwaway tenant.
        let mut ids = vec![];
        for i in 0..3 {
            let c = create_connection(
                &pool,
                scope,
                "custom",
                &format!("rs-acct-{i}"),
                &format!("rs-conn-{i}"),
                Some(format!("legacy-cred-{i}").as_bytes()),
                1,
                &serde_json::json!([]),
                &serde_json::json!({}),
                &serde_json::json!({}),
                None,
                1,
                ConnectionAuth::static_active(),
                ConnectionOwner::Organization,
                None,
            )
            .await
            .unwrap();
            ids.push(c.id);
        }
        ids.sort(); // reseal_candidate_ids orders by id

        let tbl = "integration_connections";
        let col = "credential_sealed";
        let ver = "credential_key_version";
        let key = "id"; // integration_connections is keyed by id

        // Keyset cursor: `id > after` is exclusive. After ids[0], a large page
        // includes ids[1]/ids[2] but never ids[0].
        let after0 =
            crate::system_worker::reseal_candidate_ids(&pool, tbl, col, ver, key, ids[0], 1000)
                .await
                .unwrap();
        assert!(!after0.contains(&ids[0]), "cursor is exclusive");
        assert!(after0.contains(&ids[1]) && after0.contains(&ids[2]));
        // After the last id, none of ours can appear (all <= ids[2]).
        let after_last =
            crate::system_worker::reseal_candidate_ids(&pool, tbl, col, ver, key, ids[2], 1000)
                .await
                .unwrap();
        assert!(ids.iter().all(|i| !after_last.contains(i)));
        // `limit` caps the page (≥1 v1 row exists past ids[0] — ids[1]).
        let capped =
            crate::system_worker::reseal_candidate_ids(&pool, tbl, col, ver, key, ids[0], 1)
                .await
                .unwrap();
        assert_eq!(capped.len(), 1, "limit bounds the page");

        // Lock + read one row inside a tx, then CAS the v2 bytes in.
        let mut tx = pool.begin().await.unwrap();
        let locked = crate::system_worker::reseal_lock_row(&mut tx, tbl, col, ver, key, ids[0])
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(locked.0.as_deref(), Some(b"legacy-cred-0".as_ref()));
        assert_eq!(locked.1, 1, "still v1 under the lock");
        assert_eq!(
            locked.2,
            Some(tenant),
            "carries the row's tenant for the seal ctx (Some for a tenant-owned family)"
        );
        let affected = crate::system_worker::reseal_write_row(
            &mut tx,
            tbl,
            col,
            ver,
            key,
            ids[0],
            b"v2-bytes",
        )
        .await
        .unwrap();
        assert_eq!(affected, 1, "CAS flips 1 → 2");
        tx.commit().await.unwrap();

        // The reader sees the new bytes at v2.
        assert_eq!(
            connection_credential_sealed(&pool, scope, ids[0])
                .await
                .unwrap()
                .unwrap(),
            (b"v2-bytes".to_vec(), 2)
        );

        // A second CAS on the now-v2 row is a no-op (a concurrent writer already
        // moved it off v1) — 0 rows, the caller counts it as skipped.
        let mut tx2 = pool.begin().await.unwrap();
        let noop = crate::system_worker::reseal_write_row(
            &mut tx2,
            tbl,
            col,
            ver,
            key,
            ids[0],
            b"v2-again",
        )
        .await
        .unwrap();
        assert_eq!(noop, 0, "CAS no-op when the row already left v1");
        tx2.commit().await.unwrap();

        // The re-sealed row drops out of the candidate predicate; the other two
        // remain (idempotent restart-safety: re-scans skip finished rows).
        let remaining = crate::system_worker::reseal_candidate_ids(
            &pool,
            tbl,
            col,
            ver,
            key,
            Uuid::nil(),
            1000,
        )
        .await
        .unwrap();
        assert!(!remaining.contains(&ids[0]));
        assert!(remaining.contains(&ids[1]) && remaining.contains(&ids[2]));

        cleanup_dek_tenant(&pool, tenant).await;
    }

    // Per-tenant LiteLLM virtual keys (Task 5): insert-or-adopt + rotate row
    // semantics, with ARBITRARY bytes (the crypto roundtrip is server-side).
    #[tokio::test]
    async fn tenant_llm_key_insert_adopt_and_rotate() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = new_dek_org(&pool).await;
        let tenant = scope.tenant_id();

        // Not minted yet.
        assert!(tenant_llm_key_sealed(&pool, scope).await.unwrap().is_none());
        assert!(tenant_llm_key_row(&pool, scope).await.unwrap().is_none());

        // First insert wins and returns our sealed bytes.
        let first = insert_tenant_llm_key(
            &pool,
            scope,
            b"sealed-v1-a",
            1,
            "fbx-tenant-x",
            Some("tok-a"),
        )
        .await
        .unwrap();
        assert!(first.we_won, "first insert wins");
        assert_eq!(first.sealed, b"sealed-v1-a");
        assert_eq!(first.key_version, 1);
        assert_eq!(
            tenant_llm_key_sealed(&pool, scope).await.unwrap().unwrap(),
            (b"sealed-v1-a".to_vec(), 1)
        );

        // A racing second insert loses (ON CONFLICT DO NOTHING) and ADOPTS the
        // winner's sealed bytes — its own minted key would be orphaned.
        let second = insert_tenant_llm_key(
            &pool,
            scope,
            b"sealed-v1-b",
            1,
            "fbx-tenant-x",
            Some("tok-b"),
        )
        .await
        .unwrap();
        assert!(!second.we_won, "second insert loses the race");
        assert_eq!(second.sealed, b"sealed-v1-a", "adopts the winner's key");
        // The stored row is unchanged (still the winner's).
        assert_eq!(
            tenant_llm_key_sealed(&pool, scope).await.unwrap().unwrap(),
            (b"sealed-v1-a".to_vec(), 1)
        );

        // Rotate: returns the OLD sealed for LiteLLM cleanup, swaps in the new,
        // bumps rotated_at, records the new companion version.
        let old = rotate_tenant_llm_key(
            &pool,
            scope,
            b"sealed-v2-c",
            2,
            "fbx-tenant-x",
            Some("tok-c"),
        )
        .await
        .unwrap();
        assert_eq!(old, Some((b"sealed-v1-a".to_vec(), 1)), "old key returned");
        assert_eq!(
            tenant_llm_key_sealed(&pool, scope).await.unwrap().unwrap(),
            (b"sealed-v2-c".to_vec(), 2)
        );
        let rotated_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("select rotated_at from tenant_llm_keys where tenant_id = $1")
                .bind(tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(rotated_at.is_some(), "rotate bumps rotated_at");

        // The row reader carries the CAS expectation + the durable cooldown
        // stamp (Phase D review H3/M4).
        let row = tenant_llm_key_row(&pool, scope).await.unwrap().unwrap();
        assert_eq!(row.sealed, b"sealed-v2-c");
        assert_eq!(row.key_version, 2);
        assert_eq!(
            row.minted_at,
            rotated_at.unwrap(),
            "minted_at is the rotation instant once rotated"
        );

        // M4: the recovery CAS only swaps while the stored bytes are still the
        // ones the caller read. A stale expectation (the key an in-flight request
        // presented, already rotated away) matches ZERO rows — the freshly
        // rotated key survives instead of being silently superseded.
        assert!(
            !rotate_tenant_llm_key_cas(
                &pool,
                scope,
                b"sealed-v1-a", // the pre-rotation key
                b"sealed-v3-stale",
                2,
                "fbx-tenant-x",
                None,
            )
            .await
            .unwrap(),
            "CAS against a superseded key must not swap"
        );
        assert_eq!(
            tenant_llm_key_sealed(&pool, scope).await.unwrap().unwrap(),
            (b"sealed-v2-c".to_vec(), 2),
            "the winning rotation is intact"
        );

        // …and it DOES swap when the expectation is the live key.
        assert!(rotate_tenant_llm_key_cas(
            &pool,
            scope,
            b"sealed-v2-c",
            b"sealed-v3-d",
            2,
            "fbx-tenant-x",
            Some("tok-d"),
        )
        .await
        .unwrap());
        assert_eq!(
            tenant_llm_key_sealed(&pool, scope).await.unwrap().unwrap(),
            (b"sealed-v3-d".to_vec(), 2)
        );

        cleanup_dek_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn tenant_llm_key_rotate_creates_when_absent() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = new_dek_org(&pool).await;
        let tenant = scope.tenant_id();

        // Rotate on a tenant with no key: nothing to delete (None), creates it.
        let old = rotate_tenant_llm_key(&pool, scope, b"sealed-new", 2, "fbx-tenant-y", None)
            .await
            .unwrap();
        assert_eq!(old, None, "no prior key to retire");
        assert_eq!(
            tenant_llm_key_sealed(&pool, scope).await.unwrap().unwrap(),
            (b"sealed-new".to_vec(), 2)
        );

        cleanup_dek_tenant(&pool, tenant).await;
    }

    // ─── OAuth client registrations (Phase D Task 3, #32) ───────────────────

    fn new_reg<'a>(
        tenant_id: Option<Uuid>,
        issuer: &'a str,
        redirect: &'a str,
        client_id: &'a str,
    ) -> NewOauthClientRegistration<'a> {
        NewOauthClientRegistration {
            tenant_id,
            issuer,
            redirect_uri: redirect,
            source: "dcr",
            client_id,
            client_secret_sealed: None,
            client_secret_key_version: 1,
            registration_endpoint: Some("https://as.test/register"),
            registration_access_token_sealed: None,
            registration_access_token_key_version: 1,
            token_endpoint_auth_method: Some("none"),
        }
    }

    // Two transactions inserting the SAME (issuer, redirect): exactly one row
    // lands and the loser's ON CONFLICT DO NOTHING yields None, so the caller
    // re-selects the winner (never a duplicate DCR client). Each `&pool` insert
    // is its own transaction.
    #[tokio::test]
    async fn client_registration_insert_race_keeps_one_row() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let issuer = format!("https://as-{}.test", Uuid::now_v7().simple());
        let redirect = "https://fbx.test/v1/oauth/callback";

        let first = insert_client_registration(&pool, new_reg(None, &issuer, redirect, "client-a"))
            .await
            .unwrap();
        assert!(first.is_some(), "first insert wins");
        assert!(
            first.as_ref().unwrap().last_used_at.is_some(),
            "last_used_at set"
        );

        // The loser conflicts on the global partial unique → None.
        let second =
            insert_client_registration(&pool, new_reg(None, &issuer, redirect, "client-b"))
                .await
                .unwrap();
        assert!(
            second.is_none(),
            "second insert conflicts (ON CONFLICT DO NOTHING)"
        );

        // Re-select returns the ONE winner, and there is exactly one row.
        let winner = find_client_registration(&pool, &issuer, redirect)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(winner.client_id, "client-a");
        let (n,): (i64,) = sqlx::query_as(
            "select count(*) from oauth_client_registrations
             where issuer = $1 and redirect_uri = $2",
        )
        .bind(&issuer)
        .bind(redirect)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 1);

        // by-id load + touch + delete round-trip.
        let by_id = find_client_registration_by_id(&pool, winner.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_id.client_id, "client-a");
        assert!(by_id.tenant_id.is_none(), "v1 rows are global");
        touch_client_registration(&pool, winner.id).await.unwrap();
        delete_client_registration(&pool, winner.id).await.unwrap();
        assert!(find_client_registration(&pool, &issuer, redirect)
            .await
            .unwrap()
            .is_none());
    }

    // The two partial uniques are INDEPENDENT: a global row (tenant_id NULL) and a
    // per-tenant row can share the same (issuer, redirect_uri); a second row within
    // the same scope conflicts; and the v1 reader sees ONLY the global row.
    #[tokio::test]
    async fn client_registration_partial_uniques_are_independent() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let tenant = org.id;
        let issuer = format!("https://as-{}.test", Uuid::now_v7().simple());
        let redirect = "https://fbx.test/v1/oauth/callback";

        let global =
            insert_client_registration(&pool, new_reg(None, &issuer, redirect, "g-client"))
                .await
                .unwrap();
        assert!(global.is_some(), "global row inserts");
        // A per-tenant row with the SAME key coexists (different partial index).
        let tenant_row =
            insert_client_registration(&pool, new_reg(Some(tenant), &issuer, redirect, "t-client"))
                .await
                .unwrap();
        assert!(
            tenant_row.is_some(),
            "a per-tenant row is independent of the same-key global row"
        );
        // A second GLOBAL row for the key conflicts.
        assert!(
            insert_client_registration(&pool, new_reg(None, &issuer, redirect, "g-dupe"))
                .await
                .unwrap()
                .is_none(),
            "a second global row for the key is refused"
        );
        // The v1 reader returns ONLY the global row (tenant_id is null).
        let found = find_client_registration(&pool, &issuer, redirect)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.client_id, "g-client");
        assert!(found.tenant_id.is_none());

        // Cleanup (registration rows before the tenant — FKs are NO ACTION).
        sqlx::query("delete from oauth_client_registrations where issuer = $1")
            .bind(&issuer)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("delete from tenants where id = $1")
            .bind(tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    // The advisory lock serializes DCR per (issuer, redirect_uri): while one
    // transaction holds it, a second connection cannot take the SAME key but CAN
    // take a different one; it frees on transaction end. This is what collapses
    // concurrent connects to ONE `/register`.
    #[tokio::test]
    async fn registration_lock_serializes_same_key() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let issuer = format!("https://as-{}.test", Uuid::now_v7().simple());
        let redirect = "https://fbx.test/v1/oauth/callback";
        let key = registration_lock_key(&issuer, redirect);
        assert_ne!(
            key,
            registration_lock_key(&issuer, "https://other.test/cb"),
            "distinct (issuer, redirect) fold to distinct keys"
        );

        let mut tx1 = pool.begin().await.unwrap();
        acquire_registration_lock(&mut tx1, &issuer, redirect)
            .await
            .unwrap();
        // A second connection cannot take the held key, but a different key is free.
        let mut c2 = pool.acquire().await.unwrap();
        let (same,): (bool,) = sqlx::query_as("select pg_try_advisory_xact_lock($1)")
            .bind(key)
            .fetch_one(&mut *c2)
            .await
            .unwrap();
        assert!(!same, "same-key lock is held by tx1");
        let (other,): (bool,) = sqlx::query_as("select pg_try_advisory_xact_lock($1)")
            .bind(registration_lock_key(&issuer, "https://other.test/cb"))
            .fetch_one(&mut *c2)
            .await
            .unwrap();
        assert!(other, "a different (issuer, redirect) key is independent");
        drop(c2);

        // Releasing tx1 frees the key.
        tx1.rollback().await.unwrap();
        let mut tx3 = pool.begin().await.unwrap();
        let (freed,): (bool,) = sqlx::query_as("select pg_try_advisory_xact_lock($1)")
            .bind(key)
            .fetch_one(&mut *tx3)
            .await
            .unwrap();
        assert!(freed, "the lock is free after tx1 released");
        tx3.rollback().await.unwrap();
    }

    // ─── Connector OAuth flows (Phase D Task 4, #32 — invariant 20) ──────────

    // A flow-row template borrowing the caller's per-case hashes/scopes (one
    // shared lifetime); string/byte literals are 'static and coerce in.
    fn new_flow<'a>(
        connection_id: Uuid,
        expected_generation: i32,
        state_hash: &'a str,
        browser_hash: &'a str,
        scopes: &'a Value,
        ttl_secs: i64,
    ) -> NewConnectorOauthFlow<'a> {
        NewConnectorOauthFlow {
            connection_id,
            initiated_by_user_id: None,
            state_hash,
            browser_hash,
            issuer: "https://as.test",
            authorization_endpoint: "https://as.test/authorize",
            token_endpoint: "https://as.test/token",
            metadata_digest: "sha256:abc",
            resource: "https://mcp.test",
            redirect_uri: "https://fbx.test/v1/oauth/callback",
            scopes,
            challenge: "chal",
            challenge_method: "S256",
            client_registration_id: None,
            client_id: "client-1",
            pkce_verifier_sealed: &[1, 2, 3],
            pkce_verifier_key_version: 1,
            expected_generation,
            ttl_secs,
        }
    }

    // The full claim matrix: happy path consumes once; replay refused; a WRONG
    // browser_hash matches nothing AND leaves consumed_at null (then the right
    // browser still completes — the no-burn proof); expired refused; peek never
    // consumes; and the row FREEZES the connection's generation so a mid-flow
    // reconnect (bump) is detectable by the callback's coherence check.
    #[tokio::test]
    async fn connector_oauth_flow_claim_matrix() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);
        // A connection to satisfy the composite (tenant_id, connection_id) FK.
        let conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct",
            "disp",
            None,
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({ "base_url": "https://x" }),
            None,
            1,
            ConnectionAuth {
                auth_kind: "oauth",
                status: "pending",
                oauth: None,
                client_secret_sealed: None,
                client_secret_key_version: 1,
                registration_id: None,
            },
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        let scopes = serde_json::json!(["read", "offline_access"]);
        let gen = conn.authorization_generation;
        let s_hash = sha256_hex("state-secret");
        let b_hash = sha256_hex("cookie-secret");

        // Insert returns the persisted row (its expires_at seeds the boot token).
        let row = insert_connector_oauth_flow(
            &pool,
            scope,
            new_flow(conn.id, gen, &s_hash, &b_hash, &scopes, 600),
        )
        .await
        .unwrap();
        assert_eq!(row.tenant_id, org.id);
        assert_eq!(row.connection_id, conn.id);
        assert!(row.consumed_at.is_none());
        assert!(row.expires_at > Utc::now());

        // peek returns the row and does NOT consume it.
        let peeked = peek_connector_oauth_flow(&pool, &s_hash)
            .await
            .unwrap()
            .expect("peek finds the live flow");
        assert_eq!(peeked.id, row.id);
        assert!(peeked.consumed_at.is_none(), "peek never consumes");
        assert_eq!(peeked.pkce_verifier_sealed, vec![1, 2, 3]);

        // WRONG browser_hash: matches nothing AND burns nothing.
        assert!(
            claim_connector_oauth_flow(&pool, &s_hash, &sha256_hex("attacker"))
                .await
                .unwrap()
                .is_none(),
            "wrong browser is refused"
        );
        let unburned = peek_connector_oauth_flow(&pool, &s_hash)
            .await
            .unwrap()
            .unwrap();
        assert!(
            unburned.consumed_at.is_none(),
            "a wrong-browser claim burns NOTHING (the no-burn proof)"
        );

        // RIGHT browser then still completes — consumes exactly once.
        let claimed = claim_connector_oauth_flow(&pool, &s_hash, &b_hash)
            .await
            .unwrap()
            .expect("the right browser claims after a wrong-browser attempt");
        assert_eq!(claimed.client_id, "client-1");
        assert_eq!(claimed.scopes, scopes);
        assert_eq!(claimed.expected_generation, conn.authorization_generation);
        assert!(claimed.consumed_at.is_some(), "claim consumes the row");

        // REPLAY (correct browser, second time) is refused.
        assert!(
            claim_connector_oauth_flow(&pool, &s_hash, &b_hash)
                .await
                .unwrap()
                .is_none(),
            "replay of a consumed flow is refused"
        );

        // Unknown state_hash: no claim, no peek row.
        assert!(
            claim_connector_oauth_flow(&pool, &sha256_hex("nope"), &b_hash)
                .await
                .unwrap()
                .is_none()
        );
        assert!(peek_connector_oauth_flow(&pool, &sha256_hex("nope"))
            .await
            .unwrap()
            .is_none());

        // Expired flow: claim refused; peek still SEES it (peek is a plain read,
        // it never filters — the caller classifies).
        let s_exp = sha256_hex("state-expired");
        insert_connector_oauth_flow(
            &pool,
            scope,
            new_flow(conn.id, gen, &s_exp, &b_hash, &scopes, -5),
        )
        .await
        .unwrap();
        assert!(
            claim_connector_oauth_flow(&pool, &s_exp, &b_hash)
                .await
                .unwrap()
                .is_none(),
            "an already-expired flow is refused"
        );
        assert!(
            peek_connector_oauth_flow(&pool, &s_exp)
                .await
                .unwrap()
                .is_some(),
            "peek never filters — it returns the expired row so the caller can 400"
        );

        // Generation drift: the row froze the connection's generation; a reconnect
        // bumps it, so the callback's `authorization_generation == expected_generation`
        // coherence check detects the drift and refuses.
        let s_gen = sha256_hex("state-gen");
        let gen_flow = insert_connector_oauth_flow(
            &pool,
            scope,
            new_flow(conn.id, gen, &s_gen, &b_hash, &scopes, 600),
        )
        .await
        .unwrap();
        let new_gen = bump_connection_generation(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        let fresh = get_connection(&pool, scope, conn.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fresh.authorization_generation, new_gen);
        assert_ne!(
            fresh.authorization_generation, gen_flow.expected_generation,
            "a reconnect (generation bump) drifts past the flow's frozen expected_generation"
        );

        // Cleanup: children-first (FKs are NO ACTION) — flows, then the connection,
        // then the tenant.
        for stmt in [
            "delete from connector_oauth_flows where tenant_id = $1",
            "delete from integration_connections where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(stmt).bind(org.id).execute(&pool).await.unwrap();
        }
    }

    /// Phase D (#32, #75) — the RLS acceptance core. Proves DB-enforced tenant
    /// isolation, NOT the Rust `where tenant_id = $n` predicate: every assertion query
    /// OMITS the predicate on purpose (the buggy-predicate proof).
    ///
    /// TEST-ROLE GOTCHA (resolution 9): a Postgres SUPERUSER bypasses RLS entirely,
    /// even under FORCE — and CI's DB user is the superuser `postgres`. So the
    /// assertions run through a dedicated connection that `SET ROLE fluidbox_runtime`
    /// (the 0018 NON-owner role, `GRANT`ed to the owner so SET ROLE works on any
    /// Postgres). Only then does the policy actually run, so this proves the policy
    /// logic under the REAL runtime role regardless of the base user's privilege.
    /// Seeding runs under the audited bypass (`worker_tx`, on the `test_connect`
    /// fixture pool) so it works whether the base role is a superuser (RLS skipped)
    /// or the table owner under FORCE RLS — and the assertions below never touch
    /// that pool, so the bypass cannot leak into what they prove.
    /// `connect()` here applies migrations 0014-0018 from scratch — a failed 0018
    /// would fail this test at `.expect("connect")` (the migration smoke check).
    #[tokio::test]
    async fn rls_enforces_tenant_isolation_under_runtime_role() {
        use sqlx::{Connection, Executor};
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");

        // Two throwaway tenants + one session + one event each.
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        {
            let mut tx = worker_tx(&pool).await.unwrap();
            for id in [a, b] {
                let slug = format!("rls-{}", id.simple());
                sqlx::query("insert into tenants (id, name, slug) values ($1, $2, $3)")
                    .bind(id)
                    .bind(&slug)
                    .bind(&slug)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            tx.commit().await.unwrap();
        }
        for id in [a, b] {
            let scope = TenantScope::assume(id);
            let policy = upsert_policy(
                &pool,
                scope,
                "rls",
                "name: rls",
                &serde_json::json!({"name":"rls"}),
            )
            .await
            .unwrap();
            let agent = create_agent(&pool, scope, "rls-agent", None).await.unwrap();
            let rev = append_agent_revision(
                &pool,
                scope,
                agent.id,
                "claude-agent-sdk",
                "img:test",
                "claude-haiku-4-5",
                None,
                policy.id,
                &serde_json::json!({}),
                None,
                &serde_json::json!([]),
                &serde_json::json!([]),
                None,
            )
            .await
            .unwrap();
            let repo = serde_json::json!({"kind":"none"});
            let empty = serde_json::json!({});
            let session = create_session(
                &pool,
                scope,
                agent.id,
                rev.id,
                "supervised",
                "trusted",
                "rls task",
                &repo,
                &empty,
                &empty,
                None,
                None,
                None,
                None,
                None,
                &[],
                None,
            )
            .await
            .unwrap();
            // One event per session (a child-table row for the parent-composed policy).
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query(
                "insert into events (event_id, session_id, seq, actor, type, payload, occurred_at)
                 values ($1, $2, 1, 'system', 'rls.test', '{}'::jsonb, now())",
            )
            .bind(Uuid::now_v7())
            .bind(session.id)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }

        // Assert through the NON-superuser runtime role — otherwise RLS is bypassed.
        let mut rt = sqlx::PgConnection::connect(&url).await.expect("rt connect");
        rt.execute("set role fluidbox_runtime")
            .await
            .expect("set role");

        async fn count_as(
            rt: &mut sqlx::PgConnection,
            guc: Option<(&str, String)>,
            sql: &'static str,
        ) -> i64 {
            let mut tx = rt.begin().await.unwrap();
            if let Some((name, val)) = guc {
                sqlx::query("select set_config($1, $2, true)")
                    .bind(name)
                    .bind(val)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            let (n,): (i64,) = sqlx::query_as(sql).fetch_one(&mut *tx).await.unwrap();
            tx.rollback().await.ok();
            n
        }
        let a_str = a.to_string();
        let tid = "fluidbox.tenant_id";

        // (a) A-scope sees ONLY tenant A's session — with NO where clause (#75 proof).
        assert_eq!(
            count_as(
                &mut rt,
                Some((tid, a_str.clone())),
                "select count(*) from sessions"
            )
            .await,
            1,
            "A-scope must see only tenant A's session even without a predicate"
        );
        // (c) child table (events) follows the parent (sessions) policy.
        assert_eq!(
            count_as(
                &mut rt,
                Some((tid, a_str.clone())),
                "select count(*) from events"
            )
            .await,
            1,
            "A-scope sees only A's events (parent-composed EXISTS policy)"
        );
        // (f) tenants keys on its own id — A-scope sees exactly its own row.
        assert_eq!(
            count_as(
                &mut rt,
                Some((tid, a_str.clone())),
                "select count(*) from tenants"
            )
            .await,
            1,
            "A-scope sees exactly the tenants row whose id matches"
        );
        // (d) the audited bypass sees BOTH tenants' rows.
        assert!(
            count_as(
                &mut rt,
                Some(("fluidbox.bypass", "system_worker".into())),
                "select count(*) from sessions"
            )
            .await
                >= 2,
            "the system_worker bypass sees every tenant"
        );
        // (e) no GUC → zero rows on a policy'd table.
        assert_eq!(
            count_as(&mut rt, None, "select count(*) from sessions").await,
            0,
            "a transaction with no GUC sees nothing"
        );

        // (b) INSERT of a cross-tenant row is refused by WITH CHECK.
        let mut tx = rt.begin().await.unwrap();
        sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
            .bind(&a_str)
            .execute(&mut *tx)
            .await
            .unwrap();
        let res = sqlx::query(
            "insert into settings (tenant_id, key, value) values ($1, 'rls-check', '{}'::jsonb)",
        )
        .bind(b) // tenant B under the tenant-A GUC
        .execute(&mut *tx)
        .await;
        tx.rollback().await.ok();
        let err = res.expect_err("a cross-tenant insert must be refused by RLS WITH CHECK");
        assert!(
            err.to_string()
                .to_lowercase()
                .contains("row-level security"),
            "expected an RLS policy violation, got: {err}"
        );

        rt.close().await.ok();

        // Cleanup, children-first, under the bypass (FKs are NO ACTION; sessions
        // cascade events, agents cascade revisions).
        let mut tx = worker_tx(&pool).await.unwrap();
        for id in [a, b] {
            for stmt in [
                "delete from sessions where tenant_id = $1",
                "delete from agents where tenant_id = $1",
                "delete from policies where tenant_id = $1",
                "delete from tenants where id = $1",
            ] {
                sqlx::query(stmt).bind(id).execute(&mut *tx).await.ok();
            }
        }
        tx.commit().await.unwrap();
    }

    /// Seed a throwaway tenant + one `created` session, returning both ids. The
    /// tenant insert rides `worker_tx` (a new tenant id is no GUC's tenant); the
    /// policy/agent/revision/session ride the scoped repositories. Runs on the base
    /// pool (superuser bypasses RLS), so it is agnostic to the enforcement asserted.
    async fn seed_tenant_session(pool: &PgPool) -> (Uuid, Uuid) {
        let tenant = Uuid::now_v7();
        {
            let slug = format!("rls-sw-{}", tenant.simple());
            let mut tx = worker_tx(pool).await.unwrap();
            sqlx::query("insert into tenants (id, name, slug) values ($1, $2, $3)")
                .bind(tenant)
                .bind(&slug)
                .bind(&slug)
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        let scope = TenantScope::assume(tenant);
        let policy = upsert_policy(
            pool,
            scope,
            "rls",
            "name: rls",
            &serde_json::json!({"name":"rls"}),
        )
        .await
        .unwrap();
        let agent = create_agent(pool, scope, "rls-agent", None).await.unwrap();
        let rev = append_agent_revision(
            pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
            None,
        )
        .await
        .unwrap();
        let repo = serde_json::json!({"kind":"none"});
        let empty = serde_json::json!({});
        let session = create_session(
            pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "rls task",
            &repo,
            &empty,
            &empty,
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
        )
        .await
        .unwrap();
        (tenant, session.id)
    }

    async fn cleanup_sw_tenant(pool: &PgPool, tenant: Uuid) {
        let mut tx = worker_tx(pool).await.unwrap();
        for stmt in [
            "delete from integration_connections where tenant_id = $1",
            "delete from sessions where tenant_id = $1",
            "delete from agents where tenant_id = $1",
            "delete from policies where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(stmt).bind(tenant).execute(&mut *tx).await.ok();
        }
        tx.commit().await.unwrap();
    }

    /// Migration 0034's queue timestamps ride the two transition functions the
    /// way `started_at` always has. The `coalesce` is load-bearing: a
    /// capacity-bounced run keeps its ORIGINAL `queued_at`, so the age bound
    /// measures TOTAL time-in-queue across bounce cycles and the requeue loop
    /// cannot be infinite even if the attempt cap were misconfigured.
    #[tokio::test]
    async fn queue_timestamps_stamp_once_and_survive_a_bounce() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        use fluidbox_core::state::SessionStatus::*;

        // created → queued stamps queued_at, and nothing else.
        let (_, row) = transition_session(&pool, scope, session, Queued, Some("park"))
            .await
            .unwrap()
            .unwrap();
        let first_queued_at = row.queued_at.expect("queued_at stamped on first park");
        assert!(row.launched_at.is_none());
        assert!(row.started_at.is_none());

        // queued → provisioning stamps launched_at (the watchdog's anchor).
        let (_, row) = transition_session(&pool, scope, session, Provisioning, None)
            .await
            .unwrap()
            .unwrap();
        let first_launched_at = row
            .launched_at
            .expect("launched_at stamped on first launch");
        assert_eq!(
            row.queued_at,
            Some(first_queued_at),
            "queued_at is stamped once"
        );

        // provisioning → queued (a capacity bounce) keeps the ORIGINAL
        // queued_at: the age bound is total time-in-queue.
        let (_, row) = transition_session(&pool, scope, session, Queued, Some("bounce"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.queued_at, Some(first_queued_at));
        assert_eq!(
            row.dispatch_attempts, 0,
            "the CLAIM increments attempts, not the transition"
        );

        // …and a redispatch keeps the original launched_at too.
        let (_, row) = transition_session(&pool, scope, session, Provisioning, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.launched_at, Some(first_launched_at));

        // The fenced sibling stamps identically — both transition functions
        // carry the columns, or a fenced driver silently skips them.
        let (tenant2, session2) = seed_tenant_session(&pool).await;
        let scope2 = TenantScope::assume(tenant2);
        let epoch = acquire_session_lease(&pool, scope2, session2, Uuid::now_v7(), 60)
            .await
            .unwrap()
            .expect("fresh lease");
        let (_, row) = transition_session_fenced(&pool, scope2, session2, Queued, None, epoch)
            .await
            .unwrap()
            .unwrap();
        assert!(row.queued_at.is_some(), "the fenced transition stamps too");
        let (_, row) =
            transition_session_fenced(&pool, scope2, session2, Provisioning, None, epoch)
                .await
                .unwrap()
                .unwrap();
        assert!(row.launched_at.is_some());

        cleanup_sw_tenant(&pool, tenant).await;
        cleanup_sw_tenant(&pool, tenant2).await;
    }

    // ─── Dispatch-claim tests run against a DEDICATED database ──────────────
    //
    // Capacity occupancy is DEPLOYMENT-WIDE by design (design 2026-08-23 §7.2 —
    // "the count IS the truth"), so `dispatch_claim` counts every tenant's rows.
    // In the shared test database that makes a cap assertion an assertion about
    // every OTHER test's rows: `seed_tenant_session` leaves a session in
    // `created`, which the occupancy predicate counts as active, and a sibling's
    // `queued` row is claimed ahead of mine because `order by created_at` is
    // global too.
    //
    // The GLOBAL_SCAN cure above does not reach this: it narrows the RETURNED
    // BATCH, and here the interference is in the COUNT and in the ORDER. So
    // these tests get their own database — created once, migrated exactly as
    // production migrates — and hold [`DISPATCH_SERIAL`] while they run. That
    // is the same isolation posture the hermetic queue e2e uses, and it turns
    // probabilistic assertions into deterministic ones.
    static DISPATCH_DB: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();
    static DISPATCH_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Swap the database component of a Postgres URL, preserving any query
    /// string (`?sslmode=…`). Used to reach the maintenance database on the
    /// same server so the dedicated one can be created.
    fn swap_db(url: &str, db: &str) -> String {
        let (head, query) = match url.split_once('?') {
            Some((h, q)) => (h, Some(q)),
            None => (url, None),
        };
        let base = head.rsplit_once('/').map(|(b, _)| b).unwrap_or(head);
        match query {
            Some(q) => format!("{base}/{db}?{q}"),
            None => format!("{base}/{db}"),
        }
    }

    /// The dedicated database's URL, created on first use.
    ///
    /// This deliberately caches the URL and NOT a `PgPool`. A pool stored in a
    /// `static` belongs to the `#[tokio::test]` runtime that built it — sqlx
    /// spawns the pool's connection tasks there — so when that first test's
    /// runtime is dropped the pool goes inert and every later borrower blocks
    /// until `acquire_timeout` and fails `PoolTimedOut`. Sharing the DATABASE
    /// and letting each test build its own pool costs one cheap no-op migration
    /// check and is runtime-safe.
    async fn dispatch_db_url(url: &str) -> String {
        DISPATCH_DB
            .get_or_init(|| async move {
                let admin = PgPool::connect(&swap_db(url, "postgres"))
                    .await
                    .expect("connect to the maintenance database");
                sqlx::query("drop database if exists fluidbox_dispatch_test")
                    .execute(&admin)
                    .await
                    .ok();
                sqlx::query("create database fluidbox_dispatch_test")
                    .execute(&admin)
                    .await
                    .expect("create the dedicated dispatch database");
                admin.close().await;
                swap_db(url, "fluidbox_dispatch_test")
            })
            .await
            .clone()
    }

    /// Seed `n` sessions already parked in `queued`, oldest first, each in its
    /// own tenant — the queue is deployment-wide, so cross-tenant rows are
    /// exactly what the dispatcher must handle.
    async fn seed_queued(pool: &PgPool, n: usize) -> Vec<(Uuid, Uuid)> {
        let mut out = Vec::new();
        for _ in 0..n {
            let (tenant, session) = seed_tenant_session(pool).await;
            transition_session(
                pool,
                TenantScope::assume(tenant),
                session,
                fluidbox_core::state::SessionStatus::Queued,
                None,
            )
            .await
            .unwrap()
            .unwrap();
            out.push((tenant, session));
        }
        out
    }

    /// A capacity cap of 1 admits exactly one run, and — the mutation guard for
    /// design §7.3 — a CLAIMED row still sitting in `queued` counts as occupied
    /// through its live lease. Drop the `filter (… orchestrator_lease_until …)`
    /// clause from the occupancy query and the second pass double-admits, so
    /// this test fails.
    #[tokio::test]
    async fn dispatch_claim_honors_cap_counting_leased_queued_as_occupied() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let _serial = DISPATCH_SERIAL.lock().await;
        let pool = &test_connect(&dispatch_db_url(&url).await)
            .await
            .expect("connect to the dedicated dispatch database");
        let seeded = seed_queued(pool, 3).await;

        let owner = Uuid::now_v7();
        let one = system_worker::dispatch_claim(pool, 1, 200, owner, 30)
            .await
            .unwrap()
            .expect("the lock is free");
        assert_eq!(one.claimed.len(), 1, "cap 1 admits exactly one");
        assert_eq!(one.active, 0, "queued rows are not active until dispatched");
        assert_eq!(
            one.claimed[0].dispatch_attempts, 1,
            "the claim increments attempts"
        );
        assert!(
            one.claimed[0].queued_at.is_some(),
            "the wait clock is carried"
        );

        // The claimed row is STILL status='queued' — run() is the single writer
        // of queued → provisioning. Its live lease is what must make it count
        // as occupied, or the next tick admits it a second time.
        let two = system_worker::dispatch_claim(pool, 1, 200, owner, 30)
            .await
            .unwrap()
            .expect("the lock is free");
        assert_eq!(two.claimed.len(), 0, "leased-queued must count as occupied");
        assert_eq!(two.leased_queued, 1);

        // Expire the lease → the row returns to the pool (crash reclaim, §7.3),
        // and it is the SAME row: a crashed claimant costs one redispatch, not
        // a lost run.
        sqlx::query(
            "update sessions set orchestrator_lease_until = now() - interval '1 second'
             where id = $1",
        )
        .bind(one.claimed[0].id)
        .execute(pool)
        .await
        .unwrap();
        let three = system_worker::dispatch_claim(pool, 1, 200, owner, 30)
            .await
            .unwrap()
            .expect("the lock is free");
        assert_eq!(three.claimed.len(), 1);
        assert_eq!(three.claimed[0].id, one.claimed[0].id);
        assert_eq!(three.claimed[0].dispatch_attempts, 2);

        for (tenant, _) in seeded {
            cleanup_sw_tenant(pool, tenant).await;
        }
        pool.close().await;
    }

    /// The cap counts SANDBOXES, not statuses — the property a status-only
    /// occupancy query silently breaks.
    ///
    /// A finalizer commits the terminal status BEFORE `finish_terminal_cleanup`
    /// reaches `reap()`, and provider deletion can fail and be retried. With the
    /// count keyed on `status` alone, the run left occupancy the instant it went
    /// terminal while its pod was still running, so the next tick admitted
    /// another one OVER the cap — and repeated reap failures made the divergence
    /// grow without bound.
    ///
    /// The marker for "may still own a sandbox" is the finalization intent,
    /// which `finish_terminal_cleanup` deletes ONLY after a successful reap.
    /// This test walks that exact sequence: intent recorded, status terminal,
    /// sandbox NOT yet reaped ⇒ the slot stays held; intent deleted (the reap
    /// succeeded) ⇒ the slot is released. Drop the `unreaped` term from the
    /// occupancy query and the middle assertion fails.
    #[tokio::test]
    async fn an_unreaped_sandbox_holds_its_slot_after_the_terminal_status() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let _serial = DISPATCH_SERIAL.lock().await;
        let pool = &test_connect(&dispatch_db_url(&url).await)
            .await
            .expect("connect to the dedicated dispatch database");
        let seeded = seed_queued(pool, 2).await;
        let (tenant_a, _) = seeded[0];
        let scope_a = TenantScope::assume(tenant_a);

        let owner = Uuid::now_v7();
        let first = system_worker::dispatch_claim(pool, 1, 200, owner, 30)
            .await
            .unwrap()
            .expect("the lock is free");
        assert_eq!(first.claimed.len(), 1, "cap 1 admits exactly one");
        let admitted = first.claimed[0].id;

        // The finalizer's ordering, reproduced: durable intent first, terminal
        // status second, reap LAST. Between the second and third steps the
        // sandbox is still running.
        begin_finalization(pool, scope_a, admitted, "completed", None, None, false, 30)
            .await
            .expect("intent persists");
        sqlx::query("update sessions set status = 'completed' where id = $1")
            .bind(admitted)
            .execute(pool)
            .await
            .unwrap();

        let mid = system_worker::dispatch_claim(pool, 1, 200, owner, 30)
            .await
            .unwrap()
            .expect("the lock is free");
        assert_eq!(mid.active, 0, "the run is terminal by status");
        assert_eq!(
            mid.unreaped, 1,
            "…but its sandbox has not been verifiably released"
        );
        assert_eq!(
            mid.claimed.len(),
            0,
            "a terminal-but-unreaped run must keep its slot, or the cap counts \
             statuses instead of sandboxes"
        );

        // The reap succeeded, so cleanup drops the intent — and only now is the
        // slot free.
        delete_finalization(pool, scope_a, admitted).await.unwrap();
        let after = system_worker::dispatch_claim(pool, 1, 200, owner, 30)
            .await
            .unwrap()
            .expect("the lock is free");
        assert_eq!(after.unreaped, 0);
        assert_eq!(
            after.claimed.len(),
            1,
            "a verifiably reaped sandbox releases its slot"
        );

        for (tenant, _) in seeded {
            cleanup_sw_tenant(pool, tenant).await;
        }
        pool.close().await;
    }

    /// The two observability reads (design §13). `queue_gauges` answers the
    /// deployment-wide operator question ("how deep, and how long has the head
    /// been waiting"); `queued_position` answers the per-run user question
    /// ("where am I") and is TENANT-SCOPED on purpose — a deployment-wide
    /// number would leak cross-tenant load through a normal run API.
    #[tokio::test]
    async fn queue_gauges_and_position_answer_their_two_questions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let _serial = DISPATCH_SERIAL.lock().await;
        let pool = &test_connect(&dispatch_db_url(&url).await)
            .await
            .expect("connect to the dedicated dispatch database");

        // Empty queue: zero depth, and zero — not an error, not a null —
        // oldest wait, so the gauge renders a real number on a quiet
        // deployment.
        assert_eq!(system_worker::queue_gauges(pool).await.unwrap(), (0, 0));

        let seeded = seed_queued(pool, 3).await;
        let (depth, oldest) = system_worker::queue_gauges(pool).await.unwrap();
        assert_eq!(depth, 3);
        assert!(oldest >= 0);

        // Age the head so the oldest-wait gauge has something to report.
        sqlx::query("update sessions set queued_at = now() - interval '90 seconds' where id = $1")
            .bind(seeded[0].1)
            .execute(pool)
            .await
            .unwrap();
        let (_, oldest) = system_worker::queue_gauges(pool).await.unwrap();
        assert!(oldest >= 90, "oldest wait tracks the head, got {oldest}");

        // Position counts only OLDER queued rows IN THE SAME TENANT.
        for (i, (tenant, session)) in seeded.iter().enumerate() {
            let scope = TenantScope::assume(*tenant);
            let row = get_session(pool, scope, *session).await.unwrap().unwrap();
            assert_eq!(
                queued_position(pool, scope, row.created_at).await.unwrap(),
                0,
                "each seeded run is alone in its own tenant, so it is at the head"
            );
            assert_eq!(i, i); // keep the index meaningful to the reader
        }

        // Three runs in ONE tenant: 0, 1, 2 — and a fourth tenant's run is
        // invisible to them.
        let (tenant, first) = seed_tenant_session(pool).await;
        let scope = TenantScope::assume(tenant);
        let mut ids = vec![first];
        for _ in 0..2 {
            let row = create_session(
                pool,
                scope,
                get_session(pool, scope, first)
                    .await
                    .unwrap()
                    .unwrap()
                    .agent_id,
                get_session(pool, scope, first)
                    .await
                    .unwrap()
                    .unwrap()
                    .agent_revision_id,
                "supervised",
                "trusted",
                "queued position",
                &serde_json::json!({"kind":"none"}),
                &serde_json::json!({}),
                &serde_json::json!({}),
                None,
                None,
                None,
                None,
                None,
                &[],
                None,
            )
            .await
            .unwrap();
            ids.push(row.id);
        }
        for id in &ids {
            transition_session(
                pool,
                scope,
                *id,
                fluidbox_core::state::SessionStatus::Queued,
                None,
            )
            .await
            .unwrap()
            .unwrap();
        }
        for (want, id) in ids.iter().enumerate() {
            let row = get_session(pool, scope, *id).await.unwrap().unwrap();
            assert_eq!(
                queued_position(pool, scope, row.created_at).await.unwrap(),
                want as i64,
                "position is the count of older queued runs in this tenant"
            );
        }

        cleanup_sw_tenant(pool, tenant).await;
        for (t, _) in seeded {
            cleanup_sw_tenant(pool, t).await;
        }
        pool.close().await;
    }

    /// FIFO is `order by created_at`, the `dispatch_after` backoff gate hides a
    /// bounced row until its not-before passes, and a batch never exceeds the
    /// headroom.
    #[tokio::test]
    async fn dispatch_claim_is_fifo_and_respects_the_backoff_gate() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let _serial = DISPATCH_SERIAL.lock().await;
        let pool = &test_connect(&dispatch_db_url(&url).await)
            .await
            .expect("connect to the dedicated dispatch database");
        let seeded = seed_queued(pool, 3).await;
        let ids: Vec<Uuid> = seeded.iter().map(|(_, s)| *s).collect();

        // Gate the OLDEST row behind a future not-before: FIFO must skip it and
        // keep walking rather than head-blocking the queue.
        sqlx::query("update sessions set dispatch_after = now() + interval '1 hour' where id = $1")
            .bind(ids[0])
            .execute(pool)
            .await
            .unwrap();

        let owner = Uuid::now_v7();
        let out = system_worker::dispatch_claim(pool, 10, 200, owner, 30)
            .await
            .unwrap()
            .expect("the lock is free");
        let claimed: Vec<Uuid> = out.claimed.iter().map(|c| c.id).collect();
        assert_eq!(
            claimed,
            vec![ids[1], ids[2]],
            "oldest-first, and the backoff-gated row is skipped, not head-blocking"
        );

        // Headroom, not the batch size, is what bounds a claim: three rows are
        // now leased-queued, so a cap of 3 leaves no room for the gated one even
        // after its gate passes.
        sqlx::query("update sessions set dispatch_after = null where id = $1")
            .bind(ids[0])
            .execute(pool)
            .await
            .unwrap();
        let full = system_worker::dispatch_claim(pool, 2, 200, owner, 30)
            .await
            .unwrap()
            .expect("the lock is free");
        assert_eq!(full.claimed.len(), 0, "headroom is exhausted");
        assert_eq!(full.leased_queued, 2);

        for (tenant, _) in seeded {
            cleanup_sw_tenant(pool, tenant).await;
        }
        pool.close().await;
    }

    /// A losing tick YIELDS rather than queueing behind the winner: the dispatch
    /// decision is serialized with `pg_try_advisory_xact_lock`, so a replica
    /// that loses simply re-polls in a second (design §7.2).
    #[tokio::test]
    async fn dispatch_claim_yields_when_another_connection_holds_the_lock() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let _serial = DISPATCH_SERIAL.lock().await;
        let pool = &test_connect(&dispatch_db_url(&url).await)
            .await
            .expect("connect to the dedicated dispatch database");
        let mut holder = pool.begin().await.unwrap();
        let (locked,): (bool,) = sqlx::query_as("select pg_try_advisory_xact_lock($1)")
            .bind(system_worker::DISPATCH_ADVISORY_KEY)
            .fetch_one(&mut *holder)
            .await
            .unwrap();
        assert!(locked);

        let out = system_worker::dispatch_claim(pool, 10, 200, Uuid::now_v7(), 30)
            .await
            .unwrap();
        assert!(
            out.is_none(),
            "a losing tick yields instead of queueing behind the winner"
        );
        holder.rollback().await.unwrap();

        // …and the lock is released with the holder's transaction, so the very
        // next tick proceeds.
        assert!(
            system_worker::dispatch_claim(pool, 10, 200, Uuid::now_v7(), 30)
                .await
                .unwrap()
                .is_some()
        );
        pool.close().await;
    }

    /// The queue-age sweep measures from `queued_at`, NOT `created_at` — a run
    /// that spent days parked for a human authorization must not be expired the
    /// moment it becomes dispatchable. It CLAIMS what it returns, so exactly one
    /// replica sheds each expired run. Adoption refuses a row a live driver
    /// owns.
    #[tokio::test]
    async fn queue_scans_use_queued_at_and_skip_live_leases() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let _serial = DISPATCH_SERIAL.lock().await;
        let pool = &test_connect(&dispatch_db_url(&url).await)
            .await
            .expect("connect to the dedicated dispatch database");

        let seeded = seed_queued(pool, 1).await;
        let (tenant, session) = seeded[0];
        assert_eq!(
            system_worker::count_admission_pending_sessions(pool)
                .await
                .unwrap(),
            1
        );

        // The depth bound RESERVES for the other pre-provisioning park: a run
        // waiting on a human authorization is accepted work that will take a
        // queue slot the moment it is approved, so it counts. Without this the
        // bound is escapable — pile up `awaiting_authorization`, approve them
        // all, and the queue exceeds its documented depth by however many were
        // waiting.
        let (t_auth, auth) = seed_tenant_session(pool).await;
        transition_session(
            pool,
            TenantScope::assume(t_auth),
            auth,
            fluidbox_core::state::SessionStatus::AwaitingAuthorization,
            None,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            system_worker::count_admission_pending_sessions(pool)
                .await
                .unwrap(),
            2,
            "an authorization-paused run reserves a queue slot"
        );

        // Ancient created_at, fresh queued_at: it has waited seconds, not days.
        sqlx::query("update sessions set created_at = now() - interval '2 hours' where id = $1")
            .bind(session)
            .execute(pool)
            .await
            .unwrap();
        let expired =
            system_worker::claim_expired_queued_sessions(pool, 60, 100, Uuid::now_v7(), 30)
                .await
                .unwrap();
        assert!(
            !expired.iter().any(|s| s.id == session),
            "the age bound measures from queued_at, not created_at"
        );

        sqlx::query("update sessions set queued_at = now() - interval '2 hours' where id = $1")
            .bind(session)
            .execute(pool)
            .await
            .unwrap();
        let expired =
            system_worker::claim_expired_queued_sessions(pool, 60, 100, Uuid::now_v7(), 30)
                .await
                .unwrap();
        assert!(expired.iter().any(|s| s.id == session));

        // …and it is CLAIMED, so a second replica sweeping the same instant
        // gets nothing. Without this the shed counter and the `RunError` ledger
        // append — both of which happen before the finalization intent picks a
        // winner — would fire once per replica for one expiration.
        let second =
            system_worker::claim_expired_queued_sessions(pool, 60, 100, Uuid::now_v7(), 30)
                .await
                .unwrap();
        assert!(
            !second.iter().any(|s| s.id == session),
            "an expired row is claimed, not handed to every replica"
        );

        // A claimant that dies leaves a lease that lapses; the row then returns
        // to the predicate and the next sweep retries it.
        sqlx::query(
            "update sessions set orchestrator_lease_until = now() - interval '1 second'
             where id = $1",
        )
        .bind(session)
        .execute(pool)
        .await
        .unwrap();
        let reclaimed =
            system_worker::claim_expired_queued_sessions(pool, 60, 100, Uuid::now_v7(), 30)
                .await
                .unwrap();
        assert!(
            reclaimed.iter().any(|s| s.id == session),
            "a lapsed claim returns the row for retry"
        );
        cleanup_sw_tenant(pool, t_auth).await;

        // Adoption: a `created` row orphaned before its park is adopted, but a
        // row a live driver is holding is left alone.
        let (t2, orphan) = seed_tenant_session(pool).await;
        let (t3, driven) = seed_tenant_session(pool).await;
        sqlx::query(
            "update sessions set created_at = now() - interval '10 minutes' where id = any($1)",
        )
        .bind(vec![orphan, driven])
        .execute(pool)
        .await
        .unwrap();
        acquire_session_lease(pool, TenantScope::assume(t3), driven, Uuid::now_v7(), 300)
            .await
            .unwrap()
            .expect("lease");
        let orphans = system_worker::orphaned_created_sessions(pool, 120, 100)
            .await
            .unwrap();
        assert!(orphans.iter().any(|s| s.id == orphan));
        assert!(
            !orphans.iter().any(|s| s.id == driven),
            "a row a live driver owns is not an orphan"
        );

        for t in [tenant, t2, t3] {
            cleanup_sw_tenant(pool, t).await;
        }
        pool.close().await;
    }

    /// Design §3.10 — a LIVE bug in the shipped network-grants feature, not a
    /// queue-only concern. `stale_nonstarted_sessions` aged every pre-launch
    /// status from `created_at`, but `awaiting_authorization` can lawfully park
    /// a run for up to the approval TTL (7 days). A run authorized more than
    /// FLUIDBOX_STALE_LAUNCH_MINS after creation re-entered `provisioning`
    /// carrying an ancient `created_at`, and the next watchdog tick failed it as
    /// "stalled before launch" moments after release. Queued runs inherit the
    /// identical trap, so both are fixed by anchoring launch age to
    /// `launched_at`.
    #[tokio::test]
    async fn stale_launch_sweep_uses_the_launch_anchor_not_created_at() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        use fluidbox_core::state::SessionStatus::*;
        transition_session(&pool, scope, session, Queued, None)
            .await
            .unwrap()
            .unwrap();
        transition_session(&pool, scope, session, Provisioning, None)
            .await
            .unwrap()
            .unwrap();

        // A run that waited two hours before dispatch: created_at is ancient,
        // launched_at is fresh. It is launching normally RIGHT NOW.
        sqlx::query("update sessions set created_at = now() - interval '2 hours' where id = $1")
            .bind(session)
            .execute(&pool)
            .await
            .unwrap();
        let stale = system_worker::stale_nonstarted_sessions(&pool, 30)
            .await
            .unwrap();
        assert!(
            !stale.iter().any(|s| s.id == session),
            "a freshly-launched run must not read as stalled just because it waited"
        );

        // …but an actually-stalled launch (old launched_at) IS swept.
        sqlx::query("update sessions set launched_at = now() - interval '2 hours' where id = $1")
            .bind(session)
            .execute(&pool)
            .await
            .unwrap();
        let stale = system_worker::stale_nonstarted_sessions(&pool, 30)
            .await
            .unwrap();
        assert!(stale.iter().any(|s| s.id == session));

        // And `created` keeps its own anchor: a row that never launched has no
        // launched_at to measure, so created_at remains the only age it has.
        let (tenant2, session2) = seed_tenant_session(&pool).await;
        sqlx::query("update sessions set created_at = now() - interval '2 hours' where id = $1")
            .bind(session2)
            .execute(&pool)
            .await
            .unwrap();
        let stale = system_worker::stale_nonstarted_sessions(&pool, 30)
            .await
            .unwrap();
        assert!(
            stale.iter().any(|s| s.id == session2),
            "an orphaned `created` row is still aged from created_at"
        );

        cleanup_sw_tenant(&pool, tenant).await;
        cleanup_sw_tenant(&pool, tenant2).await;
    }

    /// Phase D (#32, #75) — RLS wave B, system_worker bypass. Proves (b) the
    /// `system_worker` scans see cross-tenant rows THROUGH `worker_tx`, and (c) THE
    /// EXPLICITNESS PROOF: the identically-shaped query WITHOUT `worker_tx` (a plain
    /// runtime-role transaction, no GUC) sees ZERO rows — the bypass is a deliberate,
    /// grep-able choice, never ambient. The `system_worker` fns are exercised through
    /// a pool that `SET ROLE`s to the NON-owner `fluidbox_runtime` (a superuser would
    /// bypass RLS and make the test vacuous).
    #[tokio::test]
    async fn rls_system_worker_bypass_is_explicit() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (ta, sa) = seed_tenant_session(&pool).await;
        let (tb, sb) = seed_tenant_session(&pool).await;

        // Runtime-role pool: the system_worker fns' internal `worker_tx` runs as
        // fluidbox_runtime under FORCE RLS, so the bypass is actually exercised.
        let rt_pool = connect(&url, Some("fluidbox_runtime"))
            .await
            .expect("runtime pool");

        // (b) two representative cross-tenant scans see BOTH tenants' rows.
        let in_status = system_worker::sessions_in_status(&rt_pool, &["created"])
            .await
            .unwrap();
        assert_eq!(
            in_status
                .iter()
                .filter(|s| s.id == sa || s.id == sb)
                .count(),
            2,
            "sessions_in_status (worker_tx) must see BOTH tenants' sessions"
        );
        assert!(
            system_worker::get_session(&rt_pool, sa)
                .await
                .unwrap()
                .is_some(),
            "get_session (worker_tx) resolves tenant A's session cross-tenant"
        );
        assert!(
            system_worker::get_session(&rt_pool, sb)
                .await
                .unwrap()
                .is_some(),
            "get_session (worker_tx) resolves tenant B's session cross-tenant"
        );

        // (c) the SAME shape WITHOUT worker_tx (plain runtime-role tx, no GUC) → 0.
        let mut plain = rt_pool.begin().await.unwrap();
        let (n,): (i64,) = sqlx::query_as("select count(*) from sessions")
            .fetch_one(&mut *plain)
            .await
            .unwrap();
        plain.rollback().await.ok();
        assert_eq!(
            n, 0,
            "a plain runtime-role tx with no bypass GUC must see zero sessions — the bypass is explicit"
        );

        cleanup_sw_tenant(&pool, ta).await;
        cleanup_sw_tenant(&pool, tb).await;
    }

    /// Phase D (#32, #75) — RLS wave B, re-seal helpers under `worker_tx`. Seeds a
    /// v1 sealed connection, then drives the restructured lock/CAS path
    /// (`reseal_begin` → `reseal_lock_row` → `reseal_write_row`) as the NON-owner
    /// runtime role: the lock RESOLVES the row and its tenant, the CAS flips exactly
    /// one v1 row to v2, and — the explicitness half — the same lock WITHOUT
    /// `worker_tx` (a plain runtime tx) resolves nothing.
    #[tokio::test]
    async fn rls_reseal_helpers_work_under_worker_tx() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let tenant = Uuid::now_v7();
        {
            let slug = format!("rls-rs-{}", tenant.simple());
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query("insert into tenants (id, name, slug) values ($1, $2, $3)")
                .bind(tenant)
                .bind(&slug)
                .bind(&slug)
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        let scope = TenantScope::assume(tenant);
        let conn = create_connection(
            &pool,
            scope,
            "mcp_http",
            "acct",
            "disp",
            Some(&[9u8, 9, 9]),
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({ "base_url": "https://x" }),
            None,
            1,
            ConnectionAuth {
                // `integration_connections_auth_kind_shape` (0013) allows only
                // static | oauth | none; a pasted-secret connection is 'static'.
                auth_kind: "static",
                status: "active",
                oauth: None,
                client_secret_sealed: None,
                client_secret_key_version: 1,
                registration_id: None,
            },
            ConnectionOwner::Organization,
            None,
        )
        .await
        .unwrap();

        let rt_pool = connect(&url, Some("fluidbox_runtime"))
            .await
            .expect("runtime pool");
        let (table, col, ver, key) = (
            "integration_connections",
            "credential_sealed",
            "credential_key_version",
            "id",
        );

        // lock + CAS-write through the restructured helpers (tx IS a worker_tx).
        let mut tx = system_worker::reseal_begin(&rt_pool).await.unwrap();
        let locked = system_worker::reseal_lock_row(&mut tx, table, col, ver, key, conn.id)
            .await
            .unwrap();
        let Some((Some(bytes), kv, tid)) = locked else {
            panic!("reseal_lock_row saw no row under worker_tx");
        };
        assert_eq!(kv, 1, "the seeded credential is v1");
        assert_eq!(tid, Some(tenant), "the lock returns the row's own tenant");
        let mut newbytes = bytes.clone();
        newbytes.push(2);
        let affected =
            system_worker::reseal_write_row(&mut tx, table, col, ver, key, conn.id, &newbytes)
                .await
                .unwrap();
        assert_eq!(
            affected, 1,
            "the CAS flips exactly one v1 row to v2 under worker_tx"
        );
        tx.commit().await.unwrap();

        // The companion version is now 2 (read back via the superuser base pool).
        let (after, kv2) = connection_credential_sealed(&pool, scope, conn.id)
            .await
            .unwrap()
            .expect("credential still present");
        assert_eq!(kv2, 2, "credential_key_version is 2 after the CAS");
        assert_eq!(after, newbytes, "the re-sealed bytes landed");

        // Explicitness: the SAME lock WITHOUT worker_tx (plain runtime tx) sees nothing.
        let mut plain = rt_pool.begin().await.unwrap();
        let none = system_worker::reseal_lock_row(&mut plain, table, col, ver, key, conn.id)
            .await
            .unwrap();
        plain.rollback().await.ok();
        assert!(
            none.is_none(),
            "without the bypass GUC the FOR UPDATE lock resolves no row — the reseal bypass is explicit"
        );

        let mut tx = worker_tx(&pool).await.unwrap();
        for stmt in [
            "delete from integration_connections where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            sqlx::query(stmt).bind(tenant).execute(&mut *tx).await.ok();
        }
        tx.commit().await.unwrap();
    }

    /// Review M3: `auth_audit_log` INSERT now carries the SAME tenant floor as every
    /// other tenant-owned write. The old `with check (true)` let a transaction scoped
    /// to tenant A append a row stamped `tenant_id = B` — a forged entry in another
    /// tenant's permanent security history that, because the log is append-only, the
    /// runtime role could never retract.
    ///
    /// Asserted through the NON-superuser `fluidbox_runtime` role (a superuser skips
    /// policies and would make this vacuous). NOTHING is committed: an audit row
    /// cannot be deleted afterwards, so every case runs in its own rolled-back tx.
    #[tokio::test]
    async fn rls_audit_insert_carries_the_tenant_floor() {
        use sqlx::{Connection, Executor};
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        // Apply migrations (incl. the runtime role) then drop that pool immediately.
        connect(&url, None).await.expect("migrate").close().await;
        let mut rt = sqlx::PgConnection::connect(&url).await.expect("rt connect");
        rt.execute("set role fluidbox_runtime")
            .await
            .expect("set role");

        async fn try_insert(
            rt: &mut sqlx::PgConnection,
            guc: Option<(&str, String)>,
            tenant: Option<Uuid>,
        ) -> sqlx::Result<()> {
            let mut tx = rt.begin().await.unwrap();
            if let Some((name, val)) = guc {
                sqlx::query("select set_config($1, $2, true)")
                    .bind(name)
                    .bind(val)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            let res = sqlx::query(
                "insert into auth_audit_log (id, tenant_id, actor_kind, action, success)
                 values ($1, $2, 'operator', 'rls.m3.probe', true)",
            )
            .bind(Uuid::now_v7())
            .bind(tenant)
            .execute(&mut *tx)
            .await
            .map(|_| ());
            tx.rollback().await.ok();
            res
        }
        fn assert_rls_refusal(res: sqlx::Result<()>, what: &str) {
            let err = res
                .err()
                .unwrap_or_else(|| panic!("{what} must be refused"));
            assert!(
                err.to_string()
                    .to_lowercase()
                    .contains("row-level security"),
                "{what}: expected an RLS policy violation, got: {err}"
            );
        }

        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let tid = "fluidbox.tenant_id";
        let bypass = ("fluidbox.bypass", "system_worker".to_string());

        // In-tenant: the ordinary audited mutation, unchanged.
        try_insert(&mut rt, Some((tid, a.to_string())), Some(a))
            .await
            .expect("an in-tenant audit row must still insert");
        // THE FINDING: tenant A cannot write tenant B's history.
        assert_rls_refusal(
            try_insert(&mut rt, Some((tid, a.to_string())), Some(b)).await,
            "a cross-tenant audit insert",
        );
        // A scoped tx cannot forge a deployment-level (NULL-tenant) row either.
        assert_rls_refusal(
            try_insert(&mut rt, Some((tid, a.to_string())), None).await,
            "a NULL-tenant audit insert from a tenant-scoped tx",
        );
        // The old pool-direct path (no GUC at all) is now refused — which is why
        // standalone audits route through `identity::insert_audit_standalone`.
        assert_rls_refusal(
            try_insert(&mut rt, None, Some(a)).await,
            "an audit insert with no GUC",
        );
        // The audited bypass remains the one way to write deployment-level rows.
        try_insert(&mut rt, Some(bypass.clone()), None)
            .await
            .expect("the system_worker bypass must still write NULL-tenant rows");
        try_insert(&mut rt, Some(bypass), Some(b))
            .await
            .expect("the system_worker bypass writes any tenant's row");

        rt.close().await.ok();
    }

    /// Review H1: a runtime role is only trustworthy if its POSTURE is checked, not
    /// just its name. PostgreSQL roles are cluster-global while 0018's grants are
    /// database-local, so on a shared cluster the name may already belong to another
    /// principal — as LOGIN/BYPASSRLS, or granted to somebody else's owner, who could
    /// then `SET ROLE` in and set `fluidbox.bypass`. Each shape must REFUSE.
    ///
    /// Probe roles are uniquely named (tests run in parallel and roles are
    /// cluster-global) and dropped at the end.
    #[tokio::test]
    async fn runtime_role_posture_refuses_unsafe_roles() {
        use sqlx::Connection;
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        // Role DDL cannot take bind parameters; the names are locally generated
        // (`fbx_(probe|other)_<uuid-hex>`), never caller input.
        async fn ddl(c: &mut sqlx::PgConnection, sql: String) -> sqlx::Result<()> {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&mut *c)
                .await
                .map(|_| ())
        }
        let mut c = sqlx::PgConnection::connect(&url).await.expect("connect");
        let probe = format!("fbx_probe_{}", Uuid::now_v7().simple());
        let other = format!("fbx_other_{}", Uuid::now_v7().simple());
        if ddl(&mut c, format!("create role {probe} nologin"))
            .await
            .is_err()
        {
            eprintln!("skipping: this database role cannot CREATE ROLE");
            return;
        }
        ddl(&mut c, format!("create role {other} nologin"))
            .await
            .expect("create the second probe role");

        // A freshly created NOLOGIN role with no memberships is the clean posture.
        assert!(
            check_runtime_role_posture(&mut c, &probe)
                .await
                .unwrap()
                .is_ok(),
            "a NOLOGIN role that is a member of nothing must pass"
        );

        // (a) attributes. LOGIN is settable by any CREATEROLE holder; BYPASSRLS needs
        // superuser, so it is asserted only where the ALTER actually lands.
        ddl(&mut c, format!("alter role {probe} login"))
            .await
            .unwrap();
        let err = check_runtime_role_posture(&mut c, &probe)
            .await
            .unwrap()
            .expect_err("a LOGIN runtime role must be refused");
        assert!(
            err.contains("LOGIN"),
            "refusal must name the attribute: {err}"
        );
        ddl(&mut c, format!("alter role {probe} nologin"))
            .await
            .unwrap();
        if ddl(&mut c, format!("alter role {probe} bypassrls"))
            .await
            .is_ok()
        {
            let err = check_runtime_role_posture(&mut c, &probe)
                .await
                .unwrap()
                .expect_err("a BYPASSRLS runtime role must be refused");
            assert!(
                err.contains("BYPASSRLS"),
                "refusal must name the attribute: {err}"
            );
            ddl(&mut c, format!("alter role {probe} nobypassrls"))
                .await
                .unwrap();
        }

        // (b) THE SHARED-CLUSTER SHAPE: someone else can SET ROLE into it.
        ddl(&mut c, format!("grant {probe} to {other}"))
            .await
            .unwrap();
        let err = check_runtime_role_posture(&mut c, &probe)
            .await
            .unwrap()
            .expect_err("a runtime role granted to another principal must be refused");
        assert!(
            err.contains(&other),
            "refusal must name the foreign member: {err}"
        );
        ddl(&mut c, format!("revoke {probe} from {other}"))
            .await
            .unwrap();

        // (c) inherited privileges we never granted.
        ddl(&mut c, format!("grant {other} to {probe}"))
            .await
            .unwrap();
        let err = check_runtime_role_posture(&mut c, &probe)
            .await
            .unwrap()
            .expect_err("a runtime role inheriting another role must be refused");
        assert!(
            err.contains(&other),
            "refusal must name the inherited role: {err}"
        );
        ddl(&mut c, format!("revoke {other} from {probe}"))
            .await
            .unwrap();

        // A name that does not exist at all is a refusal, never a silent pass.
        assert!(check_runtime_role_posture(&mut c, "fbx_no_such_role_xyz")
            .await
            .unwrap()
            .is_err());

        for r in [&probe, &other] {
            ddl(&mut c, format!("drop role {r}")).await.ok();
        }
        c.close().await.ok();
    }

    /// Review M2: the boot gate reads the EFFECTIVE role of a pooled connection, so
    /// it observes `after_connect SET ROLE` rather than whatever `DATABASE_URL` says.
    /// Under the role split the answer must be "not bypassing" — that is the whole
    /// point of the split, and in multi-user mode boot refuses on anything else.
    #[tokio::test]
    async fn pool_role_bypasses_rls_reads_the_effective_role() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let rt_pool = connect(&url, Some("fluidbox_runtime"))
            .await
            .expect("runtime pool");
        assert_eq!(
            pool_role_bypasses_rls(&rt_pool).await.unwrap(),
            None,
            "a pool that SET ROLEs to fluidbox_runtime must be RLS-BOUND"
        );
        rt_pool.close().await;
    }

    // ─── Durable execution claims (Phase E, #33; Gap 11) ────────────────────
    // DB-backed; self-skip when DATABASE_URL is unset (CI proves them).

    /// Stamp a delivery row's claim directly (bypassing the due scan) so a test
    /// can record consecutive attempts without waiting out the backoff. Under
    /// `worker_tx` (RLS bypass), like the sweeps.
    async fn stamp_delivery_claim(pool: &PgPool, delivery_id: Uuid, owner: Uuid) {
        let mut tx = worker_tx(pool).await.unwrap();
        sqlx::query(
            "update result_deliveries
                set claimed_by = $2, claimed_until = now() + interval '5 minutes'
              where id = $1",
        )
        .bind(delivery_id)
        .bind(owner)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    /// Read the claim + backoff columns a delivery row does not expose on
    /// [`ResultDeliveryRow`] (they are coordination state, deliberately not part of
    /// the serialized API shape). Under `worker_tx`, like the sweeps.
    async fn delivery_claim_state(
        pool: &PgPool,
        delivery_id: Uuid,
    ) -> (
        Option<Uuid>,
        Option<DateTime<Utc>>,
        i32,
        DateTime<Utc>,
        String,
    ) {
        let mut tx = worker_tx(pool).await.unwrap();
        let row = sqlx::query(
            "select claimed_by, claimed_until, attempts, next_attempt_at, status
               from result_deliveries where id = $1",
        )
        .bind(delivery_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        (
            row.get("claimed_by"),
            row.get("claimed_until"),
            row.get("attempts"),
            row.get("next_attempt_at"),
            row.get("status"),
        )
    }

    /// Force a session's status (state-machine-bypassing) so a test can drive
    /// terminality directly. Under `worker_tx` (RLS bypass), like the sweeps.
    async fn force_session_status(pool: &PgPool, session_id: Uuid, status: &str) {
        let mut tx = worker_tx(pool).await.unwrap();
        sqlx::query("update sessions set status = $2 where id = $1")
            .bind(session_id)
            .bind(status)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn claim_won_completed_then_duplicate_adopts_without_redispatch() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);

        // Won.
        let claim_id =
            match claim_tool_execution(&pool, scope, session_id, "tc1", "sha256:aaa", 600)
                .await
                .unwrap()
            {
                ClaimOutcome::Won { claim_id } => claim_id,
                o => panic!("expected Won, got {o:?}"),
            };
        let result = serde_json::json!({
            "content": [{"type":"text","text":"the answer"}], "is_error": false
        });
        assert!(complete_tool_execution(
            &pool,
            scope,
            claim_id,
            "succeeded",
            Some("sha256:res"),
            Some(false),
            Some(&result),
            None,
        )
        .await
        .unwrap()
        .settled());

        // A duplicate for the SAME (session, tool_call_id, digest) adopts the
        // stored outcome — and, the false-green guard: the claim was NOT
        // re-dispatched (attempt stays 1; the stored result is byte-identical).
        // The LIVE single-upstream-request proof rides the hardening e2e (T9 §f).
        match claim_tool_execution(&pool, scope, session_id, "tc1", "sha256:aaa", 600)
            .await
            .unwrap()
        {
            ClaimOutcome::Existing(row) => {
                assert_eq!(row.state, "succeeded");
                assert_eq!(
                    row.attempt, 1,
                    "a duplicate must not re-dispatch (attempt stays 1)"
                );
                assert_eq!(
                    row.result_content.as_ref(),
                    Some(&result),
                    "the duplicate adopts the exact stored result"
                );
            }
            o => panic!("expected Existing(succeeded), got {o:?}"),
        }
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn claim_refuses_a_terminal_session() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        // Cancel-during-approval, brokered half: a terminal (or winding-down)
        // session refuses the claim in the same lock-holding tx as cancellation.
        force_session_status(&pool, session_id, "cancelled").await;
        assert!(
            matches!(
                claim_tool_execution(&pool, scope, session_id, "tc1", "sha256:aaa", 600)
                    .await
                    .unwrap(),
                ClaimOutcome::SessionTerminal
            ),
            "a cancelled session must refuse the claim"
        );
        // Winding-down also refuses.
        force_session_status(&pool, session_id, "finalizing").await;
        assert!(matches!(
            claim_tool_execution(&pool, scope, session_id, "tc2", "sha256:bbb", 600)
                .await
                .unwrap(),
            ClaimOutcome::SessionTerminal
        ));
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn reclaim_is_only_for_failed_before_send() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);

        // failed_before_send IS re-claimable (same row, attempt+1).
        let id = match claim_tool_execution(&pool, scope, session_id, "fbs", "sha256:1", 600)
            .await
            .unwrap()
        {
            ClaimOutcome::Won { claim_id } => claim_id,
            o => panic!("expected Won, got {o:?}"),
        };
        assert!(complete_tool_execution(
            &pool,
            scope,
            id,
            "failed_before_send",
            None,
            Some(false),
            None,
            Some("connect refused"),
        )
        .await
        .unwrap()
        .settled());
        assert_eq!(
            reclaim_failed_before_send(&pool, scope, session_id, "fbs", "sha256:1", 600, 3)
                .await
                .unwrap(),
            ReclaimOutcome::Reclaimed { attempt: 2 },
            "a failed_before_send row must be re-claimable"
        );
        let row = get_tool_execution(&pool, scope, session_id, "fbs", "sha256:1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "claimed");
        assert_eq!(row.attempt, 2, "a re-claim bumps attempt");

        // Every OTHER state refuses the re-claim.
        // 'claimed' (the row we just re-claimed).
        assert_eq!(
            reclaim_failed_before_send(&pool, scope, session_id, "fbs", "sha256:1", 600, 3)
                .await
                .unwrap(),
            ReclaimOutcome::Lost
        );
        // 'succeeded'.
        assert!(complete_tool_execution(
            &pool,
            scope,
            row.id,
            "succeeded",
            None,
            Some(false),
            None,
            None
        )
        .await
        .unwrap()
        .settled());
        assert_eq!(
            reclaim_failed_before_send(&pool, scope, session_id, "fbs", "sha256:1", 600, 3)
                .await
                .unwrap(),
            ReclaimOutcome::Lost
        );
        // 'ambiguous' (a separate claim).
        let id2 = match claim_tool_execution(&pool, scope, session_id, "amb", "sha256:2", 600)
            .await
            .unwrap()
        {
            ClaimOutcome::Won { claim_id } => claim_id,
            o => panic!("expected Won, got {o:?}"),
        };
        assert!(complete_tool_execution(
            &pool,
            scope,
            id2,
            "ambiguous",
            None,
            Some(true),
            None,
            None
        )
        .await
        .unwrap()
        .settled());
        assert_eq!(
            reclaim_failed_before_send(&pool, scope, session_id, "amb", "sha256:2", 600, 3)
                .await
                .unwrap(),
            ReclaimOutcome::Lost
        );
        cleanup_sw_tenant(&pool, tenant).await;
    }

    /// Review I1: the re-claim budget is BOUNDED. A client that keeps
    /// re-presenting one `(session, tool_call_id, input_digest)` against a sick
    /// upstream must stop winning re-claims at the cap — that is what stops the
    /// unmetered `sessions`-row lock churn — and the refusal must be
    /// DISTINGUISHABLE from losing a race, so the caller can answer terminally
    /// instead of polling a row that will never move again.
    #[tokio::test]
    async fn reclaim_is_capped_at_max_attempts() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        const CAP: i32 = 2;

        let id = match claim_tool_execution(&pool, scope, session_id, "cap", "sha256:c", 600)
            .await
            .unwrap()
        {
            ClaimOutcome::Won { claim_id } => claim_id,
            o => panic!("expected Won, got {o:?}"),
        };
        // Attempt 1 (the insert) failed before send → one re-claim is left.
        assert!(complete_tool_execution(
            &pool,
            scope,
            id,
            "failed_before_send",
            None,
            Some(true),
            None,
            Some("connect refused"),
        )
        .await
        .unwrap()
        .settled());
        assert_eq!(
            reclaim_failed_before_send(&pool, scope, session_id, "cap", "sha256:c", 600, CAP)
                .await
                .unwrap(),
            ReclaimOutcome::Reclaimed { attempt: 2 },
            "re-claims within the cap must still be granted"
        );
        // Attempt 2 also failed before send → the budget is spent.
        assert!(complete_tool_execution(
            &pool,
            scope,
            id,
            "failed_before_send",
            None,
            Some(true),
            None,
            Some("connect refused"),
        )
        .await
        .unwrap()
        .settled());
        assert_eq!(
            reclaim_failed_before_send(&pool, scope, session_id, "cap", "sha256:c", 600, CAP)
                .await
                .unwrap(),
            ReclaimOutcome::Exhausted { attempt: CAP },
            "past the cap the re-claim must be refused, not granted"
        );
        // …and refused WITHOUT churning the row: it stays exactly where the last
        // dispatch left it, so nothing accumulates per rejected retry.
        let row = get_tool_execution(&pool, scope, session_id, "cap", "sha256:c")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (row.state.as_str(), row.attempt),
            ("failed_before_send", CAP)
        );
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn stale_claim_sweep_marks_ambiguous() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let id = match claim_tool_execution(&pool, scope, session_id, "stale", "sha256:s", 600)
            .await
            .unwrap()
        {
            ClaimOutcome::Won { claim_id } => claim_id,
            o => panic!("expected Won, got {o:?}"),
        };
        // Force it past expiry, then sweep: a crashed dispatcher's claim → ambiguous.
        // The sweep is a tenant-less GLOBAL scan and the test beside this one
        // expires a claim of its own, so both halves of the GLOBAL_SCAN discipline
        // apply: guard from before the row is stale, read the batch session-scoped.
        let scan = GLOBAL_SCAN.lock().await;
        {
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query(
                "update tool_execution_claims set claim_expires_at = now() - interval '1 minute' where id = $1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let swept = sweep_stale_claims(&pool, session_id).await;
        drop(scan);
        assert!(
            swept
                .iter()
                .any(|(t, s, tc, _)| *t == tenant && *s == session_id && tc == "stale"),
            "the stale claim must be swept and returned with its tenant/session"
        );
        let row = get_tool_execution(&pool, scope, session_id, "stale", "sha256:s")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.state, "ambiguous",
            "a swept stale claim lands in ambiguous"
        );
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn late_complete_loses_to_a_sweep_flipped_row() {
        // T4 rider: a dispatcher that CASes `complete` AFTER the sweeper already
        // flipped its expired claim to `ambiguous` must LOSE — the CAS keys on
        // state='claimed', which the sweep changed. finish_won_claim relies on
        // this false to skip a second (double) tool.brokered ledger row.
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let id = match claim_tool_execution(&pool, scope, session_id, "late", "sha256:l", 600)
            .await
            .unwrap()
        {
            ClaimOutcome::Won { claim_id } => claim_id,
            o => panic!("expected Won, got {o:?}"),
        };
        // The sweeper wins the row (expire → sweep → ambiguous). Guarded even
        // though this test ignores the batch: an unguarded sweep here is what
        // STOLE the neighbouring test's stale claim (3 runs in 6 — GLOBAL_SCAN).
        let scan = GLOBAL_SCAN.lock().await;
        {
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query(
                "update tool_execution_claims set claim_expires_at = now() - interval '1 minute' where id = $1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        assert_eq!(
            sweep_stale_claims(&pool, session_id).await.len(),
            1,
            "this test's own claim is the one the sweep flipped"
        );
        drop(scan);
        // The dispatcher's late completion CAS finds no 'claimed' row → false.
        assert!(
            !complete_tool_execution(&pool, scope, id, "succeeded", None, Some(false), None, None)
                .await
                .unwrap()
                .settled(),
            "a late complete must lose to the sweep's ambiguous row"
        );
        // The durable truth stays `ambiguous` (the swept row was not overwritten).
        let row = get_tool_execution(&pool, scope, session_id, "late", "sha256:l")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "ambiguous");
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn claim_two_tx_race_yields_exactly_one_winner() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let pool2 = pool.clone();
        // Two concurrent transactions on the SAME natural key: the unique index +
        // `on conflict do nothing` make exactly one Win and one adopt (Existing).
        let (a, b) = tokio::join!(
            claim_tool_execution(&pool, scope, session_id, "race", "sha256:r", 600),
            claim_tool_execution(&pool2, scope, session_id, "race", "sha256:r", 600),
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        let mut wins = 0;
        let mut existings = 0;
        for o in [&a, &b] {
            match o {
                ClaimOutcome::Won { .. } => wins += 1,
                ClaimOutcome::Existing(_) => existings += 1,
                ClaimOutcome::SessionTerminal => {}
            }
        }
        assert_eq!(
            wins, 1,
            "exactly one concurrent claim wins the single dispatch"
        );
        assert_eq!(existings, 1, "the loser adopts the existing row");
        cleanup_sw_tenant(&pool, tenant).await;
    }

    // ─── Multi-replica coordination (Phase E, #33; Gap 13) ──────────────────
    // DB-backed; self-skip when DATABASE_URL is unset (CI proves them).

    /// Put an approvals row into `pending` the way the gate does (register the
    /// intent, then promote it), returning the row.
    async fn seed_pending_approval(
        pool: &PgPool,
        scope: TenantScope,
        session_id: Uuid,
        tool_call_id: &str,
        ttl_secs: i64,
    ) -> ApprovalRow {
        let (intent, inserted) = register_tool_intent(
            pool,
            scope,
            session_id,
            tool_call_id,
            "Bash",
            "git push",
            "sha256:args",
        )
        .await
        .unwrap();
        assert!(inserted, "fresh intent");
        promote_intent_to_pending(
            pool,
            scope,
            intent.id,
            Some("high"),
            "once",
            "Bash",
            ttl_secs,
        )
        .await
        .unwrap()
        .expect("promoted to pending")
    }

    /// Count this session's ledger rows by event type.
    async fn count_events(pool: &PgPool, scope: TenantScope, session_id: Uuid, ty: &str) -> usize {
        events_after(pool, scope, session_id, 0, 500)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.r#type == ty)
            .count()
    }

    fn decision_events(
        session_id: Uuid,
        approval_id: Uuid,
        decision: &str,
        decided_by: &str,
    ) -> Vec<Redacted<EventEnvelope>> {
        let r = Redactor::default();
        vec![
            r.scrub(EventEnvelope::new(
                session_id,
                Actor::Human,
                EventBody::ApprovalDecided {
                    approval_id,
                    tool_call_id: "tc-decide".into(),
                    decision: decision.into(),
                    decided_by: decided_by.into(),
                },
            )),
            r.scrub(EventEnvelope::new(
                session_id,
                Actor::System,
                EventBody::ToolDecision {
                    tool_call_id: "tc-decide".into(),
                    tool: "Bash".into(),
                    verdict: "allow".into(),
                    source: "human".into(),
                    original_verdict: None,
                    reason: Some(format!("human:{decided_by}")),
                },
            )),
        ]
    }

    /// The operational mirror follows COMMIT, not append intent, and every
    /// transactional approval event crosses the same seam. This catches both
    /// regressions from PR #181: phantom records for failed appends and missing
    /// records for events appended inside approval transactions.
    #[tokio::test]
    async fn event_mirror_is_commit_accurate_and_covers_approval_transactions() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let approval = seed_pending_approval(&pool, scope, session_id, "tc-decide", 600).await;

        let failed = EventEnvelope::new(
            session_id,
            Actor::System,
            EventBody::RunError {
                message: "must stay tenant-scoped".into(),
            },
        );
        let failed_id = failed.event_id;
        let committed = EventEnvelope::new(
            session_id,
            Actor::System,
            EventBody::QuiesceRequested { deadline_secs: 30 },
        );
        let committed_id = committed.event_id;
        let approval_events =
            decision_events(session_id, approval.id, "approved_once", "mirror-test");
        let approval_ids: Vec<_> = approval_events
            .iter()
            .map(|event| event.get().event_id)
            .collect();

        let writer = fluidbox_obs::capture::CaptureWriter::new();
        let config = fluidbox_obs::LogConfig {
            format: fluidbox_obs::Format::Json,
            filter: "trace".into(),
            throttle_per_sec: 0,
            ..Default::default()
        };
        let (subscriber, _handle) =
            fluidbox_obs::subscriber_with_writer(&config, writer.clone()).unwrap();
        let guard = tracing::subscriber::set_default(subscriber);

        let wrong_scope = TenantScope::assume(Uuid::now_v7());
        assert!(
            append_event(&pool, wrong_scope, Redactor::default().scrub(failed))
                .await
                .is_err(),
            "a cross-tenant append must fail"
        );
        append_event(&pool, scope, Redactor::default().scrub(committed))
            .await
            .unwrap();
        decide_approval_tx(
            &pool,
            scope,
            approval.id,
            "approved_once",
            "mirror-test",
            approval_events,
        )
        .await
        .unwrap()
        .expect("fresh approval decision wins");
        drop(guard);

        let records = writer.json();
        let count = |event_id: Uuid| {
            records
                .iter()
                .filter(|record| record["event_id"] == event_id.to_string())
                .count()
        };
        assert_eq!(
            count(failed_id),
            0,
            "a failed append produced a phantom log"
        );
        assert_eq!(count(committed_id), 1, "ordinary committed event missing");
        for event_id in approval_ids {
            assert_eq!(
                count(event_id),
                1,
                "transactional approval event missing or duplicated"
            );
        }
        cleanup_sw_tenant(&pool, tenant).await;
    }

    /// **THE load-bearing Gap-13 test.** A decided approval ledgers EXACTLY ONE
    /// `approval.decided` and ONE `tool.decision`, no matter how many handlers are
    /// attached to the row.
    ///
    /// Why this would have FAILED before the change: emission used to live in
    /// `await_pending_decision`, which ran it UNCONDITIONALLY for every awakened
    /// waiter — and two waiters on one pending row is an ordinary occurrence (a
    /// `/permission` retry across a runner restart re-attaches while the first
    /// call still blocks; both the has-session-grant branch and the
    /// lost-the-promotion branch fall through to the same wait). Both would wake
    /// on one decision and both would append, giving 2 + 2 (design :1058-1066 —
    /// a single-process bug, not merely a multi-replica one). The events are now
    /// carried BY the decision CAS, so the sequence below — three deciders
    /// racing/retrying one row, exactly as N waiters would — writes one pair.
    #[tokio::test]
    async fn decided_approval_ledgers_exactly_one_pair_however_many_deciders() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let approval = seed_pending_approval(&pool, scope, session_id, "tc-decide", 600).await;

        // Two GENUINELY concurrent deciders (separate pool handles), each carrying
        // its own copy of the events — the shape two re-attached waiters had.
        let pool2 = pool.clone();
        let (a, b) = tokio::join!(
            decide_approval_tx(
                &pool,
                scope,
                approval.id,
                "approved_once",
                "human:alice",
                decision_events(session_id, approval.id, "approved_once", "alice"),
            ),
            decide_approval_tx(
                &pool2,
                scope,
                approval.id,
                "approved_once",
                "human:alice",
                decision_events(session_id, approval.id, "approved_once", "alice"),
            ),
        );
        let winners = [a.unwrap(), b.unwrap()]
            .iter()
            .filter(|o| o.is_some())
            .count();

        // A third, LATER decider (the waiter's own timeout CAS racing a human who
        // already won) must also emit nothing.
        let late = decide_approval_tx(
            &pool,
            scope,
            approval.id,
            "denied",
            "timeout",
            decision_events(session_id, approval.id, "denied", "timeout"),
        )
        .await
        .unwrap();

        let decided = count_events(&pool, scope, session_id, "approval.decided").await;
        let tool_dec = count_events(&pool, scope, session_id, "tool.decision").await;
        cleanup_sw_tenant(&pool, tenant).await;

        assert_eq!(winners, 1, "exactly one concurrent decider wins the CAS");
        assert!(
            late.is_none(),
            "a decider that lost the CAS decides nothing"
        );
        assert_eq!(
            decided, 1,
            "exactly ONE approval.decided per decided approval (was 1-per-waiter)"
        );
        assert_eq!(
            tool_dec, 1,
            "exactly ONE tool.decision per decided approval (was 1-per-waiter)"
        );
    }

    /// The expiry decision site obeys the same rule: single-winner CAS, one pair
    /// of events, and a loser (a human who decided first) writes nothing.
    #[tokio::test]
    async fn expiry_decision_is_single_winner_and_emits_once() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        // Already past its deadline.
        let approval = seed_pending_approval(&pool, scope, session_id, "tc-decide", -60).await;

        // Tenant-less global scan too, but the ONE that needs no GLOBAL_SCAN guard
        // (see the module note): since Phase E it only READS — the decision moved
        // to the scoped, single-winner `expire_approval_tx` below — so a sibling's
        // scan cannot take this row away, and asking whether MY approval is in the
        // batch is already immune to whatever else is in it.
        let scanned = system_worker::expired_pending_approvals(&pool, 100)
            .await
            .unwrap();
        let seen = scanned.iter().any(|r| r.id == approval.id);

        let pool2 = pool.clone();
        let (a, b) = tokio::join!(
            expire_approval_tx(
                &pool,
                scope,
                approval.id,
                decision_events(session_id, approval.id, "expired", "timeout"),
            ),
            expire_approval_tx(
                &pool2,
                scope,
                approval.id,
                decision_events(session_id, approval.id, "expired", "timeout"),
            ),
        );
        let winners = [a.unwrap(), b.unwrap()]
            .iter()
            .filter(|o| o.is_some())
            .count();
        let decided = count_events(&pool, scope, session_id, "approval.decided").await;
        let tool_dec = count_events(&pool, scope, session_id, "tool.decision").await;
        // The post-wait terminal deny: one winner, and (review Minor A) the event
        // now rides the claim's OWN transaction, so "won the marker" and "the event
        // exists" can no longer diverge. Two waiters, two event vectors, one event.
        let deny_event = || {
            vec![Redactor::default().scrub(EventEnvelope::new(
                session_id,
                Actor::System,
                EventBody::ToolDecision {
                    tool_call_id: "tc-decide".into(),
                    tool: "Bash".into(),
                    verdict: "deny".into(),
                    source: "session_terminal".into(),
                    original_verdict: Some("allow".into()),
                    reason: Some("session stopped accepting work during the approval wait".into()),
                },
            ))]
        };
        let m1 = claim_terminal_deny_tx(&pool, scope, approval.id, deny_event())
            .await
            .unwrap();
        let m2 = claim_terminal_deny_tx(&pool, scope, approval.id, deny_event())
            .await
            .unwrap();
        let after_deny = count_events(&pool, scope, session_id, "tool.decision").await;
        cleanup_sw_tenant(&pool, tenant).await;

        assert!(
            seen,
            "the cross-tenant scan finds an over-deadline approval"
        );
        assert_eq!(winners, 1, "exactly one replica expires the row");
        assert_eq!(decided, 1, "expiry ledgers ONE approval.decided");
        assert_eq!(tool_dec, 1, "expiry ledgers ONE tool.decision");
        assert!(m1, "the first terminal-deny claim wins");
        assert!(!m2, "a second waiter's terminal-deny claim emits nothing");
        assert_eq!(
            after_deny,
            tool_dec + 1,
            "the winning claim appended EXACTLY ONE tool.decision, in its own \
             transaction; the loser appended none"
        );
    }

    /// Lease steal matrix + the epoch's defining asymmetry: it moves ONLY on an
    /// owner change. Fresh / self-renew / held-by-another-unexpired / expired.
    #[tokio::test]
    async fn session_lease_steals_on_expiry_and_epoch_moves_only_on_owner_change() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());

        // (1) FRESH: no owner → acquired, epoch 0 → 1 (owner changed null → A).
        let e1 = acquire_session_lease(&pool, scope, session_id, a, 300)
            .await
            .unwrap();
        // (2) SELF-RENEW: same owner keeps the epoch (the fence must not move
        //     under a healthy driver's own feet).
        let e2 = acquire_session_lease(&pool, scope, session_id, a, 300)
            .await
            .unwrap();
        // (3) HELD BY ANOTHER, UNEXPIRED: refused outright.
        let held = acquire_session_lease(&pool, scope, session_id, b, 300)
            .await
            .unwrap();
        // (4) EXPIRED: force the deadline into the past, then B steals — epoch+1.
        {
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query(
                "update sessions set orchestrator_lease_until = now() - interval '1 minute'
                 where id = $1",
            )
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let e3 = acquire_session_lease(&pool, scope, session_id, b, 300)
            .await
            .unwrap();
        let after = session_lease(&pool, scope, session_id).await.unwrap();
        cleanup_sw_tenant(&pool, tenant).await;

        assert_eq!(
            e1,
            Some(1),
            "a fresh acquire is an owner change: epoch 0 → 1"
        );
        assert_eq!(e2, Some(1), "a self-renew must NOT move the epoch");
        assert_eq!(
            held, None,
            "an unexpired lease held by another replica is refused"
        );
        assert_eq!(
            e3,
            Some(2),
            "a steal after expiry is an owner change: epoch+1"
        );
        let (owner, _, epoch) = after.expect("session row");
        assert_eq!(owner, Some(b), "the steal recorded the new owner");
        assert_eq!(epoch, 2);
    }

    /// Source guards for the two Gap-13 SQL predicates whose behavioral tests are
    /// DB-gated (they self-skip without `DATABASE_URL`, so CI is where they run).
    /// These assert the predicates themselves, so deleting either one fails
    /// IMMEDIATELY — with or without a database — instead of silently passing a
    /// skipped suite. Needles are split so this guard is not itself an occurrence.
    #[test]
    fn coordination_sql_predicates_are_present() {
        let src = concat!(
            include_str!("sessions.rs"),
            include_str!("result_deliveries.rs")
        );

        // (1) The epoch is a FENCING TOKEN, not a counter: it moves only when the
        // owner changes. Drop the conditional and a healthy driver's own renew
        // invalidates its in-flight fence — every renew would look like a takeover.
        let epoch_guard = concat!("orchestrator_owner_id is distinct ", "from $3");
        assert!(
            src.contains(epoch_guard),
            "acquire_session_lease must bump orchestrator_epoch ONLY on an owner \
             change (`{epoch_guard}`); an unconditional bump makes a self-renew \
             fence the renewing driver out of its own session"
        );

        // (2) A delivery attempt is recorded only by the replica that HOLDS the
        // row's claim. Drop the guard and a replica whose claim expired mid-attempt
        // stomps the new owner's attempt counter and backoff.
        let claim_guard = concat!("where id = $1 and claimed_", "by = $8");
        assert!(
            src.contains(claim_guard),
            "mark_delivery_attempt must be owner-guarded (`{claim_guard}`) or two \
             replicas can both record attempts on one delivery row"
        );

        // (3) SKIP LOCKED is what makes two replicas' claimed sets DISJOINT; a
        // plain FOR UPDATE would serialize them onto the same rows instead.
        // Scoped to the STATEMENT (the prose above it mentions the clause too, so a
        // whole-file `contains` would be satisfied by the doc comment alone).
        let sw = include_str!("system_worker.rs");
        let stmt_start = sw.find("with due as (").expect("the claim CTE exists");
        let stmt_end = sw[stmt_start..]
            .find("returning d.*")
            .map(|i| stmt_start + i)
            .expect("the claim CTE returns its rows");
        let skip_locked = concat!("for update skip ", "locked");
        assert!(
            sw[stmt_start..stmt_end].contains(skip_locked),
            "claim_due_deliveries's CTE must use `{skip_locked}` so replicas take \
             disjoint slices rather than queueing on each other"
        );

        // (4) The claim scan must EXCLUDE rows another replica currently holds.
        // Without the `claimed_until` half, a replica re-picks a row it just lost
        // and re-runs the external side effect every 3 s tick (review I2); without
        // the `claimed_by = $1` half, our own re-stamped row becomes unreachable to
        // us on the very next pass.
        let scan_pred = "(claimed_until is null or claimed_until < now() or claimed_by = $1)";
        assert!(
            sw[stmt_start..stmt_end].contains(scan_pred),
            "claim_due_deliveries must skip rows another replica holds (`{scan_pred}`)"
        );

        // (5) The per-row re-stamp (review I2) is a strict OWNER CAS, never a
        // steal: a row taken over by another replica must match ZERO rows so the
        // caller skips it BEFORE performing the external side effect. Sliced to the
        // statement — the prose above it discusses `claimed_by` at length.
        let ext_start = src
            .find("pub async fn extend_delivery_claim(")
            .expect("the per-row claim re-stamp exists");
        let ext_end = src[ext_start..]
            .find(".bind(id)")
            .map(|i| ext_start + i)
            .expect("the re-stamp binds its row id");
        let restamp_stmt = &src[ext_start..ext_end];
        let owner_cas = concat!(
            "where id = $1 and claimed_by = $2 and ",
            "status = 'pending'"
        );
        assert!(
            restamp_stmt.contains(owner_cas),
            "extend_delivery_claim must be a strict owner CAS (`{owner_cas}`); a \
             predicate that also matches an EXPIRED claim held by someone else would \
             steal a row mid-flight and duplicate its external side effect"
        );
        let ttl_stamp = "claimed_until = now() + make_interval(secs => $3)";
        assert!(
            restamp_stmt.contains(ttl_stamp),
            "extend_delivery_claim must actually MOVE the deadline (`{ttl_stamp}`), \
             or the TTL still measures from the batch claim rather than this attempt"
        );
    }

    /// Source guard for the review-I1 re-claim CAP. The behavioral test
    /// (`reclaim_is_capped_at_max_attempts`) is DB-gated and self-skips without
    /// `DATABASE_URL`, so deleting the predicate would pass a skipped suite
    /// silently. Sliced to the STATEMENT — the doc comment above it explains the
    /// cap at length and would satisfy a whole-file `contains` on its own.
    #[test]
    fn the_reclaim_attempt_cap_predicate_is_present() {
        let src = include_str!("tool_executions.rs");
        let start = src
            .find("pub async fn reclaim_failed_before_send(")
            .expect("the re-claim exists");
        let end = src[start..]
            .find(".bind(max_attempts)")
            .map(|i| start + i)
            .expect("the re-claim binds its cap");
        let stmt = &src[start..end];
        let cap = concat!("state = 'failed_before_send' and ", "attempt < $6");
        assert!(
            stmt.contains(cap),
            "reclaim_failed_before_send's CAS must carry the attempt cap (`{cap}`). \
             Without it a client looping /tools/call on ONE (tool_call_id, \
             input_digest) against a sick upstream re-claims forever — free of \
             budget, free of ledger, two exclusive sessions-row locks per \
             iteration on the row cancellation itself needs."
        );
    }

    /// I2, behaviorally: a LOST delivery claim must be caught by the per-row
    /// re-stamp (before the external side effect), because the alternative — the
    /// old owner discovering it at `mark_delivery_attempt` — silently drops the
    /// BACKOFF as well as the attempt record, leaving the row immediately due
    /// again in a ~3 s-tick loop that never reaches `max_attempts` and repeats the
    /// external effect every pass.
    #[tokio::test]
    async fn a_lost_delivery_claim_is_caught_before_the_attempt_and_freezes_no_backoff() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        // Enqueue → claim inside one GLOBAL_SCAN window: until the renewal below
        // lands, this row is due (then briefly leased for only 5 s) and any
        // sibling test's claim scan would take it out from under this one.
        let scan = GLOBAL_SCAN.lock().await;
        let dest = serde_json::json!({"kind": "signed_webhook", "url": "http://127.0.0.1:1/cb"});
        let row = enqueue_result_delivery(&pool, scope, session_id, None, &dest)
            .await
            .unwrap();
        let (mine, thief) = (Uuid::now_v7(), Uuid::now_v7());

        // Claimed by us with a DELIBERATELY short TTL (5 s) — the batch stamp the
        // worker starts from; the re-stamp then renews it for the attempt itself.
        let claimed = claim_deliveries(&pool, mine, 10, 5, &[row.id]).await;
        assert!(claimed.iter().any(|c| c.id == row.id), "we claimed the row");
        let before = delivery_claim_state(&pool, row.id).await;
        let renewed = extend_delivery_claim(&pool, scope, row.id, mine, 300)
            .await
            .unwrap();
        let after_renew = delivery_claim_state(&pool, row.id).await;
        drop(scan);

        // Now the thief takes it (as an expired-claim steal would).
        stamp_delivery_claim(&pool, row.id, thief).await;
        let restamp_after_theft = extend_delivery_claim(&pool, scope, row.id, mine, 300)
            .await
            .unwrap();
        // …and the old owner's attempt record is refused, changing NOTHING.
        let marked = mark_delivery_attempt(
            &pool,
            scope,
            row.id,
            mine,
            false,
            Some("stale replica"),
            None,
            30,
            6,
        )
        .await
        .unwrap();
        let after_theft = delivery_claim_state(&pool, row.id).await;
        cleanup_sw_tenant(&pool, tenant).await;

        assert!(renewed, "the holder re-stamps its own claim");
        assert_eq!(before.0, Some(mine), "the batch claim named us");
        assert!(
            after_renew.1 > before.1,
            "the re-stamp must MOVE the deadline (the TTL measures THIS attempt, \
             not the batch claim): {:?} → {:?}",
            before.1,
            after_renew.1
        );
        assert!(
            !restamp_after_theft,
            "a row taken over by another replica must fail the re-stamp — that is \
             the skip that stops the duplicate external call"
        );
        assert!(
            marked.is_none(),
            "the owner guard refuses the stale replica's attempt record"
        );
        assert_eq!(
            (after_theft.2, after_theft.3),
            (after_renew.2, after_renew.3),
            "a refused record leaves attempts AND next_attempt_at untouched — the \
             row stays immediately due, which is precisely why the re-stamp above \
             must catch this first"
        );
        assert_eq!(
            after_theft.0,
            Some(thief),
            "the thief still owns the row (nothing was stomped)"
        );
    }

    /// The fencing token does its job: a driver carrying a STALE epoch mutates
    /// nothing, while the current holder's identical call succeeds.
    #[tokio::test]
    async fn epoch_fence_rejects_a_stale_driver_and_admits_the_holder() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());

        let stale = acquire_session_lease(&pool, scope, session_id, a, 300)
            .await
            .unwrap()
            .unwrap();
        // A steals, stalls; B takes over (epoch moves) — A's token is now stale.
        {
            let mut tx = worker_tx(&pool).await.unwrap();
            sqlx::query(
                "update sessions set orchestrator_lease_until = now() - interval '1 minute'
                 where id = $1",
            )
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let fresh = acquire_session_lease(&pool, scope, session_id, b, 300)
            .await
            .unwrap()
            .unwrap();

        let by_stale = transition_session_fenced(
            &pool,
            scope,
            session_id,
            SessionStatus::Provisioning,
            Some("stale driver"),
            stale,
        )
        .await
        .unwrap();
        let by_holder = transition_session_fenced(
            &pool,
            scope,
            session_id,
            SessionStatus::Provisioning,
            Some("current holder"),
            fresh,
        )
        .await
        .unwrap();
        let status = get_session(&pool, scope, session_id)
            .await
            .unwrap()
            .map(|s| (s.status, s.status_reason));
        cleanup_sw_tenant(&pool, tenant).await;

        assert_ne!(stale, fresh, "a takeover must move the epoch");
        assert!(
            by_stale.is_none(),
            "a stale-epoch driver's lifecycle mutation must affect ZERO rows"
        );
        assert!(by_holder.is_some(), "the current lease holder proceeds");
        assert_eq!(
            status,
            Some(("provisioning".into(), Some("current holder".into()))),
            "only the holder's write landed"
        );
    }

    /// Two replicas polling one due-delivery backlog take DISJOINT sets, and a
    /// replica that no longer holds a row's claim cannot record its attempt.
    #[tokio::test]
    async fn delivery_claims_are_disjoint_and_attempts_are_owner_guarded() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id) = seed_tenant_session(&pool).await;
        let scope = TenantScope::assume(tenant);
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());

        // The backlog these two replicas race for must be exactly the four rows
        // below — a sibling test's due delivery would otherwise eat replica A's
        // `limit` (the scan is FIFO by `next_attempt_at`, so an older foreign row
        // sorts FIRST) and leave A holding rows of a tenant this test cannot even
        // address. Enqueue and both claims therefore share one GLOBAL_SCAN window,
        // and each batch is read back through the owning helper.
        let scan = GLOBAL_SCAN.lock().await;
        let mut ids = Vec::new();
        for i in 0..4 {
            let d = enqueue_result_delivery(
                &pool,
                scope,
                session_id,
                None,
                &serde_json::json!({"kind":"signed_webhook","url":format!("https://x.test/{i}")}),
            )
            .await
            .unwrap();
            ids.push(d.id);
        }

        // Replica A claims two, replica B claims the rest: SKIP LOCKED + the
        // claim stamp make the sets disjoint (B cannot see A's claimed rows).
        let claimed_a = claim_deliveries(&pool, a, 2, 300, &ids).await;
        let claimed_b = claim_deliveries(&pool, b, 10, 300, &ids).await;
        drop(scan);
        let set_a: std::collections::HashSet<Uuid> = claimed_a.iter().map(|r| r.id).collect();
        let set_b: std::collections::HashSet<Uuid> = claimed_b.iter().map(|r| r.id).collect();
        let overlap = set_a.intersection(&set_b).count();

        // B cannot record an attempt on a row A holds.
        let stolen = mark_delivery_attempt(
            &pool,
            scope,
            *set_a.iter().next().unwrap(),
            b,
            false,
            Some("not mine"),
            None,
            30,
            3,
        )
        .await
        .unwrap();
        // A can, and doing so RELEASES the claim.
        let own_id = *set_a.iter().next().unwrap();
        let mine =
            mark_delivery_attempt(&pool, scope, own_id, a, false, Some("refused"), None, 30, 3)
                .await
                .unwrap();
        let released: Option<(Option<Uuid>,)> = {
            let mut tx = worker_tx(&pool).await.unwrap();
            let r = sqlx::query_as("select claimed_by from result_deliveries where id = $1")
                .bind(own_id)
                .fetch_optional(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            r
        };
        cleanup_sw_tenant(&pool, tenant).await;

        assert_eq!(set_a.len(), 2, "the limit bounds a replica's claimed slice");
        assert_eq!(set_b.len(), 2, "the other replica takes what is left");
        assert_eq!(overlap, 0, "two replicas never claim the same delivery row");
        assert!(
            stolen.is_none(),
            "a replica that does not hold the claim cannot record an attempt"
        );
        assert!(mine.is_some(), "the claim holder records its attempt");
        assert_eq!(
            released,
            Some((None,)),
            "recording an attempt releases the claim for the next backoff window"
        );
    }

    // ─── LLM budget reservations (Phase E, #33; Gap 14) ─────────────────────
    // DB-backed; self-skip when DATABASE_URL is unset (CI proves them). The
    // no-DB SOURCE GUARD below keeps the admission predicate mutation-provable
    // locally.

    /// The body of `reserve_llm_budget`, for the source guards below.
    fn reserve_llm_budget_body() -> &'static str {
        let src = include_str!("llm_reservations.rs");
        let start = src
            .find("pub async fn reserve_llm_budget(")
            .expect("reserve_llm_budget exists");
        let end = src[start..]
            .find("pub async fn charge_llm_reservation(")
            .map(|i| start + i)
            .expect("the next fn delimits the body");
        &src[start..end]
    }

    /// The admission statement is the whole fix, so its load-bearing predicates
    /// are asserted from source — a mutation that drops the ceiling guard or
    /// stops counting live reservations fails HERE, with no database.
    #[test]
    fn reserve_llm_budget_sql_keeps_its_load_bearing_predicates() {
        let body = reserve_llm_budget_body();
        for (needle, why) in [
            (
                "for update",
                "the sessions row lock is the SERIALIZER — a CTE alone cannot see a \
                 concurrent transaction's uncommitted reservation, so without this both \
                 racers pass the same guard (Gap 14 returns)",
            ),
            (
                "a.n < $8::bigint as under_ceiling",
                "the finite ceiling on concurrent reservations (design :1118)",
            ),
            (
                "u.tokens + a.tokens + $6::bigint <= $9::bigint",
                "the token projection must include LIVE RESERVATIONS, not just recorded usage",
            ),
            (
                "u.cost + a.cost + coalesce($7::float8, 0) <= $10::float8",
                "the cost projection must include LIVE RESERVATIONS, not just recorded usage",
            ),
        ] {
            assert!(
                body.contains(needle),
                "reserve_llm_budget's SQL lost `{needle}` — {why}"
            );
        }
    }

    /// `active` counts by STATE ALONE. Narrowing it with an expiry predicate
    /// (`… and expires_at > now()`) reopens an UNBUDGETED window between a
    /// reservation expiring and the sweeper converting it: the row would stop
    /// counting against the projection while its spend is still unsettled.
    ///
    /// Review I2: the first cut asserted the bare prefix
    /// `where session_id = $2 and state = 'reserved'`, which that exact mutation
    /// still CONTAINS — the guard passed on the drift it existed to catch. It now
    /// slices the whole `active` sub-select and pins the clause through its
    /// newline terminator, plus a direct refusal of any `expires_at` narrowing.
    #[test]
    fn reserve_llm_budget_counts_active_reservations_by_state_alone() {
        let body = reserve_llm_budget_body();
        let start = body.find("active as (").expect("the `active` CTE exists");
        let end = body[start..]
            .find("guard as (")
            .map(|i| start + i)
            .expect("the `guard` CTE delimits `active`");
        let active = &body[start..end];
        assert!(
            active.contains("where session_id = $2 and state = 'reserved'\n"),
            "the `active` sub-select's WHERE must END at `state = 'reserved'` — anything \
             appended to it (an expiry predicate above all) stops expired-but-unswept rows \
             counting, which is precisely the unbudgeted window this closes"
        );
        assert!(
            !active.contains("expires_at"),
            "`active` must not read expires_at AT ALL: expiry is the SWEEPER's business, \
             and every form of narrowing here reopens the same window"
        );
    }

    /// The SOLE-CLAIMANT carve-out (`a.n = 0`) — the most consequential deviation
    /// from the plan's literal predicate, and the reason a run whose per-request
    /// conservative estimate alone exceeds its remaining budget stops cleanly
    /// instead of livelocking: with nothing else in flight there is nothing to
    /// drain, so refusing forever would never become admitting. Its DB test
    /// discriminates but self-skips without `DATABASE_URL`; this rides every run.
    #[test]
    fn reserve_llm_budget_keeps_the_sole_claimant_carve_out() {
        let body = reserve_llm_budget_body();
        let start = body.find("guard as (").expect("the `guard` CTE exists");
        let end = body[start..]
            .find("ins as (")
            .map(|i| start + i)
            .expect("the `ins` CTE delimits `guard`");
        let guard = &body[start..end];
        for (needle, arm) in [
            ("($9::bigint is null or a.n = 0", "token"),
            ("($10::float8 is null or a.n = 0", "cost"),
        ] {
            assert!(
                guard.contains(needle),
                "the {arm} budget arm lost its `a.n = 0` sole-claimant disjunct — a lone \
                 request would then be refused by its own conservative estimate with no \
                 sibling to drain, livelocking the run instead of stopping it"
            );
        }
        // The carve-out is a DISJUNCT of the budget arms only — it must never
        // reach the ceiling guard, which has to bind even the first request.
        assert!(
            guard.contains("a.n < $8::bigint as under_ceiling"),
            "the ceiling arm must stay unconditional"
        );
    }

    /// Seed a session plus a scope, and give it a settled usage row so the
    /// projection has a non-zero `used` component.
    async fn seed_reservation_session(
        pool: &PgPool,
        used_tokens: i64,
    ) -> (Uuid, Uuid, TenantScope) {
        let (tenant, session_id) = seed_tenant_session(pool).await;
        let scope = TenantScope::assume(tenant);
        if used_tokens > 0 {
            add_usage(
                pool,
                scope,
                session_id,
                "claude-haiku-4-5",
                used_tokens,
                0,
                0,
                0,
                Some(0.01),
                "facade",
                None,
            )
            .await
            .unwrap();
        }
        (tenant, session_id, scope)
    }

    /// Reserve with the fixture's fixed model and TTL — the tests vary only the
    /// numbers they assert on.
    #[allow(clippy::too_many_arguments)]
    async fn reserve(
        pool: &PgPool,
        scope: TenantScope,
        session: Uuid,
        id: Uuid,
        tokens: i64,
        cost: Option<f64>,
        ceiling: i64,
        budget_tokens: Option<i64>,
        budget_cost: Option<f64>,
    ) -> ReserveOutcome {
        reserve_llm_budget(
            pool,
            scope,
            session,
            id,
            "claude-haiku-4-5",
            tokens,
            cost,
            ceiling,
            budget_tokens,
            budget_cost,
            600,
        )
        .await
        .unwrap()
    }

    /// Push a reservation's expiry into the past (what a crashed facade request
    /// looks like to the sweeper).
    async fn expire_reservation(pool: &PgPool, id: Uuid) {
        let mut tx = worker_tx(pool).await.unwrap();
        sqlx::query(
            "update llm_reservations set expires_at = now() - interval '1 minute' where id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn reserve_llm_budget_books_and_settles() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id, scope) = seed_reservation_session(&pool, 100).await;

        let req = Uuid::now_v7();
        assert_eq!(
            reserve(
                &pool,
                scope,
                session_id,
                req,
                500,
                Some(0.02),
                32,
                Some(10_000),
                Some(1.0)
            )
            .await,
            ReserveOutcome::Reserved
        );
        let totals = active_reservation_totals(&pool, scope, session_id)
            .await
            .unwrap();
        assert_eq!((totals.tokens, totals.active), (500, 1));

        // Charge is a one-way CAS: the second call finds no `reserved` row.
        assert!(charge_llm_reservation(&pool, scope, req).await.unwrap());
        assert!(!charge_llm_reservation(&pool, scope, req).await.unwrap());
        assert!(
            !release_llm_reservation(&pool, scope, req).await.unwrap(),
            "a charged reservation can never be released back"
        );
        let row = get_llm_reservation(&pool, scope, req)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "charged");
        let after = active_reservation_totals(&pool, scope, session_id)
            .await
            .unwrap();
        assert_eq!(
            (after.tokens, after.active),
            (0, 0),
            "a charged row stops being active"
        );

        // Release is the mirror image, on a fresh booking.
        let req2 = Uuid::now_v7();
        assert_eq!(
            reserve(
                &pool,
                scope,
                session_id,
                req2,
                500,
                Some(0.02),
                32,
                Some(10_000),
                Some(1.0)
            )
            .await,
            ReserveOutcome::Reserved
        );
        assert!(release_llm_reservation(&pool, scope, req2).await.unwrap());
        assert_eq!(
            get_llm_reservation(&pool, scope, req2)
                .await
                .unwrap()
                .unwrap()
                .state,
            "released"
        );
        assert_eq!(
            active_reservation_totals(&pool, scope, session_id)
                .await
                .unwrap()
                .active,
            0
        );
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn reserve_llm_budget_counts_recorded_usage_and_live_reservations() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        // 600 tokens already recorded against a 1000-token budget.
        let (tenant, session_id, scope) = seed_reservation_session(&pool, 600).await;

        // First booking fits: 600 recorded + 0 live + 300 = 900 <= 1000.
        assert_eq!(
            reserve(
                &pool,
                scope,
                session_id,
                Uuid::now_v7(),
                300,
                None,
                32,
                Some(1000),
                None
            )
            .await,
            ReserveOutcome::Reserved
        );
        // Second is individually small but 600 + 300 + 300 = 1200 > 1000. It is
        // refused ONLY because the LIVE reservation is counted — recorded usage
        // alone (600 + 300) would have passed.
        assert_eq!(
            reserve(
                &pool,
                scope,
                session_id,
                Uuid::now_v7(),
                300,
                None,
                32,
                Some(1000),
                None
            )
            .await,
            ReserveOutcome::BudgetExceeded {
                budget: "max_tokens",
                active: 1
            }
        );
        // The cost arm binds the same way, on its own.
        let (t2, s2, sc2) = seed_reservation_session(&pool, 0).await;
        assert_eq!(
            reserve(
                &pool,
                sc2,
                s2,
                Uuid::now_v7(),
                1,
                Some(0.90),
                32,
                None,
                Some(1.0)
            )
            .await,
            ReserveOutcome::Reserved
        );
        assert_eq!(
            reserve(
                &pool,
                sc2,
                s2,
                Uuid::now_v7(),
                1,
                Some(0.90),
                32,
                None,
                Some(1.0)
            )
            .await,
            ReserveOutcome::BudgetExceeded {
                budget: "max_cost_usd",
                active: 1
            }
        );
        // A run with NO caps is never refused by the budget arms.
        assert_eq!(
            reserve(
                &pool,
                sc2,
                s2,
                Uuid::now_v7(),
                1_000_000,
                Some(999.0),
                32,
                None,
                None
            )
            .await,
            ReserveOutcome::Reserved
        );
        cleanup_sw_tenant(&pool, tenant).await;
        cleanup_sw_tenant(&pool, t2).await;
    }

    /// The SOLE-CLAIMANT rule: with nothing else in flight the budget arms are
    /// skipped, so a lone request whose conservative estimate alone exceeds the
    /// remaining budget still gets to run (it would otherwise 429-livelock with
    /// nothing to drain). The moment a sibling exists, the projection binds.
    #[tokio::test]
    async fn reserve_llm_budget_admits_the_sole_claimant_then_binds() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id, scope) = seed_reservation_session(&pool, 900).await;
        // 900 recorded, budget 1000, this request alone wants 5000.
        assert_eq!(
            reserve(
                &pool,
                scope,
                session_id,
                Uuid::now_v7(),
                5000,
                None,
                32,
                Some(1000),
                None
            )
            .await,
            ReserveOutcome::Reserved,
            "a lone request is admitted — the accumulated check already ruled"
        );
        assert!(matches!(
            reserve(
                &pool,
                scope,
                session_id,
                Uuid::now_v7(),
                1,
                None,
                32,
                Some(1000),
                None
            )
            .await,
            ReserveOutcome::BudgetExceeded { .. }
        ));
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn reserve_llm_budget_enforces_the_concurrency_ceiling() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id, scope) = seed_reservation_session(&pool, 0).await;
        // Ceiling 2, no budget caps at all — only the ceiling can refuse.
        for _ in 0..2 {
            assert_eq!(
                reserve(
                    &pool,
                    scope,
                    session_id,
                    Uuid::now_v7(),
                    1,
                    None,
                    2,
                    None,
                    None
                )
                .await,
                ReserveOutcome::Reserved
            );
        }
        assert_eq!(
            reserve(
                &pool,
                scope,
                session_id,
                Uuid::now_v7(),
                1,
                None,
                2,
                None,
                None
            )
            .await,
            ReserveOutcome::CeilingExceeded {
                active: 2,
                ceiling: 2
            }
        );
        cleanup_sw_tenant(&pool, tenant).await;
    }

    /// THE GAP-14 ACCEPTANCE. Two genuinely concurrent transactions on separate
    /// connections, each individually inside the budget, jointly over it: exactly
    /// ONE may book. This is the race the facade's check-then-record budget lost
    /// every time.
    #[tokio::test]
    async fn reserve_llm_budget_two_tx_race_yields_exactly_one_winner() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id, scope) = seed_reservation_session(&pool, 0).await;
        let pool2 = pool.clone();
        // Budget 1000; each request books 600 — either alone fits, both do not.
        let (a, b) = tokio::join!(
            reserve(
                &pool,
                scope,
                session_id,
                Uuid::now_v7(),
                600,
                None,
                32,
                Some(1000),
                None
            ),
            reserve(
                &pool2,
                scope,
                session_id,
                Uuid::now_v7(),
                600,
                None,
                32,
                Some(1000),
                None
            ),
        );
        let wins = [&a, &b]
            .iter()
            .filter(|o| ***o == ReserveOutcome::Reserved)
            .count();
        assert_eq!(
            wins, 1,
            "exactly one concurrent reservation may take the shared budget (got {a:?} / {b:?})"
        );
        assert!(
            [&a, &b]
                .iter()
                .any(|o| matches!(o, ReserveOutcome::BudgetExceeded { .. })),
            "the loser is refused on the BUDGET, not on some other arm (got {a:?} / {b:?})"
        );
        let totals = active_reservation_totals(&pool, scope, session_id)
            .await
            .unwrap();
        assert_eq!(
            (totals.active, totals.tokens),
            (1, 600),
            "only the winner's booking exists"
        );
        cleanup_sw_tenant(&pool, tenant).await;
    }

    #[tokio::test]
    async fn sweep_converts_expired_reservations_conservatively() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let (tenant, session_id, scope) = seed_reservation_session(&pool, 0).await;
        let req = Uuid::now_v7();
        reserve(
            &pool,
            scope,
            session_id,
            req,
            4242,
            Some(0.25),
            32,
            None,
            None,
        )
        .await;

        // The sweep is a tenant-less GLOBAL scan, so hold the scan guard from
        // before this booking can be swept until this test has swept it, and read
        // every batch through the session-scoped helper (see GLOBAL_SCAN).
        let _scan = GLOBAL_SCAN.lock().await;

        // A live reservation is NOT swept.
        assert!(sweep_reservations(&pool, session_id).await.is_empty());

        expire_reservation(&pool, req).await;
        let swept = sweep_reservations(&pool, session_id).await;
        assert_eq!(swept.len(), 1);
        assert_eq!(swept[0].reserved_tokens, 4242);
        assert_eq!(swept[0].session_id, session_id);
        assert_eq!(
            swept[0].tenant_id, tenant,
            "the swept row carries its OWN tenant — the worker ledgers the \
             conservative charge under exactly this scope"
        );

        // The conservative charge is now real, budget-visible usage…
        let totals = usage_totals(&pool, scope, session_id).await.unwrap();
        assert_eq!(totals.output_tokens, 4242);
        assert!((totals.cost_usd - 0.25).abs() < 1e-9);
        // …and the reservation is settled, so it is no longer double-counted.
        assert_eq!(
            get_llm_reservation(&pool, scope, req)
                .await
                .unwrap()
                .unwrap()
                .state,
            "charged"
        );
        assert_eq!(
            active_reservation_totals(&pool, scope, session_id)
                .await
                .unwrap()
                .active,
            0
        );
        // Idempotent: a second sweep of the same instant finds nothing.
        assert!(sweep_reservations(&pool, session_id).await.is_empty());
        drop(_scan);
        cleanup_sw_tenant(&pool, tenant).await;
    }

    /// The sweeper and a late drain settle the SAME request id, so `add_usage`'s
    /// `on conflict (external_id) do nothing` makes them idempotent in EITHER
    /// order — never a double charge, never a lost charge.
    #[tokio::test]
    async fn sweep_and_late_drain_are_idempotent_in_either_order() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");

        // Order A — sweeper first, drain late. The conservative charge stands;
        // the drain's real usage is the no-op and its CAS loses.
        let (ta, sa, sca) = seed_reservation_session(&pool, 0).await;
        let ra = Uuid::now_v7();
        reserve(&pool, sca, sa, ra, 5000, Some(0.50), 32, None, None).await;
        // Guarded + session-scoped like every other global-scan read (GLOBAL_SCAN):
        // the guard is taken before the booking becomes sweepable and released
        // once this test has swept it.
        let scan_a = GLOBAL_SCAN.lock().await;
        expire_reservation(&pool, ra).await;
        assert_eq!(sweep_reservations(&pool, sa).await.len(), 1);
        drop(scan_a);
        assert!(
            !add_usage(
                &pool,
                sca,
                sa,
                "claude-haiku-4-5",
                7,
                11,
                0,
                0,
                Some(0.001),
                "facade",
                Some(&ra.to_string()),
            )
            .await
            .unwrap(),
            "the late drain's usage row is refused by the external_id conflict"
        );
        assert!(
            !charge_llm_reservation(&pool, sca, ra).await.unwrap(),
            "the late drain's CAS finds an already-charged reservation"
        );
        let a = usage_totals(&pool, sca, sa).await.unwrap();
        assert_eq!(
            (a.requests, a.output_tokens, a.input_tokens),
            (1, 5000, 0),
            "exactly one usage row, and it is the conservative one"
        );

        // Order B — drain first, sweeper late. The REAL usage stands and the
        // sweeper's conservative row is the no-op.
        let (tb, sb, scb) = seed_reservation_session(&pool, 0).await;
        let rb = Uuid::now_v7();
        reserve(&pool, scb, sb, rb, 5000, Some(0.50), 32, None, None).await;
        assert!(add_usage(
            &pool,
            scb,
            sb,
            "claude-haiku-4-5",
            7,
            11,
            0,
            0,
            Some(0.001),
            "facade",
            Some(&rb.to_string()),
        )
        .await
        .unwrap());
        // …crash before the CAS: the row is still `reserved`, so the sweep runs.
        let scan_b = GLOBAL_SCAN.lock().await;
        expire_reservation(&pool, rb).await;
        assert_eq!(sweep_reservations(&pool, sb).await.len(), 1);
        drop(scan_b);
        let b = usage_totals(&pool, scb, sb).await.unwrap();
        assert_eq!(
            (b.requests, b.input_tokens, b.output_tokens),
            (1, 7, 11),
            "exactly one usage row, and the authoritative numbers won"
        );
        assert_eq!(
            get_llm_reservation(&pool, scb, rb)
                .await
                .unwrap()
                .unwrap()
                .state,
            "charged"
        );
        cleanup_sw_tenant(&pool, ta).await;
        cleanup_sw_tenant(&pool, tb).await;
    }
}
