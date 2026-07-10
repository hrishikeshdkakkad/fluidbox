# Phase 3 — Scheduled Borrowing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A schedule is a trigger subscription with a clock: a `schedules` table + a tick worker fire runs through the same `run_service::create_run` with `InvocationContext.kind = schedule`, exactly-once via deterministic idempotency-claim keys, with overlap (`allow|skip_if_running|replace`) and missed-run (`skip|catch_up`) policies, schedule status in the dashboard, and a new e2e acceptance phase.

**Architecture:** New pure-domain module `fluidbox-core/src/schedule.rs` (cron parsing + DST-correct next-fire via `cron` + `chrono-tz`); migration 0004 (schedules table, `concurrency_policy` on `trigger_subscriptions`, `skip_reason` on `trigger_invocations`); concurrency enforcement inside the one `run_service::create_run` (all invocations honor it); a `scheduler.rs` worker shaped like `deliveries.rs`. Result delivery (Phase 2) is reused unchanged.

**Tech Stack:** Rust (axum/sqlx/tokio), Neon Postgres, Next.js dashboard (presentation-only), bash e2e.

## Global Constraints

- Backend 100% Rust; dashboard presentation-only; DB is Neon Postgres (CLAUDE.md hard constraints).
- **§17 #5 SETTLED (user, 2026-07-10):** overlap default `allow`; missed-run default `skip`; `concurrency_policy` enforced for **ALL** invocations (API invokes too) inside `run_service::create_run`. `skip_if_running`/`replace`/`catch_up` are per-subscription opt-ins.
- Never fire-all-missed: a missed gap produces at most ONE catch-up run (policy `catch_up`) or ONE recorded skip (policy `skip`).
- Every entry point converges on `run_service::create_run`; RunSpec frozen at creation; server is the single status writer; ledger accepts only `Redacted<EventEnvelope>` (no new event types needed).
- Skips must be **visibly recorded** — they live on the `trigger_invocations` claim rows (`skip_reason`), never silently dropped.
- No new env vars. Do not touch the permission/approval path.
- DB-gated tests need `set -a; source .env; set +a` first (direct Neon URL).
- Phase is done only when `just check` AND `just e2e` are fully green (including the NEW e2e phase). Do NOT start Phase 4.
- Commit after every task. End commit messages with:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` and the Claude-Session trailer used by this session.

## File Structure

- Create: `crates/fluidbox-core/src/schedule.rs` — pure cron/policy domain (no I/O).
- Create: `migrations/0004_schedules.sql`.
- Create: `crates/fluidbox-server/src/scheduler.rs` — tick worker.
- Create: `scripts/e2e-schedule.sh` — new acceptance phase.
- Modify: `Cargo.toml` (workspace deps), `crates/fluidbox-core/Cargo.toml`, `crates/fluidbox-core/src/lib.rs`.
- Modify: `crates/fluidbox-db/src/lib.rs` — schedules CRUD, skip-aware claims, atomic bind, `concurrency_policy` column plumbing.
- Modify: `crates/fluidbox-server/src/run_service.rs` (RunCreation outcome + concurrency gate), `orchestrator.rs` (cancel reason), `api.rs` (caller updates), `triggers.rs` (schedule create + invoke changes), `main.rs` (wire worker).
- Modify: `apps/web/app/lib/api.ts`, `apps/web/app/triggers/page.tsx`.
- Modify: `scripts/e2e.sh`, `docs/HANDOVER.md`, `CLAUDE.md`.

---

### Task 1: Cron schedule domain in fluidbox-core

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.dependencies]`)
- Modify: `crates/fluidbox-core/Cargo.toml`
- Modify: `crates/fluidbox-core/src/lib.rs`
- Create: `crates/fluidbox-core/src/schedule.rs`

**Interfaces:**
- Produces: `fluidbox_core::schedule::{ConcurrencyPolicy, MissedRunPolicy, CronSchedule}`
  - `ConcurrencyPolicy::{Allow, SkipIfRunning, Replace}` with `parse(&str) -> Option<Self>` and `as_str(&self) -> &'static str` (strings: `allow`, `skip_if_running`, `replace`; `Default = Allow`)
  - `MissedRunPolicy::{Skip, CatchUp}` with `parse`/`as_str` (strings: `skip`, `catch_up`; `Default = Skip`)
  - `CronSchedule::parse(cron_expr: &str, timezone: &str) -> Result<CronSchedule, String>`
  - `CronSchedule::next_fire_after(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>>`

- [ ] **Step 1: Add dependencies**

In root `Cargo.toml` `[workspace.dependencies]`, after the `chrono = …` line add:

```toml
chrono-tz = "0.10"
cron = "0.17"
```

In `crates/fluidbox-core/Cargo.toml` `[dependencies]` add:

```toml
chrono-tz.workspace = true
cron.workspace = true
```

- [ ] **Step 2: Write the failing tests**

Create `crates/fluidbox-core/src/schedule.rs` with the module doc, empty stubs NOT yet — write the full file in Step 4; first register the module and write tests. Practical TDD here: create the file with types + `todo!()` bodies so tests compile, or write the complete file and watch tests pass — for a pure module, write tests FIRST inside the new file:

```rust
//! Cron schedule domain (design doc §6.2). Pure: parsing, validation, and
//! DST-correct next-fire computation — no clock, no I/O; the scheduler
//! worker supplies `now`. §17 #5 (settled 2026-07-10): overlap default
//! `allow`, missed-run default `skip`; catch_up fires exactly ONE run —
//! fire-all-missed is a thundering herd and is not representable here.

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use std::str::FromStr;

/// What happens when a firing (or API invoke) comes due while a previous
/// run of the same subscription is still active. Enforced for ALL
/// invocations inside `run_service::create_run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConcurrencyPolicy {
    #[default]
    Allow,
    SkipIfRunning,
    Replace,
}

impl ConcurrencyPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "skip_if_running" => Some(Self::SkipIfRunning),
            "replace" => Some(Self::Replace),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::SkipIfRunning => "skip_if_running",
            Self::Replace => "replace",
        }
    }
}

/// What happens when the scheduler discovers fire times in the past
/// (control plane down, or the subscription was disabled across them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MissedRunPolicy {
    #[default]
    Skip,
    CatchUp,
}

impl MissedRunPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "skip" => Some(Self::Skip),
            "catch_up" => Some(Self::CatchUp),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::CatchUp => "catch_up",
        }
    }
}

/// A parsed cron expression bound to an explicit IANA timezone. The `cron`
/// crate wants a seconds field, so a standard 5-field expression gets
/// second 0 prepended; 6/7-field expressions pass through — the seconds
/// field doubles as the e2e fire-fast seam (sub-minute cadence).
pub struct CronSchedule {
    schedule: cron::Schedule,
    tz: Tz,
}

impl CronSchedule {
    pub fn parse(cron_expr: &str, timezone: &str) -> Result<Self, String> {
        let tz = Tz::from_str(timezone).map_err(|_| {
            format!("unknown timezone '{timezone}' (use an IANA name like 'America/New_York' or 'UTC')")
        })?;
        let expr = cron_expr.trim();
        let normalized = match expr.split_whitespace().count() {
            5 => format!("0 {expr}"),
            6 | 7 => expr.to_string(),
            n => {
                return Err(format!(
                    "cron expression has {n} fields; want 5 (min hour dom mon dow) or 6-7 (with seconds)"
                ))
            }
        };
        let schedule = cron::Schedule::from_str(&normalized)
            .map_err(|e| format!("invalid cron expression: {e}"))?;
        Ok(Self { schedule, tz })
    }

    /// Next fire time strictly after `after`, computed in the schedule's
    /// timezone (DST-correct), returned in UTC. None = no future firing.
    pub fn next_fire_after(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.schedule
            .after(&after.with_timezone(&self.tz))
            .next()
            .map(|t| t.with_timezone(&Utc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn policies_parse_and_roundtrip() {
        assert_eq!(ConcurrencyPolicy::parse("allow"), Some(ConcurrencyPolicy::Allow));
        assert_eq!(
            ConcurrencyPolicy::parse("skip_if_running"),
            Some(ConcurrencyPolicy::SkipIfRunning)
        );
        assert_eq!(ConcurrencyPolicy::parse("replace"), Some(ConcurrencyPolicy::Replace));
        assert_eq!(ConcurrencyPolicy::parse("sometimes"), None);
        assert_eq!(ConcurrencyPolicy::default().as_str(), "allow"); // §17 #5
        assert_eq!(MissedRunPolicy::parse("skip"), Some(MissedRunPolicy::Skip));
        assert_eq!(MissedRunPolicy::parse("catch_up"), Some(MissedRunPolicy::CatchUp));
        assert_eq!(MissedRunPolicy::parse("fire_all"), None);
        assert_eq!(MissedRunPolicy::default().as_str(), "skip"); // §17 #5
    }

    #[test]
    fn five_field_cron_is_normalized_and_six_field_passes_through() {
        // Standard cron (no seconds) — fires at second 0.
        let s = CronSchedule::parse("*/5 * * * *", "UTC").unwrap();
        let n = s.next_fire_after(utc("2026-07-10T00:01:00Z")).unwrap();
        assert_eq!(n, utc("2026-07-10T00:05:00Z"));
        // Seconds field (the e2e fire-fast seam).
        let s = CronSchedule::parse("*/5 * * * * *", "UTC").unwrap();
        let n = s.next_fire_after(utc("2026-07-10T00:00:01Z")).unwrap();
        assert_eq!(n, utc("2026-07-10T00:00:05Z"));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(CronSchedule::parse("*/5 * * * *", "Mars/Olympus").is_err());
        assert!(CronSchedule::parse("not a cron", "UTC").is_err());
        assert!(CronSchedule::parse("* * * *", "UTC").is_err()); // 4 fields
        assert!(CronSchedule::parse("99 * * * * *", "UTC").is_err()); // bad seconds
    }

    #[test]
    fn next_fire_is_dst_correct() {
        // America/New_York springs forward 2026-03-08 (EST -5 → EDT -4).
        // Daily 09:30 local must be 14:30Z before and 13:30Z after.
        let s = CronSchedule::parse("0 30 9 * * *", "America/New_York").unwrap();
        assert_eq!(
            s.next_fire_after(utc("2026-03-06T00:00:00Z")).unwrap(),
            utc("2026-03-06T14:30:00Z")
        );
        assert_eq!(
            s.next_fire_after(utc("2026-03-09T00:00:00Z")).unwrap(),
            utc("2026-03-09T13:30:00Z")
        );
        // Fixed +05:30 offset (no DST): 09:00 Kolkata = 03:30Z.
        let s = CronSchedule::parse("0 0 9 * * *", "Asia/Kolkata").unwrap();
        assert_eq!(
            s.next_fire_after(utc("2026-07-10T00:00:00Z")).unwrap(),
            utc("2026-07-10T03:30:00Z")
        );
    }

    #[test]
    fn next_fire_is_strictly_after() {
        let s = CronSchedule::parse("*/5 * * * * *", "UTC").unwrap();
        // `after` exactly on a fire boundary → the NEXT slot, never the same.
        let n = s.next_fire_after(utc("2026-07-10T00:00:05Z")).unwrap();
        assert_eq!(n, utc("2026-07-10T00:00:10Z"));
    }
}
```

In `crates/fluidbox-core/src/lib.rs` add `pub mod schedule;` alongside the existing module declarations.

- [ ] **Step 3: Run the tests**

Run: `cargo test -p fluidbox-core schedule::`
Expected: PASS (5 tests). If the DST assertion fails, print the actual value the `cron` crate computes, verify it is the correct IANA behavior by hand (EST=UTC-5, EDT=UTC-4), and pin the test to the verified-correct value — the invariant being proven is that the UTC instant tracks the timezone's offset change.

- [ ] **Step 4: fmt + clippy + commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

```bash
git add Cargo.toml Cargo.lock crates/fluidbox-core
git commit -m "core: cron schedule domain — DST-correct next-fire + overlap/missed policies (§17 #5 settled: allow/skip defaults)"
```

---

### Task 2: Migration 0004 + fluidbox-db layer

**Files:**
- Create: `migrations/0004_schedules.sql`
- Modify: `crates/fluidbox-db/src/lib.rs`

**Interfaces:**
- Consumes: nothing new (self-contained DB layer).
- Produces (all in `fluidbox_db`):
  - `ScheduleRow { id, subscription_id, cron: String, timezone: String, next_fire_at: Option<DateTime<Utc>>, missed_run_policy: String, last_fired_at: Option<DateTime<Utc>>, created_at, updated_at }`
  - `create_schedule(pool, subscription: Uuid, cron: &str, timezone: &str, next_fire_at: DateTime<Utc>, missed_run_policy: &str) -> sqlx::Result<ScheduleRow>`
  - `schedule_for_subscription(pool, subscription: Uuid) -> sqlx::Result<Option<ScheduleRow>>`
  - `schedules_for_tenant(pool, tenant: Uuid) -> sqlx::Result<Vec<ScheduleRow>>`
  - `due_schedules(pool, limit: i64) -> sqlx::Result<Vec<ScheduleRow>>`
  - `advance_schedule(pool, id: Uuid, from: DateTime<Utc>, to: Option<DateTime<Utc>>, fired_at: Option<DateTime<Utc>>) -> sqlx::Result<bool>`
  - `mark_invocation_skipped(pool, invocation: Uuid, reason: &str) -> sqlx::Result<()>`
  - `TriggerInvocationRow { id, subscription_id, idempotency_key: String, session_id: Option<Uuid>, skip_reason: Option<String>, created_at }`
  - `list_subscription_invocations(pool, subscription: Uuid, limit: i64) -> sqlx::Result<Vec<TriggerInvocationRow>>`
  - `active_subscription_sessions(pool, subscription: Uuid) -> sqlx::Result<Vec<SessionRow>>`
  - `InvocationClaim` gains variant `Skipped { reason: String }`
  - `create_session(…, trigger: Option<&Value>, bind_invocation: Option<Uuid>)` — new last param, atomic bind in the same transaction; standalone `bind_invocation()` fn is REMOVED
  - `TriggerSubscriptionRow` gains `pub concurrency_policy: String`; `create_trigger_subscription` gains `concurrency_policy: &str` param (positioned right after `autonomy`)

- [ ] **Step 1: Write the migration**

Create `migrations/0004_schedules.sql`:

```sql
-- Phase 3 of "borrow the agent, on demand": scheduled borrowing
-- (design doc §6.2/§10/§12 Phase 3).
-- §17 #5 settled 2026-07-10: overlap default 'allow', missed-run default
-- 'skip'; concurrency_policy is enforced for ALL invocations inside
-- run_service::create_run (API invokes and schedule firings alike).

-- Deferred from Phase 2 so config never lies; now create_run enforces it.
-- allow | skip_if_running | replace.
alter table trigger_subscriptions
    add column concurrency_policy text not null default 'allow';

-- A skipped firing is recorded on the SAME claim table that makes firing
-- exactly-once: every scheduled fire time ends as exactly one row — bound
-- to a session, or marked skipped (overlap | missed | error: …). Skipped
-- rows are terminal: never re-claimable, never stealable.
alter table trigger_invocations add column skip_reason text;

-- The clock on a subscription (§6.2): a schedule is NOT a new kind of
-- object — subscription_id is unique, enabled-ness rides the subscription
-- (a disabled subscription's schedule does not advance; the gap becomes a
-- missed-run case on re-enable, same as a scheduler outage), and each
-- firing is an ordinary run through run_service::create_run.
create table schedules (
    id uuid primary key,
    subscription_id uuid not null unique references trigger_subscriptions(id) on delete cascade,
    cron text not null,
    timezone text not null,                 -- explicit IANA name; DST-correct
    next_fire_at timestamptz,               -- null = no future firing
    missed_run_policy text not null default 'skip',  -- skip | catch_up
    last_fired_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index schedules_due on schedules(next_fire_at) where next_fire_at is not null;
```

- [ ] **Step 2: Subscription row plumbing**

In `crates/fluidbox-db/src/lib.rs`:

1. Add to `TriggerSubscriptionRow` (after `autonomy`):

```rust
    pub concurrency_policy: String,
```

2. In `SUBSCRIPTION_COLS`, add `concurrency_policy` after `autonomy`:

```rust
const SUBSCRIPTION_COLS: &str = "id, tenant_id, agent_id, name, trigger_kind, pinned_revision_id, \
     enabled, task_template, allow_task_override, allow_workspace_override, autonomy, \
     concurrency_policy, budget_override, workspace_override, result_destinations, created_at, updated_at";
```

3. `create_trigger_subscription`: add param `concurrency_policy: &str` right after `autonomy: Option<&str>`; add `concurrency_policy` to the insert column list after `autonomy` and a `$` placeholder (renumber to `$1..$15`), and `.bind(concurrency_policy)` after `.bind(autonomy)`.

- [ ] **Step 3: Skip-aware claims + atomic bind**

1. Add the variant to `InvocationClaim`:

```rust
    /// This key's firing was skipped (overlap | missed | error: …) — a
    /// terminal outcome; replays of the key return it forever.
    Skipped { reason: String },
```

2. In `claim_invocation`, change the existing-row select to include `skip_reason` and branch on it after the `session_id` check:

```rust
    let existing = sqlx::query(
        "select id, session_id, request_digest, skip_reason, created_at from trigger_invocations
         where subscription_id = $1 and idempotency_key = $2",
    )
```

after the `if let Some(session_id) = … { return Ok(InvocationClaim::Replay {…}) }` block add:

```rust
    if let Some(reason) = existing.get::<Option<String>, _>("skip_reason") {
        return Ok(InvocationClaim::Skipped { reason });
    }
```

3. In the takeover update, add `and skip_reason is null` to the `where` clause (after `session_id is null`).

4. Add after `release_invocation`:

```rust
/// A skipped firing is the terminal state of its claim row: visibly
/// recorded, never re-claimable. Guarded on session_id so a bound run can
/// never be relabelled a skip.
pub async fn mark_invocation_skipped(
    pool: &PgPool,
    invocation: Uuid,
    reason: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "update trigger_invocations set skip_reason = $2
         where id = $1 and session_id is null",
    )
    .bind(invocation)
    .bind(reason)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TriggerInvocationRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub idempotency_key: String,
    pub session_id: Option<Uuid>,
    pub skip_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub async fn list_subscription_invocations(
    pool: &PgPool,
    subscription: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<TriggerInvocationRow>> {
    sqlx::query_as(
        "select id, subscription_id, idempotency_key, session_id, skip_reason, created_at
         from trigger_invocations where subscription_id = $1
         order by created_at desc limit $2",
    )
    .bind(subscription)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Non-terminal runs of a subscription — the concurrency-policy input.
pub async fn active_subscription_sessions(
    pool: &PgPool,
    subscription: Uuid,
) -> sqlx::Result<Vec<SessionRow>> {
    sqlx::query_as(
        "select s.* from sessions s
         join trigger_invocations i on i.session_id = s.id
         where i.subscription_id = $1
           and s.status not in ('completed','failed','cancelled','budget_exceeded')
         order by s.created_at",
    )
    .bind(subscription)
    .fetch_all(pool)
    .await
}
```

5. `create_session`: add final param `bind_invocation: Option<Uuid>` and make the insert + bind one transaction (this is what makes scheduler firing exactly-once — a crash can never leave a created run unclaimed, so the 60s claim takeover can never re-fire it):

```rust
#[allow(clippy::too_many_arguments)]
pub async fn create_session(
    pool: &PgPool,
    tenant: Uuid,
    agent_id: Uuid,
    agent_revision_id: Uuid,
    autonomy: &str,
    task: &str,
    repo_source: &Value,
    run_spec: &Value,
    budgets: &Value,
    trigger: Option<&Value>,
    bind_invocation: Option<Uuid>,
) -> sqlx::Result<SessionRow> {
    let mut tx = pool.begin().await?;
    let row: SessionRow = sqlx::query_as(
        "insert into sessions
           (id, tenant_id, agent_id, agent_revision_id, autonomy, task, repo_source, run_spec, budgets, trigger)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(tenant)
    .bind(agent_id)
    .bind(agent_revision_id)
    .bind(autonomy)
    .bind(task)
    .bind(repo_source)
    .bind(run_spec)
    .bind(budgets)
    .bind(trigger)
    .fetch_one(&mut *tx)
    .await?;
    // Atomic claim bind: the run and its idempotency claim commit together,
    // so a crash can never orphan a created run from its claim (which would
    // let the stale-claim takeover duplicate it).
    if let Some(invocation) = bind_invocation {
        sqlx::query("update trigger_invocations set session_id = $2 where id = $1")
            .bind(invocation)
            .bind(row.id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(row)
}
```

6. DELETE the standalone `pub async fn bind_invocation(…)` (replaced by the atomic path; `release_invocation` stays).

7. Fix existing `create_session` call sites in the `#[cfg(test)] mod tests` (there are three: seq test, stale-sweep test if it calls it, delivery test, workspace test — grep `create_session(` in the tests module) by adding a final `None` argument.

- [ ] **Step 4: Schedules CRUD**

Add a new section after the result-deliveries section:

```rust
// ─── Schedules (Phase 3: the clock on a subscription) ────────────────────

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ScheduleRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub cron: String,
    pub timezone: String,
    pub next_fire_at: Option<DateTime<Utc>>,
    pub missed_run_policy: String,
    pub last_fired_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn create_schedule(
    pool: &PgPool,
    subscription: Uuid,
    cron: &str,
    timezone: &str,
    next_fire_at: DateTime<Utc>,
    missed_run_policy: &str,
) -> sqlx::Result<ScheduleRow> {
    sqlx::query_as(
        "insert into schedules (id, subscription_id, cron, timezone, next_fire_at, missed_run_policy)
         values ($1, $2, $3, $4, $5, $6) returning *",
    )
    .bind(Uuid::now_v7())
    .bind(subscription)
    .bind(cron)
    .bind(timezone)
    .bind(next_fire_at)
    .bind(missed_run_policy)
    .fetch_one(pool)
    .await
}

pub async fn schedule_for_subscription(
    pool: &PgPool,
    subscription: Uuid,
) -> sqlx::Result<Option<ScheduleRow>> {
    sqlx::query_as("select * from schedules where subscription_id = $1")
        .bind(subscription)
        .fetch_optional(pool)
        .await
}

pub async fn schedules_for_tenant(pool: &PgPool, tenant: Uuid) -> sqlx::Result<Vec<ScheduleRow>> {
    sqlx::query_as(
        "select sc.* from schedules sc
         join trigger_subscriptions sub on sub.id = sc.subscription_id
         where sub.tenant_id = $1",
    )
    .bind(tenant)
    .fetch_all(pool)
    .await
}

/// Due work for the (single, sequential) scheduler worker — same no-locking
/// contract as due_result_deliveries. A disabled subscription's schedule is
/// not due and does NOT advance: re-enabling turns the gap into a
/// missed-run case, exactly like a scheduler outage.
pub async fn due_schedules(pool: &PgPool, limit: i64) -> sqlx::Result<Vec<ScheduleRow>> {
    sqlx::query_as(
        "select sc.* from schedules sc
         join trigger_subscriptions sub on sub.id = sc.subscription_id
         where sc.next_fire_at is not null and sc.next_fire_at <= now() and sub.enabled
         order by sc.next_fire_at limit $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// CAS advance: only moves the clock if next_fire_at is still the fire time
/// this worker processed — two workers can never double-advance past an
/// unhandled fire time.
pub async fn advance_schedule(
    pool: &PgPool,
    id: Uuid,
    from: DateTime<Utc>,
    to: Option<DateTime<Utc>>,
    fired_at: Option<DateTime<Utc>>,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        "update schedules set
            next_fire_at = $2,
            last_fired_at = coalesce($3, last_fired_at),
            updated_at = now()
         where id = $1 and next_fire_at = $4",
    )
    .bind(id)
    .bind(to)
    .bind(fired_at)
    .bind(from)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}
```

- [ ] **Step 5: DB integration test (Neon-gated, self-skipping)**

Append to the `#[cfg(test)] mod tests` in `crates/fluidbox-db/src/lib.rs`:

```rust
    #[tokio::test]
    async fn schedule_lifecycle_and_skip_claims() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let tenant = ensure_default_tenant(&pool).await.unwrap();
        let agent = create_agent(&pool, tenant, "test-sched-agent", None)
            .await
            .unwrap();
        let sub = create_trigger_subscription(
            &pool,
            tenant,
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
        )
        .await
        .unwrap();
        assert_eq!(sub.concurrency_policy, "skip_if_running");

        // Overdue schedule → due; disabled subscription → not due.
        let past = Utc::now() - chrono::Duration::seconds(1);
        let sched = create_schedule(&pool, sub.id, "*/5 * * * * *", "UTC", past, "skip")
            .await
            .unwrap();
        assert!(due_schedules(&pool, 50).await.unwrap().iter().any(|s| s.id == sched.id));
        set_trigger_subscription_enabled(&pool, sub.id, false).await.unwrap();
        assert!(!due_schedules(&pool, 50).await.unwrap().iter().any(|s| s.id == sched.id));
        set_trigger_subscription_enabled(&pool, sub.id, true).await.unwrap();

        // Deterministic fire key: claim once, mark skipped, replay the skip.
        let key = "sched:2026-07-10T00:00:00Z";
        let claim = claim_invocation(&pool, sub.id, key, "d1").await.unwrap();
        let InvocationClaim::Claimed { invocation_id } = claim else {
            panic!("expected Claimed, got {claim:?}");
        };
        mark_invocation_skipped(&pool, invocation_id, "missed").await.unwrap();
        let again = claim_invocation(&pool, sub.id, key, "d1").await.unwrap();
        let InvocationClaim::Skipped { reason } = again else {
            panic!("expected Skipped, got {again:?}");
        };
        assert_eq!(reason, "missed");
        let inv = list_subscription_invocations(&pool, sub.id, 10).await.unwrap();
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0].skip_reason.as_deref(), Some("missed"));
        assert!(inv[0].session_id.is_none());

        // CAS advance: succeeds from the processed fire time, then refuses.
        let future = Utc::now() + chrono::Duration::seconds(60);
        assert!(advance_schedule(&pool, sched.id, past, Some(future), None).await.unwrap());
        assert!(!advance_schedule(&pool, sched.id, past, Some(future), None).await.unwrap());
        let row = schedule_for_subscription(&pool, sub.id).await.unwrap().unwrap();
        assert_eq!(row.next_fire_at, Some(future));
        assert!(row.last_fired_at.is_none()); // skips never touch last_fired_at
        assert!(!due_schedules(&pool, 50).await.unwrap().iter().any(|s| s.id == sched.id));

        // Cleanup (cascades schedules + invocations).
        sqlx::query("delete from trigger_subscriptions where id = $1")
            .bind(sub.id)
            .execute(&pool)
            .await
            .unwrap();
    }
```

Note: `advance_schedule` binds/compares timestamps — Postgres timestamptz has microsecond precision while chrono has nanoseconds, so the CAS `next_fire_at = $4` compare works because `past` round-trips through the same insert. If the second assert fails on precision, truncate in the test: `let past = past - chrono::Duration::nanoseconds(past.timestamp_subsec_nanos() as i64 % 1_000);` — do NOT loosen the SQL.

- [ ] **Step 6: Fix the one production `create_session` caller**

`crates/fluidbox-server/src/run_service.rs:132` — add `None,` after the trigger argument (Task 3 replaces this with the real value; `None` keeps the workspace compiling now).

- [ ] **Step 7: Run the DB tests**

```bash
set -a; source .env; set +a
cargo test -p fluidbox-db
```
Expected: all pass including `schedule_lifecycle_and_skip_claims` (migration 0004 auto-applies via `sqlx::migrate!` on connect… it does NOT — migrations run on server boot via `fluidbox_db::connect`? Check: `connect` runs `sqlx::migrate!("../../migrations")` per lib.rs:22 — yes, `connect()` migrates, so the test picks it up).

- [ ] **Step 8: fmt + clippy + commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`

```bash
git add migrations crates/fluidbox-db crates/fluidbox-server/src/run_service.rs
git commit -m "db: schedules table, concurrency_policy, skip-aware idempotency claims, atomic claim bind (migration 0004)"
```

---

### Task 3: Concurrency enforcement in create_run + cancel reason

**Files:**
- Modify: `crates/fluidbox-server/src/run_service.rs`
- Modify: `crates/fluidbox-server/src/orchestrator.rs` (cancel signature)
- Modify: `crates/fluidbox-server/src/api.rs` (two call sites)
- Modify: `crates/fluidbox-server/src/triggers.rs` (invoke call site)

**Interfaces:**
- Consumes: `fluidbox_core::schedule::ConcurrencyPolicy`, `fluidbox_db::{active_subscription_sessions, get_trigger_subscription, mark_invocation_skipped}`, `InvocationClaim::Skipped`.
- Produces:
  - `run_service::RunCreation::{Created(fluidbox_db::SessionRow), SkippedOverlap { running_session_id: Uuid }}`
  - `run_service::CreateRun` gains `pub bound_invocation: Option<Uuid>`
  - `run_service::create_run(…) -> ApiResult<RunCreation>`
  - `orchestrator::cancel(state, id, reason: &str) -> bool`

- [ ] **Step 1: orchestrator::cancel takes a reason**

In `orchestrator.rs`, change the signature and the transition reason:

```rust
/// Cancel a session (admin action or a `replace` concurrency policy).
/// Captures whatever the agent produced so far, then tears everything down.
pub async fn cancel(state: &AppState, id: Uuid, reason: &str) -> bool {
```

and inside, `Some("cancelled by user")` becomes `Some(reason)`.

In `api.rs` `cancel_session`, update the call: `orchestrator::cancel(&state, id, "cancelled by user").await;`

- [ ] **Step 2: run_service — RunCreation + the §17 #5 gate**

In `run_service.rs`:

1. Imports: add `use fluidbox_core::schedule::ConcurrencyPolicy;`.

2. Add to `CreateRun` (after `result_destinations`):

```rust
    /// Idempotency claim bound atomically with session creation (same DB
    /// transaction) — a crash can never leave a created run unclaimed, so a
    /// stale-claim takeover can never duplicate it. None for manual runs.
    pub bound_invocation: Option<Uuid>,
```

3. Add above `create_run`:

```rust
pub enum RunCreation {
    Created(fluidbox_db::SessionRow),
    /// concurrency_policy = skip_if_running and another run of this
    /// subscription is still active. Nothing was created; the caller
    /// records the skip visibly (claim row → skip_reason, or 409).
    SkippedOverlap { running_session_id: Uuid },
}
```

4. Change the return type to `ApiResult<RunCreation>` and insert the gate right after the policy/autonomy checks (before budgets/workspace work):

```rust
    // §17 #5 (settled 2026-07-10): the subscription's concurrency policy
    // governs EVERY invocation that carries one — API invokes and schedule
    // firings alike. Manual runs carry no subscription and are never gated.
    if let Some(sub_id) = req.invocation.subscription_id {
        let sub = fluidbox_db::get_trigger_subscription(&state.pool, sub_id)
            .await?
            .filter(|s| s.tenant_id == state.tenant_id)
            .ok_or_else(|| {
                ApiError::Internal("invocation references a missing subscription".into())
            })?;
        let policy = ConcurrencyPolicy::parse(&sub.concurrency_policy).ok_or_else(|| {
            ApiError::Internal(format!(
                "bad stored concurrency_policy '{}'",
                sub.concurrency_policy
            ))
        })?;
        if policy != ConcurrencyPolicy::Allow {
            let active = fluidbox_db::active_subscription_sessions(&state.pool, sub_id).await?;
            match policy {
                ConcurrencyPolicy::SkipIfRunning => {
                    if let Some(s) = active.first() {
                        return Ok(RunCreation::SkippedOverlap {
                            running_session_id: s.id,
                        });
                    }
                }
                ConcurrencyPolicy::Replace => {
                    for s in &active {
                        crate::orchestrator::cancel(
                            state,
                            s.id,
                            "replaced by a newer invocation of this subscription",
                        )
                        .await;
                    }
                }
                ConcurrencyPolicy::Allow => unreachable!(),
            }
        }
    }
```

5. Pass the bind into the session insert and wrap the return:

```rust
    let session = fluidbox_db::create_session(
        …existing args…,
        Some(&serde_json::to_value(&req.invocation)?),
        req.bound_invocation,
    )
    .await?;
    …ledger + spawn_run unchanged…
    Ok(RunCreation::Created(session))
```

- [ ] **Step 3: Update the two callers**

`api.rs` `create_session`: add `bound_invocation: None,` to the `CreateRun` literal and unwrap the outcome:

```rust
    let created = crate::run_service::create_run(&state, crate::run_service::CreateRun { …, bound_invocation: None }).await?;
    let session = match created {
        crate::run_service::RunCreation::Created(s) => s,
        // Manual runs carry no subscription — unreachable, but honest.
        crate::run_service::RunCreation::SkippedOverlap { running_session_id } => {
            return Err(ApiError::Conflict(format!(
                "skipped: run {running_session_id} is still active (concurrency_policy=skip_if_running)"
            )))
        }
    };
    Ok(Json(json!({ "session": session })))
```

`triggers.rs` `invoke`:
1. In the claim match, add the new arm (before `InFlight`):

```rust
        fluidbox_db::InvocationClaim::Skipped { reason } => {
            return Err(ApiError::Conflict(format!(
                "this Idempotency-Key was skipped ({reason}) — use a new key to retry"
            )))
        }
```

2. In the `CreateRun` literal add `bound_invocation: Some(invocation_id),`.
3. Replace the `match created` block (the bind call disappears — it is atomic now):

```rust
    match created {
        Ok(crate::run_service::RunCreation::Created(session)) => Ok(Json(json!({
            "session_id": session.id,
            "status": session.status,
            "replay": false,
            "poll_url": format!("/v1/triggers/{}/runs/{}", sub.id, session.id),
        }))),
        Ok(crate::run_service::RunCreation::SkippedOverlap { running_session_id }) => {
            // The skip is the terminal outcome of this key — recorded, not retried.
            fluidbox_db::mark_invocation_skipped(&state.pool, invocation_id, "overlap")
                .await
                .ok();
            Err(ApiError::Conflict(format!(
                "skipped: run {running_session_id} from this subscription is still active (concurrency_policy=skip_if_running)"
            )))
        }
        Err(e) => {
            // Free the key so the caller's retry isn't wedged behind a failure.
            fluidbox_db::release_invocation(&state.pool, invocation_id)
                .await
                .ok();
            Err(e)
        }
    }
```

- [ ] **Step 4: Build, test, commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p fluidbox-core -p fluidbox-server`
Expected: clean; existing triggers.rs unit tests still pass.

```bash
git add crates/fluidbox-server
git commit -m "server: concurrency_policy enforced in create_run for all invocations; claim bind atomic with session creation"
```

---

### Task 4: Schedule-aware trigger create API

**Files:**
- Modify: `crates/fluidbox-server/src/triggers.rs`

**Interfaces:**
- Consumes: `fluidbox_core::schedule::{ConcurrencyPolicy, MissedRunPolicy, CronSchedule}`, `fluidbox_db::{create_schedule, schedule_for_subscription, schedules_for_tenant, list_subscription_invocations}`.
- Produces (used by Task 5's scheduler):
  - `triggers::schedule_context(fire_time: &str) -> BTreeMap<String, String>` — the template context of a schedule firing (key: `fire_time`)
  - `triggers::sub_run_params(&fluidbox_db::TriggerSubscriptionRow) -> ApiResult<(Autonomy, Option<Budgets>, Vec<ResultDestination>, Option<WorkspaceSpec>)>`
- API shape:
  - `POST /v1/triggers` body gains `concurrency_policy?: string` and `schedule?: { cron: string, timezone?: string (default "UTC"), missed_run_policy?: string (default "skip") }`; response gains `"schedule": ScheduleRow | null`; `trigger_kind` becomes `"schedule"` when a schedule is attached
  - `GET /v1/triggers` response gains `"schedules": ScheduleRow[]`
  - `GET /v1/triggers/{id}` response gains `"schedule": ScheduleRow | null` and `"invocations": TriggerInvocationRow[]`

- [ ] **Step 1: Shared helpers**

In `triggers.rs`, imports: add `use fluidbox_core::schedule::{ConcurrencyPolicy, CronSchedule, MissedRunPolicy};`.

Add near `render_task_template`:

```rust
/// The template context a schedule firing renders with. Kept deliberately
/// small: schedules have no external caller, so `fire_time` (RFC3339 UTC)
/// is the only variable input.
pub fn schedule_context(fire_time: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("fire_time".to_string(), fire_time.to_string())])
}

/// Subscription-stored run parameters shared by every borrow path (API
/// invoke and schedule firing): autonomy, budget tightening, result
/// destinations, and the subscription workspace override.
pub fn sub_run_params(
    sub: &fluidbox_db::TriggerSubscriptionRow,
) -> ApiResult<(
    Autonomy,
    Option<Budgets>,
    Vec<ResultDestination>,
    Option<WorkspaceSpec>,
)> {
    let autonomy = match sub.autonomy.as_deref() {
        Some("autonomous") => Autonomy::Autonomous,
        _ => Autonomy::Supervised,
    };
    let budget_override: Option<Budgets> = sub
        .budget_override
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| ApiError::Internal(format!("bad stored budget override: {e}")))?;
    let destinations: Vec<ResultDestination> =
        serde_json::from_value(sub.result_destinations.clone())
            .map_err(|e| ApiError::Internal(format!("bad stored destinations: {e}")))?;
    let workspace: Option<WorkspaceSpec> = sub
        .workspace_override
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| ApiError::Internal(format!("bad stored subscription workspace: {e}")))?;
    Ok((autonomy, budget_override, destinations, workspace))
}
```

Refactor `invoke()` to use `sub_run_params` (replace its inline `autonomy`, `budget_override`, `destinations` parsing AND the `sub_workspace` parse — the narrowing block consumes the returned workspace).

- [ ] **Step 2: CreateTrigger gains schedule + concurrency_policy**

```rust
#[derive(Deserialize)]
pub struct ScheduleInput {
    pub cron: String,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub missed_run_policy: Option<String>,
}
```

Add to `CreateTrigger`:

```rust
    /// allow (default) | skip_if_running | replace — enforced for ALL
    /// invocations of this subscription (§17 #5).
    #[serde(default)]
    pub concurrency_policy: Option<String>,
    /// Attach a clock: the subscription becomes trigger_kind='schedule'.
    #[serde(default)]
    pub schedule: Option<ScheduleInput>,
```

- [ ] **Step 3: Validation + creation in `create()`**

After the existing template check, add:

```rust
    let concurrency = req.concurrency_policy.as_deref().unwrap_or("allow");
    if ConcurrencyPolicy::parse(concurrency).is_none() {
        return Err(ApiError::BadRequest(
            "concurrency_policy must be allow | skip_if_running | replace".into(),
        ));
    }
    // A schedule fires with no caller: the cron/timezone must parse, the
    // template must exist and render from the schedule context alone, and
    // there must actually be a future firing.
    let schedule_cfg = match &req.schedule {
        None => None,
        Some(s) => {
            let tz = s.timezone.as_deref().unwrap_or("UTC");
            let cron = CronSchedule::parse(&s.cron, tz).map_err(ApiError::BadRequest)?;
            let missed = s.missed_run_policy.as_deref().unwrap_or("skip");
            if MissedRunPolicy::parse(missed).is_none() {
                return Err(ApiError::BadRequest(
                    "missed_run_policy must be skip | catch_up".into(),
                ));
            }
            let tpl = template.ok_or_else(|| {
                ApiError::BadRequest("a schedule needs a task_template (there is no caller)".into())
            })?;
            render_task_template(tpl, &schedule_context("2026-01-01T00:00:00Z")).map_err(|e| {
                ApiError::BadRequest(format!(
                    "task_template must render from the schedule context ({{{{fire_time}}}}): {e}"
                ))
            })?;
            let first = cron.next_fire_after(chrono::Utc::now()).ok_or_else(|| {
                ApiError::BadRequest("cron expression never fires in the future".into())
            })?;
            Some((s.cron.trim().to_string(), tz.to_string(), missed.to_string(), first))
        }
    };
    let trigger_kind = if schedule_cfg.is_some() { "schedule" } else { "api" };
```

Change the `create_trigger_subscription` call: pass `trigger_kind` instead of `"api"` and add `concurrency,` right after the autonomy argument.

After the token mint, create the clock and include it in the response:

```rust
    let schedule_row = match schedule_cfg {
        None => None,
        Some((cron, tz, missed, first)) => Some(
            fluidbox_db::create_schedule(&state.pool, sub.id, &cron, &tz, first, &missed).await?,
        ),
    };

    // token + callback_secret appear ONLY here, once, at creation.
    Ok(Json(json!({
        "subscription": sub,
        "schedule": schedule_row,
        "token": token,
        "callback_secret": secret_plain,
    })))
```

- [ ] **Step 4: list() and get() expose schedule state**

```rust
pub async fn list(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let subscriptions =
        fluidbox_db::list_trigger_subscriptions(&state.pool, state.tenant_id).await?;
    let schedules = fluidbox_db::schedules_for_tenant(&state.pool, state.tenant_id).await?;
    Ok(Json(json!({ "subscriptions": subscriptions, "schedules": schedules })))
}
```

In `get()`, add:

```rust
    let schedule = fluidbox_db::schedule_for_subscription(&state.pool, id).await?;
    let invocations = fluidbox_db::list_subscription_invocations(&state.pool, id, 30).await?;
```

and extend the json to `{"subscription": sub, "schedule": schedule, "sessions": sessions, "deliveries": deliveries, "invocations": invocations}`.

- [ ] **Step 5: Unit test for the schedule context render rule**

Append to `triggers.rs` tests:

```rust
    #[test]
    fn schedule_context_renders_fire_time_only() {
        let ctx = schedule_context("2026-07-10T00:00:00Z");
        assert_eq!(
            render_task_template("sweep at {{fire_time}}", &ctx).unwrap(),
            "sweep at 2026-07-10T00:00:00Z"
        );
        // A schedule template referencing caller keys is dead config.
        assert!(render_task_template("do {{ticket}}", &ctx).is_err());
    }
```

- [ ] **Step 6: Build, test, commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p fluidbox-server`

```bash
git add crates/fluidbox-server/src/triggers.rs
git commit -m "server: schedule-aware trigger create — cron/timezone/missed policy validated at config time, schedule state on list/get"
```

---

### Task 5: The scheduler tick worker

**Files:**
- Create: `crates/fluidbox-server/src/scheduler.rs`
- Modify: `crates/fluidbox-server/src/main.rs`

**Interfaces:**
- Consumes: `fluidbox_db::{due_schedules, advance_schedule, claim_invocation, mark_invocation_skipped, get_trigger_subscription, sha256_hex, InvocationClaim, ScheduleRow}`, `fluidbox_core::schedule::{CronSchedule, MissedRunPolicy}`, `crate::triggers::{render_task_template, schedule_context, sub_run_params}`, `crate::run_service::{create_run, CreateRun, RunCreation, RevisionSelector}`.
- Produces: `scheduler::spawn_worker(state: AppState)`, `scheduler::fire_key(DateTime<Utc>) -> String`.

- [ ] **Step 1: Write scheduler.rs**

```rust
//! The schedule tick worker (design doc §6.2) — shaped like deliveries.rs:
//! one sequential poll loop per server, the DB as the source of truth.
//! Firing is exactly-once by construction: each (subscription, scheduled
//! fire time) claims a deterministic key on the SAME trigger_invocations
//! table the API path uses, and the session insert binds the claim in one
//! transaction — a crashed or double-fired scheduler replays, never
//! duplicates. Every fire time ends as exactly one claim row: bound to a
//! run, or visibly skipped (overlap | missed | error: …).

use crate::run_service::{self, CreateRun, RevisionSelector, RunCreation};
use crate::state::AppState;
use crate::triggers::{render_task_template, schedule_context, sub_run_params};
use chrono::{DateTime, SecondsFormat, Utc};
use fluidbox_core::schedule::{CronSchedule, MissedRunPolicy};
use fluidbox_core::spec::{InvocationContext, InvocationKind};
use fluidbox_db::ScheduleRow;
use std::time::Duration;

const TICK: Duration = Duration::from_secs(1);
/// A firing older than this is "missed" (control plane down or subscription
/// disabled across it) and goes through missed_run_policy; younger, it just
/// fires — a slow tick is not an outage.
const MISSED_GRACE_SECS: i64 = 30;

/// Deterministic idempotency key for one scheduled fire time.
pub fn fire_key(fire_time: DateTime<Utc>) -> String {
    format!("sched:{}", fire_time.to_rfc3339_opts(SecondsFormat::Secs, true))
}

pub fn spawn_worker(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            let due = match fluidbox_db::due_schedules(&state.pool, 20).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("schedule poll failed: {e}");
                    continue;
                }
            };
            for sched in due {
                fire_one(&state, &sched).await;
            }
        }
    });
}

async fn fire_one(state: &AppState, sched: &ScheduleRow) {
    let Some(fire_time) = sched.next_fire_at else { return };
    let sub = match fluidbox_db::get_trigger_subscription(&state.pool, sched.subscription_id).await
    {
        Ok(Some(s)) => s,
        Ok(None) => return, // subscription deleted mid-tick; cascade wins
        Err(e) => {
            tracing::warn!("schedule {}: subscription lookup failed: {e}", sched.id);
            return;
        }
    };
    // create() validated cron+tz; a parse failure here means a manual DB
    // edit. Loud log, no advance (we cannot compute one) — visible, bounded.
    let cron = match CronSchedule::parse(&sched.cron, &sched.timezone) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("schedule {} has unparseable cron/timezone: {e}", sched.id);
            return;
        }
    };
    let now = Utc::now();
    let next = cron.next_fire_after(now);
    let missed = (now - fire_time).num_seconds() > MISSED_GRACE_SECS;
    let missed_policy =
        MissedRunPolicy::parse(&sched.missed_run_policy).unwrap_or(MissedRunPolicy::Skip);
    let key = fire_key(fire_time);
    let digest = fluidbox_db::sha256_hex(&key);

    // Missed + skip: record ONE skip row keyed at the oldest missed fire
    // time, then jump to the next future firing. Intermediate missed slots
    // get no rows — recording a thundering herd is as bad as firing one.
    if missed && missed_policy == MissedRunPolicy::Skip {
        if let Ok(fluidbox_db::InvocationClaim::Claimed { invocation_id }) =
            fluidbox_db::claim_invocation(&state.pool, sub.id, &key, &digest).await
        {
            fluidbox_db::mark_invocation_skipped(&state.pool, invocation_id, "missed")
                .await
                .ok();
            tracing::info!("schedule {}: missed {} → skipped", sched.id, key);
        }
        advance(state, sched, fire_time, next, None).await;
        return;
    }

    // On-time fire, or the single catch-up firing for a missed gap.
    match fluidbox_db::claim_invocation(&state.pool, sub.id, &key, &digest).await {
        Ok(fluidbox_db::InvocationClaim::Claimed { invocation_id }) => {
            let created = build_and_create(state, &sub, sched, fire_time, missed, invocation_id)
                .await;
            match created {
                Ok(RunCreation::Created(session)) => {
                    tracing::info!("schedule {}: fired {} → run {}", sched.id, key, session.id);
                    advance(state, sched, fire_time, next, Some(fire_time)).await;
                }
                Ok(RunCreation::SkippedOverlap { running_session_id }) => {
                    fluidbox_db::mark_invocation_skipped(&state.pool, invocation_id, "overlap")
                        .await
                        .ok();
                    tracing::info!(
                        "schedule {}: {} skipped (run {} still active)",
                        sched.id,
                        key,
                        running_session_id
                    );
                    advance(state, sched, fire_time, next, None).await;
                }
                Err(e) => {
                    // A failed firing is recorded, not retried — retrying a
                    // config error every tick would loop forever.
                    fluidbox_db::mark_invocation_skipped(
                        &state.pool,
                        invocation_id,
                        &format!("error: {e}"),
                    )
                    .await
                    .ok();
                    tracing::warn!("schedule {}: firing {} failed: {e}", sched.id, key);
                    advance(state, sched, fire_time, next, None).await;
                }
            }
        }
        // Crash recovery: this fire time already produced its outcome
        // (a bound run or a recorded skip) — advance past it, fire nothing.
        Ok(fluidbox_db::InvocationClaim::Replay { .. })
        | Ok(fluidbox_db::InvocationClaim::Skipped { .. }) => {
            advance(state, sched, fire_time, next, None).await;
        }
        // Another worker holds this fire mid-creation: leave next_fire_at
        // alone; the next tick resolves to Replay/Skipped.
        Ok(fluidbox_db::InvocationClaim::InFlight) => {}
        Err(e) => tracing::warn!("schedule {}: claim failed: {e}", sched.id),
    }
}

async fn build_and_create(
    state: &AppState,
    sub: &fluidbox_db::TriggerSubscriptionRow,
    sched: &ScheduleRow,
    fire_time: DateTime<Utc>,
    catch_up: bool,
    invocation_id: uuid::Uuid,
) -> crate::error::ApiResult<RunCreation> {
    let fire_str = fire_time.to_rfc3339_opts(SecondsFormat::Secs, true);
    let template = sub.task_template.as_deref().ok_or_else(|| {
        crate::error::ApiError::Internal("schedule subscription has no task_template".into())
    })?;
    let task = render_task_template(template, &schedule_context(&fire_str))
        .map_err(crate::error::ApiError::Internal)?;
    let (autonomy, budget_override, result_destinations, explicit_workspace) =
        sub_run_params(sub)?;
    run_service::create_run(
        state,
        CreateRun {
            agent: sub.agent_id.to_string(),
            revision: match sub.pinned_revision_id {
                Some(rid) => RevisionSelector::Pinned(rid),
                None => RevisionSelector::Latest,
            },
            task,
            explicit_workspace,
            autonomy,
            budget_override,
            invocation: InvocationContext {
                kind: InvocationKind::Schedule,
                subscription_id: Some(sub.id),
                actor: Some(format!("schedule:{}", sub.name)),
                attributes: serde_json::json!({
                    "cron": sched.cron,
                    "timezone": sched.timezone,
                    "fire_time": fire_str,
                    "catch_up": catch_up,
                }),
                received_at: Some(Utc::now()),
            },
            result_destinations,
            bound_invocation: Some(invocation_id),
        },
    )
    .await
}

async fn advance(
    state: &AppState,
    sched: &ScheduleRow,
    from: DateTime<Utc>,
    to: Option<DateTime<Utc>>,
    fired_at: Option<DateTime<Utc>>,
) {
    match fluidbox_db::advance_schedule(&state.pool, sched.id, from, to, fired_at).await {
        Ok(true) => {}
        Ok(false) => tracing::debug!("schedule {}: advance lost CAS (benign)", sched.id),
        Err(e) => tracing::warn!("schedule {}: advance failed: {e}", sched.id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fire_key_is_deterministic_and_second_precise() {
        let t: DateTime<Utc> = "2026-07-10T12:00:05Z".parse().unwrap();
        assert_eq!(fire_key(t), "sched:2026-07-10T12:00:05Z");
        assert_eq!(fire_key(t), fire_key(t));
        let t2: DateTime<Utc> = "2026-07-10T12:00:06Z".parse().unwrap();
        assert_ne!(fire_key(t), fire_key(t2));
    }
}
```

- [ ] **Step 2: Wire into main.rs**

Add `mod scheduler;` to the module list and, after `deliveries::spawn_worker(state.clone());`:

```rust
    scheduler::spawn_worker(state.clone());
```

- [ ] **Step 3: Build, test, commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p fluidbox-server`

```bash
git add crates/fluidbox-server
git commit -m "server: scheduler tick worker — exactly-once firing via deterministic claim keys; overlap + missed-run policies"
```

---

### Task 6: Dashboard — schedule status on the Triggers page

**Files:**
- Modify: `apps/web/app/lib/api.ts`
- Modify: `apps/web/app/triggers/page.tsx`

**Interfaces:**
- Consumes: the Task 4 API shapes (`schedules` on list, `schedule`+`invocations` on get, `concurrency_policy`/`schedule` on create).
- Presentation-only — zero logic beyond rendering.

- [ ] **Step 1: Types in api.ts**

Add `concurrency_policy: string;` to `TriggerSubscription` (after `autonomy`). Add after `TriggerSubscription`:

```typescript
export interface Schedule {
  id: string;
  subscription_id: string;
  cron: string;
  timezone: string;
  next_fire_at: string | null;
  missed_run_policy: string;
  last_fired_at: string | null;
}

export interface TriggerInvocation {
  id: string;
  subscription_id: string;
  idempotency_key: string;
  session_id: string | null;
  skip_reason: string | null;
  created_at: string;
}
```

- [ ] **Step 2: page.tsx — load schedules, show them on rows**

In `Triggers()`: add `const [schedules, setSchedules] = useState<Record<string, Schedule>>({});` and in `load()` read them from the list response:

```typescript
      const r = await apiGet<{ subscriptions: TriggerSubscription[]; schedules?: Schedule[] }>("/triggers");
      setSubs(r.subscriptions);
      setSchedules(Object.fromEntries((r.schedules || []).map((s) => [s.subscription_id, s])));
```

Pass `schedule={schedules[s.id]}` to `TriggerRow`; add `schedule?: Schedule` to its props. In `TriggerRow`, extend the summary line (after the callback fragment inside the second `<span className="mut">`):

```typescript
            {sub.concurrency_policy !== "allow" ? ` · ${sub.concurrency_policy}` : ""}
```

and after that span, when there is a schedule, add a third line:

```tsx
          {schedule && (
            <span className="mut mono" style={{ display: "block", fontSize: 11.5, marginTop: 2 }}>
              ⏱ {schedule.cron} ({schedule.timezone}) · missed: {schedule.missed_run_policy}
              {schedule.next_fire_at ? ` · next ${new Date(schedule.next_fire_at).toLocaleTimeString()}` : ""}
              {schedule.last_fired_at ? ` · last ${new Date(schedule.last_fired_at).toLocaleTimeString()}` : ""}
            </span>
          )}
```

(Adjust placement so the grid stays intact — the schedule line lives inside the first grid cell's `<span className="task">`.)

- [ ] **Step 3: TriggerActivity — invocations incl. skips**

Extend the poll to `{ sessions, deliveries, invocations }` (`invocations?: TriggerInvocation[]`) and store them. Change the two-column grid to three (`gridTemplateColumns: "1fr 1fr 1fr"`) and add a third column after deliveries:

```tsx
      <div>
        <div className="sectitle" style={{ marginTop: 0 }}>
          firings &amp; skips
        </div>
        {invocations.length === 0 ? (
          <div className="empty">no invocations yet</div>
        ) : (
          invocations.map((i) => (
            <div key={i.id} className="spread" style={{ padding: "4px 0", gap: 8 }}>
              <span className="mono mut" style={{ fontSize: 11.5, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {i.idempotency_key}
              </span>
              {i.session_id ? (
                <Link className="link mono" href={`/sessions/${i.session_id}`} style={{ fontSize: 12 }}>
                  {short(i.session_id)}
                </Link>
              ) : (
                <span className={`autopill autonomous`} title={i.skip_reason || undefined}>
                  {i.skip_reason ? `skipped: ${i.skip_reason.slice(0, 24)}` : "pending"}
                </span>
              )}
            </div>
          ))
        )}
      </div>
```

- [ ] **Step 4: NewTrigger — schedule + concurrency fields**

Add state:

```typescript
  const [concurrency, setConcurrency] = useState("allow");
  const [scheduled, setScheduled] = useState(false);
  const [cron, setCron] = useState("");
  const [timezone, setTimezone] = useState("UTC");
  const [missedPolicy, setMissedPolicy] = useState("skip");
```

In `submit()`, after the callback line:

```typescript
      if (concurrency !== "allow") body.concurrency_policy = concurrency;
      if (scheduled) {
        if (!cron.trim()) {
          setErr("a schedule needs a cron expression");
          setBusy(false);
          return;
        }
        body.schedule = { cron: cron.trim(), timezone: timezone.trim() || "UTC", missed_run_policy: missedPolicy };
      }
```

Add fields to the form (after the autonomous checkbox, before the callback URL):

```tsx
          <label className="field">
            <span className="lab">Overlap policy — when a new invocation arrives while a run is active</span>
            <select className="inp" value={concurrency} onChange={(e) => setConcurrency(e.target.value)}>
              <option value="allow">allow (default — runs may overlap)</option>
              <option value="skip_if_running">skip_if_running (classic cron — skip is recorded)</option>
              <option value="replace">replace (cancel the running run, start the new one)</option>
            </select>
          </label>
          <label className="field" style={{ flexDirection: "row", gap: 8, alignItems: "center" }}>
            <input type="checkbox" checked={scheduled} onChange={(e) => setScheduled(e.target.checked)} />
            <span className="lab" style={{ margin: 0 }}>
              run on a schedule (cron — the task template renders {"{{fire_time}}"})
            </span>
          </label>
          {scheduled && (
            <>
              <label className="field">
                <span className="lab">Cron (5-field standard, or 6-field with seconds)</span>
                <input className="inp mono" value={cron} onChange={(e) => setCron(e.target.value)} placeholder="0 7 * * 1-5" />
              </label>
              <label className="field">
                <span className="lab">Timezone (IANA — DST-correct)</span>
                <input className="inp mono" value={timezone} onChange={(e) => setTimezone(e.target.value)} placeholder="America/New_York" />
              </label>
              <label className="field">
                <span className="lab">Missed-run policy — scheduler was down across fire times</span>
                <select className="inp" value={missedPolicy} onChange={(e) => setMissedPolicy(e.target.value)}>
                  <option value="skip">skip (default — record the gap, resume the cadence)</option>
                  <option value="catch_up">catch_up (fire exactly one make-up run)</option>
                </select>
              </label>
            </>
          )}
```

Import `Schedule, TriggerInvocation` from `../lib/api` at the top of page.tsx.

- [ ] **Step 5: Build + commit**

Run: `cd apps/web && pnpm build` (or the repo's `just check` web step)
Expected: build succeeds, no type errors.

```bash
git add apps/web
git commit -m "web: schedule status on triggers — cron/next/last fire, policies, firings & skips column, schedule create form"
```

---

### Task 7: E2E acceptance phase — scripts/e2e-schedule.sh

**Files:**
- Create: `scripts/e2e-schedule.sh`
- Modify: `scripts/e2e.sh`

**Interfaces:**
- Consumes: the full Phase 3 API. Owns its control plane (like `e2e-failures.sh`) because the exactly-once test restarts the server. Uses `psql "$DATABASE_URL"` as the test seam for time travel (rewinding `next_fire_at`) and fake-active sessions — precedent: e2e-failures.sh F4.
- No-model runs are made cheap + deterministic by subscription budget `{"max_wall_clock_secs": 1}` — the wall-clock sweeper (10s tick) forces `budget_exceeded` terminal within ~15s even when a live key is present.

- [ ] **Step 1: Write scripts/e2e-schedule.sh**

```bash
#!/usr/bin/env bash
# Phase 3 acceptance — scheduled borrowing (design doc §12 Phase 3):
#   • a schedule is a trigger subscription with a clock; each firing is an
#     ordinary run with InvocationContext.kind=schedule via create_run
#   • config-time validation: cron / timezone / template / policies
#   • EXACTLY-ONCE: deterministic claim key (subscription + fire time) —
#     a restarted scheduler replays a stale fire time, never duplicates it
#   • overlap policies enforced for ALL invocations (§17 #5): schedule
#     skip_if_running + replace, API-invoke skip (409) + default allow
#   • missed-run policies: skip records ONE visible skip; catch_up fires
#     exactly ONE make-up run (never fire-all-missed)
#   • terminal schedule-fired runs publish signed callbacks (Phase 2 reused)
#   • live: a repository-maintenance agent on a sub-minute schedule
#     completes, overlapping firings skip visibly (self-skips without key)
# Owns the stack (restarts the server mid-phase). Time travel via psql.
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker psql python3 curl git cargo openssl
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
CT="content-type: application/json"

if port_in_use; then
  echo "port 8787 already serving — this phase owns the stack"
  exit 1
fi
cargo build -q -p fluidbox-server || exit 1
trap 'stop_server' EXIT
start_server || exit 1

B=/tmp/fbx-sched-body.json
post()   { curl -s -o "$B" -w "%{http_code}" -X POST -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }
tpost()  { curl -s -o "$B" -w "%{http_code}" -X POST -H "authorization: Bearer $1" -H "$CT" ${4:+-H "$4"} -d "$3" "$API/v1$2"; }
sfield() { curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']$2"; }
tget()   { curl -s -H "$H" "$API/v1/triggers/$1"; }
pq()     { psql "$DATABASE_URL" -qtA -c "$1" | head -1; }

# Poll GET /v1/triggers/{id} until a python expression over it is truthy.
wait_trig() { # sub-id python-expr [tries=20 sleep=1]
  local sub=$1 expr=$2 tries=${3:-20} pause=${4:-1}
  for _ in $(seq 1 "$tries"); do
    if tget "$sub" | python3 -c "
import sys, json
d = json.load(sys.stdin)
sys.exit(0 if ($expr) else 1)" 2>/dev/null; then return 0; fi
    sleep "$pause"
  done
  return 1
}
run_count()  { tget "$1" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['sessions']))"; }
skip_count() { # sub-id reason
  tget "$1" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(sum(1 for i in d['invocations'] if (i.get('skip_reason') or '').startswith('$2')))"
}
wait_terminal() {
  local deadline=$(( $(date +%s) + ${2:-120} )) st=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    st=$(sfield "$1" "['status']")
    case "$st" in completed|failed|cancelled|budget_exceeded) echo "$st"; return 0 ;; esac
    sleep 3
  done
  echo "timeout(last=$st)"; return 1
}
rewind() { # sub-id interval-sql (e.g. "now()" or "now() - interval '10 minutes'")
  pq "update schedules set next_fire_at = $2 where subscription_id = '$1' returning id" >/dev/null
}
set_status() { pq "update sessions set status = '$2' where id = '$1' returning id" >/dev/null; }

say "RECEIVER — captures signed callbacks from schedule-fired runs"
RCV_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fbx-sched-rcv.XXXXXX")
RCV_PORT=8898
python3 - "$RCV_PORT" "$RCV_DIR" <<'PYEOF' &
import http.server, json, sys, pathlib
port, out = int(sys.argv[1]), pathlib.Path(sys.argv[2])
n = 0
class Hh(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global n
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        n += 1
        (out / f"delivery-{n}.json").write_text(json.dumps({
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode()}))
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), Hh).serve_forever()
PYEOF
RCV_PID=$!
trap 'kill $RCV_PID 2>/dev/null; stop_server' EXIT
sleep 0.5
ok "callback receiver on :$RCV_PORT"

AGENT="sched-agent-$$"
post "/agents" "{\"name\":\"$AGENT\",\"policy\":\"default\"}" >/dev/null
# Every no-model subscription tightens max_wall_clock_secs to 1: the budget
# sweeper (10s tick) forces terminal within ~15s — cheap and deterministic
# even when a live model key is present.
TB='{"max_wall_clock_secs": 1}'

say "VALIDATION — bad schedule config is refused at create time"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"v1-$$\",\"task_template\":\"t\",\"schedule\":{\"cron\":\"not a cron\"}}")
[ "$CODE" = "400" ] && ok "bad cron → 400" || no "wanted 400, got $CODE"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"v2-$$\",\"task_template\":\"t\",\"schedule\":{\"cron\":\"*/5 * * * * *\",\"timezone\":\"Mars/Olympus\"}}")
[ "$CODE" = "400" ] && ok "bad timezone → 400" || no "wanted 400, got $CODE"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"v3-$$\",\"allow_task_override\":true,\"schedule\":{\"cron\":\"*/5 * * * * *\"}}")
[ "$CODE" = "400" ] && ok "schedule without template → 400 (no caller to supply a task)" || no "wanted 400, got $CODE"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"v4-$$\",\"task_template\":\"do {{ticket}}\",\"schedule\":{\"cron\":\"*/5 * * * * *\"}}")
[ "$CODE" = "400" ] && ok "template with caller keys on a schedule → 400" || no "wanted 400, got $CODE"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"v5-$$\",\"task_template\":\"t\",\"schedule\":{\"cron\":\"*/5 * * * * *\",\"missed_run_policy\":\"fire_all_missed\"}}")
[ "$CODE" = "400" ] && ok "unknown missed_run_policy → 400 (fire-all-missed is not a thing)" || no "wanted 400, got $CODE"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"v6-$$\",\"task_template\":\"t\",\"concurrency_policy\":\"sometimes\"}")
[ "$CODE" = "400" ] && ok "unknown concurrency_policy → 400" || no "wanted 400, got $CODE"

say "SUB A — every-5s schedule fires ordinary runs (kind=schedule, signed callback)"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"schedA-$$\",
  \"task_template\":\"Maintenance sweep at {{fire_time}}.\",\"budgets\":$TB,
  \"concurrency_policy\":\"skip_if_running\",\"autonomous\":true,
  \"schedule\":{\"cron\":\"*/5 * * * * *\",\"timezone\":\"UTC\"},
  \"callback_url\":\"http://127.0.0.1:$RCV_PORT/cb\"}")
SUBA=$(cat "$B" | j "['subscription']['id']"); SECA=$(cat "$B" | j "['callback_secret']")
[ "$CODE" = "200" ] && [ -n "$SUBA" ] && ok "SUB A created" || { no "SUB A create → $CODE: $(cat "$B")"; exit 1; }
[ "$(cat "$B" | j "['subscription']['trigger_kind']")" = "schedule" ] && ok "trigger_kind=schedule" || no "wrong trigger_kind"
[ -n "$(cat "$B" | j "['schedule']['next_fire_at']")" ] && ok "next_fire_at computed at create" || no "no next_fire_at"
wait_trig "$SUBA" "len(d['sessions']) >= 1" 20 1 && ok "schedule fired within 20s" || no "no firing within 20s"
SA=$(tget "$SUBA" | j "['sessions'][-1]['id']")
[ "$(sfield "$SA" "['trigger']['kind']")" = "schedule" ] && ok "sessions.trigger kind=schedule" || no "trigger kind wrong"
[ "$(sfield "$SA" "['run_spec']['invocation']['kind']")" = "schedule" ] && ok "RunSpec froze invocation kind=schedule" || no "run_spec kind wrong"
[ "$(sfield "$SA" "['run_spec']['invocation']['subscription_id']")" = "$SUBA" ] && ok "RunSpec froze the subscription id" || no "sub id wrong"
FT=$(sfield "$SA" "['run_spec']['invocation']['attributes']['fire_time']")
[ -n "$FT" ] && ok "fire_time frozen into the invocation ($FT)" || no "no fire_time attribute"
case "$(sfield "$SA" "['task']")" in "Maintenance sweep at 20"*) ok "task rendered {{fire_time}}";; *) no "task not rendered: $(sfield "$SA" "['task']")";; esac
wait_trig "$SUBA" "d['schedule']['last_fired_at'] is not None" 10 1 \
  && ok "last_fired_at recorded" || no "last_fired_at not set"

say "SUB A — disable stops the clock (the schedule does not advance)"
post "/triggers/$SUBA/disable" "{}" >/dev/null
sleep 2   # let an in-flight tick settle
INV_A=$(tget "$SUBA" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['invocations']))")
sleep 7
INV_A2=$(tget "$SUBA" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['invocations']))")
[ "$INV_A" = "$INV_A2" ] && ok "no invocations while disabled ($INV_A)" || no "fired while disabled ($INV_A → $INV_A2)"

say "EXACTLY-ONCE — a restarted scheduler replays a stale fire time, never re-fires it"
KEY=$(tget "$SUBA" | python3 -c "
import sys, json
d = json.load(sys.stdin)
b = [i for i in d['invocations'] if i['session_id']]
print(b[-1]['idempotency_key'])")   # oldest bound firing
T="${KEY#sched:}"
DUP_BEFORE=$(pq "select count(*) from trigger_invocations where idempotency_key = '$KEY'")
stop_server
pq "update schedules set next_fire_at = '$T' where subscription_id = '$SUBA' returning id" >/dev/null
pq "update trigger_subscriptions set enabled = true where id = '$SUBA' returning id" >/dev/null
start_server || exit 1
sleep 5
DUP_AFTER=$(pq "select count(*) from trigger_invocations where idempotency_key = '$KEY'")
[ "$DUP_BEFORE" = "1" ] && [ "$DUP_AFTER" = "1" ] && ok "fire time $T claimed exactly once across restart" || no "claims: before=$DUP_BEFORE after=$DUP_AFTER"
BOUND=$(pq "select count(distinct session_id) from trigger_invocations where idempotency_key = '$KEY' and session_id is not null")
[ "$BOUND" = "1" ] && ok "…and bound to exactly one run" || no "bound to $BOUND runs"
NEXT_FUTURE=$(pq "select (next_fire_at > now()) from schedules where subscription_id = '$SUBA'")
[ "$NEXT_FUTURE" = "t" ] && ok "replayed fire time advanced the clock" || no "next_fire_at did not advance"
post "/triggers/$SUBA/disable" "{}" >/dev/null

say "OVERLAP skip_if_running — SUB B (daily cron; fired on demand via time travel)"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"schedB-$$\",
  \"task_template\":\"sweep {{fire_time}}\",\"budgets\":$TB,\"autonomous\":true,
  \"concurrency_policy\":\"skip_if_running\",
  \"schedule\":{\"cron\":\"0 0 3 * * *\",\"timezone\":\"UTC\"}}")
SUBB=$(cat "$B" | j "['subscription']['id']")
[ "$CODE" = "200" ] && ok "SUB B created" || no "SUB B → $CODE"
rewind "$SUBB" "now()"
wait_trig "$SUBB" "len(d['sessions']) >= 1" 15 1 && ok "manual-fire seam works (1 run)" || no "SUB B did not fire"
SB1=$(tget "$SUBB" | j "['sessions'][-1]['id']")
FINAL_B=$(wait_terminal "$SB1" 60) || true
case "$FINAL_B" in completed|failed|budget_exceeded) ok "SUB B run terminal ($FINAL_B)";; *) no "SUB B run: $FINAL_B";; esac
set_status "$SB1" "running"   # fake an in-flight run (test seam)
rewind "$SUBB" "now()"
wait_trig "$SUBB" "any((i.get('skip_reason') or '') == 'overlap' for i in d['invocations'])" 15 1 \
  && ok "overlapping firing skipped (recorded, reason=overlap)" || no "no overlap skip recorded"
[ "$(run_count "$SUBB")" = "1" ] && ok "no second run created" || no "run count: $(run_count "$SUBB")"
set_status "$SB1" "$FINAL_B"

say "OVERLAP replace — SUB C: the clock cancels the stale run and starts fresh"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"schedC-$$\",
  \"task_template\":\"sweep {{fire_time}}\",\"budgets\":$TB,\"autonomous\":true,
  \"concurrency_policy\":\"replace\",
  \"schedule\":{\"cron\":\"0 0 3 * * *\",\"timezone\":\"UTC\"}}")
SUBC=$(cat "$B" | j "['subscription']['id']")
[ "$CODE" = "200" ] && ok "SUB C created" || no "SUB C → $CODE"
rewind "$SUBC" "now()"
wait_trig "$SUBC" "len(d['sessions']) >= 1" 15 1 || no "SUB C did not fire"
SC1=$(tget "$SUBC" | j "['sessions'][-1]['id']")
FINAL_C=$(wait_terminal "$SC1" 60) || true
set_status "$SC1" "running"
rewind "$SUBC" "now()"
wait_trig "$SUBC" "len(d['sessions']) >= 2" 15 1 && ok "replace fired a new run" || no "no replacement run"
[ "$(sfield "$SC1" "['status']")" = "cancelled" ] && ok "stale run cancelled" || no "stale run status: $(sfield "$SC1" "['status']")"
sfield "$SC1" "['status_reason']" | grep -q "replaced" && ok "cancel reason names the replacement" || no "reason: $(sfield "$SC1" "['status_reason']")"

say "MISSED skip — SUB D: a 10-minute gap records ONE skip and resumes the cadence"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"schedD-$$\",
  \"task_template\":\"sweep {{fire_time}}\",\"budgets\":$TB,\"autonomous\":true,
  \"schedule\":{\"cron\":\"0 0 3 * * *\",\"timezone\":\"UTC\",\"missed_run_policy\":\"skip\"}}")
SUBD=$(cat "$B" | j "['subscription']['id']")
rewind "$SUBD" "now() - interval '10 minutes'"
wait_trig "$SUBD" "any((i.get('skip_reason') or '') == 'missed' for i in d['invocations'])" 15 1 \
  && ok "missed firing recorded as skipped (reason=missed)" || no "no missed skip"
[ "$(run_count "$SUBD")" = "0" ] && ok "no run created for the missed slot" || no "runs: $(run_count "$SUBD")"
[ "$(skip_count "$SUBD" missed)" = "1" ] && ok "exactly ONE skip row for the whole gap" || no "skips: $(skip_count "$SUBD" missed)"
[ "$(pq "select (next_fire_at > now()) from schedules where subscription_id = '$SUBD'")" = "t" ] \
  && ok "clock resumed at the next future firing" || no "clock not advanced"

say "MISSED catch_up — SUB E: a 10-minute gap fires exactly ONE make-up run"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"schedE-$$\",
  \"task_template\":\"sweep {{fire_time}}\",\"budgets\":$TB,\"autonomous\":true,
  \"schedule\":{\"cron\":\"0 0 3 * * *\",\"timezone\":\"UTC\",\"missed_run_policy\":\"catch_up\"}}")
SUBE=$(cat "$B" | j "['subscription']['id']")
rewind "$SUBE" "now() - interval '10 minutes'"
wait_trig "$SUBE" "len(d['sessions']) >= 1" 15 1 && ok "catch-up run fired" || no "no catch-up run"
sleep 4   # give a would-be second catch-up time to (wrongly) appear
[ "$(run_count "$SUBE")" = "1" ] && ok "exactly ONE catch-up (never fire-all-missed)" || no "runs: $(run_count "$SUBE")"
SE1=$(tget "$SUBE" | j "['sessions'][-1]['id']")
[ "$(sfield "$SE1" "['run_spec']['invocation']['attributes']['catch_up']")" = "True" ] \
  && ok "run is marked catch_up=true in its frozen invocation" || no "catch_up attr wrong"
[ "$(pq "select (next_fire_at > now()) from schedules where subscription_id = '$SUBE'")" = "t" ] \
  && ok "clock resumed after catch-up" || no "clock not advanced"

say "§17 #5 — concurrency_policy governs API invokes too (same create_run gate)"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"apiF-$$\",
  \"task_template\":\"api noop\",\"budgets\":$TB,\"concurrency_policy\":\"skip_if_running\"}")
SUBF=$(cat "$B" | j "['subscription']['id']"); TOKF=$(cat "$B" | j "['token']")
CODE=$(tpost "$TOKF" "/triggers/$SUBF/invoke" '{}' "Idempotency-Key: f1")
SF1=$(cat "$B" | j "['session_id']")
[ "$CODE" = "200" ] && ok "first invoke → run" || no "invoke → $CODE"
FINAL_F=$(wait_terminal "$SF1" 60) || true
set_status "$SF1" "running"
CODE=$(tpost "$TOKF" "/triggers/$SUBF/invoke" '{}' "Idempotency-Key: f2")
[ "$CODE" = "409" ] && ok "API invoke against an active run → 409 skipped" || no "wanted 409, got $CODE"
[ "$(skip_count "$SUBF" overlap)" = "1" ] && ok "API skip visibly recorded (reason=overlap)" || no "skip not recorded"
CODE=$(tpost "$TOKF" "/triggers/$SUBF/invoke" '{}' "Idempotency-Key: f2")
[ "$CODE" = "409" ] && ok "replaying the skipped key returns the skip (409)" || no "wanted 409, got $CODE"
set_status "$SF1" "$FINAL_F"
CODE=$(tpost "$TOKF" "/triggers/$SUBF/invoke" '{}' "Idempotency-Key: f3")
[ "$CODE" = "200" ] && ok "invoke succeeds once the run is terminal (it was the policy)" || no "wanted 200, got $CODE"

say "§17 #5 — default allow: overlapping API invokes still stack (back-compat)"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"apiG-$$\",\"task_template\":\"api noop\",\"budgets\":$TB}")
SUBG=$(cat "$B" | j "['subscription']['id']"); TOKG=$(cat "$B" | j "['token']")
tpost "$TOKG" "/triggers/$SUBG/invoke" '{}' "Idempotency-Key: g1" >/dev/null
SG1=$(cat "$B" | j "['session_id']")
wait_terminal "$SG1" 60 >/dev/null || true
set_status "$SG1" "running"
CODE=$(tpost "$TOKG" "/triggers/$SUBG/invoke" '{}' "Idempotency-Key: g2")
[ "$CODE" = "200" ] && ok "default allow: second invoke → 200 while first is active" || no "wanted 200, got $CODE"
set_status "$SG1" "failed"

say "PUBLISH — a schedule-fired run's terminal result arrives signed (Phase 2 reused)"
DFILE=""
for _ in $(seq 1 30); do
  DFILE=$(grep -l "$SA" "$RCV_DIR"/delivery-*.json 2>/dev/null | head -1)
  [ -n "$DFILE" ] && break
  sleep 2
done
[ -n "$DFILE" ] && ok "callback received for schedule-fired run" || no "no callback within 60s"
if [ -n "$DFILE" ]; then
  TS=$(python3 -c "import json;print(json.load(open('$DFILE'))['headers']['x-fluidbox-timestamp'])")
  SIG=$(python3 -c "import json;print(json.load(open('$DFILE'))['headers']['x-fluidbox-signature'])")
  BODY=$(python3 -c "import json;print(json.load(open('$DFILE'))['body'])")
  CALC="v1=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SECA" | sed 's/^.* //')"
  [ "$CALC" = "$SIG" ] && ok "HMAC signature verifies" || no "signature mismatch"
  python3 -c "
import json
p = json.loads(json.load(open('$DFILE'))['body'])
assert p['run']['invocation']['kind'] == 'schedule'
" && ok "payload carries the schedule invocation" || no "payload invocation wrong"
fi

say "LIVE — §12: repository-maintenance agent on a schedule; overlaps skip; result published"
if [ "${E2E_SKIP_LIVE:-0}" = "1" ] || [ -z "${ANTHROPIC_API_KEY:-}" ] \
   || ! curl -fsS -m 3 http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1; then
  echo "  SKIP: live tier needs ANTHROPIC_API_KEY + gateway (E2E_SKIP_LIVE=${E2E_SKIP_LIVE:-0})"
else
  FX=$(mktemp -d "${TMPDIR:-/tmp}/fbx-sched-fx.XXXXXX")
  git -C "$FX" init -q -b main
  git -C "$FX" config user.email e2e@fluidbox.dev
  git -C "$FX" config user.name fbx-e2e
  echo "maintenance-target v1" > "$FX/f.txt"; git -C "$FX" add -A; git -C "$FX" commit -qm c1
  CODE=$(post "/triggers" "{\"agent\":\"claude-fixer\",\"name\":\"sched-live-$$\",
    \"task_template\":\"Repository maintenance run (fired {{fire_time}}): read f.txt in the workspace and state its exact contents, then stop. Do not modify anything.\",
    \"autonomous\":true,\"concurrency_policy\":\"skip_if_running\",
    \"workspace\":{\"kind\":\"git_repository\",\"clone_url\":\"file://$FX\",\"ref\":\"main\"},
    \"schedule\":{\"cron\":\"*/5 * * * * *\",\"timezone\":\"UTC\"},
    \"callback_url\":\"http://127.0.0.1:$RCV_PORT/cb\"}")
  SUBL=$(cat "$B" | j "['subscription']['id']"); SECL=$(cat "$B" | j "['callback_secret']")
  [ "$CODE" = "200" ] && ok "live maintenance schedule created" || no "live create → $CODE: $(cat "$B")"
  wait_trig "$SUBL" "len(d['sessions']) >= 1" 20 1 && ok "live schedule fired" || no "live schedule did not fire"
  SL=$(tget "$SUBL" | j "['sessions'][-1]['id']")
  FINALL=$(wait_terminal "$SL" 420) || true
  post "/triggers/$SUBL/disable" "{}" >/dev/null
  # A follow-up firing may have started in the completion→disable window; cancel strays.
  tget "$SUBL" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for s in d['sessions']:
    if s['status'] not in ('completed','failed','cancelled','budget_exceeded'):
        print(s['id'])" | while read -r sid; do
    curl -s -X POST -H "$H" "$API/v1/sessions/$sid/cancel" >/dev/null
  done
  [ "$FINALL" = "completed" ] && ok "live maintenance run completed" || no "live terminal: $FINALL"
  SKIPS=$(skip_count "$SUBL" overlap)
  [ "${SKIPS:-0}" -ge 1 ] && ok "overlapping firings skipped while it worked ($SKIPS)" || no "no overlap skips during live run"
  LFILE=""
  for _ in $(seq 1 30); do
    LFILE=$(grep -l "$SL" "$RCV_DIR"/delivery-*.json 2>/dev/null | head -1)
    [ -n "$LFILE" ] && break
    sleep 2
  done
  if [ -n "$LFILE" ]; then
    LTS=$(python3 -c "import json;print(json.load(open('$LFILE'))['headers']['x-fluidbox-timestamp'])")
    LSIG=$(python3 -c "import json;print(json.load(open('$LFILE'))['headers']['x-fluidbox-signature'])")
    LBODY=$(python3 -c "import json;print(json.load(open('$LFILE'))['body'])")
    LCALC="v1=$(printf '%s.%s' "$LTS" "$LBODY" | openssl dgst -sha256 -hmac "$SECL" | sed 's/^.* //')"
    [ "$LCALC" = "$LSIG" ] && ok "live callback signature verifies" || no "live signature mismatch"
    python3 -c "
import json
p = json.loads(json.load(open('$LFILE'))['body'])
assert p['run']['status'] == 'completed'
assert p['usage']['cost_usd'] > 0, 'live run must have real cost'
assert p['run']['summary'], 'live run must carry a summary'
assert p['run']['invocation']['kind'] == 'schedule'
" && ok "live callback: completed + cost + summary + schedule invocation" || no "live payload incomplete"
  else
    no "no live callback within 60s"
  fi
  rm -rf "$FX"
fi

# Housekeeping: silence every schedule this phase created.
for S in "$SUBA" "$SUBB" "$SUBC" "$SUBD" "$SUBE"; do
  [ -n "${S:-}" ] && post "/triggers/$S/disable" "{}" >/dev/null
done
rm -rf "$RCV_DIR"

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
```

Make it executable: `chmod +x scripts/e2e-schedule.sh`.

Two fragile spots to verify while implementing (fix in the script, not by weakening asserts):
- `['sessions'][-1]` — `list_subscription_sessions` orders `created_at desc`, so index `-1` is the OLDEST (first) run; that is the intent everywhere it appears (first firing / stale run). Double-check each use.
- The `catch_up` attribute prints as Python `True` via `j` — the comparison string must match.

- [ ] **Step 2: Wire into scripts/e2e.sh**

- Header comment: add `#   phase 5: scheduled borrowing (cron firing, exactly-once, overlap/missed policies)` and renumber failure paths to phase 6.
- Replace the tail phases:

```bash
say "PHASE 5/6 — scheduled borrowing"
stop_server   # the schedule suite owns (and restarts) its own control plane
bash "$ROOT/scripts/e2e-schedule.sh" || SUITE_FAIL=1

say "PHASE 6/6 — failure paths"
bash "$ROOT/scripts/e2e-failures.sh" || SUITE_FAIL=1
```

and update the earlier `say` lines from `X/5` to `X/6`.

- [ ] **Step 3: Run the new phase standalone, then the whole suite**

```bash
bash scripts/e2e-schedule.sh     # fast iteration on this phase alone
just e2e                          # the full bar — ALL phases must pass
```
Expected: new phase ~45 checks green; suite total ≈ 121 + new checks, ALL PHASES PASSED.

- [ ] **Step 4: Commit**

```bash
git add scripts/e2e-schedule.sh scripts/e2e.sh
git commit -m "test(e2e): scheduled-borrowing acceptance phase — firing, exactly-once across restart, overlap/missed policies, API-invoke gating, signed publish"
```

---

### Task 8: Docs — HANDOVER rev 5 + CLAUDE.md invariants

**Files:**
- Modify: `docs/HANDOVER.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: CLAUDE.md**

1. In the `just e2e` command comment, add schedules: `live demo A + governance + git workspaces + api triggers + schedules + failure paths`.
2. Add one invariant bullet to "Load-bearing invariants" after the result-delivery bullet:

```markdown
- **A schedule is a trigger subscription with a clock, never a new object** (`schedules`, migration 0004). The tick worker fires through the same `run_service::create_run` with `InvocationContext.kind=schedule`; firing is **exactly-once** via a deterministic idempotency claim (`sched:{fire_time}` on `trigger_invocations`) bound to the session in the same transaction. §17 #5 (settled 2026-07-10): `concurrency_policy` defaults `allow` and is enforced in `create_run` for ALL invocations (`skip_if_running`/`replace` opt-in; API invokes get a 409 skip); missed-run defaults `skip` — a gap records ONE skip row, `catch_up` fires exactly ONE make-up run, never fire-all-missed. Skips are terminal claim rows (`skip_reason`), visible on the subscription. A disabled subscription's schedule does not advance — re-enabling goes through the missed-run path.
```

- [ ] **Step 2: HANDOVER.md rev 5**

- Header: `(rev 5: borrow-the-agent Phase 3 shipped)`; state adds **scheduled borrowing (Phase 3)** and the new e2e totals (read them from the actual run output).
- §1: add a Phase 3 bullet mirroring the Phase 2 one: schedules table + tick worker, §17 #5 settled defaults (allow / skip, enforced in create_run for all invocations), deterministic-claim exactly-once with atomic bind, one-skip-per-gap missed handling, dashboard schedule status, `scripts/e2e-schedule.sh` acceptance.
- §4 rough edges: add — schedules are create-only (edit = recreate, like subscriptions); one schedule per subscription; `MISSED_GRACE_SECS=30` constant (a fire >30s late is "missed"); a missed gap records one skip row keyed at the oldest missed fire time (intermediates get no rows); the fake-active e2e seam flips `sessions.status` via psql.
- §5: add "**Schedule an agent:** Triggers page → New trigger → 'run on a schedule' (or `POST /v1/triggers` with `schedule:{cron,timezone,missed_run_policy}` + `concurrency_policy`); watch firings & skips on the trigger's activity panel."
- §6: mark Phase 3 ✅ shipped 2026-07-10 with the acceptance script and the settled §17 #5 line; next = Phase 4 (GitHub PR fan-out) — do not start it.

- [ ] **Step 3: Final verification + commit**

```bash
just check    # fmt + clippy -D warnings + tests + web build
```
Expected: green.

```bash
git add docs/HANDOVER.md CLAUDE.md docs/superpowers/plans/2026-07-10-phase3-scheduled-borrowing.md
git commit -m "docs: handover rev 5 — design-doc Phase 3 (scheduled borrowing) shipped; §17 #5 settled defaults recorded"
```

---

## Self-Review Notes

- **Spec coverage:** schedules table w/ explicit tz + next/last fire + missed policy (§10) → Task 2; `concurrency_policy` on `trigger_subscriptions` (§6.2, deferred from Phase 2) → Task 2/3; scheduler worker shaped like deliveries.rs → Task 5; exactly-once via Phase 2 claim table + deterministic key → Tasks 2/3/5 + e2e restart test; overlap `allow|skip_if_running|replace` with visible skips → Tasks 3/5 + e2e; missed `skip`/one-catch-up → Task 5 + e2e; dashboard status → Task 6; fire-fast e2e seam (seconds-field cron + psql time travel) → Task 7; §12 acceptance demo (repository-maintenance agent, skips overlapping work, publishes result) → Task 7 live tier.
- **Type consistency:** `RunCreation`/`bound_invocation` names used identically in Tasks 3/5; `fire_key` format `sched:%Y-%m-%dT%H:%M:%SZ` matches the e2e `${KEY#sched:}` parsing and the DB test literal; `concurrency_policy` param position (after `autonomy`) consistent between Task 2 signature and Task 4 caller.
- **Known accepted risks (document, don't fix here):** skip_if_running has a benign race window between the active-count read and session insert (single scheduler is serial; concurrent API invokes could both pass — same best-effort class as Phase 2's delivery-enqueue crash window). Live-tier follow-up firing in the completion→disable window is cancelled by the script.
