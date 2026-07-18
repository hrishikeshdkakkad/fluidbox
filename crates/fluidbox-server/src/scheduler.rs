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
use crate::triggers::{render_task_template, schedule_context, sub_run_params, SubRunParams};
use chrono::{DateTime, SecondsFormat, Utc};
use fluidbox_core::schedule::{CronSchedule, MissedRunPolicy};
use fluidbox_core::spec::{InvocationContext, InvocationKind};
use fluidbox_db::{ScheduleRow, TenantScope};
use std::time::Duration;

const TICK: Duration = Duration::from_secs(1);
/// A firing older than this is "missed" (control plane down or subscription
/// disabled across it) and goes through missed_run_policy; younger, it just
/// fires — a slow tick is not an outage.
const MISSED_GRACE_SECS: i64 = 30;

/// Deterministic idempotency key for one scheduled fire time.
pub fn fire_key(fire_time: DateTime<Utc>) -> String {
    format!(
        "sched:{}",
        fire_time.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}

pub fn spawn_worker(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            let due = match fluidbox_db::system_worker::due_schedules(&state.pool, 20).await {
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
    let Some(fire_time) = sched.next_fire_at else {
        return;
    };
    // Worker path: the schedule row from the global `due_schedules` scan carries
    // only a subscription id, so resolve the subscription cross-tenant, then
    // derive the owning tenant's scope for every subsequent call.
    let sub = match fluidbox_db::system_worker::get_trigger_subscription(
        &state.pool,
        sched.subscription_id,
    )
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return, // subscription deleted mid-tick; cascade wins
        Err(e) => {
            tracing::warn!("schedule {}: subscription lookup failed: {e}", sched.id);
            return;
        }
    };
    let scope = TenantScope::assume(sub.tenant_id);
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
            fluidbox_db::claim_invocation(&state.pool, scope, sub.id, &key, &digest).await
        {
            fluidbox_db::mark_invocation_skipped(&state.pool, scope, invocation_id, "missed")
                .await
                .ok();
            tracing::info!("schedule {}: missed {} → skipped", sched.id, key);
        }
        advance(state, scope, sched, fire_time, next, None).await;
        return;
    }

    // On-time fire, or the single catch-up firing for a missed gap.
    match fluidbox_db::claim_invocation(&state.pool, scope, sub.id, &key, &digest).await {
        Ok(fluidbox_db::InvocationClaim::Claimed { invocation_id }) => {
            let created =
                build_and_create(state, scope, &sub, sched, fire_time, missed, invocation_id).await;
            match created {
                Ok(RunCreation::Created(session)) => {
                    tracing::info!("schedule {}: fired {} → run {}", sched.id, key, session.id);
                    advance(state, scope, sched, fire_time, next, Some(fire_time)).await;
                }
                Ok(RunCreation::SkippedOverlap { running_session_id }) => {
                    fluidbox_db::mark_invocation_skipped(
                        &state.pool,
                        scope,
                        invocation_id,
                        "overlap",
                    )
                    .await
                    .ok();
                    tracing::info!(
                        "schedule {}: {} skipped (run {} still active)",
                        sched.id,
                        key,
                        running_session_id
                    );
                    advance(state, scope, sched, fire_time, next, None).await;
                }
                Ok(RunCreation::ReplaceUnpersisted { running_session_id }) => {
                    // Transient replace failure: record a visible skip and
                    // advance — the NEXT tick fires fresh (unlike an error,
                    // which would mark this firing permanently lost).
                    fluidbox_db::mark_invocation_skipped(
                        &state.pool,
                        scope,
                        invocation_id,
                        "replace_cancel_unpersisted",
                    )
                    .await
                    .ok();
                    tracing::warn!(
                        "schedule {}: {} skipped (cancel of {} not persisted; next tick retries)",
                        sched.id,
                        key,
                        running_session_id
                    );
                    advance(state, scope, sched, fire_time, next, None).await;
                }
                Err(e) => {
                    // A failed firing is recorded, not retried — retrying a
                    // config error every tick would loop forever.
                    fluidbox_db::mark_invocation_skipped(
                        &state.pool,
                        scope,
                        invocation_id,
                        &format!("error: {e}"),
                    )
                    .await
                    .ok();
                    tracing::warn!("schedule {}: firing {} failed: {e}", sched.id, key);
                    advance(state, scope, sched, fire_time, next, None).await;
                }
            }
        }
        // Crash recovery: this fire time already produced its outcome
        // (a bound run or a recorded skip) — advance past it, fire nothing.
        Ok(fluidbox_db::InvocationClaim::Replay { .. })
        | Ok(fluidbox_db::InvocationClaim::Skipped { .. }) => {
            advance(state, scope, sched, fire_time, next, None).await;
        }
        // Another worker holds this fire mid-creation: leave next_fire_at
        // alone; the next tick resolves to Replay/Skipped.
        Ok(fluidbox_db::InvocationClaim::InFlight) => {}
        Err(e) => tracing::warn!("schedule {}: claim failed: {e}", sched.id),
    }
}

#[allow(clippy::too_many_arguments)]
async fn build_and_create(
    state: &AppState,
    scope: TenantScope,
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
    let SubRunParams {
        autonomy,
        budget_override,
        result_destinations,
        workspace: explicit_workspace,
    } = sub_run_params(sub)?;
    run_service::create_run(
        state,
        scope,
        CreateRun {
            agent: sub.agent_id.to_string(),
            revision: match sub.pinned_revision_id {
                Some(rid) => RevisionSelector::Pinned(rid),
                None => RevisionSelector::Latest,
            },
            task,
            explicit_workspace,
            autonomy,
            trust_tier: fluidbox_core::spec::TrustTier::Trusted,
            budget_override,
            // The subscription's own capability keep-list applies inside
            // create_run; firings add no further narrowing.
            capability_selection: None,
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
                ..Default::default()
            },
            // A schedule tick has no directly-authenticated user.
            invoked_by_user_id: None,
            // Server-derived authority only; a schedule names no explicit binding.
            explicit_bindings: std::collections::HashMap::new(),
            result_destinations,
            bound_invocation: Some(invocation_id),
            bound_dispatch: None,
        },
    )
    .await
}

async fn advance(
    state: &AppState,
    scope: TenantScope,
    sched: &ScheduleRow,
    from: DateTime<Utc>,
    to: Option<DateTime<Utc>>,
    fired_at: Option<DateTime<Utc>>,
) {
    match fluidbox_db::advance_schedule(&state.pool, scope, sched.id, from, to, fired_at).await {
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
