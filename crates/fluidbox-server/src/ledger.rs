//! Thin helper to append events through the redactor (the only door).

use crate::state::AppState;
use fluidbox_core::event::{Actor, EventBody, EventEnvelope};
use fluidbox_db::TenantScope;
use uuid::Uuid;

/// Append one event, scoped to the session's tenant. `scope` MUST be the
/// session's own tenant — `append_event` refuses (RowNotFound) a session that
/// does not belong to it, so a wrong scope drops the event rather than
/// cross-writing.
pub async fn record(
    state: &AppState,
    scope: TenantScope,
    session: Uuid,
    actor: Actor,
    body: EventBody,
) -> i64 {
    // Operational metrics (Phase F, #34) are derived from the same canonical
    // events they audit: this is the ONE funnel every ledger write passes
    // through, so a decision/outcome cannot be counted twice or missed at a
    // forgotten return path. Read from `&body` BEFORE it moves into the envelope.
    observe_event(&state.metrics, &body);
    let env = EventEnvelope::new(session, actor, body);
    let redacted = state.redactor.scrub(env);
    match fluidbox_db::append_event(&state.pool, scope, redacted).await {
        Ok(seq) => {
            state.metrics.ledger_events.inc();
            seq
        }
        Err(e) => {
            tracing::error!("failed to append event for {session}: {e}");
            -1
        }
    }
}

/// Fold a canonical event into the operational-metrics registry. No ids, hosts,
/// credentials or payloads are read — only the bounded classification fields
/// (verdict, source, outcome, latency) the design's §Operational-metrics list
/// asks for. A variant with no metric is deliberately a no-op. Takes `&Metrics`
/// (not `&AppState`) so the whole event→metric mapping is unit-testable with no
/// database — the derivation is where a wrong label or a missed arm would hide.
fn observe_event(m: &crate::metrics::Metrics, body: &EventBody) {
    match body {
        EventBody::ToolDecision {
            verdict, source, ..
        } => {
            m.gate_verdicts.inc(verdict);
            // The deciding stage is only meaningful for a non-allow verdict.
            if verdict != "allow" {
                m.gate_sources.inc(source);
            }
        }
        EventBody::BrokeredToolCall {
            latency_ms,
            outcome,
            ..
        } => {
            m.broker_latency_ms.observe(*latency_ms as f64);
            if let Some(o) = outcome {
                m.brokered_outcomes.inc(o);
            }
            // NB: the upstream HTTP response class (401/404/429/5xx) is counted at
            // the broker's own classification site, where the numeric status is in
            // hand — NOT re-parsed out of this event's redacted error string.
        }
        EventBody::CallbackDelivered { .. } => m.deliveries.inc("delivered"),
        EventBody::CallbackFailed { .. } => m.deliveries.inc("failed"),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Metrics;

    fn decision(verdict: &str, source: &str) -> EventBody {
        EventBody::ToolDecision {
            tool_call_id: "t".into(),
            tool: "Bash".into(),
            verdict: verdict.into(),
            source: source.into(),
            original_verdict: None,
            reason: None,
        }
    }

    #[test]
    fn tool_decision_counts_verdict_always_and_source_only_when_not_allow() {
        let m = Metrics::default();
        observe_event(&m, &decision("allow", "policy"));
        observe_event(&m, &decision("deny", "capability"));
        observe_event(&m, &decision("require_approval", "policy"));
        assert_eq!(m.gate_verdicts.get("allow"), 1);
        assert_eq!(m.gate_verdicts.get("deny"), 1);
        assert_eq!(m.gate_verdicts.get("require_approval"), 1);
        // An allow must NOT touch the deny-source family; the two non-allows must.
        assert_eq!(m.gate_sources.get("capability"), 1);
        assert_eq!(m.gate_sources.get("policy"), 1);
    }

    #[test]
    fn brokered_call_observes_latency_and_outcome() {
        let m = Metrics::default();
        observe_event(
            &m,
            &EventBody::BrokeredToolCall {
                tool_call_id: "t".into(),
                tool: "mcp__x__y".into(),
                server: "x".into(),
                binding_id: None,
                ok: false,
                latency_ms: 37,
                result_digest: None,
                error: Some("boom".into()),
                outcome: Some("ambiguous".into()),
            },
        );
        assert_eq!(m.broker_latency_ms.count(), 1);
        assert_eq!(m.brokered_outcomes.get("ambiguous"), 1);
    }

    #[test]
    fn callback_events_count_delivery_outcomes() {
        let m = Metrics::default();
        observe_event(
            &m,
            &EventBody::CallbackDelivered {
                delivery_id: uuid::Uuid::nil(),
                url: "https://x".into(),
                attempt: 1,
            },
        );
        observe_event(
            &m,
            &EventBody::CallbackFailed {
                delivery_id: uuid::Uuid::nil(),
                url: "https://x".into(),
                attempts: 6,
                error: "gone".into(),
            },
        );
        assert_eq!(m.deliveries.get("delivered"), 1);
        assert_eq!(m.deliveries.get("failed"), 1);
    }
}
