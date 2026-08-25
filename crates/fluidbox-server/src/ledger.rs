//! Server-side ledger helper.
//!
//! Durability and the shared operational mirror live together in
//! `fluidbox-db`: that layer owns the transaction commit boundary and therefore
//! can cover both ordinary appends and approval events written inside larger
//! transactions. This helper adds server-local operational metrics only after a
//! successful append.

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
    let metrics_body = body.clone();
    let env = EventEnvelope::new(session, actor, body);
    let redacted = state.redactor.scrub(env);
    match fluidbox_db::append_event(&state.pool, scope, redacted).await {
        Ok(seq) => {
            // Metrics must obey the same durable-event boundary as the mirror:
            // a failed append is not an event and must not increment counters.
            observe_event(&state.metrics, &metrics_body);
            state.metrics.ledger_events.inc();
            seq
        }
        Err(error) => {
            // `record` preserves its historical best-effort signature, so this
            // line is the operational signal that the audit append was lost.
            tracing::error!(
                session_id = %session,
                tenant_id = %scope.tenant_id(),
                error = %error,
                error_kind = fluidbox_obs::field::error_kind::DB,
                "LEDGER APPEND FAILED — this event is absent from the audit trail"
            );
            -1
        }
    }
}

/// Fold a committed canonical event into the server's operational metrics.
/// Only bounded classification fields are read; ids and content are excluded
/// from metric labels to keep their cardinality bounded.
fn observe_event(metrics: &crate::metrics::Metrics, body: &EventBody) {
    match body {
        EventBody::ToolDecision {
            verdict, source, ..
        } => {
            metrics.gate_verdicts.inc(verdict);
            if verdict != "allow" {
                metrics.gate_sources.inc(source);
            }
        }
        EventBody::BrokeredToolCall {
            latency_ms,
            outcome,
            ..
        } => {
            metrics.broker_latency_ms.observe(*latency_ms as f64);
            if let Some(outcome) = outcome {
                metrics.brokered_outcomes.inc(outcome);
            }
        }
        EventBody::CallbackDelivered { .. } => metrics.deliveries.inc("delivered"),
        EventBody::CallbackFailed { .. } => metrics.deliveries.inc("failed"),
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
        let metrics = Metrics::default();
        observe_event(&metrics, &decision("allow", "policy"));
        observe_event(&metrics, &decision("deny", "capability"));
        observe_event(&metrics, &decision("require_approval", "policy"));
        assert_eq!(metrics.gate_verdicts.get("allow"), 1);
        assert_eq!(metrics.gate_verdicts.get("deny"), 1);
        assert_eq!(metrics.gate_verdicts.get("require_approval"), 1);
        assert_eq!(metrics.gate_sources.get("capability"), 1);
        assert_eq!(metrics.gate_sources.get("policy"), 1);
    }

    #[test]
    fn brokered_call_observes_latency_and_outcome() {
        let metrics = Metrics::default();
        observe_event(
            &metrics,
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
        assert_eq!(metrics.broker_latency_ms.count(), 1);
        assert_eq!(metrics.brokered_outcomes.get("ambiguous"), 1);
    }

    #[test]
    fn callback_events_count_delivery_outcomes() {
        let metrics = Metrics::default();
        observe_event(
            &metrics,
            &EventBody::CallbackDelivered {
                delivery_id: Uuid::nil(),
                url: "https://x".into(),
                attempt: 1,
            },
        );
        observe_event(
            &metrics,
            &EventBody::CallbackFailed {
                delivery_id: Uuid::nil(),
                url: "https://x".into(),
                attempts: 6,
                error: "gone".into(),
            },
        );
        assert_eq!(metrics.deliveries.get("delivered"), 1);
        assert_eq!(metrics.deliveries.get("failed"), 1);
    }
}
