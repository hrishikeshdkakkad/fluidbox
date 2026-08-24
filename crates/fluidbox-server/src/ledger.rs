//! Thin helper to append events through the redactor (the only door) — and the
//! one place canonical events become log records.
//!
//! # Why the logging lives here
//!
//! This function is already documented as "the ONE funnel every ledger write
//! passes through, so a decision/outcome cannot be counted twice or missed at a
//! forgotten return path". That property is exactly what structured logging
//! needs, and it is not available anywhere else: the permission gate alone has a
//! dozen return points, the orchestrator's transition funnel more. Deriving log
//! records here rather than sprinkling `info!` through those paths means a new
//! event type is logged the day it is added, and a moved return statement cannot
//! silently stop logging.
//!
//! # The content boundary
//!
//! **Logs carry identity, classification, timing and outcome. They never carry
//! content.** Tool arguments, agent messages, prompts, tool results and command
//! lines stay in the ledger and do not appear here — not even redacted, and not
//! even at DEBUG.
//!
//! That is a tenancy decision, not a squeamish one. The ledger is tenant-scoped
//! with row-level security behind it; the log stream is a single shared pipe to
//! whatever aggregator the deployment ships to, with one access-control list for
//! every tenant at once. Putting one tenant's agent commands there would quietly
//! undo a property this system calls a signature requirement. So the log records
//! the SHAPE of what happened (`tool`, `verdict`, `source`, `input_digest`,
//! `bytes`, `latency`) and `session_id` + `tool_call_id` join it back to the
//! ledger, where the content is — under the access controls that content
//! deserves.

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
    // Logged from the REDACTED body, never the raw one: the ledger's own
    // scrubbing applies first, then the log formatter's runs on top. Two
    // independent redactors, in series, on the way to a shared pipe.
    log_event(session, scope.tenant_id(), actor, &redacted.get().body);
    match fluidbox_db::append_event(&state.pool, scope, redacted).await {
        Ok(seq) => {
            state.metrics.ledger_events.inc();
            seq
        }
        Err(e) => {
            // The audit trail just lost an entry. That is a durability failure,
            // not a nuisance — and because `record` returns `-1` rather than
            // propagating, this log line is the ONLY signal it happened.
            tracing::error!(
                session_id = %session,
                tenant_id = %scope.tenant_id(),
                error = %e,
                error_kind = fluidbox_obs::field::error_kind::DB,
                "LEDGER APPEND FAILED — this event is absent from the audit trail"
            );
            -1
        }
    }
}

/// Mirror one canonical event into the structured log.
///
/// Levels are chosen so that the DEFAULT filter shows an operator the story of a
/// run — lifecycle, decisions that refused something, failures — and `debug`
/// adds the step-by-step. The rule of thumb: if a human would want to know it
/// happened without going looking, it is INFO; if it only matters while
/// debugging, it is DEBUG; if it needs someone to act, it is WARN.
///
/// Takes plain ids rather than `&AppState` so the whole mapping is unit-testable
/// against a capturing subscriber with no database — the derivation is where a
/// wrong level or a leaked field would hide.
fn log_event(session: Uuid, tenant: Uuid, actor: Actor, body: &EventBody) {
    let kind = body.type_name();
    // Every record carries the run, the tenant, the actor and the canonical
    // event name, so one filter (`event="tool.decision"`) reaches exactly the
    // population the ledger query would.
    macro_rules! ev {
        ($lvl:ident, $($rest:tt)*) => {
            tracing::$lvl!(
                session_id = %session,
                tenant_id = %tenant,
                actor = actor.as_str(),
                event = %kind,
                $($rest)*
            )
        };
    }
    match body {
        EventBody::SessionCreated {
            agent, autonomy, ..
        } => ev!(info, agent = %agent, autonomy = %autonomy, "run created"),

        EventBody::StatusChanged { from, to, reason } => {
            ev!(info, from = %from, to = %to, reason = reason.as_deref(), "run status changed")
        }

        EventBody::WorkspaceInitialized {
            base_commit,
            files,
            repo,
            r#ref,
        } => ev!(
            info,
            base_commit = base_commit.as_deref(),
            files = files.unwrap_or(0),
            // The clone URL is credential-free by construction here (the event's
            // own doc says so) and is the thing you need to tell "wrong repo"
            // from "wrong ref". The formatter scrubs it regardless.
            repo = repo.as_deref(),
            git_ref = r#ref.as_deref(),
            "workspace initialised"
        ),

        // Content stays in the ledger — see the module docs. The SHAPE (who
        // spoke, how much) is the operational signal and is all that is here.
        EventBody::AgentMessage { role, text } => {
            ev!(debug, role = %role, text_bytes = text.len(), "agent message")
        }

        EventBody::ToolRequested {
            tool,
            tool_call_id,
            input_digest,
            ..
        } => ev!(
            debug,
            tool = %tool,
            tool_call_id = %tool_call_id,
            digest = %input_digest,
            "tool requested"
        ),

        // The single most important record in the system. An `allow` is the
        // common case and sits at DEBUG; anything that REFUSED or PAUSED is at
        // INFO, because "why did this run not do the thing" is the question this
        // answers and it should be answerable without raising the level.
        EventBody::ToolDecision {
            tool_call_id,
            tool,
            verdict,
            source,
            original_verdict,
            reason,
        } => {
            if verdict == "allow" {
                ev!(
                    debug,
                    tool = %tool,
                    tool_call_id = %tool_call_id,
                    verdict = %verdict,
                    source = %source,
                    "tool call allowed"
                );
            } else {
                ev!(
                    info,
                    tool = %tool,
                    tool_call_id = %tool_call_id,
                    verdict = %verdict,
                    source = %source,
                    original_verdict = original_verdict.as_deref(),
                    reason = reason.as_deref(),
                    "tool call refused or held for approval"
                );
            }
        }

        EventBody::ToolCompleted {
            tool_call_id,
            tool,
            ok,
            ..
        } => {
            if *ok {
                ev!(debug, tool = %tool, tool_call_id = %tool_call_id, "tool completed")
            } else {
                ev!(info, tool = %tool, tool_call_id = %tool_call_id, outcome = "error", "tool failed")
            }
        }

        EventBody::ApprovalRequested {
            approval_id,
            tool_call_id,
            tool,
            risk,
            expires_at,
            ..
        } => ev!(
            info,
            approval_id = %approval_id,
            tool_call_id = %tool_call_id,
            tool = %tool,
            risk = risk.as_deref(),
            expires_at = %expires_at,
            "waiting for a human decision"
        ),

        EventBody::ApprovalDecided {
            approval_id,
            tool_call_id,
            decision,
            decided_by,
        } => ev!(
            info,
            approval_id = %approval_id,
            tool_call_id = %tool_call_id,
            decision = %decision,
            // The user id or the literal "operator" — never a credential.
            decided_by = %decided_by,
            "approval decided"
        ),

        EventBody::ModelResponse {
            model,
            input_tokens,
            output_tokens,
            cost_usd,
            ..
        } => ev!(
            debug,
            model = %model,
            input_tokens = *input_tokens,
            output_tokens = *output_tokens,
            cost_usd = cost_usd.unwrap_or(0.0),
            "model responded"
        ),

        EventBody::BudgetExceeded {
            budget,
            limit,
            spent,
        } => ev!(
            warn,
            budget = %budget,
            limit = %limit,
            spent = %spent,
            error_kind = fluidbox_obs::field::error_kind::BUDGET,
            "run stopped: budget exceeded"
        ),

        EventBody::RunResult { outcome, .. } => {
            ev!(info, outcome = %outcome, "run finished")
        }

        // WARN, not ERROR: a run failing is usually the tenant's code or the
        // agent's judgement, not a fault in this control plane. The control
        // plane's own faults are logged where they happen, at ERROR.
        EventBody::RunError { message } => {
            ev!(warn, error = %message, outcome = "error", "run errored")
        }

        EventBody::CallbackDelivered {
            delivery_id,
            url,
            attempt,
        } => ev!(
            debug,
            delivery_id = %delivery_id,
            host = fluidbox_obs::url_host(url),
            attempt = *attempt,
            "result callback delivered"
        ),

        EventBody::CallbackFailed {
            delivery_id,
            url,
            attempts,
            error,
        } => ev!(
            warn,
            delivery_id = %delivery_id,
            host = fluidbox_obs::url_host(url),
            attempt = *attempts,
            error = %error,
            error_kind = fluidbox_obs::field::error_kind::UPSTREAM,
            "result callback gave up"
        ),

        EventBody::CapabilitiesFrozen { bundles, tools } => {
            ev!(
                info,
                bundles = bundles.len(),
                tools = *tools,
                "capabilities frozen"
            )
        }

        EventBody::NetworkGrantFrozen {
            mode,
            targets,
            digest,
            awaiting_authorization,
            ..
        } => ev!(
            info,
            mode = %mode,
            targets = targets.len(),
            digest = %digest,
            awaiting_authorization = *awaiting_authorization,
            "network grant frozen"
        ),

        EventBody::NetworkDenied {
            target,
            port,
            protocol,
            decision,
            rule,
        } => ev!(
            info,
            target = %target,
            port = *port,
            protocol = %protocol,
            decision = %decision,
            policy_rule = rule.as_deref(),
            "sandbox egress denied by the datapath"
        ),

        // WARN: past the per-session cap means something is scanning, and the
        // per-flow events stopped — so this is the last chance to notice.
        EventBody::NetworkDeniedRollup {
            suppressed,
            distinct_targets,
            targets_truncated,
            ..
        } => ev!(
            warn,
            suppressed = *suppressed,
            distinct_targets = *distinct_targets,
            truncated = *targets_truncated,
            "sandbox egress denials suppressed past the per-session cap"
        ),

        // WARN because the ABSENCE of denial events must never be read as
        // evidence there were none — which is exactly what a quiet log invites.
        EventBody::NetworkObservationDegraded { reason } => {
            ev!(warn, reason = %reason, "network observation degraded — denials may be unrecorded")
        }

        EventBody::NetworkGrantRevoked { mode, reason } => {
            ev!(info, mode = %mode, reason = %reason, "network grant revoked")
        }

        EventBody::ArtifactCollected {
            kind: k,
            name,
            bytes,
            truncated,
            ..
        } => ev!(
            debug,
            artifact_kind = %k,
            name = %name,
            bytes = *bytes,
            truncated = *truncated,
            "artifact collected"
        ),

        EventBody::ArtifactMissing { kind: k, reason } => ev!(
            warn,
            artifact_kind = %k,
            reason = %reason,
            "artifact NOT collected — its absence is explicit, not 'no changes'"
        ),

        EventBody::QuiesceRequested { deadline_secs } => {
            ev!(info, deadline_secs = *deadline_secs, "quiesce requested")
        }

        EventBody::BrokeredToolCall {
            tool_call_id,
            tool,
            server,
            binding_id,
            ok,
            latency_ms,
            error,
            outcome,
            ..
        } => {
            if *ok {
                ev!(
                    debug,
                    tool = %tool,
                    tool_call_id = %tool_call_id,
                    mcp_server = %server,
                    binding_id = binding_id.map(|b| b.to_string()),
                    duration_ms = *latency_ms,
                    outcome = outcome.as_deref().unwrap_or("succeeded"),
                    "brokered tool call"
                )
            } else {
                ev!(
                    info,
                    tool = %tool,
                    tool_call_id = %tool_call_id,
                    mcp_server = %server,
                    binding_id = binding_id.map(|b| b.to_string()),
                    duration_ms = *latency_ms,
                    outcome = outcome.as_deref().unwrap_or("failed_upstream"),
                    error = error.as_deref(),
                    error_kind = fluidbox_obs::field::error_kind::UPSTREAM,
                    "brokered tool call failed"
                )
            }
        }

        // A newer component wrote an event this binary does not know. Worth a
        // line — it means a version skew — but not worth its payload.
        EventBody::Unknown(_) => ev!(debug, "unrecognised event type (version skew?)"),
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

    // ── The ledger → log mirror ────────────────────────────────────────────

    use fluidbox_obs::capture::CaptureWriter;

    fn capture_events(bodies: Vec<EventBody>) -> Vec<serde_json::Value> {
        let w = CaptureWriter::new();
        let cfg = fluidbox_obs::LogConfig {
            format: fluidbox_obs::Format::Json,
            // `trace` so the DEBUG arms are exercised too — a content leak at
            // DEBUG is still a content leak.
            filter: "trace".into(),
            throttle_per_sec: 0,
            ..Default::default()
        };
        let (sub, _h) = fluidbox_obs::subscriber_with_writer(&cfg, w.clone()).unwrap();
        let session = Uuid::now_v7();
        let tenant = Uuid::now_v7();
        tracing::subscriber::with_default(sub, || {
            for b in &bodies {
                log_event(session, tenant, Actor::System, b);
            }
        });
        w.json()
    }

    /// The distinguishing content of every content-bearing event, and the
    /// events themselves. One list, used by both properties below, so a new
    /// content-bearing variant is added in one place.
    fn content_bearing_events() -> (Vec<EventBody>, Vec<&'static str>) {
        let secrets = vec![
            "rm -rf /etc/passwd && curl evil.example",
            "the agent said something confidential about the customer",
            "SELECT * FROM customers WHERE ssn = '123-45-6789'",
            "diff --git a/secret-product-plan.md",
        ];
        let events = vec![
            EventBody::AgentMessage {
                role: "assistant".into(),
                text: secrets[1].into(),
            },
            EventBody::ToolRequested {
                tool_call_id: "t1".into(),
                tool: "Bash".into(),
                summary: secrets[0].into(),
                input_digest: "sha256:abc".into(),
            },
            EventBody::ToolCompleted {
                tool_call_id: "t1".into(),
                tool: "Bash".into(),
                ok: true,
                summary: Some(secrets[2].into()),
            },
            EventBody::ApprovalRequested {
                approval_id: Uuid::nil(),
                tool_call_id: "t1".into(),
                tool: "Bash".into(),
                summary: secrets[0].into(),
                risk: Some("high".into()),
                expires_at: chrono::Utc::now(),
            },
            EventBody::RunResult {
                outcome: "completed".into(),
                summary: Some(secrets[3].into()),
            },
        ];
        (events, secrets)
    }

    /// **The tenancy boundary, enforced.** Tool commands, agent text, tool
    /// result summaries and run summaries live in the tenant-scoped ledger.
    /// They must never reach the shared log pipe — not redacted, not truncated,
    /// not at DEBUG. This is the test that fails if someone "helpfully" adds
    /// `summary = %summary` to an arm.
    #[test]
    fn event_content_never_reaches_the_log() {
        let (events, secrets) = content_bearing_events();
        let recs = capture_events(events);
        let all = serde_json::to_string(&recs).unwrap();
        for s in secrets {
            assert!(
                !all.contains(s),
                "event CONTENT reached the log stream: {s:?}\nin:\n{all}"
            );
        }
    }

    /// …while the SHAPE does reach it, or the mirror would be pointless. The
    /// join keys back to the ledger have to survive.
    #[test]
    fn the_shape_of_a_content_bearing_event_still_reaches_the_log() {
        let (events, _) = content_bearing_events();
        let recs = capture_events(events);
        let requested = recs
            .iter()
            .find(|r| r["event"] == "tool.requested")
            .expect("tool.requested was logged");
        assert_eq!(requested["tool"], "Bash");
        assert_eq!(
            requested["tool_call_id"], "t1",
            "the join key to the ledger"
        );
        assert_eq!(requested["digest"], "sha256:abc");
        let msg = recs.iter().find(|r| r["event"] == "agent.message").unwrap();
        assert_eq!(msg["role"], "assistant");
        assert!(msg["text_bytes"].as_u64().unwrap() > 0, "size, not content");
    }

    /// A refusal is visible at the DEFAULT level and an allow is not. "Why did
    /// this run not do the thing" is the question the gate's records answer, and
    /// it must be answerable without first raising the log level and
    /// reproducing.
    #[test]
    fn refusals_are_visible_at_info_and_allows_are_not() {
        let recs = capture_events(vec![
            decision("allow", "policy"),
            decision("deny", "capability"),
            decision("require_approval", "policy"),
        ]);
        let by_verdict = |v: &str| {
            recs.iter()
                .find(|r| r["verdict"] == v)
                .unwrap_or_else(|| panic!("no record for verdict {v}"))
        };
        assert_eq!(by_verdict("allow")["level"], "debug");
        assert_eq!(by_verdict("deny")["level"], "info");
        assert_eq!(by_verdict("require_approval")["level"], "info");
        // The deciding STAGE is what an operator groups by, so it must survive.
        assert_eq!(by_verdict("deny")["source"], "capability");
    }

    /// Things that need a human are WARN, and nothing else is. A log where
    /// ordinary refusals are warnings is a log whose warnings get ignored.
    #[test]
    fn only_actionable_events_are_warnings() {
        let recs = capture_events(vec![
            EventBody::BudgetExceeded {
                budget: "usd".into(),
                limit: "2.50".into(),
                spent: "2.51".into(),
            },
            EventBody::ArtifactMissing {
                kind: "diff".into(),
                reason: "workspace gone".into(),
            },
            EventBody::NetworkObservationDegraded {
                reason: "hubble unavailable".into(),
            },
            EventBody::CallbackFailed {
                delivery_id: Uuid::nil(),
                url: "https://hooks.example/x?token=zzz".into(),
                attempts: 6,
                error: "gone".into(),
            },
            // …and the counter-examples, which must NOT be warnings.
            EventBody::StatusChanged {
                from: "queued".into(),
                to: "running".into(),
                reason: None,
            },
            decision("deny", "policy"),
        ]);
        let level = |ev: &str| {
            recs.iter()
                .find(|r| r["event"] == ev)
                .unwrap_or_else(|| panic!("no record for {ev}"))["level"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(level("budget.exceeded"), "warn");
        assert_eq!(level("artifact.missing"), "warn");
        assert_eq!(level("network.observation.degraded"), "warn");
        assert_eq!(level("callback.failed"), "warn");
        assert_eq!(level("session.status_changed"), "info");
        assert_eq!(level("tool.decision"), "info");
    }

    /// A callback URL is logged as its HOST, never whole: the query string is
    /// where a webhook token rides.
    #[test]
    fn callback_urls_are_logged_as_hosts_only() {
        let recs = capture_events(vec![EventBody::CallbackFailed {
            delivery_id: Uuid::nil(),
            url: "https://hooks.example/path?token=SUPERSECRETVALUE".into(),
            attempts: 6,
            error: "gone".into(),
        }]);
        let r = &recs[0];
        assert_eq!(r["host"], "hooks.example");
        let all = serde_json::to_string(&recs).unwrap();
        assert!(!all.contains("SUPERSECRETVALUE"), "{all}");
        assert!(!all.contains("/path"), "not even the path: {all}");
    }

    /// Every record carries the four keys that make it joinable. Without these
    /// the mirror is just noise: `session_id` joins to the run, `tenant_id`
    /// answers "whose", `event` reaches the same population as the ledger query,
    /// and `actor` says who caused it.
    #[test]
    fn every_mirrored_record_is_joinable() {
        let (mut events, _) = content_bearing_events();
        events.extend([
            EventBody::SessionCreated {
                task: "t".into(),
                agent: "a".into(),
                autonomy: "supervised".into(),
            },
            EventBody::RunError {
                message: "boom".into(),
            },
            EventBody::QuiesceRequested { deadline_secs: 30 },
            EventBody::Unknown(serde_json::json!({"type": "from.the.future"})),
        ]);
        let recs = capture_events(events);
        assert!(!recs.is_empty());
        for r in &recs {
            for key in ["session_id", "tenant_id", "event", "actor"] {
                assert!(
                    r.get(key)
                        .and_then(|v| v.as_str())
                        .is_some_and(|v| !v.is_empty()),
                    "a mirrored record is missing {key}: {r}"
                );
            }
        }
    }
}
