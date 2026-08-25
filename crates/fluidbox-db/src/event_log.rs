//! Commit-accurate operational mirror of canonical ledger events.
//!
//! The ledger is tenant-scoped; the log stream is shared. Consequently this
//! module records identity, bounded classifications, timing, and outcome only.
//! Free-form event content remains exclusively in the durable ledger.

use fluidbox_core::event::{EventBody, EventEnvelope};
use uuid::Uuid;

/// Mirror an event only after the transaction that appended it has committed.
///
/// This is deliberately crate-private: callers must go through the database
/// append/commit helpers so a rolled-back event can never produce a log record.
pub(super) fn log_committed_event(tenant: Uuid, env: &EventEnvelope, seq: i64) {
    let session = env.session_id;
    let actor = env.actor;
    let body = &env.body;
    let kind = body.type_name();

    macro_rules! ev {
        ($lvl:ident, $($rest:tt)*) => {
            tracing::$lvl!(
                target: "fluidbox_server::ledger",
                session_id = %session,
                tenant_id = %tenant,
                event_id = %env.event_id,
                event_seq = seq,
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
            repo = repo.as_deref(),
            git_ref = r#ref.as_deref(),
            "workspace initialised"
        ),

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

        // `message` is arbitrary runner/tenant content. Its classification is
        // enough for the shared stream; the full text remains in the ledger.
        EventBody::RunError { message: _ } => {
            ev!(warn, outcome = "error", "run errored")
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

        // Callback failures can contain the complete operator-supplied URL in
        // `error`; only the safe upstream classification and URL host cross the
        // shared-log boundary.
        EventBody::CallbackFailed {
            delivery_id,
            url,
            attempts,
            error: _,
        } => ev!(
            warn,
            delivery_id = %delivery_id,
            host = fluidbox_obs::url_host(url),
            attempt = *attempts,
            error_kind = fluidbox_obs::field::error_kind::UPSTREAM,
            "result callback gave up"
        ),

        EventBody::CapabilitiesFrozen { bundles, tools } => ev!(
            info,
            bundles = bundles.len(),
            tools = *tools,
            "capabilities frozen"
        ),

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

        EventBody::NetworkObservationDegraded { reason } => ev!(
            warn,
            reason = %reason,
            "network observation degraded — denials may be unrecorded"
        ),

        EventBody::NetworkGrantRevoked { mode, reason } => {
            ev!(info, mode = %mode, reason = %reason, "network grant revoked")
        }

        EventBody::ArtifactCollected {
            kind,
            name,
            bytes,
            truncated,
            ..
        } => ev!(
            debug,
            artifact_kind = %kind,
            name = %name,
            bytes = *bytes,
            truncated = *truncated,
            "artifact collected"
        ),

        EventBody::ArtifactMissing { kind, reason } => ev!(
            warn,
            artifact_kind = %kind,
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
            error: _,
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
                    error_kind = fluidbox_obs::field::error_kind::UPSTREAM,
                    "brokered tool call failed"
                )
            }
        }

        EventBody::Unknown(_) => ev!(debug, "unrecognised event type (version skew?)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::event::Actor;
    use fluidbox_obs::capture::CaptureWriter;

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

    fn capture_events(bodies: Vec<EventBody>) -> Vec<serde_json::Value> {
        let writer = CaptureWriter::new();
        let config = fluidbox_obs::LogConfig {
            format: fluidbox_obs::Format::Json,
            filter: "trace".into(),
            throttle_per_sec: 0,
            ..Default::default()
        };
        let (subscriber, _guard) =
            fluidbox_obs::subscriber_with_writer(&config, writer.clone()).unwrap();
        let tenant = Uuid::now_v7();
        tracing::subscriber::with_default(subscriber, || {
            for (index, body) in bodies.into_iter().enumerate() {
                let event = EventEnvelope::new(Uuid::now_v7(), Actor::System, body);
                log_committed_event(tenant, &event, index as i64 + 1);
            }
        });
        writer.json()
    }

    fn content_bearing_events() -> (Vec<EventBody>, Vec<&'static str>) {
        let secrets = vec![
            "rm -rf /etc/passwd && curl evil.example",
            "the agent said something confidential about the customer",
            "SELECT * FROM customers WHERE ssn = '123-45-6789'",
            "diff --git a/secret-product-plan.md",
            "runner exposed private tenant details",
            "POST https://user:pass@hooks.example/private?token=CALLBACKSECRET",
            "MCP response includes CUSTOMER-ONLY-CONTENT",
            "alice@tenant-secret.invalid",
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
            EventBody::RunError {
                message: secrets[4].into(),
            },
            EventBody::CallbackFailed {
                delivery_id: Uuid::nil(),
                url: format!("https://hooks.example/path?email={}", secrets[7]),
                attempts: 6,
                error: secrets[5].into(),
            },
            EventBody::BrokeredToolCall {
                tool_call_id: "mcp-1".into(),
                tool: "mcp__customer__lookup".into(),
                server: "customer".into(),
                binding_id: None,
                ok: false,
                latency_ms: 37,
                result_digest: None,
                error: Some(secrets[6].into()),
                outcome: Some("failed_upstream".into()),
            },
        ];
        (events, secrets)
    }

    #[test]
    fn event_content_never_reaches_the_shared_log() {
        let (events, secrets) = content_bearing_events();
        let records = capture_events(events);
        let all = serde_json::to_string(&records).unwrap();
        for secret in secrets {
            assert!(
                !all.contains(secret),
                "event content reached the shared log: {secret:?}\n{all}"
            );
        }
    }

    #[test]
    fn content_event_shape_and_commit_identity_are_preserved() {
        let (events, _) = content_bearing_events();
        let records = capture_events(events);
        let requested = records
            .iter()
            .find(|record| record["event"] == "tool.requested")
            .expect("tool.requested was logged");
        assert_eq!(requested["tool"], "Bash");
        assert_eq!(requested["tool_call_id"], "t1");
        assert_eq!(requested["digest"], "sha256:abc");
        for record in records {
            for key in [
                "session_id",
                "tenant_id",
                "event_id",
                "event_seq",
                "event",
                "actor",
            ] {
                assert!(!record[key].is_null(), "missing {key}: {record}");
            }
        }
    }

    #[test]
    fn callback_urls_are_logged_as_authority_hosts_only() {
        let records = capture_events(vec![EventBody::CallbackFailed {
            delivery_id: Uuid::nil(),
            url: "https://hooks.example/path?email=alice@tenant-secret.invalid".into(),
            attempts: 6,
            error: "gone".into(),
        }]);
        assert_eq!(records[0]["host"], "hooks.example");
        let all = serde_json::to_string(&records).unwrap();
        assert!(!all.contains("tenant-secret.invalid"), "{all}");
        assert!(!all.contains("/path"), "{all}");
    }

    #[test]
    fn refusal_levels_match_operational_severity() {
        let records = capture_events(vec![
            decision("allow", "policy"),
            decision("deny", "capability"),
            decision("require_approval", "policy"),
        ]);
        let level = |verdict: &str| {
            records
                .iter()
                .find(|record| record["verdict"] == verdict)
                .unwrap_or_else(|| panic!("no record for verdict {verdict}"))["level"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert_eq!(level("allow"), "debug");
        assert_eq!(level("deny"), "info");
        assert_eq!(level("require_approval"), "info");
    }
}
