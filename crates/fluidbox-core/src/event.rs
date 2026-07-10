use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Canonical event bodies. Names are stable dot-strings — they are the
/// public timeline contract; add variants, never rename them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EventBody {
    #[serde(rename = "session.created")]
    SessionCreated {
        task: String,
        agent: String,
        autonomy: String,
    },
    #[serde(rename = "session.status_changed")]
    StatusChanged {
        from: String,
        to: String,
        reason: Option<String>,
    },
    #[serde(rename = "workspace.initialized")]
    WorkspaceInitialized {
        base_commit: Option<String>,
        files: Option<u64>,
        /// Remote identity for git workspaces (clone URL — never credentialed).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repo: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        r#ref: Option<String>,
    },
    #[serde(rename = "agent.message")]
    AgentMessage { role: String, text: String },
    #[serde(rename = "tool.requested")]
    ToolRequested {
        tool_call_id: String,
        tool: String,
        /// Human-readable one-liner (command, file path…), redacted.
        summary: String,
        input_digest: String,
    },
    #[serde(rename = "tool.decision")]
    ToolDecision {
        tool_call_id: String,
        tool: String,
        verdict: String,
        /// policy | human | autonomy_rewrite | timeout | session_scope
        source: String,
        /// Original policy verdict when a rewrite happened (autonomy).
        original_verdict: Option<String>,
        reason: Option<String>,
    },
    #[serde(rename = "tool.completed")]
    ToolCompleted {
        tool_call_id: String,
        tool: String,
        ok: bool,
        summary: Option<String>,
    },
    #[serde(rename = "approval.requested")]
    ApprovalRequested {
        approval_id: Uuid,
        tool_call_id: String,
        tool: String,
        summary: String,
        risk: Option<String>,
        expires_at: DateTime<Utc>,
    },
    #[serde(rename = "approval.decided")]
    ApprovalDecided {
        approval_id: Uuid,
        tool_call_id: String,
        decision: String,
        decided_by: String,
    },
    #[serde(rename = "model.response")]
    ModelResponse {
        model: String,
        input_tokens: u64,
        output_tokens: u64,
        cache_read_tokens: u64,
        cache_write_tokens: u64,
        cost_usd: Option<f64>,
    },
    #[serde(rename = "budget.exceeded")]
    BudgetExceeded {
        budget: String,
        limit: String,
        spent: String,
    },
    #[serde(rename = "run.result")]
    RunResult {
        outcome: String,
        summary: Option<String>,
    },
    #[serde(rename = "run.error")]
    RunError { message: String },
    /// Forward-compat: events written by newer components still round-trip.
    #[serde(untagged)]
    Unknown(Value),
}

impl EventBody {
    pub fn type_name(&self) -> String {
        match serde_json::to_value(self) {
            Ok(Value::Object(m)) => m
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown")
                .to_string(),
            _ => "unknown".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    Agent,
    System,
    Human,
    Harness,
}

impl Actor {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::System => "system",
            Self::Human => "human",
            Self::Harness => "harness",
        }
    }
}

/// The envelope persisted to the append-only ledger. `seq` is assigned by
/// the database (per-session, gapless) — it is `None` until persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: Uuid,
    pub schema_version: u32,
    pub session_id: Uuid,
    pub seq: Option<i64>,
    pub occurred_at: DateTime<Utc>,
    pub actor: Actor,
    pub body: EventBody,
}

impl EventEnvelope {
    pub fn new(session_id: Uuid, actor: Actor, body: EventBody) -> Self {
        Self {
            event_id: Uuid::now_v7(),
            schema_version: 1,
            session_id,
            seq: None,
            occurred_at: Utc::now(),
            actor,
            body,
        }
    }
}

/// Proof that an envelope passed through the `Redactor`. The ledger only
/// accepts `Redacted<EventEnvelope>`; the private field makes it
/// unconstructible outside this module.
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
    pub fn get(&self) -> &T {
        &self.0
    }
}

/// Scrubs secret-shaped strings out of event payloads. Model prompts never
/// reach the ledger at all (the facade streams bytes without persisting);
/// this catches secrets that leak into tool summaries or agent text.
pub struct Redactor {
    patterns: Vec<regex::Regex>,
}

impl Default for Redactor {
    fn default() -> Self {
        let raw = [
            r"sk-ant-[A-Za-z0-9_\-]{8,}",     // Anthropic keys / oauth tokens
            r"sk-[A-Za-z0-9]{20,}",           // OpenAI-style keys
            r"ghp_[A-Za-z0-9]{20,}",          // GitHub PAT
            r"github_pat_[A-Za-z0-9_]{20,}",  // GitHub fine-grained PAT
            r"gho_[A-Za-z0-9]{20,}",          // GitHub OAuth
            r"AKIA[0-9A-Z]{16}",              // AWS access key id
            r"xox[baprs]-[A-Za-z0-9\-]{10,}", // Slack tokens
            r"npg_[A-Za-z0-9]{8,}",           // Neon passwords
            r"(?i)bearer\s+[A-Za-z0-9\._\-]{16,}",
            r"postgres(ql)?://[^\s:]+:[^@\s]+@", // connection-string passwords
        ];
        Self {
            patterns: raw.iter().map(|p| regex::Regex::new(p).unwrap()).collect(),
        }
    }
}

impl Redactor {
    pub fn scrub_text(&self, text: &str) -> String {
        let mut out = text.to_string();
        for re in &self.patterns {
            out = re.replace_all(&out, "‹redacted›").into_owned();
        }
        out
    }

    fn scrub_value(&self, v: &mut Value) {
        match v {
            Value::String(s) => *s = self.scrub_text(s),
            Value::Array(a) => a.iter_mut().for_each(|x| self.scrub_value(x)),
            Value::Object(m) => m.values_mut().for_each(|x| self.scrub_value(x)),
            _ => {}
        }
    }

    /// The only door into the ledger.
    pub fn scrub(&self, mut env: EventEnvelope) -> Redacted<EventEnvelope> {
        // Round-trip the body through JSON so every string field is covered
        // regardless of variant shape.
        if let Ok(mut v) = serde_json::to_value(&env.body) {
            self.scrub_value(&mut v);
            if let Ok(body) = serde_json::from_value::<EventBody>(v.clone()) {
                env.body = body;
            } else {
                env.body = EventBody::Unknown(v);
            }
        }
        Redacted(env)
    }
}

/// Digest helper for tool inputs (stored instead of raw input).
pub fn digest_json(v: &Value) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(serde_json::to_string(v).unwrap_or_default().as_bytes());
    format!("sha256:{}", hex::encode(&h.finalize()[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_dot_names_roundtrip() {
        let body = EventBody::ToolDecision {
            tool_call_id: "t1".into(),
            tool: "Bash".into(),
            verdict: "deny".into(),
            source: "autonomy_rewrite".into(),
            original_verdict: Some("require_approval".into()),
            reason: None,
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["type"], "tool.decision");
        let back: EventBody = serde_json::from_value(json).unwrap();
        assert_eq!(back.type_name(), "tool.decision");
    }

    #[test]
    fn unknown_events_survive() {
        let json = serde_json::json!({"type": "future.event", "data": {"x": 1}});
        let body: EventBody = serde_json::from_value(json.clone()).unwrap();
        assert!(matches!(body, EventBody::Unknown(_)));
        assert_eq!(serde_json::to_value(&body).unwrap(), json);
    }

    #[test]
    fn redactor_scrubs_secrets_deep() {
        let r = Redactor::default();
        let env = EventEnvelope::new(
            Uuid::now_v7(),
            Actor::Agent,
            EventBody::AgentMessage {
                role: "assistant".into(),
                text: "use key sk-ant-api03-abcdefgh12345678 and ghp_0123456789abcdefghij ok"
                    .into(),
            },
        );
        let red = r.scrub(env);
        let text = serde_json::to_string(&red.get().body).unwrap();
        assert!(!text.contains("sk-ant-api03"));
        assert!(!text.contains("ghp_0123456789"));
        assert!(text.contains("‹redacted›"));
    }

    #[test]
    fn redactor_scrubs_connection_strings() {
        let r = Redactor::default();
        let s = r.scrub_text("postgresql://user:supersecret@host/db");
        assert!(!s.contains("supersecret"));
    }
}
