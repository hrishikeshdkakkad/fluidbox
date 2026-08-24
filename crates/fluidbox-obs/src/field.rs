//! The canonical field vocabulary.
//!
//! # Why a vocabulary at all
//!
//! Structured logging only pays off if the same fact is spelled the same way
//! everywhere. `session_id` in one module and `run_id` in another produces two
//! index columns for one concept, and every query then has to know both — which
//! in practice means every query gets one of them wrong. A dashboard built on
//! `duration_ms` silently loses the module that emits `elapsed_ms`.
//!
//! So the field names are `const`s, and instrumentation spells them by
//! reference. The compiler then enforces what a style guide could only ask for,
//! and renaming a field is a refactor rather than an archaeology project.
//!
//! # Naming rules (asserted by the tests at the bottom)
//!
//! * `snake_case`, ASCII, no dots — dotted keys read as nesting in most
//!   aggregators and this schema is deliberately FLAT (one level, cheap to
//!   index, no ambiguity about whether `http.status` is an object).
//! * No name may be one the redactor's field deny-list would blank
//!   ([`crate::redact::sensitive_field`]) — a vocabulary entry that always
//!   redacts to nothing is a bug, not a field.
//! * No name may collide with a [reserved key](crate::format) of the record
//!   envelope, because the formatter would have to rename it at write time and
//!   the field would then be un-queryable under the name it was declared with.
//!
//! # Cardinality
//!
//! Unlike `fluidbox-server::metrics`, high-cardinality values are FINE here:
//! `tenant_id` and `session_id` are exactly what makes a log line answer a
//! question, and a log store is built for that (a time-series registry is not —
//! which is why the metrics module bans them). The bound that matters for logs
//! is VOLUME, and that is [`crate::throttle`]'s job.

// ── Correlation ────────────────────────────────────────────────────────────
// The ids that let one line be joined to every other line about the same work.

/// Per-HTTP-request id. Generated at ingress, echoed in the `x-request-id`
/// response header, inherited by every line the request produces.
pub const REQUEST_ID: &str = "request_id";
/// W3C trace id (32 hex chars), adopted from an inbound `traceparent` when
/// present so a record joins a trace the caller already started. The matching
/// `span_id` is stamped by the formatter (it is derived from `tracing`'s own
/// span id), which is why only the trace id is a vocabulary field.
pub const TRACE_ID: &str = "trace_id";
/// The run. Named `session_id` because that is the table, the API path segment,
/// and the word every other module already uses — "run" is the product noun,
/// `session_id` is the key.
pub const SESSION_ID: &str = "session_id";
/// The owning tenant. On every line that touches tenant-owned data, so a
/// noisy-neighbour question is one filter away.
pub const TENANT_ID: &str = "tenant_id";
/// The acting user, when one exists (absent for the operator token and for
/// worker-driven work).
pub const USER_ID: &str = "user_id";
/// Which credential class is acting: `operator` | `user` | `pat` | `trigger` |
/// `runner` | `worker` | `anonymous`.
pub const PRINCIPAL: &str = "principal";

// ── Domain objects ─────────────────────────────────────────────────────────
pub const AGENT_ID: &str = "agent_id";
pub const REVISION: &str = "revision";
pub const SUBSCRIPTION_ID: &str = "subscription_id";
pub const DELIVERY_ID: &str = "delivery_id";
pub const CONNECTION_ID: &str = "connection_id";
pub const REGISTRATION_ID: &str = "registration_id";
pub const BINDING_ID: &str = "binding_id";
pub const APPROVAL_ID: &str = "approval_id";
pub const TOOL_CALL_ID: &str = "tool_call_id";
pub const SCHEDULE_ID: &str = "schedule_id";
/// Deterministic schedule-fire id (safe structural identity, never a secret
/// key despite the legacy internal name `fire_key`).
pub const FIRE_ID: &str = "fire_id";
pub const FLOW_ID: &str = "flow_id";

// ── HTTP ───────────────────────────────────────────────────────────────────
pub const METHOD: &str = "method";
/// The ROUTE PATTERN (`/v1/sessions/{id}`), never the concrete path. Keeping the
/// pattern is what makes "which endpoint is slow" answerable by grouping; the
/// concrete id is already on the line as [`SESSION_ID`].
pub const ROUTE: &str = "route";
/// The concrete path, WITHOUT the query string — queries carry OAuth codes and
/// GitHub flow tokens (the existing `TraceLayer` comment says so, and this
/// vocabulary keeps that promise).
pub const PATH: &str = "path";
pub const STATUS: &str = "status";
pub const REQ_BYTES: &str = "req_bytes";
pub const RESP_BYTES: &str = "resp_bytes";
pub const CLIENT_IP: &str = "client_ip";
pub const USER_AGENT: &str = "user_agent";
/// Which listener served this: `public` | `internal` | `metrics`. The planes
/// have different trust models, so telling them apart in one query matters.
pub const PLANE: &str = "plane";
/// `complete` | `body_error` | `body_dropped` for the response-body lifecycle.
pub const RESPONSE_STATE: &str = "response_state";

// ── Outcome ────────────────────────────────────────────────────────────────
/// `ok` | `error` — the coarse split every dashboard starts from.
pub const OUTCOME: &str = "outcome";
/// A STABLE, low-cardinality classification of a failure (`db`, `upstream`,
/// `timeout`, `forbidden`, `not_found`, `conflict`, `capacity`, …). Distinct
/// from [`ERROR`], which is the human message and is neither stable nor
/// groupable.
pub const ERROR_KIND: &str = "error_kind";
pub const ERROR: &str = "error";
pub const RETRYABLE: &str = "retryable";
pub const ATTEMPT: &str = "attempt";
/// Safe credential shape (`bearer`, `cookie`, `none`, …), never credential
/// material.
pub const CREDENTIAL_KIND: &str = "credential_kind";

// ── Timing ─────────────────────────────────────────────────────────────────
/// Wall-clock milliseconds for the operation the record describes. ONE name for
/// this concept, everywhere.
pub const DURATION_MS: &str = "duration_ms";
/// Milliseconds spent waiting on something else (queue, lock, upstream) inside
/// [`DURATION_MS`].
pub const WAIT_MS: &str = "wait_ms";

// ── Run lifecycle ──────────────────────────────────────────────────────────
pub const FROM: &str = "from";
pub const TO: &str = "to";
pub const AUTONOMY: &str = "autonomy";
pub const TRUST_TIER: &str = "trust_tier";
pub const HARNESS: &str = "harness";
pub const MODEL: &str = "model";
pub const PROVIDER: &str = "provider";
pub const INVOCATION_KIND: &str = "invocation_kind";
pub const QUEUE_POSITION: &str = "queue_position";
pub const REASON: &str = "reason";

// ── Governance (the permission gate) ───────────────────────────────────────
pub const TOOL: &str = "tool";
/// `allow` | `deny` | `require_approval`.
pub const VERDICT: &str = "verdict";
/// Which gate STAGE decided: `capability` | `binding` | `schema` | `trust_tier`
/// | `policy` | `human` | `budget` | … Mirrors the ledger's `source` exactly, so
/// a log query and a timeline query return the same population.
pub const SOURCE: &str = "source";
/// The verdict before an autonomy rewrite, when one happened.
pub const ORIGINAL_VERDICT: &str = "original_verdict";
pub const CAPABILITY: &str = "capability";
pub const SLOT: &str = "slot";
pub const POLICY_RULE: &str = "policy_rule";
/// A digest (`sha256:…`) standing in for content that must never be logged —
/// tool arguments, prompts, results.
pub const DIGEST: &str = "digest";

// ── Egress / upstream ──────────────────────────────────────────────────────
/// Target HOST only — never the full URL, which carries query material.
pub const HOST: &str = "host";
pub const SCHEME: &str = "scheme";
pub const UPSTREAM_STATUS: &str = "upstream_status";
pub const MCP_SERVER: &str = "mcp_server";
pub const PROTOCOL_VERSION: &str = "protocol_version";

// ── Cost / usage ───────────────────────────────────────────────────────────
pub const COST_USD: &str = "cost_usd";
pub const INPUT_TOKENS: &str = "input_tokens";
pub const OUTPUT_TOKENS: &str = "output_tokens";
pub const BUDGET_REMAINING_USD: &str = "budget_remaining_usd";

// ── Database ───────────────────────────────────────────────────────────────
pub const DB_OP: &str = "db_op";
pub const DB_ROWS: &str = "db_rows";
pub const DB_POOL_SIZE: &str = "db_pool_size";
pub const DB_POOL_IDLE: &str = "db_pool_idle";

/// Every name in the vocabulary, for the invariants below and for
/// documentation generation. Kept in sync by
/// [`tests::vocabulary_is_complete`], which fails if a `pub const &str` is added
/// to this module without being listed.
pub const ALL: &[&str] = &[
    REQUEST_ID,
    TRACE_ID,
    SESSION_ID,
    TENANT_ID,
    USER_ID,
    PRINCIPAL,
    AGENT_ID,
    REVISION,
    SUBSCRIPTION_ID,
    DELIVERY_ID,
    CONNECTION_ID,
    REGISTRATION_ID,
    BINDING_ID,
    APPROVAL_ID,
    TOOL_CALL_ID,
    SCHEDULE_ID,
    FIRE_ID,
    FLOW_ID,
    METHOD,
    ROUTE,
    PATH,
    STATUS,
    REQ_BYTES,
    RESP_BYTES,
    CLIENT_IP,
    USER_AGENT,
    PLANE,
    RESPONSE_STATE,
    OUTCOME,
    ERROR_KIND,
    ERROR,
    RETRYABLE,
    ATTEMPT,
    CREDENTIAL_KIND,
    DURATION_MS,
    WAIT_MS,
    FROM,
    TO,
    AUTONOMY,
    TRUST_TIER,
    HARNESS,
    MODEL,
    PROVIDER,
    INVOCATION_KIND,
    QUEUE_POSITION,
    REASON,
    TOOL,
    VERDICT,
    SOURCE,
    ORIGINAL_VERDICT,
    CAPABILITY,
    SLOT,
    POLICY_RULE,
    DIGEST,
    HOST,
    SCHEME,
    UPSTREAM_STATUS,
    MCP_SERVER,
    PROTOCOL_VERSION,
    COST_USD,
    INPUT_TOKENS,
    OUTPUT_TOKENS,
    BUDGET_REMAINING_USD,
    DB_OP,
    DB_ROWS,
    DB_POOL_SIZE,
    DB_POOL_IDLE,
];

/// The stable value set for [`OUTCOME`].
pub mod outcome {
    pub const OK: &str = "ok";
    pub const ERROR: &str = "error";
}

/// The stable value set for [`PRINCIPAL`].
pub mod principal {
    pub const OPERATOR: &str = "operator";
    pub const USER: &str = "user";
    pub const PAT: &str = "pat";
    pub const TRIGGER: &str = "trigger";
    /// The in-sandbox runner, authenticating with one of its four
    /// audience-scoped session tokens.
    pub const RUNNER: &str = "runner";
    /// A background worker with no external caller (sweepers, the scheduler).
    pub const WORKER: &str = "worker";
    pub const ANONYMOUS: &str = "anonymous";
}

/// The stable value set for [`ERROR_KIND`].
///
/// Low-cardinality and CLOSED on purpose. `error_kind` is what an alert groups
/// on and what a dashboard splits by, so it has to be a small enumeration
/// somebody chose — the moment it becomes "whatever string the call site felt
/// like", every panel built on it silently stops covering new failures. The
/// human detail belongs in [`ERROR`], which is free-form precisely because
/// nothing aggregates it.
pub mod error_kind {
    /// The database refused, timed out, or was unreachable.
    pub const DB: &str = "db";
    /// A third party we called answered badly or not at all. THEIR fault.
    pub const UPSTREAM: &str = "upstream";
    /// We gave up waiting.
    pub const TIMEOUT: &str = "timeout";
    /// The caller is not who they claim to be.
    pub const UNAUTHENTICATED: &str = "unauthenticated";
    /// The caller is authenticated but not permitted.
    pub const FORBIDDEN: &str = "forbidden";
    /// The caller asked for something that does not exist — or that they may not
    /// know exists, which is the same response by design.
    pub const NOT_FOUND: &str = "not_found";
    /// The request was malformed.
    pub const INVALID: &str = "invalid";
    /// A concurrent change or a uniqueness violation.
    pub const CONFLICT: &str = "conflict";
    /// Deliberate backpressure — a queue bound, a rate limit, an open breaker.
    /// Distinct from every other kind because it is the system WORKING.
    pub const CAPACITY: &str = "capacity";
    /// A policy, governance, or custody rule refused. Also the system working.
    pub const POLICY: &str = "policy";
    /// Sealing, unsealing, or key custody failed.
    pub const CUSTODY: &str = "custody";
    /// A run exceeded its budget.
    pub const BUDGET: &str = "budget";
    /// The sandbox substrate (Docker, Kubernetes) refused or failed.
    pub const PROVIDER: &str = "provider";
    /// A bug on our side: an invariant violated, an unexpected shape, a panic
    /// caught. The kind that should page someone.
    pub const INTERNAL: &str = "internal";

    /// Every kind, for the exhaustiveness test and for documentation.
    pub const ALL: &[&str] = &[
        DB,
        UPSTREAM,
        TIMEOUT,
        UNAUTHENTICATED,
        FORBIDDEN,
        NOT_FOUND,
        INVALID,
        CONFLICT,
        CAPACITY,
        POLICY,
        CUSTODY,
        BUDGET,
        PROVIDER,
        INTERNAL,
    ];
}

/// The stable value set for [`PLANE`].
pub mod plane {
    pub const PUBLIC: &str = "public";
    pub const INTERNAL: &str = "internal";
    pub const METRICS: &str = "metrics";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::sensitive_field;

    #[test]
    fn names_are_flat_snake_case_ascii() {
        for f in ALL {
            assert!(!f.is_empty(), "empty field name");
            assert!(
                f.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{f}: field names are lowercase ascii snake_case"
            );
            assert!(!f.contains('.'), "{f}: the record schema is FLAT — no dots");
            assert!(
                !f.starts_with('_') && !f.ends_with('_'),
                "{f}: stray underscore"
            );
        }
    }

    #[test]
    fn names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for f in ALL {
            assert!(seen.insert(*f), "{f}: duplicated in the vocabulary");
        }
    }

    /// A vocabulary entry the redactor always blanks is a bug: the field would
    /// be declared, spelled correctly at every call site, and empty in every
    /// record. Better to fail here than to discover it during an incident.
    #[test]
    fn no_vocabulary_field_is_permanently_redacted() {
        for f in ALL {
            assert!(
                !sensitive_field(f),
                "{f} is in the vocabulary but the field deny-list would blank it"
            );
        }
    }

    /// The envelope keys the formatter writes itself. A vocabulary field with
    /// one of these names would be renamed at write time and become
    /// un-queryable under its declared name.
    #[test]
    fn no_vocabulary_field_collides_with_a_reserved_envelope_key() {
        for f in ALL {
            assert!(
                !crate::format::RESERVED.contains(f),
                "{f} collides with a reserved envelope key"
            );
        }
    }

    /// `error_kind` values must be as disciplined as the field names: an
    /// alert grouped on a typo'd kind matches nothing and nobody notices.
    #[test]
    fn error_kinds_are_unique_lowercase_and_listed() {
        let mut seen = std::collections::BTreeSet::new();
        for k in error_kind::ALL {
            assert!(seen.insert(*k), "{k}: duplicated");
            assert!(
                k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{k}: lowercase snake_case"
            );
        }
        let declared = include_str!("field.rs")
            .lines()
            .filter(|l| l.trim_start().starts_with("pub const ") && l.contains(": &str = \""))
            .filter(|l| l.starts_with("    pub const "))
            .count();
        // The three value-set modules each contribute their own constants; only
        // `error_kind`'s are asserted here, so count just those by subtracting
        // the other two modules' known sizes.
        let others = outcome_len() + principal_len() + plane_len();
        assert_eq!(
            declared - others,
            error_kind::ALL.len(),
            "an error_kind constant was added without being listed in error_kind::ALL"
        );
    }

    fn outcome_len() -> usize {
        2
    }
    fn principal_len() -> usize {
        7
    }
    fn plane_len() -> usize {
        3
    }

    /// Guards against the list drifting from the constants above. Counting is
    /// crude but it is the only check available without a proc macro, and it
    /// does catch the real mistake: adding a `pub const` and forgetting `ALL`.
    #[test]
    fn vocabulary_is_complete() {
        let src = include_str!("field.rs");
        let declared = src
            .lines()
            .filter(|l| l.starts_with("pub const ") && l.contains(": &str = \""))
            .count();
        // `ALL` itself is `&[&str]`, not `&str`, so it is not counted above.
        assert_eq!(
            declared,
            ALL.len(),
            "a `pub const … : &str` was added to field.rs without being listed in ALL"
        );
    }
}
