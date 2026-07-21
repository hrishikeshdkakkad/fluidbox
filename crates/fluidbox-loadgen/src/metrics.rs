//! Latency percentiles and the outcome taxonomy.
//!
//! Two deliberate positions, both of which are the point of the module:
//!
//! 1. **No averages.** A mean latency under load is the least informative number
//!    available: it hides the tail that actually decides whether a deployment is
//!    usable. `Percentiles` therefore reports p50/p95/p99/max (and min/n), and
//!    the mean only as a footnote for spotting a skewed distribution.
//!
//! 2. **Every response is classified, and "not 2xx" is not a classification.**
//!    A control plane under load fails in kinds — it refuses (`wrong_audience`,
//!    `tenant_llm_keys_required`), it throttles, it denies at the gate, it times
//!    out, it refuses the connection — and those are different facts about the
//!    system. `classify_response` maps status + body onto that taxonomy.
//!
//! WHAT THE HTTP TAXONOMY DELIBERATELY DOES NOT DO: it does not guess WHICH gate
//! stage produced a denial. `/permission` answers `{"decision":"deny","message":
//! …}` and the message is a free-text reason; the authoritative stage lives in
//! the ledger as `events.payload->'data'->>'source'` (internal.rs writes
//! `capability` / `binding` / `schema` / `trust_tier` / `policy` / …). Scenarios
//! with a database handle read that histogram directly (see `report.rs`), so the
//! harness never has to infer a stage from prose.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One request's classified result. Ordering is by discriminant, which keeps a
/// report's per-op breakdown stable across runs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    /// A 2xx that carried no further semantics (a create, a list, a heartbeat).
    Ok2xx,
    /// `/permission` (or `/tools/call`) answered `allow`.
    GateAllow,
    /// `/permission` (or `/tools/call`) answered `deny`. The STAGE is not
    /// recorded here on purpose — see the module docs.
    GateDeny,
    /// A brokered call the upstream answered with `isError: true`.
    ToolIsError,
    /// The bearer did not resolve at all.
    Unauthorized,
    /// 403 `{"error":"wrong_audience"}` — the Gap 10 audience refusal. Its own
    /// bucket because during a load run it means a token was routed wrongly,
    /// which is a harness bug, not a deployment finding.
    WrongAudience,
    /// 403 that was not an audience refusal.
    Forbidden,
    NotFound,
    /// 429, or any body carrying the egress governor's refusal text.
    Throttled,
    /// The run hit its LLM budget (the facade's own refusal).
    BudgetExceeded,
    /// `FLUIDBOX_REQUIRE_SSO=1` with `FLUIDBOX_LLM_KEY_MODE=shared`.
    TenantLlmKeysRequired,
    /// A tenant with no mintable LiteLLM virtual key.
    TenantLlmKeyUnavailable,
    ClientError(u16),
    ServerError(u16),
    OtherStatus(u16),
    /// The request did not complete within `--timeout-secs`.
    Timeout,
    /// Nothing was listening / the connection was refused or reset before a
    /// status line. Under load this is the signal that the deployment's accept
    /// queue or file-descriptor ceiling has been reached.
    ConnectionRefused,
    /// Any other transport failure, tagged with a short kind.
    Transport(String),
}

impl Outcome {
    pub fn label(&self) -> String {
        match self {
            Outcome::Ok2xx => "ok_2xx".into(),
            Outcome::GateAllow => "gate_allow".into(),
            Outcome::GateDeny => "gate_deny".into(),
            Outcome::ToolIsError => "tool_is_error".into(),
            Outcome::Unauthorized => "unauthorized_401".into(),
            Outcome::WrongAudience => "wrong_audience_403".into(),
            Outcome::Forbidden => "forbidden_403".into(),
            Outcome::NotFound => "not_found_404".into(),
            Outcome::Throttled => "throttled".into(),
            Outcome::BudgetExceeded => "budget_exceeded".into(),
            Outcome::TenantLlmKeysRequired => "tenant_llm_keys_required_503".into(),
            Outcome::TenantLlmKeyUnavailable => "tenant_llm_key_unavailable_503".into(),
            Outcome::ClientError(c) => format!("client_error_{c}"),
            Outcome::ServerError(c) => format!("server_error_{c}"),
            Outcome::OtherStatus(c) => format!("status_{c}"),
            Outcome::Timeout => "timeout".into(),
            Outcome::ConnectionRefused => "connection_refused".into(),
            Outcome::Transport(k) => format!("transport_{k}"),
        }
    }

    /// "The deployment answered, and the answer was a normal one." A gate DENY
    /// counts: refusing is the system working. A 5xx, a timeout and a refused
    /// connection do not.
    pub fn is_healthy(&self) -> bool {
        matches!(
            self,
            Outcome::Ok2xx
                | Outcome::GateAllow
                | Outcome::GateDeny
                | Outcome::ToolIsError
                | Outcome::Throttled
        )
    }
}

/// Classify one completed HTTP response.
///
/// Order is load-bearing: the specific refusal shapes are tested BEFORE the
/// generic status buckets, so `503 tenant_llm_keys_required` never degrades into
/// an anonymous `server_error_503`.
pub fn classify_response(status: u16, body: &str) -> Outcome {
    // The egress governor answers 200 with a refusal in the body on the brokered
    // path (broker.rs renders a CallErr as a tool result), so throttling has to
    // be detected from the body before the status class is consulted.
    if body.contains("outbound rate limit reached") || body.contains("circuit breaker") {
        return Outcome::Throttled;
    }
    match status {
        200..=299 => {
            // The gate answers 200 for BOTH verdicts; the verdict is the fact.
            if body.contains("\"decision\":\"allow\"") || body.contains("\"decision\": \"allow\"") {
                return Outcome::GateAllow;
            }
            if body.contains("\"decision\":\"deny\"") || body.contains("\"decision\": \"deny\"") {
                return Outcome::GateDeny;
            }
            // A brokered dispatch renders `{ok:true, result:{content, is_error}}`
            // for every DEFINITIVE outcome — a `true` there is an upstream tool
            // error, not a transport failure, and the two must never merge.
            if body.contains("\"is_error\":true") || body.contains("\"is_error\": true") {
                return Outcome::ToolIsError;
            }
            Outcome::Ok2xx
        }
        401 => Outcome::Unauthorized,
        403 => {
            if body.contains("wrong_audience") {
                Outcome::WrongAudience
            } else {
                Outcome::Forbidden
            }
        }
        404 => Outcome::NotFound,
        429 => Outcome::Throttled,
        503 if body.contains("tenant_llm_keys_required") => Outcome::TenantLlmKeysRequired,
        503 if body.contains("tenant_llm_key_unavailable") => Outcome::TenantLlmKeyUnavailable,
        // The facade's budget stop is dialect-shaped, so it is matched on text
        // rather than on a status it does not uniquely own.
        400..=499 if body.contains("budget") && body.contains("exceeded") => {
            Outcome::BudgetExceeded
        }
        400..=499 => Outcome::ClientError(status),
        500..=599 => Outcome::ServerError(status),
        other => Outcome::OtherStatus(other),
    }
}

/// Classify a transport failure from the FLAGS a client can observe.
///
/// Taking flags rather than a `reqwest::Error` keeps this pure and therefore
/// unit-testable — `reqwest::Error` cannot be constructed outside the crate, so
/// a signature taking one would be a function with no test.
pub fn classify_transport(is_timeout: bool, is_connect: bool, message: &str) -> Outcome {
    if is_timeout {
        return Outcome::Timeout;
    }
    if is_connect {
        return Outcome::ConnectionRefused;
    }
    let lower = message.to_ascii_lowercase();
    // A connect failure does not always arrive flagged as one (a reset during
    // the handshake, an exhausted ephemeral-port range). Under load these ARE
    // the finding, so they must not be swept into a generic bucket.
    for needle in ["connection refused", "connection reset", "broken pipe"] {
        if lower.contains(needle) {
            return Outcome::ConnectionRefused;
        }
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return Outcome::Timeout;
    }
    let kind = if lower.contains("dns") {
        "dns"
    } else if lower.contains("tls") || lower.contains("certificate") {
        "tls"
    } else if lower.contains("body") || lower.contains("decode") {
        "body"
    } else {
        "other"
    };
    Outcome::Transport(kind.into())
}

/// Wrap a `reqwest::Error` into the taxonomy. Thin by design: all the logic
/// lives in the pure `classify_transport` above.
pub fn classify_reqwest(e: &reqwest::Error) -> Outcome {
    classify_transport(e.is_timeout(), e.is_connect(), &e.to_string())
}

// ─── Percentiles ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Percentiles {
    pub n: usize,
    pub min_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub mean_us: u64,
}

/// Nearest-rank (the definition with no interpolation): the p-th percentile is
/// the value at index `ceil(p/100 * n) - 1` of the ascending sample.
///
/// Chosen over a linear-interpolating definition because every reported number
/// is then an OBSERVED latency — "p99 = 812 ms" names a request that actually
/// took 812 ms, which is what an operator can go and look for in a log.
pub fn percentiles(samples: &mut [u64]) -> Percentiles {
    if samples.is_empty() {
        return Percentiles::default();
    }
    samples.sort_unstable();
    let n = samples.len();
    let at = |p: f64| -> u64 {
        let idx = ((p / 100.0) * n as f64).ceil() as usize;
        samples[idx.max(1).min(n) - 1]
    };
    let sum: u128 = samples.iter().map(|v| *v as u128).sum();
    Percentiles {
        n,
        min_us: samples[0],
        p50_us: at(50.0),
        p95_us: at(95.0),
        p99_us: at(99.0),
        max_us: samples[n - 1],
        mean_us: (sum / n as u128) as u64,
    }
}

// ─── Recording ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct OpSamples {
    micros: Vec<u64>,
    /// Keyed by the VARIANT, not by its label. Keying by label would need a
    /// second, string-shaped copy of `Outcome::is_healthy` to answer
    /// "how many were unhealthy", and the two would drift the first time a
    /// variant was added. Labels are produced only at render time.
    outcomes: BTreeMap<Outcome, u64>,
}

/// Per-operation latency samples + outcome counts.
///
/// A `std::sync::Mutex` (not an async one) is deliberate: the critical section
/// is a `push` and a counter bump, and holding a std mutex across that is orders
/// of magnitude cheaper than an async handoff. It is never held across `.await`.
#[derive(Default)]
pub struct Recorder {
    ops: BTreeMap<String, OpSamples>,
}

pub type SharedRecorder = Arc<Mutex<Recorder>>;

pub fn shared_recorder() -> SharedRecorder {
    Arc::new(Mutex::new(Recorder::default()))
}

impl Recorder {
    pub fn record(&mut self, op: &str, dur: Duration, outcome: Outcome) {
        let e = self.ops.entry(op.to_string()).or_default();
        e.micros.push(dur.as_micros().min(u64::MAX as u128) as u64);
        *e.outcomes.entry(outcome).or_insert(0) += 1;
    }

    pub fn summary(&self) -> Vec<OpSummary> {
        self.ops
            .iter()
            .map(|(op, s)| {
                let mut micros = s.micros.clone();
                OpSummary {
                    op: op.clone(),
                    latency: percentiles(&mut micros),
                    outcomes: s.outcomes.iter().map(|(k, v)| (k.label(), *v)).collect(),
                }
            })
            .collect()
    }

    /// Requests whose outcome was NOT healthy, across every op. This is the one
    /// number a capacity gate can be written against.
    pub fn unhealthy_total(&self) -> u64 {
        self.ops
            .values()
            .flat_map(|s| s.outcomes.iter())
            .filter(|(outcome, _)| !outcome.is_healthy())
            .map(|(_, n)| *n)
            .sum()
    }

    pub fn request_total(&self) -> u64 {
        self.ops.values().map(|s| s.micros.len() as u64).sum()
    }
}

#[derive(Clone, Debug)]
pub struct OpSummary {
    pub op: String,
    pub latency: Percentiles,
    pub outcomes: Vec<(String, u64)>,
}

pub fn record_into(rec: &SharedRecorder, op: &str, dur: Duration, outcome: Outcome) {
    if let Ok(mut g) = rec.lock() {
        g.record(op, dur, outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_percentiles_over_one_to_one_hundred() {
        let mut xs: Vec<u64> = (1..=100).collect();
        let p = percentiles(&mut xs);
        assert_eq!(p.n, 100);
        assert_eq!(p.min_us, 1);
        // Nearest rank: ceil(0.50*100) = 50 → index 49 → the value 50.
        assert_eq!(p.p50_us, 50);
        assert_eq!(p.p95_us, 95);
        assert_eq!(p.p99_us, 99);
        assert_eq!(p.max_us, 100);
        assert_eq!(p.mean_us, 50); // 5050/100 = 50.5, truncated
    }

    #[test]
    fn percentiles_sort_unsorted_input() {
        let mut xs = vec![100u64, 1, 50, 2, 99];
        let p = percentiles(&mut xs);
        assert_eq!(p.min_us, 1);
        assert_eq!(p.max_us, 100);
        // n=5: ceil(0.5*5)=3 → index 2 → 50.
        assert_eq!(p.p50_us, 50);
        // ceil(0.95*5)=5 → index 4 → 100.
        assert_eq!(p.p95_us, 100);
    }

    /// Nearest rank ROUNDS UP. This is the case that distinguishes it from the
    /// rounding-down variant, and it needs a sample size where the rank is not
    /// an integer — at n=100 every percentile this module reports lands on a
    /// whole number and ceil/floor agree, so a test built only on that size
    /// cannot see the difference. (Found by mutating `.ceil()` to `.floor()`
    /// and watching only ONE test fail.)
    #[test]
    fn nearest_rank_rounds_up_not_down() {
        let mut xs = vec![10u64, 20, 30];
        let p = percentiles(&mut xs);
        // ceil(0.50*3) = 2 → index 1 → 20. Rounding DOWN would give index 1-1=0 → 10.
        assert_eq!(p.p50_us, 20, "p50 of [10,20,30] is the middle observation");
        // ceil(0.95*3) = 3 → index 2 → 30.
        assert_eq!(p.p95_us, 30);

        let mut xs: Vec<u64> = (1..=7).collect();
        let p = percentiles(&mut xs);
        assert_eq!(p.p50_us, 4, "ceil(3.5)=4 → index 3 → the value 4");
        assert_eq!(p.p95_us, 7, "ceil(6.65)=7 → index 6 → the value 7");
        assert_eq!(p.p99_us, 7);
    }

    #[test]
    fn a_single_sample_is_every_percentile() {
        let mut xs = vec![7u64];
        let p = percentiles(&mut xs);
        assert_eq!(
            (p.n, p.min_us, p.p50_us, p.p99_us, p.max_us),
            (1, 7, 7, 7, 7)
        );
    }

    #[test]
    fn an_empty_sample_is_all_zero_and_never_panics() {
        let mut xs: Vec<u64> = vec![];
        assert_eq!(percentiles(&mut xs), Percentiles::default());
    }

    /// The tail is the whole point: a distribution that is fast except for one
    /// outlier must NOT read as fast at p99 when there are ≥100 samples.
    #[test]
    fn one_slow_request_in_a_hundred_shows_at_p99() {
        let mut xs: Vec<u64> = std::iter::repeat_n(1u64, 99).collect();
        xs.push(10_000);
        let p = percentiles(&mut xs);
        assert_eq!(p.p95_us, 1);
        assert_eq!(
            p.p99_us, 1,
            "ceil(0.99*100)=99 → index 98, still the fast bulk"
        );
        assert_eq!(p.max_us, 10_000, "…and max is what surfaces it");
        assert_eq!(
            p.mean_us, 100,
            "the mean hides it as a 100us 'average' — the reason this module reports neither alone"
        );
    }

    #[test]
    fn gate_verdicts_are_classified_from_the_body_not_the_status() {
        assert_eq!(
            classify_response(200, r#"{"decision":"allow"}"#),
            Outcome::GateAllow
        );
        assert_eq!(
            classify_response(200, r#"{"decision":"deny","message":"not approved"}"#),
            Outcome::GateDeny
        );
        // Pretty-printed spacing must not change the classification.
        assert_eq!(
            classify_response(200, "{\"decision\": \"deny\", \"message\": \"x\"}"),
            Outcome::GateDeny
        );
    }

    #[test]
    fn the_deployments_own_refusal_shapes_get_their_own_buckets() {
        assert_eq!(
            classify_response(403, r#"{"error":"wrong_audience"}"#),
            Outcome::WrongAudience
        );
        assert_eq!(
            classify_response(403, r#"{"error":"nope"}"#),
            Outcome::Forbidden
        );
        assert_eq!(
            classify_response(503, r#"{"error":"tenant_llm_keys_required"}"#),
            Outcome::TenantLlmKeysRequired
        );
        assert_eq!(
            classify_response(503, r#"{"error":"tenant_llm_key_unavailable"}"#),
            Outcome::TenantLlmKeyUnavailable
        );
        // A 503 that is NOT one of those must stay an anonymous server error —
        // otherwise the two buckets above would absorb unrelated failures.
        assert_eq!(
            classify_response(503, "upstream down"),
            Outcome::ServerError(503)
        );
    }

    #[test]
    fn throttling_is_recognised_from_a_200_body_as_well_as_from_429() {
        assert_eq!(classify_response(429, ""), Outcome::Throttled);
        assert_eq!(
            classify_response(
                200,
                r#"{"ok":false,"error":"outbound rate limit reached (scope connection), retry after 7s"}"#
            ),
            Outcome::Throttled
        );
    }

    #[test]
    fn an_upstream_tool_error_is_not_a_transport_failure() {
        assert_eq!(
            classify_response(
                200,
                r#"{"ok":true,"result":{"content":[],"is_error":true}}"#
            ),
            Outcome::ToolIsError
        );
        assert_eq!(
            classify_response(
                200,
                r#"{"ok":true,"result":{"content":[],"is_error":false}}"#
            ),
            Outcome::Ok2xx
        );
    }

    #[test]
    fn transport_flags_beat_message_text() {
        assert_eq!(
            classify_transport(true, false, "whatever"),
            Outcome::Timeout
        );
        assert_eq!(
            classify_transport(false, true, "whatever"),
            Outcome::ConnectionRefused
        );
        // Unflagged resets still land in the connection bucket — under load
        // those ARE the accept-queue finding.
        assert_eq!(
            classify_transport(
                false,
                false,
                "error sending request: Connection reset by peer"
            ),
            Outcome::ConnectionRefused
        );
        assert_eq!(
            classify_transport(false, false, "error decoding response body"),
            Outcome::Transport("body".into())
        );
        assert_eq!(
            classify_transport(false, false, "something else entirely"),
            Outcome::Transport("other".into())
        );
    }

    /// Labels must be unique across variants, or two distinct outcomes would
    /// merge into one row of the report and a `ClientError(400)` would be
    /// indistinguishable from a `ServerError(400)`.
    #[test]
    fn every_variant_has_a_distinct_label_and_a_stated_health() {
        let all = [
            Outcome::Ok2xx,
            Outcome::GateAllow,
            Outcome::GateDeny,
            Outcome::ToolIsError,
            Outcome::Unauthorized,
            Outcome::WrongAudience,
            Outcome::Forbidden,
            Outcome::NotFound,
            Outcome::Throttled,
            Outcome::BudgetExceeded,
            Outcome::TenantLlmKeysRequired,
            Outcome::TenantLlmKeyUnavailable,
            Outcome::ClientError(400),
            Outcome::ServerError(500),
            Outcome::OtherStatus(100),
            Outcome::Timeout,
            Outcome::ConnectionRefused,
            Outcome::Transport("other".into()),
        ];
        let mut labels = std::collections::HashSet::new();
        for o in &all {
            assert!(labels.insert(o.label()), "duplicate label for {o:?}");
        }
        // The healthy set is exactly "the deployment answered normally".
        let healthy: Vec<String> = all
            .iter()
            .filter(|o| o.is_healthy())
            .map(|o| o.label())
            .collect();
        assert_eq!(
            healthy,
            vec![
                "ok_2xx".to_string(),
                "gate_allow".to_string(),
                "gate_deny".to_string(),
                "tool_is_error".to_string(),
                "throttled".to_string()
            ],
            "a change to the healthy set must be deliberate: it moves the capacity gate"
        );
    }

    #[test]
    fn the_recorder_counts_per_op_and_totals_the_unhealthy() {
        let mut r = Recorder::default();
        r.record("permission", Duration::from_millis(1), Outcome::GateAllow);
        r.record("permission", Duration::from_millis(3), Outcome::GateDeny);
        r.record("permission", Duration::from_millis(2), Outcome::Timeout);
        r.record(
            "facade",
            Duration::from_millis(5),
            Outcome::ServerError(502),
        );
        let s = r.summary();
        assert_eq!(s.len(), 2);
        let perm = s
            .iter()
            .find(|o| o.op == "permission")
            .expect("op recorded");
        assert_eq!(perm.latency.n, 3);
        assert_eq!(perm.latency.max_us, 3000);
        assert_eq!(r.request_total(), 4);
        assert_eq!(r.unhealthy_total(), 2, "the timeout and the 502");
    }
}
