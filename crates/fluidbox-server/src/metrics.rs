//! Hand-rolled, dependency-free operational metrics (Phase F, issue #34
//! deliverable 2; design §Operational metrics).
//!
//! **Why hand-rolled.** The alternative is a metrics crate (`prometheus`,
//! `metrics`), which would pull a registry, a macro layer, and an exposition
//! encoder into a binary whose whole design ethos is "the Rust API owns the
//! logic, nothing floats". A control plane needs perhaps a dozen counters, three
//! gauges and two histograms; that is three small lock-free primitives and one
//! text renderer, all here, all auditable in one file.
//!
//! **Cardinality is a security property, not a style choice.** Tenants are
//! mutually untrusted (a hostile tenant can create connections, name MCP servers,
//! and drive tool calls at will). A metric labelled by `tenant_id`,
//! `connection_id` or an upstream host would let that tenant mint unbounded time
//! series and exhaust this registry's memory — a cardinality DoS. So every label
//! set here is FIXED AT COMPILE TIME ([`Family`]), with an `_other` catch-all that
//! absorbs an unexpected value into ONE bucket instead of growing the map. The
//! design's "internal IDs ... without recording credentials, authorization codes,
//! full prompts, or raw tool payloads" is honoured by construction: nothing here
//! records an id, a host, a credential or a payload. Per-tenant / per-connection
//! attribution is answered from the ledger and `usage_entries` (already redacted,
//! already tenant-scoped), which is where a high-cardinality question belongs.
//!
//! **What is in the registry vs. read live.** Monotonic counters and latency
//! histograms accumulate here. Point-in-time values that a durable source already
//! holds — the database pool's checked-out count, the live MCP-session-registry
//! size, the governor's own rejection tallies — are read at render time from that
//! source ([`Live`]) rather than shadowed by an event-driven gauge that would
//! drift on restart. The one exception is [`Metrics::active_runs`], a replica-local
//! gauge maintained by the orchestrator transition funnel; it resets to zero on
//! restart (disclosed — it is an operational trend signal, and the authoritative
//! in-flight count is the `sessions` table).

use crate::auth::Admin;
use crate::state::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// A monotonically increasing counter.
#[derive(Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    #[cfg(test)]
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A gauge that can move both directions. `dec` saturates at zero so a
/// transition decremented on a replica that never saw the matching increment
/// (e.g. a run that entered `running` before this process booted) can never
/// drive the gauge negative.
#[derive(Default)]
pub struct Gauge(AtomicI64);

impl Gauge {
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    /// Saturating decrement — never below zero.
    pub fn dec(&self) {
        // fetch_update keeps the floor atomic against concurrent inc/dec.
        let _ = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(if v > 0 { v - 1 } else { 0 })
            });
    }
    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A labelled counter over a FIXED set of label values, plus an `_other`
/// catch-all. The value set is fixed at construction, so an untrusted caller
/// cannot grow the series count — the cardinality-DoS defence. Values render in
/// declaration order (deterministic exposition; a `HashMap` would not be), and a
/// value not in the set lands in `_other` instead of being dropped or panicking.
pub struct Family {
    /// e.g. `fluidbox_gate_decisions_total`
    name: &'static str,
    /// e.g. `verdict`
    label: &'static str,
    /// Ordered `(value, count)` — small N, linear scan on the hot path is
    /// cheaper than a hash and keeps render order stable.
    buckets: Vec<(&'static str, AtomicU64)>,
    other: AtomicU64,
}

impl Family {
    pub fn new(name: &'static str, label: &'static str, values: &[&'static str]) -> Self {
        Family {
            name,
            label,
            buckets: values.iter().map(|v| (*v, AtomicU64::new(0))).collect(),
            other: AtomicU64::new(0),
        }
    }

    /// Increment the bucket for `value`, or `_other` if `value` is not one of the
    /// declared labels.
    pub fn inc(&self, value: &str) {
        for (v, c) in &self.buckets {
            if *v == value {
                c.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        self.other.fetch_add(1, Ordering::Relaxed);
    }

    /// Test/read accessor: the current count for a declared value (0 if unknown).
    #[cfg(test)]
    pub fn get(&self, value: &str) -> u64 {
        self.buckets
            .iter()
            .find(|(v, _)| *v == value)
            .map(|(_, c)| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn render(&self, out: &mut String, help: &str) {
        let _ = writeln!(out, "# HELP {} {}", self.name, help);
        let _ = writeln!(out, "# TYPE {} counter", self.name);
        for (v, c) in &self.buckets {
            let _ = writeln!(
                out,
                "{}{{{}=\"{}\"}} {}",
                self.name,
                self.label,
                v,
                c.load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            out,
            "{}{{{}=\"_other\"}} {}",
            self.name,
            self.label,
            self.other.load(Ordering::Relaxed)
        );
    }
}

/// A fixed-bucket cumulative histogram (Prometheus histogram shape). `bounds` are
/// the exclusive upper edges in the metric's own unit (milliseconds here); an
/// implicit `+Inf` bucket catches the tail. Storage is per-bucket (non-cumulative)
/// and rendered cumulatively, so the arithmetic is a single prefix sum with no
/// possibility of a non-monotone `le` sequence.
pub struct Histogram {
    name: &'static str,
    bounds: &'static [f64],
    /// One counter per bound plus one for `+Inf`; `counts.len() == bounds.len() + 1`.
    counts: Vec<AtomicU64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    pub fn new(name: &'static str, bounds: &'static [f64]) -> Self {
        Histogram {
            name,
            bounds,
            counts: (0..bounds.len() + 1).map(|_| AtomicU64::new(0)).collect(),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Observe a value in the histogram's unit (milliseconds). The value is
    /// bounded by the caller's own timers; a `NaN`/negative is clamped to the
    /// first bucket rather than skipped, so `count` always reconciles with the
    /// bucket total.
    pub fn observe(&self, value: f64) {
        let idx = self
            .bounds
            .iter()
            .position(|b| value <= *b)
            .unwrap_or(self.bounds.len());
        self.counts[idx].fetch_add(1, Ordering::Relaxed);
        // Sum is accumulated as an integer in the metric's unit; observations are
        // whole milliseconds from `Duration::as_millis`, so no precision is lost.
        let ms = if value.is_finite() && value > 0.0 {
            value as u64
        } else {
            0
        };
        self.sum.fetch_add(ms, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Test accessor: total observations.
    #[cfg(test)]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    fn render(&self, out: &mut String, help: &str) {
        let _ = writeln!(out, "# HELP {} {}", self.name, help);
        let _ = writeln!(out, "# TYPE {} histogram", self.name);
        let mut cumulative = 0u64;
        for (i, bound) in self.bounds.iter().enumerate() {
            cumulative += self.counts[i].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{}_bucket{{le=\"{}\"}} {}",
                self.name, bound, cumulative
            );
        }
        cumulative += self.counts[self.bounds.len()].load(Ordering::Relaxed);
        let _ = writeln!(out, "{}_bucket{{le=\"+Inf\"}} {}", self.name, cumulative);
        // sum is milliseconds; expose as a float in the base unit's convention.
        let _ = writeln!(
            out,
            "{}_sum {}",
            self.name,
            self.sum.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "{}_count {}",
            self.name,
            self.count.load(Ordering::Relaxed)
        );
    }
}

/// Latency-histogram bucket edges in MILLISECONDS for a brokered upstream call:
/// a few ms (fast local MCP) up to the 900 s upstream timeout's neighbourhood.
const BROKER_LATENCY_MS: &[f64] = &[
    5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0, 30000.0,
];
/// Latency-histogram bucket edges in MILLISECONDS for run provisioning
/// (creation → running): tens of ms to a couple of minutes.
const PROVISION_LATENCY_MS: &[f64] = &[
    100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0, 30000.0, 60000.0, 120000.0,
];

/// The process-wide metrics registry. One instance lives on [`crate::state::AppStateInner`].
///
/// Fields are grouped by the design's §Operational-metrics bullets. Each is fed
/// from exactly one insertion point (a funnel where the data already sits) —
/// [`crate::ledger::record`] for event-derived families, the orchestrator
/// transition for run lifecycle, the facade for reservations, the governor/pool
/// read live at render.
pub struct Metrics {
    // ── Tool-call gate (design: "tool calls allowed, denied, awaiting approval,
    // failed, and ambiguous"). Fed from `ledger::record`'s `ToolDecision` arm.
    /// `verdict` = allow | deny | require_approval (plus `_other`).
    pub gate_verdicts: Family,
    /// `source` for a non-`allow` decision: capability | binding | schema |
    /// trust_tier | policy | protocol_violation | human | session_terminal |
    /// autonomy_rewrite | session_scope (anything else → `_other`).
    pub gate_sources: Family,
    // ── Brokered execution (design: broker latency; tool calls failed/ambiguous).
    /// `outcome` = succeeded | failed_upstream | failed_before_send | ambiguous.
    pub brokered_outcomes: Family,
    pub broker_latency_ms: Histogram,
    /// Upstream MCP failure class the broker genuinely distinguishes (it collapses
    /// numeric statuses into semantic `CallErr` variants by design, so a numeric
    /// 401/404/429/5xx split is not retained at the result and is deliberately NOT
    /// fabricated here): unauthorized (clean 401) | insufficient_scope (SEP-835) |
    /// unavailable (upstream-health failure — 5xx/429/timeout, the breaker's input).
    pub upstream_classes: Family,
    /// Tool-result truncations (the per-event / total SSE caps tripped).
    pub tool_result_truncations: Counter,
    // ── Egress governance (design: egress-policy rejections). Fed from the
    // governor gate the broker dials through. `reason` = rate_limited (any rate
    // dimension) | breaker_open. (SSRF `admit_url` refusals are not counted: their
    // sites are the state-less dial helpers, and a save-time-admitted URL reaching
    // one is already a misconfiguration, not a steady-state signal.)
    pub egress_rejections: Family,
    // ── OAuth custody (design: refresh attempts, races, failures, invalid grants;
    // revocations and generation mismatches).
    /// `event` = attempt | success | invalid_grant | error | race.
    pub oauth_refresh: Family,
    pub connection_revocations: Counter,
    pub generation_mismatches: Counter,
    // ── LLM budget (Gap 14 reservations). `event` = booked | released | charged |
    // swept | refused.
    pub reservations: Family,
    // ── Delivery (result callbacks + external publish). Fed from `ledger::record`'s
    // `CallbackDelivered`/`CallbackFailed` arms. `event` = delivered | failed.
    pub deliveries: Family,
    // ── Run lifecycle. `outcome` = completed | failed | cancelled | budget_exceeded.
    pub runs_terminal: Family,
    /// In-flight runs (provisioning..finalizing). Replica-local; resets on restart.
    pub active_runs: Gauge,
    pub run_provisioning_ms: Histogram,
    // ── Durability (design: database event and ledger write rates).
    pub ledger_events: Counter,
    /// Metrics-scrape failures (a live read — pool count etc. — that errored).
    pub scrape_errors: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            gate_verdicts: Family::new(
                "fluidbox_gate_decisions_total",
                "verdict",
                &["allow", "deny", "require_approval"],
            ),
            gate_sources: Family::new(
                "fluidbox_gate_deny_source_total",
                "source",
                &[
                    "capability",
                    "binding",
                    "schema",
                    "trust_tier",
                    "policy",
                    "protocol_violation",
                    "human",
                    "session_terminal",
                    "autonomy_rewrite",
                    "session_scope",
                ],
            ),
            brokered_outcomes: Family::new(
                "fluidbox_brokered_calls_total",
                "outcome",
                &[
                    "succeeded",
                    "failed_upstream",
                    "failed_before_send",
                    "ambiguous",
                ],
            ),
            broker_latency_ms: Histogram::new("fluidbox_broker_call_latency_ms", BROKER_LATENCY_MS),
            upstream_classes: Family::new(
                "fluidbox_upstream_failures_total",
                "class",
                &["unauthorized", "insufficient_scope", "unavailable"],
            ),
            tool_result_truncations: Counter::default(),
            egress_rejections: Family::new(
                "fluidbox_egress_rejections_total",
                "reason",
                &["rate_limited", "breaker_open"],
            ),
            oauth_refresh: Family::new(
                "fluidbox_oauth_refresh_total",
                "event",
                &["attempt", "success", "invalid_grant", "error", "race"],
            ),
            connection_revocations: Counter::default(),
            generation_mismatches: Counter::default(),
            reservations: Family::new(
                "fluidbox_llm_reservations_total",
                "event",
                &["booked", "released", "charged", "swept", "refused"],
            ),
            deliveries: Family::new(
                "fluidbox_deliveries_total",
                "event",
                &["delivered", "failed"],
            ),
            runs_terminal: Family::new(
                "fluidbox_runs_terminal_total",
                "outcome",
                &["completed", "failed", "cancelled", "budget_exceeded"],
            ),
            active_runs: Gauge::default(),
            run_provisioning_ms: Histogram::new(
                "fluidbox_run_provisioning_latency_ms",
                PROVISION_LATENCY_MS,
            ),
            ledger_events: Counter::default(),
            scrape_errors: Counter::default(),
        }
    }
}

/// Point-in-time values read from their authoritative source at render time,
/// never shadowed by an event-driven gauge. Assembled by the metrics handler and
/// the governor; keeping them out of [`Metrics`] is what stops a restart from
/// leaving a stale pool/session gauge behind.
pub struct Live {
    /// `sqlx` pool: total connections and currently-idle. In-use = size - idle.
    pub pool_size: u32,
    pub pool_idle: u32,
    pub pool_max: u32,
    /// Live per-run upstream MCP sessions held on this replica.
    pub mcp_sessions: u64,
    /// Governor durable-tier degrade count (a DB-outage fell back to local-only).
    pub governor_degraded: u64,
}

/// Render the full Prometheus text exposition. Deterministic: families and
/// histograms emit in field-declaration order and buckets in declaration order,
/// so a golden-string test is stable.
pub fn render(m: &Metrics, live: &Live) -> String {
    let mut out = String::with_capacity(4096);

    m.gate_verdicts
        .render(&mut out, "Tool-call gate verdicts by verdict class.");
    m.gate_sources.render(
        &mut out,
        "Tool-call gate deny/approval decisions by deciding stage.",
    );
    m.brokered_outcomes.render(
        &mut out,
        "Brokered tool executions by durable claim outcome.",
    );
    m.broker_latency_ms
        .render(&mut out, "Brokered upstream call latency, milliseconds.");
    m.upstream_classes.render(
        &mut out,
        "Upstream MCP call failures by broker-distinguished class.",
    );

    counter(
        &mut out,
        "fluidbox_tool_result_truncations_total",
        "Brokered tool results truncated at an SSE/size cap.",
        m.tool_result_truncations.get(),
    );

    m.egress_rejections
        .render(&mut out, "Outbound egress admission refusals by reason.");
    // Rate-limit and breaker-open refusals live on the governor's own tallies
    // (read live so a restart cannot leave a stale count) rather than being
    // double-counted into the family above.
    gauge_i64(
        &mut out,
        "fluidbox_egress_governor_degraded_total",
        "counter",
        "Times the durable egress governor fell back to local-only on a store error.",
        live.governor_degraded as i64,
    );

    m.oauth_refresh
        .render(&mut out, "Connector OAuth token-refresh outcomes.");
    counter(
        &mut out,
        "fluidbox_connection_revocations_total",
        "Connections revoked.",
        m.connection_revocations.get(),
    );
    counter(
        &mut out,
        "fluidbox_generation_mismatches_total",
        "Brokered dials refused on a stale authorization generation.",
        m.generation_mismatches.get(),
    );

    m.reservations
        .render(&mut out, "LLM budget reservation lifecycle events.");
    m.deliveries
        .render(&mut out, "Result-delivery callback outcomes.");
    m.runs_terminal
        .render(&mut out, "Runs reaching a terminal state by outcome.");

    gauge_i64(
        &mut out,
        "fluidbox_active_runs",
        "gauge",
        "In-flight runs (provisioning through finalizing) on this replica.",
        m.active_runs.get(),
    );
    m.run_provisioning_ms.render(
        &mut out,
        "Run provisioning latency (created to running), milliseconds.",
    );

    counter(
        &mut out,
        "fluidbox_ledger_events_total",
        "Events appended to the redacted ledger.",
        m.ledger_events.get(),
    );

    // Live gauges from their authoritative sources.
    gauge_i64(
        &mut out,
        "fluidbox_mcp_sessions_active",
        "gauge",
        "Live upstream MCP sessions held on this replica.",
        live.mcp_sessions as i64,
    );
    gauge_i64(
        &mut out,
        "fluidbox_db_pool_connections",
        "gauge",
        "Total connections in the database pool.",
        live.pool_size as i64,
    );
    gauge_i64(
        &mut out,
        "fluidbox_db_pool_idle",
        "gauge",
        "Idle (available) connections in the database pool.",
        live.pool_idle as i64,
    );
    gauge_i64(
        &mut out,
        "fluidbox_db_pool_max",
        "gauge",
        "Configured maximum size of the database pool.",
        live.pool_max as i64,
    );
    counter(
        &mut out,
        "fluidbox_metrics_scrape_errors_total",
        "Live reads that failed while rendering this exposition.",
        m.scrape_errors.get(),
    );

    out
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(out, "{name} {value}");
}

fn gauge_i64(out: &mut String, name: &str, kind: &str, help: &str, value: i64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    let _ = writeln!(out, "{name} {value}");
}

/// The Prometheus text exposition content type (v0.0.4).
const EXPOSITION_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Assemble the [`Live`] snapshot from authoritative sources. All reads are
/// in-memory (pool stats, a brief registry lock) — NO database query — so a
/// scrape, including on the unauthenticated bind, cannot be turned into DB load.
async fn snapshot(state: &AppState) -> Live {
    let mcp_sessions = state.mcp_sessions.lock().await.len() as u64;
    Live {
        pool_size: state.pool.size(),
        pool_idle: state.pool.num_idle() as u32,
        pool_max: state.cfg.db_pool.max_connections,
        mcp_sessions,
        governor_degraded: state.governor.degraded_count(),
    }
}

async fn render_response(state: &AppState) -> impl IntoResponse {
    let live = snapshot(state).await;
    let body = render(&state.metrics, &live);
    (
        [(axum::http::header::CONTENT_TYPE, EXPOSITION_CONTENT_TYPE)],
        body,
    )
}

/// `GET /v1/admin/metrics` — admin-token-gated Prometheus exposition. The `Admin`
/// extractor is the SAME gate the rest of `/v1/admin/*` uses, and under
/// `FLUIDBOX_REQUIRE_SSO=1` it stays valid (operator break-glass surface) while a
/// user/PAT principal cannot reach it.
pub async fn admin_metrics(_: Admin, State(state): State<AppState>) -> impl IntoResponse {
    render_response(&state).await
}

/// The handler served on the optional `FLUIDBOX_METRICS_BIND` listener. It is
/// UNAUTHENTICATED by design (the scrape convention), which is why that listener
/// must bind a private interface — see [`crate::config::Config::metrics_bind`].
pub async fn metrics_endpoint(State(state): State<AppState>) -> impl IntoResponse {
    render_response(&state).await
}

/// Whether a session status counts as an in-flight run for [`Metrics::active_runs`]:
/// a sandbox exists / capacity is held from `provisioning` through `finalizing`.
/// `created` is pre-sandbox; the four terminal states have released it.
pub fn status_is_active(status: fluidbox_core::state::SessionStatus) -> bool {
    use fluidbox_core::state::SessionStatus::*;
    matches!(
        status,
        Provisioning | Initializing | Running | AwaitingApproval | Cancelling | Finalizing
    )
}

/// The active-runs gauge delta for a `from → to` transition, factored out so the
/// accounting is unit-testable without driving the orchestrator. `+1` on the edge
/// that first enters the active band, `-1` on the edge that leaves it for a
/// terminal state, `0` otherwise. Because the gauge only ever counts edges INTO
/// and OUT OF the active band (never within it), and `Gauge::dec` saturates at
/// zero, no sequence — including one that begins mid-run after a restart — drives
/// it negative or double-counts.
pub fn active_delta(
    from: fluidbox_core::state::SessionStatus,
    to: fluidbox_core::state::SessionStatus,
) -> i64 {
    let was = status_is_active(from);
    let now = status_is_active(to);
    match (was, now) {
        (false, true) => 1,
        (true, false) => -1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::state::SessionStatus;

    #[test]
    fn counter_and_gauge_basics() {
        let c = Counter::default();
        c.inc();
        c.add(4);
        assert_eq!(c.get(), 5);

        let g = Gauge::default();
        g.inc();
        g.inc();
        g.dec();
        assert_eq!(g.get(), 1);
        // Saturating: dec past zero stays at zero.
        g.dec();
        g.dec();
        assert_eq!(g.get(), 0);
    }

    #[test]
    fn family_routes_unknown_values_to_other_not_a_new_series() {
        let f = Family::new("t", "l", &["allow", "deny"]);
        f.inc("allow");
        f.inc("allow");
        f.inc("deny");
        f.inc("something_new"); // unexpected → _other, NOT a new bucket
        assert_eq!(f.get("allow"), 2);
        assert_eq!(f.get("deny"), 1);
        // Cardinality is bounded: still exactly the two declared buckets.
        assert_eq!(f.buckets.len(), 2);
        let mut out = String::new();
        f.render(&mut out, "help");
        assert!(out.contains("t{l=\"allow\"} 2"));
        assert!(out.contains("t{l=\"deny\"} 1"));
        assert!(out.contains("t{l=\"_other\"} 1"));
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_reconcile() {
        let h = Histogram::new("h", &[10.0, 100.0]);
        h.observe(5.0); // le=10
        h.observe(50.0); // le=100
        h.observe(500.0); // +Inf
        let mut out = String::new();
        h.render(&mut out, "help");
        // Cumulative: le=10 has 1, le=100 has 2, +Inf has 3.
        assert!(out.contains("h_bucket{le=\"10\"} 1"), "{out}");
        assert!(out.contains("h_bucket{le=\"100\"} 2"), "{out}");
        assert!(out.contains("h_bucket{le=\"+Inf\"} 3"), "{out}");
        assert!(out.contains("h_count 3"), "{out}");
        // Sum reconciles the observed integer milliseconds.
        assert!(out.contains("h_sum 555"), "{out}");
        assert_eq!(h.count(), 3);
    }

    #[test]
    fn active_delta_counts_the_band_edges_exactly_once() {
        use SessionStatus::*;
        // Enter the active band once (created → provisioning).
        assert_eq!(active_delta(Created, Provisioning), 1);
        // Moving within the band never re-increments.
        assert_eq!(active_delta(Provisioning, Initializing), 0);
        assert_eq!(active_delta(Initializing, Running), 0);
        assert_eq!(active_delta(Running, AwaitingApproval), 0);
        assert_eq!(active_delta(AwaitingApproval, Running), 0);
        assert_eq!(active_delta(Running, Finalizing), 0);
        // Leave the band exactly once (active → terminal).
        assert_eq!(active_delta(Finalizing, Completed), -1);
        // A run that goes terminal WITHOUT ever provisioning (created → failed)
        // never entered the band, so it must not decrement.
        assert_eq!(active_delta(Created, Failed), 0);
        // A full lifecycle nets to zero.
        let seq = [
            (Created, Provisioning),
            (Provisioning, Initializing),
            (Initializing, Running),
            (Running, Finalizing),
            (Finalizing, Completed),
        ];
        let net: i64 = seq.iter().map(|(f, t)| active_delta(*f, *t)).sum();
        assert_eq!(net, 0, "a full lifecycle must net to zero");
    }

    #[test]
    fn render_is_deterministic_and_well_formed() {
        let m = Metrics::default();
        m.gate_verdicts.inc("allow");
        m.brokered_outcomes.inc("ambiguous");
        m.broker_latency_ms.observe(42.0);
        m.active_runs.inc();
        let live = Live {
            pool_size: 8,
            pool_idle: 6,
            pool_max: 10,
            mcp_sessions: 3,
            governor_degraded: 0,
        };
        let a = render(&m, &live);
        let b = render(&m, &live);
        assert_eq!(a, b, "render must be deterministic");
        // Spot-check the exposition names a monitoring system keys on exist.
        for needle in [
            "fluidbox_gate_decisions_total{verdict=\"allow\"} 1",
            "fluidbox_brokered_calls_total{outcome=\"ambiguous\"} 1",
            "fluidbox_broker_call_latency_ms_count 1",
            "fluidbox_active_runs 1",
            "fluidbox_db_pool_idle 6",
            "fluidbox_db_pool_max 10",
            "fluidbox_mcp_sessions_active 3",
            "# TYPE fluidbox_gate_decisions_total counter",
            "# TYPE fluidbox_broker_call_latency_ms histogram",
        ] {
            assert!(a.contains(needle), "missing exposition line: {needle}\n{a}");
        }
    }
}

/// A duplicate metric NAME across families/gauges would make the exposition
/// invalid (Prometheus rejects a repeated `# TYPE`). This can only happen by a
/// copy-paste in [`render`] or a constructor, and no smaller unit test sees the
/// whole set at once — so assert the whole rendered surface has unique metric
/// names. Kept a source-level guard rather than a golden file so adding a metric
/// does not require regenerating a fixture, only staying unique.
#[cfg(test)]
mod exposition_guard {
    use super::*;

    #[test]
    fn every_metric_name_is_unique_in_the_exposition() {
        let m = Metrics::default();
        let live = Live {
            pool_size: 1,
            pool_idle: 1,
            pool_max: 1,
            mcp_sessions: 0,
            governor_degraded: 0,
        };
        let text = render(&m, &live);
        let mut names = std::collections::HashSet::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let name = rest.split_whitespace().next().unwrap_or("");
                assert!(
                    names.insert(name.to_string()),
                    "duplicate metric name in exposition: {name}"
                );
            }
        }
        // Sanity: we actually emitted a healthy number of distinct metrics.
        assert!(
            names.len() >= 15,
            "expected the full metric set, got {}",
            names.len()
        );
    }
}
