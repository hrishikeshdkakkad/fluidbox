//! Report rendering.
//!
//! Rule this module exists to enforce: EVERY REPORT LINE CARRIES THE PARAMETERS
//! THAT PRODUCED IT. A percentile with no N, no concurrency and no seed beside
//! it is a number somebody will quote in six months with no way to reproduce it,
//! so the parameter block is printed by the same function that prints the
//! numbers and cannot be omitted by a scenario.

use crate::metrics::{OpSummary, Recorder};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The reproducibility header + whatever the scenario wants to add.
#[derive(Clone, Debug, Default)]
pub struct Params(BTreeMap<String, String>);

impl Params {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(mut self, k: &str, v: impl std::fmt::Display) -> Self {
        self.0.insert(k.to_string(), v.to_string());
        self
    }
    pub fn as_json(&self) -> Value {
        Value::Object(
            self.0
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect(),
        )
    }
}

/// A scenario-supplied table of facts read from the database rather than from an
/// HTTP response (ledger deny sources, execution-claim states, row counts).
#[derive(Clone, Debug, Default)]
pub struct DbFacts(Vec<(String, Vec<(String, i64)>)>);

impl DbFacts {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, title: &str, rows: Vec<(String, i64)>) {
        self.0.push((title.to_string(), rows));
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    fn as_json(&self) -> Value {
        Value::Object(
            self.0
                .iter()
                .map(|(t, rows)| {
                    (
                        t.clone(),
                        Value::Object(rows.iter().map(|(k, v)| (k.clone(), json!(v))).collect()),
                    )
                })
                .collect(),
        )
    }
}

fn ms(us: u64) -> String {
    format!("{:.1}ms", us as f64 / 1000.0)
}

pub fn print(scenario: &str, params: &Params, rec: &Recorder, facts: &DbFacts, as_json: bool) {
    let summaries = rec.summary();
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&to_json(scenario, params, rec, facts, &summaries))
                .unwrap_or_default()
        );
        return;
    }

    println!("\n══ fluidbox-loadgen — scenario '{scenario}' ══");
    println!("  parameters (every number below is conditioned on these):");
    for (k, v) in &params.0 {
        println!("    {k:<28} {v}");
    }

    println!("\n  latency (nearest-rank percentiles over completed requests, incl. failures):");
    println!(
        "    {:<26} {:>6}  {:>9} {:>9} {:>9} {:>9} {:>9}",
        "operation", "n", "min", "p50", "p95", "p99", "max"
    );
    for s in &summaries {
        let l = &s.latency;
        println!(
            "    {:<26} {:>6}  {:>9} {:>9} {:>9} {:>9} {:>9}",
            s.op,
            l.n,
            ms(l.min_us),
            ms(l.p50_us),
            ms(l.p95_us),
            ms(l.p99_us),
            ms(l.max_us)
        );
    }

    println!(
        "\n  outcome taxonomy (per operation; a gate DENY is a healthy answer, a 5xx is not):"
    );
    for s in &summaries {
        println!("    {}", s.op);
        for (label, n) in &s.outcomes {
            println!("      {label:<34} {n:>8}");
        }
    }

    if !facts.is_empty() {
        println!("\n  database-derived facts (authoritative — read from the ledger/claim rows,");
        println!("  not inferred from response prose):");
        for (title, rows) in &facts.0 {
            println!("    {title}");
            if rows.is_empty() {
                println!("      (no rows)");
            }
            for (k, n) in rows {
                println!("      {k:<34} {n:>8}");
            }
        }
    }

    let total = rec.request_total();
    let unhealthy = rec.unhealthy_total();
    println!(
        "\n  TOTAL {total} requests, {unhealthy} unhealthy ({:.2}%)",
        if total == 0 {
            0.0
        } else {
            100.0 * unhealthy as f64 / total as f64
        }
    );
    println!("{}", LIMITS);
}

fn to_json(
    scenario: &str,
    params: &Params,
    rec: &Recorder,
    facts: &DbFacts,
    summaries: &[OpSummary],
) -> Value {
    json!({
        "scenario": scenario,
        "parameters": params.as_json(),
        "operations": summaries.iter().map(|s| json!({
            "op": s.op,
            "latency_us": {
                "n": s.latency.n,
                "min": s.latency.min_us,
                "p50": s.latency.p50_us,
                "p95": s.latency.p95_us,
                "p99": s.latency.p99_us,
                "max": s.latency.max_us,
                "mean": s.latency.mean_us,
            },
            "outcomes": s.outcomes.iter()
                .map(|(k, v)| (k.clone(), json!(v)))
                .collect::<serde_json::Map<String, Value>>(),
        })).collect::<Vec<_>>(),
        "db_facts": facts.as_json(),
        "totals": {"requests": rec.request_total(), "unhealthy": rec.unhealthy_total()},
        "limits": LIMITS.trim(),
    })
}

/// Printed at the foot of EVERY report, on purpose. The single most likely way
/// this harness misleads someone is by having its numbers quoted as "we tested
/// 300 concurrent sandboxes"; the numbers are about the control plane, and the
/// difference is stated where the numbers are, not only in a document.
pub const LIMITS: &str = "
  WHAT THESE NUMBERS DO NOT COVER
    * No sandboxes were provisioned for the seeded sessions. This measures the
      CONTROL PLANE at N concurrent runs — gate, facade, broker, approvals, DB —
      not the container runtime, the image pull, the workspace archive transfer,
      or the per-sandbox memory/CPU footprint. A deployment that passes here can
      still fail to schedule 300 pods.
    * The load is generated from ONE process on ONE host. Client-side CPU, the
      local ephemeral-port range and the loopback path are shared with the
      deployment under test, so absolute latencies are optimistic and the tail
      includes the harness's own scheduling.
    * Rate limits and circuit breakers have TWO tiers. The in-memory (local)
      tier — token buckets and breakers per tenant/connection/host — is
      PER-REPLICA and is checked FIRST, so a single-replica run cannot show the
      N x local ceiling a multi-replica deployment has. Phase F added a durable,
      Postgres-backed tier (default-on; FLUIDBOX_EGRESS_DURABLE) that enforces a
      deployment-WIDE, cross-replica ceiling for the tenant, user, connection and
      (tenant, host) dimensions — that ceiling IS visible from a single replica.
      The host_global cross-tenant tier stays local and per-replica.
    * Percentiles are over the requests this run made. p99 of 1,000 requests is
      one datum; it is not a service-level objective.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Outcome;
    use std::time::Duration;

    fn fixture() -> (Params, Recorder, DbFacts) {
        let params = Params::new()
            .set("seed", 24301u64)
            .set("sessions_seeded", 60);
        let mut rec = Recorder::default();
        rec.record(
            "internal.permission",
            Duration::from_millis(3),
            Outcome::GateAllow,
        );
        rec.record(
            "internal.permission",
            Duration::from_millis(9),
            Outcome::GateDeny,
        );
        rec.record(
            "internal.facade",
            Duration::from_millis(40),
            Outcome::ServerError(502),
        );
        let mut facts = DbFacts::new();
        facts.add("ledger deny sources", vec![("capability".into(), 1)]);
        (params, rec, facts)
    }

    /// The report is the tool's ENTIRE output; a serialization failure there
    /// would throw away a run that may have taken an hour. This drives the JSON
    /// path end to end and checks the numbers survive the round trip.
    #[test]
    fn the_json_report_round_trips_every_number() {
        let (params, rec, facts) = fixture();
        let v = to_json(
            "concurrent-sandboxes",
            &params,
            &rec,
            &facts,
            &rec.summary(),
        );
        let s = serde_json::to_string(&v).expect("the report must serialize");
        let back: Value = serde_json::from_str(&s).expect("…and parse back");

        assert_eq!(back["scenario"], "concurrent-sandboxes");
        assert_eq!(back["parameters"]["seed"], "24301");
        assert_eq!(back["totals"]["requests"], 3);
        assert_eq!(back["totals"]["unhealthy"], 1, "only the 502 is unhealthy");
        assert_eq!(back["db_facts"]["ledger deny sources"]["capability"], 1);

        let ops = back["operations"].as_array().expect("an operations array");
        assert_eq!(ops.len(), 2);
        let perm = ops
            .iter()
            .find(|o| o["op"] == "internal.permission")
            .expect("the permission op is present");
        assert_eq!(perm["latency_us"]["n"], 2);
        assert_eq!(perm["latency_us"]["max"], 9000);
        assert_eq!(perm["outcomes"]["gate_allow"], 1);
        assert_eq!(perm["outcomes"]["gate_deny"], 1);

        // The limits footer travels WITH the numbers, so a JSON consumer cannot
        // quote a p99 without also receiving the statement of what it excludes.
        assert!(
            back["limits"]
                .as_str()
                .is_some_and(|l| l.contains("No sandboxes were provisioned")),
            "the limits footer must ride in the JSON payload too"
        );
    }

    /// A scenario that made zero requests must render rather than divide by
    /// zero — this is the shape of a run that failed during setup, i.e. exactly
    /// when the report is most needed.
    #[test]
    fn an_empty_run_still_renders() {
        let rec = Recorder::default();
        let v = to_json("connections", &Params::new(), &rec, &DbFacts::new(), &[]);
        assert_eq!(v["totals"]["requests"], 0);
        print("connections", &Params::new(), &rec, &DbFacts::new(), false);
        print("connections", &Params::new(), &rec, &DbFacts::new(), true);
    }
}
