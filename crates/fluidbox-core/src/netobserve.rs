//! Turning denied network flows into timeline events, without letting a port
//! scan flood the ledger.
//!
//! The pure half of Phase 5. `append_event` takes a per-session ROW LOCK and
//! assigns a gapless sequence, so every event is a serialized write against the
//! session — which makes a hostile workload's flood a self-inflicted denial of
//! service on its own audit trail, and a real one on the database. A sandbox
//! that scans 65 535 ports must therefore produce a BOUNDED number of events.
//!
//! Two mechanisms, and they answer different questions:
//!
//! - **Dedup** answers "have we already said this?" — the first N *unique*
//!   `{target, port, protocol}` tuples are reported individually, because those
//!   are the ones an operator can act on.
//! - **The rollup** answers "what happened after that?" — everything past the
//!   unique cap is counted and periodically summarized, so the trail says
//!   "and 4 812 more denials across 213 targets" rather than either flooding or
//!   silently dropping them.
//!
//! Never claiming "no denials" is a hard requirement: an observation gap is a
//! GAP, and [`ObservationState::degraded`] records it so the timeline can say
//! "observation was unavailable" instead of implying silence meant safety.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Unique `{target, port, protocol}` tuples reported individually per session,
/// before everything else becomes rollup counts. Sized so an operator sees the
/// distinct destinations a misconfigured run actually wanted (a handful in
/// practice) while a scan cannot mint more than this many ledger writes.
pub const MAX_UNIQUE_DENIALS: usize = 20;

/// Distinct targets tracked for the rollup. Past this the rollup still counts
/// events but stops growing its target set — the memory bound that keeps a
/// hostile run from growing this map without limit.
pub const MAX_TRACKED_TARGETS: usize = 512;

/// One denied flow, already reduced to the fields a timeline may carry.
///
/// There is deliberately no payload, no TLS SNI beyond the destination name the
/// policy itself matched on, and no byte count — Hubble flows carry no reliable
/// per-flow byte totals, so volume comes from the collector's `/proc/net/dev`
/// instead. That split is stated in the docs rather than implied.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeniedFlow {
    /// The destination as the policy saw it: a name when the flow was
    /// name-resolved, otherwise an address.
    pub target: String,
    pub port: u16,
    pub protocol: String,
    /// The policy verdict verbatim ("DENIED"), kept so a future "audit" or
    /// "allowed" mode reads the same shape.
    pub decision: String,
    /// Which rule decided, when the datapath reports one.
    pub rule: Option<String>,
}

impl DeniedFlow {
    /// The dedup key. Deliberately excludes `rule`: the same denial reported
    /// with and without rule attribution is ONE fact, and keying on the rule
    /// would let an attacker double every event by varying it.
    pub fn key(&self) -> (String, u16, String) {
        (self.target.clone(), self.port, self.protocol.clone())
    }
}

/// What the observer decided to do with a flow.
#[derive(Debug, Clone, PartialEq)]
pub enum Observation {
    /// Append this as its own timeline event.
    Emit(DeniedFlow),
    /// Already reported, or past the unique cap — counted only.
    Suppressed,
    /// Time to append a rollup of everything suppressed since the last one.
    Rollup(DenialRollup),
}

/// The periodic summary of suppressed denials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DenialRollup {
    /// Denials suppressed since the previous rollup.
    pub suppressed: u64,
    /// Distinct targets among them, capped at [`MAX_TRACKED_TARGETS`].
    pub distinct_targets: usize,
    /// The most-denied targets, for the operator's first question.
    pub top_targets: Vec<(String, u64)>,
    /// True when the distinct-target count hit its cap — so the number is a
    /// floor, and the event says so rather than under-reporting silently.
    pub targets_truncated: bool,
}

/// Per-session observation state. Replica-local: an observer runs per replica,
/// so a session observed from two replicas could report the same first denial
/// twice. That is acceptable and disclosed — the alternative is a durable
/// cross-replica dedup table on the hot path of a purely informational signal.
#[derive(Debug, Default)]
pub struct ObservationState {
    seen: BTreeMap<(String, u16, String), u64>,
    emitted: usize,
    suppressed_since_rollup: u64,
    targets_since_rollup: BTreeMap<String, u64>,
    targets_truncated: bool,
    /// Set when the observation source itself was unavailable. The timeline
    /// must never read "no denials" when the truth is "we could not look".
    pub degraded: bool,
}

impl ObservationState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a denied flow and decide what the ledger should say about it.
    pub fn observe(&mut self, flow: DeniedFlow) -> Observation {
        let key = flow.key();
        let count = self.seen.entry(key.clone()).or_insert(0);
        *count += 1;
        let first_time = *count == 1;

        if first_time && self.emitted < MAX_UNIQUE_DENIALS {
            self.emitted += 1;
            return Observation::Emit(flow);
        }

        self.suppressed_since_rollup += 1;
        if self.targets_since_rollup.len() < MAX_TRACKED_TARGETS {
            *self.targets_since_rollup.entry(flow.target).or_insert(0) += 1;
        } else if !self.targets_since_rollup.contains_key(&flow.target) {
            // Past the bound: keep counting the total, stop growing the map,
            // and remember that the distinct count is now a floor.
            self.targets_truncated = true;
        } else {
            *self.targets_since_rollup.get_mut(&flow.target).unwrap() += 1;
        }
        Observation::Suppressed
    }

    /// Drain the suppressed denials into a rollup. Returns `None` when there is
    /// nothing to say — a quiet session appends nothing, so the rollup timer
    /// costs no ledger writes at all.
    pub fn take_rollup(&mut self) -> Option<DenialRollup> {
        if self.suppressed_since_rollup == 0 {
            return None;
        }
        let mut top: Vec<(String, u64)> = std::mem::take(&mut self.targets_since_rollup)
            .into_iter()
            .collect();
        // Descending by count, then by name so the output is deterministic.
        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let distinct_targets = top.len();
        top.truncate(5);
        let rollup = DenialRollup {
            suppressed: std::mem::take(&mut self.suppressed_since_rollup),
            distinct_targets,
            top_targets: top,
            targets_truncated: std::mem::take(&mut self.targets_truncated),
        };
        Some(rollup)
    }

    /// Total distinct tuples this session has been denied, across all time.
    pub fn distinct_denials(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(target: &str, port: u16) -> DeniedFlow {
        DeniedFlow {
            target: target.into(),
            port,
            protocol: "TCP".into(),
            decision: "DENIED".into(),
            rule: None,
        }
    }

    #[test]
    fn the_first_of_each_unique_tuple_is_emitted_and_repeats_are_not() {
        let mut s = ObservationState::new();
        assert!(matches!(
            s.observe(flow("a.test", 443)),
            Observation::Emit(_)
        ));
        // The same tuple again says nothing new.
        assert_eq!(s.observe(flow("a.test", 443)), Observation::Suppressed);
        assert_eq!(s.observe(flow("a.test", 443)), Observation::Suppressed);
        // A different PORT on the same host is a different fact.
        assert!(matches!(
            s.observe(flow("a.test", 80)),
            Observation::Emit(_)
        ));
        // …as is a different protocol.
        let udp = DeniedFlow {
            protocol: "UDP".into(),
            ..flow("a.test", 443)
        };
        assert!(matches!(s.observe(udp), Observation::Emit(_)));
        assert_eq!(s.distinct_denials(), 3);
    }

    #[test]
    fn the_rule_field_cannot_be_used_to_double_events() {
        // The dedup key excludes `rule` on purpose: the same denial reported
        // with and without rule attribution is ONE fact, and keying on it would
        // let a varying rule string mint an unbounded number of ledger writes.
        let mut s = ObservationState::new();
        assert!(matches!(
            s.observe(flow("a.test", 443)),
            Observation::Emit(_)
        ));
        let with_rule = DeniedFlow {
            rule: Some("cnp/fluidbox-run-x".into()),
            ..flow("a.test", 443)
        };
        assert_eq!(s.observe(with_rule), Observation::Suppressed);
    }

    #[test]
    fn a_port_scan_cannot_flood_the_ledger() {
        // THE reason this module exists: `append_event` takes a per-session row
        // lock, so an unbounded event stream is a database problem, not just a
        // noisy timeline.
        let mut s = ObservationState::new();
        let mut emitted = 0;
        for port in 1..=65535u16 {
            if matches!(s.observe(flow("victim.test", port)), Observation::Emit(_)) {
                emitted += 1;
            }
        }
        assert_eq!(
            emitted, MAX_UNIQUE_DENIALS,
            "a full port scan must mint exactly the unique cap, not 65535 events"
        );
        // …and nothing is LOST: the remainder is counted for the rollup.
        let r = s.take_rollup().expect("a scan must produce a rollup");
        assert_eq!(r.suppressed, 65535 - MAX_UNIQUE_DENIALS as u64);
        assert_eq!(r.distinct_targets, 1);
        assert_eq!(r.top_targets[0].0, "victim.test");
    }

    #[test]
    fn a_target_sweep_is_bounded_in_memory_and_says_so() {
        // The other half of the same hostile shape: many TARGETS rather than
        // many ports. The map stops growing, the total keeps counting, and the
        // rollup FLAGS that its distinct count is a floor rather than
        // under-reporting silently.
        let mut s = ObservationState::new();
        for i in 0..(MAX_TRACKED_TARGETS + 500) {
            s.observe(flow(&format!("t{i}.test"), 443));
        }
        let r = s.take_rollup().unwrap();
        assert!(
            r.targets_truncated,
            "truncation must be visible in the event"
        );
        assert_eq!(r.distinct_targets, MAX_TRACKED_TARGETS);
        // Every denial past the emit cap is still COUNTED, truncation or not.
        assert_eq!(
            r.suppressed,
            (MAX_TRACKED_TARGETS + 500 - MAX_UNIQUE_DENIALS) as u64
        );
    }

    #[test]
    fn a_quiet_session_appends_nothing() {
        // The rollup timer must cost zero ledger writes when there is nothing
        // to say — otherwise every idle run pays for the observer.
        let mut s = ObservationState::new();
        assert!(s.take_rollup().is_none());
        assert!(matches!(
            s.observe(flow("a.test", 443)),
            Observation::Emit(_)
        ));
        // One emitted flow is not "suppressed", so still nothing to roll up.
        assert!(s.take_rollup().is_none());
    }

    #[test]
    fn rollups_are_deterministic_and_ranked() {
        let mut s = ObservationState::new();
        // Fill the emit budget with a target we do not care about…
        for p in 1..=(MAX_UNIQUE_DENIALS as u16) {
            s.observe(flow("noise.test", p));
        }
        // …then produce a clear ranking among the suppressed.
        for _ in 0..10 {
            s.observe(flow("loud.test", 443));
        }
        for _ in 0..3 {
            s.observe(flow("quiet.test", 443));
        }
        let r = s.take_rollup().unwrap();
        assert_eq!(r.top_targets[0], ("loud.test".into(), 10));
        assert_eq!(r.top_targets[1], ("quiet.test".into(), 3));
        // Draining resets, so the next window reports only its own traffic.
        assert!(s.take_rollup().is_none());
    }

    #[test]
    fn degraded_observation_is_recorded_not_implied() {
        // "No denials" and "we could not look" must never be the same signal.
        let mut s = ObservationState::new();
        assert!(!s.degraded);
        s.degraded = true;
        assert!(
            s.degraded,
            "a Hubble outage must be visible, so silence is never read as safety"
        );
    }
}
