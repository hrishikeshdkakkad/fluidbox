//! Self-observability for the logging subsystem.
//!
//! Logging that silently drops records is worse than logging that is merely
//! sparse: an operator reading a quiet log concludes the system is quiet. These
//! counters make every drop accountable, so "nothing happened" and "we stopped
//! telling you what happened" are distinguishable.
//!
//! Process-wide atomics, read by `fluidbox-server::metrics` at scrape time and
//! surfaced as `fluidbox_log_*` series. Deliberately not per-target: the point
//! is a health signal, and [`crate::throttle::report`] answers "which callsite"
//! with far more detail than a metric label ever could.

use std::sync::atomic::{AtomicU64, Ordering};

/// One process-wide instance. A `static` rather than a handle threaded through
/// the layer because the readers (`metrics::render`) are far from the writers
/// (the formatter) and threading it would put an `Arc` on a hot path to serve a
/// once-a-minute scrape.
pub static STATS: Stats = Stats::new();

#[derive(Debug)]
pub struct Stats {
    emitted: AtomicU64,
    suppressed: AtomicU64,
    redactions: AtomicU64,
    truncations: AtomicU64,
    write_errors: AtomicU64,
}

impl Stats {
    const fn new() -> Self {
        Self {
            emitted: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
            redactions: AtomicU64::new(0),
            truncations: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
        }
    }

    /// Records actually written to the sink.
    pub fn emitted(&self) -> u64 {
        self.emitted.load(Ordering::Relaxed)
    }
    /// Records dropped by the per-callsite rate limiter. Non-zero means the log
    /// is INCOMPLETE — pair it with [`crate::throttle::report`] to find out where.
    pub fn suppressed(&self) -> u64 {
        self.suppressed.load(Ordering::Relaxed)
    }
    /// Field values blanked or rewritten by the redactor. A steady non-zero rate
    /// is normal (upstream errors quote URLs); a SPIKE is worth a look, because
    /// it means something newly started carrying credential-shaped text into
    /// logs.
    pub fn redactions(&self) -> u64 {
        self.redactions.load(Ordering::Relaxed)
    }
    /// Values or lines cut at the configured ceiling.
    pub fn truncations(&self) -> u64 {
        self.truncations.load(Ordering::Relaxed)
    }
    /// Failed writes to the sink (a full disk, a closed pipe). Logging never
    /// propagates these — a broken log must not take the control plane down —
    /// so this counter is the only evidence they happened.
    pub fn write_errors(&self) -> u64 {
        self.write_errors.load(Ordering::Relaxed)
    }

    pub(crate) fn inc_emitted(&self) {
        self.emitted.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn inc_suppressed(&self) {
        self.suppressed.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn add_redactions(&self, n: u64) {
        if n > 0 {
            self.redactions.fetch_add(n, Ordering::Relaxed);
        }
    }
    pub(crate) fn inc_truncations(&self) {
        self.truncations.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn inc_write_errors(&self) {
        self.write_errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// A point-in-time copy, for rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub emitted: u64,
    pub suppressed: u64,
    pub redactions: u64,
    pub truncations: u64,
    pub write_errors: u64,
}

/// Read every counter at once.
pub fn snapshot() -> Snapshot {
    Snapshot {
        emitted: STATS.emitted(),
        suppressed: STATS.suppressed(),
        redactions: STATS.redactions(),
        truncations: STATS.truncations(),
        write_errors: STATS.write_errors(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate_and_snapshot_reads_them_together() {
        let s = Stats::new();
        s.inc_emitted();
        s.inc_emitted();
        s.add_redactions(3);
        s.add_redactions(0); // a zero must not cost an atomic op or a count
        assert_eq!(s.emitted(), 2);
        assert_eq!(s.redactions(), 3);
        assert_eq!(s.suppressed(), 0);
    }
}
