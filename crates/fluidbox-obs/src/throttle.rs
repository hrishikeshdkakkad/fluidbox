//! Per-callsite rate limiting.
//!
//! # Why a log subsystem needs a governor
//!
//! The failure mode this prevents is specific and it has already happened in
//! this codebase's shape. Several loops here retry on a fixed tick and log on
//! every failure: the network-grant re-verification retries every ~2s, the
//! delivery worker backs off but the claim sweeper does not, the orchestrator's
//! `drive_finalization` re-enters per drive, and the reservation sweeper runs
//! every 10s. Point any one of them at a persistent fault — a revoked
//! credential, a dead upstream, a full disk — and it emits the same line
//! forever. Left ungoverned that fills the volume, prices a log-vendor bill by
//! the gigabyte, and buries the ONE line that explains the incident under a
//! million copies of its symptom.
//!
//! # The rule
//!
//! Each `tracing` callsite (a unique `file:line`, resolved once and `'static`)
//! gets a fixed-window budget of N records per second. Past the budget records
//! are dropped and counted. Nothing is silently lost:
//!
//! * [`crate::stats::STATS`] counts every suppression, so a dashboard shows the
//!   log itself is incomplete.
//! * [`report`] names the offending callsites and their counts, which the server
//!   emits periodically as a single WARN — one line per minute per flood instead
//!   of thousands.
//!
//! # Why levels are NOT exempt
//!
//! It is tempting to exempt ERROR. That gets it backwards: an error in a 2s
//! retry loop is precisely the flood this exists to stop, and it is also the
//! most likely one. Suppression is lossless in the sense that matters — the
//! COUNT survives and the callsite is named — so an operator still learns "this
//! error fired 40,000 times", which is more useful than 40,000 identical lines.
//! Setting the limit to 0 disables the whole mechanism for deployments that
//! would rather pay for the volume.
//!
//! # Cost
//!
//! One hash and one short lock per record, sharded 16 ways. That is strictly
//! less than the write it guards (a `write_all` to stdout takes a process-wide
//! lock), so the throttle cannot be the bottleneck.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Number of independent shards. Sized so that contention between the tokio
/// worker threads of a busy replica is negligible while the memory cost stays
/// trivial (a few hundred bytes plus one entry per live callsite).
const SHARDS: usize = 16;

/// Identity of a callsite, in the form an operator can act on. `tracing`'s own
/// `callsite::Identifier` is a stable pointer but says nothing readable, so the
/// key is the location plus the target — which is also exactly what [`report`]
/// needs to print.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CallsiteKey {
    pub target: &'static str,
    pub file: Option<&'static str>,
    pub line: Option<u32>,
}

#[derive(Debug, Default)]
struct Bucket {
    /// Unix second the current window began.
    window: u64,
    /// Records admitted in the current window.
    admitted: u32,
    /// Records dropped in the current window.
    dropped: u64,
    /// Records dropped since the last [`report`], across windows.
    dropped_since_report: u64,
}

/// A fixed-window, per-callsite limiter.
pub struct Throttle {
    /// Records per callsite per second. `0` disables the limiter entirely.
    limit: u32,
    shards: [Mutex<HashMap<CallsiteKey, Bucket>>; SHARDS],
    /// Total suppressions, mirrored here so [`report`] can decide cheaply
    /// whether there is anything to say without locking every shard.
    total_dropped: AtomicU64,
}

impl Throttle {
    pub fn new(limit_per_sec: u32) -> Self {
        Self {
            limit: limit_per_sec,
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            total_dropped: AtomicU64::new(0),
        }
    }

    /// Whether this record may be written. Returns `true` unconditionally when
    /// the limiter is disabled.
    pub fn admit(&self, key: CallsiteKey) -> bool {
        if self.limit == 0 {
            return true;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            // A clock before the epoch is not a reason to stop logging.
            .unwrap_or(0);
        let shard = &self.shards[shard_of(&key)];
        // A poisoned shard must not stop the process from logging — that would
        // turn a panic in one worker into blindness everywhere. Recover the
        // guard and carry on; the worst case is one skewed window.
        let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
        let b = map.entry(key).or_default();
        if b.window != now {
            b.window = now;
            b.admitted = 0;
            b.dropped = 0;
        }
        if b.admitted < self.limit {
            b.admitted += 1;
            true
        } else {
            b.dropped += 1;
            b.dropped_since_report += 1;
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
            crate::stats::STATS.inc_suppressed();
            false
        }
    }

    /// Drain the suppression counts accumulated since the last call, heaviest
    /// first. Empty when nothing was dropped — the caller then says nothing,
    /// which is the point: a healthy deployment never sees this line.
    pub fn report(&self) -> Vec<(CallsiteKey, u64)> {
        if self.total_dropped.load(Ordering::Relaxed) == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        for shard in &self.shards {
            let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
            for (k, b) in map.iter_mut() {
                if b.dropped_since_report > 0 {
                    out.push((*k, b.dropped_since_report));
                    b.dropped_since_report = 0;
                }
            }
        }
        self.total_dropped.store(0, Ordering::Relaxed);
        out.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        out
    }

    /// The configured per-second budget (`0` = disabled). Read by the boot
    /// banner so the effective setting is visible in the logs it governs.
    pub fn limit(&self) -> u32 {
        self.limit
    }
}

fn shard_of(key: &CallsiteKey) -> usize {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    (h.finish() as usize) % SHARDS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(line: u32) -> CallsiteKey {
        CallsiteKey {
            target: "test",
            file: Some("t.rs"),
            line: Some(line),
        }
    }

    #[test]
    fn admits_up_to_the_limit_then_drops() {
        let t = Throttle::new(3);
        let k = key(1);
        assert!(t.admit(k));
        assert!(t.admit(k));
        assert!(t.admit(k));
        assert!(!t.admit(k), "the 4th record in the window must be dropped");
        assert!(!t.admit(k));
    }

    /// The budget is PER CALLSITE: one chatty loop must not silence an unrelated
    /// module. This is the property that makes throttling safe to enable by
    /// default.
    #[test]
    fn one_flooding_callsite_does_not_silence_another() {
        let t = Throttle::new(1);
        let noisy = key(10);
        let quiet = key(20);
        assert!(t.admit(noisy));
        for _ in 0..100 {
            let _ = t.admit(noisy);
        }
        assert!(t.admit(quiet), "an unrelated callsite kept its own budget");
    }

    /// Nothing is silently lost: the drop count is recoverable and the report
    /// drains (so counts are not double-reported next minute).
    #[test]
    fn report_names_the_flood_and_then_drains() {
        let t = Throttle::new(1);
        let k = key(30);
        assert!(t.admit(k));
        for _ in 0..9 {
            assert!(!t.admit(k));
        }
        let r = t.report();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].0, k);
        assert_eq!(r[0].1, 9, "every suppressed record is accounted for");
        assert!(t.report().is_empty(), "a drained report does not repeat");
    }

    /// Heaviest first — an operator reading a truncated report sees the worst
    /// offender, not an arbitrary one.
    #[test]
    fn report_is_ordered_by_volume() {
        let t = Throttle::new(1);
        for (line, n) in [(1_u32, 5_usize), (2, 50), (3, 20)] {
            let k = key(line);
            assert!(t.admit(k));
            for _ in 0..n {
                let _ = t.admit(k);
            }
        }
        let r = t.report();
        assert_eq!(r[0].1, 50);
        assert_eq!(r[1].1, 20);
        assert_eq!(r[2].1, 5);
    }

    #[test]
    fn zero_disables_the_limiter_entirely() {
        let t = Throttle::new(0);
        let k = key(40);
        for _ in 0..10_000 {
            assert!(t.admit(k));
        }
        assert!(t.report().is_empty());
    }
}
