//! Latency measurement for the canonical wide event.
//!
//! # The pattern this supports
//!
//! One record per unit of work, emitted when the work FINISHES, carrying its
//! duration and its outcome:
//!
//! ```ignore
//! let sw = Stopwatch::start();
//! let r = do_the_thing().await;
//! match &r {
//!     Ok(_)  => info!(op = "workspace.fetch", outcome = field::outcome::OK,
//!                     duration_ms = sw.ms(), "workspace ready"),
//!     Err(e) => warn!(op = "workspace.fetch", outcome = field::outcome::ERROR,
//!                     error_kind = field::error_kind::UPSTREAM,
//!                     duration_ms = sw.ms(), error = %e, "workspace fetch failed"),
//! }
//! ```
//!
//! Two lines ("starting X" / "finished X") is the instinct and it is the wrong
//! one at scale: it doubles volume, and the two halves have to be correlated by
//! the reader anyway. One record at completion carries strictly more information
//! — you know it finished, how long it took, and how it ended — and the *span*
//! (which exists for the whole operation) is what tells you something is
//! currently in flight.
//!
//! # Why not a `Drop` guard
//!
//! A guard that logs on drop cannot know the outcome, logs on every early return
//! including `?` propagation, and fires during unwinding. Explicit measurement
//! at the point where the result is in hand is a few more characters and says
//! what actually happened.

use std::time::Instant;

/// A monotonic elapsed-time measurement.
///
/// Backed by [`Instant`], not the wall clock: an NTP step or a leap-second smear
/// mid-operation must not produce a negative or wildly wrong duration in a
/// latency histogram.
#[derive(Debug, Clone, Copy)]
pub struct Stopwatch(Instant);

impl Stopwatch {
    pub fn start() -> Self {
        Self(Instant::now())
    }

    /// Elapsed whole milliseconds.
    ///
    /// Saturating: a duration beyond `u64` milliseconds is ~584 million years,
    /// so this cannot round-trip wrong in practice, but the saturation means a
    /// clock anomaly yields a large number rather than a panic on a logging path.
    pub fn ms(&self) -> u64 {
        self.0.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }

    /// Elapsed milliseconds with sub-millisecond resolution, for operations
    /// fast enough that whole milliseconds quantise everything to 0 or 1 (the
    /// permission gate's in-memory stages, a cache hit).
    pub fn ms_f64(&self) -> f64 {
        self.0.elapsed().as_secs_f64() * 1000.0
    }

    pub fn elapsed(&self) -> std::time::Duration {
        self.0.elapsed()
    }
}

impl Default for Stopwatch {
    fn default() -> Self {
        Self::start()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_forward_and_never_goes_backwards() {
        let sw = Stopwatch::start();
        let a = sw.ms_f64();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = sw.ms_f64();
        assert!(b >= a, "monotonic");
        assert!(b >= 4.0, "measured {b}ms for a 5ms sleep");
        assert!(sw.ms() >= 4, "whole-ms accessor agrees: {}", sw.ms());
    }

    /// Sub-millisecond work must not all collapse to zero — that is the case the
    /// float accessor exists for.
    #[test]
    fn sub_millisecond_work_is_measurable() {
        let sw = Stopwatch::start();
        let mut acc = 0u64;
        for i in 0..1000 {
            acc = acc.wrapping_add(i);
        }
        std::hint::black_box(acc);
        assert!(sw.ms_f64() > 0.0, "sub-ms work measured as exactly zero");
    }
}
