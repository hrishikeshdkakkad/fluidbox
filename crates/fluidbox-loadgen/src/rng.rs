//! A seeded, reproducible PRNG.
//!
//! Why hand-rolled rather than `rand`: the harness's contract is "a run is
//! reproducible from its `--seed`", and a dependency can change its generator
//! stream across a semver-compatible bump without breaking anything but that
//! contract. SplitMix64 is twenty lines, is the seeding routine the xoshiro
//! family itself uses, and is pinned here by a test that asserts the exact
//! first values for seed 0 — so a change to the stream is a test failure, not a
//! silent loss of replayability.
//!
//! SCOPE OF THE DETERMINISM CLAIM (stated here so no report over-claims it):
//! the seed governs WORKLOAD SHAPE — which tool a request asks for, which
//! session it targets, the order of a shuffled matrix. It does NOT govern
//! session ids, token plaintexts or wall-clock interleaving: ids must be fresh
//! per run (`api_tokens.token_sha256` is UNIQUE, so a byte-identical re-run
//! against the same database would fail to insert), and concurrency is
//! genuinely nondeterministic by design — that is what is being measured.

/// SplitMix64. `state` advances by the golden-ratio constant per draw.
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `[0, n)`. `n == 0` yields 0 (the only total answer); modulo
    /// bias is irrelevant at the cardinalities a load matrix uses (< 100).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next_u64() % n
    }

    /// Uniform pick. `None` for an empty slice — never a panic, because the
    /// caller's slice is built from CLI input.
    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> Option<&'a T> {
        if xs.is_empty() {
            return None;
        }
        xs.get(self.below(xs.len() as u64) as usize)
    }

    /// Fisher-Yates, so a failure matrix can be run in a seed-determined order
    /// (arm ordering matters when arms have side effects on shared state).
    pub fn shuffle<T>(&mut self, xs: &mut [T]) {
        if xs.len() < 2 {
            return;
        }
        for i in (1..xs.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            xs.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stream is PINNED, not merely "deterministic within one build". These
    /// are the first three SplitMix64 draws for seed 0; if the algorithm is ever
    /// swapped, every recorded `--seed` in a past report stops meaning what it
    /// meant, so that change must be deliberate enough to edit this test.
    #[test]
    fn the_stream_is_pinned_for_a_known_seed() {
        let mut r = Rng::new(0);
        assert_eq!(r.next_u64(), 16294208416658607535);
        assert_eq!(r.next_u64(), 7960286522194355700);
        assert_eq!(r.next_u64(), 487617019471545679);
    }

    #[test]
    fn the_same_seed_replays_and_a_different_seed_diverges() {
        let draw = |seed| {
            let mut r = Rng::new(seed);
            (0..16).map(|_| r.next_u64()).collect::<Vec<_>>()
        };
        assert_eq!(draw(42), draw(42), "the same seed must replay exactly");
        assert_ne!(draw(42), draw(43));
    }

    #[test]
    fn below_stays_in_range_and_zero_is_total() {
        let mut r = Rng::new(7);
        for _ in 0..2000 {
            assert!(r.below(5) < 5);
        }
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn pick_is_none_only_for_an_empty_slice() {
        let mut r = Rng::new(1);
        let empty: [u8; 0] = [];
        assert!(r.pick(&empty).is_none());
        let xs = [1u8, 2, 3];
        for _ in 0..100 {
            assert!(xs.contains(r.pick(&xs).expect("non-empty slice always picks")));
        }
    }

    #[test]
    fn shuffle_is_a_permutation_and_is_seed_determined() {
        let permute = |seed| {
            let mut r = Rng::new(seed);
            let mut xs: Vec<u32> = (0..32).collect();
            r.shuffle(&mut xs);
            xs
        };
        let a = permute(9);
        assert_eq!(a, permute(9), "same seed ⇒ same order");
        let mut sorted = a.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            (0..32).collect::<Vec<u32>>(),
            "must be a permutation"
        );
        assert_ne!(a, (0..32).collect::<Vec<u32>>(), "…and not the identity");
    }
}
