//! Outbound egress governor (Phase E, #33; plan E14) — the last two unbuilt
//! controls on the design's broker-egress list (design :836-861): "rate-limit per
//! tenant, user, connection, and upstream host" and "circuit-break unhealthy
//! upstreams".
//!
//! # Shape
//!
//! Three INDEPENDENT token buckets are consulted per dial — per tenant, per
//! connection, per upstream host — and a per-connection circuit breaker rides on
//! top. A refusal happens strictly BEFORE any request bytes are written, so the
//! broker maps it to `DispatchOutcome::NeverSent` ⇒ execution-claim state
//! `failed_before_send` ⇒ re-claimable, which is what makes the retry-after hint
//! we hand the caller safe to act on.
//!
//! # Per-replica, by design (disclosed limitation)
//!
//! ALL state here is in-memory and REPLICA-LOCAL. With N replicas the effective
//! ceiling is N × the configured rate and a breaker opened on one replica does
//! not stop the others. This is a deliberate v1 scope call (plan E14, following
//! the `llm_keys` per-replica mint-budget precedent): it is a fairness/abuse
//! backstop and an upstream-protection reflex, NOT a hard quota. The durable,
//! multi-replica limiter is Phase F.
//!
//! # Bounded memory (this matters)
//!
//! Every map is capped at [`MAX_TRACKED`] entries with LRU eviction, preferring
//! entries whose state carries no information (a full bucket, a clean breaker).
//! Without the cap the per-host map would be a memory-growth vector under hostile
//! input: one connection can name arbitrarily many upstream hosts across a run's
//! calls, and each would mint a permanent map entry. Eviction is safe by
//! construction — a re-created bucket starts full, so the worst case is that an
//! attacker who can cycle 4096 distinct hosts evades the HOST dimension; the
//! tenant and connection dimensions key on ids they cannot cycle and still bind.
//!
//! # Time
//!
//! The clock is injected ([`Clock`]) so every timing test drives it explicitly —
//! no test in this module or in `broker.rs` ever sleeps.

use crate::config::Config;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use uuid::Uuid;

/// Which dimension refused the dial (rides in the refusal message, and in the
/// `Throttled` a caller inspects).
pub const SCOPE_TENANT: &str = "tenant";
pub const SCOPE_CONNECTION: &str = "connection";
pub const SCOPE_HOST: &str = "host";
pub const SCOPE_BREAKER: &str = "breaker";

/// Per-minute dial ceilings. A tenant's whole org shares `TENANT`; one connection
/// (one credential, one upstream) gets `CONNECTION`; one upstream host gets
/// `HOST` across every connection pointed at it. Env-overridable — see
/// [`GovernorLimits::from_config`].
pub const DEFAULT_TENANT_PER_MIN: u32 = 120;
pub const DEFAULT_CONNECTION_PER_MIN: u32 = 60;
pub const DEFAULT_HOST_PER_MIN: u32 = 120;
/// Consecutive transport/5xx failures that open a connection's breaker.
pub const DEFAULT_BREAKER_THRESHOLD: u32 = 5;
/// How long an open breaker refuses before admitting one half-open probe.
pub const DEFAULT_BREAKER_OPEN_SECS: u64 = 60;

/// Per-map entry ceiling (see the module docs on bounded memory).
pub const MAX_TRACKED: usize = 4096;

/// Token-bucket unit scale: one dial costs `UNIT` units and a bucket refills
/// `per_min` units per elapsed millisecond, so a `per_min`-rate bucket regains a
/// whole token in `60_000 / per_min` ms. All-integer math — no float drift, and
/// the refill is a MONOTONIC function of elapsed time rather than a fixed window
/// (a fixed window, like the `login.rs` per-IP counter, admits `2 × limit` across
/// a window boundary; a bucket cannot).
const UNIT: u64 = 60_000;

/// The tunable ceilings, resolved once at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernorLimits {
    pub tenant_per_min: u32,
    pub connection_per_min: u32,
    pub host_per_min: u32,
    pub breaker_threshold: u32,
    pub breaker_open_secs: u64,
}

impl Default for GovernorLimits {
    fn default() -> Self {
        GovernorLimits {
            tenant_per_min: DEFAULT_TENANT_PER_MIN,
            connection_per_min: DEFAULT_CONNECTION_PER_MIN,
            host_per_min: DEFAULT_HOST_PER_MIN,
            breaker_threshold: DEFAULT_BREAKER_THRESHOLD,
            breaker_open_secs: DEFAULT_BREAKER_OPEN_SECS,
        }
    }
}

impl GovernorLimits {
    /// Boot-resolved limits. `config.rs` already failed boot on a malformed
    /// value, so every field here is a parsed number.
    ///
    /// **Zero means DISABLED**, per dimension — never "block everything". An
    /// operator who zeroes a limit means "do not rate-limit this"; a limiter that
    /// answered a typo'd `0` by refusing every outbound dial would be a
    /// self-inflicted outage, and the fail-closed direction we actually care
    /// about (credentials, tenancy, admission) is enforced elsewhere. The same
    /// rule applies to both breaker knobs: `THRESHOLD=0` or `OPEN_SECS=0`
    /// disables the breaker (a zero-length open window is not a breaker).
    pub fn from_config(cfg: &Config) -> Self {
        GovernorLimits {
            tenant_per_min: cfg.egress_rate_tenant_per_min,
            connection_per_min: cfg.egress_rate_connection_per_min,
            host_per_min: cfg.egress_rate_host_per_min,
            breaker_threshold: cfg.egress_breaker_threshold,
            breaker_open_secs: cfg.egress_breaker_open_secs,
        }
    }

    fn breaker_enabled(&self) -> bool {
        self.breaker_threshold > 0 && self.breaker_open_secs > 0
    }
}

/// A pre-dial refusal: which dimension said no, and how long the caller should
/// wait. Never carries the upstream host — see [`Throttled::message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Throttled {
    pub scope: &'static str,
    pub retry_after_secs: u64,
}

impl Throttled {
    /// The runner-facing refusal text. `host_digest` MUST be a digest
    /// (`broker::msg_digest`) — the raw upstream host never leaves the broker in
    /// an error string, matching the discipline already applied to untrusted
    /// upstream error messages.
    pub fn message(&self, host_digest: &str) -> String {
        if self.scope == SCOPE_BREAKER {
            format!(
                "upstream circuit breaker open after repeated transport failures \
                 (scope {}, upstream {host_digest}) — retry after {}s",
                self.scope, self.retry_after_secs
            )
        } else {
            format!(
                "outbound rate limit reached (scope {}, upstream {host_digest}) — retry after {}s",
                self.scope, self.retry_after_secs
            )
        }
    }
}

/// What one dispatch observed about the upstream's HEALTH — the breaker's only
/// input. See `broker::breaker_signal` for the authoritative classification: a
/// definitive upstream tool error (JSON-RPC error, `isError`, 4xx) is
/// [`Outcome::Ok`] because the upstream is demonstrably alive and answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    TransportFailure,
}

/// Monotonic millisecond clock. `Real` reads the process monotonic clock;
/// `Manual` is driven explicitly by tests so bucket refill and breaker windows
/// are deterministic without a single sleep.
enum Clock {
    Real(Instant),
    #[cfg_attr(not(test), allow(dead_code))]
    Manual(AtomicU64),
}

impl Clock {
    fn now_ms(&self) -> u64 {
        match self {
            Clock::Real(base) => u64::try_from(base.elapsed().as_millis()).unwrap_or(u64::MAX),
            Clock::Manual(ms) => ms.load(Ordering::SeqCst),
        }
    }
}

/// One dimension's token bucket.
struct Bucket {
    units: u64,
    last_ms: u64,
}

fn capacity(per_min: u32) -> u64 {
    u64::from(per_min).saturating_mul(UNIT)
}

impl Bucket {
    fn new(per_min: u32, now_ms: u64) -> Self {
        Bucket {
            units: capacity(per_min),
            last_ms: now_ms,
        }
    }

    /// Add the tokens elapsed time has earned, capped at capacity.
    fn refill(&mut self, per_min: u32, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.last_ms);
        self.last_ms = now_ms;
        if elapsed == 0 {
            return;
        }
        self.units = self
            .units
            .saturating_add(elapsed.saturating_mul(u64::from(per_min)))
            .min(capacity(per_min));
    }

    fn has_token(&self) -> bool {
        self.units >= UNIT
    }

    fn take(&mut self) {
        self.units = self.units.saturating_sub(UNIT);
    }

    /// Seconds until this bucket holds a whole token again (≥1 when throttled).
    fn retry_after_secs(&self, per_min: u32) -> u64 {
        let missing = UNIT.saturating_sub(self.units);
        if missing == 0 || per_min == 0 {
            return 0;
        }
        missing.div_ceil(u64::from(per_min)).div_ceil(1000).max(1)
    }

    /// A full bucket is indistinguishable from a freshly created one, so it is
    /// the preferred eviction victim.
    fn is_full(&self, per_min: u32) -> bool {
        self.units >= capacity(per_min)
    }
}

/// Per-connection breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BreakerState {
    /// Healthy; `failures` counts CONSECUTIVE transport/5xx failures (any
    /// healthy answer resets it to 0).
    Closed { failures: u32 },
    /// Refusing every dial until `breaker_open_secs` after `opened_ms`.
    Open { opened_ms: u64 },
    /// Exactly ONE probe is in flight, admitted at `probe_ms`; every other caller
    /// is refused. `probe_ms` also bounds a LOST probe: if no outcome is reported
    /// within one open window the next caller becomes the new probe, so a caller
    /// that dies between the gate and its report cannot wedge the breaker shut.
    HalfOpen { probe_ms: u64 },
}

struct Breaker {
    state: BreakerState,
}

impl Breaker {
    fn clean(&self) -> bool {
        matches!(self.state, BreakerState::Closed { failures: 0 })
    }
}

/// A bounded, LRU-evicting map. `used` is a monotonic access sequence, so a
/// touch is O(1) and only an eviction pays an O(n) scan.
struct Bounded<K, V> {
    map: HashMap<K, Slot<V>>,
    seq: u64,
}

struct Slot<V> {
    used: u64,
    value: V,
}

impl<K: Eq + Hash + Clone, V> Bounded<K, V> {
    fn new() -> Self {
        Bounded {
            map: HashMap::new(),
            seq: 0,
        }
    }

    /// Borrow (creating on a miss) the entry for `key`, marking it most-recently
    /// used. `forgettable` identifies entries whose removal loses no information
    /// — they are evicted first, so an OPEN breaker or a partially drained bucket
    /// survives an eviction storm ahead of idle ones.
    fn entry(
        &mut self,
        key: &K,
        make: impl FnOnce() -> V,
        forgettable: impl Fn(&V) -> bool,
    ) -> &mut V {
        self.seq += 1;
        let seq = self.seq;
        if self.map.len() >= MAX_TRACKED && !self.map.contains_key(key) {
            self.evict_one(&forgettable);
        }
        let slot = self.map.entry(key.clone()).or_insert_with(|| Slot {
            used: seq,
            value: make(),
        });
        slot.used = seq;
        &mut slot.value
    }

    fn evict_one(&mut self, forgettable: &impl Fn(&V) -> bool) {
        let victim = self
            .map
            .iter()
            .filter(|(_, s)| forgettable(&s.value))
            .min_by_key(|(_, s)| s.used)
            .map(|(k, _)| k.clone())
            // Nothing forgettable: bounded memory still wins — drop the
            // least-recently-used entry outright.
            .or_else(|| {
                self.map
                    .iter()
                    .min_by_key(|(_, s)| s.used)
                    .map(|(k, _)| k.clone())
            });
        if let Some(k) = victim {
            self.map.remove(&k);
        }
    }

    /// Entry count — the bounded-memory assertion's only observation point.
    #[cfg_attr(not(test), allow(dead_code))]
    fn len(&self) -> usize {
        self.map.len()
    }
}

struct GovState {
    tenants: Bounded<Uuid, Bucket>,
    connections: Bounded<Uuid, Bucket>,
    hosts: Bounded<String, Bucket>,
    /// Keyed `(connection, host)` — strictly FINER than per-connection (which is
    /// why `report` takes the host too). A connection normally has exactly one
    /// upstream, so this is per-connection in practice; the refinement matters
    /// for the legacy credential-free bundle path, where there is no connection
    /// id at all (`Uuid::nil()`) and only the host distinguishes upstreams.
    breakers: Bounded<(Uuid, String), Breaker>,
}

/// The in-memory, per-replica outbound governor held on `AppState`.
pub struct EgressGovernor {
    limits: GovernorLimits,
    clock: Clock,
    state: Mutex<GovState>,
}

impl EgressGovernor {
    pub fn new(limits: GovernorLimits) -> Self {
        EgressGovernor {
            limits,
            clock: Clock::Real(Instant::now()),
            state: Mutex::new(GovState {
                tenants: Bounded::new(),
                connections: Bounded::new(),
                hosts: Bounded::new(),
                breakers: Bounded::new(),
            }),
        }
    }

    pub fn from_config(cfg: &Config) -> Self {
        Self::new(GovernorLimits::from_config(cfg))
    }

    pub fn limits(&self) -> GovernorLimits {
        self.limits
    }

    /// Admit (or refuse) ONE outbound brokered dial.
    ///
    /// Evaluation order, and why:
    /// 1. **Buckets first, all-or-nothing.** All three dimensions are peeked
    ///    before any token is consumed, so a call refused by the connection
    ///    dimension does not burn its tenant's or its host's budget. Precedence
    ///    on refusal is tenant → connection → host.
    /// 2. **Breaker second.** Consulting it is a state transition (an open
    ///    breaker past its window promotes THIS caller to the half-open probe),
    ///    so it must not run for a call the buckets already refused — that would
    ///    spend the single probe slot on a dial that never happens.
    ///
    /// A poisoned lock is recovered rather than propagated: the governor is an
    /// availability control, and failing every brokered dial because one caller
    /// panicked mid-update would be a worse outcome than a slightly stale bucket.
    pub fn check(&self, tenant: Uuid, connection: Uuid, host: &str) -> Result<(), Throttled> {
        let now = self.clock.now_ms();
        let st = &mut *self.lock();
        let l = self.limits;
        // 1. Peek every dimension (refilling as it goes) WITHOUT consuming.
        for (scope, retry) in [
            (
                SCOPE_TENANT,
                peek(&mut st.tenants, &tenant, l.tenant_per_min, now),
            ),
            (
                SCOPE_CONNECTION,
                peek(&mut st.connections, &connection, l.connection_per_min, now),
            ),
            (
                SCOPE_HOST,
                peek(&mut st.hosts, &host.to_string(), l.host_per_min, now),
            ),
        ] {
            if let Some(retry_after_secs) = retry {
                return Err(Throttled {
                    scope,
                    retry_after_secs,
                });
            }
        }
        // 2. Breaker (may promote this caller to the half-open probe).
        if let Some(t) = self.check_breaker(st, connection, host, now) {
            return Err(t);
        }
        // 3. Everyone said yes — consume one token from each enabled dimension.
        take(&mut st.tenants, &tenant, l.tenant_per_min, now);
        take(&mut st.connections, &connection, l.connection_per_min, now);
        take(&mut st.hosts, &host.to_string(), l.host_per_min, now);
        Ok(())
    }

    /// Feed one dispatch's health observation back into the connection's breaker.
    /// Consecutive means consecutive: any [`Outcome::Ok`] resets the count.
    pub fn report(&self, connection: Uuid, host: &str, outcome: Outcome) {
        if !self.limits.breaker_enabled() {
            return;
        }
        let now = self.clock.now_ms();
        let threshold = self.limits.breaker_threshold;
        let st = &mut *self.lock();
        let br = breaker_entry(st, connection, host);
        br.state = match (br.state, outcome) {
            (BreakerState::Closed { failures }, Outcome::TransportFailure) => {
                let n = failures.saturating_add(1);
                if n >= threshold {
                    BreakerState::Open { opened_ms: now }
                } else {
                    BreakerState::Closed { failures: n }
                }
            }
            (BreakerState::Closed { .. }, Outcome::Ok) => BreakerState::Closed { failures: 0 },
            // The probe answered: success closes and fully resets; failure opens
            // a FRESH window (never a shorter one).
            (BreakerState::HalfOpen { .. }, Outcome::Ok) => BreakerState::Closed { failures: 0 },
            (BreakerState::HalfOpen { .. }, Outcome::TransportFailure) => {
                BreakerState::Open { opened_ms: now }
            }
            // A straggler from a dial admitted before the breaker opened. It says
            // nothing about the open window's premise, so the window stands —
            // only a half-open PROBE can close a breaker.
            (open @ BreakerState::Open { .. }, _) => open,
        };
    }

    fn check_breaker(
        &self,
        st: &mut GovState,
        connection: Uuid,
        host: &str,
        now: u64,
    ) -> Option<Throttled> {
        if !self.limits.breaker_enabled() {
            return None;
        }
        let open_ms = self.limits.breaker_open_secs.saturating_mul(1000);
        let br = breaker_entry(st, connection, host);
        match br.state {
            BreakerState::Closed { .. } => None,
            BreakerState::Open { opened_ms } => {
                let elapsed = now.saturating_sub(opened_ms);
                if elapsed >= open_ms {
                    br.state = BreakerState::HalfOpen { probe_ms: now };
                    None
                } else {
                    Some(breaker_refusal(open_ms - elapsed))
                }
            }
            BreakerState::HalfOpen { probe_ms } => {
                let elapsed = now.saturating_sub(probe_ms);
                if elapsed >= open_ms {
                    // The in-flight probe never reported (a caller died between
                    // the gate and its report) — take over as the new probe.
                    br.state = BreakerState::HalfOpen { probe_ms: now };
                    None
                } else {
                    Some(breaker_refusal(open_ms - elapsed))
                }
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GovState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Test-only manual clock (never compiled into the server binary).
    #[cfg(test)]
    pub fn manual(limits: GovernorLimits) -> Self {
        EgressGovernor {
            limits,
            clock: Clock::Manual(AtomicU64::new(0)),
            state: Mutex::new(GovState {
                tenants: Bounded::new(),
                connections: Bounded::new(),
                hosts: Bounded::new(),
                breakers: Bounded::new(),
            }),
        }
    }

    #[cfg(test)]
    pub fn advance_ms(&self, ms: u64) {
        match &self.clock {
            Clock::Manual(c) => {
                c.fetch_add(ms, Ordering::SeqCst);
            }
            Clock::Real(_) => panic!("advance_ms on a real clock"),
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> (usize, usize, usize, usize) {
        let st = self.lock();
        (
            st.tenants.len(),
            st.connections.len(),
            st.hosts.len(),
            st.breakers.len(),
        )
    }
}

fn breaker_refusal(remaining_ms: u64) -> Throttled {
    Throttled {
        scope: SCOPE_BREAKER,
        retry_after_secs: remaining_ms.div_ceil(1000).max(1),
    }
}

fn breaker_entry<'a>(st: &'a mut GovState, connection: Uuid, host: &str) -> &'a mut Breaker {
    st.breakers.entry(
        &(connection, host.to_string()),
        || Breaker {
            state: BreakerState::Closed { failures: 0 },
        },
        Breaker::clean,
    )
}

/// Refill one dimension's bucket and report whether a token is available.
/// `None` = available (or the dimension is DISABLED via `per_min == 0`);
/// `Some(secs)` = throttled, with the retry hint.
fn peek<K: Eq + Hash + Clone>(
    b: &mut Bounded<K, Bucket>,
    key: &K,
    per_min: u32,
    now: u64,
) -> Option<u64> {
    if per_min == 0 {
        return None;
    }
    let bucket = b.entry(key, || Bucket::new(per_min, now), |bk| bk.is_full(per_min));
    bucket.refill(per_min, now);
    if bucket.has_token() {
        None
    } else {
        Some(bucket.retry_after_secs(per_min))
    }
}

/// Consume one token. Only ever called after [`peek`] said yes for EVERY
/// dimension, so it cannot leave a partial charge behind.
fn take<K: Eq + Hash + Clone>(b: &mut Bounded<K, Bucket>, key: &K, per_min: u32, now: u64) {
    if per_min == 0 {
        return;
    }
    b.entry(key, || Bucket::new(per_min, now), |bk| bk.is_full(per_min))
        .take();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(tenant: u32, conn: u32, host: u32) -> GovernorLimits {
        GovernorLimits {
            tenant_per_min: tenant,
            connection_per_min: conn,
            host_per_min: host,
            // Breaker OFF unless a test is about the breaker, so a rate test can
            // never accidentally be measuring the breaker.
            breaker_threshold: 0,
            breaker_open_secs: 0,
        }
    }

    fn breaker_limits(threshold: u32, open_secs: u64) -> GovernorLimits {
        GovernorLimits {
            // Rate dimensions OFF so a breaker test measures only the breaker.
            tenant_per_min: 0,
            connection_per_min: 0,
            host_per_min: 0,
            breaker_threshold: threshold,
            breaker_open_secs: open_secs,
        }
    }

    // ── Token buckets ───────────────────────────────────────────────────────

    #[test]
    fn bucket_starts_full_refills_monotonically_and_caps_at_capacity() {
        // Capacity 6/min ⇒ one token per 10s. Only the connection dimension is
        // enabled so the arithmetic under test is unambiguous.
        let g = EgressGovernor::manual(limits(0, 6, 0));
        let (t, c, h) = (Uuid::new_v4(), Uuid::new_v4(), "mcp.example.test");
        // A fresh bucket starts FULL: 6 dials pass back-to-back at t=0.
        for i in 0..6 {
            assert!(g.check(t, c, h).is_ok(), "dial {i} must pass a full bucket");
        }
        // The 7th is refused, and the hint is the ~10s a token takes to earn.
        let e = g.check(t, c, h).expect_err("bucket exhausted");
        assert_eq!(e.scope, SCOPE_CONNECTION);
        assert_eq!(e.retry_after_secs, 10);

        // PARTIAL refill: 10s buys exactly one token, not two.
        g.advance_ms(10_000);
        assert!(g.check(t, c, h).is_ok(), "10s must earn one token");
        assert!(
            g.check(t, c, h).is_err(),
            "10s must earn ONE token, not more"
        );

        // CAP: an hour of idleness cannot bank more than capacity.
        g.advance_ms(3_600_000);
        for i in 0..6 {
            assert!(g.check(t, c, h).is_ok(), "banked dial {i}");
        }
        assert!(
            g.check(t, c, h).is_err(),
            "an idle bucket must cap at capacity, not bank unboundedly"
        );
    }

    #[test]
    fn retry_hint_shrinks_as_the_bucket_refills() {
        // 2/min ⇒ 30s per token. Exhaust, then watch the hint shrink.
        let g = EgressGovernor::manual(limits(0, 2, 0));
        let (t, c, h) = (Uuid::new_v4(), Uuid::new_v4(), "h");
        assert!(g.check(t, c, h).is_ok());
        assert!(g.check(t, c, h).is_ok());
        assert_eq!(g.check(t, c, h).unwrap_err().retry_after_secs, 30);
        g.advance_ms(20_000);
        assert_eq!(g.check(t, c, h).unwrap_err().retry_after_secs, 10);
        g.advance_ms(10_000);
        assert!(g.check(t, c, h).is_ok());
    }

    #[test]
    fn the_three_dimensions_are_independent() {
        // Tenant 100 (roomy), connection 2, host 100: exhausting ONE connection
        // must not touch a sibling connection under the same tenant.
        let g = EgressGovernor::manual(limits(100, 2, 100));
        let t = Uuid::new_v4();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(g.check(t, a, "h1").is_ok());
        assert!(g.check(t, a, "h1").is_ok());
        let e = g.check(t, a, "h1").expect_err("connection a is exhausted");
        assert_eq!(e.scope, SCOPE_CONNECTION);
        assert!(
            g.check(t, b, "h1").is_ok(),
            "connection b must be unaffected by a's exhaustion"
        );
    }

    #[test]
    fn tenant_exhaustion_throttles_every_connection_it_owns() {
        // Tenant 2, connection/host roomy: the tenant ceiling binds across
        // DIFFERENT connections and hosts …
        let g = EgressGovernor::manual(limits(2, 100, 100));
        let t = Uuid::new_v4();
        assert!(g.check(t, Uuid::new_v4(), "h1").is_ok());
        assert!(g.check(t, Uuid::new_v4(), "h2").is_ok());
        let e = g
            .check(t, Uuid::new_v4(), "h3")
            .expect_err("the tenant ceiling binds across its connections");
        assert_eq!(e.scope, SCOPE_TENANT);
        // … and only for THAT tenant.
        assert!(g.check(Uuid::new_v4(), Uuid::new_v4(), "h1").is_ok());
    }

    #[test]
    fn host_dimension_binds_across_connections_and_tenants() {
        let g = EgressGovernor::manual(limits(100, 100, 2));
        assert!(g
            .check(Uuid::new_v4(), Uuid::new_v4(), "shared.test")
            .is_ok());
        assert!(g
            .check(Uuid::new_v4(), Uuid::new_v4(), "shared.test")
            .is_ok());
        let e = g
            .check(Uuid::new_v4(), Uuid::new_v4(), "shared.test")
            .expect_err("the host ceiling is shared by every caller");
        assert_eq!(e.scope, SCOPE_HOST);
        // A different host is untouched.
        assert!(g
            .check(Uuid::new_v4(), Uuid::new_v4(), "other.test")
            .is_ok());
    }

    #[test]
    fn a_refused_dial_does_not_charge_the_other_dimensions() {
        // Connection 1, tenant 10: the connection refuses the 2nd dial, so the
        // TENANT must still have 9 tokens for its other connections.
        let g = EgressGovernor::manual(limits(10, 1, 0));
        let t = Uuid::new_v4();
        let a = Uuid::new_v4();
        assert!(g.check(t, a, "h").is_ok());
        for _ in 0..5 {
            assert_eq!(
                g.check(t, a, "h").unwrap_err().scope,
                SCOPE_CONNECTION,
                "connection a stays refused"
            );
        }
        // 9 tenant tokens must remain (1 spent, 5 refusals charged nothing).
        for i in 0..9 {
            assert!(
                g.check(t, Uuid::new_v4(), "h").is_ok(),
                "sibling dial {i} must find the tenant budget unspent"
            );
        }
        assert_eq!(
            g.check(t, Uuid::new_v4(), "h").unwrap_err().scope,
            SCOPE_TENANT
        );
    }

    #[test]
    fn zero_disables_a_dimension_rather_than_blocking_everything() {
        // Every dimension zero ⇒ the governor admits everything.
        let g = EgressGovernor::manual(limits(0, 0, 0));
        let (t, c) = (Uuid::new_v4(), Uuid::new_v4());
        for _ in 0..1000 {
            assert!(
                g.check(t, c, "h").is_ok(),
                "0 must mean disabled, not 0/min"
            );
        }
        // A zeroed dimension alongside an enforced one leaves the other enforced.
        let g = EgressGovernor::manual(limits(0, 1, 0));
        assert!(g.check(t, c, "h").is_ok());
        assert_eq!(
            g.check(t, c, "h").unwrap_err().scope,
            SCOPE_CONNECTION,
            "zeroing tenant/host must not disable the connection dimension"
        );
    }

    // ── Circuit breaker ─────────────────────────────────────────────────────

    #[test]
    fn consecutive_means_consecutive() {
        // Threshold 5: four failures then a SUCCESS resets the count, so the next
        // four failures must not open it either.
        let g = EgressGovernor::manual(breaker_limits(5, 60));
        let (t, c, h) = (Uuid::new_v4(), Uuid::new_v4(), "h");
        for _ in 0..4 {
            assert!(g.check(t, c, h).is_ok());
            g.report(c, h, Outcome::TransportFailure);
        }
        assert!(g.check(t, c, h).is_ok(), "4 < threshold — still closed");
        g.report(c, h, Outcome::Ok);
        for _ in 0..4 {
            assert!(
                g.check(t, c, h).is_ok(),
                "the success reset the consecutive count"
            );
            g.report(c, h, Outcome::TransportFailure);
        }
        assert!(
            g.check(t, c, h).is_ok(),
            "still 4 consecutive, still closed"
        );
        g.report(c, h, Outcome::TransportFailure);
        assert_eq!(
            g.check(t, c, h).unwrap_err().scope,
            SCOPE_BREAKER,
            "the 5th consecutive failure must open the breaker"
        );
    }

    #[test]
    fn open_breaker_refuses_then_admits_exactly_one_half_open_probe() {
        let g = EgressGovernor::manual(breaker_limits(3, 60));
        let (t, c, h) = (Uuid::new_v4(), Uuid::new_v4(), "h");
        for _ in 0..3 {
            assert!(g.check(t, c, h).is_ok());
            g.report(c, h, Outcome::TransportFailure);
        }
        // Open: refused, with a retry hint that shrinks with the window.
        let e = g.check(t, c, h).expect_err("breaker is open");
        assert_eq!(e.scope, SCOPE_BREAKER);
        assert_eq!(e.retry_after_secs, 60);
        g.advance_ms(30_000);
        assert_eq!(g.check(t, c, h).unwrap_err().retry_after_secs, 30);
        // Still open one millisecond short of the window.
        g.advance_ms(29_999);
        assert!(g.check(t, c, h).is_err(), "the window is not over yet");

        // At the window: EXACTLY ONE caller is admitted as the probe.
        g.advance_ms(1);
        assert!(
            g.check(t, c, h).is_ok(),
            "the first caller becomes the probe"
        );
        for i in 0..5 {
            assert_eq!(
                g.check(t, c, h).unwrap_err().scope,
                SCOPE_BREAKER,
                "half-open must admit ONE probe, not {}",
                i + 2
            );
        }
    }

    #[test]
    fn half_open_probe_success_closes_and_resets_the_count() {
        let g = EgressGovernor::manual(breaker_limits(3, 60));
        let (t, c, h) = (Uuid::new_v4(), Uuid::new_v4(), "h");
        for _ in 0..3 {
            let _ = g.check(t, c, h);
            g.report(c, h, Outcome::TransportFailure);
        }
        g.advance_ms(60_000);
        assert!(g.check(t, c, h).is_ok(), "probe admitted");
        g.report(c, h, Outcome::Ok);
        // Closed AND reset: two fresh failures must not re-open it (that would
        // prove the pre-open count survived).
        assert!(g.check(t, c, h).is_ok());
        g.report(c, h, Outcome::TransportFailure);
        assert!(g.check(t, c, h).is_ok());
        g.report(c, h, Outcome::TransportFailure);
        assert!(
            g.check(t, c, h).is_ok(),
            "a closing probe must reset the consecutive count to zero"
        );
    }

    #[test]
    fn half_open_probe_failure_reopens_a_full_fresh_window() {
        let g = EgressGovernor::manual(breaker_limits(3, 60));
        let (t, c, h) = (Uuid::new_v4(), Uuid::new_v4(), "h");
        for _ in 0..3 {
            let _ = g.check(t, c, h);
            g.report(c, h, Outcome::TransportFailure);
        }
        g.advance_ms(60_000);
        assert!(g.check(t, c, h).is_ok(), "probe admitted");
        g.report(c, h, Outcome::TransportFailure);
        // A FULL window, measured from the probe's failure — not the leftover of
        // the previous one.
        assert_eq!(g.check(t, c, h).unwrap_err().retry_after_secs, 60);
        g.advance_ms(59_999);
        assert!(
            g.check(t, c, h).is_err(),
            "the fresh window is still running"
        );
        g.advance_ms(1);
        assert!(
            g.check(t, c, h).is_ok(),
            "a second probe after a full window"
        );
    }

    #[test]
    fn a_lost_probe_cannot_wedge_the_breaker_shut_forever() {
        // A caller that dies between the gate and its report leaves the breaker
        // half-open with a probe that never lands. One window later the next
        // caller takes over as the probe.
        let g = EgressGovernor::manual(breaker_limits(2, 30));
        let (t, c, h) = (Uuid::new_v4(), Uuid::new_v4(), "h");
        for _ in 0..2 {
            let _ = g.check(t, c, h);
            g.report(c, h, Outcome::TransportFailure);
        }
        g.advance_ms(30_000);
        assert!(g.check(t, c, h).is_ok(), "probe admitted (and then lost)");
        g.advance_ms(29_999);
        assert!(
            g.check(t, c, h).is_err(),
            "the probe is still considered live"
        );
        g.advance_ms(1);
        assert!(g.check(t, c, h).is_ok(), "a lost probe must not wedge shut");
    }

    #[test]
    fn breaker_state_never_leaks_across_connections_or_hosts() {
        let g = EgressGovernor::manual(breaker_limits(2, 60));
        let t = Uuid::new_v4();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        for _ in 0..2 {
            let _ = g.check(t, a, "h1");
            g.report(a, "h1", Outcome::TransportFailure);
        }
        assert!(g.check(t, a, "h1").is_err(), "a/h1 is open");
        assert!(
            g.check(t, b, "h1").is_ok(),
            "a sibling connection is unharmed"
        );
        assert!(
            g.check(t, a, "h2").is_ok(),
            "the same connection on a different upstream is unharmed"
        );
    }

    #[test]
    fn a_straggler_success_cannot_close_an_open_breaker() {
        // Only a half-open PROBE closes a breaker. A success reported by a dial
        // that was admitted before the breaker opened must not cancel the window.
        let g = EgressGovernor::manual(breaker_limits(2, 60));
        let (t, c, h) = (Uuid::new_v4(), Uuid::new_v4(), "h");
        for _ in 0..2 {
            let _ = g.check(t, c, h);
            g.report(c, h, Outcome::TransportFailure);
        }
        assert!(g.check(t, c, h).is_err());
        g.report(c, h, Outcome::Ok);
        assert!(
            g.check(t, c, h).is_err(),
            "an out-of-band success must not re-open the gate"
        );
    }

    #[test]
    fn zero_breaker_knobs_disable_the_breaker() {
        for l in [breaker_limits(0, 60), breaker_limits(5, 0)] {
            let g = EgressGovernor::manual(l);
            let (t, c, h) = (Uuid::new_v4(), Uuid::new_v4(), "h");
            for _ in 0..50 {
                assert!(g.check(t, c, h).is_ok(), "a disabled breaker never trips");
                g.report(c, h, Outcome::TransportFailure);
            }
        }
    }

    // ── Bounded memory ──────────────────────────────────────────────────────

    #[test]
    fn maps_stay_bounded_under_many_distinct_hosts() {
        let g = EgressGovernor::manual(GovernorLimits {
            tenant_per_min: 0,
            connection_per_min: 0,
            host_per_min: 10,
            breaker_threshold: 3,
            breaker_open_secs: 60,
        });
        let (t, c) = (Uuid::new_v4(), Uuid::new_v4());
        for i in 0..(MAX_TRACKED * 2) {
            let host = format!("h{i}.example.test");
            assert!(g.check(t, c, &host).is_ok());
            g.report(c, &host, Outcome::Ok);
        }
        let (_, _, hosts, breakers) = g.tracked();
        assert!(
            hosts <= MAX_TRACKED && breakers <= MAX_TRACKED,
            "unbounded growth: {hosts} hosts / {breakers} breakers over the {MAX_TRACKED} cap"
        );
        assert!(
            hosts > 0 && breakers > 0,
            "the maps recorded nothing at all"
        );
    }

    #[test]
    fn eviction_prefers_idle_entries_over_an_open_breaker() {
        // Open one breaker, then flood the map with clean ones. The OPEN entry —
        // the only one carrying information — must survive.
        let g = EgressGovernor::manual(breaker_limits(2, 60));
        let (t, c) = (Uuid::new_v4(), Uuid::new_v4());
        for _ in 0..2 {
            let _ = g.check(t, c, "victim.test");
            g.report(c, "victim.test", Outcome::TransportFailure);
        }
        assert!(g.check(t, c, "victim.test").is_err(), "precondition: open");
        for i in 0..(MAX_TRACKED * 2) {
            let host = format!("flood{i}.test");
            let _ = g.check(t, c, &host);
            g.report(c, &host, Outcome::Ok);
        }
        assert!(
            g.check(t, c, "victim.test").is_err(),
            "the open breaker was evicted by a flood of clean ones"
        );
    }

    // ── Refusal message ─────────────────────────────────────────────────────

    #[test]
    fn refusal_messages_carry_scope_and_retry_after_and_never_the_raw_host() {
        let host = "secret-internal.corp.example";
        let digest = "sha256:deadbeefcafe0001";
        for scope in [SCOPE_TENANT, SCOPE_CONNECTION, SCOPE_HOST, SCOPE_BREAKER] {
            let m = Throttled {
                scope,
                retry_after_secs: 42,
            }
            .message(digest);
            assert!(m.contains(scope), "message dropped the scope: {m}");
            assert!(m.contains("42"), "message dropped the retry hint: {m}");
            assert!(m.contains(digest), "message dropped the host digest: {m}");
            assert!(
                !m.contains(host),
                "message leaked the raw upstream host: {m}"
            );
        }
    }

    #[test]
    fn defaults_match_the_documented_plan_values() {
        let d = GovernorLimits::default();
        assert_eq!(d.tenant_per_min, 120);
        assert_eq!(d.connection_per_min, 60);
        assert_eq!(d.host_per_min, 120);
        assert_eq!(d.breaker_threshold, 5);
        assert_eq!(d.breaker_open_secs, 60);
    }
}
