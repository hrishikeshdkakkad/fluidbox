//! Outbound egress governor (Phase E, #33; plan E14) — the last two unbuilt
//! controls on the design's broker-egress list (design :836-861): "rate-limit per
//! tenant, user, connection, and upstream host" and "circuit-break unhealthy
//! upstreams".
//!
//! # Shape
//!
//! Four INDEPENDENT token buckets are consulted per dial — per tenant, per
//! connection, per (tenant, upstream host), and a loose cross-tenant tier on the
//! host — and a per-`(tenant, connection, host)` circuit breaker rides on top. A
//! refusal happens strictly BEFORE any request bytes are written, so the broker
//! maps it to `DispatchOutcome::NeverSent` ⇒ execution-claim state
//! `failed_before_send` ⇒ re-claimable, which is what makes the retry-after hint
//! we hand the caller safe to act on.
//!
//! # Everything here is PER TENANT (review I5)
//!
//! No dimension may let one tenant refuse another's healthy calls. The host
//! bucket was originally keyed by host string alone, so a tenant exhausting its
//! dials against a shared SaaS host throttled every other tenant pointed at it;
//! the breaker was keyed `(connection, host)`, which collapsed to host-only for
//! the legacy credential-free path (`connection == Uuid::nil()`) and let five
//! failures from one tenant open another's breaker. Both now carry the tenant.
//! The only deliberately shared control is [`SCOPE_HOST_GLOBAL`], set at
//! [`HOST_GLOBAL_FACTOR`] × the per-tenant host ceiling: upstream protection
//! against a stampede, loose enough that it is not a cross-tenant fairness lever.
//!
//! # TWO TIERS since Phase F (Task 1)
//!
//! Everything above describes the LOCAL tier, and its VERDICT is unchanged — same
//! buckets, same breaker, same arithmetic, same tests. (Not its cost:
//! [`EgressGovernor::check`] now
//! also computes the permit's host digest, an unconditional SHA-256 per admission,
//! so that the value keying a durable breaker row is byte-identical to the one the
//! refusal message and the broker's logs carry. "Unchanged" below always means the
//! decision, never the instruction count.) What Phase F adds is a SECOND,
//! Postgres-backed tier ([`fluidbox_db::governance`], migration 0023) that a dial
//! must ALSO pass. The local tier is consulted FIRST because it is free and it
//! catches a runaway loop with zero DB load; the durable tier is what makes the
//! numbers mean something across replicas.
//!
//! Three properties are worth stating up front:
//!
//! * **Degrade, never fail.** A durable-tier error (DB down, timeout) is logged,
//!   counted ([`EgressGovernor::degraded_count`]) and ADMITTED on the local
//!   verdict alone. This is an abuse/fairness control, not a quota system — the
//!   same reason `0` means "disable that dimension" and never "block everything".
//!   Degrading is right for a BLIP and wrong as the only signal for a permanent
//!   misconfiguration, which is why there is also a one-shot usability probe —
//!   see [`EgressGovernor::preflight_durable`].
//! * **The local tier can over-charge itself.** A dial the local tier admits and
//!   the durable tier then refuses has already spent its local tokens, and may
//!   have been promoted to the local half-open probe. Both self-heal (the bucket
//!   refills; an unreported probe is taken over after one window — see
//!   `a_lost_probe_cannot_wedge_the_breaker_shut_forever`), and both err toward
//!   refusing, which is the safe direction.
//! * **`host_global` stays LOCAL-ONLY.** It is the one dimension keyed across
//!   tenants, so a durable version would need a per-dial RLS bypass. Trading the
//!   short, audited bypass inventory for a tighter ceiling on ONE deliberately
//!   loose upstream-protection tier is the wrong trade; its N× looseness stays
//!   disclosed. See [`fluidbox_db::governance::rate_tiers`].
//!
//! # The USER dimension (Phase F, durable tier only)
//!
//! The design names four dimensions — tenant, user, connection, host — and Phase E
//! shipped every one except **user**, so one member of an org could spread dials
//! across the org's connections and consume the whole tenant bucket. Phase F adds
//! it, keyed on `sessions.invoked_by_user_id` and resolved inside the durable
//! admission statement. Two consequences to keep honest:
//!
//! * it lives in the DURABLE tier only, because the local tier's verdict is
//!   deliberately unchanged — so `FLUIDBOX_EGRESS_DURABLE=0` means no per-user
//!   limiting at all;
//! * a run with NO invoking user (trigger and schedule invocations — the column is
//!   nullable) SKIPS the tier rather than bucketing every unattended run in the org
//!   under the nil uuid, which would be one shared ceiling for all automation;
//! * it AGGREGATES. 60/min is one user's whole outbound budget across every run and
//!   every connection they own simultaneously — not 60 per run. The design's own
//!   working-set assumption is 3 attached MCP servers per run, whose effective
//!   ceiling was 3 × the per-connection 60 = 180/min; under this dimension that
//!   user is bounded at 60/min in total. That is a deliberate BEHAVIOUR CHANGE for
//!   fan-out shapes, not a no-op default, and `FLUIDBOX_EGRESS_RATE_USER_PER_MIN`
//!   is the knob (`0` disables the dimension outright).
//!
//! `docs/hosted/connector-admission-policy.md` and `.env.example` state the same
//! limitations — keep all three honest together. (They were not, for one commit:
//! the doc still said "per-user limiting is not implemented", "a refusal costs
//! nothing" and "durable limiting is Phase F" after all three had shipped.)
//!
//! # What a dial costs (disclosed)
//!
//! The durable tier is not free and the price lands on the broker's hottest path:
//! roughly 9 extra database round trips per brokered dial (`admit` costs BEGIN,
//! `set_config`, two statements and COMMIT/ROLLBACK; `report` costs 4 more, and the
//! 401 re-mint path dispatches twice), plus 4 per swept tenant on a sweep tick, plus
//! a one-time 6-round-trip preflight. Every dial in one tenant also SERIALISES on
//! that tenant's single `egress_rate_windows` row, which the admission transaction
//! holds across the breaker round trip. `fluidbox_db::governance`'s module docs
//! carry the full accounting; `FLUIDBOX_EGRESS_DURABLE=0` is the escape hatch.
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
use fluidbox_db::governance::{self, AdmitRequest, DurableAdmission, DurableLimits};
use fluidbox_db::TenantScope;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use uuid::Uuid;

/// Which dimension refused the dial (rides in the refusal message, and in the
/// `Throttled` a caller inspects).
pub const SCOPE_TENANT: &str = "tenant";
pub const SCOPE_CONNECTION: &str = "connection";
pub const SCOPE_HOST: &str = "host";
/// The PER-USER dimension (Phase F). Enforced in the DURABLE tier only — the
/// local governor is deliberately unchanged — so it is inert when
/// `FLUIDBOX_EGRESS_DURABLE=0`.
///
/// It appears in this module because a `Throttled` can carry it and
/// `Throttled::message` renders it, but the VALUE is produced by
/// `fluidbox_db::governance`; the only direct reader here is the test that pins
/// the two spellings together (a drift would refuse dials with a scope name this
/// module's own precedence order does not know).
#[cfg_attr(not(test), allow(dead_code))]
pub const SCOPE_USER: &str = "user";
/// The cross-tenant upstream-protection tier (review I5): a much looser ceiling
/// on ONE host summed over every tenant, so partitioning the per-tenant host
/// bucket does not turn N tenants into N × the load one upstream sees.
pub const SCOPE_HOST_GLOBAL: &str = "host_global";
pub const SCOPE_BREAKER: &str = "breaker";

/// Per-minute dial ceilings. A tenant's whole org shares `TENANT`; one connection
/// (one credential, one upstream) gets `CONNECTION`; one upstream host gets
/// `HOST` across every connection pointed at it. Env-overridable — see
/// [`GovernorLimits::from_config`].
pub const DEFAULT_TENANT_PER_MIN: u32 = 120;
pub const DEFAULT_CONNECTION_PER_MIN: u32 = 60;
pub const DEFAULT_HOST_PER_MIN: u32 = 120;
/// The per-USER ceiling (Phase F). Chosen as 60 — the same number as
/// `DEFAULT_CONNECTION_PER_MIN`, deliberately, and NOT as the tenant's 120.
///
/// The reasoning against the three existing numbers: a typical run dials ONE
/// connection, so today's effective per-user ceiling is already 60 (the connection
/// bucket) — it just is not stated anywhere and evaporates the moment a user fans
/// out across a second connection, which is precisely the hole this dimension
/// exists to close. Setting it to 60 makes the common case's real ceiling explicit
/// and unchanged, and starts binding exactly where the old arrangement leaked.
/// Setting it to the tenant's 120 would have been a no-op default: at parity with
/// the tier above it, the user bucket could never refuse before the tenant bucket
/// did, and the dimension would ship dead.
pub const DEFAULT_USER_PER_MIN: u32 = 60;
/// The global host tier is this multiple of the PER-TENANT host ceiling. It is
/// deliberately loose: it exists to stop a stampede on one upstream, not to
/// arbitrate between tenants (that is what the per-tenant bucket does), so it
/// must not bind before roughly this many tenants are simultaneously saturating
/// their own host budgets against the same upstream.
pub const HOST_GLOBAL_FACTOR: u32 = 8;
/// Consecutive transport/5xx failures that open a connection's breaker.
pub const DEFAULT_BREAKER_THRESHOLD: u32 = 5;
/// How long an open breaker refuses before admitting one half-open probe.
pub const DEFAULT_BREAKER_OPEN_SECS: u64 = 60;

/// Per-map entry ceiling (see the module docs on bounded memory).
pub const MAX_TRACKED: usize = 4096;

/// How often ONE replica runs the durable tier's row collection, and how idle a
/// row must be to be collected. The sweep is inline (it costs one dial every
/// [`SWEEP_INTERVAL_SECS`] a bounded `DELETE`) rather than a spawned task, so
/// there is no detached work to leak and the cost is visible where it is paid.
const SWEEP_INTERVAL_SECS: u64 = 300;
const SWEEP_IDLE_SECS: u64 = 3600;
/// Rows deleted per pass. A backlog drains over several passes instead of one
/// long statement holding locks — "bounded" is the point, not "instant".
const SWEEP_BATCH: i64 = 5000;
/// How many TENANTS one sweep tick collects, in rotation.
///
/// This number is what turns the sweeper's capacity from O(replicas) into
/// O(tenants). The first cut swept the tenant of whichever dial happened to win the
/// once-per-interval CAS: with T tenants and R replicas that visits a given tenant
/// about once per `SWEEP_INTERVAL_SECS · T / R` seconds, so past `T > 12R` the
/// [`SWEEP_IDLE_SECS`] threshold never binds and the lottery does — and at the
/// design's 300-user / 1,500-connection scale that is the ordinary case, not a
/// corner. With a rotation, a replica serving T tenants visits each one every
///
/// ```text
/// SWEEP_INTERVAL_SECS × ceil(T / SWEEP_TENANTS_PER_TICK)
/// ```
///
/// seconds — a function of the constants rather than of luck.
///
/// 16 is the trade: one tick costs 16 × ~4 round trips inline on ONE dial every
/// [`SWEEP_INTERVAL_SECS`], and covers 4 800 tenant-visits per replica per hour,
/// which is more than [`MAX_TRACKED`] can hold.
const SWEEP_TENANTS_PER_TICK: usize = 16;

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
    /// Durable tier only — see [`DEFAULT_USER_PER_MIN`] and [`SCOPE_USER`].
    pub user_per_min: u32,
    pub breaker_threshold: u32,
    pub breaker_open_secs: u64,
    /// Whether the cross-replica Postgres tier is consulted at all (Phase F,
    /// `FLUIDBOX_EGRESS_DURABLE`, default ON). `false` restores exactly Phase E's
    /// per-replica behaviour, INCLUDING the absence of the user dimension.
    pub durable: bool,
}

impl Default for GovernorLimits {
    fn default() -> Self {
        GovernorLimits {
            tenant_per_min: DEFAULT_TENANT_PER_MIN,
            connection_per_min: DEFAULT_CONNECTION_PER_MIN,
            host_per_min: DEFAULT_HOST_PER_MIN,
            user_per_min: DEFAULT_USER_PER_MIN,
            breaker_threshold: DEFAULT_BREAKER_THRESHOLD,
            breaker_open_secs: DEFAULT_BREAKER_OPEN_SECS,
            durable: true,
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
            user_per_min: cfg.egress_rate_user_per_min,
            breaker_threshold: cfg.egress_breaker_threshold,
            breaker_open_secs: cfg.egress_breaker_open_secs,
            durable: cfg.egress_durable,
        }
    }

    fn breaker_enabled(&self) -> bool {
        self.breaker_threshold > 0 && self.breaker_open_secs > 0
    }

    /// The same ceilings, as the durable tier's view of them. `host_global` has no
    /// counterpart on purpose (see the module docs); everything else maps 1:1, so
    /// the two tiers enforce the SAME numbers rather than two sets that can drift.
    fn durable(&self) -> DurableLimits {
        DurableLimits {
            tenant_per_min: self.tenant_per_min,
            user_per_min: self.user_per_min,
            connection_per_min: self.connection_per_min,
            host_per_min: self.host_per_min,
            breaker_threshold: self.breaker_threshold,
            breaker_open_secs: self.breaker_open_secs,
        }
    }

    /// The cross-tenant ceiling on ONE upstream host (review I5). Derived, not a
    /// separate knob: it tracks whatever the per-tenant host limit is set to, and
    /// `0` (host limiting disabled) disables this tier too — never "block
    /// everything", same rule as every other dimension.
    fn host_global_per_min(&self) -> u32 {
        self.host_per_min.saturating_mul(HOST_GLOBAL_FACTOR)
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
    /// `epoch` identifies THIS probe: the admission that was promoted carries
    /// it in its [`Permit`], and only that permit's report may transition the
    /// state (review I6).
    HalfOpen { probe_ms: u64, epoch: u64 },
}

struct Breaker {
    state: BreakerState,
    /// Monotonic per-breaker probe counter — never reused, so a stale permit can
    /// never match a later window.
    epochs: u64,
}

impl Breaker {
    fn clean(&self) -> bool {
        matches!(self.state, BreakerState::Closed { failures: 0 })
    }

    /// Promote the calling dial to the half-open probe and return its epoch.
    fn promote(&mut self, now: u64) -> u64 {
        self.epochs = self.epochs.saturating_add(1);
        self.state = BreakerState::HalfOpen {
            probe_ms: now,
            epoch: self.epochs,
        };
        self.epochs
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

    /// ONE pass (review I6): the older shape scanned the map twice at capacity
    /// (once filtered to forgettable entries, once unfiltered as the fallback).
    /// Both candidates are tracked in a single iteration instead — same
    /// preference order, half the work under the governor's one mutex.
    fn evict_one(&mut self, forgettable: &impl Fn(&V) -> bool) {
        let mut oldest_forgettable: Option<(&K, u64)> = None;
        let mut oldest: Option<(&K, u64)> = None;
        for (k, slot) in self.map.iter() {
            if oldest.is_none_or(|(_, u)| slot.used < u) {
                oldest = Some((k, slot.used));
            }
            if forgettable(&slot.value) && oldest_forgettable.is_none_or(|(_, u)| slot.used < u) {
                oldest_forgettable = Some((k, slot.used));
            }
        }
        // Nothing forgettable: bounded memory still wins — drop the
        // least-recently-used entry outright.
        let victim = oldest_forgettable.or(oldest).map(|(k, _)| k.clone());
        if let Some(k) = victim {
            self.map.remove(&k);
        }
    }

    /// Entry count — the bounded-memory assertion's only observation point.
    #[cfg_attr(not(test), allow(dead_code))]
    fn len(&self) -> usize {
        self.map.len()
    }

    /// Every tracked key. Used by ONE caller — the sweeper's tenant rotation, for
    /// which the tenant map is exactly "the tenants this replica is serving".
    fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }
}

struct GovState {
    tenants: Bounded<Uuid, Bucket>,
    connections: Bounded<Uuid, Bucket>,
    /// Keyed `(tenant, host)` — the host ceiling is PER TENANT (review I5).
    /// Keying it by host alone made it a cross-tenant DoS: one tenant burning
    /// 120 dials/min at a shared SaaS host refused every other tenant's healthy
    /// calls to that host, and nothing about that refusal was the other tenants'
    /// doing.
    hosts: Bounded<(Uuid, String), Bucket>,
    /// The cross-tenant tier on the same host, at [`HOST_GLOBAL_FACTOR`] × the
    /// per-tenant ceiling — upstream protection only.
    hosts_global: Bounded<String, Bucket>,
    /// Keyed `(tenant, connection, host)`. The tenant component is load-bearing
    /// (review I5): the legacy credential-free bundle path has no connection id
    /// at all (`Uuid::nil()`), so `(connection, host)` collapsed every tenant's
    /// legacy traffic to one host-keyed breaker and five failures from one
    /// tenant refused another's dials. A connection normally has exactly one
    /// upstream, so the host component is a refinement that matters for the same
    /// legacy path.
    breakers: Bounded<(Uuid, Uuid, String), Breaker>,
    /// The last tenant the durable sweeper collected, i.e. the rotation cursor.
    /// Lives here rather than in an atomic because choosing the next batch reads
    /// `tenants` and writes the cursor, and those two must be one critical section
    /// or two concurrent ticks could hand out the same batch.
    sweep_cursor: Uuid,
}

/// Proof that ONE dial was admitted, and by whom (review I5/I6). It is what
/// [`EgressGovernor::report`] must be handed back: the breaker is keyed by
/// `(tenant, connection, host)` — none of which `report` could reconstruct on
/// its own for the legacy nil-connection path — and a half-open PROBE is
/// identified by the epoch stamped here at admission, so only the dial that was
/// actually promoted can transition that breaker.
///
/// Derefs to the host key so callers that already carry it around (the broker's
/// refusal digests, its logs) keep reading it straight off the permit.
#[derive(Debug, Clone)]
pub struct Permit {
    tenant: Uuid,
    connection: Uuid,
    host: String,
    /// The stored/reported form of `host` — see [`host_digest`]. Computed ONCE at
    /// admission so the digest that keys the durable breaker is byte-identical to
    /// the one the refusal message would have carried.
    digest: String,
    /// `Some(epoch)` iff THIS admission was the breaker's half-open probe.
    probe: Option<u64>,
    /// `Some(epoch)` iff THIS admission was elected the DURABLE breaker's
    /// deployment-wide half-open probe (Phase F). Independent of `probe`: the two
    /// breakers are separate state machines with separate epoch counters, and a
    /// dial can be the probe for either, both, or neither.
    durable_probe: Option<i64>,
}

impl std::ops::Deref for Permit {
    type Target = str;
    fn deref(&self) -> &str {
        &self.host
    }
}

/// The outbound governor held on `AppState`: an in-memory per-replica tier plus
/// (Phase F) the cross-replica Postgres tier layered under it.
pub struct EgressGovernor {
    limits: GovernorLimits,
    clock: Clock,
    state: Mutex<GovState>,
    /// How many dials were admitted because the DURABLE tier errored. A rising
    /// count means the cross-replica ceiling is not being enforced — the tier is
    /// degrading exactly as designed, and the operator should know.
    degraded: AtomicU64,
    /// Monotonic ms of the last durable-row collection this replica ran. `0` = never.
    last_sweep_ms: AtomicU64,
    /// One-shot latch for the durable-tier usability probe: the task that flips it
    /// runs the probe, everyone else skips (it is advisory — nobody waits on it).
    /// See [`EgressGovernor::preflight_durable`].
    preflight_claimed: AtomicBool,
    /// Set iff the probe RAN and FAILED. Read only to restate the diagnosis on the
    /// periodic health line — the tier keeps trying regardless, so a grant fixed
    /// underneath a running server heals without a restart.
    preflight_failed: AtomicBool,
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
                hosts_global: Bounded::new(),
                breakers: Bounded::new(),
                sweep_cursor: Uuid::nil(),
            }),
            degraded: AtomicU64::new(0),
            last_sweep_ms: AtomicU64::new(0),
            preflight_claimed: AtomicBool::new(false),
            preflight_failed: AtomicBool::new(false),
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
    pub fn check(&self, tenant: Uuid, connection: Uuid, host: &str) -> Result<Permit, Throttled> {
        let now = self.clock.now_ms();
        let st = &mut *self.lock();
        let l = self.limits;
        // 1. Peek every dimension (refilling as it goes) WITHOUT consuming, and
        //    SHORT-CIRCUIT on the first refusal (review I6). Short-circuiting is
        //    not just cheaper: a caller its own tenant bucket already refused
        //    must not reach the host maps at all, or it could keep naming fresh
        //    hosts and force an eviction scan per dial — cross-tenant lock
        //    contention bought with dials that were never going to happen.
        if let Some(retry_after_secs) = peek(&mut st.tenants, &tenant, l.tenant_per_min, now) {
            return Err(Throttled {
                scope: SCOPE_TENANT,
                retry_after_secs,
            });
        }
        if let Some(retry_after_secs) =
            peek(&mut st.connections, &connection, l.connection_per_min, now)
        {
            return Err(Throttled {
                scope: SCOPE_CONNECTION,
                retry_after_secs,
            });
        }
        let host_key = (tenant, host.to_string());
        if let Some(retry_after_secs) = peek(&mut st.hosts, &host_key, l.host_per_min, now) {
            return Err(Throttled {
                scope: SCOPE_HOST,
                retry_after_secs,
            });
        }
        let global_per_min = l.host_global_per_min();
        if let Some(retry_after_secs) =
            peek(&mut st.hosts_global, &host.to_string(), global_per_min, now)
        {
            return Err(Throttled {
                scope: SCOPE_HOST_GLOBAL,
                retry_after_secs,
            });
        }
        // 2. Breaker (may promote this caller to the half-open probe).
        let probe = self.check_breaker(st, tenant, connection, host, now)?;
        // 3. Everyone said yes — consume one token from each enabled dimension.
        take(&mut st.tenants, &tenant, l.tenant_per_min, now);
        take(&mut st.connections, &connection, l.connection_per_min, now);
        take(&mut st.hosts, &host_key, l.host_per_min, now);
        take(&mut st.hosts_global, &host.to_string(), global_per_min, now);
        Ok(Permit {
            tenant,
            connection,
            host: host.to_string(),
            digest: host_digest(host),
            probe,
            durable_probe: None,
        })
    }

    /// The SECOND, cross-replica tier (Phase F), applied to a permit the LOCAL tier
    /// has already issued. Split that way on purpose: the broker keeps one gate
    /// function for the local half (`broker::governor_gate`) and one refusal
    /// renderer, and this module keeps `check` byte-for-byte what it was.
    ///
    /// Order is local-first and deliberate: the local tier costs a mutex and some
    /// integer arithmetic, so a runaway loop is refused without ever touching the
    /// database, and the DB only ever sees dials that already passed a real gate.
    ///
    /// **A local admission is not free even when this tier then refuses.** The
    /// local tokens are already spent and the dial may already hold the local
    /// half-open probe slot. Both self-heal (buckets refill; an unreported probe is
    /// taken over after one window — see
    /// `a_lost_probe_cannot_wedge_the_breaker_shut_forever`), and both err toward
    /// refusing, which is the safe direction for an abuse control. Undoing them
    /// would mean a rollback path through the local tier's `take`: strictly more
    /// machinery for a strictly less safe outcome.
    ///
    /// `session` is the RUN's session, used only to resolve the invoking user for
    /// the per-user dimension inside the durable statement.
    pub async fn check_durable(
        &self,
        pool: &PgPool,
        scope: TenantScope,
        session: Uuid,
        permit: &mut Permit,
    ) -> Result<(), Throttled> {
        if !self.limits.durable {
            return Ok(());
        }
        self.preflight_durable(pool, scope).await;
        let answer = governance::admit(
            pool,
            scope,
            AdmitRequest {
                session_id: session,
                connection_id: permit.connection,
                host_digest: &permit.digest,
                replica: &crate::orchestrator::replica_id().to_string(),
                limits: self.limits.durable(),
            },
        )
        .await;
        permit.durable_probe = self.fold_durable(answer)?;
        self.maybe_sweep(pool, scope).await;
        Ok(())
    }

    /// Fold the durable tier's answer into a verdict, DEGRADING on error.
    ///
    /// Split out from [`check_durable`](Self::check_durable) precisely so the
    /// degrade path is reachable from a unit test without a database: everything
    /// about "a DB failure must admit, not refuse" lives here, in eight lines, with
    /// no I/O.
    ///
    /// The refusal `scope` is passed through verbatim — `fluidbox-db`'s scope
    /// constants and this module's are the same strings by contract, pinned by
    /// `the_two_tiers_agree_on_every_scope_name`.
    fn fold_durable(
        &self,
        answer: sqlx::Result<DurableAdmission>,
    ) -> Result<Option<i64>, Throttled> {
        match answer {
            Ok(DurableAdmission::Admitted { probe_epoch }) => Ok(probe_epoch),
            Ok(DurableAdmission::Refused(r)) => Err(Throttled {
                scope: r.scope,
                retry_after_secs: r.retry_after_secs,
            }),
            // DEGRADE. A rate limiter that fails dials when its own bookkeeping
            // store is unreachable has converted a fairness control into an
            // outage amplifier: the database being down is already bad, and
            // refusing every brokered tool call on top of it helps nobody. The
            // local tier still bounds this replica; the count says the ceiling
            // is not currently deployment-wide.
            Err(e) => {
                self.degraded.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    target: "governor",
                    "durable egress governance unavailable — admitting on the per-replica \
                     verdict alone (cross-replica ceiling NOT enforced): {e}"
                );
                Ok(None)
            }
        }
    }

    /// Dials admitted (or health reports lost) because the durable tier was
    /// unreachable. Surfaced to operators by [`maybe_sweep`](Self::maybe_sweep) —
    /// a counter nobody reads is not observability.
    pub fn degraded_count(&self) -> u64 {
        self.degraded.load(Ordering::Relaxed)
    }

    /// ONE-SHOT usability probe for the durable tier: can this process actually
    /// read and write the governance tables as the role it runs as?
    ///
    /// **Why this exists.** Migration 0023 wraps its DML grants in
    /// `if exists (select 1 from pg_roles …)`, because 0018 §(a) warns rather than
    /// fails when the runtime role is absent (a managed host may not let the
    /// migrating role create roles, and refusing the migration would be worse). If
    /// the role appears afterwards, the grant was silently skipped; every `admit`
    /// and `report` then answers `permission denied`, and the *correct* degrade path
    /// converts that into admit-and-count. The deployment believes it has a
    /// cross-replica ceiling and has none — and, worse, a PERMANENT
    /// misconfiguration is indistinguishable from a transient blip, because both
    /// produce the same trickle of per-dial warnings.
    ///
    /// **WARN, not refuse — and the justification is not "warnings are easier".**
    /// Three reasons, in order of weight:
    ///
    /// 1. It would be inconsistent with the tier's own rule. The identical
    ///    statement failing at runtime ADMITS (degrade, never fail) precisely
    ///    because this is a fairness/abuse control and not a quota system. Refusing
    ///    boot for the same failure at t=0 would make "the database said no" fatal
    ///    at one instant and harmless at every other.
    /// 2. `FLUIDBOX_EGRESS_DURABLE` defaults ON, so a refusal is not a refusal of
    ///    something an operator asked for — it is a refusal of a default. Phase F
    ///    has to be deployable as a no-op on an existing install; turning a missed
    ///    grant into an un-bootable control plane converts a fairness-control gap
    ///    into a total outage, which is exactly the outage amplification
    ///    [`fold_durable`](Self::fold_durable) refuses to do one dial at a time.
    /// 3. Refusing here would be stricter than the migration that CREATES the
    ///    condition: 0023's grant block warns and continues.
    ///
    /// What it buys instead is the thing that was actually missing: ONE
    /// `tracing::error!` naming the remediation, distinguishable by level and text
    /// from the per-dial degrade `warn!`, restated on every periodic health line so
    /// it cannot scroll away. The tier keeps trying afterwards, so a grant fixed
    /// underneath a running server heals without a restart.
    ///
    /// **Placement.** It runs on the first durable dial rather than in `main.rs`
    /// (another owner's file in this wave), latched so exactly one task pays for it;
    /// it is `pub` precisely so a boot call can be added later with no behaviour
    /// change — the latch makes a second call free. It needs a real `TenantScope`,
    /// which is another reason first-dial is a natural home: it probes under the
    /// same RLS binding a real dial uses.
    pub async fn preflight_durable(&self, pool: &PgPool, scope: TenantScope) {
        if self
            .preflight_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        match governance::preflight(pool, scope).await {
            Ok(()) => tracing::info!(
                target: "governor",
                "durable egress governance preflight OK — the cross-replica tier is \
                 readable and writable by this process"
            ),
            Err(e) => {
                self.preflight_failed.store(true, Ordering::Relaxed);
                tracing::error!(
                    target: "governor",
                    "DURABLE EGRESS GOVERNANCE IS NOT USABLE — the cross-replica \
                     ceiling is NOT in force and every dial will fall back to \
                     per-replica limiting (N replicas ⇒ N× the configured rate). \
                     This is a PERMANENT misconfiguration, not a transient outage. \
                     Most likely cause: migration 0023's DML grants were skipped \
                     because the runtime role did not exist yet — grant \
                     select/insert/update/delete on egress_rate_windows and \
                     egress_breakers to it, or set FLUIDBOX_EGRESS_DURABLE=0 to stop \
                     paying for a tier you are not getting. Probe error: {e}"
                );
            }
        }
    }

    /// The next tenants to collect, as a deterministic ROTATION over the tenants
    /// this replica is serving.
    ///
    /// The local governor's own tenant bucket map IS that set — every tenant that
    /// dialed recently enough to still be tracked — so the rotation needs no new
    /// bookkeeping and no cross-tenant query. The cursor is the last tenant handed
    /// out; each tick takes up to [`SWEEP_TENANTS_PER_TICK`] ids strictly after it
    /// in sort order and wraps. Sorting is what makes it a rotation rather than a
    /// second lottery: `HashMap` iteration order is not stable across mutations, so
    /// an index cursor into it would skip.
    ///
    /// `current` (the tenant whose dial triggered the tick) is always included. That
    /// is not belt-and-braces: `peek` never creates a bucket for a dimension whose
    /// limit is `0`, so with `FLUIDBOX_EGRESS_RATE_TENANT_PER_MIN=0` the tenant map
    /// is EMPTY while the connection/host/user dimensions are still writing rows.
    fn sweep_batch(&self, current: Uuid) -> Vec<Uuid> {
        let st = &mut *self.lock();
        let mut ids: Vec<Uuid> = st.tenants.keys().copied().collect();
        if !ids.contains(&current) {
            ids.push(current);
        }
        ids.sort_unstable();
        let start = ids.partition_point(|id| *id <= st.sweep_cursor);
        let mut batch: Vec<Uuid> = ids[start..]
            .iter()
            .copied()
            .take(SWEEP_TENANTS_PER_TICK)
            .collect();
        // Wrap, without re-taking anything this pass already took.
        let need = SWEEP_TENANTS_PER_TICK.saturating_sub(batch.len());
        batch.extend(ids[..start.min(need)].iter().copied());
        if let Some(last) = batch.last() {
            st.sweep_cursor = *last;
        }
        batch
    }

    /// Collect information-free durable rows for a ROTATING BATCH of this replica's
    /// tenants, at most once per [`SWEEP_INTERVAL_SECS`] per replica. Tenant-scoped
    /// on purpose: it needs no RLS bypass, and the tenants generating rows are the
    /// ones paying to clean them. A failure is logged and the tenant comes round
    /// again next cycle — it must never affect the dial that triggered the tick.
    ///
    /// **What this bounds.** With a replica serving T tenants, each is visited every
    /// `SWEEP_INTERVAL_SECS × ceil(T / SWEEP_TENANTS_PER_TICK)` seconds, so a
    /// tenant's residue is bounded by "keys dialed within [`SWEEP_IDLE_SECS`] + that
    /// period" — constants, not luck. The first cut swept only the tenant of
    /// whichever dial won the CAS, which is O(replicas) of capacity against
    /// O(tenants) of demand; see [`SWEEP_TENANTS_PER_TICK`] for the arithmetic and
    /// why `T > 12R` made the idle threshold stop binding altogether.
    ///
    /// **What it does NOT bound (disclosed).** A tenant that stops dialing entirely
    /// falls out of the local tenant map and therefore out of the rotation, so its
    /// last working set is frozen — finite, no longer growing, but not collected
    /// until it dials again. A deployment-wide collector belongs beside the other
    /// system-worker sweeps in `workers.rs`.
    async fn maybe_sweep(&self, pool: &PgPool, scope: TenantScope) {
        let now = self.clock.now_ms();
        let last = self.last_sweep_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) < SWEEP_INTERVAL_SECS.saturating_mul(1000) {
            return;
        }
        // CAS so N concurrent dials on this replica run ONE sweep between them.
        if self
            .last_sweep_ms
            .compare_exchange(last, now, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        // The sweep tick is also this replica's periodic health report. The degrade
        // path logs each individual failure at warn, but a slow trickle scrolls
        // past; the RUNNING TOTAL is what tells an operator the cross-replica
        // ceiling has not actually been in force.
        let degraded = self.degraded_count();
        if degraded > 0 {
            tracing::warn!(
                target: "governor",
                "durable egress governance has degraded {degraded} time(s) on this replica \
                 since boot — those dials were admitted on the per-replica verdict alone"
            );
        }
        if self.preflight_failed.load(Ordering::Relaxed) {
            tracing::error!(
                target: "governor",
                "durable egress governance is still UNUSABLE by this process (the boot \
                 probe failed) — the cross-replica ceiling has not been in force at any \
                 point since boot; see the preflight error for the remediation"
            );
        }
        for tenant in self.sweep_batch(scope.tenant_id()) {
            if let Err(e) = governance::sweep(
                pool,
                TenantScope::assume(tenant),
                SWEEP_IDLE_SECS,
                SWEEP_BATCH,
            )
            .await
            {
                tracing::warn!(
                    target: "governor",
                    "durable egress governance sweep failed (retrying next cycle): {e}"
                );
            }
        }
    }

    /// Feed one dispatch's health observation back into the connection's breaker.
    /// Consecutive means consecutive: any [`Outcome::Ok`] resets the count.
    pub fn report(&self, permit: &Permit, outcome: Outcome) {
        if !self.limits.breaker_enabled() {
            return;
        }
        let now = self.clock.now_ms();
        let threshold = self.limits.breaker_threshold;
        let st = &mut *self.lock();
        let br = breaker_entry(st, permit.tenant, permit.connection, &permit.host);
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
            // The PROBE answered — and it is the probe only if this permit
            // carries the epoch stamped when it was promoted (review I6).
            // Success closes and fully resets; failure opens a FRESH window
            // (never a shorter one).
            (BreakerState::HalfOpen { epoch, .. }, out) if permit.probe == Some(epoch) => match out
            {
                Outcome::Ok => BreakerState::Closed { failures: 0 },
                Outcome::TransportFailure => BreakerState::Open { opened_ms: now },
            },
            // A straggler: a dial admitted BEFORE this probe window (typically
            // before the breaker opened at all) reporting late. It says nothing
            // about the probe's premise, so it must not close the breaker early
            // nor reopen it and swallow the real probe's answer.
            (half @ BreakerState::HalfOpen { .. }, _) => half,
            // Same reasoning for a straggler arriving while the window is open —
            // only a half-open PROBE can close a breaker.
            (open @ BreakerState::Open { .. }, _) => open,
        };
    }

    /// Feed one dispatch's health observation into BOTH breakers (Phase F). This
    /// is what production calls; bare [`report`](Self::report) remains the local
    /// tier and is what the timing tests drive.
    ///
    /// The permit carries both epochs, so the local breaker is decided by
    /// `permit.probe` and the durable one by `permit.durable_probe` — a dial can be
    /// the probe for either, both, or neither, and each breaker ignores a report
    /// that does not carry ITS epoch.
    ///
    /// A durable failure here is logged and counted, never propagated: the dial has
    /// already happened, and a bookkeeping write cannot be allowed to change what
    /// the caller does with its result. The cost of losing one observation is a
    /// breaker that opens one dial later.
    pub async fn report_durable(
        &self,
        pool: &PgPool,
        scope: TenantScope,
        permit: &Permit,
        outcome: Outcome,
    ) {
        self.report(permit, outcome);
        if !self.limits.durable || !self.limits.breaker_enabled() {
            return;
        }
        if let Err(e) = governance::report(
            pool,
            scope,
            permit.connection,
            &permit.digest,
            outcome == Outcome::Ok,
            permit.durable_probe,
            &self.limits.durable(),
        )
        .await
        {
            self.degraded.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                target: "governor",
                "durable breaker report lost (upstream {} health not recorded \
                 deployment-wide): {e}",
                permit.digest
            );
        }
    }

    /// Consult (and possibly transition) the breaker for one admitted dial.
    /// `Ok(Some(epoch))` = admitted AS the half-open probe; `Ok(None)` =
    /// admitted normally; `Err` = refused.
    fn check_breaker(
        &self,
        st: &mut GovState,
        tenant: Uuid,
        connection: Uuid,
        host: &str,
        now: u64,
    ) -> Result<Option<u64>, Throttled> {
        if !self.limits.breaker_enabled() {
            return Ok(None);
        }
        let open_ms = self.limits.breaker_open_secs.saturating_mul(1000);
        let br = breaker_entry(st, tenant, connection, host);
        match br.state {
            BreakerState::Closed { .. } => Ok(None),
            BreakerState::Open { opened_ms } => {
                let elapsed = now.saturating_sub(opened_ms);
                if elapsed >= open_ms {
                    Ok(Some(br.promote(now)))
                } else {
                    Err(breaker_refusal(open_ms - elapsed))
                }
            }
            BreakerState::HalfOpen { probe_ms, .. } => {
                let elapsed = now.saturating_sub(probe_ms);
                if elapsed >= open_ms {
                    // The in-flight probe never reported (a caller died between
                    // the gate and its report) — take over as the new probe. The
                    // epoch bumps, so the abandoned probe's late report is a
                    // straggler and cannot decide this window.
                    Ok(Some(br.promote(now)))
                } else {
                    Err(breaker_refusal(open_ms - elapsed))
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
                hosts_global: Bounded::new(),
                breakers: Bounded::new(),
                sweep_cursor: Uuid::nil(),
            }),
            degraded: AtomicU64::new(0),
            last_sweep_ms: AtomicU64::new(0),
            preflight_claimed: AtomicBool::new(false),
            preflight_failed: AtomicBool::new(false),
        }
    }

    /// Test-only: admit one dial and feed its outcome back through the permit
    /// that admission produced — the exact shape every production caller has.
    #[cfg(test)]
    fn dial(
        &self,
        tenant: Uuid,
        connection: Uuid,
        host: &str,
        o: Outcome,
    ) -> Result<(), Throttled> {
        let permit = self.check(tenant, connection, host)?;
        self.report(&permit, o);
        Ok(())
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

/// The stored/reported form of an upstream host: a digest, never the host.
///
/// Byte-identical to `broker::msg_digest` (pinned by a test) so the value that
/// keys a durable breaker row is the same value a refusal message shows and the
/// same value the broker logs — one host, one identifier, everywhere. Defined here
/// rather than imported so this module stays free of a back-dependency on the
/// broker, which already depends on it.
pub fn host_digest(host: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(&Sha256::digest(host.as_bytes())[..8])
    )
}

fn breaker_refusal(remaining_ms: u64) -> Throttled {
    Throttled {
        scope: SCOPE_BREAKER,
        retry_after_secs: remaining_ms.div_ceil(1000).max(1),
    }
}

fn breaker_entry<'a>(
    st: &'a mut GovState,
    tenant: Uuid,
    connection: Uuid,
    host: &str,
) -> &'a mut Breaker {
    st.breakers.entry(
        &(tenant, connection, host.to_string()),
        || Breaker {
            state: BreakerState::Closed { failures: 0 },
            epochs: 0,
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
            // The user dimension lives in the DURABLE tier only, so it can never
            // affect a local-tier test; zero says so out loud.
            user_per_min: 0,
            // Breaker OFF unless a test is about the breaker, so a rate test can
            // never accidentally be measuring the breaker.
            breaker_threshold: 0,
            breaker_open_secs: 0,
            // Every test in this module drives the LOCAL tier through `check` /
            // `report`, which never consult the durable tier — but `false` keeps
            // that independent of the entry point a future test picks.
            durable: false,
        }
    }

    fn breaker_limits(threshold: u32, open_secs: u64) -> GovernorLimits {
        GovernorLimits {
            // Rate dimensions OFF so a breaker test measures only the breaker.
            tenant_per_min: 0,
            connection_per_min: 0,
            host_per_min: 0,
            user_per_min: 0,
            breaker_threshold: threshold,
            breaker_open_secs: open_secs,
            durable: false,
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
    fn host_dimension_binds_across_connections_but_never_across_tenants() {
        // Review I5. This test previously asserted the OPPOSITE — that the host
        // ceiling was "shared by every caller" — which is exactly the
        // cross-tenant denial-of-service being fixed: with the shipped default
        // of 120, one tenant's 120 dials at a shared SaaS host refused every
        // other tenant's healthy calls to it. The assertion is not weakened:
        // the host dimension still binds (a tenant cannot escape it by cycling
        // connections, asserted here), and the cross-tenant ceiling still
        // exists — it just lives in the loose HOST_GLOBAL tier below.
        let g = EgressGovernor::manual(limits(100, 100, 2));
        let noisy = Uuid::new_v4();
        assert!(g.check(noisy, Uuid::new_v4(), "shared.test").is_ok());
        assert!(g.check(noisy, Uuid::new_v4(), "shared.test").is_ok());
        let e = g
            .check(noisy, Uuid::new_v4(), "shared.test")
            .expect_err("the host ceiling binds across ONE tenant's connections");
        assert_eq!(e.scope, SCOPE_HOST);
        // The victim tenant, same host, is untouched.
        assert!(
            g.check(Uuid::new_v4(), Uuid::new_v4(), "shared.test")
                .is_ok(),
            "one tenant exhausting a shared host must not refuse another's calls"
        );
        // A different host is untouched for the noisy tenant too.
        assert!(g.check(noisy, Uuid::new_v4(), "other.test").is_ok());
    }

    #[test]
    fn the_global_host_tier_still_protects_one_upstream_from_a_stampede() {
        // Per-tenant host ceiling 1 ⇒ global tier HOST_GLOBAL_FACTOR × 1. Each
        // tenant is allowed exactly one dial, so the tier can only be reached by
        // MANY tenants — which is the only thing it is meant to catch.
        let g = EgressGovernor::manual(limits(1000, 1000, 1));
        for i in 0..HOST_GLOBAL_FACTOR {
            assert!(
                g.check(Uuid::new_v4(), Uuid::new_v4(), "shared.test")
                    .is_ok(),
                "tenant {i} must get its own host token"
            );
        }
        let e = g
            .check(Uuid::new_v4(), Uuid::new_v4(), "shared.test")
            .expect_err("the cross-tenant tier must cap total load on one host");
        assert_eq!(e.scope, SCOPE_HOST_GLOBAL);
        // …and it is per HOST, not global-global.
        assert!(g
            .check(Uuid::new_v4(), Uuid::new_v4(), "other.test")
            .is_ok());
    }

    #[test]
    fn the_legacy_nil_connection_breaker_is_still_per_tenant() {
        // Review I5. The credential-free legacy path has no connection id, so
        // the breaker key collapsed to (nil, host) — five failures from ONE
        // tenant opened every other tenant's breaker for that host.
        let g = EgressGovernor::manual(breaker_limits(2, 60));
        let (noisy, victim, h) = (Uuid::new_v4(), Uuid::new_v4(), "legacy.test");
        for _ in 0..2 {
            let _ = g.dial(noisy, Uuid::nil(), h, Outcome::TransportFailure);
        }
        assert_eq!(
            g.check(noisy, Uuid::nil(), h)
                .expect_err("the noisy tenant's breaker is open")
                .scope,
            SCOPE_BREAKER
        );
        assert!(
            g.check(victim, Uuid::nil(), h).is_ok(),
            "another tenant's legacy dials to the same host must still be admitted"
        );
    }

    #[test]
    fn only_the_admitted_probe_may_transition_a_half_open_breaker() {
        // Review I6. A slow dial admitted BEFORE the breaker opened must not be
        // mistaken for the half-open probe: its success would close the breaker
        // on evidence about a different window, and its failure would re-open a
        // window the real probe was about to close.
        let g = EgressGovernor::manual(breaker_limits(2, 60));
        let (t, c, h) = (Uuid::new_v4(), Uuid::new_v4(), "h");
        let straggler = g.check(t, c, h).expect("admitted while closed");
        for _ in 0..2 {
            let _ = g.dial(t, c, h, Outcome::TransportFailure);
        }
        g.advance_ms(60_000);
        let probe = g.check(t, c, h).expect("promoted to the half-open probe");
        assert!(
            g.check(t, c, h).is_err(),
            "precondition: the breaker really is half-open with ONE probe out"
        );

        // The straggler answers first — it is NOT the probe, so nothing moves.
        g.report(&straggler, Outcome::Ok);
        assert!(
            g.check(t, c, h).is_err(),
            "a straggler's success must not close a half-open breaker"
        );

        // The real probe answers — and its success is what closes the breaker.
        g.report(&probe, Outcome::Ok);
        assert!(
            g.check(t, c, h).is_ok(),
            "the admitted probe's success must close the breaker"
        );

        // The mirror case: a straggler FAILURE must not reopen against a probe.
        let g = EgressGovernor::manual(breaker_limits(2, 60));
        let stale = g.check(t, c, h).expect("admitted while closed");
        for _ in 0..2 {
            let _ = g.dial(t, c, h, Outcome::TransportFailure);
        }
        g.advance_ms(60_000);
        let probe = g.check(t, c, h).expect("promoted");
        g.report(&stale, Outcome::TransportFailure);
        g.report(&probe, Outcome::Ok);
        assert!(
            g.check(t, c, h).is_ok(),
            "the real probe's success must decide the window, not a straggler's failure"
        );
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
            assert!(g.dial(t, c, h, Outcome::TransportFailure).is_ok());
        }
        assert!(
            g.dial(t, c, h, Outcome::Ok).is_ok(),
            "4 < threshold — still closed"
        );
        for _ in 0..4 {
            assert!(
                g.dial(t, c, h, Outcome::TransportFailure).is_ok(),
                "the success reset the consecutive count"
            );
        }
        assert!(
            g.dial(t, c, h, Outcome::TransportFailure).is_ok(),
            "still 4 consecutive, still closed"
        );
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
            assert!(g.dial(t, c, h, Outcome::TransportFailure).is_ok());
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
            let _ = g.dial(t, c, h, Outcome::TransportFailure);
        }
        g.advance_ms(60_000);
        assert!(g.dial(t, c, h, Outcome::Ok).is_ok(), "probe admitted");
        // Closed AND reset: two fresh failures must not re-open it (that would
        // prove the pre-open count survived).
        assert!(g.dial(t, c, h, Outcome::TransportFailure).is_ok());
        assert!(g.dial(t, c, h, Outcome::TransportFailure).is_ok());
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
            let _ = g.dial(t, c, h, Outcome::TransportFailure);
        }
        g.advance_ms(60_000);
        assert!(
            g.dial(t, c, h, Outcome::TransportFailure).is_ok(),
            "probe admitted"
        );
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
            let _ = g.dial(t, c, h, Outcome::TransportFailure);
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
            let _ = g.dial(t, a, "h1", Outcome::TransportFailure);
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
        // The straggler's permit is taken FIRST — admitted while the breaker was
        // still closed, reported long after it opened.
        let straggler = g.check(t, c, h).expect("admitted while closed");
        for _ in 0..2 {
            let _ = g.dial(t, c, h, Outcome::TransportFailure);
        }
        assert!(g.check(t, c, h).is_err());
        g.report(&straggler, Outcome::Ok);
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
                assert!(
                    g.dial(t, c, h, Outcome::TransportFailure).is_ok(),
                    "a disabled breaker never trips"
                );
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
            user_per_min: 0,
            breaker_threshold: 3,
            breaker_open_secs: 60,
            durable: false,
        });
        let (t, c) = (Uuid::new_v4(), Uuid::new_v4());
        for i in 0..(MAX_TRACKED * 2) {
            let host = format!("h{i}.example.test");
            assert!(g.dial(t, c, &host, Outcome::Ok).is_ok());
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
            let _ = g.dial(t, c, "victim.test", Outcome::TransportFailure);
        }
        assert!(g.check(t, c, "victim.test").is_err(), "precondition: open");
        for i in 0..(MAX_TRACKED * 2) {
            let host = format!("flood{i}.test");
            let _ = g.dial(t, c, &host, Outcome::Ok);
        }
        assert!(
            g.check(t, c, "victim.test").is_err(),
            "the open breaker was evicted by a flood of clean ones"
        );
    }

    // ── Breaker × rate-bucket interaction ───────────────────────────────────

    #[test]
    fn a_breaker_refusal_charges_no_rate_bucket() {
        // The one combination NEITHER helper above can express: `limits()` zeroes
        // the breaker and `breaker_limits()` zeroes the rates, so until now every
        // test in this module ran with one of the two controls switched OFF and a
        // mutation making a breaker refusal charge the tenant bucket passed all of
        // them. That behavior would let ONE sick upstream drain its org's shared
        // budget and throttle every OTHER connection — so pin the current, correct
        // behavior: `check` peeks all three dimensions, consults the breaker, and
        // consumes tokens ONLY when everyone said yes.
        let h = "up.example.test";

        // A — the TENANT dimension (the shared budget). Connection/host roomy so
        // the only bucket that can speak is the tenant's.
        let g = EgressGovernor::manual(GovernorLimits {
            tenant_per_min: 5,
            connection_per_min: 100,
            host_per_min: 100,
            user_per_min: 0,
            breaker_threshold: 2,
            breaker_open_secs: 60,
            durable: false,
        });
        let t = Uuid::new_v4();
        let (sick, healthy) = (Uuid::new_v4(), Uuid::new_v4());
        // Two admitted dials: 2 tenant tokens spent, and the breaker opens.
        for _ in 0..2 {
            assert!(g.dial(t, sick, h, Outcome::TransportFailure).is_ok());
        }
        // 20 refusals — 4× the whole tenant capacity — all from the BREAKER.
        for i in 0..20 {
            let e = g.check(t, sick, h).expect_err("the breaker is open");
            assert_eq!(
                e.scope, SCOPE_BREAKER,
                "refusal {i} came from the wrong gate"
            );
        }
        // A sibling connection (its own clean breaker, same tenant) still gets
        // EXACTLY the 3 tokens the two admitted dials left — the 20 refusals cost
        // the tenant nothing.
        for i in 0..3 {
            assert!(
                g.check(t, healthy, h).is_ok(),
                "sibling dial {i} must survive the sick connection's refusals"
            );
        }
        // FALSE-GREEN guard: the bucket IS charged by ADMITTED dials, so the three
        // passes above are the remaining budget and not "nothing is ever charged".
        let e = g.check(t, healthy, h).expect_err("tenant capacity is 5");
        assert_eq!(e.scope, SCOPE_TENANT);

        // B — the CONNECTION dimension. The breaker is keyed (connection, host),
        // so a SECOND host gives the same connection a clean breaker while sharing
        // its one connection bucket.
        let g = EgressGovernor::manual(GovernorLimits {
            tenant_per_min: 100,
            connection_per_min: 5,
            host_per_min: 100,
            user_per_min: 0,
            breaker_threshold: 2,
            breaker_open_secs: 60,
            durable: false,
        });
        let (t, c) = (Uuid::new_v4(), Uuid::new_v4());
        for _ in 0..2 {
            assert!(g.dial(t, c, h, Outcome::TransportFailure).is_ok());
        }
        for _ in 0..20 {
            assert_eq!(g.check(t, c, h).unwrap_err().scope, SCOPE_BREAKER);
        }
        let other = "other.example.test";
        for i in 0..3 {
            assert!(
                g.check(t, c, other).is_ok(),
                "dial {i} to a healthy host must survive the other host's refusals"
            );
        }
        let e = g.check(t, c, other).expect_err("connection capacity is 5");
        assert_eq!(e.scope, SCOPE_CONNECTION);
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
        // Phase F. The user ceiling is the CONNECTION number, not the tenant one:
        // at parity with the tier above it the dimension could never refuse first
        // and would ship dead (see DEFAULT_USER_PER_MIN).
        assert_eq!(d.user_per_min, 60);
        assert!(
            d.user_per_min < d.tenant_per_min,
            "a user ceiling at or above the tenant ceiling can never bind"
        );
        // The durable tier ships ON — a fix for an N× ceiling that must be
        // switched on is a fix that ships dark.
        assert!(d.durable);
    }

    /// A `Config` with the seven governor knobs set to DISTINCT, recognisable
    /// values and everything else inert.
    ///
    /// The full literal is deliberate. `Config` has no `Default`, `from_env` reads
    /// the process environment (unusable from a parallel test), and the mapping
    /// under test is exactly "does each field land in the right place" — which a
    /// helper that took seven arguments and built the same struct would not test.
    /// `harness.rs` carries the same fixture for the same reason. If a new `Config`
    /// field breaks this, adding it here is one line — and the break is a prompt to
    /// ask whether the governor should be reading it.
    #[cfg(test)]
    fn cfg_with_egress(
        tenant: u32,
        connection: u32,
        host: u32,
        user: u32,
        threshold: u32,
        open_secs: u64,
        durable: bool,
    ) -> Config {
        Config {
            bind: String::new(),
            internal_bind: String::new(),
            database_url: String::new(),
            runtime_role: None,
            allow_rls_bypass: false,
            db_pool: fluidbox_db::PoolSettings::default(),
            admin_token: String::new(),
            public_control_url: String::new(),
            data_dir: std::path::PathBuf::new(),
            sandbox_image: String::new(),
            default_model: String::new(),
            codex_sandbox_image: String::new(),
            default_codex_model: String::new(),
            llm_upstream_url: String::new(),
            llm_upstream_key: String::new(),
            llm_upstream_is_anthropic: false,
            llm_key_mode: crate::config::LlmKeyMode::Shared,
            llm_admin_url: String::new(),
            llm_tenant_models: Vec::new(),
            llm_tenant_max_budget: None,
            llm_tenant_budget_duration: None,
            llm_tenant_tpm: None,
            llm_tenant_rpm: None,
            llm_max_concurrent_reservations: crate::facade::DEFAULT_MAX_CONCURRENT_RESERVATIONS,
            credential_key: None,
            kms_mode: crate::config::KmsMode::Off,
            kms_static_kek: None,
            kms_aws_key_id: None,
            kms_aws_endpoint: None,
            github_api_url: String::new(),
            github_web_url: String::new(),
            github_clone_base: String::new(),
            keep_workspaces: false,
            public_url: String::new(),
            egress_allow_cidrs: Vec::new(),
            egress_proxy: None,
            // The seven fields this fixture exists for.
            egress_rate_tenant_per_min: tenant,
            egress_rate_connection_per_min: connection,
            egress_rate_host_per_min: host,
            egress_rate_user_per_min: user,
            egress_durable: durable,
            egress_breaker_threshold: threshold,
            egress_breaker_open_secs: open_secs,
            provider: "docker".into(),
            network_mode: fluidbox_core::traits::NetworkMode::HostDev,
            require_enforced_netpol: false,
            netpol_probe_image: String::new(),
            internal_service: None,
            internal_service_namespace: None,
            max_archive_bytes: 0,
            archive_ttl_secs: 0,
            require_sso: false,
            trust_forwarded_for: false,
            session_idle_secs: 0,
            session_absolute_secs: 0,
            oidc_discovery_max_age_secs: 0,
            oidc_clock_skew_secs: 0,
            session_reauth_secs: 0,
            max_request_body_bytes: crate::config::DEFAULT_MAX_REQUEST_BODY_BYTES,
            workload_identity: crate::config::WorkloadIdentityMode::default(),
            // Task 4 (archive store): inert here — the governor reads none of it.
            archive_store: fluidbox_workspace::ArchiveStoreConfig::Fs,
            metrics_bind: None,
        }
    }

    #[test]
    fn from_config_maps_every_knob_to_the_field_that_enforces_it() {
        // THE PATH PRODUCTION TAKES. `EgressGovernor::from_config` →
        // `GovernorLimits::from_config` is the only way a real server ever builds
        // its limits; `GovernorLimits::default()` is never called by the binary. A
        // test that asserts on `default()` therefore proves nothing about the
        // mapping: `durable: cfg.egress_durable` could be replaced by
        // `durable: false` — disabling the entire cross-replica tier and silently
        // reopening the N× ceiling this whole task exists to close — with every
        // fluidbox-server test still green. That mutation is what this test exists
        // to catch.
        //
        // Seven DISTINCT values, none of them a default and none equal to another,
        // so a transposition (host ↔ user, threshold ↔ open_secs) fails as loudly
        // as a dropped field.
        let cfg = cfg_with_egress(11, 22, 33, 44, 55, 66, true);
        let l = GovernorLimits::from_config(&cfg);
        assert_eq!(l.tenant_per_min, 11, "tenant knob");
        assert_eq!(l.connection_per_min, 22, "connection knob");
        assert_eq!(l.host_per_min, 33, "host knob");
        assert_eq!(l.user_per_min, 44, "user knob");
        assert_eq!(l.breaker_threshold, 55, "breaker threshold knob");
        assert_eq!(l.breaker_open_secs, 66, "breaker open-window knob");
        assert!(
            l.durable,
            "the durable tier must follow FLUIDBOX_EGRESS_DURABLE"
        );

        // …and the flag is a MAPPING, not a constant: the other value must survive
        // the trip too, or `durable: true` would pass the assertion above.
        let off = GovernorLimits::from_config(&cfg_with_egress(11, 22, 33, 44, 55, 66, false));
        assert!(
            !off.durable,
            "FLUIDBOX_EGRESS_DURABLE=0 must reach GovernorLimits — a hardcoded \
             `true` here would make the disable knob dead"
        );

        // The SHIPPED defaults, through the same path: `config.rs` resolves an
        // absent env var to these constants, so this pins that the deployed
        // behaviour is the documented one and not merely that `default()` is.
        let shipped = GovernorLimits::from_config(&cfg_with_egress(
            DEFAULT_TENANT_PER_MIN,
            DEFAULT_CONNECTION_PER_MIN,
            DEFAULT_HOST_PER_MIN,
            DEFAULT_USER_PER_MIN,
            DEFAULT_BREAKER_THRESHOLD,
            DEFAULT_BREAKER_OPEN_SECS,
            true,
        ));
        assert_eq!(
            shipped,
            GovernorLimits::default(),
            "the constants config.rs falls back to must produce exactly the \
             documented defaults"
        );
    }

    // ── Phase F: the durable tier's SQL-free half ───────────────────────────

    #[test]
    fn the_two_tiers_agree_on_every_scope_name() {
        // The scope strings are a wire format between this module and
        // `fluidbox-db::governance` (which cannot depend on this crate — the
        // dependency runs the other way), and they end up in the runner-facing
        // refusal message. A drift here would be invisible: the durable tier would
        // refuse with a scope this module's precedence and messages do not know.
        assert_eq!(SCOPE_TENANT, governance::SCOPE_TENANT);
        assert_eq!(SCOPE_USER, governance::SCOPE_USER);
        assert_eq!(SCOPE_CONNECTION, governance::SCOPE_CONNECTION);
        assert_eq!(SCOPE_HOST, governance::SCOPE_HOST);
        assert_eq!(SCOPE_BREAKER, governance::SCOPE_BREAKER);
    }

    #[test]
    fn the_durable_view_carries_every_ceiling_except_host_global() {
        // The two tiers must enforce the SAME numbers; a hand-copied projection is
        // exactly where they would drift.
        let l = GovernorLimits {
            tenant_per_min: 11,
            connection_per_min: 22,
            host_per_min: 33,
            user_per_min: 44,
            breaker_threshold: 5,
            breaker_open_secs: 66,
            durable: true,
        };
        let d = l.durable();
        assert_eq!(d.tenant_per_min, 11);
        assert_eq!(d.connection_per_min, 22);
        assert_eq!(d.host_per_min, 33);
        assert_eq!(d.user_per_min, 44);
        assert_eq!(d.breaker_threshold, 5);
        assert_eq!(d.breaker_open_secs, 66);
        // `host_global` deliberately has no durable counterpart (a cross-tenant key
        // would need a per-dial RLS bypass). The local tier still derives and
        // enforces it, so this is a documented gap, not a forgotten field.
        //
        // The expected value is WRITTEN OUT, not recomputed. `33 * HOST_GLOBAL_FACTOR`
        // put the same constant on both sides of the assertion, so changing the
        // factor could not fail it — a "test" of `x == x`. 264 = 33 × 8; if the
        // factor moves, this number has to move with it, deliberately and visibly.
        assert_eq!(HOST_GLOBAL_FACTOR, 8, "the shipped cross-tenant multiplier");
        assert_eq!(l.host_global_per_min(), 264);
        // …and it is DERIVED from the host ceiling, not a fourth constant: zeroing
        // the host dimension must disable this tier too, never "block everything".
        assert_eq!(
            GovernorLimits {
                host_per_min: 0,
                ..l
            }
            .host_global_per_min(),
            0
        );
    }

    #[test]
    fn a_durable_tier_error_admits_rather_than_refusing() {
        // DEGRADE, never fail. The DB being unreachable is already an incident;
        // refusing every brokered tool call on top of it turns a fairness control
        // into an outage amplifier. The local tier still bounds this replica.
        let g = EgressGovernor::manual(limits(0, 0, 0));
        assert_eq!(g.degraded_count(), 0);
        let admitted = g
            .fold_durable(Err(sqlx::Error::PoolTimedOut))
            .expect("a durable-tier failure must ADMIT, never refuse");
        assert_eq!(
            admitted, None,
            "a degraded admission holds no probe — it was never elected one"
        );
        assert_eq!(
            g.degraded_count(),
            1,
            "a degraded admission must be COUNTED: a rising count is the only \
             signal that the cross-replica ceiling is not being enforced"
        );
        // …and it keeps counting, so the signal is a rate and not a boolean.
        let _ = g.fold_durable(Err(sqlx::Error::WorkerCrashed));
        assert_eq!(g.degraded_count(), 2);
    }

    #[test]
    fn a_durable_refusal_becomes_a_throttled_with_its_scope_and_hint_intact() {
        let g = EgressGovernor::manual(limits(0, 0, 0));
        for scope in [
            governance::SCOPE_TENANT,
            governance::SCOPE_USER,
            governance::SCOPE_CONNECTION,
            governance::SCOPE_HOST,
            governance::SCOPE_BREAKER,
        ] {
            let t = g
                .fold_durable(Ok(DurableAdmission::Refused(
                    fluidbox_db::governance::DurableRefusal {
                        scope,
                        retry_after_secs: 17,
                    },
                )))
                .expect_err("a durable refusal must refuse");
            assert_eq!(t.scope, scope);
            assert_eq!(t.retry_after_secs, 17);
            // …and it must render as a refusal message the runner can act on,
            // carrying the digest and never the raw host.
            let m = t.message("sha256:deadbeefcafe0001");
            assert!(m.contains(scope) && m.contains("17"), "got: {m}");
        }
        assert_eq!(
            g.degraded_count(),
            0,
            "a refusal is not a degradation — conflating them would hide real outages"
        );
    }

    #[test]
    fn a_durable_probe_election_rides_the_permit_and_a_plain_admission_carries_none() {
        // The epoch is the ONLY thing that distinguishes the deployment-wide probe's
        // completion from a straggler's, so it must survive the fold verbatim.
        let g = EgressGovernor::manual(limits(0, 0, 0));
        assert_eq!(
            g.fold_durable(Ok(DurableAdmission::Admitted {
                probe_epoch: Some(42)
            }))
            .unwrap(),
            Some(42)
        );
        assert_eq!(
            g.fold_durable(Ok(DurableAdmission::Admitted { probe_epoch: None }))
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_permit_carries_the_host_digest_and_never_the_raw_host() {
        // The digest is computed ONCE at admission, so the value that keys the
        // durable breaker row is byte-identical to the one the refusal message and
        // the broker's logs show.
        let g = EgressGovernor::manual(limits(0, 0, 0));
        let host = "secret-internal.corp.example";
        let p = g.check(Uuid::new_v4(), Uuid::new_v4(), host).unwrap();
        assert_eq!(p.digest, host_digest(host));
        assert!(p.digest.starts_with("sha256:"));
        assert!(
            !p.digest.contains("corp.example"),
            "the digest leaked the host: {}",
            p.digest
        );
        assert_eq!(
            p.digest,
            crate::broker::msg_digest(host),
            "the governor's digest and the broker's must be the SAME function — \
             two spellings of one host would key two breaker rows"
        );
        assert_eq!(
            p.durable_probe, None,
            "the local tier elects no durable probe"
        );
    }

    // ── Phase F: the durable tier's I/O half, without a database ─────────────
    //
    // These use a LAZY pool pointed at a port nothing listens on. Nothing connects
    // unless the code under test actually reaches the database, and a refused
    // connection is instant and local — no DATABASE_URL, no server, no Neon. The
    // observation is `degraded_count()`: 0 means the early return held, 1 means the
    // call reached the pool and the degrade path caught the failure. That is what
    // makes deleting an early return VISIBLE rather than merely slower.

    fn unreachable_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://nobody:nobody@127.0.0.1:1/nowhere")
            .expect("a lazy pool never dials at construction")
    }

    fn durable_limits(durable: bool) -> GovernorLimits {
        GovernorLimits {
            tenant_per_min: 10,
            connection_per_min: 10,
            host_per_min: 10,
            user_per_min: 10,
            breaker_threshold: 3,
            breaker_open_secs: 60,
            durable,
        }
    }

    #[tokio::test]
    async fn the_durable_tier_switch_really_switches_it_off() {
        // `config.rs` promises `FLUIDBOX_EGRESS_DURABLE=0` "restores exactly Phase
        // E's per-replica behaviour". Until now that rested on inspection: neither
        // `check_durable` nor `report_durable` had a test at all. Both early returns
        // are asserted here from the observable side.
        let scope = TenantScope::assume(Uuid::new_v4());
        let (t, c, h) = (Uuid::new_v4(), Uuid::new_v4(), "up.example.test");

        let off = EgressGovernor::manual(durable_limits(false));
        let mut permit = off.check(t, c, h).expect("the local tier admits");
        off.check_durable(&unreachable_pool(), scope, Uuid::new_v4(), &mut permit)
            .await
            .expect("a disabled durable tier admits without consulting anything");
        assert_eq!(
            off.degraded_count(),
            0,
            "a disabled tier must not touch the pool at all — a degrade here means \
             the early return is gone and every dial is paying for a round trip"
        );
        assert_eq!(permit.durable_probe, None);

        off.report_durable(
            &unreachable_pool(),
            scope,
            &permit,
            Outcome::TransportFailure,
        )
        .await;
        assert_eq!(
            off.degraded_count(),
            0,
            "the report path's disable check must hold too"
        );
        assert!(
            !off.preflight_claimed.load(Ordering::SeqCst),
            "a disabled tier must not even run the usability probe — there is \
             nothing to be usable"
        );

        // FALSE-GREEN GUARD: with the tier ON, the same calls DO reach the pool and
        // DO degrade — so the zeroes above are the early return and not "this test
        // can never observe anything".
        let on = EgressGovernor::manual(durable_limits(true));
        let mut permit = on.check(t, c, h).expect("the local tier admits");
        on.check_durable(&unreachable_pool(), scope, Uuid::new_v4(), &mut permit)
            .await
            .expect("an unreachable durable tier DEGRADES, never refuses");
        assert!(
            on.degraded_count() >= 1,
            "with the tier enabled the unreachable pool must be observed"
        );
        // The usability probe is WIRED, not merely written: an enabled tier runs it
        // once and records the diagnosis. Without this, deleting the call site would
        // be invisible — the whole point of the probe is that the degrade path is
        // silent about permanent failure.
        assert!(
            on.preflight_claimed.load(Ordering::SeqCst),
            "an enabled durable tier must run the usability probe"
        );
        assert!(
            on.preflight_failed.load(Ordering::SeqCst),
            "…and must RECORD that it failed, so the periodic health line can \
             restate it after the one-shot ERROR has scrolled away"
        );
        let before = on.degraded_count();
        on.report_durable(
            &unreachable_pool(),
            scope,
            &permit,
            Outcome::TransportFailure,
        )
        .await;
        assert!(
            on.degraded_count() > before,
            "a lost durable health report must be counted too"
        );
    }

    #[tokio::test]
    async fn the_sweep_interval_gates_the_tick() {
        // `maybe_sweep` had no test either. The interval gate is what keeps the
        // collection off the hot path; without it every dial would sweep.
        let g = EgressGovernor::manual(durable_limits(true));
        let scope = TenantScope::assume(Uuid::new_v4());
        let pool = unreachable_pool();

        // The clock must be ADVANCED (a little) before the first assertion: at t=0
        // the CAS is 0 → 0, so a governor with no gate at all would leave
        // `last_sweep_ms` at 0 and look identical to a gated one. One second in, a
        // missing gate stamps 1_000 and the difference is visible. (This test passed
        // against a gate-less mutant until that was fixed.)
        g.advance_ms(1_000);
        g.maybe_sweep(&pool, scope).await;
        assert_eq!(
            g.last_sweep_ms.load(Ordering::SeqCst),
            0,
            "1s is not an interval — no tick may run, and none may be claimed"
        );

        g.advance_ms(SWEEP_INTERVAL_SECS * 1000);
        g.maybe_sweep(&pool, scope).await;
        let claimed = SWEEP_INTERVAL_SECS * 1000 + 1_000;
        assert_eq!(
            g.last_sweep_ms.load(Ordering::SeqCst),
            claimed,
            "one full interval must claim a tick"
        );
        // …and the claim holds: a call one second later is gated again.
        g.advance_ms(1_000);
        g.maybe_sweep(&pool, scope).await;
        assert_eq!(g.last_sweep_ms.load(Ordering::SeqCst), claimed);
    }

    #[test]
    fn the_sweeper_rotates_over_every_tenant_this_replica_serves() {
        // The defect this pins: the first cut swept the tenant of whichever dial
        // won the CAS, so with T tenants and R replicas a given tenant was collected
        // about once per 300·T/R seconds and past T > 12R the idle threshold never
        // bound — the lottery did. A rotation makes coverage a function of the
        // constants. Deliberately more tenants than one tick can hold.
        let g = EgressGovernor::manual(durable_limits(true));
        let n = SWEEP_TENANTS_PER_TICK * 3 + 5;
        let tenants: Vec<Uuid> = (0..n).map(|_| Uuid::new_v4()).collect();
        for (i, t) in tenants.iter().enumerate() {
            // A DISTINCT host per tenant: the cross-tenant `host_global` bucket is
            // keyed by host alone, so a shared host would make this test's setup
            // silently depend on HOST_GLOBAL_FACTOR × host_per_min ≥ n — coupling a
            // rotation test to an unrelated constant.
            g.check(*t, Uuid::new_v4(), &format!("h{i}"))
                .expect("admitted");
        }

        // ONE tick is bounded …
        let first = g.sweep_batch(tenants[0]);
        assert_eq!(
            first.len(),
            SWEEP_TENANTS_PER_TICK,
            "a tick must not sweep every tenant at once — the cost is inline on one dial"
        );

        // … and ceil(T / K) ticks cover ALL of them, each exactly once.
        let mut seen = first;
        let ticks = n.div_ceil(SWEEP_TENANTS_PER_TICK);
        for _ in 1..ticks {
            seen.extend(g.sweep_batch(tenants[0]));
        }
        let mut unique = seen.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            n,
            "every tenant this replica serves must be visited within ceil(T/K) \
             ticks — {} of {n} were, over {ticks} ticks",
            unique.len()
        );
        assert_eq!(
            seen.len(),
            unique.len() + (ticks * SWEEP_TENANTS_PER_TICK - n),
            "a full cycle must not revisit a tenant before covering the rest \
             (only the wrap at the end may repeat)"
        );

        // A tenant the tenant MAP does not know is still swept: `peek` creates no
        // bucket when the tenant dimension is disabled, so with
        // FLUIDBOX_EGRESS_RATE_TENANT_PER_MIN=0 the map is empty while the other
        // dimensions keep writing rows.
        let g = EgressGovernor::manual(GovernorLimits {
            tenant_per_min: 0,
            ..durable_limits(true)
        });
        let lonely = Uuid::new_v4();
        g.check(lonely, Uuid::new_v4(), "h").expect("admitted");
        assert_eq!(g.sweep_batch(lonely), vec![lonely]);
    }
}
