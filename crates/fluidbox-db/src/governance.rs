//! Cross-replica outbound egress governance (Phase F, Task 1; migration 0023).
//!
//! This is the DURABLE tier under `fluidbox-server`'s in-memory `EgressGovernor`.
//! Phase E shipped that governor entirely in-process and disclosed the hole: "with
//! N replicas the effective ceiling is N × the configured rate and a breaker opened
//! on one replica does not stop the others". Everything here exists to close that,
//! and nothing here replaces the local tier — the server checks local FIRST (free,
//! catches a runaway loop with zero DB load) and consults this one only for dials
//! the local tier already admitted.
//!
//! # What this module owns, and what it does not
//!
//! It owns SQL and transactions. It deliberately owns ONE piece of policy too —
//! [`rate_verdict`] and [`rate_tiers`] — because the comparison is meaningless
//! without the counts and the counts are meaningless without the limits, and
//! splitting them across a crate boundary would leave two half-descriptions of one
//! rule. It owns NO retry, NO fallback, and NO error swallowing: every failure is
//! returned as [`sqlx::Error`], and DEGRADING on it (admit on the local verdict
//! alone, log, count) is the server's decision, made in one place.
//!
//! # Take-then-check, then ROLL BACK on a refusal
//!
//! [`admit`] increments every enabled dimension in ONE multi-row upsert and reads
//! each dimension's POST-increment count back; the comparison then happens in Rust.
//! That buys a single round trip on the hot path instead of a check-then-take pair
//! that would need a second statement and could still race between them.
//!
//! **A refusal — from ANY dimension, rate or breaker — then rolls the WHOLE
//! admission back, so it charges nothing.** The transaction is the unit: nothing a
//! refused dial touched survives it.
//!
//! That is not tidiness. An earlier revision committed the take on a RATE refusal
//! and called the result "marginally STRICTER … the safe direction"; it is neither
//! marginal nor confined to the offender, and it contradicted the rationale twenty
//! lines below it that justifies the breaker's rollback. `PRECEDENCE` reports
//! `tenant` FIRST, so the moment the tenant row goes over its ceiling every OTHER
//! connection and user in the organisation is refused for the rest of the minute —
//! and the surplus on that row is contributed by dials the narrower
//! `connection`/`user`/`host` tiers had already refused. Concretely: 3 replicas,
//! `connection_per_min = 60`, `tenant_per_min = 120`, one runaway connection. Each
//! replica's LOCAL bucket admits 60/min, so 180 attempts/min reach this tier; the
//! durable `connection` tier refuses after 60, but COMMITTING the take charges
//! `tenant` all 180 and throttles the whole org from attempt ~121. Rolling back
//! charges only the 60 that were actually admitted.
//!
//! Rolling back does NOT stop the limiter working: the refusing dimension's stored
//! count returns to exactly its ceiling, so the next dial increments across it
//! again and is refused again, for the whole window
//! (`a_rate_refusal_rolls_its_charge_back_and_keeps_refusing_all_window` pins this
//! — "rollback" and "the limiter silently stopped counting" are one mistake apart).
//!
//! # What a dial now costs (disclosed)
//!
//! Governance is not free, and the price is paid on the broker's hottest path:
//!
//! * [`admit`] is BEGIN + `set_config` + the rate upsert + the breaker statement +
//!   COMMIT/ROLLBACK — **5 round trips** (4 with the breaker disabled, 0 with every
//!   dimension disabled), before the dial itself has sent a byte.
//! * [`report`] is BEGIN + `set_config` + one upsert + COMMIT — **4 more**. The
//!   broker reports once per dispatch and the 401 re-mint path dispatches twice, so
//!   a re-minted dial pays 13.
//! * Each swept tenant costs another 4, amortised over `SWEEP_INTERVAL_SECS`.
//!
//! The serialisation matters more than the count. `RATE_UPSERT` takes a row lock on
//! the `tenant` dimension's SINGLE row and the transaction holds it across the
//! breaker round trip, so every dial in one tenant serialises on that one row for
//! the duration of two statements. That is the deliberate price of an exact
//! cross-replica count; it also means per-tenant durable throughput is bounded by
//! round-trip latency, not by the configured ceiling. `FLUIDBOX_EGRESS_DURABLE=0`
//! is the escape hatch, and [`preflight`] is what tells an operator the tier is
//! being paid for and not delivering.
//!
//! # Time
//!
//! Every timestamp comes from the DATABASE clock (`now()`, `date_trunc('minute',
//! now())`). The local governor's clock is a per-process `Instant` base, which is a
//! monotonic offset from an arbitrary origin and is NOT comparable across replicas
//! — so no `last_ms` / `opened_ms` / `probe_ms` value is ever persisted.
//!
//! # Tenancy
//!
//! Both tables are tenant-owned and carry `tenant_id` directly; every statement
//! rides [`crate::scoped_tx`], so the RLS policy from 0023 is the enforcing floor
//! and the explicit `tenant_id = $n` predicate is the defence in depth — including
//! `SWEEP`'s two outer `DELETE`s, which now repeat it BESIDE the `ctid in (…)`
//! subquery instead of leaving it to the subquery alone. That was the one place in
//! this module where the stated discipline was not followed, on its two most
//! destructive statements: an unqualified `delete … where ctid in (…)` is correct
//! only for as long as the subquery is, so a policy or predicate regression there
//! had the whole table as its blast radius rather than one tenant's rows. No
//! function here takes a bypass — deliberately. The cross-tenant `host_global`
//! dimension of the local governor is therefore NOT mirrored here (see
//! [`rate_tiers`]).

use crate::{scoped_tx, TenantScope};
use sqlx::PgPool;
use uuid::Uuid;

/// Rate dimensions, as stored in `egress_rate_windows.scope`. These strings are a
/// WIRE FORMAT between this module and `fluidbox-server`'s governor (which cannot
/// be depended on from here — the dependency runs the other way), so the server
/// asserts equality against its own `SCOPE_*` constants in a unit test.
pub const SCOPE_TENANT: &str = "tenant";
pub const SCOPE_USER: &str = "user";
pub const SCOPE_CONNECTION: &str = "connection";
pub const SCOPE_HOST: &str = "host";
/// Not a rate dimension — the label a breaker refusal carries.
pub const SCOPE_BREAKER: &str = "breaker";

/// Refusal precedence, mirroring the local governor's order and extending it with
/// the new `user` dimension in the position the design names (tenant, user,
/// connection, host). Only the FIRST over-limit dimension is reported, so the
/// caller learns the broadest thing that refused it.
const PRECEDENCE: [&str; 4] = [SCOPE_TENANT, SCOPE_USER, SCOPE_CONNECTION, SCOPE_HOST];

/// The durable tier's ceilings. `0` DISABLES that dimension — never "block
/// everything" — exactly as in the local governor: an operator who zeroes a limit
/// means "do not rate-limit this", and a limiter that answered a typo'd `0` by
/// refusing every outbound dial would be a self-inflicted outage. The same rule
/// covers both breaker knobs: zero on EITHER disables the breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableLimits {
    pub tenant_per_min: u32,
    pub user_per_min: u32,
    pub connection_per_min: u32,
    pub host_per_min: u32,
    pub breaker_threshold: u32,
    pub breaker_open_secs: u64,
}

impl DurableLimits {
    fn breaker_enabled(&self) -> bool {
        self.breaker_threshold > 0 && self.breaker_open_secs > 0
    }

    /// The ceiling for one dimension. An UNKNOWN scope answers `0` (= disabled),
    /// so a scope this build does not understand is inert rather than fatal.
    fn limit_for(&self, scope: &str) -> u32 {
        match scope {
            SCOPE_TENANT => self.tenant_per_min,
            SCOPE_USER => self.user_per_min,
            SCOPE_CONNECTION => self.connection_per_min,
            SCOPE_HOST => self.host_per_min,
            _ => 0,
        }
    }
}

/// Which durable dimension refused this dial, and how long to wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableRefusal {
    pub scope: &'static str,
    pub retry_after_secs: u64,
}

/// The durable tier's verdict for ONE dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableAdmission {
    /// Admitted. `probe_epoch` is `Some` iff THIS dial was elected the breaker's
    /// half-open probe — it must be handed back to [`report`] verbatim, because it
    /// is the only thing that distinguishes the probe's answer from a straggler's.
    Admitted {
        probe_epoch: Option<i64>,
    },
    Refused(DurableRefusal),
}

/// One dimension's post-increment answer from the admission upsert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierHit {
    pub scope: String,
    pub hits: i64,
    pub retry_after_secs: i64,
}

/// Everything one durable admission needs. Grouped into a struct because the
/// alternative is a seven-argument call in which `connection_id` and `session_id`
/// are both bare `Uuid`s.
#[derive(Debug, Clone, Copy)]
pub struct AdmitRequest<'a> {
    /// The RUN's session — used ONLY to resolve `invoked_by_user_id` for the user
    /// dimension, inside the same statement (see [`RATE_UPSERT`]).
    pub session_id: Uuid,
    /// The dialing connection. The legacy credential-free brokered path has none
    /// and passes the NIL uuid; that is a real key, not a sentinel to special-case
    /// — the tenant component of both primary keys is what keeps it per-tenant.
    pub connection_id: Uuid,
    /// A DIGEST of the upstream host, never the host itself.
    pub host_digest: &'a str,
    /// This replica's identity, recorded on an elected breaker probe. Purely
    /// informational: correctness rides on `probe_epoch`.
    pub replica: &'a str,
    pub limits: DurableLimits,
}

// ─── SQL ────────────────────────────────────────────────────────────────────

/// The whole rate tier in ONE statement: increment every enabled dimension and
/// return each one's post-increment count.
///
/// * `$1` tenant, `$2` scopes, `$3` subjects (parallel arrays, already filtered to
///   the ENABLED dimensions), `$4` include-user, `$5` session.
/// * The `user` row is produced by the statement itself rather than by the caller,
///   because its subject is `sessions.invoked_by_user_id` — resolving it in Rust
///   would cost a second round trip on every dial. The `is not null` predicate is
///   what SKIPS the tier for trigger/schedule invocations, which have no user
///   (migration 0012:260): bucketing them under the nil uuid instead would give
///   every unattended run in the org one shared ceiling.
/// * `s.tenant_id = $1` is defence in depth under the `sessions` RLS policy the
///   surrounding `scoped_tx` already binds; a session from another tenant resolves
///   to no row, so the tier is skipped rather than charged to a stranger.
/// * A row whose stored `window_start` is an older minute RESETS to 1 instead of
///   accumulating, which is what keeps this table one row per KEY rather than one
///   row per key per minute.
/// * The scope/subject pairs are unique by construction (one row per dimension),
///   so `ON CONFLICT DO UPDATE` can never be asked to touch one row twice.
const RATE_UPSERT: &str = "\
insert into egress_rate_windows as w (tenant_id, scope, subject, window_start, hits)
select $1::uuid, x.scope, x.subject, date_trunc('minute', now()), 1
  from (
        select t.scope, t.subject
          from unnest($2::text[], $3::text[]) as t(scope, subject)
        union all
        select 'user'::text, s.invoked_by_user_id::text
          from sessions s
         where $4::boolean
           and s.id = $5::uuid
           and s.tenant_id = $1::uuid
           and s.invoked_by_user_id is not null
       ) as x
on conflict (tenant_id, scope, subject) do update
   set hits = case when w.window_start = excluded.window_start
                   then w.hits + 1
                   else 1 end,
       window_start = excluded.window_start
returning w.scope,
          w.hits,
          coalesce(greatest(1, ceil(extract(epoch from
              (w.window_start + interval '1 minute' - now()))))::bigint, 1)";

/// Consult (and possibly transition) the durable breaker for one dial.
///
/// The UPDATE arm is the PROBE ELECTION: it fires only for a breaker whose open
/// window has fully elapsed, bumps `probe_epoch`, and stamps this replica. Because
/// it is a single conditional UPDATE, only one caller wins any GIVEN election —
/// every other replica's UPDATE matches zero rows and falls through to the refusal
/// branch. The second disjunct is the LOST-PROBE takeover: a replica that dies
/// between election and completion would otherwise wedge the breaker half-open
/// forever, so after one further window the next caller is elected with a FRESH
/// epoch. (The local breaker has the same rule and the same reason —
/// `governor.rs`'s `a_lost_probe_cannot_wedge_the_breaker_shut_forever`.)
///
/// **The guarantee is NOT "exactly one probe is in flight deployment-wide" — it is
/// that at most one probe can DECIDE.** The takeover disjunct cannot tell a dead
/// replica from a slow one, and it does not try: a full brokered dial is
/// `initialize` + `notifications/initialized` + `tools/call`, each bounded by the
/// broker's 30s `MCP_TIMEOUT`, i.e. up to ~90s against a 60s default open window,
/// so OVERLAPPING PROBES ARE ROUTINE rather than an edge case. What holds
/// regardless is the epoch: `BREAKER_REPORT` transitions the row only for a
/// completion whose epoch equals the row's CURRENT `probe_epoch`, and every
/// takeover bumps it, so a superseded probe is inert in BOTH directions — its late
/// success cannot close a window it knows nothing about and its late failure cannot
/// swallow the live probe's answer. Overlap therefore costs extra dials at a sick
/// upstream, bounded by one per open window, and never a wrong transition. Widening
/// the takeover window would trade those dials for a longer wedge after a genuinely
/// dead replica; both breakers make the same trade for the same reason.
///
/// The outer SELECT reads the PRE-update snapshot — CTEs and the main query share
/// one snapshot — so `state` and the retry hint are the values as of BEFORE any
/// election. That is fine and intended: when `probe_epoch` comes back non-null the
/// caller ignores both, and when it comes back null nothing was updated.
///
/// Zero rows = no breaker row = closed = admit.
const BREAKER_ADMIT: &str = "\
with promoted as (
    update egress_breakers b
       set state = 'half_open',
           probe_epoch = b.probe_epoch + 1,
           probe_owner = $4::text,
           probe_started_at = now(),
           updated_at = now()
     where b.tenant_id = $1::uuid
       and b.connection_id = $2::uuid
       and b.host_digest = $3::text
       and ((b.state = 'open'
             and b.opened_at < now() - make_interval(secs => $5::double precision))
         or (b.state = 'half_open'
             and b.probe_started_at < now() - make_interval(secs => $5::double precision)))
    returning b.probe_epoch
)
select (select probe_epoch from promoted),
       b.state,
       coalesce(greatest(1, ceil(extract(epoch from (
           (case when b.state = 'half_open' then b.probe_started_at else b.opened_at end)
           + make_interval(secs => $5::double precision) - now()))))::bigint, 1)
  from egress_breakers b
 where b.tenant_id = $1::uuid
   and b.connection_id = $2::uuid
   and b.host_digest = $3::text";

/// Feed one dispatch's HEALTH observation into the durable breaker.
///
/// `$4` ok, `$5` the epoch this dial was elected with (NULL if it was not the
/// probe), `$6` threshold.
///
/// The three-way discrimination in every `case` is the whole point:
///
/// 1. **This dial IS the probe** (`state = 'half_open'` AND the epoch matches):
///    success closes and fully RESETS the consecutive count; failure opens a FRESH
///    window, never a shortened continuation of the old one.
/// 2. **The breaker is not closed and this dial is not its probe** — a straggler,
///    typically a dial admitted before the breaker opened at all. It says nothing
///    about the probe's premise, so it transitions NOTHING in either direction: a
///    late success must not cancel a window, and a late failure must not swallow
///    the real probe's answer.
/// 3. **Closed**: ordinary consecutive-failure counting.
///
/// The INSERT arm covers "no row yet": a success writes a clean closed row, and a
/// failure opens immediately only if the threshold is 1 (i.e. `0 + 1 >= threshold`).
const BREAKER_REPORT: &str = "\
insert into egress_breakers as b
    (tenant_id, connection_id, host_digest, state, failures, opened_at,
     probe_epoch, probe_owner, probe_started_at, updated_at)
values ($1::uuid, $2::uuid, $3::text,
        case when $4::boolean then 'closed'::text
             when $6::int <= 1 then 'open'::text
             else 'closed'::text end,
        case when $4::boolean then 0 else 1 end,
        case when not $4::boolean and $6::int <= 1 then now() else null end,
        0, null, null, now())
on conflict (tenant_id, connection_id, host_digest) do update set
    state = case
        when b.state = 'half_open' and $5::bigint is not null and b.probe_epoch = $5::bigint
             then case when $4::boolean then 'closed'::text else 'open'::text end
        when b.state <> 'closed' then b.state
        when $4::boolean then 'closed'::text
        when b.failures + 1 >= $6::int then 'open'::text
        else 'closed'::text end,
    failures = case
        when b.state = 'half_open' and $5::bigint is not null and b.probe_epoch = $5::bigint
             then 0
        when b.state <> 'closed' then b.failures
        when $4::boolean then 0
        else b.failures + 1 end,
    opened_at = case
        when b.state = 'half_open' and $5::bigint is not null and b.probe_epoch = $5::bigint
             then case when $4::boolean then null else now() end
        when b.state <> 'closed' then b.opened_at
        when not $4::boolean and b.failures + 1 >= $6::int then now()
        else null end,
    updated_at = now()";

/// Bounded, tenant-scoped collection of rows that carry no LIVE information: rate
/// windows whose minute is long gone, and breakers untouched for `idle_secs`.
///
/// **Why an OPEN breaker is now eligible once AGED.** The earlier predicate kept
/// every non-closed breaker forever, on the theory that forgetting an open one
/// re-admits traffic to a dead upstream. But a breaker row has no connection FK,
/// so an OPEN row whose connection was revoked/abandoned never sees another dial,
/// never transitions, and grew without bound — a tenant could mint permanent rows
/// by tripping a breaker then dropping the connection. The resolution keys on TIME,
/// not state: `idle_secs` (3600) is FAR longer than any `breaker_open_secs`
/// (default 60), so a row untouched for `idle_secs` cannot be protecting anything
/// live — an endpoint still being dialed refreshes `updated_at` within its open
/// window (a half-open probe, or a report). Collecting an aged open row costs at
/// most ONE re-probe of an endpoint nobody has dialed in an hour, which is exactly
/// what half-open already does on a 60 s cycle. A RECENT open breaker (live
/// protection) still survives, because its `updated_at` is recent.
///
/// `limit` caps a single pass so a large backlog is drained over several passes
/// instead of one long statement holding locks. Both outer `DELETE`s repeat
/// `tenant_id = $1` beside the `ctid` subquery — redundant with the subquery and
/// RLS, which is the point: every statement in this module carries the predicate.
const SWEEP: &str = "\
with dead_windows as (
    delete from egress_rate_windows
     where tenant_id = $1::uuid
       and ctid in (
           select ctid from egress_rate_windows
            where tenant_id = $1::uuid
              and window_start < now() - make_interval(secs => $2::double precision)
            limit $3::bigint)
    returning 1
), dead_breakers as (
    delete from egress_breakers
     where tenant_id = $1::uuid
       and ctid in (
           select ctid from egress_breakers
            where tenant_id = $1::uuid
              and updated_at < now() - make_interval(secs => $2::double precision)
            limit $3::bigint)
    returning 1
)
select (select count(*) from dead_windows) + (select count(*) from dead_breakers)";

/// The BOOT USABILITY PROBE (Phase F fix wave). Four statements that exercise every
/// privilege the durable tier needs — `insert`, `update` (the `on conflict` arm),
/// `select` (the `where` clauses) and `delete` — on BOTH tables, as whatever role
/// the server actually runs as and under the RLS policy the tenant GUC binds. The
/// whole probe is ROLLED BACK, so it proves the privileges without leaving a row.
///
/// Why a probe at all: migration 0023's grant block is wrapped in `if exists (…
/// pg_roles …)` because 0018 §(a) warns rather than fails when the runtime role
/// does not exist on a managed host. If the role is created afterwards, the grant
/// was silently skipped and EVERY `admit`/`report` then answers `permission denied`
/// — which the (correct) degrade path converts into admit-and-count. The deployment
/// believes it has a cross-replica ceiling and has none, and the per-dial warning
/// makes a permanent misconfiguration look exactly like a transient blip.
///
/// The subjects are deliberately un-collidable with real data: `scope='preflight'`
/// is not a dimension name, and a real `host_digest` is always `sha256:<hex>`.
///
/// DELETE FIRST, INSERT SECOND — the order is load-bearing and it is not the
/// obvious one. Insert-then-delete probes the same four privileges but nets to zero
/// inside the transaction, which makes the closing `rollback` observationally
/// identical to a `commit`: the safety property would be untestable and the next
/// person to "simplify" it would find every test still green. Deleting first (a
/// no-op match, but the ACL and the policy are checked all the same) leaves the two
/// inserted rows depending on the rollback for their removal.
const PREFLIGHT: [&str; 4] = [
    "delete from egress_rate_windows where tenant_id = $1::uuid and scope = 'preflight'",
    "delete from egress_breakers where tenant_id = $1::uuid and host_digest = 'preflight'",
    "insert into egress_rate_windows (tenant_id, scope, subject, window_start, hits)
     values ($1::uuid, 'preflight', '', date_trunc('minute', now()), 0)
     on conflict (tenant_id, scope, subject) do update set hits = 0",
    "insert into egress_breakers (tenant_id, connection_id, host_digest, state)
     values ($1::uuid, '00000000-0000-0000-0000-000000000000'::uuid, 'preflight', 'closed')
     on conflict (tenant_id, connection_id, host_digest) do update set updated_at = now()",
];

// ─── Pure policy ────────────────────────────────────────────────────────────

/// The ENABLED rate dimensions the caller can key itself, as parallel
/// (scope, subject) arrays. Zero-limit dimensions are omitted ENTIRELY — not sent,
/// not counted, not stored — which is what makes `0` cost nothing rather than
/// costing a row.
///
/// The `user` dimension is deliberately absent from this list: its subject lives in
/// `sessions.invoked_by_user_id` and is resolved inside [`RATE_UPSERT`].
///
/// **The cross-tenant `host_global` dimension is NOT mirrored durably.** It is the
/// one dimension of the local governor whose key spans tenants, so a durable row
/// for it could not satisfy any `fluidbox.tenant_id` predicate and would need a
/// per-dial RLS bypass on the broker's hottest path. Trading a short, audited,
/// grep-able bypass inventory for a tighter ceiling on ONE deliberately loose
/// upstream-protection tier is the wrong trade; the local tier still enforces it
/// per replica, and the N× looseness there stays disclosed.
pub fn rate_tiers(
    limits: &DurableLimits,
    tenant: Uuid,
    connection: Uuid,
    host_digest: &str,
) -> (Vec<String>, Vec<String>) {
    let mut scopes = Vec::with_capacity(3);
    let mut subjects = Vec::with_capacity(3);
    let mut push = |scope: &str, subject: String| {
        scopes.push(scope.to_string());
        subjects.push(subject);
    };
    if limits.tenant_per_min > 0 {
        push(SCOPE_TENANT, tenant.to_string());
    }
    if limits.connection_per_min > 0 {
        push(SCOPE_CONNECTION, connection.to_string());
    }
    if limits.host_per_min > 0 {
        push(SCOPE_HOST, host_digest.to_string());
    }
    (scopes, subjects)
}

/// The first dimension whose POST-increment count exceeded its ceiling, in
/// [`PRECEDENCE`] order. `hits > limit` (not `>=`) is what makes a ceiling of N
/// admit exactly N dials per window.
///
/// A dimension that is absent from `hits` was never charged — either its limit is
/// `0` (disabled) or, for `user`, the run has no invoking user — and therefore
/// cannot refuse. That is the whole implementation of "skip the user tier rather
/// than bucketing everything under nil".
pub fn rate_verdict(limits: &DurableLimits, hits: &[TierHit]) -> Option<DurableRefusal> {
    for scope in PRECEDENCE {
        let limit = limits.limit_for(scope);
        if limit == 0 {
            continue;
        }
        if let Some(h) = hits.iter().find(|h| h.scope == scope) {
            if h.hits > i64::from(limit) {
                return Some(DurableRefusal {
                    scope,
                    retry_after_secs: h.retry_after_secs.max(1) as u64,
                });
            }
        }
    }
    None
}

// ─── Statements ─────────────────────────────────────────────────────────────

/// Admit (or refuse) ONE outbound dial against the DURABLE tier.
///
/// Rate dimensions first, breaker second — the same order as the local governor,
/// and for the same reason: consulting the breaker is a STATE TRANSITION (it may
/// elect this caller as the half-open probe), so it must not run for a dial the
/// rate tier already refused, which would spend the single deployment-wide probe
/// slot on a call that never happens.
///
/// Both statements ride ONE transaction. That is not just fewer round trips: the
/// rate charge and the probe election commit together, so a crash between them
/// cannot leave a charged window beside an un-elected breaker. It is also what
/// makes the breaker-refusal rollback (see the module docs) a single `rollback()`
/// rather than a compensating UPDATE.
pub async fn admit(
    pool: &PgPool,
    scope: TenantScope,
    req: AdmitRequest<'_>,
) -> sqlx::Result<DurableAdmission> {
    let l = req.limits;
    let (scopes, subjects) = rate_tiers(&l, scope.tenant_id(), req.connection_id, req.host_digest);
    let want_user = l.user_per_min > 0;
    // Everything disabled: no statement, no transaction, no round trip.
    if scopes.is_empty() && !want_user && !l.breaker_enabled() {
        return Ok(DurableAdmission::Admitted { probe_epoch: None });
    }
    let mut tx = scoped_tx(pool, scope).await?;

    if !scopes.is_empty() || want_user {
        let rows: Vec<(String, i64, i64)> = sqlx::query_as(RATE_UPSERT)
            .bind(scope.tenant_id())
            .bind(&scopes)
            .bind(&subjects)
            .bind(want_user)
            .bind(req.session_id)
            .fetch_all(&mut *tx)
            .await?;
        let hits: Vec<TierHit> = rows
            .into_iter()
            .map(|(scope, hits, retry_after_secs)| TierHit {
                scope,
                hits,
                retry_after_secs,
            })
            .collect();
        if let Some(refusal) = rate_verdict(&l, &hits) {
            // ROLL THE TAKE BACK — see the module docs. Committing it charged the
            // TENANT row for refusals raised by the narrower connection/user/host
            // tiers, and because `PRECEDENCE` reports `tenant` first, once that row
            // went over every other connection and user in the org was refused for
            // the rest of the minute. The limiter still binds after the rollback:
            // the refusing dimension's count returns to exactly its ceiling, so the
            // next dial re-crosses it.
            tx.rollback().await?;
            return Ok(DurableAdmission::Refused(refusal));
        }
    }

    if !l.breaker_enabled() {
        tx.commit().await?;
        return Ok(DurableAdmission::Admitted { probe_epoch: None });
    }

    let row: Option<(Option<i64>, String, i64)> = sqlx::query_as(BREAKER_ADMIT)
        .bind(scope.tenant_id())
        .bind(req.connection_id)
        .bind(req.host_digest)
        .bind(req.replica)
        .bind(l.breaker_open_secs as f64)
        .fetch_optional(&mut *tx)
        .await?;
    let verdict = match row {
        // No breaker row at all ⇒ never failed ⇒ closed.
        None => DurableAdmission::Admitted { probe_epoch: None },
        Some((Some(epoch), _, _)) => DurableAdmission::Admitted {
            probe_epoch: Some(epoch),
        },
        Some((None, state, _)) if state == "closed" => {
            DurableAdmission::Admitted { probe_epoch: None }
        }
        Some((None, _, retry_after_secs)) => DurableAdmission::Refused(DurableRefusal {
            scope: SCOPE_BREAKER,
            retry_after_secs: retry_after_secs.max(1) as u64,
        }),
    };
    match verdict {
        // A BREAKER refusal charges nothing (module docs), exactly like the rate
        // refusal above: rolling the whole admission back is what stops one sick
        // upstream from burning its org's shared per-minute budget and throttling
        // every other connection it owns. Nothing else in this transaction needs to
        // survive — the election UPDATE matched zero rows, which is precisely why
        // we are refusing.
        DurableAdmission::Refused(_) => tx.rollback().await?,
        DurableAdmission::Admitted { .. } => tx.commit().await?,
    }
    Ok(verdict)
}

/// Prove the durable tier is USABLE by the role this process actually runs as.
///
/// One rolled-back transaction exercising insert / update / select / delete on both
/// tables (see the `PREFLIGHT` statements for why this exists at all — a silently
/// skipped 0023 grant degrades the whole feature to nothing, permanently, and the
/// degrade path makes that indistinguishable from a transient outage).
///
/// It answers `Err` and never interprets it: this module's only consumer,
/// `fluidbox-server`'s `EgressGovernor`, owns the decision of what to do about a
/// failure, in one place, as with every other failure here.
pub async fn preflight(pool: &PgPool, scope: TenantScope) -> sqlx::Result<()> {
    let mut tx = scoped_tx(pool, scope).await?;
    for stmt in PREFLIGHT {
        sqlx::query(stmt)
            .bind(scope.tenant_id())
            .execute(&mut *tx)
            .await?;
    }
    // Nothing a probe writes may survive it.
    tx.rollback().await
}

/// Feed one dispatch's health observation back into the durable breaker.
///
/// `probe_epoch` MUST be the value [`admit`] returned for THIS dial (`None` when it
/// was an ordinary admission). Passing a fabricated or remembered epoch is the one
/// way to make a straggler decide a window it knows nothing about.
///
/// Only TRANSPORT failures count as failures; the caller (`broker::breaker_signal`)
/// owns that classification and a definitive upstream answer — a JSON-RPC error, an
/// `isError` result, a 4xx — is HEALTH, because the upstream demonstrably answered.
pub async fn report(
    pool: &PgPool,
    scope: TenantScope,
    connection_id: Uuid,
    host_digest: &str,
    ok: bool,
    probe_epoch: Option<i64>,
    limits: &DurableLimits,
) -> sqlx::Result<()> {
    if !limits.breaker_enabled() {
        return Ok(());
    }
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(BREAKER_REPORT)
        .bind(scope.tenant_id())
        .bind(connection_id)
        .bind(host_digest)
        .bind(ok)
        .bind(probe_epoch)
        // SATURATE, never wrap: `breaker_threshold` is a `u32`, but the durable
        // predicate binds `i32`. A value above `i32::MAX` under `as i32` would
        // wrap to a NEGATIVE threshold, and the SQL `failures >= $6` would then
        // trip the breaker on the very first failure — the exact opposite of the
        // "effectively never" the local `u32` tier gives the same value. `try_from`
        // + `i32::MAX` keeps the two tiers consistent at the extreme.
        .bind(i32::try_from(limits.breaker_threshold).unwrap_or(i32::MAX))
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

/// Collect this tenant's information-free governance rows. Returns how many were
/// deleted. See [`SWEEP`] for what is and is not eligible.
pub async fn sweep(
    pool: &PgPool,
    scope: TenantScope,
    idle_secs: u64,
    limit: i64,
) -> sqlx::Result<i64> {
    let mut tx = scoped_tx(pool, scope).await?;
    let (n,): (i64,) = sqlx::query_as(SWEEP)
        .bind(scope.tenant_id())
        .bind(idle_secs as f64)
        .bind(limit)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(tenant: u32, user: u32, conn: u32, host: u32) -> DurableLimits {
        DurableLimits {
            tenant_per_min: tenant,
            user_per_min: user,
            connection_per_min: conn,
            host_per_min: host,
            // Breaker OFF unless a test is about the breaker, so a rate test can
            // never accidentally be measuring the breaker.
            breaker_threshold: 0,
            breaker_open_secs: 0,
        }
    }

    fn breaker_limits(threshold: u32, open_secs: u64) -> DurableLimits {
        DurableLimits {
            // Rate dimensions OFF so a breaker test measures only the breaker.
            tenant_per_min: 0,
            user_per_min: 0,
            connection_per_min: 0,
            host_per_min: 0,
            breaker_threshold: threshold,
            breaker_open_secs: open_secs,
        }
    }

    fn hit(scope: &str, hits: i64) -> TierHit {
        TierHit {
            scope: scope.to_string(),
            hits,
            retry_after_secs: 7,
        }
    }

    // ─── Pure policy (no DB) ────────────────────────────────────────────────

    #[test]
    fn zero_limits_are_omitted_from_the_charged_tiers() {
        let (t, c, h) = (Uuid::now_v7(), Uuid::now_v7(), "sha256:abc");
        let (scopes, subjects) = rate_tiers(&limits(0, 0, 0, 0), t, c, h);
        assert!(
            scopes.is_empty() && subjects.is_empty(),
            "a fully disabled tier must charge NOTHING, not store zero-limit rows"
        );

        let (scopes, subjects) = rate_tiers(&limits(10, 10, 0, 5), t, c, h);
        assert_eq!(scopes, vec![SCOPE_TENANT, SCOPE_HOST]);
        assert_eq!(subjects, vec![t.to_string(), h.to_string()]);
        assert!(
            !scopes.contains(&SCOPE_USER.to_string()),
            "the user subject is resolved in SQL from sessions.invoked_by_user_id, \
             never keyed by the caller"
        );
    }

    #[test]
    fn a_disabled_dimension_can_never_refuse_even_if_a_row_comes_back() {
        // Defence in depth: a stale row for a dimension an operator has since
        // zeroed must not throttle anyone.
        let l = limits(0, 0, 0, 0);
        assert_eq!(rate_verdict(&l, &[hit(SCOPE_TENANT, 9_999)]), None);
    }

    #[test]
    fn the_ceiling_admits_exactly_n_then_refuses() {
        let l = limits(3, 0, 0, 0);
        assert_eq!(rate_verdict(&l, &[hit(SCOPE_TENANT, 3)]), None, "the Nth");
        assert_eq!(
            rate_verdict(&l, &[hit(SCOPE_TENANT, 4)]),
            Some(DurableRefusal {
                scope: SCOPE_TENANT,
                retry_after_secs: 7
            }),
            "the N+1th"
        );
    }

    #[test]
    fn refusal_precedence_is_tenant_then_user_then_connection_then_host() {
        let l = limits(1, 1, 1, 1);
        let all_over = [
            hit(SCOPE_HOST, 5),
            hit(SCOPE_CONNECTION, 5),
            hit(SCOPE_USER, 5),
            hit(SCOPE_TENANT, 5),
        ];
        assert_eq!(rate_verdict(&l, &all_over).unwrap().scope, SCOPE_TENANT);
        assert_eq!(
            rate_verdict(&l, &all_over[..3]).unwrap().scope,
            SCOPE_USER,
            "user is reported ahead of connection and host"
        );
        assert_eq!(
            rate_verdict(&l, &all_over[..2]).unwrap().scope,
            SCOPE_CONNECTION
        );
        assert_eq!(rate_verdict(&l, &all_over[..1]).unwrap().scope, SCOPE_HOST);
    }

    #[test]
    fn a_tier_absent_from_the_answer_cannot_refuse() {
        // This IS the user-tier skip: a run with no invoking user produces no
        // 'user' row, so an enabled user ceiling still refuses nobody.
        let l = limits(100, 1, 100, 100);
        assert_eq!(
            rate_verdict(&l, &[hit(SCOPE_TENANT, 1)]),
            None,
            "an enabled user ceiling must not refuse a run that has no user"
        );
        assert_eq!(
            rate_verdict(&l, &[hit(SCOPE_TENANT, 1), hit(SCOPE_USER, 2)])
                .unwrap()
                .scope,
            SCOPE_USER,
            "…but it must refuse the moment a user IS present and over"
        );
    }

    #[test]
    fn the_retry_hint_is_never_zero() {
        let l = limits(1, 0, 0, 0);
        let over = TierHit {
            scope: SCOPE_TENANT.into(),
            hits: 2,
            retry_after_secs: 0,
        };
        assert_eq!(rate_verdict(&l, &[over]).unwrap().retry_after_secs, 1);
    }

    // ─── DB-backed (self-skipping) ──────────────────────────────────────────
    //
    // Every fixture uses its OWN throwaway tenant. The rate table's primary key is
    // (tenant_id, scope, subject) and the `tenant` dimension's subject IS the
    // tenant id, so two tests sharing the default tenant would share — and race —
    // one row. A per-test tenant makes every assertion here local by construction,
    // which is the #33 collision class stated in `lib.rs`'s test-module header.

    use crate::identity::create_org;
    use crate::test_connect;

    async fn throwaway_tenant(pool: &PgPool) -> TenantScope {
        let slug = format!("egov-{}", Uuid::now_v7().simple());
        TenantScope::assume(create_org(pool, &slug, None).await.unwrap().id)
    }

    /// A session in `scope`'s tenant with the given invoking user. The agent /
    /// revision / policy chain is the standard fixture shape (`create_session`
    /// verifies both belong to the tenant in SQL).
    async fn seed_session(pool: &PgPool, scope: TenantScope, user: Option<Uuid>) -> Uuid {
        let policy = crate::upsert_policy(
            pool,
            scope,
            "egov",
            "name: egov",
            &serde_json::json!({"name":"egov"}),
        )
        .await
        .unwrap();
        let agent = crate::create_agent(pool, scope, "egov-agent", None)
            .await
            .unwrap();
        let rev = crate::append_agent_revision(
            pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            None,
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        // A BARE uuid is exactly what production stores: migration 0012:256-260
        // adds `invoked_by_user_id` nullable and with NO foreign key on purpose
        // ("historical sessions may outlive users"), so seeding a `users` row here
        // would test a relationship the schema does not have.
        let repo = serde_json::json!({"kind":"none"});
        let empty = serde_json::json!({});
        crate::create_session(
            pool,
            scope,
            agent.id,
            rev.id,
            "supervised",
            "trusted",
            "egov task",
            &repo,
            &empty,
            &empty,
            None,
            None,
            user,
            None,
            None,
            &[],
        )
        .await
        .unwrap()
        .id
    }

    fn req<'a>(session: Uuid, conn: Uuid, host: &'a str, l: DurableLimits) -> AdmitRequest<'a> {
        AdmitRequest {
            session_id: session,
            connection_id: conn,
            host_digest: host,
            replica: "replica-test",
            limits: l,
        }
    }

    /// The breaker's clock is the DATABASE clock, so "time passed" is expressed by
    /// backdating the row rather than by sleeping — no test here ever sleeps.
    async fn backdate_breaker(pool: &PgPool, scope: TenantScope, secs: i64) {
        let mut tx = scoped_tx(pool, scope).await.unwrap();
        sqlx::query(
            "update egress_breakers
                set opened_at = opened_at - make_interval(secs => $2::double precision),
                    probe_started_at = probe_started_at - make_interval(secs => $2::double precision)
              where tenant_id = $1",
        )
        .bind(scope.tenant_id())
        .bind(secs as f64)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    async fn breaker_state(pool: &PgPool, scope: TenantScope) -> (String, i32, i64) {
        let mut tx = scoped_tx(pool, scope).await.unwrap();
        let row: (String, i32, i64) = sqlx::query_as(
            "select state, failures, probe_epoch from egress_breakers where tenant_id = $1",
        )
        .bind(scope.tenant_id())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        row
    }

    async fn window_hits(pool: &PgPool, scope: TenantScope, dim: &str) -> i64 {
        let mut tx = scoped_tx(pool, scope).await.unwrap();
        let row: Option<(i64,)> = sqlx::query_as(
            "select hits from egress_rate_windows where tenant_id = $1 and scope = $2",
        )
        .bind(scope.tenant_id())
        .bind(dim)
        .fetch_optional(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        row.map(|(h,)| h).unwrap_or(0)
    }

    #[tokio::test]
    async fn durable_windows_accumulate_across_independent_transactions() {
        // THE point of the whole task: each `admit` is its own transaction, which is
        // what a second replica's call also is. If the count did not survive the
        // commit boundary the tier would be per-connection, not per-deployment.
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let session = seed_session(&pool, scope, None).await;
        let l = limits(3, 0, 0, 0);
        let (c, h) = (Uuid::now_v7(), "sha256:host");

        for i in 0..3 {
            assert!(
                matches!(
                    admit(&pool, scope, req(session, c, h, l)).await.unwrap(),
                    DurableAdmission::Admitted { .. }
                ),
                "dial {i} is inside the ceiling"
            );
        }
        let refused = admit(&pool, scope, req(session, c, h, l)).await.unwrap();
        let DurableAdmission::Refused(r) = refused else {
            panic!("the 4th dial must be refused by the tenant ceiling: {refused:?}");
        };
        assert_eq!(r.scope, SCOPE_TENANT);
        assert!(
            (1..=60).contains(&r.retry_after_secs),
            "the retry hint must be the remainder of the minute, got {}",
            r.retry_after_secs
        );
        // Take-then-check, then ROLL BACK: the refusal's own increment does not
        // survive, so the stored count is the 3 ADMITTED dials and never 4. (This
        // assertion read `4` while the refusal was committed — see the module docs
        // for why charging a refusal was neither marginal nor safe.)
        assert_eq!(window_hits(&pool, scope, SCOPE_TENANT).await, 3);
    }

    #[tokio::test]
    async fn a_rate_refusal_rolls_its_charge_back_and_keeps_refusing_all_window() {
        // TWO properties, and they are one mistake apart.
        //
        // (a) A refusal raised by a NARROW dimension must not charge the BROAD one.
        //     `PRECEDENCE` reports `tenant` first, so a tenant row pushed over by
        //     refusals a connection ceiling already rejected throttles every other
        //     connection and user in the org for the rest of the minute — the exact
        //     self-inflicted denial of service the breaker rollback exists to stop.
        // (b) The limiter must still REFUSE after rolling back. A rollback restores
        //     the refusing dimension to exactly its ceiling, so the next dial
        //     re-crosses it; a rollback that also un-did the limit would look like a
        //     fix and be a hole.
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let session = seed_session(&pool, scope, None).await;
        // Tenant roomy (50), connection tight (2): only the connection tier speaks,
        // and the tenant row is the shared budget the over-charge would drain.
        let l = limits(50, 0, 2, 0);
        let (noisy, sibling, h) = (Uuid::now_v7(), Uuid::now_v7(), "sha256:host");

        for i in 0..2 {
            assert!(
                matches!(
                    admit(&pool, scope, req(session, noisy, h, l))
                        .await
                        .unwrap(),
                    DurableAdmission::Admitted { .. }
                ),
                "dial {i} is inside the connection ceiling"
            );
        }
        // 40 refusals — 20× the connection ceiling, and 4/5 of the tenant's whole
        // budget if any of them were charged.
        for i in 0..40 {
            let refused = admit(&pool, scope, req(session, noisy, h, l))
                .await
                .unwrap();
            let DurableAdmission::Refused(r) = refused else {
                panic!("refusal {i} must persist for the WHOLE window: {refused:?}");
            };
            assert_eq!(
                r.scope, SCOPE_CONNECTION,
                "refusal {i} came from the wrong dimension"
            );
        }
        assert_eq!(
            window_hits(&pool, scope, SCOPE_CONNECTION).await,
            2,
            "the refusing dimension must sit at its ceiling, not climb with refusals"
        );
        assert_eq!(
            window_hits(&pool, scope, SCOPE_TENANT).await,
            2,
            "40 refusals raised by the CONNECTION tier must not have charged the \
             org's shared tenant budget"
        );
        // …and the tenant budget really is intact: a SIBLING connection still has
        // its own ceiling and the org still has 48 of its 50.
        for i in 0..2 {
            assert!(
                matches!(
                    admit(&pool, scope, req(session, sibling, h, l))
                        .await
                        .unwrap(),
                    DurableAdmission::Admitted { .. }
                ),
                "sibling dial {i} must survive the noisy connection's refusals"
            );
        }
        assert_eq!(window_hits(&pool, scope, SCOPE_TENANT).await, 4);
    }

    #[tokio::test]
    async fn the_preflight_probe_proves_read_and_write_and_leaves_nothing_behind() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        preflight(&pool, scope).await.expect("the probe must pass");
        // Twice, because a probe that leaves a row behind would collide with itself
        // and because the second run must not see the first one's residue.
        preflight(&pool, scope).await.expect("idempotent");

        let mut tx = scoped_tx(&pool, scope).await.unwrap();
        let (windows,): (i64,) =
            sqlx::query_as("select count(*) from egress_rate_windows where tenant_id = $1")
                .bind(scope.tenant_id())
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        let (breakers,): (i64,) =
            sqlx::query_as("select count(*) from egress_breakers where tenant_id = $1")
                .bind(scope.tenant_id())
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            (windows, breakers),
            (0, 0),
            "the probe writes inside a transaction it ROLLS BACK — a probe that \
             leaves rows behind is a probe that pollutes the thing it measures"
        );

        // …and it passes AS THE ROLE PRODUCTION RUNS AS. `test_connect`'s pool sets
        // the system_worker bypass on every connection, so the run above proved the
        // statements are well-formed and nothing about privileges. This one runs
        // under `fluidbox_runtime` with RLS actually binding — i.e. it is the
        // assertion that 0023's enumerated DML grants reached that role, which is
        // the exact failure the probe exists to report.
        use sqlx::Executor;
        let as_runtime = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    conn.execute("set role fluidbox_runtime").await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .expect("runtime-role pool");
        preflight(&as_runtime, scope).await.expect(
            "the probe must pass for the deployment's runtime role — a \
                     failure here means 0023's DML grants did not reach it",
        );
    }

    #[tokio::test]
    async fn a_null_invoking_user_skips_the_user_tier_entirely() {
        // Trigger/schedule runs have no user (migration 0012:260). Bucketing them
        // under the nil uuid would give every unattended run in the org ONE shared
        // ceiling; the tier must be skipped instead.
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let unattended = seed_session(&pool, scope, None).await;
        let user = Uuid::now_v7();
        let attended = seed_session(&pool, scope, Some(user)).await;
        // User ceiling 1, everything else disabled.
        let l = limits(0, 1, 0, 0);
        let (c, h) = (Uuid::now_v7(), "sha256:host");

        for i in 0..25 {
            assert!(
                matches!(
                    admit(&pool, scope, req(unattended, c, h, l)).await.unwrap(),
                    DurableAdmission::Admitted { .. }
                ),
                "unattended dial {i} must not be charged to a user tier at all"
            );
        }
        assert_eq!(
            window_hits(&pool, scope, SCOPE_USER).await,
            0,
            "a user-less run must write NO user window row"
        );

        // The same ceiling binds hard the moment there IS a user.
        assert!(matches!(
            admit(&pool, scope, req(attended, c, h, l)).await.unwrap(),
            DurableAdmission::Admitted { .. }
        ));
        let refused = admit(&pool, scope, req(attended, c, h, l)).await.unwrap();
        let DurableAdmission::Refused(r) = refused else {
            panic!("the attended run's 2nd dial must hit the user ceiling: {refused:?}");
        };
        assert_eq!(r.scope, SCOPE_USER);
        // 1, not 2: the refused dial's own increment is rolled back with the rest of
        // its transaction, so the stored count sits AT the ceiling rather than
        // climbing past it with every refusal (module docs, "take-then-check, then
        // ROLL BACK"). It is still the value that keeps refusing — the next dial
        // increments 1 → 2 and re-crosses the ceiling of 1.
        assert_eq!(window_hits(&pool, scope, SCOPE_USER).await, 1);
        assert!(
            matches!(
                admit(&pool, scope, req(attended, c, h, l)).await.unwrap(),
                DurableAdmission::Refused(_)
            ),
            "and it keeps refusing after the rollback"
        );
    }

    #[tokio::test]
    async fn the_user_tier_binds_across_the_orgs_connections_and_hosts() {
        // The exact hole `governor.rs` deferred to Phase F: "one user can still
        // spread calls across an org's connections and consume the whole tenant
        // bucket". A per-connection ceiling cannot see it; the user tier can.
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let user = Uuid::now_v7();
        let session = seed_session(&pool, scope, Some(user)).await;
        // Connection/host ceilings roomy so ONLY the user tier can speak.
        let l = limits(0, 2, 50, 50);

        assert!(matches!(
            admit(&pool, scope, req(session, Uuid::now_v7(), "sha256:a", l))
                .await
                .unwrap(),
            DurableAdmission::Admitted { .. }
        ));
        assert!(matches!(
            admit(&pool, scope, req(session, Uuid::now_v7(), "sha256:b", l))
                .await
                .unwrap(),
            DurableAdmission::Admitted { .. }
        ));
        let refused = admit(&pool, scope, req(session, Uuid::now_v7(), "sha256:c", l))
            .await
            .unwrap();
        let DurableAdmission::Refused(r) = refused else {
            panic!("a third connection must not escape the user ceiling: {refused:?}");
        };
        assert_eq!(r.scope, SCOPE_USER);

        // A DIFFERENT user in the same org is untouched.
        let other = seed_session(&pool, scope, Some(Uuid::now_v7())).await;
        assert!(
            matches!(
                admit(&pool, scope, req(other, Uuid::now_v7(), "sha256:a", l))
                    .await
                    .unwrap(),
                DurableAdmission::Admitted { .. }
            ),
            "one user's exhaustion must not refuse a colleague"
        );
    }

    #[tokio::test]
    async fn durable_windows_never_leak_between_tenants() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let noisy = throwaway_tenant(&pool).await;
        let victim = throwaway_tenant(&pool).await;
        let ns = seed_session(&pool, noisy, None).await;
        let vs = seed_session(&pool, victim, None).await;
        // Deliberately the SAME connection id and host digest in both tenants —
        // only the tenant component of the key separates them.
        let (c, h) = (Uuid::now_v7(), "sha256:shared");
        let l = limits(0, 0, 1, 1);

        assert!(matches!(
            admit(&pool, noisy, req(ns, c, h, l)).await.unwrap(),
            DurableAdmission::Admitted { .. }
        ));
        assert!(matches!(
            admit(&pool, noisy, req(ns, c, h, l)).await.unwrap(),
            DurableAdmission::Refused(_)
        ));
        assert!(
            matches!(
                admit(&pool, victim, req(vs, c, h, l)).await.unwrap(),
                DurableAdmission::Admitted { .. }
            ),
            "another tenant's identical connection/host key must be a different bucket"
        );
    }

    #[tokio::test]
    async fn zero_everywhere_admits_everything() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let session = seed_session(&pool, scope, Some(Uuid::now_v7())).await;
        let l = limits(0, 0, 0, 0);
        let (c, h) = (Uuid::now_v7(), "sha256:host");
        for i in 0..50 {
            assert!(
                matches!(
                    admit(&pool, scope, req(session, c, h, l)).await.unwrap(),
                    DurableAdmission::Admitted { .. }
                ),
                "0 must mean disabled, not 0/min (dial {i})"
            );
        }
        assert_eq!(
            window_hits(&pool, scope, SCOPE_TENANT).await,
            0,
            "a fully disabled tier must not even write rows"
        );
    }

    #[tokio::test]
    async fn the_breaker_opens_and_elects_exactly_one_probe_deployment_wide() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let session = seed_session(&pool, scope, None).await;
        let l = breaker_limits(2, 60);
        let (c, h) = (Uuid::now_v7(), "sha256:sick");

        // Two consecutive transport failures open it.
        for _ in 0..2 {
            let a = admit(&pool, scope, req(session, c, h, l)).await.unwrap();
            let DurableAdmission::Admitted { probe_epoch } = a else {
                panic!("a closed breaker admits: {a:?}");
            };
            report(&pool, scope, c, h, false, probe_epoch, &l)
                .await
                .unwrap();
        }
        assert_eq!(breaker_state(&pool, scope).await.0, "open");
        let refused = admit(&pool, scope, req(session, c, h, l)).await.unwrap();
        let DurableAdmission::Refused(r) = refused else {
            panic!("an open breaker must refuse: {refused:?}");
        };
        assert_eq!(r.scope, SCOPE_BREAKER);
        assert!((1..=60).contains(&r.retry_after_secs));

        // One window later EXACTLY ONE caller is elected — every subsequent caller
        // is refused while that probe is live. This is the deployment-wide single
        // election: each `admit` here is an independent transaction, i.e. what a
        // second replica's call is.
        backdate_breaker(&pool, scope, 61).await;
        let a = admit(&pool, scope, req(session, c, h, l)).await.unwrap();
        let DurableAdmission::Admitted {
            probe_epoch: Some(epoch),
        } = a
        else {
            panic!("the first caller past the window must be elected the probe: {a:?}");
        };
        assert_eq!(epoch, 1, "the first election is epoch 1");
        for i in 0..5 {
            assert!(
                matches!(
                    admit(&pool, scope, req(session, c, h, l)).await.unwrap(),
                    DurableAdmission::Refused(_)
                ),
                "half-open must admit ONE probe, not {}",
                i + 2
            );
        }

        // The probe's success closes AND resets the consecutive count.
        report(&pool, scope, c, h, true, Some(epoch), &l)
            .await
            .unwrap();
        let (state, failures, _) = breaker_state(&pool, scope).await;
        assert_eq!((state.as_str(), failures), ("closed", 0));
        assert!(matches!(
            admit(&pool, scope, req(session, c, h, l)).await.unwrap(),
            DurableAdmission::Admitted { probe_epoch: None }
        ));
    }

    #[tokio::test]
    async fn only_the_matching_probe_epoch_may_transition_a_durable_breaker() {
        // A dial admitted BEFORE the breaker opened reports late. Its success must
        // not close a window it knows nothing about, and its failure must not
        // reopen one the real probe was about to close.
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let session = seed_session(&pool, scope, None).await;
        let l = breaker_limits(2, 60);
        let (c, h) = (Uuid::now_v7(), "sha256:sick");

        for _ in 0..2 {
            admit(&pool, scope, req(session, c, h, l)).await.unwrap();
            report(&pool, scope, c, h, false, None, &l).await.unwrap();
        }
        backdate_breaker(&pool, scope, 61).await;
        let DurableAdmission::Admitted {
            probe_epoch: Some(epoch),
        } = admit(&pool, scope, req(session, c, h, l)).await.unwrap()
        else {
            panic!("expected an election");
        };

        // (a) A straggler with NO epoch — an ordinary admission from before the
        //     breaker opened. Reports success: nothing moves.
        report(&pool, scope, c, h, true, None, &l).await.unwrap();
        assert_eq!(
            breaker_state(&pool, scope).await.0,
            "half_open",
            "an epoch-less success must not close a half-open breaker"
        );
        // (b) A straggler carrying a WRONG epoch — a probe from an earlier window.
        report(&pool, scope, c, h, true, Some(epoch + 99), &l)
            .await
            .unwrap();
        assert_eq!(
            breaker_state(&pool, scope).await.0,
            "half_open",
            "a mismatched epoch must not close a half-open breaker"
        );
        // (c) A straggler FAILURE must not reopen against the live probe either.
        report(&pool, scope, c, h, false, Some(epoch + 99), &l)
            .await
            .unwrap();
        assert_eq!(
            breaker_state(&pool, scope).await.0,
            "half_open",
            "a mismatched-epoch failure must not swallow the real probe's answer"
        );
        // (d) The real probe decides the window.
        report(&pool, scope, c, h, true, Some(epoch), &l)
            .await
            .unwrap();
        assert_eq!(breaker_state(&pool, scope).await.0, "closed");
    }

    #[tokio::test]
    async fn a_probe_failure_opens_a_full_fresh_window_and_a_lost_probe_cannot_wedge_it() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let session = seed_session(&pool, scope, None).await;
        let l = breaker_limits(2, 60);
        let (c, h) = (Uuid::now_v7(), "sha256:sick");

        for _ in 0..2 {
            admit(&pool, scope, req(session, c, h, l)).await.unwrap();
            report(&pool, scope, c, h, false, None, &l).await.unwrap();
        }
        backdate_breaker(&pool, scope, 61).await;
        let DurableAdmission::Admitted {
            probe_epoch: Some(epoch),
        } = admit(&pool, scope, req(session, c, h, l)).await.unwrap()
        else {
            panic!("expected an election");
        };
        // The probe FAILS ⇒ a fresh full window, not the remainder of the old one.
        report(&pool, scope, c, h, false, Some(epoch), &l)
            .await
            .unwrap();
        let refused = admit(&pool, scope, req(session, c, h, l)).await.unwrap();
        let DurableAdmission::Refused(r) = refused else {
            panic!("a failed probe must reopen: {refused:?}");
        };
        assert_eq!(r.retry_after_secs, 60, "a FULL fresh window");

        // A LOST probe (the elected replica died before reporting) must not wedge
        // the breaker half-open forever: one window later the next caller is
        // elected, with a fresh epoch.
        backdate_breaker(&pool, scope, 61).await;
        let DurableAdmission::Admitted {
            probe_epoch: Some(second),
        } = admit(&pool, scope, req(session, c, h, l)).await.unwrap()
        else {
            panic!("expected a second election");
        };
        backdate_breaker(&pool, scope, 61).await;
        let DurableAdmission::Admitted {
            probe_epoch: Some(third),
        } = admit(&pool, scope, req(session, c, h, l)).await.unwrap()
        else {
            panic!("a lost probe must not wedge the breaker shut");
        };
        assert!(
            third > second,
            "the takeover must mint a FRESH epoch ({third} must exceed {second}) — \
             otherwise the abandoned probe's late report could still decide the window"
        );
        // …and the abandoned probe's late report is now inert.
        report(&pool, scope, c, h, true, Some(second), &l)
            .await
            .unwrap();
        assert_eq!(breaker_state(&pool, scope).await.0, "half_open");
    }

    #[tokio::test]
    async fn a_breaker_refusal_charges_no_durable_rate_window() {
        // Without the rollback, ONE sick upstream would burn its org's shared
        // per-minute budget and throttle every OTHER connection the org owns. The
        // local governor has the same property and the same test.
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let session = seed_session(&pool, scope, None).await;
        let l = DurableLimits {
            tenant_per_min: 50,
            user_per_min: 0,
            connection_per_min: 0,
            host_per_min: 0,
            breaker_threshold: 2,
            breaker_open_secs: 60,
        };
        let (sick, healthy) = (Uuid::now_v7(), Uuid::now_v7());
        let h = "sha256:sick";

        for _ in 0..2 {
            admit(&pool, scope, req(session, sick, h, l)).await.unwrap();
            report(&pool, scope, sick, h, false, None, &l)
                .await
                .unwrap();
        }
        assert_eq!(window_hits(&pool, scope, SCOPE_TENANT).await, 2);

        // 20 breaker refusals — none may charge the shared tenant window.
        for i in 0..20 {
            let refused = admit(&pool, scope, req(session, sick, h, l)).await.unwrap();
            let DurableAdmission::Refused(r) = refused else {
                panic!("refusal {i} should have come from the breaker: {refused:?}");
            };
            assert_eq!(r.scope, SCOPE_BREAKER);
        }
        assert_eq!(
            window_hits(&pool, scope, SCOPE_TENANT).await,
            2,
            "a breaker refusal must roll its rate charge back — 20 refusals from ONE \
             sick upstream must not drain the org's shared budget"
        );
        // FALSE-GREEN guard: the window IS charged by admitted dials, so the
        // constant above is a rollback and not "nothing is ever charged".
        assert!(matches!(
            admit(&pool, scope, req(session, healthy, "sha256:ok", l))
                .await
                .unwrap(),
            DurableAdmission::Admitted { .. }
        ));
        assert_eq!(window_hits(&pool, scope, SCOPE_TENANT).await, 3);
    }

    #[tokio::test]
    async fn the_sweep_is_bounded_and_collects_aged_rows_including_open_breakers() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let session = seed_session(&pool, scope, None).await;
        let l = DurableLimits {
            tenant_per_min: 100,
            user_per_min: 0,
            connection_per_min: 100,
            host_per_min: 100,
            breaker_threshold: 2,
            breaker_open_secs: 60,
        };
        let (sick, quiet) = (Uuid::now_v7(), Uuid::now_v7());
        // A breaker that went OPEN, and a clean one.
        for _ in 0..2 {
            admit(&pool, scope, req(session, sick, "sha256:sick", l))
                .await
                .unwrap();
            report(&pool, scope, sick, "sha256:sick", false, None, &l)
                .await
                .unwrap();
        }
        admit(&pool, scope, req(session, quiet, "sha256:quiet", l))
            .await
            .unwrap();
        report(&pool, scope, quiet, "sha256:quiet", true, None, &l)
            .await
            .unwrap();

        // Nothing is stale yet.
        assert_eq!(sweep(&pool, scope, 3600, 1000).await.unwrap(), 0);
        // Age everything by an hour, then sweep with a 30-minute idle threshold.
        {
            let mut tx = scoped_tx(&pool, scope).await.unwrap();
            sqlx::query(
                "update egress_rate_windows set window_start = window_start - interval '1 hour'
                  where tenant_id = $1",
            )
            .bind(scope.tenant_id())
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query(
                "update egress_breakers set updated_at = updated_at - interval '1 hour'
                  where tenant_id = $1",
            )
            .bind(scope.tenant_id())
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        // THE BOUND MUST BIND. There are exactly 5 collectable rate windows here
        // (tenant ×1, connection ×2, host ×2) and — now that an AGED open breaker is
        // eligible (see `SWEEP`) — 2 collectable breakers (`quiet` closed, `sick`
        // open), all aged an hour past the 30-min `idle`. `limit` of 2 drains them
        // over three passes: 2 windows + 2 breakers, then 2 windows, then 1 window.
        // An earlier version passed `1000` against 6 rows, which made the whole
        // `limit` clause deletable with the test still green: "bounded" is the
        // property, and an unbounded DELETE holding locks over a large backlog is
        // precisely what it exists to prevent.
        assert_eq!(
            sweep(&pool, scope, 1800, 2).await.unwrap(),
            4,
            "pass 1 must cap at 2 windows + 2 breakers"
        );
        assert_eq!(
            sweep(&pool, scope, 1800, 2).await.unwrap(),
            2,
            "pass 2 must cap at 2 windows (both breakers already gone)"
        );
        assert_eq!(
            sweep(&pool, scope, 1800, 2).await.unwrap(),
            1,
            "pass 3 drains the remainder"
        );
        assert_eq!(
            sweep(&pool, scope, 1800, 2).await.unwrap(),
            0,
            "a drained tenant sweeps nothing"
        );
        assert_eq!(window_hits(&pool, scope, SCOPE_TENANT).await, 0);
        // BOTH aged breakers are gone — the abandoned-open-row leak is closed. The
        // separate `a_recent_open_breaker_is_never_swept` proves the flip side: a
        // breaker whose `updated_at` is recent (live protection) survives.
        let mut tx = scoped_tx(&pool, scope).await.unwrap();
        let (rows,): (i64,) =
            sqlx::query_as("select count(*) from egress_breakers where tenant_id = $1")
                .bind(scope.tenant_id())
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(rows, 0, "every aged breaker row must be collected");
    }

    /// The flip side of the abandoned-open-row fix: a breaker whose `updated_at` is
    /// RECENT — a live protection on an endpoint still being dialed — must survive
    /// the sweep. Only TIME distinguishes "abandoned" from "live", so this proves
    /// the sweep never forgets a protection that could still be doing work.
    #[tokio::test]
    async fn a_recent_open_breaker_is_never_swept() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let scope = throwaway_tenant(&pool).await;
        let session = seed_session(&pool, scope, None).await;
        let l = DurableLimits {
            tenant_per_min: 100,
            user_per_min: 0,
            connection_per_min: 100,
            host_per_min: 100,
            breaker_threshold: 2,
            breaker_open_secs: 60,
        };
        let live = Uuid::now_v7();
        for _ in 0..2 {
            admit(&pool, scope, req(session, live, "sha256:live", l))
                .await
                .unwrap();
            report(&pool, scope, live, "sha256:live", false, None, &l)
                .await
                .unwrap();
        }
        // NOT aged: its `updated_at` is now(). A generous idle grace still spares it.
        let collected = sweep(&pool, scope, 1800, 100).await.unwrap();
        let (state, _, _) = breaker_state(&pool, scope).await;
        assert_eq!(
            state, "open",
            "a recent open breaker is a live protection and must survive; swept {collected}"
        );
    }

    #[tokio::test]
    async fn rls_isolates_egress_governance_between_tenants() {
        // Migration 0023 owns the full 0018 triple for two NEW tenant-owned tables.
        // The assertions run as the NON-owner `fluidbox_runtime` role, because a
        // SUPERUSER/BYPASSRLS role (CI's `postgres`, Neon's default) skips every
        // policy and would make this test pass while proving nothing.
        use sqlx::{Connection, Executor};
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = test_connect(&url).await.expect("connect");
        let a = throwaway_tenant(&pool).await;
        let b = throwaway_tenant(&pool).await;
        let l = DurableLimits {
            tenant_per_min: 100,
            user_per_min: 0,
            connection_per_min: 100,
            host_per_min: 100,
            breaker_threshold: 2,
            breaker_open_secs: 60,
        };
        for scope in [a, b] {
            let session = seed_session(&pool, scope, None).await;
            let c = Uuid::now_v7();
            admit(&pool, scope, req(session, c, "sha256:rls", l))
                .await
                .unwrap();
            report(&pool, scope, c, "sha256:rls", false, None, &l)
                .await
                .unwrap();
        }

        let mut rt = sqlx::PgConnection::connect(&url).await.expect("rt connect");
        rt.execute("set role fluidbox_runtime")
            .await
            .expect("set role");
        async fn count_as(rt: &mut sqlx::PgConnection, tenant: Uuid, sql: &'static str) -> i64 {
            let mut tx = rt.begin().await.unwrap();
            sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
                .bind(tenant.to_string())
                .execute(&mut *tx)
                .await
                .unwrap();
            let (n,): (i64,) = sqlx::query_as(sql).fetch_one(&mut *tx).await.unwrap();
            tx.rollback().await.ok();
            n
        }
        // No WHERE clause anywhere below: the policy is the only thing filtering.
        assert_eq!(
            count_as(
                &mut rt,
                a.tenant_id(),
                "select count(*) from egress_rate_windows"
            )
            .await,
            3,
            "A-scope must see exactly its own three rate windows"
        );
        assert_eq!(
            count_as(
                &mut rt,
                a.tenant_id(),
                "select count(*) from egress_breakers"
            )
            .await,
            1,
            "A-scope must see exactly its own breaker"
        );
        // The write side is bound too: a WITH CHECK violation, not a silent
        // cross-tenant insert.
        let mut tx = rt.begin().await.unwrap();
        sqlx::query("select set_config('fluidbox.tenant_id', $1, true)")
            .bind(a.tenant_id().to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        let refused = sqlx::query(
            "insert into egress_rate_windows (tenant_id, scope, subject, window_start, hits)
             values ($1, 'tenant', 'x', now(), 1)",
        )
        .bind(b.tenant_id())
        .execute(&mut *tx)
        .await;
        assert!(
            refused.is_err(),
            "A-scope must not be able to insert a row into tenant B"
        );
        tx.rollback().await.ok();
    }
}
