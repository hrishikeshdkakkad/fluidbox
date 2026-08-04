//! Governed sandbox network access: the grant domain.
//!
//! A **`NetworkGrant`** is the frozen, immutable answer to "where may this run
//! connect?" — resolved BEFORE any sandbox exists, stored in the `RunSpec`, and
//! enforced in the datapath (Kubernetes: Cilium L3/L4). A sandbox can never
//! widen one: the grant is in the frozen spec and the enforcement is below the
//! application, so there is nothing to opt into or around.
//!
//! Three things about this module are load-bearing.
//!
//! **Authority is epoch-scoped.** A session already *is* an epoch — fresh
//! sandbox, freshly minted credentials, policy read at creation. A grant binds
//! to one epoch and cannot outlive it. [`NetworkGrant::expires_at`] is
//! ABSOLUTE and the struct is [`SCHEMA_VERSION`]-stamped, so a later effort can
//! introduce a shorter epoch clock (expiry → quiesce → checkpoint → continue)
//! without redesigning anything here. In THIS effort the expiry is validated to
//! cover the run's own wall-clock deadline, so it never fires mid-run.
//!
//! **Lowering is total.** [`FqdnPattern`] is shaped to EXACTLY Cilium's
//! `toFQDNs` expressiveness — `matchName` and a single-label `matchPattern` —
//! and [`FqdnPattern::validate`] enforces the CRD's own character class. There
//! is deliberately no pattern this type can express that the datapath cannot
//! enforce, so a grant that resolves can always be rendered; a grant that
//! cannot be rendered is refused HERE, at resolution, with a reason.
//!
//! **Deny precedence is a documented total order**, not an emergent property of
//! evaluation order. The order the code actually runs, in full:
//!
//! 0. `offline` short-circuits to Active — the absence of authority needs no
//!    enforcer and no policy, which is what keeps every pre-existing run working
//! 1. enforceability (`Unenforceable`)
//! 2. structural validity (`InvalidTarget`) and blocked ranges (`BlockedRange`)
//! 3. explicit policy deny
//! 4. mode ceiling
//! 5. `public` + brokered surfaces
//! 6. a deny the datapath cannot express for this mode
//! 7. target-catalog subset
//! 8. expiry (clamped first; refuses if it would lapse before the run)
//! 9. approval requirement, else allow
//!
//! An earlier revision of this list omitted 0, 1 and 7, which an adversarial
//! review caught: the documentation claimed an order the implementation did not
//! have. `deny_precedence_total_order` proves the ranked part pairwise.
//!
//! ## What this module does NOT decide
//!
//! Whether the deployment can *enforce* a grant is a provider question
//! (`NetworkPolicyProvider`), answered by the caller and folded in as
//! [`DenialReason::Unenforceable`]. Keeping the pure order here and the
//! capability question there is what lets a cluster without an enforcer be
//! offline-only and fail closed without this module knowing what a cluster is.

use crate::netpolicy::IpCidr;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::net::IpAddr;

/// Stamped into every grant. Bump ONLY for a change that alters what an
/// existing frozen grant MEANS — a new field with a fail-safe default does not
/// qualify. Consumers refuse a version they do not know rather than guessing.
pub const SCHEMA_VERSION: u32 = 1;

/// Grant lifetime when neither the policy ceiling nor the request bounds it.
/// Comfortably exceeds the default run wall clock (1800 s, `Budgets::default`)
/// so the covering check below does not refuse an otherwise ordinary run.
pub const DEFAULT_GRANT_SECS: u64 = 3600;

// ─── Mode ─────────────────────────────────────────────────────────────────

/// How much network a run may have. **Declaration order IS the ceiling order**
/// (`Offline < Approved < Public`) — the derived `Ord` is what
/// [`NetworkPolicy::max_mode`] compares against, and
/// `mode_order_is_the_ceiling_order` pins it so a reordering of these variants
/// cannot silently widen every policy in the fleet.
///
/// Named `NetworkGrantMode`, not `NetworkMode`: `traits::NetworkMode` already
/// exists and means something else entirely (how the SANDBOX is attached —
/// `HostDev` vs `Hardened`). Two types called the same thing at two layers is
/// how a lowering bug gets written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkGrantMode {
    /// No egress beyond the standing control-plane allow. Byte-identical in
    /// effect to today's `zeroEgress`: default-deny by absence-of-allow.
    #[default]
    Offline,
    /// Exactly the grant's targets, and nothing else.
    Approved,
    /// Everything the deployment's deny wall does not forbid.
    Public,
}

impl NetworkGrantMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Approved => "approved",
            Self::Public => "public",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "offline" => Self::Offline,
            "approved" => Self::Approved,
            "public" => Self::Public,
            _ => return None,
        })
    }

    /// Does this mode reach anything beyond the standing control-plane allow?
    pub fn grants_egress(&self) -> bool {
        !matches!(self, Self::Offline)
    }
}

// ─── L4 ───────────────────────────────────────────────────────────────────

/// Transport a target rule covers. Deliberately NOT an `Any` variant: a grant
/// names one transport so that "UDP/QUIC to a TCP-granted host" is a denial the
/// bypass matrix can assert, rather than an accident of a permissive default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L4Protocol {
    Tcp,
    Udp,
}

impl L4Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

/// An inclusive port range. A single port is `from == to`; the wire form keeps
/// both so lowering to Cilium's `{port, endPort}` is mechanical.
/// NOT `deny_unknown_fields`, deliberately.
///
/// This type is shared by the STORED representation (frozen RunSpecs and
/// stored policy blobs) and the authoring path. Making it strict made stored
/// blobs strict at the same boundary, so a row that had legitimately been
/// accepted with an extra key would suddenly fail to deserialize — stranding a
/// policy that is already governing runs, which is the one thing the lenient
/// stored shape exists to prevent. Authoring strictness belongs in the
/// `Draft*` mirrors in `policy.rs`, where it cannot reach stored data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortSpec {
    pub from: u16,
    pub to: u16,
}

impl PortSpec {
    pub fn single(p: u16) -> Self {
        Self { from: p, to: p }
    }

    pub fn range(from: u16, to: u16) -> Self {
        Self { from, to }
    }

    /// Port 0 is not a destination; an inverted range would silently match
    /// nothing (or, lowered, everything) so it is refused rather than clamped.
    pub fn validate(&self) -> Result<(), String> {
        if self.from == 0 || self.to == 0 {
            return Err("port 0 is not a valid destination".into());
        }
        if self.from > self.to {
            return Err(format!(
                "port range {}-{} is inverted (from must be <= to)",
                self.from, self.to
            ));
        }
        Ok(())
    }

    pub fn contains_range(&self, other: &PortSpec) -> bool {
        self.from <= other.from && other.to <= self.to
    }

    /// Do these ranges share ANY port? Distinct from [`Self::contains_range`],
    /// and the distinction is a security boundary: containment answers "is this
    /// wholly permitted", overlap answers "does this touch the forbidden".
    pub fn intersects(&self, other: &PortSpec) -> bool {
        self.from <= other.to && other.from <= self.to
    }
}

// ─── FQDN patterns ────────────────────────────────────────────────────────

/// A DNS target, shaped to EXACTLY what Cilium's `toFQDNs` can enforce.
///
/// `Wildcard` is a SINGLE-label wildcard because that is what Cilium's
/// `matchPattern` actually does: its `*` lowers to `[-a-zA-Z0-9_]*`, which
/// cannot cross a dot. So `Wildcard("example.com")` matches `api.example.com`
/// but NOT `a.b.example.com` and NOT the bare `example.com` — a run that needs
/// the apex as well must name it too. Modelling this honestly is the point: a
/// multi-label wildcard type would look like it worked and quietly under-grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FqdnPattern {
    /// Lowers to `matchName`.
    Exact { name: String },
    /// Lowers to `matchPattern: "*.{suffix}"`.
    Wildcard { suffix: String },
}

/// The character class Cilium's CRD enforces on `matchName`
/// (`^([-a-zA-Z0-9_]+[.]?)+$`, observed directly from an API-server rejection
/// during the Phase 0 spike). Validating it HERE means a resolvable grant can
/// always be written to the API — a rejection at apply time would be a run that
/// fails after provisioning instead of a refusal that never starts one.
fn valid_dns_charset(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

impl FqdnPattern {
    /// Case-folded, trailing-dot-normalized form — DNS is case-insensitive and
    /// `example.com.` and `example.com` are the same name, so both must digest
    /// and compare identically or an approver could consent to one spelling and
    /// get another.
    pub fn normalized(&self) -> Self {
        fn norm(s: &str) -> String {
            s.trim_end_matches('.').to_ascii_lowercase()
        }
        match self {
            Self::Exact { name } => Self::Exact { name: norm(name) },
            Self::Wildcard { suffix } => Self::Wildcard {
                suffix: norm(suffix),
            },
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        let (what, value) = match self {
            Self::Exact { name } => ("dns name", name),
            Self::Wildcard { suffix } => ("dns wildcard suffix", suffix),
        };
        let normalized = value.trim_end_matches('.').to_ascii_lowercase();
        if !valid_dns_charset(&normalized) {
            return Err(format!(
                "{what} {value:?} is not a valid DNS name (labels of [-a-zA-Z0-9_], \
                 <=63 bytes each, <=253 total)"
            ));
        }
        if normalized.contains('*') {
            return Err(format!(
                "{what} {value:?} must not contain '*' — use the wildcard variant, \
                 which lowers to a single-label matchPattern"
            ));
        }
        if matches!(self, Self::Wildcard { .. }) && !normalized.contains('.') {
            return Err(format!(
                "dns wildcard suffix {value:?} must have at least two labels — \
                 a wildcard over a bare TLD is never a deliberate grant"
            ));
        }
        Ok(())
    }

    /// Does this pattern's matched set contain `other`'s? Wildcards cover only
    /// the exact single-label names they match, and cover another wildcard only
    /// when identical (`*.a.com` does not match `x.b.a.com`, so it cannot cover
    /// `*.b.a.com`).
    pub fn covers(&self, other: &FqdnPattern) -> bool {
        match (&self.normalized(), &other.normalized()) {
            (Self::Exact { name: a }, Self::Exact { name: b }) => a == b,
            (Self::Wildcard { suffix }, Self::Exact { name }) => name
                .strip_suffix(suffix)
                .and_then(|p| p.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.')),
            (Self::Wildcard { suffix: a }, Self::Wildcard { suffix: b }) => a == b,
            (Self::Exact { .. }, Self::Wildcard { .. }) => false,
        }
    }

    /// Do these patterns match any name in common?
    ///
    /// For DENY evaluation, where the question is "does the request touch
    /// anything forbidden", not "is the request wholly forbidden". A wildcard
    /// matches exactly one label, so two DIFFERENT wildcards never intersect
    /// (`*.a.com` matches `x.a.com`; `*.b.a.com` matches `x.b.a.com`; no name
    /// is in both).
    pub fn intersects(&self, other: &FqdnPattern) -> bool {
        self.covers(other) || other.covers(self)
    }

    /// Display form, and the exact string that lowers into a Cilium selector.
    pub fn as_selector(&self) -> String {
        match self.normalized() {
            Self::Exact { name } => name,
            Self::Wildcard { suffix } => format!("*.{suffix}"),
        }
    }
}

// ─── Target rules ─────────────────────────────────────────────────────────

/// `IpCidr` has no serde impls (it is a pure predicate helper), and a grant is
/// frozen into jsonb. Serializing the canonical `addr/prefix` string keeps ONE
/// encoding: what a human reads in the audit trail is what reparses.
mod cidr_serde {
    use super::*;

    pub fn serialize<S: Serializer>(c: &IpCidr, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(c)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<IpCidr, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// One place a run may connect. `Dns` and `Cidr` are distinct selectors in the
/// datapath (name-derived identities versus CIDR identities), so neither ever
/// covers the other — a DNS grant is not an IP grant even when the name
/// currently resolves to that IP.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetRule {
    Dns {
        pattern: FqdnPattern,
        ports: Vec<PortSpec>,
        protocol: L4Protocol,
    },
    Cidr {
        #[serde(with = "cidr_serde")]
        cidr: IpCidr,
        ports: Vec<PortSpec>,
        protocol: L4Protocol,
    },
}

impl TargetRule {
    pub fn dns(pattern: FqdnPattern, ports: Vec<PortSpec>, protocol: L4Protocol) -> Self {
        Self::Dns {
            pattern,
            ports,
            protocol,
        }
    }

    pub fn cidr(cidr: IpCidr, ports: Vec<PortSpec>, protocol: L4Protocol) -> Self {
        Self::Cidr {
            cidr,
            ports,
            protocol,
        }
    }

    pub fn ports(&self) -> &[PortSpec] {
        match self {
            Self::Dns { ports, .. } | Self::Cidr { ports, .. } => ports,
        }
    }

    pub fn protocol(&self) -> L4Protocol {
        match self {
            Self::Dns { protocol, .. } | Self::Cidr { protocol, .. } => *protocol,
        }
    }

    /// Human/ledger form — stable, and never anything but the target itself
    /// (targets are operator-authored, but they still ride into events).
    pub fn describe(&self) -> String {
        let ports = self
            .ports()
            .iter()
            .map(|p| {
                if p.from == p.to {
                    p.from.to_string()
                } else {
                    format!("{}-{}", p.from, p.to)
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        let what = match self {
            Self::Dns { pattern, .. } => pattern.as_selector(),
            Self::Cidr { cidr, .. } => cidr.to_string(),
        };
        format!("{what} {}/{ports}", self.protocol().as_str())
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Dns { pattern, .. } => pattern.validate()?,
            Self::Cidr { .. } => {}
        }
        if self.ports().is_empty() {
            return Err(format!(
                "target {} names no ports — an all-ports grant must say so explicitly \
                 as 1-65535",
                match self {
                    Self::Dns { pattern, .. } => pattern.as_selector(),
                    Self::Cidr { cidr, .. } => cidr.to_string(),
                }
            ));
        }
        for p in self.ports() {
            p.validate()?;
        }
        Ok(())
    }

    /// Does this rule share ANY (destination, port) with `other`?
    ///
    /// **This is what a DENY must be evaluated with, and using `covers` there
    /// was a real bypass.** `covers` is set containment, so a deny of
    /// `*.example.com TCP/443-444` versus a request for
    /// `api.example.com TCP/80-443` compared false in BOTH directions — the
    /// deny's selector is wider but its ports are narrower, the request's ports
    /// are wider but its selector is narrower, so neither contains the other —
    /// and the grant was issued INCLUDING the explicitly denied port 443.
    /// Overlap is the correct relation: a request that touches any forbidden
    /// (destination, port) is forbidden.
    ///
    /// DNS and CIDR rules never intersect, matching the rest of the model: they
    /// are different selectors in the datapath, and grant-time code cannot know
    /// what a name will resolve to. A CIDR deny is enforced by the datapath
    /// wall, not here.
    pub fn intersects(&self, other: &TargetRule) -> bool {
        if self.protocol() != other.protocol() {
            return false;
        }
        let selectors_meet = match (self, other) {
            (Self::Dns { pattern: a, .. }, Self::Dns { pattern: b, .. }) => a.intersects(b),
            (Self::Cidr { cidr: a, .. }, Self::Cidr { cidr: b, .. }) => {
                a.contains(b.addr) || b.contains(a.addr)
            }
            _ => false,
        };
        selectors_meet
            && self
                .ports()
                .iter()
                .any(|p| other.ports().iter().any(|q| p.intersects(q)))
    }

    /// Does this rule authorize everything `other` authorizes? Used BOTH for
    /// the policy target-catalog subset check and for downstream narrowing, so
    /// the two can never disagree about what "narrower" means.
    pub fn covers(&self, other: &TargetRule) -> bool {
        if self.protocol() != other.protocol() {
            return false;
        }
        let selector_covers = match (self, other) {
            (Self::Dns { pattern: a, .. }, Self::Dns { pattern: b, .. }) => a.covers(b),
            (Self::Cidr { cidr: a, .. }, Self::Cidr { cidr: b, .. }) => {
                a.prefix <= b.prefix && a.contains(b.addr)
            }
            _ => false,
        };
        selector_covers
            && other
                .ports()
                .iter()
                .all(|p| self.ports().iter().any(|q| q.contains_range(p)))
    }
}

// ─── Structural deny: the blocked classes, as CIDRs ───────────────────────

/// The blocked classes of [`ip_blocked`], written as CIDRs so a *range* can be
/// judged without enumerating it.
///
/// There are deliberately TWO encodings of one policy — the address predicate
/// in `netpolicy` and this list — because they answer different questions
/// ("is this address blocked?" versus "does this range contain a blocked
/// address?"). `blocked_cidrs_agree_with_ip_blocked` sweeps a structured
/// address corpus through both and fails if they ever disagree, which is what
/// keeps the duplication honest instead of a drift waiting to happen.
const BLOCKED_V4: &[&str] = &[
    "0.0.0.0/8",       // "this network" (incl. unspecified)
    "10.0.0.0/8",      // RFC1918
    "100.64.0.0/10",   // CGNAT
    "127.0.0.0/8",     // loopback
    "169.254.0.0/16",  // link-local, incl. the cloud metadata endpoint
    "172.16.0.0/12",   // RFC1918
    "192.0.0.0/24",    // IETF protocol assignments
    "192.0.2.0/24",    // documentation (TEST-NET-1)
    "192.168.0.0/16",  // RFC1918
    "198.18.0.0/15",   // benchmarking
    "198.51.100.0/24", // documentation (TEST-NET-2)
    "203.0.113.0/24",  // documentation (TEST-NET-3)
    "224.0.0.0/4",     // multicast
    "240.0.0.0/4",     // reserved, incl. 255.255.255.255 broadcast
];

const BLOCKED_V6: &[&str] = &[
    "::/128",        // unspecified
    "::1/128",       // loopback
    "fc00::/7",      // unique-local
    "fe80::/10",     // link-local
    "fec0::/10",     // site-local (deprecated)
    "ff00::/8",      // multicast
    "2001:db8::/32", // documentation
];

/// The v6 prefixes that really address an IPv4 host, mirroring
/// `netpolicy::embedded_ipv4`. A grant inside one of these decides on its v4
/// form, so `::ffff:8.8.8.8/128` is admitted while `::ffff:0:0/96` (which spans
/// all of v4, including RFC1918) is refused.
const V4_EMBEDDING_V6: &[&str] = &[
    "::/96",         // v4-compatible
    "::ffff:0:0/96", // v4-mapped
    "64:ff9b::/96",  // well-known NAT64
];

fn parse_all(list: &[&str]) -> Vec<IpCidr> {
    list.iter()
        .map(|s| s.parse().expect("blocked-class CIDR literal must parse"))
        .collect()
}

/// Two aligned prefixes overlap iff either contains the other's network
/// address — there is no partial-overlap case for CIDRs.
fn overlaps(a: &IpCidr, b: &IpCidr) -> bool {
    a.contains(b.addr) || b.contains(a.addr)
}

/// Does this CIDR grant reach ANY address [`ip_blocked`] forbids?
///
/// This is the structural deny — the first and highest-precedence rule in
/// [`resolve_network_grant`]. It is defence in depth, not the boundary: the
/// datapath deny wall forbids these ranges regardless of what resolution
/// computed. Its real value is a refusal at create time, naming the range,
/// instead of a run that starts and then mysteriously cannot connect.
///
/// **Scope, stated honestly:** this judges CIDR targets only. A DNS target that
/// *resolves* into blocked space cannot be caught here — nothing at grant time
/// knows a future DNS answer. That case is the datapath wall's job, and the
/// residual it leaves (the rebinding window) is documented in the threat model.
pub fn cidr_grants_blocked(c: &IpCidr) -> bool {
    let blocked = match c.addr {
        IpAddr::V4(_) => BLOCKED_V4,
        IpAddr::V6(a) => {
            for e in parse_all(V4_EMBEDDING_V6) {
                if !overlaps(&e, c) {
                    continue;
                }
                // Fully inside an embedding prefix: decide on the embedded v4.
                if c.prefix >= 96 && e.contains(c.addr) {
                    let s = a.segments();
                    let v4 = std::net::Ipv4Addr::from((u32::from(s[6]) << 16) | u32::from(s[7]));
                    return cidr_grants_blocked(&IpCidr {
                        addr: IpAddr::V4(v4),
                        prefix: c.prefix - 96,
                    });
                }
                // Spans an embedding range: it contains embedded RFC1918 and
                // metadata space, whatever its own network address looks like.
                return true;
            }
            BLOCKED_V6
        }
    };
    parse_all(blocked).iter().any(|b| overlaps(b, c))
}

// ─── The policy section ───────────────────────────────────────────────────

/// The `network:` section of a [`crate::policy::Policy`] — the CAP, never the
/// grant. Every field's default is the fail-safe one: a policy that says
/// nothing about the network grants nothing, so enabling sandbox egress is
/// always a deliberate, auditable policy edit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct NetworkPolicy {
    /// The most a run under this policy may have. Default `offline`.
    #[serde(default)]
    pub max_mode: NetworkGrantMode,
    /// The target catalog: a requested target must be COVERED by one of these.
    /// Empty means no target is grantable, which is what makes `approved` mode
    /// inert until an operator populates it.
    #[serde(default)]
    pub allow: Vec<TargetRule>,
    /// Explicit denies, evaluated ABOVE the catalog and above the mode.
    #[serde(default)]
    pub deny: Vec<TargetRule>,
    /// Does a grant that clears every other rule still need a human?
    #[serde(default)]
    pub require_approval: bool,
    /// `public` + brokered surfaces is refused unless this is set — the
    /// dangerous pairing is credentials plus reach, and a run holding brokered
    /// tool results with unrestricted egress is exactly that. Follows the
    /// `TrustTier::ReadOnly` precedent of refusing rather than degrading.
    #[serde(default)]
    pub allow_public_with_brokered: bool,
    /// Ceiling on grant lifetime. `None` = [`DEFAULT_GRANT_SECS`].
    #[serde(default)]
    pub max_grant_secs: Option<u64>,
}

impl NetworkPolicy {
    /// Digest of the governing section, frozen into the grant so the approval
    /// decision path can tell "the policy changed under me" from "it did not"
    /// without re-deriving the whole document.
    pub fn digest(&self) -> String {
        crate::event::digest_json(&serde_json::to_value(self).unwrap_or(Value::Null))
    }

    pub fn validate(&self) -> Result<(), String> {
        for (i, t) in self.allow.iter().enumerate() {
            t.validate()
                .map_err(|e| format!("network.allow[{i}]: {e}"))?;
        }
        for (i, t) in self.deny.iter().enumerate() {
            t.validate()
                .map_err(|e| format!("network.deny[{i}]: {e}"))?;
        }
        Ok(())
    }
}

// ─── The request ──────────────────────────────────────────────────────────

/// What an agent revision DECLARES it needs, and what a subscription or
/// per-run override may narrow it to. Narrowing is remove-only
/// ([`NetworkRequest::narrowed_by`]), mirroring `Budgets::tightened_by` and the
/// remove-only bundle keep-list: without a declaration on the revision, every
/// scheduled and webhook-triggered run would be offline-only, because a
/// schedule has no caller to pass a request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct NetworkRequest {
    #[serde(default)]
    pub mode: NetworkGrantMode,
    #[serde(default)]
    pub targets: Vec<TargetRule>,
    /// Requested lifetime. Clamped by the policy ceiling; may only shorten.
    #[serde(default)]
    pub duration_secs: Option<u64>,
}

impl NetworkRequest {
    pub fn offline() -> Self {
        Self::default()
    }

    /// Apply a downstream override. The result can only be NARROWER: the mode
    /// takes the minimum, a requested target survives only if the base already
    /// covered it, and the duration takes the minimum. An override naming a
    /// target the base never had is DROPPED, not honoured — the same
    /// remove-only shape as `narrow_bundles`, for the same reason.
    pub fn narrowed_by(&self, override_: Option<&NetworkRequest>) -> NetworkRequest {
        let Some(o) = override_ else {
            return self.clone();
        };
        NetworkRequest {
            mode: self.mode.min(o.mode),
            targets: o
                .targets
                .iter()
                .filter(|t| self.targets.iter().any(|base| base.covers(t)))
                .cloned()
                .collect(),
            duration_secs: match (self.duration_secs, o.duration_secs) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, b) => b,
            },
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        for (i, t) in self.targets.iter().enumerate() {
            t.validate().map_err(|e| format!("targets[{i}]: {e}"))?;
        }
        if self.mode == NetworkGrantMode::Public && !self.targets.is_empty() {
            return Err(
                "a public grant must not carry targets — public is 'everything the deny \
                 wall permits', and listing targets beside it reads as a narrowing that \
                 the datapath would not apply"
                    .into(),
            );
        }
        Ok(())
    }
}

// ─── The grant ────────────────────────────────────────────────────────────

/// The frozen answer, stored in the `RunSpec`. Immutable for the life of the
/// run: a policy edit after freezing governs only FUTURE runs, which is what
/// makes `approvals.input_digest == grant.digest()` a stable thing for a human
/// to consent to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkGrant {
    pub schema_version: u32,
    pub mode: NetworkGrantMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<TargetRule>,
    /// ABSOLUTE expiry. `None` only for `offline`, which has no authority to
    /// expire. Validated at resolution to cover the run's wall-clock deadline,
    /// so it never fires mid-run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Digest of the `NetworkPolicy` section that produced this grant.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy_digest: String,
    /// The governing policy's explicit denies, FROZEN so the datapath can
    /// enforce them rather than resolution merely checking them.
    ///
    /// Resolution alone was not enough: it iterates the REQUESTED targets, and
    /// a `public` request has none by construction — so every `network.deny`
    /// entry was skipped and `public` lowered to "the world minus the
    /// deployment-wide wall", silently ignoring the tenant's own denies. A
    /// policy that says "public, but never this corporate range" was not
    /// getting the second half.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<TargetRule>,
}

impl Default for NetworkGrant {
    /// What every pre-network frozen `RunSpec` deserializes to: no authority,
    /// no expiry, no governing policy recorded. Historical runs were offline
    /// and must read as offline forever.
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            mode: NetworkGrantMode::Offline,
            targets: Vec::new(),
            expires_at: None,
            policy_digest: String::new(),
            denied: Vec::new(),
        }
    }
}

impl NetworkGrant {
    pub fn offline() -> Self {
        Self::default()
    }

    /// The consent anchor. Computed over the canonical JSON of the whole grant
    /// rather than stored in it — a stored digest is one that can disagree with
    /// its own content, and this one is compared at the approval decision to
    /// prove the thing being released is the thing that was shown.
    pub fn digest(&self) -> String {
        crate::event::digest_json(&serde_json::to_value(self).unwrap_or(Value::Null))
    }

    pub fn grants_egress(&self) -> bool {
        self.mode.grants_egress()
    }

    /// Has this grant's authority lapsed? Offline never expires (it has nothing
    /// to lose); anything else without an expiry is treated as EXPIRED rather
    /// than eternal, so a malformed or hand-edited row fails closed.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        match (self.mode, self.expires_at) {
            (NetworkGrantMode::Offline, _) => false,
            (_, Some(exp)) => now >= exp,
            (_, None) => true,
        }
    }

    /// Refuse a grant stamped by a future schema we cannot interpret.
    pub fn schema_supported(&self) -> bool {
        self.schema_version <= SCHEMA_VERSION
    }
}

// ─── Resolution ───────────────────────────────────────────────────────────

/// Everything outside the request and the policy that resolution needs.
#[derive(Debug, Clone)]
pub struct ResolutionContext {
    pub now: DateTime<Utc>,
    /// The run's frozen wall-clock budget. The grant must outlive it, so the
    /// authority cannot lapse while the agent is still working. `None` (a run
    /// that opted out of a wall clock) means the grant's own expiry is the only
    /// bound, which is a coherent story rather than an unbounded one.
    pub run_wall_clock_secs: Option<u64>,
    /// Does this run hold brokered tool surfaces? Feeds the `public` rule.
    pub has_brokered_surfaces: bool,
    /// Can the deployment actually enforce a grant? `false` ⇒ offline-only,
    /// fail closed. Answered by the provider, not by this module.
    pub enforcement_available: bool,
}

/// Why a grant was refused. Fixed cardinality: these strings are metric label
/// values and ledger reasons, so the set must stay enumerable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DenialReason {
    /// A target is malformed — it could never be lowered.
    InvalidTarget { detail: String },
    /// A CIDR target reaches a structurally blocked class.
    BlockedRange { target: String },
    /// An explicit policy deny covers the target.
    PolicyDeny { target: String },
    /// The requested mode exceeds the policy ceiling.
    ModeCeiling {
        requested: NetworkGrantMode,
        ceiling: NetworkGrantMode,
    },
    /// `public` plus brokered surfaces, without the policy opt-in.
    PublicWithBrokered,
    /// The policy carries a deny the datapath cannot express for this mode.
    UnenforceableDeny { target: String },
    /// A target the policy's catalog does not cover.
    NotInCatalog { target: String },
    /// The deployment cannot enforce a grant at all.
    Unenforceable { detail: String },
    /// The grant would expire before the run's own deadline.
    ExpiryTooShort {
        grant_secs: u64,
        run_wall_clock_secs: u64,
    },
}

impl DenialReason {
    /// Stable, bounded label for metrics and the ledger.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidTarget { .. } => "invalid_target",
            Self::BlockedRange { .. } => "blocked_range",
            Self::PolicyDeny { .. } => "policy_deny",
            Self::ModeCeiling { .. } => "mode_ceiling",
            Self::PublicWithBrokered => "public_with_brokered",
            Self::UnenforceableDeny { .. } => "unenforceable_deny",
            Self::NotInCatalog { .. } => "not_in_catalog",
            Self::Unenforceable { .. } => "unenforceable",
            Self::ExpiryTooShort { .. } => "expiry_too_short",
        }
    }

    /// Operator-facing sentence. Never echoes anything but operator-authored
    /// target text and our own vocabulary.
    pub fn message(&self) -> String {
        match self {
            Self::InvalidTarget { detail } => format!("invalid network target: {detail}"),
            Self::BlockedRange { target } => format!(
                "network target {target} reaches a structurally blocked range \
                 (loopback/private/link-local/metadata/multicast/reserved)"
            ),
            Self::PolicyDeny { target } => {
                format!("network target {target} is explicitly denied by policy")
            }
            Self::ModeCeiling { requested, ceiling } => format!(
                "network mode '{}' exceeds the policy ceiling '{}'",
                requested.as_str(),
                ceiling.as_str()
            ),
            Self::PublicWithBrokered => "a public network grant is refused for a run holding \
                 brokered tool surfaces; set network.allow_public_with_brokered to opt in"
                .into(),
            Self::UnenforceableDeny { target } => format!(
                "this policy denies {target} by NAME, and a name-based deny cannot be \
                 programmed in the datapath (Cilium's egressDeny has no FQDN selector) — \
                 so a 'public' grant would allow the world with that deny silently absent, \
                 and is refused. Express the deny as a CIDR to have it enforced. An \
                 'approved' grant is narrower (resolution refuses to GRANT a denied name), \
                 but note it does not enforce the deny at the datapath either: a denied \
                 service co-hosted on a granted name's address stays reachable."
            ),
            Self::NotInCatalog { target } => {
                format!("network target {target} is not covered by the policy's allowed targets")
            }
            Self::Unenforceable { detail } => {
                format!("this deployment cannot enforce network grants: {detail}")
            }
            Self::ExpiryTooShort {
                grant_secs,
                run_wall_clock_secs,
            } => format!(
                "a {grant_secs}s network grant would expire before the run's \
                 {run_wall_clock_secs}s wall-clock budget; raise network.max_grant_secs \
                 or lower the run's budget"
            ),
        }
    }
}

/// The three outcomes. `NeedsApproval` carries the SAME grant that would be
/// activated, so the digest a human consents to is the digest that later
/// governs — there is no re-resolution between consent and activation.
#[derive(Debug, Clone, PartialEq)]
pub enum GrantResolution {
    Active(NetworkGrant),
    NeedsApproval(NetworkGrant),
    Denied(DenialReason),
}

impl GrantResolution {
    pub fn grant(&self) -> Option<&NetworkGrant> {
        match self {
            Self::Active(g) | Self::NeedsApproval(g) => Some(g),
            Self::Denied(_) => None,
        }
    }
}

/// Resolve a request against a policy. **The order below IS the security
/// contract** — see `deny_precedence_total_order`, which proves it pairwise.
///
/// 0. `offline` → Active (short-circuit: no authority, so no enforcer needed)
/// 1. enforceability
/// 2. structural validity + blocked ranges
/// 3. explicit policy deny
/// 4. mode ceiling
/// 5. `public` + brokered
/// 6. a deny the datapath cannot express for this mode
/// 7. target-catalog subset
/// 8. expiry (clamps, then refuses if it would lapse before the run ends)
/// 9. approval requirement, else allow
///
/// Expiry CLAMPS (a request may only shorten, the policy ceiling bounds it);
/// everything else REFUSES rather than silently downgrading, because a run that
/// quietly got less network than it asked for fails in a way nobody can debug.
pub fn resolve_network_grant(
    request: &NetworkRequest,
    policy: &NetworkPolicy,
    ctx: &ResolutionContext,
) -> GrantResolution {
    // An offline request is always satisfiable and needs no enforcement: it is
    // the absence of authority, which every deployment can provide.
    if !request.mode.grants_egress() {
        return GrantResolution::Active(NetworkGrant {
            policy_digest: policy.digest(),
            ..NetworkGrant::offline()
        });
    }

    if !ctx.enforcement_available {
        return GrantResolution::Denied(DenialReason::Unenforceable {
            detail: "no network-policy enforcer is configured or detected".into(),
        });
    }

    // ── 1. structural ────────────────────────────────────────────────────
    if let Err(detail) = request.validate() {
        return GrantResolution::Denied(DenialReason::InvalidTarget { detail });
    }
    for t in &request.targets {
        if let TargetRule::Cidr { cidr, .. } = t {
            if cidr_grants_blocked(cidr) {
                return GrantResolution::Denied(DenialReason::BlockedRange {
                    target: t.describe(),
                });
            }
        }
    }

    // ── 2. explicit policy deny ──────────────────────────────────────────
    for t in &request.targets {
        // OVERLAP, not containment — see `TargetRule::intersects`. A partially
        // overlapping deny used to compare false in both directions and let the
        // forbidden ports through.
        if policy.deny.iter().any(|d| d.intersects(t)) {
            return GrantResolution::Denied(DenialReason::PolicyDeny {
                target: t.describe(),
            });
        }
    }

    // ── 3. mode ceiling ──────────────────────────────────────────────────
    if request.mode > policy.max_mode {
        return GrantResolution::Denied(DenialReason::ModeCeiling {
            requested: request.mode,
            ceiling: policy.max_mode,
        });
    }

    // ── 4. public + brokered ─────────────────────────────────────────────
    if request.mode == NetworkGrantMode::Public
        && ctx.has_brokered_surfaces
        && !policy.allow_public_with_brokered
    {
        return GrantResolution::Denied(DenialReason::PublicWithBrokered);
    }

    // ── 4b. denies we could not enforce for this mode ────────────────────
    //
    // `public` allows the world and relies on `egressDeny` to carve holes in
    // it. Cilium's `EgressDenyRule` has no `toFQDNs` (verified against the
    // 1.19.6 CRD; cilium#35494 declined it because a DNS deny would fail open
    // for unresolved names), so a NAME-based deny cannot be rendered. Under
    // `approved` this does not matter — the grant is a closed allow-list and
    // resolution already refuses any target overlapping a deny — but under
    // `public` it would mean issuing a grant that silently ignores the
    // operator's deny. Refuse instead.
    if request.mode == NetworkGrantMode::Public {
        if let Some(d) = policy
            .deny
            .iter()
            .find(|d| matches!(d, TargetRule::Dns { .. }))
        {
            return GrantResolution::Denied(DenialReason::UnenforceableDeny {
                target: d.describe(),
            });
        }
    }

    // ── 5. target-catalog subset ─────────────────────────────────────────
    for t in &request.targets {
        if !policy.allow.iter().any(|a| a.covers(t)) {
            return GrantResolution::Denied(DenialReason::NotInCatalog {
                target: t.describe(),
            });
        }
    }

    // ── expiry: clamp, then require it to outlive the run ────────────────
    // Clamped to a sane maximum before any i64 arithmetic. An unbounded `u64`
    // cast with `as i64` wraps — `u64::MAX` becomes -1, which would produce an
    // "active" grant whose expiry is a second in the PAST. A year is far beyond
    // any real grant and keeps every downstream `Duration` well inside range.
    const MAX_GRANT_SECS: u64 = 365 * 24 * 3600;
    let ceiling = policy
        .max_grant_secs
        .unwrap_or(DEFAULT_GRANT_SECS)
        .min(MAX_GRANT_SECS);
    let grant_secs = request
        .duration_secs
        .map_or(ceiling, |d| d.min(ceiling))
        .min(MAX_GRANT_SECS);
    if let Some(wall) = ctx.run_wall_clock_secs {
        if grant_secs < wall {
            return GrantResolution::Denied(DenialReason::ExpiryTooShort {
                grant_secs,
                run_wall_clock_secs: wall,
            });
        }
    }

    let grant = NetworkGrant {
        schema_version: SCHEMA_VERSION,
        mode: request.mode,
        targets: request
            .targets
            .iter()
            .map(|t| match t {
                TargetRule::Dns {
                    pattern,
                    ports,
                    protocol,
                } => TargetRule::Dns {
                    pattern: pattern.normalized(),
                    ports: ports.clone(),
                    protocol: *protocol,
                },
                other => other.clone(),
            })
            .collect(),
        expires_at: Some(ctx.now + Duration::seconds(grant_secs as i64)),
        policy_digest: policy.digest(),
        // Frozen so the datapath enforces them. A `public` grant especially
        // needs this: it carries no targets, so resolution's deny loop never
        // sees anything to compare against.
        denied: policy.deny.clone(),
    };

    // ── 6/7. approval, else allow ────────────────────────────────────────
    if policy.require_approval {
        GrantResolution::NeedsApproval(grant)
    } else {
        GrantResolution::Active(grant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // The address predicate is the OTHER encoding of the blocked classes; only
    // `blocked_cidrs_agree_with_ip_blocked` consults it directly.
    use crate::netpolicy::ip_blocked;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn ctx() -> ResolutionContext {
        ResolutionContext {
            now: now(),
            run_wall_clock_secs: Some(1800),
            has_brokered_surfaces: false,
            enforcement_available: true,
        }
    }

    fn dns(name: &str, port: u16) -> TargetRule {
        TargetRule::dns(
            FqdnPattern::Exact { name: name.into() },
            vec![PortSpec::single(port)],
            L4Protocol::Tcp,
        )
    }

    fn wild(suffix: &str, port: u16) -> TargetRule {
        TargetRule::dns(
            FqdnPattern::Wildcard {
                suffix: suffix.into(),
            },
            vec![PortSpec::single(port)],
            L4Protocol::Tcp,
        )
    }

    fn cidr(s: &str, port: u16) -> TargetRule {
        TargetRule::cidr(
            s.parse().unwrap(),
            vec![PortSpec::single(port)],
            L4Protocol::Tcp,
        )
    }

    // ─── mode ordering ────────────────────────────────────────────────────

    #[test]
    fn mode_order_is_the_ceiling_order() {
        // The derived Ord IS the ceiling comparison in resolve_network_grant.
        // Reordering the variants would silently widen every policy, so the
        // order is pinned here rather than left to declaration accident.
        assert!(NetworkGrantMode::Offline < NetworkGrantMode::Approved);
        assert!(NetworkGrantMode::Approved < NetworkGrantMode::Public);
        assert_eq!(NetworkGrantMode::default(), NetworkGrantMode::Offline);
        for m in [
            NetworkGrantMode::Offline,
            NetworkGrantMode::Approved,
            NetworkGrantMode::Public,
        ] {
            assert_eq!(NetworkGrantMode::parse(m.as_str()), Some(m));
        }
        assert!(!NetworkGrantMode::Offline.grants_egress());
        assert!(NetworkGrantMode::Approved.grants_egress());
        assert!(NetworkGrantMode::Public.grants_egress());
    }

    // ─── THE crux test ────────────────────────────────────────────────────

    /// The precedence order is a documented TOTAL order, so it is proven
    /// PAIRWISE-EXHAUSTIVELY: for every ordered pair (i, j) with i < j, a case
    /// where BOTH conditions hold must report i. A merely-sequential test
    /// (one condition at a time) would pass even if the branches were shuffled.
    ///
    /// Two conditions are mutually exclusive BY CONSTRUCTION: `public` mode
    /// requires empty targets, so it cannot be combined with a condition that
    /// works by adding one. That combination is not a hole in the sweep — it
    /// ACTIVATES the rank-0 condition (`public` carrying targets is itself
    /// invalid), and the expected winner is computed accordingly, so those
    /// pairs still assert "the earliest ACTIVE condition wins".
    #[test]
    fn deny_precedence_total_order() {
        type Setup = fn(&mut NetworkRequest, &mut NetworkPolicy, &mut ResolutionContext);
        struct Cond {
            name: &'static str,
            setup: Setup,
            code: &'static str,
            /// Forces `public` mode, which forbids targets.
            needs_public: bool,
            /// Works by adding a target, which `public` forbids.
            adds_target: bool,
        }
        let conditions: Vec<Cond> = vec![
            Cond {
                name: "unenforceable",
                // Ranked FIRST because the code checks it first: nothing below
                // can be delivered by a deployment with no enforcer, so there
                // is no point refusing on a narrower ground. It was previously
                // excluded from this matrix and tested only in isolation — an
                // adversarial review flagged exactly that gap.
                setup: |_req, _p, c| c.enforcement_available = false,
                code: "unenforceable",
                needs_public: false,
                adds_target: false,
            },
            Cond {
                name: "invalid_target",
                setup: |req, _p, _c| {
                    // A port-0 target can never lower.
                    req.targets.push(TargetRule::dns(
                        FqdnPattern::Exact {
                            name: "invalid.test".into(),
                        },
                        vec![PortSpec::single(0)],
                        L4Protocol::Tcp,
                    ));
                },
                code: "invalid_target",
                needs_public: false,
                adds_target: true,
            },
            Cond {
                name: "blocked_range",
                setup: |req, p, _c| {
                    let t = cidr("169.254.169.254/32", 80);
                    // Catalogued and mode-legal, so ONLY the structural rule
                    // can be what refuses it.
                    p.allow.push(t.clone());
                    req.targets.push(t);
                },
                code: "blocked_range",
                needs_public: false,
                adds_target: true,
            },
            Cond {
                name: "policy_deny",
                setup: |req, p, _c| {
                    let t = dns("denied.test", 443);
                    p.allow.push(t.clone());
                    p.deny.push(t.clone());
                    req.targets.push(t);
                },
                code: "policy_deny",
                needs_public: false,
                adds_target: true,
            },
            Cond {
                name: "mode_ceiling",
                setup: |_req, p, _c| {
                    // The base request is `approved`; drop the ceiling below it.
                    p.max_mode = NetworkGrantMode::Offline;
                },
                code: "mode_ceiling",
                needs_public: false,
                adds_target: false,
            },
            Cond {
                name: "public_with_brokered",
                setup: |req, p, c| {
                    req.mode = NetworkGrantMode::Public;
                    p.max_mode = NetworkGrantMode::Public;
                    c.has_brokered_surfaces = true;
                    p.allow_public_with_brokered = false;
                },
                code: "public_with_brokered",
                needs_public: true,
                adds_target: false,
            },
            Cond {
                name: "not_in_catalog",
                setup: |req, _p, _c| req.targets.push(dns("uncatalogued.test", 443)),
                code: "not_in_catalog",
                needs_public: false,
                adds_target: true,
            },
            Cond {
                name: "expiry_too_short",
                setup: |_req, p, c| {
                    p.max_grant_secs = Some(60);
                    c.run_wall_clock_secs = Some(1800);
                },
                code: "expiry_too_short",
                needs_public: false,
                adds_target: false,
            },
        ];

        let fresh = || {
            (
                NetworkRequest {
                    mode: NetworkGrantMode::Approved,
                    targets: vec![],
                    duration_secs: None,
                },
                NetworkPolicy {
                    max_mode: NetworkGrantMode::Public,
                    allow: vec![],
                    deny: vec![],
                    require_approval: false,
                    allow_public_with_brokered: true,
                    max_grant_secs: None,
                },
                ctx(),
            )
        };

        // Every condition alone reports itself — the diagonal.
        for c in &conditions {
            let (mut req, mut pol, mut rc) = fresh();
            (c.setup)(&mut req, &mut pol, &mut rc);
            match resolve_network_grant(&req, &pol, &rc) {
                GrantResolution::Denied(r) => assert_eq!(
                    r.code(),
                    c.code,
                    "condition {} alone must report {}, got {}",
                    c.name,
                    c.code,
                    r.code()
                ),
                other => panic!("condition {} alone must deny, got {other:?}", c.name),
            }
        }

        // Pairwise: with BOTH i and j active, the EARLIEST ACTIVE one wins.
        let mut pairs = 0usize;
        for i in 0..conditions.len() {
            for j in (i + 1)..conditions.len() {
                let (a, b) = (&conditions[i], &conditions[j]);
                let (mut req, mut pol, mut rc) = fresh();
                // Apply the LATER one first, so a resolver that simply returned
                // "the last condition configured" would fail this.
                (b.setup)(&mut req, &mut pol, &mut rc);
                (a.setup)(&mut req, &mut pol, &mut rc);
                // Combining a public-mode condition with a target-adding one
                // activates the rank-0 rule, which then outranks both.
                let mutually_exclusive =
                    (a.needs_public && b.adds_target) || (b.needs_public && a.adds_target);
                let expected = if mutually_exclusive {
                    "invalid_target"
                } else {
                    a.code
                };
                match resolve_network_grant(&req, &pol, &rc) {
                    GrantResolution::Denied(r) => assert_eq!(
                        r.code(),
                        expected,
                        "{} (rank {i}) + {} (rank {j}) must report {expected}; got {}",
                        a.name,
                        b.name,
                        r.code()
                    ),
                    other => panic!("{}+{} must deny, got {other:?}", a.name, b.name),
                }
                pairs += 1;
            }
        }
        assert_eq!(
            pairs,
            conditions.len() * (conditions.len() - 1) / 2,
            "every ordered pair must be exercised"
        );
    }

    #[test]
    fn unenforceable_outranks_everything_but_offline() {
        // A deployment that cannot enforce is offline-only and fails closed —
        // ABOVE the whole order, because nothing below it can be delivered.
        let c = ResolutionContext {
            enforcement_available: false,
            ..ctx()
        };
        let req = NetworkRequest {
            mode: NetworkGrantMode::Approved,
            targets: vec![cidr("169.254.169.254/32", 80)], // also structurally blocked
            duration_secs: None,
        };
        match resolve_network_grant(&req, &NetworkPolicy::default(), &c) {
            GrantResolution::Denied(r) => assert_eq!(r.code(), "unenforceable"),
            other => panic!("expected unenforceable, got {other:?}"),
        }
        // …but an OFFLINE run still resolves on an unenforceable deployment:
        // the absence of authority needs no enforcer.
        let offline = NetworkRequest::offline();
        match resolve_network_grant(&offline, &NetworkPolicy::default(), &c) {
            GrantResolution::Active(g) => assert_eq!(g.mode, NetworkGrantMode::Offline),
            other => panic!("offline must resolve anywhere, got {other:?}"),
        }
    }

    // ─── the two encodings of the blocked classes ─────────────────────────

    /// `ip_blocked` (address predicate) and `BLOCKED_V4`/`BLOCKED_V6` (ranges)
    /// encode ONE policy twice. This sweeps a structured corpus through both
    /// and fails on any disagreement, so the duplication cannot drift.
    #[test]
    fn blocked_cidrs_agree_with_ip_blocked() {
        let v4_lists = parse_all(BLOCKED_V4);
        let v6_lists = parse_all(BLOCKED_V6);
        let mut checked = 0usize;

        // Sweep every /8 boundary, both edges of every blocked range, and their
        // immediate neighbours — where an off-by-one would live.
        let mut probes: Vec<IpAddr> = Vec::new();
        for a in 0u32..=255 {
            for (b, c, d) in [(0u32, 0u32, 0u32), (0, 0, 1), (255, 255, 255), (64, 1, 1)] {
                probes.push(IpAddr::V4(std::net::Ipv4Addr::new(
                    a as u8, b as u8, c as u8, d as u8,
                )));
            }
        }
        for s in [
            "169.254.169.254",
            "169.253.255.255",
            "169.255.0.0",
            "100.63.255.255",
            "100.64.0.0",
            "100.127.255.255",
            "100.128.0.0",
            "198.17.255.255",
            "198.18.0.0",
            "198.19.255.255",
            "198.20.0.0",
            "192.0.0.255",
            "192.0.1.0",
            "192.0.2.255",
            "192.0.3.0",
            "172.15.255.255",
            "172.16.0.0",
            "172.31.255.255",
            "172.32.0.0",
            "198.51.100.1",
            "203.0.113.1",
            "8.8.8.8",
            "93.184.216.34",
        ] {
            probes.push(s.parse().unwrap());
        }
        for s in [
            "::1",
            "::",
            "fc00::1",
            "fbff::1",
            "fe00::1",
            "fe80::1",
            "febf::ffff",
            "fec0::1",
            "feff::1",
            "ff02::1",
            "2001:db8::1",
            "2001:db9::1",
            "2606:2800:220:1::1",
        ] {
            probes.push(s.parse().unwrap());
        }

        for ip in probes {
            let by_predicate = ip_blocked(ip, false, &[]);
            let host = IpCidr {
                addr: ip,
                prefix: match ip {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                },
            };
            let by_ranges = match ip {
                IpAddr::V4(_) => v4_lists.iter().any(|b| b.contains(ip)),
                IpAddr::V6(_) => v6_lists.iter().any(|b| b.contains(ip)),
            };
            assert_eq!(
                by_predicate, by_ranges,
                "ip_blocked and the CIDR list disagree about {ip}"
            );
            // …and the host-route form of the same address agrees too, which is
            // the encoding a /32 or /128 grant would actually carry.
            assert_eq!(
                by_predicate,
                cidr_grants_blocked(&host),
                "cidr_grants_blocked disagrees for the host route of {ip}"
            );
            checked += 1;
        }
        assert!(checked > 1000, "corpus too small to be meaningful");
    }

    #[test]
    fn cidr_grants_blocked_judges_ranges_not_just_addresses() {
        // A range that CONTAINS blocked space is refused even though its own
        // network address is public — this is the whole reason the range
        // encoding exists beside the address predicate.
        assert!(cidr_grants_blocked(&"0.0.0.0/0".parse().unwrap()));
        assert!(cidr_grants_blocked(&"8.0.0.0/6".parse().unwrap())); // spans 10/8
        assert!(cidr_grants_blocked(&"169.254.0.0/16".parse().unwrap()));
        assert!(cidr_grants_blocked(&"172.16.0.0/12".parse().unwrap()));
        // Genuinely public ranges pass.
        assert!(!cidr_grants_blocked(&"8.8.8.0/24".parse().unwrap()));
        assert!(!cidr_grants_blocked(&"93.184.216.34/32".parse().unwrap()));
        assert!(!cidr_grants_blocked(&"2606:2800::/32".parse().unwrap()));
        // v6 forms that really address v4 decide on their v4 form.
        assert!(cidr_grants_blocked(&"::ffff:0:0/96".parse().unwrap())); // all of v4
        assert!(cidr_grants_blocked(&"::ffff:10.0.0.1/128".parse().unwrap()));
        assert!(cidr_grants_blocked(
            &"64:ff9b::169.254.169.254/128".parse().unwrap()
        ));
        // …while the same forms carrying a PUBLIC v4 are admitted (the guard
        // against passing by blocking these prefixes wholesale).
        assert!(!cidr_grants_blocked(
            &"::ffff:93.184.216.34/128".parse().unwrap()
        ));
        assert!(!cidr_grants_blocked(
            &"64:ff9b::93.184.216.34/128".parse().unwrap()
        ));
    }

    #[test]
    fn cidr_string_form_roundtrips() {
        for s in ["10.0.0.0/8", "0.0.0.0/0", "93.184.216.34/32", "fc00::/7"] {
            let c: IpCidr = s.parse().unwrap();
            assert_eq!(c.to_string(), s);
            assert_eq!(c.to_string().parse::<IpCidr>().unwrap(), c);
        }
        // …and through the grant's own serde path.
        let t = cidr("93.184.216.0/24", 443);
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["cidr"], "93.184.216.0/24");
        assert_eq!(serde_json::from_value::<TargetRule>(v).unwrap(), t);
    }

    // ─── FQDN semantics ───────────────────────────────────────────────────

    #[test]
    fn wildcard_matches_exactly_one_label_like_cilium() {
        let w = FqdnPattern::Wildcard {
            suffix: "example.com".into(),
        };
        assert!(w.covers(&FqdnPattern::Exact {
            name: "api.example.com".into()
        }));
        // Cilium's matchPattern `*` lowers to [-a-zA-Z0-9_]* and cannot cross a
        // dot, so neither of these is covered — modelling it any other way
        // would over-promise what the datapath enforces.
        assert!(!w.covers(&FqdnPattern::Exact {
            name: "a.b.example.com".into()
        }));
        assert!(!w.covers(&FqdnPattern::Exact {
            name: "example.com".into()
        }));
        assert!(!w.covers(&FqdnPattern::Exact {
            name: "notexample.com".into()
        }));
        // A wildcard covers another wildcard only when identical.
        assert!(w.covers(&w));
        assert!(!w.covers(&FqdnPattern::Wildcard {
            suffix: "b.example.com".into()
        }));
        // An exact name never covers a wildcard.
        assert!(!FqdnPattern::Exact {
            name: "example.com".into()
        }
        .covers(&w));
        assert_eq!(w.as_selector(), "*.example.com");
    }

    #[test]
    fn dns_names_normalize_case_and_trailing_dot() {
        let a = FqdnPattern::Exact {
            name: "API.Example.COM.".into(),
        };
        let b = FqdnPattern::Exact {
            name: "api.example.com".into(),
        };
        assert_eq!(a.normalized(), b);
        assert!(a.covers(&b));
        assert!(b.covers(&a));
        // The digest of a grant must not depend on spelling: an approver
        // consents to a digest, and two spellings of one name must be one
        // consent.
        let g = |p: FqdnPattern| {
            let req = NetworkRequest {
                mode: NetworkGrantMode::Approved,
                targets: vec![TargetRule::dns(
                    p,
                    vec![PortSpec::single(443)],
                    L4Protocol::Tcp,
                )],
                duration_secs: None,
            };
            let pol = NetworkPolicy {
                max_mode: NetworkGrantMode::Approved,
                allow: vec![wild("example.com", 443), dns("api.example.com", 443)],
                ..Default::default()
            };
            match resolve_network_grant(&req, &pol, &ctx()) {
                GrantResolution::Active(g) => g.digest(),
                other => panic!("expected active, got {other:?}"),
            }
        };
        assert_eq!(
            g(FqdnPattern::Exact {
                name: "API.Example.COM.".into()
            }),
            g(FqdnPattern::Exact {
                name: "api.example.com".into()
            })
        );
    }

    #[test]
    fn invalid_fqdns_are_refused_before_they_can_reach_the_api_server() {
        // The charset is Cilium's own CRD regex. Anything outside it would be
        // rejected at apply time — after provisioning — so it is refused here.
        for bad in [
            "not a name",
            "has!bang.test",
            "*.wild.test",
            "",
            "a..b.test",
        ] {
            assert!(
                FqdnPattern::Exact { name: bad.into() }.validate().is_err(),
                "{bad:?} must be refused"
            );
        }
        for ok in ["example.com", "a-b.example.com", "under_score.test", "host"] {
            assert!(
                FqdnPattern::Exact { name: ok.into() }.validate().is_ok(),
                "{ok:?} must be accepted"
            );
        }
        // A wildcard over a bare TLD is never deliberate.
        assert!(FqdnPattern::Wildcard {
            suffix: "com".into()
        }
        .validate()
        .is_err());
        assert!(FqdnPattern::Wildcard {
            suffix: "example.com".into()
        }
        .validate()
        .is_ok());
    }

    // ─── covers / narrowing ───────────────────────────────────────────────

    #[test]
    fn covers_requires_selector_protocol_and_ports() {
        let base = TargetRule::dns(
            FqdnPattern::Wildcard {
                suffix: "example.com".into(),
            },
            vec![PortSpec::range(80, 443)],
            L4Protocol::Tcp,
        );
        assert!(base.covers(&dns("api.example.com", 443)));
        assert!(base.covers(&TargetRule::dns(
            FqdnPattern::Exact {
                name: "api.example.com".into()
            },
            vec![PortSpec::range(100, 200)],
            L4Protocol::Tcp
        )));
        // Wrong protocol, out-of-range port, and a different name all fail.
        assert!(!base.covers(&TargetRule::dns(
            FqdnPattern::Exact {
                name: "api.example.com".into()
            },
            vec![PortSpec::single(443)],
            L4Protocol::Udp
        )));
        assert!(!base.covers(&dns("api.example.com", 8443)));
        assert!(!base.covers(&dns("api.other.com", 443)));
        // A DNS rule never covers a CIDR rule, even one the name resolves to:
        // they are different selectors in the datapath.
        assert!(!base.covers(&cidr("93.184.216.34/32", 443)));
        // CIDR containment is prefix-wise.
        assert!(cidr("10.0.0.0/8", 443).covers(&cidr("10.1.2.0/24", 443)));
        assert!(!cidr("10.1.2.0/24", 443).covers(&cidr("10.0.0.0/8", 443)));
    }

    /// The bypass an adversarial review found: an explicit policy deny that
    /// only PARTIALLY overlaps the request used to compare false in both
    /// directions and let the forbidden ports through.
    ///
    /// The original `deny.covers(req) || req.covers(deny)` test fails here
    /// because neither contains the other — the deny's selector is wider but
    /// its ports narrower, the request's ports wider but its selector
    /// narrower. Overlap is the relation a deny needs.
    #[test]
    fn a_partially_overlapping_deny_still_denies() {
        let pol = NetworkPolicy {
            max_mode: NetworkGrantMode::Approved,
            allow: vec![TargetRule::dns(
                FqdnPattern::Wildcard {
                    suffix: "example.com".into(),
                },
                vec![PortSpec::range(1, 65535)],
                L4Protocol::Tcp,
            )],
            deny: vec![TargetRule::dns(
                FqdnPattern::Wildcard {
                    suffix: "example.com".into(),
                },
                vec![PortSpec::range(443, 444)],
                L4Protocol::Tcp,
            )],
            ..Default::default()
        };
        // Requests 80-443: catalogued, mode-legal, and TOUCHING the denied 443.
        let req = NetworkRequest {
            mode: NetworkGrantMode::Approved,
            targets: vec![TargetRule::dns(
                FqdnPattern::Exact {
                    name: "api.example.com".into(),
                },
                vec![PortSpec::range(80, 443)],
                L4Protocol::Tcp,
            )],
            duration_secs: None,
        };
        match resolve_network_grant(&req, &pol, &ctx()) {
            GrantResolution::Denied(DenialReason::PolicyDeny { .. }) => {}
            other => panic!("a request touching an explicit deny must be refused, got {other:?}"),
        }

        // FALSE-GREEN GUARD: a request that genuinely misses the denied range
        // must still be granted, so this cannot pass by denying everything.
        let clear = NetworkRequest {
            targets: vec![TargetRule::dns(
                FqdnPattern::Exact {
                    name: "api.example.com".into(),
                },
                vec![PortSpec::range(80, 442)],
                L4Protocol::Tcp,
            )],
            ..req.clone()
        };
        assert!(
            matches!(
                resolve_network_grant(&clear, &pol, &ctx()),
                GrantResolution::Active(_)
            ),
            "a request that does not touch the deny must still be granted"
        );
    }

    #[test]
    fn overlap_and_containment_are_different_relations() {
        let a = TargetRule::dns(
            FqdnPattern::Wildcard {
                suffix: "example.com".into(),
            },
            vec![PortSpec::range(443, 444)],
            L4Protocol::Tcp,
        );
        let b = TargetRule::dns(
            FqdnPattern::Exact {
                name: "api.example.com".into(),
            },
            vec![PortSpec::range(80, 443)],
            L4Protocol::Tcp,
        );
        // Neither contains the other…
        assert!(!a.covers(&b) && !b.covers(&a));
        // …but they share api.example.com:443, and overlap is symmetric.
        assert!(a.intersects(&b) && b.intersects(&a));

        // Disjoint ports do not overlap.
        let c = TargetRule::dns(
            FqdnPattern::Exact {
                name: "api.example.com".into(),
            },
            vec![PortSpec::range(80, 442)],
            L4Protocol::Tcp,
        );
        assert!(!a.intersects(&c));
        // A different protocol never overlaps.
        let udp = TargetRule::dns(
            FqdnPattern::Exact {
                name: "api.example.com".into(),
            },
            vec![PortSpec::single(443)],
            L4Protocol::Udp,
        );
        assert!(!a.intersects(&udp));
        // Two DIFFERENT wildcards match no name in common (a wildcard is
        // exactly one label), so they must not be treated as overlapping.
        let w1 = TargetRule::dns(
            FqdnPattern::Wildcard {
                suffix: "a.com".into(),
            },
            vec![PortSpec::single(443)],
            L4Protocol::Tcp,
        );
        let w2 = TargetRule::dns(
            FqdnPattern::Wildcard {
                suffix: "b.a.com".into(),
            },
            vec![PortSpec::single(443)],
            L4Protocol::Tcp,
        );
        assert!(!w1.intersects(&w2));
        // CIDR overlap is real containment either way.
        assert!(cidr("10.0.0.0/8", 443).intersects(&cidr("10.1.0.0/16", 443)));
        assert!(cidr("10.1.0.0/16", 443).intersects(&cidr("10.0.0.0/8", 443)));
        assert!(!cidr("10.0.0.0/8", 443).intersects(&cidr("11.0.0.0/8", 443)));
        // DNS and CIDR are different selectors and never intersect.
        assert!(!a.intersects(&cidr("93.184.216.34/32", 443)));
    }

    #[test]
    fn narrowing_is_remove_only() {
        let declared = NetworkRequest {
            mode: NetworkGrantMode::Public,
            targets: vec![wild("example.com", 443), cidr("10.0.0.0/8", 22)],
            duration_secs: Some(3600),
        };
        // An override may narrow the mode, keep a covered subset, shorten…
        let narrowed = declared.narrowed_by(Some(&NetworkRequest {
            mode: NetworkGrantMode::Approved,
            targets: vec![dns("api.example.com", 443)],
            duration_secs: Some(600),
        }));
        assert_eq!(narrowed.mode, NetworkGrantMode::Approved);
        assert_eq!(narrowed.targets, vec![dns("api.example.com", 443)]);
        assert_eq!(narrowed.duration_secs, Some(600));

        // …and may NOT widen: a bigger mode, a longer duration, and an
        // uncovered target are all refused by construction.
        let widened = declared.narrowed_by(Some(&NetworkRequest {
            mode: NetworkGrantMode::Public,
            targets: vec![dns("evil.test", 443), dns("api.example.com", 443)],
            duration_secs: Some(99999),
        }));
        assert_eq!(widened.mode, NetworkGrantMode::Public); // min(public, public)
        assert_eq!(
            widened.targets,
            vec![dns("api.example.com", 443)],
            "an uncovered target must be DROPPED, not honoured"
        );
        assert_eq!(widened.duration_secs, Some(3600));

        // No override = unchanged.
        assert_eq!(declared.narrowed_by(None), declared);
    }

    // ─── the happy paths ──────────────────────────────────────────────────

    #[test]
    fn approved_grant_freezes_targets_and_an_absolute_expiry() {
        let req = NetworkRequest {
            mode: NetworkGrantMode::Approved,
            targets: vec![dns("api.example.com", 443)],
            duration_secs: None,
        };
        let pol = NetworkPolicy {
            max_mode: NetworkGrantMode::Approved,
            allow: vec![wild("example.com", 443)],
            max_grant_secs: Some(7200),
            ..Default::default()
        };
        let g = match resolve_network_grant(&req, &pol, &ctx()) {
            GrantResolution::Active(g) => g,
            other => panic!("expected active, got {other:?}"),
        };
        assert_eq!(g.mode, NetworkGrantMode::Approved);
        assert_eq!(g.schema_version, SCHEMA_VERSION);
        assert_eq!(g.expires_at, Some(now() + Duration::seconds(7200)));
        assert_eq!(g.policy_digest, pol.digest());
        assert!(g.grants_egress());
        assert!(!g.is_expired(now()));
        assert!(g.is_expired(now() + Duration::seconds(7201)));
        // The digest is stable across clones and reserializations — it is what
        // an approver consents to.
        assert_eq!(g.digest(), g.clone().digest());
        let back: NetworkGrant = serde_json::from_value(serde_json::to_value(&g).unwrap()).unwrap();
        assert_eq!(back.digest(), g.digest());
    }

    #[test]
    fn require_approval_parks_the_same_grant_it_would_have_activated() {
        // The grant a human consents to must be byte-identical to the one that
        // later governs — there is no re-resolution between the two.
        let req = NetworkRequest {
            mode: NetworkGrantMode::Approved,
            targets: vec![dns("api.example.com", 443)],
            duration_secs: None,
        };
        let allow = vec![wild("example.com", 443)];
        let permissive = NetworkPolicy {
            max_mode: NetworkGrantMode::Approved,
            allow: allow.clone(),
            require_approval: false,
            ..Default::default()
        };
        let gated = NetworkPolicy {
            require_approval: true,
            ..permissive.clone()
        };
        let a = match resolve_network_grant(&req, &permissive, &ctx()) {
            GrantResolution::Active(g) => g,
            other => panic!("expected active, got {other:?}"),
        };
        let p = match resolve_network_grant(&req, &gated, &ctx()) {
            GrantResolution::NeedsApproval(g) => g,
            other => panic!("expected needs-approval, got {other:?}"),
        };
        // Same authority, different gate — only the policy digest differs,
        // because require_approval is part of the governing section.
        assert_eq!(a.mode, p.mode);
        assert_eq!(a.targets, p.targets);
        assert_eq!(a.expires_at, p.expires_at);
        assert_ne!(a.policy_digest, p.policy_digest);
    }

    #[test]
    fn offline_is_the_floor_and_needs_no_policy_or_enforcer() {
        // An offline request resolves under the DEFAULT (empty) policy, which
        // is what makes "a policy that says nothing grants nothing" work
        // without refusing every ordinary run.
        let pol = NetworkPolicy::default();
        assert_eq!(pol.max_mode, NetworkGrantMode::Offline);
        match resolve_network_grant(&NetworkRequest::offline(), &pol, &ctx()) {
            GrantResolution::Active(g) => {
                assert_eq!(g.mode, NetworkGrantMode::Offline);
                assert!(!g.grants_egress());
                assert!(g.expires_at.is_none());
                assert!(!g.is_expired(now() + Duration::days(365)));
            }
            other => panic!("expected active offline, got {other:?}"),
        }
        // …while ANY egress under that same default policy is refused.
        let req = NetworkRequest {
            mode: NetworkGrantMode::Approved,
            targets: vec![dns("example.com", 443)],
            duration_secs: None,
        };
        assert!(matches!(
            resolve_network_grant(&req, &pol, &ctx()),
            GrantResolution::Denied(DenialReason::ModeCeiling { .. })
        ));
    }

    #[test]
    fn public_with_brokered_needs_the_explicit_opt_in() {
        let req = NetworkRequest {
            mode: NetworkGrantMode::Public,
            targets: vec![],
            duration_secs: None,
        };
        let pol = NetworkPolicy {
            max_mode: NetworkGrantMode::Public,
            allow_public_with_brokered: false,
            ..Default::default()
        };
        let with_brokered = ResolutionContext {
            has_brokered_surfaces: true,
            ..ctx()
        };
        assert!(matches!(
            resolve_network_grant(&req, &pol, &with_brokered),
            GrantResolution::Denied(DenialReason::PublicWithBrokered)
        ));
        // Without brokered surfaces the same request is fine…
        assert!(matches!(
            resolve_network_grant(&req, &pol, &ctx()),
            GrantResolution::Active(_)
        ));
        // …and so is the opted-in policy.
        let opted = NetworkPolicy {
            allow_public_with_brokered: true,
            ..pol
        };
        assert!(matches!(
            resolve_network_grant(&req, &opted, &with_brokered),
            GrantResolution::Active(_)
        ));
    }

    #[test]
    fn expiry_clamps_down_but_must_still_outlive_the_run() {
        let req = |secs: Option<u64>| NetworkRequest {
            mode: NetworkGrantMode::Approved,
            targets: vec![],
            duration_secs: secs,
        };
        let pol = NetworkPolicy {
            max_mode: NetworkGrantMode::Approved,
            max_grant_secs: Some(7200),
            ..Default::default()
        };
        // A request may only SHORTEN: 3600 < 7200 takes effect…
        match resolve_network_grant(&req(Some(3600)), &pol, &ctx()) {
            GrantResolution::Active(g) => {
                assert_eq!(g.expires_at, Some(now() + Duration::seconds(3600)))
            }
            other => panic!("expected active, got {other:?}"),
        }
        // …while a longer request clamps to the policy ceiling.
        match resolve_network_grant(&req(Some(99999)), &pol, &ctx()) {
            GrantResolution::Active(g) => {
                assert_eq!(g.expires_at, Some(now() + Duration::seconds(7200)))
            }
            other => panic!("expected active, got {other:?}"),
        }
        // A grant that would lapse mid-run REFUSES rather than clamping the
        // run: silently expiring authority is the failure mode this avoids.
        let long_run = ResolutionContext {
            run_wall_clock_secs: Some(10_000),
            ..ctx()
        };
        assert!(matches!(
            resolve_network_grant(&req(None), &pol, &long_run),
            GrantResolution::Denied(DenialReason::ExpiryTooShort { .. })
        ));
        // A run with no wall clock is bounded by the grant alone.
        let no_wall = ResolutionContext {
            run_wall_clock_secs: None,
            ..ctx()
        };
        assert!(matches!(
            resolve_network_grant(&req(None), &pol, &no_wall),
            GrantResolution::Active(_)
        ));
    }

    /// Adding `denied` must not change the digest of an ALREADY-FROZEN grant.
    ///
    /// The digest is the consent anchor: `approvals.input_digest` equals it for
    /// every parked grant. If deploying this field changed the digest of grants
    /// frozen before it existed, every run waiting on a human would fail its
    /// release re-verification with `grant_digest_mismatch` and have to be
    /// recreated. `skip_serializing_if` is what prevents that, and this is the
    /// test that keeps it prevented.
    #[test]
    fn adding_denied_does_not_disturb_an_already_frozen_grants_digest() {
        let frozen: NetworkGrant = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "mode": "approved",
            "targets": [],
            "expires_at": "2099-01-01T00:00:00Z",
            "policy_digest": "sha256:p"
        }))
        .unwrap();
        assert!(frozen.denied.is_empty(), "an absent key defaults to empty");
        let wire = serde_json::to_value(&frozen).unwrap();
        assert!(
            wire.get("denied").is_none(),
            "an empty deny list must not appear on the wire: {wire}"
        );
        // Byte-identical to what the pre-`denied` build would have produced.
        assert_eq!(
            wire,
            serde_json::json!({
                "schema_version": 1,
                "mode": "approved",
                "expires_at": "2099-01-01T00:00:00Z",
                "policy_digest": "sha256:p"
            })
        );
        // …and a grant that DOES carry denies serializes them and digests
        // differently, so the field is not merely inert.
        let with_denies = NetworkGrant {
            denied: vec![TargetRule::cidr(
                "203.0.113.0/24".parse().unwrap(),
                vec![PortSpec::single(443)],
                L4Protocol::Tcp,
            )],
            ..frozen.clone()
        };
        assert_ne!(with_denies.digest(), frozen.digest());
    }

    #[test]
    fn a_grant_without_an_expiry_reads_as_expired_not_eternal() {
        // A hand-edited or malformed row must fail closed.
        let g = NetworkGrant {
            schema_version: SCHEMA_VERSION,
            mode: NetworkGrantMode::Public,
            targets: vec![],
            expires_at: None,
            policy_digest: String::new(),
            denied: vec![],
        };
        assert!(g.is_expired(now()));
        // …and a future schema version is refused rather than guessed at.
        let future = NetworkGrant {
            schema_version: SCHEMA_VERSION + 1,
            ..g
        };
        assert!(!future.schema_supported());
        assert!(NetworkGrant::offline().schema_supported());
    }

    #[test]
    fn denial_reason_codes_are_bounded_and_distinct() {
        // These are metric label values: the set must stay enumerable, and no
        // two reasons may share a code.
        let all = [
            DenialReason::InvalidTarget { detail: "x".into() },
            DenialReason::BlockedRange { target: "x".into() },
            DenialReason::PolicyDeny { target: "x".into() },
            DenialReason::ModeCeiling {
                requested: NetworkGrantMode::Public,
                ceiling: NetworkGrantMode::Offline,
            },
            DenialReason::PublicWithBrokered,
            DenialReason::UnenforceableDeny { target: "x".into() },
            DenialReason::NotInCatalog { target: "x".into() },
            DenialReason::Unenforceable { detail: "x".into() },
            DenialReason::ExpiryTooShort {
                grant_secs: 1,
                run_wall_clock_secs: 2,
            },
        ];
        let codes: std::collections::BTreeSet<_> = all.iter().map(|r| r.code()).collect();
        assert_eq!(codes.len(), all.len(), "denial codes must be distinct");
        for r in &all {
            assert!(!r.message().is_empty());
            // Round-trips through the wire form (it rides into the ledger).
            let v = serde_json::to_value(r).unwrap();
            assert_eq!(serde_json::from_value::<DenialReason>(v).unwrap(), *r);
        }
    }

    #[test]
    fn public_grants_must_not_carry_targets() {
        let req = NetworkRequest {
            mode: NetworkGrantMode::Public,
            targets: vec![dns("example.com", 443)],
            duration_secs: None,
        };
        let pol = NetworkPolicy {
            max_mode: NetworkGrantMode::Public,
            allow: vec![dns("example.com", 443)],
            ..Default::default()
        };
        assert!(matches!(
            resolve_network_grant(&req, &pol, &ctx()),
            GrantResolution::Denied(DenialReason::InvalidTarget { .. })
        ));
    }
}
