//! Lowering a [`GrantedNetwork`] to Cilium objects — pure builders over
//! `serde_json::Value`, no cluster I/O, exactly like [`crate::manifest`].
//!
//! Everything here was validated against real Cilium 1.19.6 during the Phase 0
//! spike (`docs/reviews/2026-08-01-cilium-substrate-spike.md`), and three of
//! its findings are structural to this file:
//!
//! **Deny precedence is global across policy objects.** The chart-static
//! `CiliumClusterwideNetworkPolicy` deny wall outranks every allow in a per-run
//! `CiliumNetworkPolicy` — proven by a per-run policy that explicitly allowed
//! `169.254.169.254/32` and was still denied. That is what lets resolution be
//! the only thing that has to be right about targets, and the wall be the thing
//! that has to be right about the floor.
//!
//! **CIDR selectors never bind in-cluster identities.** A deny on a cluster
//! pod's exact `/32` does not touch an identity-based allow to that pod, so the
//! wall can carry the full blocked-class list without any risk of blackholing
//! `:8788` or the controlled resolver. It also means `public` must lower to
//! `toEntities: [world]` and NEVER `[all]` — `world` cannot reach cluster
//! identities, which is precisely what makes `public` safe.
//!
//! **The per-run selector is a security control.** Within one policy's
//! selector, an FQDN grant's resolved addresses are reachable by every endpoint
//! that policy selects, including one that never did the lookup. Selecting on
//! all three run identity labels is what keeps concurrent runs isolated;
//! widening it silently pools their granted addresses.

use fluidbox_core::network::{FqdnPattern, NetworkGrantMode, PortSpec, TargetRule};
use fluidbox_core::traits::GrantedNetwork;
use serde_json::{json, Value};

/// The three identity labels a per-run policy selects on. `session` already
/// exists on every pod ([`crate::manifest::LABEL_SESSION`]); the other two are
/// added so the selector is specific to one run of one tenant.
pub const LABEL_SESSION: &str = "fluidbox.dev/session";
pub const LABEL_TENANT: &str = "fluidbox.dev/tenant";
pub const LABEL_RUN: &str = "fluidbox.dev/run";

/// Deterministic per-run policy name — same shape as the pod's, so an operator
/// reading `kubectl get cnp` sees the run it belongs to.
pub fn policy_name(session_id: uuid::Uuid) -> String {
    format!("fluidbox-{session_id}")
}

/// The pod labels a per-run policy will select. Applied to the sandbox pod so
/// the selector below can be exact.
pub fn identity_labels(g: &GrantedNetwork, session_id: uuid::Uuid) -> Value {
    json!({
        LABEL_SESSION: session_id.to_string(),
        LABEL_TENANT: g.tenant_id.to_string(),
        LABEL_RUN: g.run_id.to_string(),
    })
}

fn port_entries(ports: &[PortSpec], protocol: &str) -> Vec<Value> {
    ports
        .iter()
        .map(|p| {
            let mut e = json!({ "port": p.from.to_string(), "protocol": protocol });
            // Cilium's range form. A single port omits `endPort` so the object
            // is byte-identical to the obvious hand-written one.
            if p.to != p.from {
                e["endPort"] = json!(p.to as i64);
            }
            e
        })
        .collect()
}

/// One `toPorts` block for a target rule.
fn to_ports(rule: &TargetRule) -> Value {
    json!([{ "ports": port_entries(rule.ports(), rule.protocol().as_str()) }])
}

/// Lower one target to a Cilium egress rule.
///
/// `Dns` lowers to `toFQDNs`; `Cidr` to `toCIDR`. They are never merged: the
/// datapath treats them as different selectors, and so does the grant model.
fn egress_rule(rule: &TargetRule) -> Value {
    match rule {
        TargetRule::Dns { pattern, .. } => {
            let selector = match pattern.normalized() {
                FqdnPattern::Exact { name } => json!({ "matchName": name }),
                // A single-label wildcard — Cilium's `*` lowers to
                // `[-a-zA-Z0-9_]*`, which cannot cross a dot. `FqdnPattern` is
                // shaped to exactly this, so the lowering is total.
                FqdnPattern::Wildcard { suffix } => {
                    json!({ "matchPattern": format!("*.{suffix}") })
                }
            };
            json!({ "toFQDNs": [selector], "toPorts": to_ports(rule) })
        }
        TargetRule::Cidr { cidr, .. } => {
            json!({ "toCIDR": [cidr.to_string()], "toPorts": to_ports(rule) })
        }
    }
}

/// The DNS rule. `toFQDNs` only works when the DNS request itself transits
/// Cilium's L7 proxy, which is what `rules.dns` turns on — without it a
/// name-based grant matches nothing at all.
///
/// **`patterns` restricts WHICH NAMES may be looked up, and that is a
/// containment control, not a formality.** An unrestricted `matchPattern: "*"`
/// is a covert egress channel on its own: the workload queries
/// `<base32-encoded-secret>.attacker.example`, the resolver forwards it to the
/// public internet, and the attacker's authoritative nameserver receives the
/// data — **without ever opening a connection the policy would have blocked.**
/// The question *is* the exfiltration. So an `approved` grant may resolve
/// exactly the names it was granted and nothing else.
///
/// `public` passes `None`, which does emit `*`: a public grant may already
/// connect anywhere the deny wall permits, so restricting its lookups would
/// buy nothing and break ordinary name resolution.
///
/// Offline gets no DNS rule whatsoever, which is what keeps offline
/// byte-identical in effect to `zeroEgress`.
fn dns_rule(resolver_labels: &Value, patterns: Option<&[&TargetRule]>) -> Value {
    let dns_matchers: Vec<Value> = match patterns {
        None => vec![json!({ "matchPattern": "*" })],
        Some(targets) => targets
            .iter()
            .filter_map(|t| match t {
                TargetRule::Dns { pattern, .. } => Some(match pattern.normalized() {
                    FqdnPattern::Exact { name } => json!({ "matchName": name }),
                    FqdnPattern::Wildcard { suffix } => {
                        json!({ "matchPattern": format!("*.{suffix}") })
                    }
                }),
                // A CIDR target needs no name resolved.
                TargetRule::Cidr { .. } => None,
            })
            .collect(),
    };
    json!({
        "toEndpoints": [{ "matchLabels": resolver_labels }],
        "toPorts": [{
            "ports": [{ "port": "53", "protocol": "ANY" }],
            "rules": { "dns": dns_matchers }
        }]
    })
}

/// What a per-run policy needs beyond the grant: which resolver to allow, and
/// the pod UID to own the object.
#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub namespace: String,
    /// Labels selecting the CONTROLLED resolver (a forward-only CoreDNS in the
    /// release namespace with no `kubernetes` plugin, so a sandbox cannot
    /// resolve in-cluster Service names).
    pub resolver_labels: Value,
    /// The pod that owns this policy, so Kubernetes GC collects it. Without an
    /// ownerReference nothing would: `terminate()` deletes only the Pod and
    /// `list_managed()` lists only Pods, so a leaked policy is invisible to
    /// both — and because Cilium allow rules are ADDITIVE, a surviving policy
    /// that later matched a re-created pod for the same session would silently
    /// REOPEN traffic.
    pub owner_pod_uid: String,
    pub owner_pod_name: String,
}

/// Build the per-run `CiliumNetworkPolicy`.
///
/// Returns `None` for an offline grant: offline is the ABSENCE of an allow, so
/// emitting an empty policy would be noise at best and, if it ever grew an
/// empty-egress-means-allow-all interpretation, a hazard. The chart-static
/// baseline already puts every sandbox in default-deny.
/// `Err` means the grant CANNOT be safely rendered and the run must not start.
pub fn build_run_policy(
    g: &GrantedNetwork,
    session_id: uuid::Uuid,
    ctx: &PolicyContext,
) -> Result<Option<Value>, String> {
    if !g.grant.grants_egress() {
        return Ok(None);
    }
    // A NAME-based deny under `public` cannot be rendered (see `egress_deny`
    // below) and `public` allows the world — so silently filtering it would
    // leave the allow standing with the deny gone.
    //
    // Checked HERE rather than only at resolution because resolution does not
    // see every path: a grant frozen before that check existed still releases
    // under the unchanged-policy shortcut, and an already-active grant is never
    // re-resolved at all. The renderer is the one place EVERY grant passes
    // through, so it is where this has to fail closed.
    if g.grant.mode == NetworkGrantMode::Public {
        // A grant frozen BEFORE deny snapshots existed carries an empty list
        // that means "unknown", not "none" — so programming it as a world-allow
        // could silently drop denies the policy really had. Nothing in the
        // grant can distinguish the two cases, so the schema version is the
        // disambiguator and a v1 public grant is refused. Recreate the run:
        // resolution will freeze a v2 grant with its denies recorded.
        if g.grant.schema_version < fluidbox_core::network::SCHEMA_WITH_DENIES {
            return Err(format!(
                "this `public` grant was frozen under schema v{} — before policy denies \
                 were recorded in the grant — so its deny set is UNKNOWN rather than \
                 empty. Refusing to program a world-allow that might be missing them; \
                 recreate the run to freeze a current grant.",
                g.grant.schema_version
            ));
        }
        if let Some(d) = g
            .grant
            .denied
            .iter()
            .find(|d| matches!(d, TargetRule::Dns { .. }))
        {
            return Err(format!(
                "this grant is `public` and its policy denies {} by NAME, which Cilium's \
                 egressDeny cannot express — refusing to program a policy that would allow \
                 the world with that deny silently absent",
                d.describe()
            ));
        }
    }
    let mut egress: Vec<Value> = Vec::new();
    match g.grant.mode {
        NetworkGrantMode::Offline => unreachable!("guarded above"),
        NetworkGrantMode::Approved => {
            let has_dns_targets = g
                .grant
                .targets
                .iter()
                .any(|t| matches!(t, TargetRule::Dns { .. }));
            if has_dns_targets {
                let dns_targets: Vec<&TargetRule> = g.grant.targets.iter().collect();
                egress.push(dns_rule(&ctx.resolver_labels, Some(&dns_targets)));
            }
            egress.extend(g.grant.targets.iter().map(egress_rule));
        }
        NetworkGrantMode::Public => {
            // Public may already connect anywhere the wall permits, so an
            // unrestricted lookup adds no reach it does not already have.
            egress.push(dns_rule(&ctx.resolver_labels, None));
            // `world`, NEVER `all`: a CIDR/world selector cannot reach
            // in-cluster identities, which is exactly the property that keeps
            // `public` from implicitly opening the cluster. `all` would throw
            // that away. The deny wall still outranks this.
            egress.push(json!({ "toEntities": ["world"] }));
        }
    }

    // The policy's own denies, rendered as `egressDeny` so they actually bind.
    // Cilium evaluates deny across ALL policies and it outranks every allow, so
    // these hold even against this policy's own `toEntities: world`. Without
    // them a `public` grant ignored the tenant's denies entirely: resolution
    // iterates REQUESTED targets and a public request has none.
    //
    // **CIDR denies ONLY.** `EgressDenyRule` in `cilium.io/v2` has no `toFQDNs`
    // field — verified against the 1.19.6 CRD schema, where `egress` carries it
    // and `egressDeny` does not. Cilium declined the feature deliberately
    // (cilium#35494): a DNS deny would have to fail open for names the proxy has
    // not yet resolved. Emitting one here would be pruned by the API server,
    // leaving the `world` allow standing with NO deny — precisely the fail-open
    // this rendering exists to prevent.
    //
    // A DNS deny is therefore enforced at RESOLUTION instead, which refuses the
    // run outright rather than issuing a grant it cannot contain. See
    // `resolve_network_grant`'s unenforceable-deny check.
    let egress_deny: Vec<Value> = g
        .grant
        .denied
        .iter()
        .filter_map(|d| match d {
            TargetRule::Cidr { cidr, .. } => Some(json!({
                "toCIDR": [cidr.to_string()],
                // Ports and protocol are part of the deny. Dropping them would
                // silently WIDEN an authored `TCP/443` deny into all-ports,
                // all-protocols — safe here by luck, but a lie about what the
                // operator wrote, and wrong the moment a deny is meant to be
                // surgical.
                "toPorts": to_ports(d),
            })),
            // Unrenderable; resolution refuses these instead.
            TargetRule::Dns { .. } => None,
        })
        .collect();

    Ok(Some(json!({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": policy_name(session_id),
            "namespace": ctx.namespace,
            "labels": {
                LABEL_SESSION: session_id.to_string(),
                "fluidbox.dev/managed": "true",
            },
            "annotations": {
                // The consent anchor, so a programmed policy traces back to the
                // exact authority that was approved.
                "fluidbox.dev/grant-digest": g.grant_digest,
            },
            "ownerReferences": [{
                "apiVersion": "v1",
                "kind": "Pod",
                "name": ctx.owner_pod_name,
                "uid": ctx.owner_pod_uid,
                "controller": true,
                "blockOwnerDeletion": true,
            }],
        },
        "spec": {
            // All three identity labels — see the module docs. This selector IS
            // the cross-run isolation boundary.
            "endpointSelector": { "matchLabels": identity_labels(g, session_id) },
            "egress": egress,
            "egressDeny": egress_deny,
        }
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::network::{L4Protocol, NetworkGrant, SCHEMA_VERSION};

    fn ctx() -> PolicyContext {
        PolicyContext {
            namespace: "fluidbox".into(),
            resolver_labels: json!({
                "k8s:io.kubernetes.pod.namespace": "fluidbox",
                "app": "fluidbox-dns",
            }),
            owner_pod_uid: "pod-uid-1".into(),
            owner_pod_name: "fluidbox-run".into(),
        }
    }

    fn granted(mode: NetworkGrantMode, targets: Vec<TargetRule>) -> GrantedNetwork {
        // The expiry is built through serde rather than chrono: this crate does
        // not depend on chrono, and a fixed timestamp keeps the fixtures
        // byte-stable anyway.
        let grant: NetworkGrant = serde_json::from_value(json!({
            "schema_version": SCHEMA_VERSION,
            "mode": mode.as_str(),
            "targets": targets,
            "expires_at": "2026-08-01T12:00:00Z",
            "policy_digest": "sha256:pol",
        }))
        .expect("grant fixture");
        GrantedNetwork {
            grant,
            tenant_id: uuid::Uuid::nil(),
            run_id: uuid::Uuid::nil(),
            grant_digest: "sha256:grant".into(),
        }
    }

    fn dns_target(suffix: &str, port: u16) -> TargetRule {
        TargetRule::dns(
            FqdnPattern::Wildcard {
                suffix: suffix.into(),
            },
            vec![PortSpec::single(port)],
            L4Protocol::Tcp,
        )
    }

    #[test]
    fn offline_emits_no_policy_at_all() {
        // Offline is the ABSENCE of an allow — byte-identical in effect to the
        // existing zeroEgress posture, delivered by the chart-static baseline.
        let sid = uuid::Uuid::now_v7();
        assert!(
            build_run_policy(&granted(NetworkGrantMode::Offline, vec![]), sid, &ctx())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn the_selector_carries_all_three_identity_labels() {
        // THE cross-run isolation control. The Phase 0 spike showed that a
        // policy selecting a shared label pools every concurrent run's resolved
        // FQDN addresses into one reachable set, so a widened selector here is
        // a silent removal of isolation — this test is the guard.
        let sid = uuid::Uuid::now_v7();
        let g = granted(
            NetworkGrantMode::Approved,
            vec![dns_target("example.com", 443)],
        );
        let p = build_run_policy(&g, sid, &ctx()).unwrap().unwrap();
        let sel = &p["spec"]["endpointSelector"]["matchLabels"];
        assert_eq!(sel[LABEL_SESSION], sid.to_string());
        assert_eq!(sel[LABEL_TENANT], g.tenant_id.to_string());
        assert_eq!(sel[LABEL_RUN], g.run_id.to_string());
        assert_eq!(
            sel.as_object().unwrap().len(),
            3,
            "exactly the three identity labels — no more, no fewer"
        );
    }

    #[test]
    fn an_approved_grant_lowers_to_fqdn_rules_plus_dns_visibility() {
        let sid = uuid::Uuid::now_v7();
        let p = build_run_policy(
            &granted(
                NetworkGrantMode::Approved,
                vec![dns_target("example.com", 443)],
            ),
            sid,
            &ctx(),
        )
        .unwrap()
        .unwrap();
        let egress = p["spec"]["egress"].as_array().unwrap();
        // The DNS-visibility rule must be present, and must carry rules.dns —
        // without it `toFQDNs` matches nothing at all.
        let dns = &egress[0];
        assert_eq!(dns["toPorts"][0]["ports"][0]["port"], "53");
        // Scoped to the granted name, not `*` — see
        // `an_approved_grant_may_resolve_only_its_granted_names` for why an
        // unrestricted lookup is itself an exfiltration channel.
        assert_eq!(
            dns["toPorts"][0]["rules"]["dns"][0]["matchPattern"],
            "*.example.com"
        );
        // …and the grant itself.
        let allow = &egress[1];
        assert_eq!(allow["toFQDNs"][0]["matchPattern"], "*.example.com");
        assert_eq!(allow["toPorts"][0]["ports"][0]["port"], "443");
        assert_eq!(allow["toPorts"][0]["ports"][0]["protocol"], "TCP");
        assert!(allow["toPorts"][0]["ports"][0].get("endPort").is_none());
    }

    /// The DNS rule must permit ONLY the granted names.
    ///
    /// An unrestricted `matchPattern: "*"` is a covert egress channel by
    /// itself — the workload encodes secrets into a lookup for a domain the
    /// attacker controls and their nameserver receives it, with no connection
    /// the policy could have blocked. This is the assertion that keeps the
    /// channel closed.
    #[test]
    fn an_approved_grant_may_resolve_only_its_granted_names() {
        let sid = uuid::Uuid::now_v7();
        let p = build_run_policy(
            &granted(
                NetworkGrantMode::Approved,
                vec![
                    dns_target("example.com", 443),
                    TargetRule::dns(
                        FqdnPattern::Exact {
                            name: "pypi.org".into(),
                        },
                        vec![PortSpec::single(443)],
                        L4Protocol::Tcp,
                    ),
                ],
            ),
            sid,
            &ctx(),
        )
        .unwrap()
        .unwrap();
        let dns = &p["spec"]["egress"][0]["toPorts"][0]["rules"]["dns"];
        let matchers = dns.as_array().unwrap();
        assert_eq!(matchers.len(), 2, "one matcher per granted name: {dns}");
        assert_eq!(matchers[0]["matchPattern"], "*.example.com");
        assert_eq!(matchers[1]["matchName"], "pypi.org");
        // THE assertion: no wildcard-everything anywhere in the rendered policy.
        let rendered = serde_json::to_string(&p).unwrap();
        assert!(
            !rendered.contains(r#"{"matchPattern":"*"}"#),
            "an approved grant must not permit arbitrary DNS lookups: {rendered}"
        );
    }

    #[test]
    fn a_public_grant_may_resolve_anything_because_it_may_reach_anything() {
        // Restricting lookups here would buy no containment — public already
        // reaches whatever the deny wall permits — and would break ordinary
        // name resolution.
        let sid = uuid::Uuid::now_v7();
        let p = build_run_policy(&granted(NetworkGrantMode::Public, vec![]), sid, &ctx())
            .unwrap()
            .unwrap();
        let dns = &p["spec"]["egress"][0]["toPorts"][0]["rules"]["dns"];
        assert_eq!(dns[0]["matchPattern"], "*");
    }

    #[test]
    fn a_cidr_only_grant_gets_no_dns_allow() {
        // Nothing to resolve ⇒ no reason to hand the run a resolver. This is
        // the same fail-safe shape as offline: capability by need, not by
        // convenience.
        let sid = uuid::Uuid::now_v7();
        let p = build_run_policy(
            &granted(
                NetworkGrantMode::Approved,
                vec![TargetRule::cidr(
                    "93.184.216.0/24".parse().unwrap(),
                    vec![PortSpec::range(80, 443)],
                    L4Protocol::Tcp,
                )],
            ),
            sid,
            &ctx(),
        )
        .unwrap()
        .unwrap();
        let egress = p["spec"]["egress"].as_array().unwrap();
        assert_eq!(egress.len(), 1, "only the CIDR allow: {egress:?}");
        assert_eq!(egress[0]["toCIDR"][0], "93.184.216.0/24");
        // A range lowers to Cilium's {port, endPort} form.
        assert_eq!(egress[0]["toPorts"][0]["ports"][0]["port"], "80");
        assert_eq!(egress[0]["toPorts"][0]["ports"][0]["endPort"], 443);
    }

    /// A `public` grant must still carry the tenant policy's own denies.
    ///
    /// This was the bypass: resolution iterates the REQUESTED targets, and a
    /// public request has none by construction, so every `network.deny` entry
    /// was skipped — and the lowering emitted `toEntities: world` with no
    /// `egressDeny` at all. A policy saying "public, but never this corporate
    /// range" got only the first half.
    #[test]
    fn a_public_grant_still_carries_the_policys_denies() {
        let sid = uuid::Uuid::now_v7();
        let mut g = granted(NetworkGrantMode::Public, vec![]);
        // CIDR denies only — a NAME deny under `public` is a REFUSAL, covered by
        // `a_dns_deny_is_never_rendered_because_cilium_cannot_express_it`.
        g.grant.denied = vec![
            TargetRule::cidr(
                "203.0.113.0/24".parse().unwrap(),
                vec![PortSpec::single(443)],
                L4Protocol::Tcp,
            ),
            TargetRule::cidr(
                "198.51.100.0/24".parse().unwrap(),
                vec![PortSpec::single(80)],
                L4Protocol::Tcp,
            ),
        ];
        let p = build_run_policy(&g, sid, &ctx()).unwrap().unwrap();
        let deny = p["spec"]["egressDeny"].as_array().unwrap();
        assert_eq!(deny.len(), 2, "both CIDR denies must render: {deny:?}");
        assert_eq!(deny[0]["toCIDR"][0], "203.0.113.0/24");
        assert_eq!(deny[1]["toCIDR"][0], "198.51.100.0/24");
        // …alongside the world allow, which Cilium's deny precedence outranks.
        let egress = p["spec"]["egress"].as_array().unwrap();
        assert!(egress.iter().any(|r| r["toEntities"][0] == "world"));
    }

    /// A NAME-based deny must NOT be rendered: `EgressDenyRule` has no
    /// `toFQDNs` in `cilium.io/v2` (verified against the 1.19.6 CRD schema —
    /// `egress` carries the field, `egressDeny` does not; cilium#35494 declined
    /// it because a DNS deny would fail open for unresolved names). Emitting
    /// one would be PRUNED by the API server, leaving the world allow standing
    /// with no deny at all — a fail-open dressed as a fix. Resolution refuses
    /// the run instead.
    #[test]
    fn a_dns_deny_is_never_rendered_because_cilium_cannot_express_it() {
        let sid = uuid::Uuid::now_v7();
        // A `public` grant whose policy denies a NAME is REFUSED outright.
        // Rendering it with the deny quietly filtered would leave the world
        // allow standing with the deny gone — a fail-open dressed as a fix.
        // Refusing HERE (not only at resolution) covers every path, including
        // grants frozen before the resolution-time check existed, and grants
        // that are already active and never re-resolved.
        let mut g = granted(NetworkGrantMode::Public, vec![]);
        g.grant.denied = vec![dns_target("corp.example", 443)];
        let err = build_run_policy(&g, sid, &ctx())
            .expect_err("a public grant with a NAME deny must refuse");
        assert!(err.contains("corp.example"), "the refusal names it: {err}");

        // APPROVED does not refuse: the grant is a closed allow-list and
        // resolution already refuses any target overlapping a deny, so nothing
        // is silently lost by not rendering it. (It does NOT enforce the deny
        // at the datapath either — a denied service co-hosted on a granted
        // name's address stays reachable. That residual is documented.)
        let mut appr = granted(
            NetworkGrantMode::Approved,
            vec![dns_target("example.com", 443)],
        );
        appr.grant.denied = vec![dns_target("corp.example", 443)];
        assert!(build_run_policy(&appr, sid, &ctx()).is_ok());

        // A CIDR deny renders, with ports and protocol intact — dropping them
        // would silently WIDEN an authored TCP/443 deny to all-ports.
        let mut ok_grant = granted(NetworkGrantMode::Public, vec![]);
        ok_grant.grant.denied = vec![TargetRule::cidr(
            "203.0.113.0/24".parse().unwrap(),
            vec![PortSpec::single(443)],
            L4Protocol::Tcp,
        )];
        let p = build_run_policy(&ok_grant, sid, &ctx()).unwrap().unwrap();
        let deny = p["spec"]["egressDeny"].as_array().unwrap();
        assert_eq!(deny.len(), 1, "only the CIDR deny is renderable: {deny:?}");
        assert_eq!(deny[0]["toCIDR"][0], "203.0.113.0/24");
        let rendered = serde_json::to_string(&p["spec"]["egressDeny"]).unwrap();
        assert!(
            !rendered.contains("toFQDNs"),
            "an unrenderable DNS deny must not be emitted: {rendered}"
        );
        assert_eq!(deny[0]["toPorts"][0]["ports"][0]["port"], "443");
        assert_eq!(deny[0]["toPorts"][0]["ports"][0]["protocol"], "TCP");
    }

    /// An APPROVED grant carries them too — defence in depth, since resolution
    /// already refuses a request that overlaps a deny.
    #[test]
    fn an_approved_grant_also_renders_the_policys_denies() {
        let sid = uuid::Uuid::now_v7();
        let mut g = granted(
            NetworkGrantMode::Approved,
            vec![dns_target("example.com", 443)],
        );
        g.grant.denied = vec![TargetRule::cidr(
            "198.51.100.0/24".parse().unwrap(),
            vec![PortSpec::single(443)],
            L4Protocol::Tcp,
        )];
        let p = build_run_policy(&g, sid, &ctx()).unwrap().unwrap();
        assert_eq!(p["spec"]["egressDeny"][0]["toCIDR"][0], "198.51.100.0/24");
    }

    #[test]
    fn public_lowers_to_world_never_all() {
        // `all` includes cluster entities; `world` cannot reach them. That
        // distinction is what keeps a public grant from implicitly opening the
        // cluster, and the Phase 0 spike is why it is stated as a rule rather
        // than left to whoever edits this next.
        let sid = uuid::Uuid::now_v7();
        let p = build_run_policy(&granted(NetworkGrantMode::Public, vec![]), sid, &ctx())
            .unwrap()
            .unwrap();
        let egress = p["spec"]["egress"].as_array().unwrap();
        let entities: Vec<&Value> = egress.iter().filter_map(|r| r.get("toEntities")).collect();
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0][0], "world");
        let rendered = serde_json::to_string(&p).unwrap();
        assert!(
            !rendered.contains("\"all\""),
            "a public grant must never lower to toEntities: all"
        );
        // Public still resolves names.
        assert!(egress
            .iter()
            .any(|r| r["toPorts"][0]["ports"][0]["port"] == "53"));
    }

    #[test]
    fn the_policy_is_owned_by_its_pod_and_carries_no_credential() {
        // ownerReference is the ONLY thing that collects a per-run policy:
        // terminate() deletes only the Pod and list_managed() lists only Pods,
        // so without it a leak is invisible to both — and a surviving policy
        // that later matched a re-created pod would REOPEN traffic, because
        // Cilium allow rules are additive.
        let sid = uuid::Uuid::now_v7();
        let p = build_run_policy(
            &granted(
                NetworkGrantMode::Approved,
                vec![dns_target("example.com", 443)],
            ),
            sid,
            &ctx(),
        )
        .unwrap()
        .unwrap();
        let owner = &p["metadata"]["ownerReferences"][0];
        assert_eq!(owner["kind"], "Pod");
        assert_eq!(owner["uid"], "pod-uid-1");
        assert_eq!(owner["controller"], true);
        assert_eq!(owner["blockOwnerDeletion"], true);
        // The grant digest travels with the object for audit.
        assert_eq!(
            p["metadata"]["annotations"]["fluidbox.dev/grant-digest"],
            "sha256:grant"
        );
        // No serviceaccount, no secret, no token anywhere in a policy object.
        let rendered = serde_json::to_string(&p).unwrap().to_lowercase();
        for forbidden in ["secret", "serviceaccount", "token", "fbx_sess"] {
            assert!(
                !rendered.contains(forbidden),
                "a network policy must never reference {forbidden}: {rendered}"
            );
        }
    }

    #[test]
    fn an_exact_name_lowers_to_matchname() {
        let sid = uuid::Uuid::now_v7();
        let p = build_run_policy(
            &granted(
                NetworkGrantMode::Approved,
                vec![TargetRule::dns(
                    // Mixed case + trailing dot must normalize: the object that
                    // reaches the API server has to be the canonical name, or
                    // two spellings of one grant would be two different objects.
                    FqdnPattern::Exact {
                        name: "API.Example.COM.".into(),
                    },
                    vec![PortSpec::single(443)],
                    L4Protocol::Tcp,
                )],
            ),
            sid,
            &ctx(),
        )
        .unwrap()
        .unwrap();
        let allow = &p["spec"]["egress"][1];
        assert_eq!(allow["toFQDNs"][0]["matchName"], "api.example.com");
        assert!(allow["toFQDNs"][0].get("matchPattern").is_none());
    }
}
