# Cilium substrate spike — Phase 0 of the governed sandbox network epic

Phase 0 exists to answer three datapath questions **before** any enforcement Rust is
written, because each would change the object model if the answer came back wrong. All
three are answered, plus four questions the spike raised on its own. One plan assumption
(**R3**) is **falsified** and its consumer is redesigned below.

- **Cluster:** kind v0.32.0, node image `kindest/node:v1.36.1`, 2 nodes
  (`control-plane`, `worker`), `disableDefaultCNI: true`, `kubeProxyMode: none`
- **CNI:** Cilium **1.19.6** (chart `cilium/cilium` 1.19.6), `kubeProxyReplacement=true`,
  `bpf.masquerade=true`, `egressGateway.enabled=true`, `l7Proxy=true`, `ipam.mode=kubernetes`
- **Image digest (pinned):**
  `quay.io/cilium/cilium@sha256:0df5b2750b64c49843aba1d649e9eaf61467cb0645ad3171db6f6962c095ac92`
- **Topology:** sandbox pods on `control-plane` (172.19.0.2); `worker` (172.19.0.3)
  labelled `egress-gateway=true`; pod CIDR `10.244.0.0/16`, service CIDR `10.96.0.0/12`;
  two off-cluster targets on the kind bridge — `172.19.0.4` and `172.19.0.5` — which
  Cilium classifies as `world` and which are **not** behind docker NAT, so the client IP
  they report is the egressing **node**, which is what makes the gateway observable.
- **Date:** 2026-08-01

---

## R1 — does approved-mode data traffic still transit the egress gateway?

**Yes, on both paths.** With one `CiliumEgressGatewayPolicy` selecting the sandbox
(`destinationCIDRs: 0.0.0.0/0`, cluster CIDRs excluded, gateway = the `worker` node):

| Grant shape | Client IP seen by the off-cluster target |
|---|---|
| pure L3/L4 (`toCIDR` + `toPorts`) | `172.19.0.3` — the **gateway** node |
| `toFQDNs` (DNS proxy engaged via `rules.dns`) | `172.19.0.3` — the **gateway** node |

The sandbox runs on `172.19.0.2`, so an un-gatewayed packet would have reported that.
cilium#19642 does not bite in this configuration on 1.19.6: putting the **DNS** request
through the L7 proxy does not divert the subsequent **data** connection around the
gateway.

**This does not change the security posture, by design.** The gateway remains SNAT plus
attribution only — the L3/L4 policy is the boundary. R1 coming back the other way would
have cost stable egress IPs and per-run attribution, not containment.

## R2 — deny-CIDR versus identity-allow precedence

**The favorable branch, via a mechanism worth stating exactly: CIDR selectors do not bind
in-cluster identities at all.**

| Probe | Result |
|---|---|
| `egressDeny toCIDR 10.0.0.0/8` + identity-allow to the server pod (`10.244.1.17:8788`) | **allowed** |
| `egressDeny toCIDR 10.244.1.17/32` — the server pod's **exact /32** — + the same identity allow | **allowed** |
| Service-IP path `10.96.139.240:8788` under the same `10.0.0.0/8` deny | **allowed** |
| `egressDeny toCIDR 172.19.0.0/16` + explicit **`toCIDR 172.19.0.4/32` allow** (a `world` destination) | **denied — deny wins** |

Denying a cluster pod's own `/32` does not touch an identity-based allow to that pod, so
the deny wall can carry RFC1918, CGNAT, metadata and loopback **without any risk** of
blackholing `:8788` or the controlled resolver. The fallback the plan held in reserve —
scoping denies to metadata plus non-cluster private space — is **not needed**.

Two consequences that are now design constraints rather than observations:

1. **`public` mode must allow `toEntities: [world]` (or `toCIDR: 0.0.0.0/0`), never
   `toEntities: [all]`.** Because CIDR/`world` selectors do not reach cluster identities,
   a `0.0.0.0/0` allow does **not** implicitly open the cluster — that property is what
   makes `public` safe, and `all` would throw it away.
2. **Deny precedence is global across policy objects** (see the composition test below),
   which is what lets the wall live in a chart-static object the per-run policy cannot edit.

## R3 — `CiliumEndpoint.status.policy` shape — **assumption falsified**

The plan expected `status.policy` to carry `realized` / `policy-enabled` /
`policy-revision` for the control-plane half of `verify()`. On 1.19.6:

```
.status keys       = [encryption, external-identifiers, id, identity, networking,
                      service-account, state]
.status.policy     = {}          # present but EMPTY
```

`helm show values cilium/cilium --version 1.19.6 | grep endpointStatus` returns
**nothing** — the `endpointStatus` knob that used to populate it no longer exists in the
chart. `CiliumNetworkPolicy.status` carries only a validation condition
(`{type: Valid, status: "True", message: "Policy validation succeeded"}`), not the
per-node enforcement map older Cilium versions published.

The enforcement fact **does** exist, but only node-locally, via the agent:

```
cilium-dbg endpoint list
591  Disabled(ingress)  Enabled(egress)  39493  k8s:app=fluidbox-sandbox
                                                k8s:fluidbox.dev/session-id=s1
```

Reaching that requires `exec` into the agent DaemonSet — a privilege the control plane
must not take, and not something the k8s API exposes.

**Redesigned `verify()` control-plane half** (Phase 3 changes accordingly):

- **Policy acceptance is proven at write time, not read time.** A malformed CNP is
  rejected by CRD schema validation at the API call itself:
  `spec.egress[0].toFQDNs[0].matchName: Invalid value: "not a valid fqdn!!" ... should
  match '^([-a-zA-Z0-9_]+[.]?)+$'`. `prepare()` therefore gets a hard error from the
  create, which is a *better* fail-closed signal than a status poll — there is no window
  in which a bad policy is silently pending.
- **Then confirm, over the k8s API only:** the CNP's `status.conditions[type=Valid]` is
  `True` (the operator accepted it semantically), and the pod's `CiliumEndpoint` exists
  with `status.state == "ready"` and a `status.identity.id`.
- **Realization stays with the in-netns `netpol-gate` init container**, which already
  proves enforcement from the pod's real network identity before untrusted code runs.
  The honest framing, which the docs must carry: the control-plane half is a
  **policy-acceptance and identity-binding** check; it is *not* a realization check, and
  nothing available over the k8s API on 1.19.x is.

---

## Beyond the three questions

### The Phase 3 object composition works as designed

A chart-static `CiliumClusterwideNetworkPolicy` (default-deny trigger + standing `:8788`
allow by server-pod identity + the deny wall) composed with a per-run `CiliumNetworkPolicy`
(DNS visibility + the grant):

| Probe | Result |
|---|---|
| baseline `:8788` by server identity | allowed |
| per-run granted FQDN | allowed |
| **per-run policy explicitly allows `169.254.169.254/32`, wall denies it** | **denied — the wall wins across objects** |
| pod with the baseline **only**, no per-run grant | offline: `:8788` allowed, everything else denied |

The third row is the structural guarantee the whole design rests on: **deny precedence is
evaluated across all policies**, so a per-run grant — however it is computed, and even if
resolution were buggy — cannot open what the chart-static wall denies. Offline mode is
default-deny by absence-of-allow, byte-identical in effect to today's `zeroEgress`.

### Cross-run isolation holds, and keying the per-run CNP on identity labels is load-bearing

Two runs, `s1` granted `echo.spike.test` (172.19.0.4) and `s2` granted `echo2.spike.test`
(172.19.0.5), each with a CNP keyed on `fluidbox.dev/session-id`. After both resolved
their own names:

```
s1 -> s2's target by FQDN  : DENIED
s1 -> s2's target by raw IP: DENIED
s2 -> s1's target by raw IP: DENIED
```

Identities are derived from labels and are distinct per run (`s1` = 39493, `s2` = 64147).

This is not a free property. **Within a single policy's selector, an FQDN grant's resolved
IPs are reachable by raw IP by every endpoint that policy selects — including a pod that
never performed the lookup.** A fresh pod matching a shared `app: fluidbox-sandbox`
selector reached `172.19.0.4` directly on its *first* packet, before issuing any DNS. The
cause: `toFQDNs` resolution produces cluster-wide CIDR **identities**, and the selector
matches that identity for every endpoint the policy selects — it is not a per-connection
or per-pod binding to a DNS answer.

So the plan's "keyed on all three identity labels" is what *creates* cross-run isolation.
A per-run CNP that selected `app: fluidbox-sandbox` alone would silently pool every
concurrent run's granted IPs into one reachable set. Phase 3 must treat the selector as a
security control and Phase 4 must regression-test it.

### Direct-IP within a grant's own target set is not blocked — state it, don't imply otherwise

Following from the same mechanism: an FQDN grant enforces as *"the IPs these names have
resolved to, within the DNS cache TTL"*, not as *"connections that went through a DNS
lookup for these names."* A run granted `pypi.org` can reach `pypi.org`'s current
addresses by raw IP. It **cannot** reach anything else (`172.19.0.5` stayed denied
throughout), so the grant is still a containment boundary — but the threat-model wording
must be "the grant is the resolved address set", and the DNS-rebinding residual the plan
already names is the same fact seen from the other side.

---

## Gate decision (the plan's Phase 0 gate)

> **Gate: R2's answer picks the deny-set shape before Phase 3.**

**Deny-set shape: the full wall.** Metadata, loopback, link-local, RFC1918, CGNAT,
injected cluster pod/service/node CIDRs, `::/0`, and the `host` / `remote-node` /
`kube-apiserver` entities all go in the chart-static `CiliumClusterwideNetworkPolicy`,
with no carve-outs. Cluster-internal reachability is unaffected because it is granted by
identity, and the wall outranks every per-run allow.

**Carried into Phase 3 as changes to the written plan:**

1. `verify()`'s control-plane half reads CNP `Valid` + CEP `state`/`identity`, **not**
   `status.policy` (which does not exist on 1.19.x). Realization proof stays in-netns.
2. `public` mode lowers to `toEntities: [world]`, never `[all]`.
3. The per-run CNP selector is a security control; it must carry all three run identity
   labels, with a test that fails if it is ever widened.

## Fixtures

The hand-written manifests that produced every result above are checked in beside this
note under [`2026-08-01-cilium-substrate-spike/`](./2026-08-01-cilium-substrate-spike/):
`kind-config.yaml`, `baseline-ccnp.yaml`, `run-s1.yaml`, `run-s2.yaml`,
`run-s1-hostile.yaml`, `r1-cegp.yaml`, `r2c-exact-podip-deny.yaml`, `fixtures.yaml`.
They are Phase 0 evidence, not shipped objects — Phase 3 generates the real ones from
Rust builders and pins them against `examples/` fixtures.
