# Governed sandbox network access

**Status:** Phases 0–3 implemented; Phase 4 (kind validation) scripted; Phases 5–6
outlined. Epoch continuation is a deliberately separate effort — see *Deferred*.

Fluidbox sandboxes were all-or-nothing on the network: on Kubernetes default-deny
with only the control plane's `:8788` reachable, on Docker either a per-session
internal bridge (`hardened`) or a host-gateway dev posture (`host-dev`, never a
boundary). The existing `egress.rs`/`netpolicy.rs` machinery governs *control-plane*
HTTP; it has never governed a single sandbox packet.

This effort lets arbitrary workloads use normal DNS, sockets and TLS while fluidbox
decides where each run may connect. **"No egress" now means no *unmediated* egress**,
enforced at L3/L4 in the datapath, with no application shims and nothing for the
workload to opt into or around.

---

## The model

- **`NetworkGrant`** — versioned, immutable, frozen into the `RunSpec`. Mode
  `offline | approved | public`; FQDN/CIDR target rules with protocol and ports; an
  absolute expiry; a policy digest. Old frozen specs deserialize to `offline` via
  `#[serde(default)]`, the additive pattern `invocation` and `brokered` already
  proved.
- **Resolution before provisioning.** `create_run` intersects the agent revision's
  declaration with any downstream narrowing, applies the policy cap and the deny
  order, and takes one of three tails: freeze-and-spawn, freeze-and-park, or refuse.
  No pod exists until the grant resolves, and a sandbox can never widen one.
- **Enforcement is provider-neutral.** `NetworkPolicyProvider::{prepare, verify,
  revoke}`. Kubernetes is Cilium; Docker enforces `offline` only; a deployment with
  no enforcer is offline-only and fails closed.

### Decisions, and why

**Authority is epoch-scoped.** A session already *is* an epoch — fresh sandbox,
freshly minted credentials, policy read at creation. A grant binds to one epoch and
cannot outlive it. Its expiry is validated to cover the run's own wall-clock
deadline so it never fires mid-run; the field is absolute and schema-versioned so a
follow-on effort can add a shorter epoch clock without redesigning anything here.

**A new session state, not a reused one.** The pre-provisioning pause is
`SessionStatus::AwaitingAuthorization`, with edges `Created → AwaitingAuthorization
→ Provisioning` plus wind-down. Reusing `AwaitingApproval` would have opened
`Created → AwaitingApproval → Running`, defeating `no_skipping_init`, which only
checks direct edges and would miss the transitive bypass.

Adding the variant is mostly *not* compiler-caught. `accepts_work()` was rewritten
from a negative definition to a wildcard-free match, so an unclassified variant now
fails to compile instead of silently answering "yes, this may spend money and call
tools". The hand-audit found one real gap: `reconcile_action` would have ADOPTED a
sandbox belonging to a session nobody had authorized; it now terminates it.

**Freeze, then approve.** The grant is computed and frozen at session creation; the
approval gates whether provisioning proceeds. This is the only ordering consistent
with RunSpec immutability, and it gives the approver a stable digest to consent to
(`approvals.input_digest == grant_digest`). A policy edit between freeze and decision
therefore cannot mutate the pending grant — so the release path re-verifies digest,
expiry and the current policy, and a policy that now permits *less* refuses the run
rather than silently substituting something narrower.

**Grants are declared on the agent revision and narrowed downstream.** A revision
declares what the agent needs; policy caps it; a subscription or per-run override may
only narrow. Without this every scheduled and webhook-triggered run would be
offline-only — a schedule has no caller to pass a request. Mirrors
`Budgets::tightened_by` and the remove-only capability keep-list.

**Deny precedence is a documented total order**, proven pairwise-exhaustively rather
than one condition at a time: structural deny → policy deny → mode ceiling →
`public`+brokered → target-catalog subset → approval → allow. Expiry clamps;
everything else refuses rather than silently downgrading.

**`public` + brokered surfaces is refused unless policy opts in**, following the
`TrustTier::ReadOnly` precedent. The dangerous pairing is credentials plus reach.

---

## What the Phase 0 spike changed

Three datapath assumptions were proven on kind + Cilium 1.19.6 before any enforcement
Rust was written ([full findings](../reviews/2026-08-01-cilium-substrate-spike.md)).
Two came back favourable; one was **falsified**:

- **`CiliumEndpoint.status.policy` is empty on 1.19.x** and the `endpointStatus` Helm
  knob no longer exists. `verify()`'s control-plane half therefore reads CNP
  `status.conditions[Valid]` plus the endpoint's `state`/`identity` — and a malformed
  policy is rejected at the API call itself, which is a better fail-closed signal
  than any status poll. Realization proof stays with the in-netns `netpol-gate` init
  container, which already proves enforcement from the pod's real identity. The
  honest framing, carried into the docs: the control-plane half is a
  policy-acceptance and identity-binding check, **not** a realization check.

Two findings became structural design constraints:

- **CIDR selectors never bind in-cluster identities** — a deny on a cluster pod's
  exact `/32` does not touch an identity-based allow to it. So the deny wall carries
  the full blocked-class list with no risk of blackholing `:8788` or the resolver,
  and `public` must lower to `toEntities: [world]`, never `[all]`.
- **Deny precedence is global across policy objects** — a per-run policy explicitly
  allowing `169.254.169.254/32` was still denied by a wall in a different object.
  That is what makes the chart-static wall the floor no per-run grant can open.

And one the spike raised on its own: **the per-run policy's selector is a security
control.** Within one selector, an FQDN grant's resolved addresses are reachable by
every endpoint that policy selects, including one that never did the lookup. Keying
on all three run identity labels is what creates cross-run isolation; a unit test
pins it at exactly three.

---

## Object model (Kubernetes)

| Object | Owner | Why there |
|---|---|---|
| `CiliumClusterwideNetworkPolicy` baseline + deny wall | chart | Cluster-scoped, so the server never needs cluster-scoped write — a compromised control plane cannot rewrite the wall containing its own sandboxes. Triggers default-deny and grants `:8788` by **server pod identity**, so it survives DNS and gateway failure. |
| Controlled CoreDNS (Deployment + Service) | chart | Forward-only, **no `kubernetes` plugin**, so a sandbox cannot resolve in-cluster Service names. Sandbox pods use `dnsPolicy: None` pointed at it. |
| `CiliumEgressGatewayPolicy` | chart | SNAT + attribution only. **Never** the boundary. |
| Per-run `CiliumNetworkPolicy` | server | The grant itself, selected on all three run identity labels. |

**Object ordering: Pod → CNP (ownerReference to the Pod UID) → verify → Secret last.**
Creating the CNP strictly before the pod would leave it with no owner, and nothing
today would collect it — `terminate()` deletes only Pods and `list_managed()` lists
only Pods. Because Cilium allow rules are additive, a surviving CNP that later matched
a re-created pod would silently *reopen* traffic. The fix uses a property the pod
already has: a container whose `secretKeyRef` is missing cannot start. So the pod
exists but nothing that matters has started, enforcement still precedes untrusted
code, and GC now backstops cleanup. It is a one-step delta from the existing
Pod-then-Secret order.

---

## Verification

| Phase | Gate |
|---|---|
| 0 | Findings note with pinned Cilium version + image digest, and the R2 answer picking the deny-set shape. **Done.** |
| 1–3 | `just check` (fmt, clippy `-D warnings`, workspace tests, web build). **924 tests green.** |
| 2 | `bash scripts/governance-e2e.sh` — refuse-on-unenforceable, the pause, approve, deny over real HTTP. **64/64.** |
| 4 | `bash scripts/netgrant-kind-validation.sh` — full assertion matrix on real Cilium, exit 0, no skips. |
| 6 | A live managed-cluster acceptance report. Unit tests and YAML alone do not count. |

## Deferred to effort #2 — epochs and continuation

Not built here; recorded so the follow-on starts warm. The product model stands:
goals may be indefinite, every execution is a finite renewable epoch, and boundaries
checkpoint state, re-resolve policy, rotate credentials and network authority, and
move to a fresh sandbox. This effort makes a grant epoch-scoped and schema-versioned.

What it will need, already verified against the code:

- **Graceful drain must route through `Cancelling`** — the quiesce channel keys on
  that status alone, and a quiesced runner exits *without* posting `/result`. Reuse
  the generic `finalize_forced`, which already quiesces for budget expiry.
- **Checkpoints need their own typed namespace, not a prefix.** `archive_ttl_sweep`
  reclaims unrecognized keys and key recognition accepts only a UUID basename — and
  the backends disagree: S3 lists recursively under the prefix (so a `checkpoints/`
  subdirectory is *not* isolated) while the filesystem backend scans only direct
  files (so it silently escapes).
- **A checkpoint is untrusted input.** Digest verification proves only that the
  unpacked bytes are the bytes the collector hashed. Unlike today's archives — packed
  by the control plane from a pristine source — a checkpoint comes from a workspace
  the agent fully controlled, making it a durable cross-epoch channel for prompt
  injection, poisoned build artifacts, and secrets written to disk. Needs hardened
  extraction and an explicit residual: **a checkpoint inherits the trust level of the
  epoch that produced it.**
- **Goal budgets cannot be a `SUM` on read** — that reintroduces the check-then-book
  race migration 0022 closed. Needs a durable lineage row locked during admission,
  and an explicit wall-clock choice (sum-of-epochs and elapsed-goal-time are
  different budgets).
- **Lineage fencing** via partial unique indexes over non-terminal rows.
