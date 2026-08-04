# Governed sandbox network access — operations

How to turn sandbox network grants on, what refuses and why, and what to do
when something is wrong. Companion to
[`kms-operations.md`](./kms-operations.md); thresholds follow
[`rollout-gates.md`](./rollout-gates.md).

The design rationale lives in the design doc; the datapath evidence lives in
[`docs/reviews/2026-08-01-cilium-substrate-spike.md`](../reviews/2026-08-01-cilium-substrate-spike.md).

---

## §1 What a grant is

A **`NetworkGrant`** is the frozen answer to "where may this run connect?",
resolved before any sandbox exists and stored immutably in the RunSpec.

| Mode | Reach |
|---|---|
| `offline` | Nothing beyond the control plane's `:8788`. The default, and what every run had before this feature. |
| `approved` | Exactly the declared FQDN/CIDR targets, on the declared ports and protocol. |
| `public` | Everything the deployment's deny wall permits. |

Authority is **epoch-scoped**: a grant binds to one run, carries an absolute
expiry validated to outlive that run's wall-clock budget, and is revoked when
the run ends. It cannot be widened from inside a sandbox, because the grant is
in the frozen spec and the enforcement is below the application.

## §2 Enabling it

**Order matters, and it is the same discipline migration 0018 needed: deploy
the binary everywhere FIRST, then enable.** A binary that predates the
`awaiting_authorization` session status reads a parked run as `failed`
(`SessionRow::status_enum` maps an unrecognized status to `Failed`), so a mixed
fleet would reap its way through the authorization pause.

1. **Roll the binary to every replica.** Migration 0028 is additive and safe to
   apply early; nothing changes behaviour until step 3.
2. **Install the chart half**, with Cilium already the cluster's CNI:

   ```yaml
   networkGrants:
     enabled: true
     clusterCIDRs: [10.0.0.0/8, 172.16.0.0/12]      # your pod/service/node ranges
     deploymentPublicCIDRs: [203.0.113.10/32]        # your LB / Ingress addresses
     upstreamResolvers: [1.1.1.1, 8.8.8.8]
   ```

   `deploymentPublicCIDRs` is **not optional in practice**: a `public` grant is
   `0.0.0.0/0`, which would otherwise hairpin back to your own public API
   through your own load balancer, reaching unauthenticated auth/OAuth/webhook
   surfaces. The chart cannot discover these addresses.
3. **Set `FLUIDBOX_NETWORK_ENFORCER=cilium`** on the server. The boot log states
   the resolved enforcer; with it unset the log says the deployment is
   offline-only, and any wider grant is refused at create time.
4. **Grant capability per policy**, which is where the ceiling lives:

   ```yaml
   network:
     max_mode: approved
     require_approval: true
     allow:
       - kind: dns
         pattern: { kind: wildcard, suffix: "pypi.org" }
         ports: [{ from: 443, to: 443 }]
         protocol: tcp
   ```

   A policy that says nothing about the network caps at `offline`, so nothing
   changes for any existing agent until someone edits a policy on purpose.
5. **Declare on the agent revision** what it needs. Without a declaration every
   scheduled and webhook-triggered run is offline-only — a schedule has no
   caller to pass a request. A subscription or per-run override may only NARROW
   the declaration.

## §3 Reading a refusal

Every refusal is enumerated. `fluidbox_network_grant_refusals_total{reason}`
counts them, and the API returns the same code's message.

| Code | Means | Fix |
|---|---|---|
| `unenforceable` | No enforcer configured or detected. | §2 step 3, or run the agent offline. |
| `mode_ceiling` | The request exceeds `network.max_mode`. | Raise the policy ceiling, or narrow the agent. |
| `not_in_catalog` | A target is outside `network.allow`. | Add it to the policy, or drop it from the agent. |
| `policy_deny` | An explicit `network.deny` rule covers it. | Intended; the deny is doing its job. |
| `blocked_range` | A CIDR target reaches a structurally blocked class (metadata, RFC1918, loopback…). | Never grant these. The datapath denies them regardless. |
| `public_with_brokered` | A `public` run also holds brokered tool surfaces. | Narrow to `approved`, or set `allow_public_with_brokered` if the pairing is genuinely intended. |
| `expiry_too_short` | The grant would lapse before the run's wall clock. | Raise `network.max_grant_secs` or lower the run's budget. |
| `invalid_target` | A target could never be lowered to a datapath rule. | Fix the declaration; the message names the problem. |

Refusals at RELEASE time (a parked grant that could not be activated) add:
`grant_digest_mismatch`, `grant_expired`, `policy_moved`, `grant_not_pending`,
`grant_schema_unsupported`. All of them mean *recreate the run* — a stale
authorization is never silently substituted with a narrower one.

## §4 The authorization pause

With `require_approval: true`, a run is frozen and parked in
`awaiting_authorization` **before provisioning**. There is no pod, no token, and
no possible model spend while it waits.

- The approval's `input_digest` **is** the grant digest, so what a human
  consents to is provably what gets activated.
- Deciding it is an **organization** authority — never self-approval. Widening a
  sandbox's reach is not something a run's own initiator may authorize.
- The approval TTL is the pause's **only** bound: wall-clock budget deliberately
  does not accrue while parked, because a run should not burn its budget waiting
  for a human. An unanswered pause is reaped by the ordinary approval-expiry
  worker.
- Release re-verifies digest, expiry and the CURRENT policy. A policy edited to
  permit LESS refuses the run rather than downgrading it.

## §5 Metrics and alerts

Both families are fixed-cardinality — the label is a mode or an enumerated
code, never a target, host, or tenant (per-tenant attribution is a ledger
question; see the cardinality note in `metrics.rs`).

| Metric | Watch for |
|---|---|
| `fluidbox_network_grants_total{outcome}` | `awaiting_authorization` climbing while `active` does not — approvals are not being answered. |
| `fluidbox_network_grant_refusals_total{reason}` | A spike in `unenforceable` after a deploy: the enforcer env var was lost. A spike in `not_in_catalog`: an agent was widened without its policy. |

**Page** on `unenforceable > 0` in a deployment that is supposed to have an
enforcer — it means every non-offline run is being refused. **Ticket** on a
sustained `awaiting_authorization` backlog. Do **not** alert on `denied`: a
human refusing a grant is the system working.

## §6 Failure modes

| Symptom | Cause | Behaviour |
|---|---|---|
| Runs refuse with `unenforceable` | `FLUIDBOX_NETWORK_ENFORCER` unset/`none` | Fail closed. Offline runs unaffected. |
| Controlled CoreDNS is down | Resolver outage | Name-based grants stop resolving. `:8788` is unaffected — it is allowed by SERVER POD IDENTITY, not by name — so runs still report. |
| Egress-gateway node is down | Gateway outage | Egress stops for granted targets. The gateway is SNAT and attribution only, never the boundary; `:8788` is not in that path. |
| A parked run never releases | Approval unanswered, or the grant lapsed | The approval TTL reaps it; the run fails with the enumerated reason. |
| A CNP exists for a session with no pod | A leak | Owner-reference GC collects it; the reconcile sweep is the backstop. This matters because Cilium allow rules are ADDITIVE — a surviving policy that later matched a re-created pod would silently reopen traffic. |

## §7 Residuals — stated, not implied

- **An FQDN grant enforces as the RESOLVED ADDRESS SET, not as a per-connection
  binding to a DNS answer.** A run granted `pypi.org` can reach `pypi.org`'s
  current addresses by raw IP. This is the same fact as the DNS-rebinding
  window, seen from the other side.
- **Consequently, a co-hosted virtual service behind a granted address is
  reachable.** If `pypi.org` shares an address with other sites (a CDN or shared
  reverse proxy), the datapath admits that address on that port and cannot tell
  which `Host`/SNI the workload then asks for. A grant is therefore
  "address × port", not "service identity". Grant names whose addresses you are
  willing to have reached in full.
- **An `approved` grant may look up only the names it was granted.** This is
  enforced, not advisory: an unrestricted DNS rule would be an exfiltration
  channel on its own (encode data into a lookup for an attacker-controlled
  domain and their nameserver receives it, with no connection to block).
  `public` keeps an unrestricted lookup because it may already reach anything
  the wall permits.
- **Cross-run isolation depends on the per-run policy's selector.** It carries
  all three run identity labels; a widened selector would pool concurrent runs'
  granted addresses into one reachable set. There is a unit test pinning it.
- **Attribution under a shared egress gateway is by Hubble flow, not by source
  IP** — every run behind one gateway shares its SNAT address.
- **Bytes come from the collector's `/proc/net/dev`, decisions from Hubble.**
  Hubble flows carry no reliable per-flow byte counts, so the two halves have
  different sources and different failure modes.
- **The Docker `host-dev` profile is not a boundary** and never was. Docker
  enforces `offline` only, under `hardened`.
