# Hosted rollout gates

**Date:** 2026-07-21
**Status:** Phase F deliverable of the multi-user MCP control plane epic (#28)
**Authority:** [`../plans/2026-07-14-multi-user-mcp-control-plane-design.md`](../plans/2026-07-14-multi-user-mcp-control-plane-design.md) §Phase F (rollout), §Scale model for 300 users, §Operational metrics.

The design names five rollout stages and a sixth deferral. This document turns
each into a gate with an **exit criterion that can be checked**, because "internal
single-org environment" is a description of a situation, not a decision procedure.

A gate is closed when its evidence exists and its thresholds hold **on the
deployment being promoted**, not on a previous one. Promotion is not automatic:
each gate ends with a named human decision.

## How to read a threshold

Every threshold below is a **planning figure derived from the design's assumptions**
(§Scale model: 300 users, 5 connections each, 10–20% concurrency, ~3 MCP servers
per active run), not an observed production number. The design says so itself:
"Planning assumptions, to be replaced with observed pilot data." **Gate 2 is where
they get replaced.** If pilot data contradicts a figure here, the figure is wrong —
update it and say so in the gate's evidence, rather than steering the deployment to
match a guess.

Three things are true of every gate and are not repeated in each one:

- **No gate is closed by a green test suite alone.** `scripts/scale-e2e.sh` proves
  mechanisms at small N in CI; it deliberately cannot prove capacity.
- **Any gate may be re-opened.** A regression in a closed gate blocks the next
  promotion, not just its own.
- **Cost is part of the evidence.** A gate that passes only by spending
  unsustainably has not passed.

## Gate 0 — prerequisites (before stage 1)

Not in the design's list; added because stages 1–5 all assume it.

| Requirement | Why it gates everything | Evidence |
|---|---|---|
| `FLUIDBOX_REQUIRE_SSO=1` | Multi-user identity is off by default; every tenant-isolation property below is vacuous without it | Boot log; `/v1/auth/me` returns a real principal |
| `FLUIDBOX_RUNTIME_ROLE` set to a posture-valid non-owner role | RLS is inert for a SUPERUSER/BYPASSRLS role, which is Neon's default. Multi-user boot refuses the bad combination, so this is enforced — but verify it rather than assume the refusal fired | `just doctor` clean; boot log names the role |
| KMS envelope sealing enabled (`FLUIDBOX_KMS_MODE`) and the KEK backed up | Custody roots on the KEK from the moment any v2 row exists; losing it is unrecoverable | Re-seal job reports zero v1 rows; documented KEK backup location |
| Runner images rebuilt from this branch | A pre-Phase-E image collapses a `wrong_audience` 403 into a silent deny and burns model spend with every tool denied | Image digest pinned in the agent revision matches the built digest |

**Decision:** the operator confirms all four. This gate has no threshold — it is a
checklist because each item is binary.

## Gate 1 — internal single-organization environment

**Purpose:** prove the system runs at all under hosted settings, with one
organization whose users are the team that built it.

| Criterion | Threshold | Evidence |
|---|---|---|
| A run completes end to end under hosted config | 20 consecutive runs, zero manual intervention | Run list; event timelines |
| Every gate verdict is attributable | 100% of tool calls produce `tool.requested` → `tool.decision` | Ledger query |
| No credential appears in logs or the ledger | Zero matches for the token prefixes and sealed-column names | Log grep, as `secrets-e2e.sh` section (k) does per boot |
| Approvals work through the dashboard | Pause, approve, deny, and expiry each observed once | Timeline screenshots or event query |

**Decision:** the team dogfoods for one week without a Sev-1. Single replica is
acceptable here; multi-replica is not yet required.

## Gate 2 — 10–25 user pilot

**Purpose:** replace the design's planning assumptions with observed data. This is
the gate whose *output* is more important than its pass/fail.

| Criterion | Threshold | Evidence |
|---|---|---|
| Concurrency observed vs. assumed | Record actual peak concurrent runs / registered users | Active-runs gauge, 1-week peak |
| Connections per user observed vs. assumed (5) | Record the real distribution, not the mean alone | Connection count by owner |
| MCP servers per active run observed vs. assumed (3) | Record the real distribution | Frozen-surface count per RunSpec |
| Per-run cost distribution | p50 and p95 model spend per run | Usage entries by session |
| Approval latency | p95 time from `approval.requested` to decision | Ledger timestamps |
| Zero cross-tenant reads | Any occurrence is a stop-ship, not a threshold | Negative-test suite + audit log |

**Decision:** the assumptions table in the design doc is updated with observed
figures, and the capacity model in Gate 3 is recomputed from them. **A pilot that
does not produce these numbers has not closed this gate**, even if nothing broke.

## Gate 3 — 60-concurrent-run capacity gate

**Purpose:** the design's own first capacity checkpoint (§Scale model: "normal
active sandboxes 30–60"). This is the gate the load harness exists for.

Run the harness at 60 concurrent sandboxes against a deployment shaped like
production (multi-replica, real Postgres, real sandbox fleet), and hold:

| Criterion | Threshold | Why this number |
|---|---|---|
| Run provisioning latency | p95 within the deployment's stated SLO, and no upward trend across the run | A rising trend means a queue, and a queue at 60 becomes a failure at 300 |
| Database pool saturation | Pool never sustains 100% checked-out; acquire timeouts zero | The pool was the first hard ceiling found in this phase; it is now configurable and must be sized from this measurement |
| Gate decision latency | p95 unchanged vs. the idle baseline by more than a stated factor | The gate is on every tool call; if it degrades under load, everything does |
| Brokered call outcomes | Ambiguous outcomes remain a small fraction, and every one is surfaced | Ambiguity is never retried, so it converts directly into operator work |
| Budget reservations | No run exceeds its budget beyond the disclosed sole-claimant bound | Reservation + usage rows |
| Egress governance | Deployment-wide ceiling observed to bind, not N× it | Durable rate-window rows vs. configured limit |
| No orphaned sandboxes | Zero after teardown, audited at the substrate | The Kubernetes epic's zero-orphan audit, repeated under load |

**This gate costs real money and provisions real infrastructure.** It requires
explicit owner approval before each execution, and the cost estimate is part of
the approval request.

**Decision:** promote only if every row holds *and* the pool/quota/limit values
used are recorded, because Gate 5's sizing is extrapolated from them.

## Gate 4 — multiple-organization beta

**Purpose:** prove tenant isolation with tenants who do not trust each other, and
prove that one tenant cannot degrade another.

| Criterion | Threshold | Evidence |
|---|---|---|
| Cross-tenant isolation under load | Tenant-isolation fuzz passes while the deployment is busy, not only when idle | `scripts/scale-e2e.sh` fuzz section, plus a run against the beta deployment |
| Noisy-neighbour containment | One tenant saturating its egress ceiling does not raise another tenant's error rate | Per-tenant rate-limit and error metrics side by side |
| Per-tenant cost attribution | Every model call attributes to exactly one tenant; totals reconcile with the gateway | Usage entries vs. LiteLLM key spend |
| Per-tenant LLM keys | `FLUIDBOX_LLM_KEY_MODE=tenant` in force, master key confined to provisioning | Boot config; facade refuses `shared` under SSO |
| Personal-connection authority | No admin or operator can decide an approval on another user's personal connection | Negative test on the live deployment |

**Known open risk carried into this gate:** the transferable connector-OAuth
`go_url` lure ([threat model](threat-model.md#residual-detail--the-transferable-connector-oauth-go_url)).
It is a social-engineering path that yields an attacker-held connection to a
victim's account. **Multi-organization beta is the stage at which it stops being
theoretical**, because tenants are now mutually untrusted. Either build the
documented closure (move the browser-facing leg onto the dashboard origin and drop
`c` from the `/go` token) or accept it explicitly, in writing, with the beta
tenants informed.

**Decision:** security review sign-off on the isolation evidence, plus an explicit
ruling on the `go_url` residual.

## Gate 5 — 300-seat production target

| Criterion | Threshold | Evidence |
|---|---|---|
| Capacity at the full-seat stress case | The harness sustains the design's 300-sandbox case, or the deployment documents a lower supported ceiling | Load-harness report |
| Replica failure | Killing a replica mid-run loses no run: leases transfer, deliveries re-claim, upstream MCP sessions are still torn down | Fault injection |
| Database failover | A failover mid-run recovers without duplicate side effects | Fault injection; delivery and claim tables after recovery |
| Sustained soak | The deployment holds the target for a sustained period without unbounded memory or connection growth | Soak report |
| Every disclosed residual is either closed or accepted in writing | No residual reaches production undecided | Threat-model residual table, signed off |

**Decision:** owner sign-off on the residual table, not just the metrics.

## Gate 6 — BYOC / private MCP

Deferred by the design until the shared SaaS boundary is proven. It is listed here
so it is visibly *not* in scope: private endpoints remain BYOC/relay/explicit-approval
only, and per-tenant egress destination allowlists are a disclosed gap
([threat model](threat-model.md), accepted residuals).

## What this document deliberately does not do

It does not set numeric SLOs for latency or availability. Those belong to the
operator of a specific deployment and depend on the substrate, the region, and the
model provider — inventing them here would create the same kind of unfounded
capacity claim this phase had to correct in the Helm chart.
