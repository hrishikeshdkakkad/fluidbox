# E2E scenario matrix on the live EKS deployment (2026-08-05)

Follow-up to `2026-08-04-network-grant-ui-acceptance/`, which proved exactly one
scenario (the `public` golden path). This run covers the scenarios that acceptance
deliberately left open: every refusal reason, `approved` mode, the bypass matrix,
cross-run isolation, Deny, and the per-run offline override.

**Verdict: PASS, with one real defect found and fixed** (cold-start enforcement
deadline, §5). Everything the network-grant feature claims is now demonstrated
against the live cluster rather than against kind.

Deployment under test: server image
`ghcr.io/hrishikeshdkakkad/fluidbox-server@sha256:bd8367…` (digest-matched to
GHCR tag `0.6.0`), chart `fluidbox-0.6.0`, helm revision 6, enforcer `cilium`.
Org `fluidzero`, agent `test` (codex, gpt-5.4-mini), policy `init`.

---

## 1. Authoring-time refusals — `POST /agents/{id}/revisions` (422, nothing persists)

| # | Declaration | Result |
|---|---|---|
| R1 | `public` **with** targets | 422 — "a public grant must not carry targets — … reads as a narrowing that the datapath would not apply" |
| R2 | wildcard suffix containing a literal `*` | 422 — not a valid DNS name |
| R3 | target naming **no** ports | 422 — "an all-ports grant must say so explicitly as 1-65535" |
| R4 | inverted port range `9000-80` | 422 — "port range 9000-80 is inverted" |
| R5 | port `0` | 422 |

## 2. Run-creation refusals — `POST /sessions` (422, no sandbox, $0)

| # | Setup | Refusal |
|---|---|---|
| C1 | agent declares `public`, ceiling `approved` | `network mode 'public' exceeds the policy ceiling 'approved'` |
| C2 | target `169.254.169.254/32` (cloud metadata) | structurally blocked range |
| C4 | target `github.com` under catalog `*.github.com` | **not covered** — proves a wildcard does NOT match the apex |
| C5 | target `example.org`, not in catalog | not covered by the policy's allowed targets |
| C6 | catalogued host, **wrong port** (22 vs 443) | not covered — port is part of the catalog check |
| C3a | operator deny on `api.github.com` (a name) | explicitly denied by policy |
| C3b | operator deny on public CIDR `140.82.112.0/20` | explicitly denied by policy |
| C7 | name-based deny under a `public` ceiling | refused: "a name-based deny cannot be programmed in the datapath (Cilium's egressDeny has no FQDN selector) — so a 'public' grant would allow the world with that deny silently absent" |

Note on C3: the first attempt used `10.1.2.3/32` and came back as *BlockedRange*,
not *PolicyDeny* — RFC1918 is refused structurally, before the operator's deny is
consulted. The test was re-run on genuinely public targets to reach the deny rule.
Worth knowing: an operator deny on private space is redundant, not load-bearing.

The `deny` lists above were published **through the API**, which the dashboard
cannot author — so this exercises server-side policy paths the UI does not reach.

## 3. `approved` mode on the live datapath — the bypass matrix

One run, one grant. Catalog: `pypi.org`, `*.pypi.org`, `files.pythonhosted.org`,
`github.com`, `*.github.com`, `*.githubusercontent.com`, **TCP/443 only**.

Allowed — all `REACHED`:
`pypi.org/simple/` · `files.pythonhosted.org` · `github.com` (apex, exact rule) ·
`api.github.com` (wildcard rule) · `raw.githubusercontent.com`

Denied — all `BLOCKED`:
`example.com` (host not in catalog) · `cloudflare-dns.com` (DoH) ·
`169.254.169.254` (**cloud metadata**) · `http://pypi.org` (**port 80 — catalog is
443**) · `1.1.1.1` and `8.8.8.8` (raw IP, foreign hosts) ·
`kubernetes.default.svc` (**in-cluster service discovery**)

Real toolchains under the same grant — both `REACHED`:
`git clone https://github.com/octocat/Hello-World` · `pip download six` (needs
pypi.org *and* files.pythonhosted.org).

**DNS layer:** resolving a non-granted name (`example.com`) **FAILED**, while a
granted name resolved. The sandbox cannot even look up what it may not reach —
the DNS-exfiltration control is live, not just modelled.

Informational: `https://140.82.112.3` (github.com's *own* resolved IP) was
`REACHED`. Expected and documented — an FQDN grant enforces as the resolved
address set.

The programmed CNP was inspected directly: DNS `matchName`/`matchPattern` rules
gate resolution, `toFQDNs` + TCP/443 gate egress, and `endpointSelector` keys on
**all three** identity labels (`session`, `run`, `tenant`).

## 4. Cross-run isolation — the property isolation rests entirely on

Run A (grant: github only) resolved `github.com` → **140.82.112.3** and reached
it, warming the node's FQDN cache. Run B was then created with a **pypi-only**
grant — by appending a revision, which also demonstrates RunSpec immutability
(A kept its frozen github grant).

| Probe from run B | Result |
|---|---|
| B1 own grant `https://pypi.org` | REACHED |
| B2 cross by **name** `https://github.com` | BLOCKED |
| B3 cross by **raw IP** `https://140.82.112.3`, cache warm | **BLOCKED** |

B3 is the decisive one: a different run's identity cannot reach an address the
node already knows.

*Honest scoping:* A had just completed when B probed, so this is a warm-cache
cross-probe rather than two strictly simultaneous sandboxes. The risk it tests —
cache/identity bleed between runs on one node — is the same, but a strictly
concurrent pair is still worth running.

## 5. DEFECT FOUND AND FIXED — cold-start enforcement deadline

The first `approved` run **failed closed**:

```
provider error: network policy enforcement could not be verified:
… was not verified within 60s (policy: accepted, awaiting operator validation; endpoint: no endpoint)
```

Root cause — not the grant code. `FLUIDBOX_NETPOL_WAIT_SECS` (60) bounds an
*observation loop*, but its clock starts when the grant is prepared, **before the
pod is schedulable**. This deployment's sandbox nodegroup runs `min_size = 0`
(`platform/eks.tf`), so the first run after any idle period must wait for a cold
EC2 node to boot and join before a CiliumEndpoint can exist. The entire budget
went to EC2 and none to the CNI.

Evidence it was purely cold start: the sandbox node became `Ready` at
**01:27:51** and the deadline expired at **01:27:52** — missed by one second.
The identical run re-launched on the warm node scheduled in 15s and passed every
probe in §3.

Impact: with a scale-to-zero sandbox nodegroup, roughly **every first run after
an idle period fails**. Fail-closed, so never unsafe — but it looks like the
feature is broken.

**Fix applied and deployed:** `deploy/cloud/values/eks-m1.yaml`
`netpol.waitSeconds` 60 → **240** (well under `FLUIDBOX_K8S_INIT_GRACE_SECS`
= 300), with the corrected rationale recorded in the file. Applied via
`deploy-app.sh`; the live pod now carries `FLUIDBOX_NETPOL_WAIT_SECS=240`.

**Regression test against the real failure.** The empty sandbox node was
terminated to force the exact cold-start condition (`sandbox nodes = 0`), then
the same `approved` run was launched:

```
t=0s   sandboxNodes=0  pod=Pending  unscheduled
t=50s  sandboxNodes=1  pod=Pending  unscheduled     <- node appears
t=70s  sandboxNodes=1  pod=Pending  on=ip-10-42-12-116
t=90s  sandboxNodes=1  pod=Running  on=ip-10-42-12-116
```

**90 seconds** from launch to Running — comfortably past the old 60s deadline
(so the old value would have failed again) and comfortably inside the new 240s.
The run completed, the egress probe returned `REACHED`, and no
"not verified within" error appeared anywhere in the ledger. Fix confirmed
against the failure it was written for, not merely against the arithmetic.

**Recommended follow-up (code, not config):** start the deadline once the pod is
scheduled/Running rather than at grant preparation. The timeout would then mean
what its comment says — a bound on CNI programming — and would not need to
absorb EC2 boot latency on any cluster. 240s is a correct mitigation for this
deployment's node shape; it is not a general answer for a slower one.

## 6. Deny, and the per-run offline override (both driven through the UI)

**Deny.** Policy `public` + require-authorization. The run parked, the approval
card appeared, **Deny** was clicked. Ledger: `approval.decided denied` →
`network.grant.revoked` → `finalizing` → `failed`, **cost $0** — no sandbox was
ever provisioned.

**Offline-only override.** Agent declared `public`; "Offline only (this run)" was
selected in the composer. The run did **not** park for authorization (an offline
grant is the absence of authority, so none is needed), **no CNP was created**, and
the in-sandbox probe of `https://github.com` returned **BLOCKED**. The run
completed normally. The narrowing reaches the datapath.

**UI inconsistency found AND fixed:** the Overview page's "Needs your attention"
card still offered *Approve once / Whole session / Deny* for a `network.grant` —
the collapse to *Authorize / Deny* had been applied only to the session-detail
page, and "Whole session" is meaningless for a grant that is inherently per-run
(the plan's own rationale for collapsing it). `apps/web/app/app/page.tsx` now
applies the same treatment. Presentation only: the decision value stays
`approved_once`.

## 7. Hygiene

- After every run reached terminal: **0** residual CiliumNetworkPolicies, **0**
  sandbox pods, **0** sandbox secrets.
- **0** token-like strings (`fbx_sess_` / `fbx_pat_` / `fbx_web_`) in server logs.

## 8. Not executed here, and why

- **Failure-mode drills** (CoreDNS down, gateway node down) and the **full
  teardown audit** from `docs/hosted/network-grants-eks-acceptance-runbook.md`
  §3 would break or destroy the live production deployment. They need a
  disposable cluster.
- **IPv6 / UDP-QUIC probes** were dropped from the matrix: the sandbox image has
  no dual-stack address and no QUIC client, so a "BLOCKED" result would prove
  nothing.
- **Grant expiry mid-run** (`max_grant_secs`) is unexercised.

## Reproduction

Refusal and setup steps were driven through the dashboard's own authenticated
proxy (`/api/fluidbox/*`) from the signed-in owner session, i.e. the same
authority and code path the UI uses. Deny and the offline override were driven by
real clicks. Sandbox-side probes ran as ordinary agent tool calls and are visible
in each run's timeline.

## 9. Final state of the drill org

Policy `init` v11 and agent `test` were restored to the posture the 2026-08-04
acceptance left them in: ceiling **public**, **require a human to authorize each
run**, empty allow/deny; the agent declares `public` with no targets. The
intermediate `approved` catalogs and deny lists used above exist only in the
policy's immutable version history, which is the point of that history.
