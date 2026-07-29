# Kubernetes network-enforcement admission race — fix + two-environment validation

**Date:** 2026-07-29 · **Branch:** `feat/k8s-network-admission-gate`
**Commits:** `f81aae7` (fix + unit regressions); validation harness + this
report land as the branch's second commit.
**Author:** validation run driven by Claude (Fable 5), evidence inline.

## 1. The defect

Measured on a real EKS 1.33 cluster on 2026-07-28 (`docs/reviews/2026-07-27-pr92-two-environment-validation.md` §8c)
and root-caused in code this run:

1. **The certification probe raced and always lost.** `verify_netpol`
   (`crates/fluidbox-provider-k8s/src/netpol.rs`) created a probe pod whose
   script sampled its two assertions exactly once, at container t=0. The AWS
   VPC CNI in `standard` enforcing mode programs NetworkPolicy for a NEW pod
   asynchronously (~20 s measured) and **fails open** meanwhile. Every gate
   worker retry created a *fresh* pod that re-entered the same window, so the
   boot gate could never pass on `scripts/eks-cluster.yaml` and every
   `POST /v1/sessions` answered 503 — no run could ever be created on EKS.
2. **Real sandbox workloads were exposed, not just the probe.** A sandbox pod
   is also a fresh pod: its containers start inside the same fail-open window,
   which means the untrusted `runner` container could execute with
   **unrestricted egress for its first seconds** — the exact property the
   boot gate exists to certify was not delivered per-pod. (Confirmed natively
   in this run, §5 N1.)

Nothing was misconfigured: the policies are correct, the nodeagent enforces.
The probe simply did not wait, and nothing made the runner wait.

## 2. The fix — a bounded, observable admission protocol

No fixed sleeps anywhere; `netpol.requireEnforced` semantics untouched
(default `true`, fails closed, `false` remains dev-only).

**One shared protocol** (`netpol::enforcement_script`): poll once per second —
positive target (internal Service `:8788`) must be **reachable** and negative
target (public Service `:8787`) must be **blocked** — and succeed only when
*both hold in the same observation*. Enforcement is monotonic once programmed,
so the first such observation is proof. At the deadline
(`FLUIDBOX_NETPOL_WAIT_SECS` / `netpol.waitSeconds`, default 60 s) it fails
**closed** with the original exit-code contract: `3` = negative still
reachable (`NotEnforced`), `2` = positive still unreachable
(`Unschedulable`). Every iteration prints an `obs i t=<epoch> pos=… neg=…`
line, so the pod log is a timestamped record of exactly what was measured.
Both targets back the same live listener, so "blocked" is evidence of policy,
never of a dead host.

Three consumers:

1. **Certification probe** (`verify_netpol`) — runs the loop instead of the
   t=0 sample; the pod's `activeDeadlineSeconds` and the worker's wait are
   *derived* from the window (`wait + PROBE_SCHEDULING_SLACK_SECS(60)`,
   `+ PROBE_CALLER_SLACK_SECS(90)`) so no second, shorter clock can kill a
   still-observing probe. On failure the probe's observation log tail is
   surfaced in the server log.
2. **Per-sandbox admission gate** — a new `netpol-gate` init container,
   **first** in every sandbox pod when the deployment requires enforcement.
   By the kubelet's init-container ordering the untrusted `runner` (and even
   the trusted workspace fetch) cannot start until the pod's *own* network is
   observed enforced. Targets are frozen per run
   (`SandboxSpec.network_admission: Option<NetworkAdmission>`) from the same
   ClusterIP pair the certification probe verified — stored by the gate
   worker *before* each probe, so a verified gate implies targets exist. On
   deadline the init container exits non-zero → the pod fails →
   `runner_status` maps it to a terminated sandbox (`init:` reason) → the run
   fails closed at zero model spend.
3. **`helm test` probe** — same loop (it had the same t=0 race, previously
   noted as "helm-test probe false-negatives on standard-mode fail-open").

**Defense in depth:** the provider itself refuses to provision an
enforcement-required spec that carries no admission targets
(`require_network_admission` in `crates/fluidbox-provider-k8s/src/lib.rs`),
so a control-plane wiring bug cannot silently skip the gate. The provider
reads the same `FLUIDBOX_REQUIRE_ENFORCED_NETPOL` env the server does, with a
pinned-equal falsey parse.

**What still gates runs:** `create_run` continues to 503 until the
certification probe passes (unchanged); the per-pod gate closes the residual
per-pod window that certification could never speak for.

### Files touched

| Area | Change |
|---|---|
| `fluidbox-core/src/traits.rs` | `NetworkAdmission` + `SandboxSpec.network_admission` |
| `fluidbox-provider-k8s/src/netpol.rs` | `enforcement_script`, convergence probe, derived deadlines, log-tail surfacing |
| `fluidbox-provider-k8s/src/manifest.rs` | `netpol-gate` first init container (conditional) |
| `fluidbox-provider-k8s/src/lib.rs` | provision refusal without admission targets |
| `fluidbox-provider-k8s/src/config.rs` | `netpol_probe_image`, mirrored `require_enforced_netpol` |
| `fluidbox-server/src/{config,state,workers,orchestrator,main}.rs` | `FLUIDBOX_NETPOL_WAIT_SECS`, target storage, freezing `NetworkAdmission` |
| `deploy/helm/fluidbox/{values.yaml,templates/server.yaml,templates/tests/netpol-probe.yaml}` | `netpol.waitSeconds`, env wiring, helm-test convergence |
| `crates/fluidbox-provider-k8s/examples/netpol_fixtures.rs` | fixture generator: validation runs the production bytes |
| `scripts/netpol-admission-validation.sh` | kind + Calico regression harness |
| `scripts/netpol-admission-eks-validation.sh` | EKS native-race validation + teardown/audit |

### Regression tests (unit)

- `netpol::tests::enforcement_script_is_a_bounded_convergence_loop` — pins
  loop-not-sample, same-observation success, deadline-not-sleep, observation
  lines, exit codes.
- `netpol::tests::probe_pod_deadline_contains_the_observation_window` — the
  pod clock strictly contains the window (derived, not magic).
- `manifest::tests::network_admission_gate_is_the_first_init_container` —
  placement before `workspace-init`, real script against frozen targets,
  restricted-PSS compliance, no tokens/volumes/env in the gate.
- `manifest::tests::no_admission_means_no_gate_container` — dev-posture pod
  shape byte-stable.
- `lib::tests::provision_refuses_enforcement_required_spec_without_admission`.
- `config::tests::enforced_flag_parses_like_the_server`.

All 576 unit tests in the three touched crates pass; `cargo clippy
--workspace --all-targets` clean; chart `helm lint` clean.

## 3. Validation topology (both environments)

The network layer is validated in isolation from the fluidbox control plane —
what EKS/kind add over unit tests is *CNI behavior*, so the stand-ins keep
everything else constant:

- Namespace `fbxval` — a stand-in "server" pod carrying the chart's exact
  Service selector labels (`app.kubernetes.io/name: fluidbox`,
  `component: server`) with busybox `httpd` listeners on **both** 8787 and
  8788, fronted by two ClusterIP Services. Reachability of both ports is
  therefore known independently of policy.
- Namespace `fbxval-sandboxes` — created from the **chart-rendered**
  `templates/sandbox.yaml` (`helm template … -s templates/sandbox.yaml`), so
  `fluidbox-sandbox-default-deny` + `fluidbox-sandbox-egress` are the
  production policy bytes (restricted PSA labels included; quota off as
  orthogonal).
- Sandbox pods are generated by
  `cargo run -p fluidbox-provider-k8s --example netpol_fixtures sandbox-pod`,
  i.e. the production `build_pod` output (gate placement, env routing,
  security baseline). Stubbed for the harness: non-gate images/commands →
  busybox scripts, runner resources shrunk; the `netpol-gate` container is
  byte-identical to production. The runner stub is the adversary: its **first
  instruction** attempts the forbidden egress a hostile agent would.
- Probe pods likewise via `… netpol_fixtures probe-pod` (production
  `build_probe_pod`).

## 4. kind + Calico (enforcing CNI) — results

Cluster: `fbx-netadm-val`, kind v1.36.1 node, Calico v3.28.0, colima/docker
(arm64). Calico programs policy for new pods fast and fails **closed**, so
the EKS race does not occur natively — phases B/C/D *simulate* it by creating
pods while the two NetworkPolicies are deleted (an unpoliced namespace is the
fail-open analog) and applying them seconds later.

**ALL 12 ASSERTIONS PASSED** (`SCRIPT_EXIT=0`). Wall time ≈ 9 min including
cluster create + delete. Targets: internal `10.96.12.177:8788`, public
`10.96.108.16:8787`.

| # | Assertion | Result |
|---|---|---|
| A1–A5 | Steady state ×5: gate admits, forbidden blocked, allowed works | PASS ×5 — 12–13 s pod end-to-end, gate passed on its **first** observation every time; runner reported `public:8787=blocked internet:443=blocked internal:8788=ok` |
| B0 | Vulnerability reproduced: pre-fix pod (no gate) in the unpoliced window | PASS — runner's first instruction reported `public:8787=OPEN internet:443=OPEN` |
| B1–B3 | Race ×3: pod created before policy; gate must hold the runner | PASS ×3 — gate observed the open network 8× each run, runner stayed `PodInitializing`, `startedAt ≥ policy-apply` (e.g. 1785303999 ≥ 1785303995), then all egress blocked |
| C-old | Pre-fix probe under late policy | PASS — `Failed`/exit 3, the measured EKS-503 cause reproduced on kind |
| C-new | Shipped probe, identical conditions | PASS — converged in 14 s after observing the open network 10× |
| D | Bound: policy never applied | PASS — exit 3 at the 15 s test window (18 s total), no hang, no runner start |

The B1 gate log — the observable protocol end to end (policies applied at
epoch `…995`):

```
obs 8 t=1785303994 pos=ok neg=open      ← still fail-open
obs 9 t=1785303997 pos=ok neg=blocked   ← enforcement observed (≤2 s after apply)
enforced
runner startedAt epoch: 1785303999 (policies applied: 1785303995)
runner: forbidden public:8787=blocked internet:443=blocked allowed internal:8788=ok
```

## 5. EKS + VPC CNI standard mode (native race) — results

Two ephemeral clusters, both uniquely named/tagged
(`fluidbox-ephemeral=true`, `fluidbox-validation=k8s-network-admission`,
`fluidbox-run-id=<id>`), account `471112572248`, `us-east-1`, EKS 1.33,
AL2023 arm64 node, vpc-cni addon with `enableNetworkPolicy: "true"`
(`aws-eks-nodeagent` verified present), default `standard` enforcing mode.
The account had **zero** pre-existing EKS clusters; identity was inspected
read-only before any mutation, and the scripts touch only their own cluster.

- **Run 1** `fbx-netadm-07290046` (~01:00–01:45 UTC-5): all phases failed on
  `FailedScheduling: Insufficient memory` — a **harness sizing defect**, not a
  protocol result: the chart's LimitRange assigned its 1 Gi default request to
  the un-stubbed containers, which cannot fit a t4g.small (kind's 12 Gi node
  had hidden this). The run still proved the teardown machinery: trap fired,
  cluster deleted, audit clean.
- **Run 2** `fbx-netadm-07290125` (~01:25–02:00): harness fixed (explicit tiny
  resources on stubs + probe pods; t4g.medium). **ALL 9 ASSERTIONS PASSED**,
  `EKS_SCRIPT_EXIT=0`.

| # | Assertion | Result |
|---|---|---|
| N1 ×2 | **Determination**: does the native fail-open window expose a real (pre-fix-shaped) sandbox workload? | PASS ×2 — **yes**: the runner's own first instruction saw `public:8787=OPEN internet:443=OPEN` at its t=0 sample, blocked ~1 s later |
| N2 ×3 | The fix on the native race: production gated pod | PASS ×3 — gate observed the open network (obs 1–2 `neg=open`), enforcement at obs 3 (~4 s), runner then found all forbidden egress blocked and the allowed path working |
| N3 ×2 | Certification, old vs new | PASS — the pre-fix probe **failed exit 3 natively both times** (`pos-ok` then `neg-fail`; the deterministic cause of "every `POST /v1/sessions` is 503"), while the shipped probe certified in 11 s over 3 observations |

The N2.1 gate log — the native VPC CNI fail-open, observed and closed:

```
obs 1 t=1785307414 pos=ok neg=open      ← fail-open window, live
obs 2 t=1785307415 pos=ok neg=open
obs 3 t=1785307418 pos=ok neg=blocked   ← policy programmed
enforced
runner: forbidden public:8787=blocked internet:443=blocked allowed internal:8788=ok
```

**On window length:** 2026-07-28's measurement saw ~20 s; this idle
single-node cluster showed ~1–4 s. The duration varies with node/nodeagent
state and policy count — AWS's contract is only "applied eventually", with no
bound. That is precisely why the fix is an *observation* protocol rather than
any timing assumption: the gate converts an exposure of unbounded-by-contract
duration into a bounded, evidenced admission, and stays correct at 1 s or 20 s.

## 6. Limitations, residuals, honesty

- **kind simulates the race** (policy applied late) rather than exhibiting
  VPC CNI's asynchronous programming; the EKS phases cover the native
  behavior. Calico's own new-pod window is fail-closed, which the gate
  tolerates by design (positive-unreachable observations until programmed).
- **The gate observes the Service VIP path** (ClusterIP DNAT → server pod),
  the same path the runner uses; it does not observe arbitrary destinations.
  The negative external canary (1.1.1.1:443) is asserted from the runner
  stub in validation, not by the shipped gate — the shipped negative target
  (live listener, port-scoped deny) is chosen precisely so "blocked" cannot
  be explained by a dead host.
- **A pod-restart of the runner container does not re-run init containers**
  (`restartPolicy: Never` makes this moot for sandbox pods — the pod never
  restarts containers).
- **`requireEnforced=false` deployments get no gate**, exactly as before —
  the flag remains the documented dev-only escape and is not weakened; the
  EKS values keep `requireEnforced: true` and the 2026-07-28 workaround note
  (`netpol.requireEnforced=false`) is now obsolete.
- **Window length is environment-dependent**: 60 s default covers the ~20 s
  measured EKS window 3×; a pathological CNI slower than the window fails
  closed (correct direction) and the knob is per-deployment.
- **Cross-knob bound not machine-checked**: `netpol.waitSeconds` must stay
  under `FLUIDBOX_K8S_INIT_GRACE_SECS` (default 300); documented in
  values.yaml, not asserted at boot.
- **The N1 winprobe samples at 1 Hz**, so a sub-second window would be
  under-sampled; the observed `OPEN` samples are a floor on exposure, not a
  precise duration. (Old-probe exit-3s in N3 independently confirm the window
  from a second vantage.)
- **In-flight sandbox pods** launched before this change carry no gate; the
  gate applies from the next provisioned run onward (RunSpec immutability is
  untouched — admission targets are frozen per new run).
- **The runner-shape validation stubs images/commands** of the non-gate
  containers (documented in §3); placement, env routing, security context and
  the gate container itself are the production bytes.

## 7. Teardown verification

Both clusters torn down by the script's EXIT trap (run 1's fired after a
deliberate failure — proving teardown-on-failure), then audited:

- `eksctl` CloudFormation stacks (`…-cluster`, `…-nodegroup-ng-1`):
  **DELETE_COMPLETE** both runs; no `DELETE_FAILED` retries needed — the two
  known EKS leak sweeps (detached VPC-CNI ENIs; the out-of-CFN
  `eks-cluster-sg-*`) found nothing to sweep this time but remain in the trap.
- VPCs `vpc-0503d5e9f21f81fbb` / `vpc-0ed306a9441f321f3`: **gone** (describe
  returns nothing); zero ENIs remained in either.
- NAT gateways `nat-0a5d6a754cc4f0d74` / `nat-0f3af12ddfb486bc0`: state
  **deleted**; their EIPs released (zero unattached EIPs account-wide).
- Nodes/volumes: instances **terminated**, volumes **InvalidVolume.NotFound**.
- Resource Groups Tagging API listed 4 ARNs per run post-delete
  (instance/ENI/volume/NAT); each was directly verified
  terminated/NotFound/deleted — **eventual-consistency index ghosts, zero
  live residue**.
- Final account-wide sweep: `aws eks list-clusters` **empty**; no
  `fbx-netadm*` stacks in any live status; no `fluidbox-ephemeral`-tagged
  VPCs; no unattached EIPs.

**Cost**: ≈1.4 cluster-hours total across both runs ≈ **$0.35** (control
plane $0.14, NAT ~$0.11, nodes ~$0.05, EIP/data cents) — against the $40 cap.

## 8. Reproduction commands

```bash
# unit + shape regressions
cargo test -p fluidbox-provider-k8s -p fluidbox-core -p fluidbox-server

# kind (enforcing CNI) — creates/deletes cluster fbx-netadm-val
scripts/netpol-admission-validation.sh          # --keep to retain

# EKS (native VPC CNI race) — creates a uniquely-tagged ephemeral cluster,
# validates, then tears down + audits to empty. ≈$0.20/h while up.
scripts/netpol-admission-eks-validation.sh
```
