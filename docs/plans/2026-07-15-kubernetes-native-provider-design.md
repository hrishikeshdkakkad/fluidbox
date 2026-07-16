# fluidbox — Kubernetes-native execution provider and cluster deployability design

**Date:** 2026-07-15
**Status:** FINALIZED v1.1 (2026-07-15) after joint adversarial review by Claude (Fable 5) and Codex (GPT-5.6-sol, max reasoning); v1.1 adds the dual-provider permanence directive (settled Q17 — Kubernetes is additive; Docker is never replaced). Docker provider is the only shipped execution backend, Kubernetes support is not implemented
**Audience:** fluidbox maintainers, security reviewers, and engineers implementing the Kubernetes provider and Helm packaging
**Relationship to other docs:** `PLAN.md` remains authoritative for product invariants and milestone direction (§2 convergence invariants bind every decision here; §6.2 defines the `ExecutionProvider` seam this design fills). `docs/ARCHITECTURE.md` describes the current Docker run path. `docs/plans/2026-07-14-multi-user-mcp-control-plane-design.md` defines the multi-user architecture; this design is orthogonal to it and lands first (user decision 2026-07-15).

## Executive verdict

fluidbox can become deployable on any conformant Kubernetes cluster — EKS, AKS, GKE, kind — without changing a single runner image, without weakening any §2 invariant, and while *strengthening* two security properties that are weak today (hostile-`.git` diff collection and sandbox egress).

The hard problem is not the provider API. The existing `ExecutionProvider` trait (`crates/fluidbox-core/src/traits.rs:53-61`) was designed for this move, `SandboxHandle` is already serializable jsonb, and the runner contract is transport-agnostic bearer-token HTTP with no host or IP assumptions. The hard problems are the three places where the control plane and the sandbox silently share a machine:

1. **Workspace hand-off** rides a host bind mount (`FLUIDBOX_DATA_DIR/workspaces/<sid>/repo → /workspace`), which does not exist across nodes.
2. **Diff capture** runs `git add -A && git diff` on that same host directory *after* the sandbox mutated it — which is both impossible across nodes and a live hostile-repository code-execution surface today (`.git/config` `diff.external`).
3. **Control-plane reachability** is `host.docker.internal`, which only resolves for a sibling container on the same daemon.

The design replaces all three with cluster-native mechanisms — an immutable archive pull, an in-pod collector with a pristine baseline, and Service networking — and packages the result as a Helm chart with hardened-by-default, *verified* network policy. Because the collection and finalizer fixes also repair live bugs in the Docker path (`fail()` captures no diff; cancel races result delivery; `/result` finalization is a lossy `tokio::spawn`), they land first as a Docker-only preparatory phase.

**This epic is additive, not a migration (user directive 2026-07-15).** The Docker provider is never replaced, deprecated, or demoted: it remains a permanently supported, co-equal execution backend for local development AND single-host production deployments (the docker-compose path stays a maintained deployment mode). `FLUIDBOX_PROVIDER` selects between `docker` (default) and `kubernetes`; both providers sit behind the same trait, share the same `fluidbox-workspace` collection semantics, and must pass the same conformance bar (demo A + the full e2e suite) at every phase boundary.

## Goals

This design must deliver:

- a `KubernetesProvider` implementing the `ExecutionProvider` seam via kube-rs, provisioning one Pod per run in a dedicated sandbox namespace;
- the SAME runner images (`fluidbox-sandbox-runner`, `fluidbox-codex-runner`) running unmodified as pods — the runner contract is untouched except one additive field (heartbeat response action);
- workspace materialization staying control-plane-side (credentialed fetch never enters the sandbox), with delivery by immutable digest-verified archive instead of bind mount;
- diff capture that never executes git against agent-controlled `.git` state, on either provider;
- a unified, durable, restart-recoverable terminal finalizer for all terminal paths (result, cancel, fail, watchdog);
- hardened-by-default sandbox networking (zero external egress) with runtime *verification* that the cluster's CNI actually enforces NetworkPolicy;
- a Helm chart deploying control plane + dashboard (+ optional LiteLLM) on EKS/AKS/GKE/kind, with per-cloud isolation recipes (`runtimeClassName`);
- **dual-provider permanence**: Docker remains a first-class, permanently supported execution backend — for local development and for single-host production via docker-compose — with Kubernetes added alongside it behind the same trait, selected per deployment by `FLUIDBOX_PROVIDER` (default `docker`); both providers meet the same conformance bar (demo A + full e2e) at every phase;
- a CI story that catches provider regressions on PRs without pulling 1.5 GB images.

## Non-goals for v1 (and one permanent non-goal)

- **Replacing or deprecating the Docker provider — permanent non-goal.** Kubernetes support never retires Docker. The docker-compose deployment path, the Docker e2e phases, and `FLUIDBOX_PROVIDER=docker` as the default all remain maintained indefinitely. Any future change that would break the Docker path is out of bounds for this epic and its follow-ups.
- **Egress proxy for sandboxes.** Deferred until brokered git-writes (§17 #4 of the capability design) create the need. v1 ships zero-egress and dev-only permissive profiles.
- **kubernetes-sigs/agent-sandbox CRD backend.** Deliberately deferred (see Settled questions Q1). Revisit as an optional second Kubernetes provider if warm-pool latency becomes a demonstrated need.
- **Warm pools / pre-provisioned sandboxes.** Cold-start latency of a pod (~1-5 s + image pull) is acceptable for fluidbox's run shape (minutes-scale agent runs).
- **Multi-replica control plane.** v1 is explicitly `replicas: 1` + `Recreate`. The OAuth advisory-lock fix lands anyway (it is cheap and removes a known correctness trap), but watchdog leader-election and horizontal scaling are out of scope.
- **Authenticated config fetch** (moving task/system-prompt/capability manifest out of env vars). v1 keeps env injection with a 512 KiB serialized ceiling; the fetch endpoint is the designated v1.1 follow-up.
- **Pre-pull DaemonSet** for runner images. Optional post-v1 optimization for first-party digests only.
- **In-cluster Postgres.** The database stays external (Neon; any direct-connection Postgres works mechanically, but Neon is the blessed path per repo constraints).

## Current execution architecture (verified)

Everything below was verified at file:line on 2026-07-15.

### The seam

```rust
// crates/fluidbox-core/src/traits.rs:53-61
pub trait ExecutionProvider: Send + Sync {
    async fn provision(&self, spec: &SandboxSpec) -> Result<SandboxHandle, ProviderError>;
    async fn state(&self, handle: &SandboxHandle) -> Result<SandboxState, ProviderError>;
    async fn terminate(&self, handle: &SandboxHandle) -> Result<(), ProviderError>;
    async fn list_orphans(&self) -> Result<Vec<(Uuid, SandboxHandle)>, ProviderError>;
    fn runtime_name(&self) -> &'static str;
}
```

`SandboxHandle {runtime, external_id, attrs: jsonb}` is persisted via `set_sandbox_handle` (`sessions.sandbox_handle jsonb`, migration 0001:61) and reattached with `serde_json::from_value` (`orchestrator.rs:399`, `workers.rs:100`). `SandboxSpec.workspace_host_dir` is documented as a "provider-internal optimization; MicroVM providers push an archive instead" (`traits.rs:26-28`) — the archive model below is the intended design, not a workaround.

**Gap:** `AppStateInner.provider` is the concrete `Arc<DockerProvider>` (`crates/fluidbox-server/src/state.rs:44`), wired in `main.rs:65,85`. The trait is never used as a trait object. Call sites (6): `orchestrator.rs:153` (provision), `orchestrator.rs:400` (terminate in reap), `workers.rs:13,22` (boot sweep), `workers.rs:104` (watchdog state check), plus a Docker-specific `ping` health check (`main.rs:66`, `api.rs:274`).

### The Docker provider (what a pod must replicate)

`crates/fluidbox-provider/src/lib.rs` (bollard over the local socket):

- Per-session bridge network `fluidbox-net-<sid>`; `Hardened` ⇒ `internal: true` (no egress); `HostDev` ⇒ normal bridge + `extra_hosts: host.docker.internal:host-gateway` (lib.rs:43-57, 87-90).
- Container `fluidbox-<sid>`, labels `fluidbox.session=<uuid>` + `fluidbox.managed=1` (orphan-sweep key), workdir `/workspace`, bind mount `{workspace_host_dir}:/workspace:rw` (lib.rs:66-118).
- Hardening: `memory: 2 GiB`, `pids_limit: 512`, `cap_drop: ALL`, `security_opt: no-new-privileges`. No CPU limit, no seccomp profile, no read-only rootfs (lib.rs:92-102).
- `state`: inspect → `Running | Exited(code) | Gone` (lib.rs:135-152). `terminate`: force-remove + network cleanup, idempotent (lib.rs:154-172). `list_orphans`: label-filtered container list, handle reconstructed from live labels (lib.rs:174-210).
- **`orchestrator.rs:150` hardcodes `NetworkMode::HostDev`** — Hardened mode exists in the provider but is not the active run path.

### Workspace lifecycle (the deepest coupling)

- Materialization is control-plane-side during `initializing` (`orchestrator.rs:108-109` → `materialize_workspace` → `crates/fluidbox-provider/src/workspace.rs`): scheme-allowlisted git fetch with credentials via `GIT_CONFIG_*` env only, shallow fetch, `remote remove origin`, local excludes, `base_commit` recorded. A bad repo fails at zero model spend.
- The tree lands at `FLUIDBOX_DATA_DIR/workspaces/<sid>/repo` and is bind-mounted into the container. The eval compose requires the SAME absolute data-dir path on host and in the server container because the host daemon resolves the bind mount (`deploy/docker-compose.eval.yml:57-65`) — the purest expression of the single-host assumption.
- At finalize, `capture_diff` runs `git add -A` + `git diff --binary --no-color <base_commit>` **on the host dir** (`workspace.rs:299-310`), stores `diff/changes.patch` as a DB artifact, then deletes the dir.

### Runner contract (why pods need zero image changes)

`images/runner-lib/contract.mjs`: env-injected identity (`FLUIDBOX_CONTROL_URL/SESSION_ID/SESSION_TOKEN/TASK/AUTONOMY/MODEL/WORKSPACE[/SYSTEM_PROMPT/CAPABILITIES]`), bearer-token HTTP to `/internal/sessions/{id}/{permission,events,heartbeat,result}` + `/internal/token/renew` + facade `/internal/llm/*`. `/permission` retries forever on transient errors with the same `tool_call_id` (server dedupes); heartbeat every 10 s (**response currently discarded** — contract.mjs:191); `/result` uses lenient auth for idempotent re-ACK. Claude gets the Anthropic trio (`ANTHROPIC_BASE_URL = <control>/internal/llm`, `ANTHROPIC_API_KEY = session token`); codex builds its facade base from the generic block. Both images: non-root uid 10001, no baked secrets, no published ports, all privileged setup at build time. No IP or same-host assumption anywhere in auth (`auth.rs` is pure bearer).

### Live defects this design fixes (found during review)

1. `fail()` transitions to `Failed` and reaps **without capturing a diff** (`orchestrator.rs:70-82`).
2. Cancel transitions terminal (enqueueing result delivery) **before** diff capture — delivery can race and omit the artifact (`orchestrator.rs:411-424`).
3. `/result` ACKs then finalizes in a **lossy `tokio::spawn`** (`internal.rs:800-803`) — a crash between ACK and finalize strands the session for the watchdog to mis-classify.
4. Control-plane `git` executes against the sandbox-mutated `.git`: `diff.external`, clean filters, and fsmonitor in agent-written `.git/config`/`.gitattributes` are a code-execution surface **on the control-plane host, today, in the Docker path**.
5. `oauth_locks` is an in-process mutex (`state.rs:58-61`) — any second replica double-rotates OAuth refresh tokens into `invalid_grant`.

## High-level target architecture

```
                        ┌──────────────────────────────────────────────┐
                        │ control-plane namespace                       │
   Ingress (https) ───▶ │  fluidbox-server Deployment (nonroot, 1 rep) │
   FLUIDBOX_PUBLIC_URL  │   :8787 public   /v1, oauth, webhooks        │
                        │   :8788 internal /internal/* (runner contract,│
                        │        workspace archive, LLM facade)         │
                        │  fluidbox-web Deployment (:3000)              │
                        │  litellm Deployment (optional, ClusterIP)     │
                        │  PVC: materialized workspace archives         │
                        └───────────────┬──────────────────────────────┘
                                        │ internal Service (ClusterIP), :8788 only
                        ┌───────────────▼──────────────────────────────┐
                        │ sandbox namespace (restricted PSA,            │
                        │  default-deny NetworkPolicy, ResourceQuota)   │
                        │  Pod fluidbox-<session-uuid>:                 │
                        │   init: workspace-init (fetch+verify+unpack)  │
                        │   main: runner image (UNMODIFIED)             │
                        │   aux:  workspace-collector (workspaced)      │
                        │   volumes: emptyDir /workspace,               │
                        │            collector-only baseline + output   │
                        │   Secret fluidbox-<sid> (session token,       │
                        │            ownerRef → Pod, GC-reaped)         │
                        └──────────────────────────────────────────────┘
```

The orchestrator remains the only controller and the single status writer. Kubernetes contributes scheduling, the kubelet, GC, and (verified) network enforcement — never lifecycle semantics.

## The Kubernetes provider

### Pod model

- **Bare Pod, not Job, not CRD.** One run = one disposable execution object; fluidbox already owns completion, retry, budget, and cleanup semantics — a Job would be a second completion controller fighting the orchestrator, and Jobs interact awkwardly with a post-exit collector container.
- Deterministic name `fluidbox-<session-uuid>`, `restartPolicy: Never`, labels `fluidbox.dev/session=<uuid>` + `fluidbox.dev/managed=true`, in the configured sandbox namespace (and ONLY that namespace — see adoption rules).
- `SandboxHandle {runtime: "kubernetes", external_id: <pod name>, attrs: {namespace, uid}}`. Every mutation uses a **UID precondition**: a stale handle must never delete a pod that reused the name.
- `activeDeadlineSeconds = wall_clock_budget + initialization_grace`, with an installation-wide ceiling for budget-less runs — an independent brake if the control plane is down while a runner keeps spending local compute. (Model spend is already braked independently: the facade denies on budget and on non-`running` states.)

### Provisioning order (Pod-first, Secret-second)

The session token reaches the pod via a per-run Secret (`secretKeyRef` into `FLUIDBOX_SESSION_TOKEN` and, for Claude, `ANTHROPIC_API_KEY`) rather than a PodSpec env literal — pods-read RBAC must not leak live tokens. Ordering eliminates the orphan window without a patch step:

1. Create the Pod referencing the deterministic, not-yet-existing Secret `fluidbox-<sid>`. The kubelet holds container start and retries until the Secret exists.
2. Read back the Pod UID.
3. Mint the session token (as today, `orchestrator.rs:96-104`).
4. Create the **immutable** Secret with an ownerReference to the Pod (`controller: false`, `blockOwnerDeletion: false`) + the session/managed labels. GC reaps it with the Pod; a labeled Secret sweep is the backstop.
5. On Secret-create failure: revoke the token, UID-precondition-delete the Pod.
6. `provision()` returns only after workspace-init succeeded and the runner container started — the orchestrator's `initializing → running` transition then matches reality, and the workspace endpoint cannot race the state gate.

Restart recovery: Pod exists / Secret absent → revoke unexposed tokens, mint fresh, create Secret. Both exist → validate labels + Secret owner UID + Pod UID, adopt. Owner-UID mismatch → fail closed, clean up.

### State and reconciliation

- `state()` inspects the **named runner container status**, not Pod phase — the collector keeps the Pod `Running` after the runner exits, so phase is misleading by design.
- A watch stream (kube-rs watcher with backoff) accelerates detection of image-pull failures, scheduling failures, OOMKills, runner exit, and node loss — but watches are an optimization, never truth: they drop, resourceVersions expire (410 Gone → relist), and the control plane restarts. **Periodic list/get reconciliation against the DB remains the source of truth**, exactly parallel to the SSE hybrid (NOTIFY wakes, the seq query delivers).
- `list_managed` (renamed from `list_orphans`) lists pods by the managed label in the configured namespace. Boot-sweep adoption validates labels + session id + runtime + namespace + UID before acting, and handles the crash-between-create-and-`set_sandbox_handle` window by adopting the pod into the session rather than orphan-killing it.

## Workspace transport (in): control-plane archive, pod pulls

**Invariant preserved.** "Workspace init is control-plane-side" is about *authority and sequencing*, not TCP direction: the credentialed fetch still happens only in the orchestrator; the pod pulls an immutable, credential-free, control-plane-selected artifact using a token it already holds (the same session token that already authenticates every other runner call). Nothing new becomes reachable.

- Materialization is unchanged. Afterward the control plane packs ONE immutable `tar.zst` archive, records byte size + SHA-256, and persists it on the **control-plane PVC** (survives `Recreate` upgrades; `LocalCopy` sources cannot be re-materialized after the fact; git sources gain a deterministic re-fetch-by-`base_commit` fallback later if wanted). The archive is deleted once init success is durably observed, with a bounded TTL sweep as backstop.
- New endpoint `GET /internal/sessions/{id}/workspace` on the **internal listener**: session derived from the bearer token — the path `{id}` is informational, exactly like every other internal route (`main.rs:220-221` states this rule today).
- Pod containers:
  - `workspace-init` (init container, collector image): download → verify size/digest → hardened extraction (reject absolute paths, `..` traversal, hardlinks/symlinks escaping the workspace root) → atomically mark complete. Ordinary init container, NOT a native sidecar: native sidecars are stable only ≥1.33 and this design must not gate on bleeding-edge clusters.
  - `runner` — the unmodified harness image, exactly today's env contract.
  - `workspace-collector` — long-lived tiny container (same collector image), the diff-out mechanism below.
- Corrupt/oversized/unsafe archives fail the init container → pod fails → structured `state()` reason → session fails at zero model spend, preserving today's "bad repo costs nothing" property.

## Artifact collection (out): pristine baseline, in-pod, resumable

**Principle: never execute git against agent-controlled `.git` state — on any provider.**

- During materialization the control plane sets aside a **pristine baseline** (the `.git` directory as materialized, before the agent ever runs). In the pod it lives in a volume mounted only into `workspace-init` and `workspace-collector` — the runner never sees it. On Docker it lives beside the workspace on the host, outside the bind mount.
- `workspaced` — a new static Rust binary (own small crate; ships in the collector image: binary + git + CA certs, non-root numeric uid, amd64+arm64, no shell/curl/coreutils; tar+zstd implemented in Rust so extraction policy is auditable in one place):
  - `workspaced diff`: reconstruct a controlled temporary repository from pristine baseline + final worktree; run git with a scrubbed environment (`GIT_CONFIG_NOSYSTEM`, no global config, no hooks, no fsmonitor, `--no-ext-diff`, no pager/prompts, controlled `HOME`), bounded CPU/time/output; write the bounded diff + metadata (size, sha256, truncated flag, status) **atomically** to a collector-only emptyDir.
  - `workspaced stream --offset N`: emit the finished file from an offset — the control plane collects via `pods/exec` with resume-on-drop, decoupling computation from the fragile exec stream. No new upload endpoint, no collector credential.
- Artifact size caps are enforced and truncation is recorded explicitly (artifacts are unbounded `text` in Postgres today — migration 0001:137).
- Collection works after runner exit (collector still runs) but not after pod deletion/eviction/node loss → those paths record explicit **`artifact_missing(reason)`** — a missing diff is never silently reported as "(no changes)".
- The same pristine-baseline + hardened-git logic becomes the Docker path's collection too (transport = host dir instead of exec), extracted into a new **`fluidbox-workspace` crate** (materialization, archiving, baselines, hardened git invocation, caps, artifact types; no bollard/kube deps — `fluidbox-core` stays I/O-free). This fixes live defect #4 before any Kubernetes code exists.

## Terminal lifecycle: durable finalizer + heartbeat quiesce

New non-terminal states **`cancelling`** and **`finalizing`** (real states, visible in the audit trail — `sessions.status` is unconstrained text so the values need no schema change; a migration DOES add durable finalization intent: pending outcome/summary + claim metadata so a restart-recoverable worker can complete an interrupted finalization). The facade, permission gate, broker, and token renew all deny work in both states; watchdog and recovery queries include them.

Unified sequence for ALL terminal paths (result / cancel / fail / watchdog):

```
persist intent + enter finalizing (or cancelling)
  → ACK /result (runner may exit)            [result path]
  → quiesce via heartbeat (30 s deadline)     [cancel path]
  → await runner-container termination
  → collect via workspace-collector (bounded, timed)
  → store artifact OR artifact_missing(reason)
  → terminal transition — delivery enqueue happens HERE, after collection
  → delete Pod (Secret follows via GC)
```

This fixes live defects #1-#3: `fail()` now collects; delivery can no longer race the artifact; `/result` persists intent before ACK instead of `tokio::spawn`-and-hope. Every stalled step has a timeout that resolves to `artifact_missing` and then terminalizes — nothing can wedge in `finalizing`.

**Quiesce channel:** the heartbeat response (runner already POSTs every 10 s; the response is currently discarded). Control plane returns `{"action": "quiesce"}` once the session enters `cancelling`; runner-lib registers a harness-specific abort callback, stops the agent, and exits 0 **without** posting `/result`. Deadline 30 s (three heartbeat opportunities + jitter), then hard-delete + `artifact_missing(quiesce_timeout)` — a racing worktree is never collected and labeled authoritative. This is the ONLY runner-contract change in the entire design, it is additive, and it lives in shared `runner-lib` (one place, both harnesses). Quiesce is an orchestrator/contract concern and deliberately does NOT appear on the provider trait.

## `ExecutionProvider` trait v2

```rust
provision(spec)          -> SandboxHandle   // spec carries an immutable workspace descriptor
state(handle)            -> SandboxStatus   // structured: Pending|Running|Terminated{exit}|Unknown + reason
collect_artifacts(handle)-> CollectedArtifacts  // bounded; artifact_missing on failure
terminate(handle)        -> ()              // idempotent, precondition-guarded
list_managed()           -> Vec<(Uuid, SandboxHandle)>
runtime_name()           -> &'static str
```

- `pods/exec` is an internal detail of the Kubernetes `collect_artifacts`; Docker's impl uses its host-dir transport with the same `fluidbox-workspace` logic. Exposing raw exec/read-file to the orchestrator would leak Kubernetes mechanics upward and make future providers (MicroVM) harder, not easier.
- Structured state reasons let the orchestrator distinguish `ImagePullBackOff` / unschedulable / OOMKilled / node-loss for the ledger instead of a generic death.
- `AppState.provider` becomes `Arc<dyn ExecutionProvider>`; selection via `FLUIDBOX_PROVIDER=docker|kubernetes` (default `docker` — local dev flow is unchanged). The Docker-specific `ping` health check generalizes to a provider `healthcheck` or moves behind the trait as a non-fatal boot probe.

## Network and trust boundaries

### Dual listener (v1-must)

Split the single bind into:

- **:8787 public** — `/v1` (admin API), OAuth callbacks, GitHub App flows, webhook ingress, public health. Exposed by the public Service/Ingress only.
- **:8788 internal** — the runner contract (`/internal/sessions/*`), token renew, workspace archive, LLM facade. Exposed by a sandbox-facing ClusterIP Service only.

Bearer auth already separates the planes logically (session tokens never grant `/v1`; the admin token never drives `/internal`), but **route absence is stronger than authorization**: a sandbox that cannot reach `/v1` at the TCP level is immune to any future `/v1` auth regression. The split also gives the CNI probe a deterministic positive/negative target pair. Cheap in axum: two routers, two binds, shared state.

### Egress profiles (values-selected; hardened is default)

| Profile | Egress from sandbox pods | Intended use |
|---|---|---|
| `zeroEgress` (default) | control-plane pods :8788 only, **no DNS**; `FLUIDBOX_CONTROL_URL` carries the internal Service **ClusterIP** (family-matched for dual-stack) | production |
| `restrictedEgress` | + kube-dns; Service DNS name in `FLUIDBOX_CONTROL_URL` | operational convenience; documented as "restricted", not "zero" (recursive DNS is an exfiltration channel) |
| `permissive` | 0.0.0.0/0 with `ipBlock.except`: `169.254.0.0/16` + pod/Service/node/private CIDRs from values (+ IPv6 ULA/link-local) | **dev-only**, values-gated, loudly documented as carrying no production guarantee |

Rationale for ClusterIP injection: NetworkPolicy cannot target a Service as an abstract object (rules are namespaceSelector+podSelector+port), a Service's ClusterIP is stable across normal Helm upgrades, and dropping DNS closes the last non-fluidbox destination. `NetworkMode::HostDev/Hardened` maps to profiles at the provider boundary; the orchestrator's hardcoded `HostDev` (`orchestrator.rs:150`) becomes a config-derived value in Phase 0. Sandboxes can never reach LiteLLM directly under any profile (parity with the Docker hardened-mode requirement, PLAN.md:271).

### Verified enforcement (NetworkPolicy is only as real as the CNI)

Kubernetes documents that NetworkPolicy without an enforcing CNI is silently inert (kind's default kindnet, notably). Shipping policies is not shipping containment. Two mechanisms:

1. **`helm test` probe** — release certification: a probe pod in the sandbox namespace under the deny policy must reach the internal Service :8788 (positive) and must NOT reach the public Service :8787 (negative). Both Services back healthy pods, so reachability is known independently of policy — no external-IP false passes.
2. **Boot-time async probe** — runtime protection: when `FLUIDBOX_PROVIDER=kubernetes`, the server boots normally but marks network enforcement `unverified` and **blocks new runs** until a probe pod (carrying the exact sandbox labels/tolerations/runtimeClass) passes the same positive/negative pair. `probe_unschedulable` and `policy_not_enforced` are distinguished (different remediation). Re-check on restart and ~6-hourly. `FLUIDBOX_REQUIRE_ENFORCED_NETPOL` defaults `true`; `false` is dev-only.

### Sandbox pod security baseline (portable everywhere)

`runAsUser: 10001` (numeric — kubelet cannot prove a named `USER` is non-root) + `runAsNonRoot`, `runAsGroup`/`fsGroup`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`, `enableServiceLinks: false`. The sandbox namespace enforces the **restricted Pod Security Standard**. `emptyDir.sizeLimit` AND ephemeral-storage requests/limits (defaults: 500m/1Gi request, 2 CPU/2Gi limit, 10Gi ephemeral — values-configurable per install and per agent later). Namespace ResourceQuota + application-level concurrent-run limit.

**Documented isolation regression:** standard pod APIs have no portable equivalent of Docker's `pids_limit: 512`; installations wanting it set kubelet `podPidsLimit`. Documented honestly in the chart README.

### Isolation tiers (cluster policy, not RunSpec input)

`runtimeClassName` comes from Helm values — never from user/agent input. Per-cloud recipes ship in docs:

| Cloud | Hard isolation | Recipe |
|---|---|---|
| GKE | gVisor (native GKE Sandbox) | node pool with `--sandbox type=gvisor`; `runtimeClassName: gvisor` |
| AKS | Kata (Pod Sandboxing) | `runtimeClassName: kata-mshv-vm-isolation` on supported pools |
| EKS | none managed | documented: self-managed gVisor nodes, or accept the runc tier |
| kind/dev | none | runc tier |

Plain runc pods with the baseline above are documented as a real but lower isolation tier — not silently equated with VM isolation.

## Packaging: Helm chart (`deploy/helm/fluidbox/`)

Helm, not an operator: the control plane is an ordinary Deployment, and fluidbox's orchestrator already IS the run controller — an operator would either duplicate it or force runs into a CRD, neither warranted for v1.

Chart contents:

- **fluidbox-server** Deployment — now `runAsNonRoot` (the Docker socket requirement is gone on this path; `deploy/server.Dockerfile`'s root user gets a K8s-mode note), `replicas: 1`, strategy `Recreate`, PVC for workspace archives, both Services (public :8787 / internal :8788), optional Ingress (its https origin becomes `FLUIDBOX_PUBLIC_URL` → CIMD + GitHub App webhooks light up with no code change — verified config-only seam).
- **fluidbox-web** Deployment + Service (`FLUIDBOX_API_URL` → server Service; admin token from Secret).
- **litellm** (optional, default off in prod values): digest-pinned image, ClusterIP-only, `LLM_UPSTREAM_URL=http://<release>-litellm:4000`, provider keys via existing-Secret refs; NetworkPolicy makes it unreachable from sandboxes. External LiteLLM is the documented production default. (The compose default `main-stable` mutable tag is NOT repeated here.)
- **Sandbox namespace** (created or referenced), restricted PSA labels, NetworkPolicies per profile, ResourceQuota/LimitRange.
- **RBAC:** ServiceAccount + Role/RoleBinding scoped to the sandbox namespace only: pods create/get/list/watch/delete, pods/exec, pods/log, secrets create/delete. Nothing cluster-scoped except an optional ClusterRole for the probe if the namespaces differ.
- **Secrets:** existing-Secret references throughout (DATABASE_URL, FLUIDBOX_ADMIN_TOKEN, FLUIDBOX_CREDENTIAL_KEY, LITELLM_MASTER_KEY, provider keys, imagePullSecrets). The chart never generates or stores credential material.
- **Values:** images (by digest for production; `FLUIDBOX_SANDBOX_IMAGE`/`FLUIDBOX_CODEX_SANDBOX_IMAGE`/collector), egress profile + CIDR lists, runtimeClassName, nodeSelector/tolerations/topologySpread/priorityClass, resource defaults, quota, archive PVC size/class, `FLUIDBOX_REQUIRE_ENFORCED_NETPOL`.
- **helm test:** the netpol probe.

Release plumbing (`.github/workflows/release.yml`): add the collector image to the multi-arch build matrix; publish the chart as an OCI artifact to GHCR.

## Convergence-invariant cross-check (PLAN.md §2)

| Invariant | Mechanism here |
|---|---|
| Fresh disposable sandbox per run; no persistent agent servers | one Pod per run, deterministic name, UID-preconditioned delete, GC'd Secret |
| Runner contract identical for every harness | images unmodified; one additive heartbeat-response field in shared runner-lib |
| Credentialed fetch never enters the sandbox | materialization unchanged control-plane-side; pod pulls a credential-free immutable archive |
| Sandbox holds only a session token | unchanged; token now delivered via per-run Secret (narrower exposure than PodSpec env) |
| Model access through the gateway; governance in Rust | facade unchanged; sandboxes cannot reach LiteLLM under any egress profile |
| Server is the single status writer | orchestrator remains sole controller; watches are wakeups, list/reconcile is truth (same philosophy as SSE NOTIFY+seq) |
| Autonomous ≠ ungoverned; permission callback always wired | untouched |
| RunSpec frozen at creation | untouched; runner images pinned by digest in production strengthens it |
| Ledger accepts only redacted envelopes | untouched; new ledger events (quiesce, artifact_missing, collection metadata) go through the same Redactor path |

## Implementation sequence

Each phase lands green through `just check`; e2e and DB-backed tests are executed only by the maintainer (standing agreement).

### Phase 0 — provider seam + collection hardening (Docker-only; fixes live defects #1-#5)

1. `AppState.provider: Arc<dyn ExecutionProvider>` + `FLUIDBOX_PROVIDER` selection (docker default); generalize the ping health check.
2. Trait v2 (structured state, `collect_artifacts`, `list_managed`); Docker impls.
3. New `fluidbox-workspace` crate: extract materialization/archiving/diff from `fluidbox-provider`; pristine-baseline + scrubbed-env hardened git collection; artifact size caps; `artifact_missing` semantics.
4. Unified durable finalizer: collect-before-terminal on ALL paths; persisted finalization intent (migration); restart-recoverable finalize worker; collection/quiesce timeouts.
5. `cancelling`/`finalizing` states; heartbeat-response quiesce in runner-lib (30 s deadline); dashboard/SSE awareness of the new states.
6. `pg_advisory_xact_lock` (keyed on connection id) around OAuth refresh rotation, replacing `oauth_locks` correctness reliance.
7. 512 KiB serialized runner-env ceiling with a clear 422 and per-component size diagnostics.
8. `NetworkMode` derived from config instead of the `orchestrator.rs:150` hardcode.

### Phase 1 — KubernetesProvider

1. `crates/fluidbox-provider-k8s` (kube-rs): Pod-first/Secret-second provisioning; blocking provision (init done + runner started); UID-preconditioned terminate; `list_managed` + adoption validation; watch+poll reconciliation; structured state from runner-container status; `activeDeadlineSeconds`.
2. `workspaced` collector crate + image (static binary + git + CA certs; Rust tar/zstd; amd64+arm64); exec-based `collect_artifacts` with `stream --offset` resume.
3. Workspace archive endpoint on the internal listener; PVC-backed archive store with TTL sweep.
4. Dual listener 8787/8788 (router split).
5. Grep-hygiene: all Kubernetes knowledge stays in `fluidbox-provider-k8s`; `events.rs`/`run_service.rs` remain provider-clean (existing e2e greps).

### Phase 2 — Helm + network hardening

1. The chart as specified (server/web/optional LiteLLM/Services/Ingress/sandbox namespace/PSA/NetworkPolicies/RBAC/quota/PVC/values).
2. Egress profiles incl. ClusterIP injection for `zeroEgress`; netpol probe as helm test AND boot-time run-gate (`FLUIDBOX_REQUIRE_ENFORCED_NETPOL`, default true).
3. Per-cloud install docs: EKS / AKS / GKE / kind — runtimeClassName recipes, CNI enforcement notes, ingress + `FLUIDBOX_PUBLIC_URL`, registry/imagePullSecrets, Neon connectivity.
4. Collector image + OCI chart publish in `release.yml`.

### Phase 3 — CI + conformance

1. Mocked-kube unit tier (manifest assembly, UID preconditions, adoption/refusal, watch 410-relist, state mapping).
2. kind + Calico PR job with a **tiny contract-stub runner image** (not the 1.5 GB production images): init-fetch happy path, corrupt-archive/digest rejection, unsafe-tar rejection, quiesce cancellation, runner crash → `artifact_missing`, control-plane restart + orphan adoption, netpol positive-8788/negative-8787, wrong-UID refusal.
3. Nightly/release job: real runner images, demo A against the Kubernetes provider (the cross-provider conformance bar per `docs/HANDOVER.md:121`), amd64+arm64 smoke.

### Deferred (explicit)

Egress proxy (waits for brokered git-writes); agent-sandbox CRD provider; warm pools; authenticated config fetch (env → fetch); pre-pull DaemonSet; multi-replica control plane (leader election / claim-guarded watchdog).

## Settled questions (adversarial review record, 2026-07-15)

Joint review: Claude (Fable 5) proposed; Codex (GPT-5.6-sol, max reasoning, read-only repo access) verified claims in code and counter-proposed; three rounds to convergence.

1. **Pod vs Job vs agent-sandbox CRD → bare Pod.** Job = a second completion controller fighting the orchestrator (which already owns status/heartbeat/budget/result), plus special native-sidecar completion semantics. agent-sandbox (v1beta1) = CRD install burden and a warm-pool/stateful-agent shape fluidbox doesn't have; `runtimeClassName` needs no CRD. Revisit as an optional provider if cold-start ever matters.
2. **Native sidecar vs ordinary init + collector → ordinary init container + long-lived collector container.** Native sidecars stable only ≥1.33; the mature-primitives composition works everywhere and keeps the collector alive post-runner-exit for collection.
3. **Workspace pull vs exec-push vs object storage → pull from control plane.** Pull preserves the control-plane-driven invariant (authority ≠ TCP direction); exec-push is race-prone and un-resumable; object storage adds a mandatory cloud dependency, egress holes in hardened policy (NetworkPolicy can't allow DNS names), and per-cloud private-endpoint variance. PVC-backed archives; object storage is a scale follow-up behind the same URL.
4. **Diff transport → collector-computed file + exec streaming with offset resume.** Direct exec stdout couples computation to a fragile stream; a POST upload endpoint needs scoped credentials, idempotency, and body-limit carve-outs ("retry for free" isn't free). Never trust agent-mutated `.git` (pristine baseline, scrubbed env) — this also fixes a live Docker-path vulnerability.
5. **Quiesce → heartbeat response, 30 s deadline.** Level-triggered `{"action":"quiesce"}`; runner exits without posting `/result`; timeout → `artifact_missing(quiesce_timeout)`, never collect a racing worktree. 20 s rejected (only two heartbeat opportunities). Quiesce is contract/orchestrator, NOT a provider-trait method.
6. **Session token in PodSpec env vs per-run Secret → Secret**, Pod-first ordering with ownerRef GC (no patch step, no orphan window).
7. **Egress default → zero-egress with ClusterIP injection, no DNS.** DNS is an exfiltration channel and the only required destination is fluidbox. `restrictedEgress` (DNS allowed) and `permissive` (dev-only, metadata + private CIDRs excepted) are values-gated profiles. Egress proxy deferred. "HostDev = allow-all" was rejected outright for Kubernetes (metadata endpoints, node services, cluster east-west).
8. **NetworkPolicy trust → verify, don't assume.** helm test + boot-time probe with positive/negative Service targets; runs blocked until verified; `FLUIDBOX_REQUIRE_ENFORCED_NETPOL` default true. kindnet famously doesn't enforce — CI uses Calico.
9. **Dual listener → v1-must** (route absence beats bearer auth alone; enables the deterministic probe).
10. **Archive persistence → PVC** over re-materialize (wrong for LocalCopy, moving refs) and over Neon blobs (WAL/backup/restore inflation; artifacts schema is inline text).
11. **`cancelling`/`finalizing` → real persisted states.** `sessions.status` is unconstrained text (Codex correction — no enum migration needed); the migration is for durable finalization intent. In-memory sub-states rejected: defeats audit and crash recovery.
12. **`/result` → persist intent before ACK** (Codex finding: today's ACK-then-`tokio::spawn` is lossy); restart-recoverable finalize worker.
13. **Code placement → new `fluidbox-workspace` crate** (git subprocess I/O belongs in neither `fluidbox-core` (pure) nor a Docker-named crate).
14. **Helm vs operator → Helm.** An operator duplicates the orchestrator or forces a run CRD; neither warranted. LiteLLM external-by-default, optional in-chart digest-pinned.
15. **CI → mocked-kube unit tier + kind/Calico PR job with a stub runner; heavy images nightly.** envtest-style fakes can't exercise kubelet/init/emptyDir/exec/CNI; 1.5 GB `kind load` on every PR rejected.
16. **Sequencing → Phase 0 (Docker-side hardening) first.** It fixes live defects and prevents debugging Kubernetes transport and diff correctness simultaneously.
17. **Provider strategy → dual-provider, additive (user directive, 2026-07-15).** Kubernetes is a second provider beside Docker, never a replacement. Docker stays the default (`FLUIDBOX_PROVIDER=docker`), stays production-supported on single hosts via docker-compose, and stays conformance-tested (its e2e phases run unchanged at every phase boundary). Trait v2 and the `fluidbox-workspace` extraction exist precisely so both providers share one semantics with two transports.

## Risks and trade-offs

- **Diff loss on pod eviction/node loss.** Accepted: recorded as explicit `artifact_missing`, never a silent "(no changes)". Docker parity note: the host dir survives container death today, so this is a real (bounded, honest) regression on catastrophic paths only.
- **Cancel-diff requires runner cooperation (quiesce).** A hung runner forfeits its diff after 30 s. Alternative (per-run PVC surviving deletion) rejected for cost/latency in v1.
- **`provision()` latency now includes archive fetch + unpack + image pull.** `initializing` covers it honestly; first-run image pull on a fresh node can dominate (~1.5 GB). Mitigations documented (regional mirrors, digest pinning); pre-pull DaemonSet deferred.
- **pids-limit regression** vs Docker (`pids_limit: 512` has no portable pod equivalent). Documented; `podPidsLimit` node config recommended.
- **Single-replica control plane** remains an availability (not correctness) ceiling; `Recreate` upgrades pause run intake briefly. Runner-side `/permission` forever-retry + PVC archives + durable finalizer make restarts non-destructive.
- **CNI probe is necessary-not-sufficient**: it proves enforcement at probe time on probe placement; it cannot prove every future node. Accepted as the practical bar, honestly documented.

## Acceptance statement

This design is accepted when: demo A (the live agent acceptance run) passes unchanged against `FLUIDBOX_PROVIDER=kubernetes` on a kind+Calico cluster and at least one managed cloud (EKS or GKE), with the hardened `zeroEgress` profile verified by the boot probe, the diff artifact produced by the collector path, `just check` green throughout, **and the Docker provider fully intact**: the same unified finalizer + hardened collection semantics (Phase 0), the full existing e2e suite green on `FLUIDBOX_PROVIDER=docker`, and the docker-compose deployment path still working — Kubernetes support lands beside Docker, never in place of it.

## References

- `PLAN.md` §2 (invariants), §6.2 (seams), M2/roadmap lines 96, 109, 152, 193, 202, 242-245
- `crates/fluidbox-core/src/traits.rs`; `crates/fluidbox-provider/src/{lib.rs,workspace.rs}`; `crates/fluidbox-server/src/{state.rs,orchestrator.rs,internal.rs,workers.rs,config.rs,facade.rs,harness.rs}`; `images/runner-lib/contract.mjs`; `deploy/{server.Dockerfile,web.Dockerfile,docker-compose.eval.yml}`; `.github/workflows/release.yml`
- Kubernetes: NetworkPolicy caveats (enforcement requires a CNI; no Service targeting; policy-application race) — kubernetes.io/docs/concepts/services-networking/network-policies/; native sidecar stability (≥1.33); Secret-held container start semantics; PodSecurity restricted profile
- kubernetes-sigs/agent-sandbox v0.5.1 (v1beta1) — evaluated and deferred (settled Q1)
- Managed-cloud isolation: GKE Sandbox (gVisor), AKS Pod Sandboxing (`kata-mshv-vm-isolation`), EKS (no managed option)
- kube-rs Api<Pod>/watcher patterns (context7 `/kube-rs/kube`)
