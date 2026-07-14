# fluidbox — Kubernetes-native execution (posture evaluation + phased design)

Status: rev 1 (design only — no code this round) · 2026-07-14
Slice name: **Phases K1–K3** (parallel track to M2 Lambda MicroVMs; shares its
trait prerequisites)
Parent design: `PLAN.md` §2 (convergence invariants), §6.2 (seams), §6.6
(sandbox contract), §6.7 (lifecycle); provider audit performed against the
tree at `main` (2026-07-14).

## 0. Summary

fluidbox's only execution substrate today is Docker (`DockerProvider`,
bollard, sibling containers over the local socket). This document evaluates
the entire posture for Kubernetes-native operation and lays out a phased
path: **K1** a `KubernetesProvider` behind the existing `ExecutionProvider`
seam plus a Helm chart and kind-based e2e; **K2** isolation/perf hardening;
**K3** an *optional* operator/CRD layer, evaluated honestly and recommended
*against* as a day-one investment.

The headline finding of the audit: the architecture is already ~90%
substrate-agnostic. The runner contract is env + one HTTP origin; workspace
init and diff capture are control-plane-side; `SandboxHandle` is serializable
jsonb; the orphan sweep and watchdog drive the provider only through the
trait. The Docker coupling is concentrated in **four leaks above the trait**
and the provider crate itself. Kubernetes is not just reachable — for the
egress-containment invariant it is *structurally better* than what the Docker
provider ships today (Hardened mode exists in code but is never selected;
on K8s, hardened-by-default is one static NetworkPolicy).

Decisions settled by the user for this round:

1. **Deliverable = this design document.** Implementation is a follow-up.
2. **Workspace delivery = shared RWX volume first**; archive push/pull is
   designed here as the portable follow-up seam, not built in K1.
3. **Targets:** kind/minikube (dev + e2e), managed cloud (EKS/GKE/AKS), and
   the Docker provider **stays supported** — runtime selected at boot.

## 1. Problem

Every fluidbox run provisions a fresh disposable sandbox (invariant §2 #1).
Today that requires a Docker daemon adjacent to the control plane: sandboxes
are sibling containers, the workspace is a host bind mount, and the sandbox
reaches the control plane via `host.docker.internal`. That posture:

- **does not deploy on Kubernetes at all** (no docker.sock in a pod worth
  having; `host.docker.internal` does not exist; host paths are node-local);
- carries a class of env gotchas (`FLUIDBOX_BIND` must be `0.0.0.0`, the
  data dir must be the *same absolute path* host-side and container-side in
  the eval compose) that exist only because of the sibling-container model;
- never actually wires the egress-free `Hardened` network mode — the
  orchestrator hard-codes `HostDev`, so containment is policy-only in
  practice (the codex image's `/etc/hosts` null-routing is the only
  structural guard);
- cannot scale past one machine: the daemon, the data dir, and the server
  are pinned together.

Kubernetes is the natural multi-node home for this workload: pods are the
disposable-sandbox primitive, NetworkPolicy is the structural egress
containment the design always promised, RBAC scopes the blast radius of the
provisioning credential, and PSA/RuntimeClass give an isolation ladder the
Docker provider lacks.

## 2. Posture audit — where Docker is actually baked in

### 2.1 Leaks above the `ExecutionProvider` trait (must fix; small)

| Where | What | K8s-blocking? |
|---|---|---|
| `crates/fluidbox-server/src/state.rs:44` + `main.rs:65` | `AppState.provider: Arc<DockerProvider>` — the concrete type, not `Arc<dyn ExecutionProvider>`; `main.rs` constructs `DockerProvider::connect()` unconditionally | yes — provider choice is compile-time |
| `crates/fluidbox-server/src/api.rs:274-276` | readiness handler calls the Docker-only inherent `ping()` and reports it as `"docker": docker_ok` | yes — `ping()` is not on the trait |
| `crates/fluidbox-server/src/orchestrator.rs:150` | `network: NetworkMode::HostDev` hard-coded in the `SandboxSpec` | yes — K8s wants hardened-by-default |
| `crates/fluidbox-server/src/config.rs:5-13, 75-77` | `absolute()` canonicalizes `FLUIDBOX_DATA_DIR` "because Docker bind mounts"; default `FLUIDBOX_PUBLIC_CONTROL_URL = http://host.docker.internal:8787` | default only — both keys stay, defaults become provider-aware |

That is the complete list. Nothing else above the trait knows Docker exists.

### 2.2 Inside the provider crate (fine — replaced wholesale by a sibling impl)

`crates/fluidbox-provider/src/lib.rs`: bollard over the local socket
(`connect_with_local_defaults`), per-session bridge network
`fluidbox-net-<id>` (`internal: true` when Hardened), container name
`fluidbox-<id>`, labels `fluidbox.session` / `fluidbox.managed=1` (the orphan
sweep key), bind `{workspace_host_dir}:/workspace:rw`, extra_host
`host.docker.internal:host-gateway` (HostDev only), hard-coded limits (2 GiB
memory, 512 pids, `cap_drop ALL`, `no-new-privileges`), and error
classification by string-matching `"No such container"`. None of this needs
touching — `DockerProvider` survives as-is; `KubernetesProvider` is a sibling
module in the same crate.

### 2.3 Already portable (no changes; the load-bearing good news)

- **Runner contract** (`images/runner-lib/contract.mjs`): the sandbox needs
  env (`FLUIDBOX_CONTROL_URL/SESSION_ID/SESSION_TOKEN/TASK/…`) and HTTP
  reachability to **one origin** for `/internal/sessions/{id}/{permission,
  events,heartbeat,result,tools/call}`, `/internal/token/renew`, and
  `/internal/llm[/v1]/*`. No inbound ports. Retry/timeout tuning is
  topology-free. Both runner images run as non-root uid 10001 already.
- **Credential custody**: the sandbox holds only the session token (its fake
  `ANTHROPIC_API_KEY`); the facade swaps the real key; LiteLLM alone holds
  provider keys. Nothing about K8s changes this.
- **Workspace init + diff capture are control-plane-side**
  (`orchestrator.rs::materialize_workspace` / `capture_diff_and_cleanup`,
  `provider/src/workspace.rs`): the credentialed git fetch never enters the
  sandbox; the diff is `git add -A && git diff --binary <base>` on the
  control plane's own view of the workspace. On K8s this ports unchanged
  under the RWX-volume decision (§5).
- **`SandboxHandle` is serializable jsonb** persisted per session — reattach
  after restart already assumes no live client. A pod handle fits the same
  shape as a container handle.
- **Orphan sweep + watchdog** drive the provider only through
  `list_orphans()` / `state()` / `terminate()` — all trait methods.

## 3. Approaches considered

**A. `KubernetesProvider` behind the existing trait, Helm-deployed control
plane (chosen, K1).** Sandboxes become pods created directly by the server
via kube-rs. The orchestrator, watchdog, ledger, and approval flow are
untouched; the DB remains the single source of truth and the server the
single status writer (invariant preserved by construction). Smallest diff,
dual-runtime with Docker, and the same refactors (trait object, `health()`
on the trait, network-mode plumbing) are prerequisites M2's
`LambdaMicrovmProvider` needs anyway.

**B. Operator + CRDs as the primary architecture.** An `AgentRun`/`Sandbox`
CRD; the server creates CRs; a controller reconciles pods. Rejected as the
*primary* path: it inserts a second reconciler into a system whose
correctness argument rests on "the server is the single status writer and
the DB is the source of truth." CR `status` would either mirror the DB
(split-brain surface, double bookkeeping) or become authoritative (violates
the invariant and moves governance state out of Postgres, where the gapless
ledger, approvals, and budgets live). The watchdog/budget/approval loops
cannot move into an operator without duplicating the governance plane.
Retained as an *optional* K3 layer with a narrowed charter (§8).

**C. Virtual-kubelet / Job-based execution.** A `Job` wrapper adds
completion and backoff-retry semantics we must disable anyway (a runner must
run exactly once; retries would replay an agent against a half-mutated
workspace and duplicate ledger streams). Bare pods with
`restartPolicy: Never` express the actual contract. Rejected.

## 4. K1 — `KubernetesProvider` design

### 4.1 Object mapping

| fluidbox concept | Kubernetes object |
|---|---|
| Sandbox | one **Pod**, `restartPolicy: Never`, in a dedicated sandbox namespace |
| Sandbox identity | pod name `fluidbox-<session_id>`; labels `fluidbox.io/session=<uuid>`, `fluidbox.io/managed=true` |
| `SandboxHandle` | `runtime: "kubernetes"`, `external_id: <pod name>`, `attrs: {namespace, uid}` — the pod **uid** guards reattach against name reuse |
| Per-session bridge network | **nothing per-session** — one static NetworkPolicy by label covers all sandboxes (§4.3) |
| Orphan sweep | `list pods -l fluidbox.io/managed=true` in the sandbox namespace |
| 2 GiB / cap-drop hardening | `resources.limits` + pod `securityContext` (§4.2) |

Trait mapping, method by method:

- `provision(spec)` → create the Pod (spec below), return the handle. The
  image, env vector, and workspace path arrive exactly as they do for
  Docker; no trait change needed for K1.
- `state(handle)` → GET pod (verify `metadata.uid` matches `attrs.uid`;
  mismatch ⇒ `Gone`): phase `Running` ⇒ `Running`; `Succeeded`/`Failed` ⇒
  `Exited(exit code from containerStatuses[0].state.terminated)`; API 404 ⇒
  `Gone`. Classification uses the **typed** `kube::Error::Api(status.code ==
  404)` — no string matching (an explicit improvement over the Docker impl).
- `terminate(handle)` → delete with a short grace period (e.g. 10s),
  tolerate 404. No network teardown step exists.
- `list_orphans()` → label-selector list; parse `fluidbox.io/session` back
  to a `Uuid`, rebuild handles from pod name/uid. Same reap-even-without-DB
  property as Docker's label sweep.
- `runtime_name()` → `"kubernetes"`; new `health()` (§6) → an API
  self-subject review or a namespaced pods `list` with `limit=1`.

Client construction: `kube::Client::try_default()` — resolves the in-cluster
ServiceAccount when the server runs as a pod, or the local kubeconfig when a
dev runs `just server` on the host against kind. One code path, both
topologies.

### 4.2 Sandbox Pod spec (sketch)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: fluidbox-8c5c9a1e-…            # fluidbox-<session_id>
  namespace: fluidbox-sandboxes
  labels:
    fluidbox.io/managed: "true"
    fluidbox.io/session: "8c5c9a1e-…"
spec:
  restartPolicy: Never                  # exactly-once; server owns lifecycle
  automountServiceAccountToken: false   # the sandbox gets NO cluster identity
  enableServiceLinks: false             # no service env leakage
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001                    # both runner images already use 10001
    fsGroup: 10001                      # RWX volume writability (§5)
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: runner
      image: ghcr.io/…/fluidbox-sandbox-runner@sha256:…   # run_spec.runner_image
      workingDir: /workspace
      env: []                           # the SandboxSpec env vector, verbatim
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: { drop: ["ALL"] }
      resources:
        limits:   { memory: 2Gi, cpu: "2", ephemeral-storage: 4Gi }
        requests: { memory: 512Mi, cpu: 250m }
      volumeMounts:
        - name: workspaces
          mountPath: /workspace
          subPath: workspaces/8c5c9a1e-…/repo
  volumes:
    - name: workspaces
      persistentVolumeClaim:
        claimName: fluidbox-workspaces   # FLUIDBOX_K8S_WORKSPACE_PVC
```

Notes:

- **Pids limit** is not expressible per-pod; it is a kubelet setting
  (`podPidsLimit`) — the chart documents it and the K2 hardening phase sets
  it on managed node pools where possible. Ephemeral-storage limits (absent
  under Docker today) partially compensate by bounding runaway disk.
- `readOnlyRootFilesystem` is **not** set in K1: the runner images write to
  `$HOME`/npm caches/`CODEX_HOME`. K2 revisits with explicit `emptyDir`
  mounts for the writable paths.
- Scheduling knobs (`nodeSelector`, `tolerations`, `priorityClassName`,
  `runtimeClassName`, `imagePullSecrets`) are provider config passed through
  from Helm values — empty by default.
- The sandbox namespace carries PSA labels
  `pod-security.kubernetes.io/enforce: restricted`. The pod spec above is
  restricted-compliant by construction, so admission becomes a regression
  tripwire, not a burden.

### 4.3 Networking

**Sandbox → control plane.** The server is a ClusterIP Service;
`FLUIDBOX_PUBLIC_CONTROL_URL=http://fluidbox-server.fluidbox.svc.cluster.local:8787`
is injected as `FLUIDBOX_CONTROL_URL`/`ANTHROPIC_BASE_URL` exactly as today.
This retires the whole `host.docker.internal` + "`FLUIDBOX_BIND` must not be
loopback" gotcha class — in-cluster DNS is unambiguous.

**Containment (the mode-mapping decision).** On Kubernetes the provider is
**hardened-by-default**: one static policy pair in the sandbox namespace,
selected by `fluidbox.io/managed=true`, no per-session objects:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sandbox-default-deny
  namespace: fluidbox-sandboxes
spec:
  podSelector: { matchLabels: { fluidbox.io/managed: "true" } }
  policyTypes: [Ingress, Egress]        # no rules ⇒ deny all both ways
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sandbox-allow-control-plane
  namespace: fluidbox-sandboxes
spec:
  podSelector: { matchLabels: { fluidbox.io/managed: "true" } }
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: fluidbox }
          podSelector:
            matchLabels: { app.kubernetes.io/name: fluidbox-server }
      ports: [{ port: 8787, protocol: TCP }]
    - to:                                # kube-dns only, port-scoped
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: kube-system }
          podSelector: { matchLabels: { k8s-app: kube-dns } }
      ports:
        - { port: 53, protocol: UDP }
        - { port: 53, protocol: TCP }
```

This structurally delivers what `NetworkMode::Hardened` promised but never
wired under Docker (`orchestrator.rs:150` hard-codes `HostDev`; the provider
comment defers "the hardened-compose path"). Decision: **the K8s provider
treats both `NetworkMode` values as hardened** — there is no legitimate
"reach the host gateway" analog worth building, and policy-only egress would
be a posture regression the platform never advertised. `HostDev` remains
meaningful only for the Docker provider. (The orchestrator stops hard-coding
the mode; see §6.)

**LiteLLM** gets the inverse policy: ingress only from the server pod;
sandboxes cannot address it (same custody line as the compose networks
today). Provider keys live only in LiteLLM's Secret.

**Browser/AS-facing surface.** The dashboard and
`FLUIDBOX_PUBLIC_URL` (OAuth `redirect_uri`, CIMD client-id document, GitHub
App manifest/install dances, webhook ingress) ride an Ingress with TLS. A
side benefit: a real https, non-loopback `FLUIDBOX_PUBLIC_URL` makes CIMD
client identity *eligible for the first time* in a standard deployment
(today's local deployments always fall back to DCR).

**Residual risk — DNS exfiltration.** Allowing port-53 egress to kube-dns
gives a covert channel (and lets a sandbox resolve names it can never
connect to). K1 accepts this with the policy layer as backstop; K2 offers
the lockdown: inject `dnsPolicy: None` + `dnsConfig` pointing at a resolver
the policy denies, and pass the control-plane Service's **ClusterIP**
(resolved at provision time) instead of the DNS name — zero DNS egress.
Documented as a values toggle because some CNIs also need DNS for the
Service VIP path.

### 4.4 What explicitly does NOT change

The internal gateway, LLM facade, permission gate, approvals, ledger,
capability broker, trigger/schedule/event spines, and both runner images are
untouched. The codex image's `/etc/hosts` null-routing of OpenAI hosts stays
as belt-and-suspenders under the NetworkPolicy. Invariants §2 #1–#4 are
preserved by construction: fresh pod per run, same runner contract, same
capability/permission/containment layering (containment strictly improves),
model access still via the facade.

## 5. Workspace delivery — RWX volume (K1), archive seam (K2)

### 5.1 RWX mode (chosen)

`FLUIDBOX_DATA_DIR` lives on a ReadWriteMany PVC mounted into the server pod
(e.g. at `/data`); each sandbox pod mounts the same PVC with
`subPath: workspaces/<session>/repo` at `/workspace`.
`materialize_workspace`, `capture_diff_and_cleanup`, and
`cleanup_workspace` run **unchanged** — the control plane reads and writes
the same filesystem the sandbox saw, exactly the property the Docker bind
mount provided. The eval-compose "same absolute path on host and container"
constraint dissolves: only the server pod's mount path matters, and
`config.rs::absolute()` keeps working (it canonicalizes a pod-local path).

Plumbing decision: `SandboxSpec.workspace_host_dir` currently carries the
server-local absolute path. The K8s provider needs the **session-relative**
subPath (`workspaces/<session>/repo`). Rather than parsing the absolute path
back apart, the spec field gains a sibling (or is re-specified) as
`workspace_dir_rel` + the provider-local base; Docker keeps joining base +
rel into a bind source, K8s uses rel as subPath. Small, decided at
implementation time; the doc records the intent that **both providers derive
their mount from one session-relative path**.

Storage classes per target:

| Target | RWX class | Notes |
|---|---|---|
| EKS | EFS CSI | fsGroup honored via CSI; git on EFS is measurably slower — see costs |
| GKE | Filestore CSI | min capacity is large (1 TiB basic) — flag in values docs |
| AKS | Azure Files (NFS) | POSIX semantics fine for git; SMB variant NOT recommended |
| generic | NFS provisioner | the lowest common denominator |
| kind (dev/e2e) | single-node: a `hostPath`-backed PV with RWX declared | RWX is only a *claim* on kind; with one node it is honest enough for e2e |

Gotchas the chart and docs must carry:

- **uid 10001 writability**: `fsGroup: 10001` on the sandbox pod plus the
  server pod writing with a matching group; on NFS-family filesystems verify
  the export squashing config doesn't defeat it.
- **subPath history**: subPath+symlink CVEs (CVE-2017-1002101 class) are
  long-patched, but the mitigating posture is also structural here — the
  control plane creates `workspaces/<session>/repo` *before* the pod exists,
  and the agent runs non-root with the PVC mounted only at that subPath.
- **Performance**: `git status`-heavy agent work on EFS/Filestore is slower
  than local disk. Accepted as a K1 cost (correctness first); K2's archive
  mode is the performance escape hatch, not premature rsync cleverness.
- **Cleanup**: unchanged (`cleanup_workspace` removes the session dir); a
  periodic janitor for dirs orphaned by crashes already exists in spirit via
  `keep_workspaces` debugging flag semantics — no new mechanism.

### 5.2 Archive mode (designed now, built in K2)

For clusters without workable RWX storage:

- **Push**: an initContainer (runner image, or a minimal curl image) pulls
  `GET /internal/sessions/{id}/workspace.tar` — a new internal endpoint,
  session-token authed like every other internal route — and unpacks into an
  `emptyDir` shared with the runner container. The tar is produced from the
  already-materialized `$DATA_DIR/workspaces/<session>/repo`.
- **Diff**: captured **before teardown** via the pods/exec subresource —
  the control plane execs `git add -A && git diff --binary <base>` in the
  pod and streams the output; this is the `terminate(collect)` shape
  PLAN.md §6.2 already anticipates for MicroVMs. The runner never computes
  its own diff: a sandbox-computed diff would let a compromised agent forge
  the audit artifact — **rejected on trust-model grounds**, recorded here so
  it isn't relitigated.
- Failure ordering: if exec-diff fails (pod already dead), the artifact
  records "(diff unavailable)" exactly as the current capture-failure path
  does; a dead sandbox can never mutate session state (delivery invariant
  unchanged).
- RBAC cost: archive mode adds `pods/exec` to the server's Role (§7). RWX
  mode does not need it — one more reason RWX ships first.

## 6. Rust refactors required above the provider (the complete list)

1. **Trait object**: `AppState.provider: Arc<dyn ExecutionProvider>`
   (`state.rs:44`); `main.rs` selects the impl from
   `FLUIDBOX_EXECUTION_PROVIDER=docker|kubernetes` (default `docker` — local
   `just dev` is untouched).
2. **Trait gains `async fn health(&self) -> Result<(), ProviderError>`**;
   `api.rs:274` reports `"provider": ok` + `"runtime": runtime_name()`
   instead of `"docker": docker_ok`. (Docker impl delegates to `ping()`.)
3. **Orchestrator network mode** (`orchestrator.rs:150`): comes from the
   provider/config, not a hard-coded `HostDev`.
4. **Workspace path plumbing**: session-relative dir on the spec (§5.1).
5. **Config**: new keys `FLUIDBOX_EXECUTION_PROVIDER`,
   `FLUIDBOX_K8S_NAMESPACE`, `FLUIDBOX_K8S_WORKSPACE_PVC`, optional
   scheduling/imagePull values; `absolute()`'s comment updated (it remains
   correct — the path is server-pod-local). `FLUIDBOX_PUBLIC_CONTROL_URL`
   default stays Docker-flavored; the chart sets the Service DNS value.
6. **New `k8s.rs` module** in `fluidbox-provider` (kube-rs + rustls,
   matching the workspace's reqwest posture). `DockerProvider` untouched.

Everything else — orchestrator lifecycle, workers, internal gateway, facade,
run_service, deliveries — compiles against the trait and does not change.
These same refactors (1–4) are prerequisites for M2's
`LambdaMicrovmProvider`; K1 pays them once.

## 7. Deploy artifacts — Helm chart + kind e2e

```
deploy/helm/fluidbox/
├── Chart.yaml
├── values.yaml                  # images (server/web/litellm/runners by digest),
│                                # neon vs in-cluster pg, ingress hosts/tls,
│                                # sandbox {namespace, pvc, limits, scheduling},
│                                # networkPolicy toggles, dns lockdown (K2)
└── templates/
    ├── server-deployment.yaml   # 1 replica, strategy: Recreate (§9)
    ├── server-service.yaml      # ClusterIP :8787
    ├── server-rbac.yaml         # SA + Role/RoleBinding in the SANDBOX ns:
    │                            #   pods: create/get/list/watch/delete ONLY
    │                            #   (+ pods/exec only when archive mode on)
    ├── web-deployment.yaml, web-service.yaml, ingress.yaml
    ├── litellm-deployment.yaml, litellm-service.yaml
    ├── sandbox-namespace.yaml   # PSA restricted labels
    ├── networkpolicies.yaml     # §4.3 pair + litellm ingress-from-server
    ├── workspaces-pvc.yaml      # RWX
    ├── secrets.yaml             # admin token, credential key, litellm master
    │                            # key; ANTHROPIC/OPENAI keys ONLY in litellm's
    └── postgres.yaml            # optional eval-mode in-cluster PG (default:
                                 # external Neon DATABASE_URL, matching CLAUDE.md)
```

Custody notes: the server's ServiceAccount is the **only** cluster identity
in the system, and its Role is namespaced to the sandbox namespace with the
five pod verbs — it cannot read Secrets, touch its own namespace's objects,
or escalate. Sandbox pods run with `automountServiceAccountToken: false`
(§4.2): a compromised agent holds a session token and nothing else, same as
today.

**kind bootstrap + e2e**: `just k8s-up` (create kind cluster, `kind load
docker-image` the runner images, `helm install` with kind values —
hostPath-backed RWX PV, no ingress TLS) and `just k8s-e2e` (port-forward the
server Service, then reuse `scripts/governance-e2e.sh` and the existing e2e
tiers unchanged — they drive HTTP APIs and are provider-blind). The GitHub
seams (`FLUIDBOX_GITHUB_API_URL`, `FLUIDBOX_GITHUB_CLONE_BASE`) work in-pod
exactly as they do on the host.

## 8. Operator/CRD evaluation (the honest part)

What a CRD layer would look like: an `AgentRun` (or `Sandbox`) CRD; the
server creates a CR per run; a controller reconciles the pod from the CR and
writes pod-level status back to CR `status`.

**What it genuinely buys:**

- `kubectl get agentruns` fleet visibility without the dashboard;
- ownerReferences GC (CR deleted ⇒ pod garbage-collected by Kubernetes even
  if the control plane is down);
- admission surface: ResourceQuota per team, ValidatingAdmissionPolicy on
  images/limits, OPA/Kyverno integration;
- drift reconciliation while the control plane is briefly down;
- a story for multi-cluster / fleet scheduling later.

**What it costs:**

- a **second reconciler** in a system whose audit story is "the server is
  the single status writer; Postgres is the source of truth." CR status
  either mirrors the DB (split-brain surface, permanent double bookkeeping)
  or becomes authoritative (moves governance state out of the ledger —
  breaks the model);
- the lifecycle logic that matters (heartbeat watchdog, budget sweeps,
  approval expiry, terminal-entry delivery enqueue) lives on DB state and
  cannot move into an operator without duplicating the governance plane;
- CRD versioning/conversion machinery, a controller deployment, and
  leader-election — real operational surface for a system that already has
  exactly-once orchestration through the DB.

**Recommendation:** provider-first (K1/K2); operator **deferred to K3 and
only if a concrete demand materializes** (kubectl UX, per-team quota
admission, or multi-cluster). When built, its charter is narrowed so the
invariants survive:

- the CR is a **provision-request/observation object only** — the server
  remains the sole writer of session status in Postgres; CR status is
  explicitly documented as a *projection*, never consulted by the control
  plane;
- alternatively (cheaper, K3a): keep pods provider-created and add only the
  **observability projection** — a controller-less "status reflector" or
  simply richer pod labels/annotations plus `kubectl` column definitions;
- ownerReferences GC can be had *without* an operator: the provider sets an
  ownerReference from the sandbox pod to a per-session ConfigMap (or to the
  CR in K3), so bulk cleanup is one delete. Orphan-sweep remains the
  authoritative reaper either way.

## 9. Security posture comparison + HA/scale notes

| Dimension | Docker today | K8s (this design) |
|---|---|---|
| Egress containment | policy-only (`HostDev` hard-coded; Hardened unwired); codex `/etc/hosts` is the only structural guard | **structural**: default-deny NetworkPolicy; control plane + DNS only (DNS closable in K2) |
| Sandbox credentials | session token only | same; plus `automountServiceAccountToken: false` (no cluster identity) |
| Kernel isolation | shared kernel, cap-drop ALL, no-new-privileges | same baseline via securityContext + seccomp `RuntimeDefault`; **upgrade path**: gVisor/Kata via `runtimeClassName` (K2 values toggle) — an isolation ladder Docker-provider deployments don't have |
| Provisioning credential blast radius | docker.sock = root-equivalent on the host (the eval compose mounts it into the server) | namespaced Role, five pod verbs, no secrets access |
| Resource limits | 2 GiB + 512 pids hard-coded | 2 GiB/cpu/ephemeral-storage per pod (values-tunable); pids at kubelet level; ResourceQuota/LimitRange on the namespace (K2) |
| Orphan cleanup | label sweep at boot | same sweep + optional ownerReference GC |
| Multi-tenancy | none (one daemon) | namespace + quota + PSA per deployment; per-tenant node pools possible |
| Cold start | image already on host | **worse**: node-local image pulls — mitigation: pre-pull DaemonSet for runner images (K2), digest-pinned |
| Workspace I/O | local disk | **worse** on RWX (EFS/Filestore latency) — accepted K1 cost; archive mode (K2) restores node-local I/O |

**HA/scale.** Recommend **`replicas: 1` + `strategy: Recreate`** for the
server in K1, honestly documented: per-run orchestrator tasks
(`spawn_run`) and approval `Notify` wakeups are in-memory in the replica
that created the run. This is already *degraded-but-safe* at N>1 — approvals
and SSE have DB-polling floors, the DB is the source of truth, and the
watchdog's stale-launch sweep (15 min) plus heartbeat watchdog fail over
runs whose owning replica died — but "safe" is not "good": a mid-`run()`
restart parks the session until a sweeper notices. Full HA needs: (a)
resumable orchestration (a claim/lease table so any replica can drive
provisioning steps idempotently), (b) `pg_notify`-backed approval wakeups
replacing the in-process `Notify`, (c) sweep intervals tightened. None of
this is K8s-specific; it is future work the chart should not pretend away.

## 10. Phasing

- **K1 — provider + chart + e2e**: refactors §6 (1–6), `KubernetesProvider`
  (RWX mode), Helm chart §7, `just k8s-up` / `just k8s-e2e` on kind, docs.
  *Converges by:* nothing above the trait changes; every §2 invariant
  preserved; Docker path untouched (`FLUIDBOX_EXECUTION_PROVIDER` defaults
  `docker`).
- **K2 — hardening + portability**: gVisor/Kata RuntimeClass toggle,
  ResourceQuota/LimitRange, runner-image pre-pull DaemonSet, DNS lockdown
  (§4.3), archive workspace mode + `pods/exec` diff capture (§5.2),
  `readOnlyRootFilesystem` with explicit writable emptyDirs, kubelet
  `podPidsLimit` guidance.
- **K3 (optional) — operator/CRDs**: per §8 charter only; reassess demand
  first.
- **Synergy with M2 (Lambda MicroVMs):** K1's refactors are M2
  prerequisites (trait object, `health()`, network-mode plumbing,
  session-relative workspace path); K2's archive mode is the same
  "archive push instead of bind mount" shape M2 needs. The tracks share a
  seam, not a schedule.

## 11. Open questions (deliberately deferred to implementation)

1. Exact shape of the workspace-path spec change (§5.1) — sibling field vs
   re-specification of `workspace_host_dir`.
2. Whether `NetworkMode` gains a third variant (`Cluster`) or the K8s
   provider simply ignores the existing two (§4.3 decides behavior, not
   naming).
3. kind e2e scope: which of the e2e tiers run in CI on kind vs remain
   Docker-only (candidate: the full `just e2e` stays Docker; a governance +
   live-demo subset runs on kind).
