# Fluidbox on GCP — architecture

Target: project **`fluidbox-506603`**, region **`us-central1`**, zone
**`us-central1-c`**.

This document records what runs where, why each choice was made, and what each
choice costs — including the things it gives up.

## 1. Topology

```
                        ┌──────────────────────────────────────────┐
   browser ───────────▶ │  platform.fluidzero.ai        (Vercel)   │
                        │                                          │
                        │   /            marketing                 │
                        │   /docs        documentation             │
                        │   /app/*       dashboard (React)         │
                        │   /api/fluidbox/*  ─┐ route handler      │
                        │   /v1/*            ─┤ next.config rewrite│
                        └─────────────────────┼────────────────────┘
                                              │  (same ORIGIN — see §2)
                                              ▼
                        ┌──────────────────────────────────────────┐
                        │  api.platform.fluidzero.ai               │
                        │  Google Cloud Load Balancer (GKE Ingress)│
                        │  · ManagedCertificate (Google-managed TLS)│
                        │  · FrontendConfig  → HTTP redirects to 443│
                        │  · BackendConfig   → timeoutSec 3600 (SSE)│
                        └───────────────────┬──────────────────────┘
                                            ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  GKE  "fluidbox"  · zonal us-central1-c · Standard · upstream Cilium    │
  │                                                                         │
  │  ns fluidbox                        ns fluidbox-sandboxes               │
  │   ├── fluidbox-server × 2            ├── ResourceQuota (12 pods)        │
  │   │    :8787 public  :8788 internal  ├── LimitRange                     │
  │   ├── fluidbox-litellm (DB-backed)   └── agent pods (created per run)   │
  │   └── ExternalSecret → fluidbox-secrets                                 │
  │                                                                         │
  │  node pool "system"   1→3 × e2-standard-4, on-demand   (always on)      │
  │  node pool "sandbox"  0→3 × e2-standard-4, SPOT        (zero when idle) │
  └────────────┬───────────────────────────────────┬────────────────────────┘
               │ private IP                        │ Cloud NAT (one static IP)
               ▼                                   ▼
        Cloud SQL PostgreSQL 16            api.anthropic.com, GHCR,
        · fluidbox  (app)                  the org's OIDC issuer, GitHub
        · litellm   (virtual keys)
```

## 2. Why `platform.fluidzero.ai` is Vercel and not the cluster

The dashboard sets `__Host-` prefixed cookies, and `__Host-` is *defined* as
host-locked. The control plane additionally refuses cookie-authenticated writes
unless the request `Origin` matches `FLUIDBOX_PUBLIC_URL` **exactly**.

So the OIDC callback (`/v1/auth/callback`) has to land on the *same origin the
dashboard runs on*. `apps/web/next.config.ts` implements exactly that: when
`FLUIDBOX_WEB_MODE=sso`, it rewrites `/v1/*` to `FLUIDBOX_API_URL`.

Consequences that follow, and are not optional:

- `server.publicUrl` is **`https://platform.fluidzero.ai`** — the Vercel origin
  — not the Ingress hostname. It is the address the *browser* sees.
- `FLUIDBOX_API_URL` must be set on Vercel at **build** time. Next.js bakes
  rewrites at build; a runtime-only value produces a deployment with no rewrite
  and a login flow that 404s.
- `api.platform.fluidzero.ai` needs its own certificate, because Vercel's proxy
  makes a real TLS connection to it.

## 3. GKE

| Decision | Choice | Why, and what it costs |
|---|---|---|
| Mode | **Standard**, not Autopilot | The sandbox plane needs node-level control Autopilot does not offer: a Spot pool that scales to zero, taints keeping agents off the control-plane node, and a gVisor RuntimeClass if hard isolation is turned on later. Autopilot also prices per pod *request*, the wrong shape for a mostly-idle fleet. Cost: we own node upgrades and sizing. |
| Location | **Zonal** (`us-central1-c`) | GKE's free tier applies a $74.40/month credit to one cluster, which cancels a single cluster's `$0.10/hr` management fee exactly. A regional control plane costs that fee three times for a data plane that is one node anyway. **Cost: a zone outage takes the control plane down.** Regional is a one-variable change (`zone` → `region`) plus the fee. |
| Dataplane | **V2 (Cilium)** | NetworkPolicy is not optional here — the server refuses to start runs until a boot probe proves the CNI actually drops traffic (`netpol.requireEnforced`). DPv2 enforces natively with no add-on to forget. It is also the prerequisite for the governed-egress feature (`networkGrants`), which is off but now becomes available. |
| Nodes | private, `GKE_METADATA`, Shielded, image streaming | Private nodes have no external address; Cloud NAT gives them one stable egress IP. `GKE_METADATA` blocks the legacy metadata endpoints from pods — the same `169.254.169.254` class the control plane's own egress predicate refuses. Image streaming matters concretely: the runner images are ~1.5 GB. |
| System pool | 1→3 × `e2-standard-4`, `max_surge=1 max_unavailable=0` | This is the fix for the lean tier's "single node = downtime" caveat. An upgrade **adds** a node, drains onto it, then removes the old one — so a one-node pool still upgrades without dropping the control plane, and the extra node is billed only for the minutes an upgrade takes. |
| Sandbox pool | 0→3 × `e2-standard-4`, **Spot**, tainted | Zero nodes when idle is what makes always-on affordable. Spot is safe here: a preempted sandbox is a failed run the control plane already knows how to re-drive, and no control-plane state lives on these nodes. The taint keeps everything else off preemptible capacity. |
| etcd | CMEK (`gke-etcd` key) | Application-layer encryption of Secret objects under a key we can rotate and revoke, on top of Google's default at-rest encryption. |

**Control-plane endpoint.** Public, with `master_authorized_cidrs` empty by
default. This is a named residual, not an oversight: GitHub Actions egress
addresses are large and change without notice, so an allowlist would break CI or
require a bastion. The endpoint is protected by IAM and TLS client certs — there
is no anonymous access — but it *is* exposed to network-level attack. Set
`master_authorized_cidrs` once a stable egress address exists; Connect Gateway
removes the public endpoint entirely and is the documented follow-up.

## 4. Data

**Cloud SQL for PostgreSQL 16, private IP only.** No public address means there
is no authorized-network list to get wrong.

Fluidbox needs **direct** connections — sqlx uses prepared statements and the SSE
fanout uses `LISTEN/NOTIFY`, both of which transaction-mode pooling breaks.
Private IP is a direct connection.

Two databases on one instance:

- `fluidbox` — the application.
- `litellm` — LiteLLM's own store, with its own user. LiteLLM applies its prisma
  schema to whatever `DATABASE_URL` it receives, so pointing it at the
  application database would let it alter tables fluidbox's migrations own.

`max_connections` is set to **100** explicitly. This is load-bearing on a small
tier: the app holds `replicas × (pool + 2)` = 2 × 27 = 54, and a `db-g1-small`
defaults to roughly 50 — leaving no headroom for migrations, `psql`, or a surge
upgrade briefly running three replicas.

**RLS actually enforces here.** Cloud SQL's user is neither `SUPERUSER` nor
`BYPASSRLS`, unlike Neon's `neondb_owner`, so migration 0018's policies execute
rather than being skipped. On top of that, `server.runtimeRole` splits the pool
onto the non-owner `fluidbox_runtime` role. Both layers, not one.

Backups: nightly + **point-in-time recovery** (WAL archiving, 7 days). Without
PITR, recovery granularity is the nightly backup — up to 24 h of runs,
approvals and audit rows.

## 5. Sealing and custody {#sealing}

`FLUIDBOX_KMS_MODE=static`, with the KEK in Secret Manager encrypted by a
customer-managed Cloud KMS key.

**Stated honestly:** fluidbox ships `off | static | aws` and has **no native GCP
KMS backend**. `static` is therefore the only mode that gives v2 envelope
sealing on GCP — per-tenant DEKs, AAD-bound so a sealed blob cannot be
transplanted across tenants or columns, with the boot gate that refuses a KEK
which cannot unwrap a stored DEK.

The gap versus the `aws` backend: with AWS KMS the key never leaves the HSM
boundary, whereas here the KEK plaintext is present in the control-plane pod's
environment. Custody still roots on Cloud KMS + IAM + audit logs (the Secret
Manager secret is CMEK-encrypted, per-secret IAM, and every access is logged),
but the trust boundary is the pod, not an HSM.

The alternative — `FLUIDBOX_KMS_MODE=off` — is worse: it falls back to v1 legacy
sealing under one deployment-wide key with no AAD, no per-tenant DEK, and no
untransplantability.

**Follow-up:** a native `gcp` `KeyWrapper` in `crates/fluidbox-server/src/kms.rs`
alongside `AwsKms`, wrapping DEKs with Cloud KMS `encrypt`/`decrypt`. That
closes the gap completely. It is a contained change — `KeyWrapper` is a small
trait — but it is a core code change and therefore out of scope for a
deployment.

## 6. Workspace archives

`server.archiveStore = "s3"`, pointed at a **GCS bucket via the S3-compatible
XML API** (`https://storage.googleapis.com`, path style, SigV4 with an HMAC key).

This is what unlocks `replicas: 2`, and with it:

- `strategy: RollingUpdate` instead of `Recreate` — deploys stop being an outage;
- PodDisruptionBudgets that mean something;
- a usable HorizontalPodAutoscaler.

The node-local alternative is one ReadWriteOnce PVC, which structurally pins the
control plane to a single replica.

**The cost:** an HMAC key is a long-lived static credential. The chart is
explicit that this backend supports neither workload identity nor STS, because
the point of the backend is that MinIO and R2 work identically. The key belongs
to a service account whose only permission is `objectAdmin` on that one bucket,
and archives age out after 14 days — they are a cache for the sandbox init
container, not a record of anything.

## 7. Identity

Two tiers exist in the codebase and they are **mutually exclusive**:

- `FLUIDBOX_WEB_AUTH=workos` — a web-tier gate on `/app`.
- `FLUIDBOX_WEB_MODE=sso` — the proxy forwards the fluidbox session cookie.

This deployment uses **`sso` + `WEB_AUTH=none`**, with **Auth0 as each org's
OIDC issuer** inside the Rust control plane (`FLUIDBOX_REQUIRE_SSO=1`). That is
the multi-tenant posture: the admin token is confined to `/v1/admin/*`
(break-glass), and browsers authenticate per-org.

Registration is automated by `scripts/cloud/auth0-idp-setup.sh`, which re-checks
Auth0 against the control plane's own conformance floor before registering.
Auth0 emits a real `email_verified` boolean and advertises PKCE `S256`, so no
claim overrides are needed.

### The consequence that is easy to miss

`FLUIDBOX_REQUIRE_SSO=1` combined with the default `FLUIDBOX_LLM_KEY_MODE=shared`
makes the LLM facade answer **`503 tenant_llm_keys_required` on every model
call**. Multi-user mode therefore *requires* `keyMode: tenant`, which requires
LiteLLM backed by its own Postgres, which requires the `litellm-database` image
variant. All three are wired, and the chart now **refuses to render** any
combination that is missing one — a control plane where no run can reach a model
is not a degraded deployment, it is a non-functional one.

## 8. Capacity and cost (lean tier)

| line | configuration | est. USD/month |
|---|---|---|
| GKE management | 1 zonal cluster | **$0** — the free tier's $74.40 credit cancels it |
| System pool | 1 × `e2-standard-4`, on-demand, us-central1 | ~$98 |
| Sandbox pool | 0 × `e2-standard-4` Spot at idle | **$0** idle; ~$30/mo per node if run continuously |
| Cloud SQL | `db-g1-small`, zonal, 20 GB SSD, PITR | ~$27 + ~$3 storage |
| Cloud NAT | 1 gateway + 1 static IP | ~$32 + egress |
| Load balancer | 1 global forwarding rule + static IP | ~$18 + egress |
| Artifact Registry | a few GB | ~$1 |
| Logging / monitoring | first 50 GiB free | ~$0–5 |
| GCS archives | 14-day retention | <$1 |
| **Idle baseline** | | **≈ $180–190/month** |

Burst: each busy sandbox node adds roughly **$0.04/hour** (Spot
`e2-standard-4`), so an hour of three-node saturation is about $0.12.

Not included: Anthropic model spend (metered per run by the facade and capped
per tenant at `$25 / 30d` by `llm.tenant.maxBudget`), and Vercel.

**Scaling limits as configured:** 3 system nodes, 3 sandbox nodes, 12 sandbox
pods (`ResourceQuota`), 100 database connections. The quota is the binding limit
on concurrent runs.

## 9. Availability, honestly

| failure | outcome |
|---|---|
| One control-plane pod dies | The other serves. RollingUpdate + PDB keep this true through deploys. |
| The single system node dies | **Control plane down** until the autoscaler replaces it (minutes). Both replicas were on that node. Raise `system_min_nodes` to 2 to remove this. |
| A node *upgrade* | No downtime — `max_surge=1, max_unavailable=0` adds a node first. |
| A zone outage | **Everything down.** Zonal cluster, zonal Cloud SQL. This is the deliberate lean-tier trade. |
| A Spot preemption | The affected run fails and is re-driven. The control plane is unaffected (different pool). |
| Cloud SQL failover | `ZONAL` has none; recovery is restore-from-backup. `REGIONAL` adds automatic failover for roughly double the cost. |

## 10. Governed sandbox egress {#network-grants}

**Enabled.** `networkGrants.enabled: true` with `enforcer: cilium`, and the
server's boot log resolves it rather than refusing:

    {"msg":"sandbox network grants: enforcer resolved","enforcer":"cilium","requested":"cilium"}

Getting here required a CLUSTER REBUILD, and the reason is worth stating
precisely because it is easy to get wrong. The blocker was narrower than "GKE
has no Cilium policy", and the narrowness is the whole point:

* GKE Dataplane V2 DOES expose `CiliumClusterwideNetworkPolicy`, behind
  `--enable-cilium-clusterwide-network-policy` (GKE >= 1.28.6-gke.1095000). The
  chart's deny-wall baseline CCNP applied fine under DPv2.
* **Fluidbox's per-run enforcer writes NAMESPACED `CiliumNetworkPolicy`**
  (`crates/fluidbox-provider-k8s/src/enforcer.rs`, `cnp_resource()`) — one per
  run, in the sandbox namespace. GKE ships **no namespaced variant** and offers
  no flag for one.

So under DPv2 the cluster-wide deny wall was expressible and the per-run grants
were not. `FLUIDBOX_NETWORK_ENFORCER=cilium` refused to boot — *"this cluster
does not serve cilium.io/v2"* — and agents declaring `approved` or `public` were
refused at create time with `422 this deployment cannot enforce network grants`.
Both refusals were correct: fail-closed beats accepting a grant you cannot
enforce.

The fix is `cilium_mode = "upstream"` — legacy datapath plus self-managed
upstream Cilium, installed by the app stack, which serves BOTH policy CRDs. It
was validated on a throwaway probe cluster before the real one was touched (a
namespaced CNP carrying `toFQDNs` was accepted `Valid: True`), then applied.
`datapath_provider` is immutable, so adopting it destroyed and recreated the
cluster.

Verify on any cluster rather than assuming either way:

    kubectl get crd ciliumnetworkpolicies.cilium.io            # per-run grants
    kubectl get crd ciliumclusterwidenetworkpolicies.cilium.io # deny wall

**What it costs.** GKE no longer manages the CNI. Node upgrades and reboots can
undo Cilium's node configuration; the startup taint on the node pools is what
makes that survivable, holding pods off a node until Cilium has re-prepared it.
Cilium version upgrades become an operator task.

**The startup taint and the autoscaler — a coupling that bit on day one.**
Every node is born tainted
`ignore-taint.cluster-autoscaler.kubernetes.io/cilium-agent-not-ready=true:NoExecute`,
and Cilium's operator removes exactly that key once the node is prepared
(`agentNotReadyTaintKey`, fed from the platform output — never retyped). The
prefix is the load-bearing part. The cluster autoscaler decides a scale-up by
SIMULATING the pending pod against the pool's node template, taints included,
and sandbox pods must not tolerate the not-ready taint (tolerating it is the
unmanaged-pod hole it exists to close). Under Cilium's plain default key,
`node.cilium.io/agent-not-ready`, the simulation therefore always answered
"does not fit" and the scale-to-zero sandbox pool could never leave zero: the
netpol probe sat Pending with `NotTriggerScaleUp: 1 node(s) had untolerated
taint(s)`, the gate reported `Unschedulable`, and the dashboard answered
`503 sandbox network isolation is not yet verified on this cluster`. Real runs
carry the same placement and would have hung identically. The
`ignore-taint.cluster-autoscaler.kubernetes.io/` prefix marks a taint as
startup-only — ignored in that simulation, honoured by everything else — and is
the key Cilium's own documentation prescribes for the purpose. Measured on this
cluster, on the pipeline apply that shipped the fix (2026-08-26): autoscaler
`TriggeredScaleUp` on the probe pod at 01:23:25Z → node born at 01:23:56Z
(31 s) → taint lifted by the operator ≈47 s later → probe scheduled, image
pulled in 0.8 s, and the gate logged *verified* at 01:24:55Z — **90 s from
decision to admitted runs**, against a 240 s probe deadline and a 300 s run-pod
grace. The seven probes before the fix had all ended `NotTriggerScaleUp`.

If the two stacks ever disagree on the key, a NEW node stays tainted NoExecute
forever and the only symptom is that same `Unschedulable`; see the runbook's
triage entry. Changing the key is therefore an ORDERED migration: Cilium learns
the new key first (app stack), the pool templates follow (platform stack), and
any node born in between must be checked. That window is not theoretical — on
2026-08-26 it caught a node. The Cilium upgrade itself rolls `cilium-operator`,
whose two replicas carry a required anti-affinity, so on the two-node system
pool the surge pod cannot co-locate and the autoscaler adds a THIRD node for
the rollout (then scales it away ~10 min later). That surge node was born with
the old key after the operator had stopped lifting it, and had to be untainted
by hand once its Cilium agent was ready. Expect the surge on every Cilium
upgrade; it is bounded and harmless once both stacks agree.

The order is not a preference. GKE applies a node-pool taint change to the
pool's EXISTING nodes immediately, and `NoExecute` means the taint manager
evicts every pod without a toleration: the apply that shipped this fix evicted
**27 pods** across `kube-system`, `external-secrets` and `fluidbox` in eight
seconds. Because the operator was already lifting the new key, it cleared the
taints within seconds and everything rescheduled — a ~30 s control-plane blip
the pipeline's smoke stage never saw. Had the pools been changed FIRST, the same
apply would have tainted every system node with a key nothing lifts and evicted
the entire control plane with nowhere to go. Cilium first is the difference
between a blip and an outage.

**The committed default must keep naming reality.** `cilium_mode` defaults to
`upstream` in BOTH stacks, and that is load-bearing rather than tidy: a default
naming the other mode makes the next `terraform plan` a cluster REPLACEMENT
(platform — `datapath_provider` is ForceNew) or a CNI UNINSTALL (app —
`helm_release.cilium` count drops to 0).

Standard `NetworkPolicy` is unaffected and independent: it is what enforces
baseline sandbox containment, and the boot probe proves it at runtime.

(This document has been wrong twice here. It first claimed the feature was
"available now that the CNI is Cilium" — inferred from "DPv2 is Cilium" without
checking CRDs. It was then corrected to "GKE withholds Cilium policy", which is
also wrong: GKE offers the clusterwide CRD behind a flag. The actual blocker was
the NAMESPACED CRD — established by reading the enforcer and confirming against
the live cluster, 2026-08-25 — and the rebuild removed it.)

## 11. What is deliberately NOT enabled

- **`server.maxConcurrentRuns`** (the run queue). Setting it switches the
  Deployment to `strategy: Recreate`, because the cap is a per-pod environment
  variable and a RollingUpdate would briefly run two generations with two
  different "deployment-wide" caps. That is a visible outage on every deploy.
  The sandbox `ResourceQuota` remains the capacity backstop.
- **gVisor** on the sandbox pool. `values/gke.yaml` documents the
  `runtimeClassName: gvisor` switch; it needs a GKE Sandbox node pool and
  carries syscall-compatibility risk with the Node-based runner images.
- **`FLUIDBOX_TRUST_FORWARDED_FOR`.** The Ingress is publicly reachable, so an
  `X-Forwarded-For` header can be forged by anyone addressing it directly rather
  than going through Vercel. Trusting it would let an attacker choose the
  identity that per-IP limiting and audit rows record. The cost of leaving it
  off is that client IPs read as the load balancer's.
