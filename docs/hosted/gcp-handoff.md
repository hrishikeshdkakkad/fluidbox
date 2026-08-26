# Fluidbox on GCP — operational handoff

Deployed 2026-08-25. Companion documents:
[`gcp-architecture.md`](./gcp-architecture.md) (why it is shaped this way, cost
model) and [`gcp-operations.md`](./gcp-operations.md) (day-two procedures).

## 1. What exists

| Surface | Address | Owner |
|---|---|---|
| Dashboard | `https://platform.fluidzero.ai` | Vercel project `fluidbox-cloud-dashboard` |
| Control plane | `https://api.platform.fluidzero.ai` | GKE `fluidbox`, zone `us-central1-c` |
| Identity | `https://hrishi-test.jp.auth0.com/` | Auth0, org `fluidzero` |
| DNS | `fluidzero.ai` zone `Z07281081TZJJI83JZY1W` | AWS Route 53, account `471112572248` |
| Everything else | project `fluidbox-506603` (number `744811671760`) | GCP |

Fixed addresses worth recording: GCLB **`34.117.119.9`** (the Route 53 A record),
Cloud NAT egress **`34.133.73.223`** (give this to upstreams that allowlist by
IP), Cloud SQL private IP **`10.30.0.3`**.

## 2. Resources

Everything below is Terraform in `deploy/cloud/gcp/` except where noted.

**bootstrap** — remote state bucket `fluidbox-506603-tfstate` (versioned,
uniform access, public-access-prevented), the Workload Identity Federation pool
`github`, two CI service accounts, a $300/month billing budget with alerts at
50/90/100% actual and 100% forecast.

**platform** — VPC `fluidbox` (nodes `10.10.0.0/20`, pods `10.20.0.0/14`,
services `10.24.0.0/20`, Cloud SQL peering `10.30.0.0/16`); Cloud Router + NAT;
GKE Standard, zonal, legacy datapath + self-managed upstream Cilium
(`cilium_mode`), private nodes, `GKE_METADATA`, Shielded,
image streaming, etcd CMEK; node pools `system` (1→3 × e2-standard-4, on-demand,
`max_surge=1 max_unavailable=0`) and `sandbox` (1→3 × e2-standard-4, **on-demand**,
tainted); Cloud SQL Postgres 16 private-IP with PITR and two databases
(`fluidbox`, `litellm`); Artifact Registry `fluidbox` with immutable tags; Cloud
KMS keyring with `gke-etcd` and `secrets`; eight Secret Manager secrets under
CMEK; uptime check, a log-based metric for boot refusals, and four alert
policies.

**app** — two PriorityClasses, the External Secrets operator, the release
namespace (Pod Security `restricted`).

**Helm** — release `fluidbox` in namespace `fluidbox`, from
`deploy/helm/fluidbox` with `values/gke.yaml` +
`deploy/cloud/gcp/values/production.yaml`.

## 3. Cost

Idle baseline **≈ $280–290/month**. Lines and the reasoning are in
[`gcp-architecture.md` §8](./gcp-architecture.md). Two things dominate and both
are deliberate: one always-on system `e2-standard-4` (~$98), one always-on
on-demand sandbox `e2-standard-4` (~$98, chosen 2026-08-26 over scale-to-zero
so a run never waits for a node) and Cloud NAT (~$32). The
GKE management fee is **$0** because a single zonal cluster is exactly cancelled
by the free tier's $74.40 credit.

The sandbox pool keeps one on-demand node; each extra node is about **$0.134/hour** while
it runs.

Not included: Anthropic model spend (metered per run, capped per tenant at
`$25 / 30d` by `llm.tenant.maxBudget`) and Vercel.

## 4. Secrets — who holds what

| Secret | Origin | If lost |
|---|---|---|
| `fluidbox-database-url` | Terraform | Regenerate from the SQL password |
| `fluidbox-admin-token` | Terraform | Rotate; it is break-glass only |
| `fluidbox-credential-key` | Terraform | **Orphans stored integration credentials** |
| `fluidbox-kms-static-kek` | Terraform | **UNRECOVERABLE** once any v2 sealed row exists |
| `litellm-master-key`, `litellm-database-url` | Terraform | Rotate |
| `anthropic-api-key` | out-of-band | Re-add from Anthropic |
| `openai-api-key` | out-of-band via `gcp-secrets.sh` | Re-add from OpenAI; optional — the gateway runs without it |
| `auth0-client-secret` | out-of-band backup | Re-read from Auth0 |

All are CMEK-encrypted under `projects/fluidbox-506603/locations/us-central1/keyRings/fluidbox/cryptoKeys/secrets`
and carry `prevent_destroy` + `ignore_changes = [secret_data]`, so a re-apply
cannot rotate them by accident.

**Nothing reaches the cluster through Helm values or a CI log.** External
Secrets syncs Secret Manager into the `fluidbox-secrets` Kubernetes Secret,
which is what the chart's `existingSecret` reads.

There is **no long-lived cloud credential** in CI: GitHub's OIDC token is
exchanged through Workload Identity Federation. The only stored secrets are
Vercel's (`VERCEL_TOKEN`, a dedicated `fluidbox-gha-deploy` token — not a
personal one) and the browser-test drill account.

## 5. Operating it

Push to `main`; `.github/workflows/deploy.yml` does the rest. Gates that stop
promotion: a plan containing any destroy/replace, the pre-upgrade migration Job,
`--atomic`, smoke, isolation and browser tests, with `helm rollback` on failure.

Rollback: `helm rollback fluidbox <REVISION> -n fluidbox`, or run the workflow
manually with `rollback_to`. **A rollback reverts the application, never the
schema** — migrations are forward-only.

Triage lives in [`gcp-operations.md`](./gcp-operations.md); start with the
`REFUSING TO BOOT` table, because fluidbox fails closed on misconfiguration and
the refusal line names the exact gate.

## 6. Dashboards and alerts

Alert policies (Cloud Monitoring), all notifying `hrishikeshkakkad@fluidzero.ai`:

| Policy | Fires on |
|---|---|
| control plane unreachable | the uptime check failing from multiple regions |
| **REFUSED TO BOOT** | the `fluidbox/boot_refusal` log metric — the highest-signal line the process emits |
| container restarting repeatedly | >3 restarts in 15 minutes |
| Cloud SQL disk > 85% | growth faster than expected |
| Cloud SQL connections near max | the pool ceiling approaching (shows up as app-side acquire timeouts, not DB errors) |

Managed Prometheus is enabled on the cluster; the control plane also exposes its
own registry at admin-gated `GET /v1/admin/metrics`.

## 7. Risks and open items

**Accepted, with reasons:**

1. **Single control-plane replica, `Recreate` upgrades.** The multi-replica path
   needs `archiveStore: "s3"`, which needs a static HMAC key, which
   `constraints/iam.disableServiceAccountKeyCreation` refuses on this project.
   That policy exists to stop long-lived static credentials, so the node-local
   PVC — which needs no credential at all — is the right answer. To change it:
   lift the constraint, set `enable_gcs_archive_store=true`, restore
   `archiveStore: "s3"` and `replicas: 2`.
2. **Zonal cluster and zonal Cloud SQL.** A zone outage takes the platform down.
   Regional is a variable change plus roughly double the cost.
3. **KEK plaintext is in the control-plane pod's environment.** Core ships no
   native GCP KMS backend, so `static` is the only mode giving v2 envelope
   sealing. Custody still roots on Cloud KMS + IAM + audit logs. The follow-up
   is a `gcp` `KeyWrapper` beside `AwsKms` in `kms.rs`.
4. **The GKE control-plane endpoint is public**, protected by IAM and TLS client
   certs, because GitHub Actions egress addresses are too broad to allowlist.
   Set `master_authorized_cidrs` once a stable egress address exists; Connect
   Gateway removes the public endpoint entirely.
5. **Auth0 is the `hrishi-test` tenant, JP region.** Standards-conformant and
   working, but dev-named. Moving to a production tenant is a dashboard action
   plus a re-run of `scripts/cloud/gcp-auth0.sh`.
6. **The CNI is self-managed, which is the price of governed egress.**
   Network grants ARE enabled (`enforcer: cilium`, resolved at boot). Reaching
   that took a cluster rebuild onto legacy datapath plus upstream Cilium,
   because GKE Dataplane V2 serves no NAMESPACED `CiliumNetworkPolicy` and the
   per-run enforcer writes exactly that. The standing cost: GKE no longer
   patches the CNI, node upgrades can undo its node configuration (the
   startup taint is what makes that survivable), and Cilium upgrades are an
   operator task. `cilium_mode` must keep defaulting to `upstream` in both
   stacks — a default naming the other mode plans a cluster replacement or a
   CNI uninstall. The startup taint's key is declared once (platform output
   `cilium_agent_not_ready_taint_key`) and MUST carry the
   `ignore-taint.cluster-autoscaler.kubernetes.io/` prefix: without it the
   autoscaler's scale-up simulation never fits a sandbox pod and the
   scale-to-zero pool is stuck at zero (the day-one 503). Fixed and proven
   2026-08-26: `TriggeredScaleUp` 0→1, gate verified 90 s after the decision.
   See gcp-architecture.md#network-grants.
7. **The run queue is off.** Enabling `server.maxConcurrentRuns` switches the
   Deployment to `Recreate`; the sandbox `ResourceQuota` (12 pods) is the
   capacity backstop meanwhile.
9. **The codex harness is unavailable until an OpenAI key is added.** The
   gateway has a `gpt-5*` route but nothing behind it, and the tenant allowlist
   is Claude-only. The catalog now reports codex `available: false` (hidden in
   the dashboard) and agent writes 422 instead of runs failing with a 403 at
   the first model call. Enabling it is one command,
   `scripts/cloud/gcp-secrets.sh --from-env-file .env` (or `OPENAI_API_KEY=…`):
   the values already opt in, the key is optional to the gateway, and tenant
   keys re-mint themselves under the widened allowlist.
8. **`FLUIDBOX_TRUST_FORWARDED_FOR` is off**, so audit rows record the load
   balancer's address rather than the client's. Trusting it on a publicly
   reachable Ingress would let an attacker choose the identity that per-IP
   limiting records.

**Needs attention:**

- The gcloud CLI credential for `hrishikeshkakkad@fluidzero.ai` is a stale,
  mislabeled entry that resolves to a different Google account, and
  `gcloud auth login` does not replace it. The ADC credential written by the
  same login IS correct, so tooling is driven from
  `gcloud auth application-default print-access-token`. Fixing the CLI store
  properly is an outstanding chore.
- `docs/reviews/2026-08-25-cloud-m1-auth0-idp/` holds the IdP registration
  evidence.

## 8. Verification record — 2026-08-25

Every line below is a runtime observation, not a configuration reading.

**Commit-to-production**
`https://github.com/hrishikeshdkakkad/fluidbox/actions/runs/32825697429` —
commit `fcbd6277`, result **success**. Jobs: `changes → verify → images →
deploy → smoke → browser` all green, with `plan`/`apply` correctly skipped (no
infrastructure change in that commit) and `rollback` skipped (nothing failed).
The pipeline resolved `fluidbox-server -> sha256:9564f2fe…` and the running
Deployment carries exactly that digest.

**Rollback**
`.../actions/runs/32826332436` with `rollback_to=12` — `rollback: success`,
every other job short-circuited, Helm revision 14 recorded "Rollback to 12", and
the running image provably changed from `sha256:9564f2fe…` to
`sha256:ae463e3c…`. Rolled forward again through the normal path
(`.../actions/runs/32826598466`, green end to end).

**Migration gate** — the pre-upgrade Job completed rather than hanging, ending:

> `FLUIDBOX_MIGRATE_ONLY=1: migrations applied and RLS posture verified — exiting 0 without serving`

with **zero** `listening` lines, having first reported `rls=enforced` under
`runtime_role=fluidbox_runtime`.

**Suites** — smoke **23 passed / 0 failed / 1 skipped** (the skip is correct: a
PodDisruptionBudget is only rendered above one replica); isolation and governed
egress **11 / 0 / 0**; browser journeys **12 / 12**.

**Security properties proven at runtime, not asserted:**

| Property | Evidence |
|---|---|
| RLS is enforced, not inert | boot log `"rls":"enforced"` under `runtime_role=fluidbox_runtime` |
| CNI actually drops traffic | boot probe `"worker":"netpol_gate"`, `+:8788 -:8787` |
| Sandboxes cannot reach the internet | a live sandbox-labelled pod returned `BLOCKED` |
| The sandbox namespace refuses weak pods | an unhardened pod was rejected by Pod Security |
| Admin token confined under REQUIRE_SSO | `401` on `/v1/sessions`, `200` on `/v1/admin/orgs` |
| Per-org data is scoped | a fresh org sees 0 IdP configs; `fluidzero` sees 2 |
| SSE survives the edge | backend `TIMEOUT_SEC 3600` vs the default backend's `30` |
| TLS is real | `CN=api.platform.fluidzero.ai`, valid to 2026-11-23 |
| Auth0 login works | a real browser completed the round trip and received a `__Host-fbx_web` cookie with Secure/HttpOnly/Path=/ |
| Logout works | `204`, cookie removed, and the server then REDIRECTS `/app` |
| Autoscaling from zero | the sandbox pool scaled 0→1 to schedule the egress probe |

**Deployed addresses:** `https://platform.fluidzero.ai` (Vercel) and
`https://api.platform.fluidzero.ai` (GKE, `34.117.119.9`) both answer `200`,
and the dashboard origin proxies `/v1/health` — the rewrite that makes
`__Host-` cookies possible.
