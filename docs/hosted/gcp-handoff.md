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
GKE Standard, zonal, Dataplane V2, private nodes, `GKE_METADATA`, Shielded,
image streaming, etcd CMEK; node pools `system` (1→3 × e2-standard-4, on-demand,
`max_surge=1 max_unavailable=0`) and `sandbox` (0→3 × e2-standard-4, **Spot**,
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

Idle baseline **≈ $180–190/month**. Lines and the reasoning are in
[`gcp-architecture.md` §8](./gcp-architecture.md). Two things dominate and both
are deliberate: one always-on `e2-standard-4` (~$98) and Cloud NAT (~$32). The
GKE management fee is **$0** because a single zonal cluster is exactly cancelled
by the free tier's $74.40 credit.

The sandbox pool costs nothing while idle. Burst is about **$0.04/hour** per
Spot node.

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
6. **The run queue is off.** Enabling `server.maxConcurrentRuns` switches the
   Deployment to `Recreate`; the sandbox `ResourceQuota` (12 pods) is the
   capacity backstop meanwhile.
7. **`FLUIDBOX_TRUST_FORWARDED_FOR` is off**, so audit rows record the load
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
