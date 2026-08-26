# Fluidbox on GCP — deployment kit

Terraform + Helm values that run the fluidbox control plane on **GKE** in
project **`fluidbox-506603`**, with the Next.js dashboard on **Vercel** and DNS
in **Route 53**.

Architecture, cost model and the decisions behind them:
[`docs/hosted/gcp-architecture.md`](../../../docs/hosted/gcp-architecture.md).
Day-two procedures: [`docs/hosted/gcp-operations.md`](../../../docs/hosted/gcp-operations.md).

## Stacks (apply order)

| # | stack | identity | what it owns |
|---|-------|----------|--------------|
| 0 | `bootstrap` | project **Owner**, once | API enablement, the remote-state bucket, the Workload Identity Federation pool, the two CI service accounts, the billing budget |
| 1 | `platform` | `fbx-deployer` | VPC + Cloud NAT, GKE (zonal, legacy datapath — see `cilium_mode`), node pools, Cloud SQL, Artifact Registry, Cloud KMS, Secret Manager, the archive bucket, observability |
| 2 | `app` | `fbx-deployer` | self-managed Cilium (`cilium_mode = upstream`), PriorityClasses, the External Secrets operator, the release namespace |
| 3 | the chart | `fbx-deployer` | `helm upgrade --install` — **not** Terraform (see below) |

`bootstrap` is the only stack that runs as Owner, because enabling an API grants
a whole product surface. Everything after it runs as a service account whose
roles are enumerated in `bootstrap/iam.tf`.

### Why the Helm release is not a `helm_release` resource

The goal is a working `helm rollback`. Wrapping the release in Terraform
replaces a one-command, revision-numbered rollback with a state-file edit, and
`helm history` stops being the record of what shipped. Terraform therefore owns
everything *around* the release; the release itself is driven by
`.github/workflows/deploy.yml`.

## First run (the documented CLI bootstrap)

Only step 0 needs a human. Everything after it runs from CI.

```
gcloud auth login hrishikeshkakkad@fluidzero.ai --update-adc
gcloud config set project fluidbox-506603

cd deploy/cloud/gcp/bootstrap
```

**0a. First apply with a LOCAL backend** — it cannot store state in a bucket it
has not created yet:

```
terraform init -backend=false
terraform apply \
  -var 'billing_account=XXXXXX-XXXXXX-XXXXXX' \
  -var 'budget_alert_emails=["you@example.com"]'
```

**0b. Migrate that state into the bucket it just made, then securely erase the
local copy.** State carries generated secrets; it does not stay on a laptop.

```
terraform init -migrate-state \
  -backend-config="bucket=fluidbox-506603-tfstate" \
  -backend-config="prefix=bootstrap"
```

Then delete `terraform.tfstate` and `terraform.tfstate.backup` from this
directory — with `shred -u` on Linux, or `rm -P` on macOS. Both files are
already gitignored (`deploy/cloud/terraform/**` patterns cover the tree), but
gitignored is not the same as gone.

**0c. Publish the CI wiring.** These are repository *variables*, not secrets:
Workload Identity Federation means there is no key to store.

```
terraform output -raw github_actions_variables
```

| variable | value |
|----------|-------|
| `GCP_PROJECT_ID` | `fluidbox-506603` |
| `GCP_REGION` | `us-central1` |
| `GKE_CLUSTER` | `fluidbox` |
| `GKE_LOCATION` | `us-central1-c` (the **zone** — this is a zonal cluster) |
| `CONTROL_PLANE_HOST` | `api.platform.fluidzero.ai` |
| `DASHBOARD_HOST` | `platform.fluidzero.ai` |
| `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_DEPLOYER_SA`, `GCP_PLANNER_SA`, `GCP_TF_STATE_BUCKET` | from the output above |

Repository **secrets** (only Vercel needs any): `VERCEL_TOKEN`,
`VERCEL_ORG_ID`, `VERCEL_PROJECT_ID`.

Create a GitHub Environment named **`production`** with required reviewers. The
deployer service account is reachable ONLY through it — the Workload Identity
binding in `bootstrap/iam.tf` matches on `attribute.environment`, so the
environment's protection rules sit *in the impersonation path* rather than
beside it.

### Then, once:

```
# 1. Platform.
cd ../platform
terraform init \
  -backend-config="bucket=fluidbox-506603-tfstate" -backend-config="prefix=platform"
terraform apply

# 2. The secrets Terraform must never see. Everything else is generated into
#    Secret Manager by the platform stack; these come from the model providers.
printf '%s' "$ANTHROPIC_API_KEY" \
  | gcloud secrets versions add anthropic-api-key --data-file=- --project fluidbox-506603
#    OpenAI is OPTIONAL - only the codex harness needs it. Add the version, then
#    opt in (values/production.yaml: litellm.openaiKeySecretKey, the
#    externalSecrets OPENAI_API_KEY entry, and the GPT models in
#    llm.tenant.models) and rotate tenant keys:
#      POST /v1/admin/orgs/{slug}/llm-key/rotate
#    Until then the harness catalog reports codex unavailable and the dashboard
#    hides it - a deployment never offers a model its gateway will refuse.
printf '%s' "$OPENAI_API_KEY" \
  | gcloud secrets versions add openai-api-key --data-file=- --project fluidbox-506603

# 3. Cluster prerequisites.
cd ../app
terraform init \
  -backend-config="bucket=fluidbox-506603-tfstate" -backend-config="prefix=app"
terraform apply \
  -var "external_secrets_sa=$(terraform -chdir=../platform output -raw external_secrets_service_account)" \
  -var "cilium_agent_not_ready_taint_key=$(terraform -chdir=../platform output -raw cilium_agent_not_ready_taint_key)"

# 4. DNS: point the control-plane host at the reserved GCLB address (Route 53).
scripts/cloud/gcp-dns.sh

# 5. First release. Every later one is automatic on push to main.
helm upgrade --install fluidbox deploy/helm/fluidbox -n fluidbox --create-namespace \
  -f deploy/helm/fluidbox/values/gke.yaml \
  -f deploy/cloud/gcp/values/production.yaml \
  --atomic --wait --timeout 20m
```

## Secrets: who holds what

Terraform **generates** the database URL, admin token, credential key, KMS KEK,
LiteLLM master key and the archive HMAC key straight into Secret Manager
(CMEK-encrypted with a Cloud KMS key). They land in Terraform state, which is
why state lives in a private, versioned, uniform-access bucket and never on a
laptop or in git.

Terraform only creates the **container** for the two external secrets
(`anthropic-api-key`, `auth0-client-secret`); their values are added
out-of-band. A value Terraform never sees is a value its state cannot leak.

Nothing reaches the cluster through Helm values. The External Secrets operator
syncs Secret Manager into the `fluidbox-secrets` Kubernetes Secret, which is
what the chart's `existingSecret` reads. **No credential passes through a CI
log.**

Every secret carries `prevent_destroy` **and** `ignore_changes = [secret_data]`.
Losing the credential key orphans stored integration credentials; losing the KEK
is unrecoverable once any v2 sealed row exists. A routine re-apply must never
rotate either — rotation is a deliberate procedure
([`docs/hosted/kms-operations.md`](../../../docs/hosted/kms-operations.md)).

## The values-merge trap

Helm deep-merges **maps** across `-f` files but **replaces lists**. In a later
values file, `sandbox: { tolerations: [] }` works; `sandbox: { nodeSelector: {} }`
**silently does nothing** and the earlier keys survive. Use
`--set sandbox.nodeSelector=null`.

This is not academic — it bit the EKS kit, where a surviving nodeSelector made
every sandbox pod unschedulable and surfaced minutes later as an inscrutable
`Pending`.

## Why there are no `just` recipes here

`justfile` sets `dotenv-load := true`, so **every** `just` recipe injects the
local `.env` — which carries a dev `DATABASE_URL` and a model key. A
`just gcp-deploy` would push laptop settings at a production apply. Cloud
commands are plain scripts with explicit environment.
