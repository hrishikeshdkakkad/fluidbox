# Fluidbox on GCP — operations runbook

Companion to [`gcp-architecture.md`](./gcp-architecture.md). Project
`fluidbox-506603`, cluster `fluidbox` in **zone** `us-central1-c`.

```
gcloud container clusters get-credentials fluidbox \
  --zone us-central1-c --project fluidbox-506603
```

> `--zone`, not `--region`. This is a **zonal** cluster; `--region` fails with a
> confusing "not found".

## Deploying

Push to `main`. `.github/workflows/deploy.yml` does the rest:

```
changes ─▶ verify ─▶ plan ─▶ apply ─▶ images ─▶ deploy ─▶ smoke ─▶ vercel
                       │                            │        │
              destroy gate                   migration    rollback
                                              gate         on failure
```

Every arrow is a hard dependency: a failed job stops promotion. Three gates
matter most:

1. **The destroy gate** (`plan`). If the Terraform plan contains any `delete`
   action — a destroy, or a replace, which for Cloud SQL or GKE means data loss
   — the job fails and prints the affected addresses. Re-run manually with
   `allow_destroy=true` only after reading the plan and taking a backup.
2. **The migration gate** (`deploy`). The chart's `pre-upgrade` hook runs the
   NEW image with `FLUIDBOX_MIGRATE_ONLY=1`: it parses the config, applies
   migrations, verifies the RLS posture, and exits. Helm waits for it, so a bad
   migration **or a bad config** fails the release before any new pod rolls.
3. **`--atomic`** (`deploy`). If any pod fails to become ready inside the
   timeout, Helm restores the previous revision automatically.

### `helm history` shows `pending-upgrade` while every pod is Ready {#pending-upgrade}

Helm 4's `watcher` wait strategy (the default whenever `--rollback-on-failure`
is set) waits for every CUSTOM RESOURCE in the release to report Ready, not
just workloads. A CR that is legitimately not Ready — the optional
ExternalSecret before its provider key has a version, a ManagedCertificate
still provisioning — holds the release in `pending-upgrade` until
`--timeout`, and then `--rollback-on-failure` reverts a healthy release. The
pipeline passes `--wait=legacy` since 2026-08-26 for exactly this reason. If
you ever see it anyway:

```
kubectl -n fluidbox get externalsecret,managedcertificate      # which one is not Ready?
kubectl -n fluidbox describe externalsecret fluidbox-optional  # its reason
```

Making the CR Ready (add the missing secret version, wait out certificate
provisioning) completes the upgrade immediately — rev 8 flipped to `deployed`
within seconds of the OpenAI key landing.

### A push run that ends `cancelled` with no failed job {#cancelled-run}

`main` was not deployed, and nothing failed. GitHub keeps at most ONE pending
run per concurrency group and cancels the older pending run when a newer one
arrives — `cancel-in-progress` only governs runs already executing. Until
2026-08-26 every event of `deploy.yml`, pull-request plans included, shared the
`deploy-production` group, so a PR event landing while the push run was still
queued (release-please opens its own PR on every releasable merge) evicted the
production deploy of that very merge. Run 32920435324 died that way.

Plans now queue under `deploy-plan-pr-<n>` and only pushes to `main` share
`deploy-production`. If a push run still shows `cancelled`:

```
gh run view <run-id> --json jobs --jq '.jobs[] | "\(.conclusion) \(.name)"'   # all skipped/cancelled, none failed?
gh run rerun <run-id>                                                          # re-queue that exact commit
```

A rerun deploys the same SHA with the same digest-pinned images — it is not a
new release, just the one that was owed.

### Manual deploy

```
helm upgrade --install fluidbox deploy/helm/fluidbox -n fluidbox \
  -f deploy/helm/fluidbox/values/gke.yaml \
  -f deploy/cloud/gcp/values/production.yaml \
  --set images.server.digest=sha256:... \
  --atomic --wait --wait-for-jobs --timeout 20m
```

Always pin a **digest**, never a tag. Artifact Registry has `immutable_tags`
on, but a digest is the only reference that cannot be ambiguous.

## Rollback {#rollback}

```
helm history fluidbox -n fluidbox
helm rollback fluidbox <REVISION> -n fluidbox --wait --timeout 15m
```

or run the deploy workflow manually with `rollback_to: <REVISION>`.

**A rollback reverts the APPLICATION, never the SCHEMA.** Fluidbox migrations
are forward-only; there is no down-migration path. A rollback is therefore safe
only across revisions whose binaries both accept the *current* schema. In
practice that means each migration must be backward-compatible with the
immediately previous release — additive columns, no drops in the same release
that stops writing them.

Two migrations are documented as **stop-the-old-binary-first** (0018 and 0028).
For those, a rollback is *not* safe and the procedure is forward-fix.

**Exercised against production, 2026-08-26.** The workflow path was run for
real, not reasoned about: `workflow_dispatch` with `rollback_to=2` produced
Helm revision 4 (`Rollback to 2`) and, decisively, changed the RUNNING
workload - the server Deployment moved to revision 2's image digest, the pod
came back `1/1 Running`, and `api.platform.fluidzero.ai/v1/health` answered
`200`. `images`, `apply`, `deploy`, `smoke` and `browser` all skipped, which is
the rollback path correctly bypassing the deploy path. Rolling forward by
re-running the deploy restored revision 5 on the original digest with smoke and
browser green.

Two things that run showed which are worth knowing before you need them:

* A rollback ADDS a revision rather than rewinding to one. History reads
  2, 3, 4 (`Rollback to 2`), 5 - so `rollback_to` always names the revision you
  want the CONTENT of, never the number you expect to land on.
* The deployment is single-replica with `strategy: Recreate` (see the
  `archiveStore` note), so a rollback is a brief hard interruption, not a
  drain. Budget for tens of seconds of 5xx, and do not start one during a
  window where that matters.

## Triage

### `REFUSING TO BOOT` {#refusing-to-boot}

The alert `fluidbox: control plane REFUSED TO BOOT` fires on the log-based
metric `fluidbox/boot_refusal`. Fluidbox fails closed on misconfiguration by
design, and the refusal line **names the exact gate**:

```
kubectl -n fluidbox logs -l app.kubernetes.io/component=server --tail=200 \
  | grep -A15 "REFUSING TO BOOT"
```

| refusal | cause | fix |
|---|---|---|
| `…role this pool runs as … is SUPERUSER or has BYPASSRLS` | RLS would be inert under `REQUIRE_SSO=1` | Confirm `server.runtimeRole: fluidbox_runtime` and that migration 0018 created the role |
| KEK cannot unwrap a stored DEK | `FLUIDBOX_KMS_STATIC_KEK` changed | Restore the previous KEK from Secret Manager — **do not** let it mint a new one |
| legacy/v2 sealing retirement gate | `FLUIDBOX_CREDENTIAL_KEY` dropped while v1 rows remain, or KMS off with v2 rows present | See [`kms-operations.md`](./kms-operations.md) |
| queue knob without a cap | `queueMaxDepth`/`queueMaxWaitSecs` set without `maxConcurrentRuns` | Set the cap or unset the knobs |

Because the pre-upgrade migration Job shares the server's environment, most of
these now fail **in the Job**, before any pod rolls — read the Job's log:

```
kubectl -n fluidbox logs job/fluidbox-server-migrate
```

### Runs blocked: "network isolation is not yet verified" {#netpol-unschedulable}

The dashboard answers `503 sandbox network isolation is not yet verified on
this cluster — runs are blocked until the NetworkPolicy enforcement probe
passes`. The server refuses to admit a run until a probe pod, placed exactly
like a sandbox, has PROVED the CNI drops traffic — so first read what the probe
concluded, then why:

```
kubectl -n fluidbox logs -l app.kubernetes.io/component=server --tail=2000 \
  | grep '"worker":"netpol_gate"' | tail -3
kubectl -n fluidbox-sandboxes describe pod fluidbox-netpol-probe | sed -n '/^Events/,$p'
```

| gate result | probe event | cause | fix |
|---|---|---|---|
| `Unschedulable` | `NotTriggerScaleUp: … untolerated taint(s)` | The sandbox pool is at zero and the autoscaler's scale-up simulation refuses the pod because the pool template carries a taint it does not tolerate. On this cluster that is the Cilium startup taint, whose key **must** sit under `ignore-taint.cluster-autoscaler.kubernetes.io/` (the autoscaler ignores that prefix in the simulation). Check `gcloud container node-pools describe sandbox --format='value(config.taints[].key)'`. | Restore the prefix in `platform/gke.tf` (`local.cilium_agent_not_ready_taint_key`) and re-apply — **never** "fix" it by giving sandbox pods a toleration for the not-ready taint; that reopens the unmanaged-pod hole the taint closes. |
| `Unschedulable` | pod Pending on a node that keeps the not-ready taint | The node was born with a taint key Cilium's operator is not configured to remove: the platform and app stacks disagree on `cilium_agent_not_ready_taint_key`. `kubectl -n kube-system get cm cilium-config -o jsonpath='{.data.agent-not-ready-taint-key}'` vs the pool template. | Re-apply the app stack with the key from `terraform -chdir=platform output -raw cilium_agent_not_ready_taint_key`; the operator lifts the taint from stuck nodes on its next pass. |
| `Unschedulable` | `TriggeredScaleUp`, pod still Pending | Cold start from zero is legitimately in progress. Measured: autoscaler decision → node **31–107 s** (Spot varies), Cilium prepares the node and lifts the taint ≈50 s, gate verified ≈90 s after the node. The gate's deadline is 360 s (`PROBE_SCHEDULING_SLACK_SECS` was sized to a warm node until 2026-08-26) and it retries 30 s after a miss. | Wait one cycle. Persisting past ~8 min is one of the rows above. |
| `NotEnforced` | probe `Failed`, exit 3 | The CNI is not dropping traffic. | Runs stay blocked by design; check Cilium agent health on the sandbox node. |

#### Changing the startup taint key (or upgrading Cilium) {#cilium-taint-migration}

Order matters, for two reasons. The operator lifts exactly ONE key, so a node
born with any other stays tainted `NoExecute` forever. And GKE applies a pool
taint change to the pool's EXISTING nodes immediately — `NoExecute` evicts every
pod without a toleration on the spot (27 pods in 8 s when this fix shipped). With
Cilium already lifting the new key that is a ~30 s blip; with the pools changed
first it is the whole control plane evicted with nowhere to go.

```
# 1. Cilium first - it must be lifting the NEW key before any node is born with it.
terraform -chdir=deploy/cloud/gcp/app apply \
  -var "external_secrets_sa=$(terraform -chdir=deploy/cloud/gcp/platform output -raw external_secrets_service_account)" \
  -var "cilium_agent_not_ready_taint_key=<the new key>"
kubectl -n kube-system get cm cilium-config -o jsonpath='{.data.agent-not-ready-taint-key}'

# 2. Pool templates - merge the platform change; the pipeline applies it in-place.

# 3. Sweep for nodes born in between. A Cilium upgrade rolls cilium-operator,
#    whose anti-affinity makes the autoscaler add a surge node to the two-node
#    system pool - born with whichever key the template had at that moment.
kubectl get nodes -o custom-columns='NAME:.metadata.name,TAINTS:.spec.taints[*].key'
#    A node still carrying the OLD key with a Ready cilium agent: lift it by hand,
#    which is exactly what the operator would have done under the old config.
kubectl taint node <node> <old-key>-
```

### Run fails: "network enforcement … was not verified within 90s" {#netgrant-verify-timeout}

```
provider error: network policy enforcement could not be verified: network
enforcement for run <id> was not verified within 90s
(policy: accepted, awaiting operator validation; endpoint: no endpoint)
```

`endpoint: no endpoint` after the full window means the pod never got a node:
until 2026-08-26 the per-run verifier started its 90 s observation clock at
policy creation, and on a scale-to-zero pool the first run after idle spent
that whole window waiting for a node (measured: the run failed 19 s BEFORE its
node existed). The verifier now waits for the pod to be SCHEDULED first,
bounded by the provider's own provisioning wait (`FLUIDBOX_K8S_INIT_GRACE_SECS`,
300 s), and only then runs the 90 s window; the failure text distinguishes
"not scheduled within Ns" (read the autoscaler's event on the pod) from a
datapath that never converged.

A GKE alert reading **"Cannot schedule pods: node(s) were unschedulable"** on
a sandbox pod is the same cold start seen from the other side: the autoscaler
CORDONS an empty sandbox node about ten minutes after it idles, and a run that
arrives in the minute before the node is gone cannot use it (`1 node(s) were
unschedulable`). The autoscaler orders a new node in the same breath
(`TriggeredScaleUp` on the pod); the run simply waits ~2 minutes for it. It
was fatal only under the old 90 s clock.

A run that fails AT provisioning now lands `failed` immediately. If one ever
sits in `finalizing` logging *"artifact collection deferred … provisioning
may be in flight"*, that is the 120 s settle window for a finalize that races
an in-flight provision — a cancel, never a driver-reported failure.

### Run fails: "key not allowed to access model" {#tenant-model-allowlist}

```
error: unexpected status 403 Forbidden: key not allowed to access model.
       This key can only access models=[...]. Tried to access <model>
```

The per-tenant LiteLLM key was minted with `llm.tenant.models` as its
allowlist and the run asked for a model outside it. Since 2026-08-26 the
catalog and agent writes are narrowed to that list, so this now only happens
for an agent created BEFORE the list was narrowed, or after the list was
widened without rotating keys.

| cause | fix |
|---|---|
| the model is genuinely not served here (e.g. any `gpt-5*` with no OpenAI key) | Change the agent's model, or enable the provider (README step 2) |
| `llm.tenant.models` was widened but keys predate it | Nothing, usually: the server reconciles every tenant key against the configured allowlist (LiteLLM's `/key/info` is the source of truth) within ten minutes of a deploy and rotates the ones that drifted. To force it now: `scripts/cloud/gcp-rotate-llm-keys.sh [slug…]` |

### CrashLoopBackOff {#crashloop}

```
kubectl -n fluidbox describe pod -l app.kubernetes.io/component=server
kubectl -n fluidbox logs -l app.kubernetes.io/component=server --previous --tail=200
```

Check the boot-refusal table first; it covers most causes. If the container
never starts at all (`CreateContainerConfigError`), the Secret is missing:

```
kubectl -n fluidbox describe externalsecret fluidbox
kubectl -n external-secrets logs -l app.kubernetes.io/name=external-secrets --tail=100
```

### Control plane unreachable {#control-plane-unreachable}

Work outward, and stop at the first layer that fails:

```
# 1. Pods
kubectl -n fluidbox get pods -l app.kubernetes.io/component=server
# 2. Endpoints — a Service with no endpoints means readiness is failing
kubectl -n fluidbox get endpoints fluidbox-server
# 3. Certificate
kubectl -n fluidbox describe managedcertificate fluidbox-server
# 4. Load balancer backends
gcloud compute backend-services list --project fluidbox-506603
# 5. DNS — ask the AUTHORITATIVE server, not a cached resolver
dig @$(dig +short NS fluidzero.ai | head -1) api.platform.fluidzero.ai A
```

`ManagedCertificate` stuck in `Provisioning` with `FailedNotVisible` means the
DNS record does not resolve to the Ingress address. Google validates by serving
the challenge from the load balancer itself, so the record must exist **first**.
Run `scripts/cloud/gcp-dns.sh`.

### Database {#database}

```
gcloud sql instances describe fluidbox-pg --project fluidbox-506603
gcloud sql operations list --instance fluidbox-pg --project fluidbox-506603 --limit 5
```

Connections near the ceiling show up as **acquire timeouts in the app**, not as
a database error. The deployment-wide figure is
`replicas × (FLUIDBOX_DB_MAX_CONNECTIONS + 2)` — the `+2` being the two
`LISTEN/NOTIFY` connections each replica holds outside the pool. Either lower
`server.dbPool.maxConnections` or raise `sql_max_connections` (which needs an
instance restart).

There is no public IP. To get a shell, use the Cloud SQL proxy from a pod inside
the VPC, or `gcloud sql connect` from a machine with Private Service Access.

### Restoring

```
gcloud sql backups list --instance fluidbox-pg --project fluidbox-506603
# Point in time (WAL, 7-day window) — restores into a NEW instance:
gcloud sql instances clone fluidbox-pg fluidbox-pg-restore \
  --point-in-time '2026-08-25T12:00:00Z' --project fluidbox-506603
```

Restore into a **new** instance, verify, then repoint `fluidbox-database-url`.
Restoring in place over a live instance is not reversible.

## Capacity

```
kubectl -n fluidbox-sandboxes get resourcequota -o yaml
kubectl get nodes -L fluidbox.dev/role
kubectl top nodes
```

The sandbox `ResourceQuota` is the binding limit on concurrent runs (12 pods).
Its three numbers are one setting expressed three ways —
`pods × sandbox.resources.requests` — so raising `pods` without raising
`requestsCpu`/`requestsMemory` silently caps you at whichever binds first.

Node pools scale automatically: system 1→3, sandbox 0→3. The sandbox pool
returning to zero when idle is what keeps the bill flat.

## Secrets

```
gcloud secrets list --project fluidbox-506603
gcloud secrets versions access latest --secret=fluidbox-admin-token --project fluidbox-506603
```

**Never rotate these casually.** Losing `fluidbox-credential-key` orphans stored
integration credentials; losing `fluidbox-kms-static-kek` is unrecoverable from
the moment any v2 sealed row exists. Terraform carries `prevent_destroy` and
`ignore_changes = [secret_data]` on both for exactly that reason — a re-apply
cannot rotate them by accident.

Adding a new version and restarting the Deployment is the rotation mechanism for
the others (External Secrets re-syncs on its `refreshInterval`, or immediately
if you delete the target Secret). For the out-of-band ones — the model-provider
keys and the IdP client secret — `scripts/cloud/gcp-secrets.sh` is the whole
procedure: it reports which have a version, adds missing ones from a dotenv /
the environment / a hidden prompt, and after a provider key changes it syncs
External Secrets and restarts the gateway. A value that DIFFERS from the
version in place is refused unless you pass `--rotate`, because a dotenv can
carry a different key than the one production runs on.

The tenant LiteLLM keys are not in that list on purpose: the server mints,
rotates (allowlist drift), and recovers them itself.

## Alerts

| policy | means | first action |
|---|---|---|
| control plane unreachable | uptime check failing from multiple regions | §"Control plane unreachable" |
| **REFUSED TO BOOT** | a fail-closed gate tripped | read the refusal line — it names the gate |
| container restarting repeatedly | crash loop | `--previous` logs |
| Cloud SQL disk > 85% | growth faster than expected | `disk_autoresize` is on; investigate what is growing |
| Cloud SQL connections near max | pool ceiling approaching | §"Database" |

## Teardown

```
helm uninstall fluidbox -n fluidbox
terraform -chdir=deploy/cloud/gcp/app destroy
# platform: BOTH deletion_protection switches must be cleared first, deliberately
terraform -chdir=deploy/cloud/gcp/platform destroy
```

The KMS key ring, the KMS keys and every Secret Manager secret carry
`prevent_destroy` and will **refuse**. That is intentional: destroying the KEK
makes every sealed row unrecoverable, and a `terraform destroy` is not the place
to make that decision. Remove them by hand, after confirming nothing sealed
under them still matters.
