# Fluidbox Cloud M1 — operator runbook

The §8 procedures from the M1 brief, written to be executed by an operator who
did not build the system. Conventions used throughout:

```bash
export AWS_PROFILE=fluidbox-deployer
CF=$(cd deploy/cloud/terraform/edge && terraform output -raw cloudfront_domain)
API="https://$CF"
ADMIN=$(aws ssm get-parameter --with-decryption --name /fluidbox/cloud/admin-token --query Parameter.Value --output text)
A="authorization: Bearer $ADMIN"
# kubectl context (created on demand by any scripts/cloud/*.sh): fluidbox-cloud
```

Under `FLUIDBOX_REQUIRE_SSO=1` (M1.2+) the admin token works ONLY on
`/v1/admin/*` — that is the entire operator onboarding surface, by design.
Run inspection/cancel (`/v1/sessions/*`) then needs an operator PAT minted
from a logged-in operator identity in the org, or the drill org's owner.

---

## 1. Provision a tenant

Follow `docs/hosted/cloud-onboarding-checklist.md` (the checklist is the
procedure; it ends with the recorded-outcome ledger row). Summary shape:

```bash
curl -fsS -X POST -H "$A" -H 'content-type: application/json' \
  -d '{"slug":"acme","display_name":"Acme, Inc."}' "$API/v1/admin/orgs"
```

## 2. Configure or rotate an OIDC application

Create (one active IdP config per org; discovery runs live at create):

```bash
curl -fsS -X POST -H "$A" -H 'content-type: application/json' -d '{
  "issuer": "<issuer-url>",
  "client_id": "<client-id>",
  "client_secret": "<secret>",
  "bootstrap_owner_email": "owner@acme.com"
}' "$API/v1/admin/orgs/acme/idp"
# then: POST $API/v1/admin/orgs/acme/idp/<id>/activate
```

- **Rotate the client secret** (same issuer/client): `PATCH
  /v1/admin/orgs/acme/idp/<id>` with `{"client_secret":"<new>"}`. Issuer and
  client_id are IMMUTABLE on a row — changing issuers is a **migration**
  (`POST …/idp/<id>/migrate`), never an edit.
- Disable / re-enable login: `POST …/idp/<id>/disable` / `…/reactivate`.
- The secret is sealed into core custody (KMS envelope). No plaintext is
  retained anywhere else — if the IdP secret is lost, rotate at the IdP and
  PATCH the new one in.

## 3. Configure or rotate model access

Model access is the per-tenant LiteLLM virtual key (minted lazily by core;
allow-listed to `claude-haiku-4-5`, $5 / rolling 30d — app-stack variables).

```bash
# rotate one tenant's virtual key (old key dies at LiteLLM in the same op):
curl -fsS -X POST -H "$A" "$API/v1/admin/orgs/acme/llm-key/rotate"
```

Upstream (deployment-wide) Anthropic key rotation: update the value in
`fluidbox-secrets` (`kubectl create secret … --dry-run=client -o yaml |
kubectl apply -f -` with the new `ANTHROPIC_API_KEY`, or re-run
`make-secrets.sh` with the new env), then restart LiteLLM:
`kubectl rollout restart deploy/litellm -n fluidbox`.

## 4. Verify the initial tenant owner

`bootstrap_owner_email` on the IdP config pre-arms the owner. If it was
omitted or the wrong address was armed, re-arm (break-glass, audited):

```bash
curl -fsS -X POST -H "$A" -H 'content-type: application/json' \
  -d '{"email":"owner@acme.com"}' "$API/v1/admin/orgs/acme/break-glass-owner"
```

Verification = the owner completes `https://<vercel-origin>/login` → org slug
→ IdP → lands on `/app`, and `GET /v1/admin/orgs/acme/members` shows the
membership active with the owner role.

## 5. Inspect a failed or stuck run

```bash
curl -fsS -H "$P" "$API/v1/sessions/<id>"            # $P = operator PAT (see header note)
curl -fsS -H "$P" "$API/v1/sessions/<id>/events?after=0&limit=500"
kubectl get pods -n fluidbox-sandboxes -o wide        # is the sandbox alive?
kubectl logs -n fluidbox <server-pod> | tail -100     # orchestrator view
kubectl describe pod -n fluidbox-sandboxes <pod>      # image pulls, netpol-gate init
```

Interpretation notes:

- A run held in `provisioning` with the netpol-gate init container running is
  the enforcement gate doing its job (VPC CNI standard mode programs policy
  asynchronously; the gate holds the untrusted runner until it observes
  enforcement).
- **Expected on a cold cluster, and it looks like a failure:** the boot-time
  enforcement probe runs in the sandbox namespace, which is pinned to a
  nodegroup that sits at ZERO. The first probe is therefore `Unschedulable`
  (then briefly `NotEnforced` while eBPF programs), the server logs that
  enforcement is not verified, and **runs are correctly blocked** meanwhile.
  Cluster Autoscaler brings up a sandbox node (~2–3 min) and a later probe
  verifies — the 2026-07-22 acceptance saw this exact sequence and it
  resolved on its own. Do not "fix" it by disabling `netpol.requireEnforced`;
  wait, then confirm with
  `kubectl logs -n fluidbox deploy/fluidbox-server | grep -i "netpol gate"`.
- `ErrImagePull` on a seeded agent means the agent revision pins an
  unpullable creation-time image — create an agent with an explicit
  `runner_image` (documented gotcha from both EKS acceptances).

## 6. Cancel an active run

```bash
curl -fsS -X POST -H "$P" "$API/v1/sessions/<id>/cancel"
```

Idempotent; the server is the single status writer. The sandbox pod is
reaped by the orchestrator (ownerRef GC covers a crashed reap). Verify:
session status `cancelled` + `fluidbox-sandboxes` empty of that run's pod.

## 7. Contain a tenant  ⚠️ INCOMPLETE BY DESIGN — READ FIRST

**This procedure is explicitly incomplete and awkward to reverse.** Core has
no suspend/reactivate lifecycle in M1 (deliberately deferred to an M3
proposal — PLAN rev 3 removed composed suspend from scope because it cannot
stop in-flight sandbox tokens and has no reactivation API). What you have is
a manual, multi-step, best-effort lockout:

```bash
# a) stop NEW authority: disable login
curl -fsS -X POST -H "$A" "$API/v1/admin/orgs/acme/idp/<id>/disable"
# b) deactivate memberships (kills PAT/session authority per member; also the
#    personal-connection kill switch):
curl -fsS -H "$A" "$API/v1/admin/orgs/acme/members"
curl -fsS -X POST -H "$A" "$API/v1/admin/orgs/acme/members/<membership_id>/deactivate"   # per member
# c) cancel each active run (operator PAT or drill-owner PAT):
#    list active sessions for the tenant, POST …/cancel each (see §6)
# d) disable trigger subscriptions / schedules the tenant owns (they fire
#    with subscription authority, not member sessions).
```

Recorded limitations (state them in any incident notes):
- Steps a–d are not atomic; a run can start between a) and c).
- In-flight sandbox session tokens keep their run alive until cancel lands.
- "Reactivation" is manual re-inversion of every step (re-enable IdP,
  re-activate every membership, re-enable subscriptions) — easy to get
  half-done. There is no single switch. That is WHY suspend/reactivate is an
  M3 core proposal, not an M1 feature.

## 8. Respond to a budget alert

`fluidbox-cloud-monthly` (tag-filtered) at 50/80/100% actual or 100%
forecast, and `fluidbox-account-breaker` (whole account — other projects
share this account):

1. Identify the driver: `AWS_PROFILE=fluidbox-operator aws ce
   get-cost-and-usage … --filter tag project=fluidbox --group-by SERVICE`
   (the acceptance harness's criterion-17 command is copy-pasteable).
2. Fluidbox-driven → check sandbox nodegroup size
   (`idle-scaledown-watch.sh`), LLM spend (`/v1/admin/metrics`, tenant
   budgets), CloudWatch log growth.
3. Runaway → contain (§7) the offending tenant, or scale the sandbox
   nodegroup max down (`sandbox_nodes_max` platform variable), or in the
   extreme `kubectl scale deploy/fluidbox-server -n fluidbox --replicas=0`
   (full stop; replay-safe — the DB is the state).
4. Account-breaker firing WITHOUT fluidbox growth → another project on the
   shared account; hand off to its owner. Never mutate non-fluidbox
   resources from the deployer role (it mostly can't, by policy).

## 9. Rotate the CloudFront origin secret

```bash
scripts/cloud/rotate-origin-secret.sh     # both sides + SSM + verification
scripts/cloud/direct-alb-check.sh         # evidence refresh
```

Cadence: monthly, and immediately after any suspected leak of the SSM value.

## 10. Recover Core after a node or pod failure

The declared beta tier is single-node/RWO — recovery is REPLACEMENT, not
failover:

- **Pod crash:** the Deployment restarts it; `Recreate` strategy means a gap
  of seconds-to-a-minute. Runs survive (DB is the state; approvals/claims are
  durable; the runner retries `/result`).
- **Node failure:** the managed nodegroup replaces the instance (max 2 covers
  the overlap); the archive PVC re-attaches in-AZ (nodes are pinned to one AZ
  precisely so the volume can follow). Expect minutes of API downtime.
- **Full re-schedule check:** `kubectl get pods -n fluidbox` all Ready,
  `curl $API/v1/health` 200, then `kubectl logs` for the RLS +
  netpol-enforcement boot lines.
- In-flight runs on the dead node: heartbeat watchdog + boot-time orphan reap
  finalize them; re-trigger as needed.

## 11. Restore or validate database recovery

Neon (both DBs): point-in-time restore via branch (console/`neonctl branches
create --parent <ts>`). Drill (validate quarterly):

1. Create a PITR branch of the app DB; note its DIRECT (non-pooler) URL.
2. `psql` the branch: `select count(*) from sessions;` sanity vs production.
3. To actually fail over: update `DATABASE_URL` in `fluidbox-secrets`
   (make-secrets.sh with the branch URL), `kubectl rollout restart
   deploy/fluidbox-server -n fluidbox`, verify boot (migrations no-op), run
   one replay.
4. LiteLLM DB is disposable-ish (virtual keys re-mint on demand after
   `llm-key/rotate`; usage history in it is advisory) — restore the same way
   if wanted.
- The sealed-custody KEK lives in KMS, NOT the database — a DB restore never
  breaks decryption; never delete the KEK (`docs/hosted/kms-operations.md`).

## 12. Scale or replace the system node

- Replace (rolling): `aws eks update-nodegroup-version --cluster-name
  fluidbox-cloud --nodegroup-name system` (AMI refresh), or terminate the
  instance and let the ASG replace it. RWO archive → expect the Recreate gap.
- Scale UP the tier: raise `system_instance_type` (platform variable) →
  plan/apply; node group replaces instances. Raise LiteLLM/server
  requests/limits in the app stack to actually use it.
- More sandbox headroom: `sandbox_nodes_max` (platform variable) + the
  chart's `sandbox.quota` tier table (values file) TOGETHER — the quota is
  the admission gate, nodes are the capacity.

## 13. Tear down the environment (and audit for leaks)

```bash
scripts/cloud/teardown.sh
```

Destroys edge → app (waits for the controller to delete the ALB) → platform,
then sweeps the two RECURRING EKS leaks (detached VPC-CNI ENI; the
EKS-created `eks-cluster-sg-<cluster>-*` SG) plus tagged EBS leftovers, then
runs an orphan audit. Bootstrap guardrails (budgets, trail, IAM, state) stay
up on purpose. Post-teardown manual audit checklist: EKS clusters=none, our
VPC gone, `aws ec2 describe-network-interfaces --filters
Name=status,Values=available` empty of ours, CloudFront distribution deleted,
ECR repo empty-or-deleted, and the next day's cost explorer shows only
bootstrap pennies.
