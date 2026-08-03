# Cloud M1 — decision sheet (§12) + apply queue

Prepared 2026-08-03 during the autonomous M1 build session. Everything
buildable was built and validated; the items below are the SEVEN decisions
the M1 brief reserves for you (§12), each with the evidence-backed
recommendation and exactly what it unblocks. Applies stay per-action-approved
— nothing on this sheet has been applied.

Context that shaped the recommendations (from the 2026-08-03 read-only
account survey): **471112572248 is a SHARED, active account** (alias
`forceplatforms`; expenseforce/accountforce/fluidzero/temporalcommerce also
live there; Aug forecast from those alone ≈ **$179/mo**; an existing $20
"My Monthly Cost Budget"; an existing `serverless_trail`; root key present
AND is the configured local credential; MFA on root; no Identity Center;
zero fluidbox EKS leftovers).

| # | decision | recommendation | notes |
|---|---|---|---|
| 1 | Account-wide budget number | **$400/mo** | other projects ≈$179 + fluidbox ≈$132 idle/≈$137 light ⇒ <$320 alerts constantly. Variable `account_budget_limit` (bootstrap). Also: raise `fluidbox_budget_limit` 50→**175** in the M1.1 apply or the tag budget fires on day one. |
| 2 | AWS account + region | **471112572248 / us-east-1** | both acceptances ran here; subnets pinned 1b/1c (1a = the proven-bad AZ). Sub-decision made for you to review: **K8s 1.35, not the proven 1.33** — 1.33 entered EXTENDED support 2026-07-28 (+$365/mo at 6×). Verified live; `upgrade_policy=STANDARD` prevents recurrence. |
| 3 | IAM bootstrap approval | **approve `terraform/bootstrap`** | one root apply, then the ceremony retires the root key (README walks it). The deployer's recorded residual: EC2-plane actions are region-locked but not resource-scoped in the shared account (threat model §operator plane). Sub-decision: our own CloudTrail = a paid SECOND management-events copy (~$1/mo) instead of adopting another project's validation-off trail — reversible. |
| 4 | M1 identity: WorkOS Connect vs other OIDC | ⚠️ **RE-TAKE — the assumed path is disproven.** Recommend **bring-your-own IdP per org** (option 3), with shared-AuthKit (option 2) as the fast path for the internal drill org | The M1.0 proof showed WorkOS exposes **one issuer + one OIDC client per environment**; a per-org Connect app is refused at authorize (`client-id-invalid`). PLAN rev 3 identity §1 does not hold as written. Three options + evidence: `docs/reviews/2026-08-03-cloud-m1-readiness/README.md`. **Also unresolved:** WorkOS omits `token_endpoint_auth_methods_supported`, so core requires `client_secret_basic` while WorkOS documents body credentials — verify the token leg before committing to any WorkOS option. |
| 5 | Vercel project | **link `apps/web` as project `fluidbox-cloud-dashboard`** (account `hrishikeshdkakkad`, already CLI-authed) | not created autonomously — linking is your decision. The proxy **code path is proven** (9/9: unbuffered SSE, `Last-Event-ID` resume, `__Host-fbx_web` survives the hop); only the platform duration cap is unmeasured. `scripts/cloud/vercel-sse-probe.sh` prints the exact 6-command recipe and runs unchanged against a preview URL. |
| 6 | First beta org + owner | **propose: a fluidzero-internal drill org first** (`fluidzero`, owner hrishidkakkad@gmail.com), then the first external | the checklist's wrong-org probe + containment drill run against the internal org before any external human is invited. |
| 7 | Real-model acceptance run | **defer until every §9 no-cost criterion is green**, then one haiku run <$0.50, you trigger it | replay covers 5–9/13/15 at $0; the real-model run only re-proves the facade/budget path with money. |

## What the M1.0 proofs changed

Two of the seven decisions moved on evidence, not opinion: **#4 must be
re-taken** (the per-org-WorkOS-Connect-app assumption is disproven at the
HTTP level), and **#5 is now a link-only step** (the proxy code path is
already proven; only the platform cap is outstanding). Full ledger:
`docs/reviews/2026-08-03-cloud-m1-readiness/README.md`.

## Start here

```bash
scripts/cloud/cloud-preflight.sh --write-tfvars
```

Read-only. Checks tooling, which identity you are, whether the root key is
still live, the EKS version's support tier (a 6x billing difference), account
capacity and name collisions — and detects your public IP to stage
`operator_cidrs`, the one input the platform stack cannot default. It ends by
listing exactly these decisions. Verified on this machine: 12 ready, 0
blocked.

## The apply queue (in order, each gated on your explicit go)

Profiles matter here and are counter-intuitive: **terraform runs as
`fluidbox-operator`** (each stack's provider assumes the deployer itself, and
the S3 backend uses ambient credentials), while **plain scripts run as
`fluidbox-deployer`**. `deploy/cloud/README.md` has the one-table version.

1. `bootstrap` apply (root, once) → ceremony → `AWS_PROFILE=fluidbox-deployer scripts/cloud/verify-bootstrap.sh` PASS → **root key retired**.
2. `platform` apply (`AWS_PROFILE=fluidbox-operator`; needs `operator_cidrs` = your IP — `[]` and `0.0.0.0/0` are refused at plan time).
3. Neon: create the two databases (runbook §11 note; direct URLs) → `make-secrets.sh` → `deploy-app.sh`.
4. `edge` apply → `rotate-origin-secret.sh` → `direct-alb-check.sh` (M1.1 edge gate).
5. `replay-on-cluster.sh` (M1.1 acceptance gate, $0).
6. Vercel project link + env → deploy → M1.2 app apply (`require_sso=true`, `public_url=<vercel origin>`) → onboard drill org via the checklist.
7. `cloud-m1-acceptance.sh` (the §9 ledger) + validation report → M1.3 sign-off.

Once the platform stack is up and has been billing for ~24h, re-apply
`bootstrap` with `-var activate_cost_allocation_tag=true` so the tag-filtered
budget starts matching (AWS refuses to activate a tag it has never seen on
billed usage). Consider raising `fluidbox_budget_limit` 50 → ~175 in the same
apply, or the tag budget alerts on day one against a ~$131 idle floor.
