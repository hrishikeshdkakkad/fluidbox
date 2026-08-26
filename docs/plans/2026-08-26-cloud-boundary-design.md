# fluidbox — the OSS ↔ managed-service boundary (design)

**Status:** proposed design — the OSS-side half of the P0 deliverable required by
[`2026-08-03-fluidbox-cloud-plan.md`](./2026-08-03-fluidbox-cloud-plan.md) (rev 4).
The commercial half lives in the private `fluidbox-cloud` repository (owner
decision, 2026-08-26) and is deliberately not in this tree.
**Date:** 2026-08-26
**Verified against:** `main @ 61838d8`
**Authority relationships:** preserves PLAN.md §2 (convergence invariants), the
ownership test and rules of the cloud PLAN, and the identity decisions of
[`2026-08-03-cloud-m1-decisions.md`](./2026-08-03-cloud-m1-decisions.md). It
proposes; it approves nothing — every core change named here requires its own
design and owner approval, per the cloud PLAN's standing rule.

## 1. Executive summary

fluidbox is a complete, MIT-licensed product: everything in this repository is
the product, self-hostable with no held-back capability, exactly as the public
site states. A managed service operated by the fluidbox team exists around it —
the same control plane, run for you. This document fixes the boundary between
the two so that both stay honest:

- **The dependency arrow points one way.** The managed layer may know about
  fluidbox; **fluidbox must never need to know about the managed layer.** No
  code, schema, configuration key, or vocabulary in this repository may exist
  only to serve the managed offering. The managed layer consumes this
  repository's public API surface and its published deployment artifacts
  (images, the Helm chart) — nothing else.
- **The deciding test is unchanged** (cloud PLAN §Ownership): *if Core were
  called directly, bypassing the managed layer, must the rule still hold? If
  yes → it lives in Core.* Everything commercial fails that test and therefore
  lives outside this repository; everything below in §6 passes it and is
  therefore proposed as ordinary, self-host-valuable fluidbox capability.
- **Core remains the runtime authority.** Per PLAN.md §2 invariant 4, fluidbox
  owns identity, policy, approvals, budget decisions, and the canonical ledger;
  external systems sit below the governance plane and are replaceable. The
  managed layer reads the ledger and the API; it is never consulted inside a
  run-time decision path, and a stale external mapping never grants access.

What this document contains: the current-substrate assessment (§2), the exact
API surface an external management layer consumes plus a proposed stability
posture (§3), the upstream-gateway seam and its conformance surface (§4), the
ranked capability gaps found by a full API audit (§5), interface-level
specifications for the seven generic capabilities that would close them (§6),
a re-scoring of the hosted rollout gates against the live deployment (§7), the
repository disposition (§8), and two hygiene findings (§9).

Framing note for anyone editing the public site later: the accurate description
of this split is **a complete open platform with a proprietary managed service
operated around it** — not "open core". Nothing here creates a second edition
of fluidbox, and the pricing page's commitments (no held-back core, no other
edition, no proprietary fork) remain true and binding on this design.

## 2. Substrate assessment — the live estate vs. the rev-3 plan

The rev-3 cloud PLAN was written against AWS/EKS. That estate was validated and
then torn down on 2026-08-15; `deploy/cloud/terraform/` and
`docs/hosted/cloud-*.md` are historical reference. The live estate is GCP, and
**`deploy/cloud/gcp/values/production.yaml` is ground truth** for what runs —
`docs/hosted/gcp-architecture.md`'s topology figure still shows `× 2` server
replicas and §4 sizes connections for two; the applied values say otherwise
(pre-existing doc bug, flagged in §9).

What actually runs (citations to the applied values and handoff):

| Fact | Evidence |
|---|---|
| GKE Standard, zonal `us-central1-c`, project `fluidbox-506603`; dashboard on Vercel (`FLUIDBOX_WEB_MODE=sso`, public URL = the Vercel origin); API host behind the GCLB; DNS in Route 53 | `docs/hosted/gcp-handoff.md` §1 |
| Control plane `replicas: 1`, `strategy: Recreate` — an org policy (`constraints/iam.disableServiceAccountKeyCreation`) blocks the HMAC key the GCS s3-mode archive backend needs, which is what two replicas require | `deploy/cloud/gcp/values/production.yaml:36-58` |
| Run-queue admission (`FLUIDBOX_MAX_CONCURRENT_RUNS`) shipped 2026-08-23 but **disabled in production** (`maxConcurrentRuns: ""`); enabling it forces `Recreate` | `production.yaml:92-102`, [`2026-08-23-run-queue-admission-design.md`](./2026-08-23-run-queue-admission-design.md) |
| The de-facto concurrency limit is the sandbox `ResourceQuota` (12 pods / 6 CPU / 12Gi), deployment-wide, not per-tenant | `production.yaml` sandbox block; threat model, accepted residuals |
| Sandbox node pool is on-demand with one node always present (scale-to-zero retired 2026-08-26 over 31–107 s node + ~50 s Cilium cold starts) | commit `8afe0c0`; `deploy/cloud/gcp/platform/variables.tf` |
| Cloud SQL PG16, private IP, RLS genuinely enforcing (`runtimeRole: fluidbox_runtime`); LiteLLM `-database` variant with its own database; `FLUIDBOX_LLM_KEY_MODE=tenant` in force | `production.yaml`, `docs/hosted/gcp-architecture.md` |
| Sealing is `FLUIDBOX_KMS_MODE=static` with the KEK in Secret Manager under CMEK; disclosed residual: KEK plaintext in the pod env | `docs/hosted/gcp-architecture.md#sealing` |
| Managed Prometheus is enabled but **no `PodMonitoring` exists** — the application's own metrics (`/v1/admin/metrics`) are unscraped | `docs/hosted/gcp-handoff.md` §6; grep of `deploy/` |
| Identity: bring-your-own IdP per org is the settled model (the per-org WorkOS path was disproven at the HTTP level); Auth0 is the operated default, validated on this estate 2026-08-25 | [`2026-08-03-cloud-m1-decisions.md`](./2026-08-03-cloud-m1-decisions.md) update block; `scripts/cloud/auth0-idp-setup.sh`; `docs/reviews/2026-08-25-cloud-m1-auth0-idp/` |
| CI: WIF (no long-lived cloud credential), plan-on-PR as a read-only identity, apply-on-main through a protected environment, destroy gate, pre-upgrade migration Job, `--rollback-on-failure --wait=legacy --wait-for-jobs`, smoke + isolation + browser suites, auto-rollback | `.github/workflows/deploy.yml`; `deploy/cloud/gcp/README.md` |
| Idle cost ≈ **$280–290/mo** (system node ~$98, sandbox node ~$98, NAT ~$32, SQL ~$30, LB ~$18; GKE fee $0 under the zonal free tier) | `docs/hosted/gcp-architecture.md` §8; `gcp-handoff.md` §3 |

Two structural facts matter for anything managing this estate from outside:

1. **The Terraform is single-estate by construction.** All three stacks pin
   `project_id == "fluidbox-506603"` with a validation block; there are no
   modules, no workspaces, resource names are literals, the `app` stack is
   never run by CI, and DNS is a hand-run cross-cloud script. Stamping a second
   estate is a refactor, not a variable change.
2. **The Helm chart is the strong per-deployment asset.** It is OCI-published,
   carries tabulated capacity tiers (starter/normal/full-seat) in
   `deploy/helm/fluidbox/values.yaml`, and refuses invalid combinations at
   render time. Any future multi-deployment story stamps chart values; it does
   not fork the chart.

## 3. The boundary contract — what an external management layer consumes

### 3.1 Planes (existing, restated)

| Plane | Base path | Credential | Note |
|---|---|---|---|
| Public API | `/v1` | admin token \| browser session \| PAT | Under `FLUIDBOX_REQUIRE_SSO=1` the admin token is **refused here** (`auth.rs`) — it satisfies only the operator plane below |
| Operator | `/v1/admin/*` | admin token only | Org lifecycle, IdP configs, membership roles, key rotation, re-seal, metrics |
| Runner contract | `/internal` | four audience-scoped session tokens | Sandbox-only; on Kubernetes a separate listener (`:8788`) — out of scope for any external layer, permanently |
| Ingress | `/v1/ingress/*` | webhook signature | Connected-service events |

### 3.2 Surfaces an external management layer consumes today

- **Org lifecycle (operator plane):** `POST /v1/admin/orgs`,
  `GET /v1/admin/orgs`, `POST/PATCH /v1/admin/orgs/{slug}/idp` +
  `activate/disable/reactivate/migrate`, `POST …/break-glass-owner`,
  `GET …/members` + role set/deactivate, `POST …/llm-key/rotate`,
  `GET/POST /v1/admin/reseal`, `GET /v1/admin/metrics`.
- **Identity handshake (public plane, browser-mediated):** `/v1/auth/login/*`,
  `/v1/auth/callback`, `/v1/auth/me`, `/v1/auth/logout` — consumed via the
  dashboard, not machine-to-machine.
- **Run facts (public plane, per-tenant credential required):**
  `GET /v1/sessions/{id}`, `GET /v1/sessions/{id}/cost`,
  `GET /v1/sessions/{id}/events`, artifacts; plus the signed result webhook
  (`x-fluidbox-delivery`-deduplicated) pushed per subscription.
- **Deployment artifacts:** the GHCR images and the OCI Helm chart, pinned by
  digest.

Dependency worth stating plainly: every *per-tenant* read above requires a
tenant-plane credential, and today those are browser-mintable PATs only — see
gap 1 in §5. Until §6(e) exists, an external layer's per-tenant consumption is
limited to what webhooks push to it and what the operator plane exposes.

### 3.3 Proposed stability posture (requires owner approval — this is new)

fluidbox is pre-1.0 and README.md promises breaking changes. An external
management layer — anyone's, not just ours; the same applies to a self-hosted
operator's automation — needs something to build against. Proposal, to be
ratified as a PLAN-level policy addition and not silently assumed:

1. **A freeze list, not a frozen API.** The endpoints in §3.2 plus the runner
   contract form the *compatibility list*. Within `/v1`, changes to listed
   endpoints are additive-only (new fields, new endpoints); removals or
   semantic changes require a deprecation window of at least one minor release
   and a CHANGELOG entry marked `BREAKING`.
2. **`docs/api/openapi.yaml` is the contract artifact.** Two mechanical fixes
   ride this: its `info.version` (0.3.0) must track the product version
   (0.8.x), and the second copy at `apps/web/public/docs/openapi.yaml` must be
   generated or CI-checked against the first — today they drift by hand.
   A CI check asserting "every routed `/v1` path appears in the spec" would
   also have caught the two undocumented surfaces below.
3. **Explicitly outside the contract:** `/internal` (sandbox planes),
   `/v1/recipes/*` and `POST /v1/triggers/{id}/run-now` (both absent from
   `openapi.yaml` — treat as unstable until documented), and the dashboard's
   proxy behavior.
4. **The one already-stable machine code stays stable:** `wrong_audience`
   (`docs/guides/api.md`) — runners key fatal aborts on it.

## 4. The upstream gateway seam

PLAN.md §2 invariant 4: *"the gateway sits below the governance plane and is
replaceable."* This section documents that the replaceability is a supported
operator seam with a precise conformance surface — useful to any operator who
wants to interpose audit, caching, routing, or accounting between fluidbox and
its model providers, with **zero core changes**.

The seam is two configuration values:

- **`LLM_UPSTREAM_URL`** (`config.rs:560`) — where the facade forwards model
  traffic. The facade appends the dialect suffix to this base
  (`facade.rs:733`): `POST {upstream}/v1/messages` for the Anthropic Messages
  dialect (the Agent SDK harness appends `/v1/messages` to
  `ANTHROPIC_BASE_URL`), `POST {upstream}/v1/responses` for the OpenAI
  Responses dialect (the codex harness). Responses stream as SSE and are teed
  for usage metering; the sandbox never sees this URL — its fake key is a
  session token the facade swaps.
- **`FLUIDBOX_LLM_ADMIN_URL`** (`config.rs:582`, defaults to the upstream) —
  where key provisioning goes in tenant key mode: `POST {admin}/key/generate`
  (the mint body carries `metadata.tenant_id` and the key alias; models,
  max_budget, budget_duration, tpm/rpm ride only when the corresponding env is
  set) and `GET {admin}/key/info?key=…` (the `llm_key_reconcile` worker reads
  `info.models` on a ~10-minute tick and rotates keys whose allowlist drifted).

**Conformance surface for an interposed gateway** (this is the whole contract;
anything speaking these five behaviors can stand in for LiteLLM):

1. `POST /v1/messages` — Anthropic Messages dialect, SSE streaming preserved.
2. `POST /v1/responses` — OpenAI Responses dialect, SSE streaming preserved.
3. `POST /key/generate` — accept the LiteLLM key-mint shape; honor or record
   `metadata.tenant_id`; return a bearer the facade will replay verbatim.
4. `GET /key/info?key=…` — return `info.models` consistent with what was
   minted, or the reconcile worker will rotate the key hourly.
5. Bearer authentication as LiteLLM does it: the master key on admin calls,
   minted virtual keys on model calls (`shared` mode presents the deployment
   key on model calls instead).

Failure semantics the interposer inherits: a non-2xx on a model call surfaces
as an upstream error event on the run timeline and the reservation releases or
retains per the facade's enumerated release rules; a 401 in tenant mode
triggers exactly one key re-provision attempt when the body carries LiteLLM's
own proxy-auth markers. An interposer returning a **402** (or any 4xx outside
that 401 shape) is a terminal upstream refusal for that request — the run sees
a failed model call, budgets and the ledger record it, and nothing in core
needs to understand why the upstream refused.

Chart support already exists: `litellm.enabled` defaults to `false` in
`deploy/helm/fluidbox/values.yaml:311` — the bundled gateway is opt-in, and
`LLM_UPSTREAM_URL` may point anywhere the operator chooses. No chart change is
needed to run fluidbox against an external, operator-owned gateway.

Boundary consequence, stated once: because this seam is generic and already
supported, an external management layer that wants per-tenant accounting or
admission on model traffic can implement it entirely *below* fluidbox, in its
own gateway, using the tenant identity that already rides key minting. Core
neither knows nor cares what the upstream does — which is precisely invariant
4 doing its job.

## 5. Ranked capability gaps (full API audit, verified at `61838d8`)

Ranked by how hard they block external management of a multi-org deployment.
Each names the §6 capability that resolves it.

1. **No machine credential for a tenant's data plane.** Under
   `FLUIDBOX_REQUIRE_SSO=1` the admin token satisfies only the `Admin`
   extractor (`auth.rs`); PATs are mintable only from a browser session
   (`tokens.rs`). No supported path exists for an operator's automation to act
   inside a tenant (create agents, pause trigger subscriptions, read usage,
   cancel runs). → §6(e).
2. **No per-org usage aggregation, window queries, or export.**
   `usage_entries` (migration `0001_init.sql`) has no `tenant_id`, no
   `agent_id`, no index on `created_at`; the only aggregates in the codebase
   are single-session. `/v1/admin/metrics` is deliberately tenant-label-free.
   → §6(c).
3. **No per-tenant concurrent-run cap.** Admission is deployment-wide
   (`FLUIDBOX_MAX_CONCURRENT_RUNS`), and off in production; one org can occupy
   the entire sandbox quota. → §6(a).
4. **Per-tenant upstream-key knobs are one global env set.** Every org's
   virtual key is minted with identical models/max_budget/tpm/rpm
   (`llm_keys.rs::knobs_from_cfg` is the only producer). → §6(b).
5. **No org suspend/resume/offboard/purge API.** `tenants.status='suspended'`
   is honored on read (`auth.rs`) but nothing ever writes it;
   `evict_tenant_llm_key` exists and is uncalled. → §6(d).
6. **The model price table is compiled in** (`fluidbox-core/src/usage.rs`) —
   substring families; unknown `gpt-5*` variants deliberately over-estimate at
   the big-tier rate (fail-safe), but models outside every family (e.g.
   `gpt-4o`) record **no cost at all**. Acceptable as the technical safety
   estimator it is; operators must keep served models within priced families.
   Deliberately *not* proposed for change — see §10.
7. **No per-org sandbox resource tiering or storage quota** — global env only.
8. **No version/build endpoint** — `/v1/health` returns `{"status":"ok"}`
   literally; no API reveals which fluidbox version a deployment runs. → §6(f).
9. **No membership provisioning** — memberships materialize only through OIDC
   login; no invite, no preauthorized-subject list, no SCIM. → §6(g).
10. **New-org policy seeding is best-effort, post-commit, with no repair
    endpoint** (`admin_orgs.rs`) — a seeding failure leaves an org that fails
    closed on every run, fixable only in SQL.
11. **`GET /v1/sessions` supports only `limit`** — no status/time filters, no
    cursor.
12. **No lifecycle DELETE** for agents, connections, capabilities, catalog
    entries, or trigger subscriptions — everything accumulates.
13. **`/v1/recipes/*` and `POST /v1/triggers/{id}/run-now` are not in
    `openapi.yaml`** — undocumented surface, excluded from §3.3's list.
14. **The `settings (tenant_id, key, value jsonb)` table** (migration 0001,
    RLS-covered by 0018) is confirmed unused apart from one RLS self-check —
    it is the natural storage hook for §6(a)/(b).

## 6. Generic capability specifications (M3 candidates)

Preamble, binding: **each item below remains a separate design + owner
approval**, exactly as the cloud PLAN requires. This section specifies
interfaces so that external consumers (and this repo's own operators) can be
designed against them; it approves nothing and sequences nothing beyond naming
what each unblocks. Every item passes the deciding test — stated per item —
and is valuable to a self-hosted operator with no managed service anywhere in
sight. All per-org values live in the existing `settings` table (gap 14)
unless a migration is named.

**(a) Per-tenant concurrent-run caps.**
*What:* per-org `max_concurrent_runs` (and optionally `max_queued`) enforced
inside the existing dispatcher admission decision, under the deployment-wide
cap. The run-queue design already anticipated a per-tenant predicate in its
admission query; this adds the per-org ceiling value and the
`settings`-sourced lookup. *API:* `PUT/GET
/v1/admin/orgs/{slug}/limits` (operator plane), values readable by admins in
the org. *Test:* a self-hosted operator with three internal teams wants
per-team caps today; holds with no external layer. → Core.
*Unblocks:* fair multi-org capacity; the public-launch quota gate.

**(b) Per-org upstream-key knob overrides.**
*What:* per-org overrides for the tenant-key mint knobs (models allowlist,
max_budget, budget_duration, tpm, rpm), falling back to the global envs.
`llm_keys.rs::knobs_from_cfg` grows a per-tenant lookup; the
`llm_key_reconcile` worker compares against the *resolved* per-org list, and a
knob change triggers the existing rotate path. *Constraint to design through:*
`harness::is_servable` gates agent authoring against the **global** catalog —
a narrower per-org list must also narrow authoring for that org, or agents
reference models their key refuses. *API:* same `…/limits` document as (a).
*Test:* a self-hosted operator wants the research org on expensive models and
the intern org on cheap ones. → Core. *Unblocks:* differentiated org limits.

**(c) Usage aggregation and export.**
*What:* (1) a migration adding `tenant_id` (backfillable via `sessions`) and
`created_at` indexing to `usage_entries`, or a rollup table maintained on
write; (2) `GET /v1/usage?from=&to=&group_by=model|agent|day` (tenant-scoped,
User/PAT); (3) `GET /v1/admin/usage/export?from=&to=&cursor=` (operator plane,
cross-tenant, cursor-paginated NDJSON). Deliberately operator-token-consumable
so it does **not** depend on (e). *Test:* every self-hosted operator doing
chargeback or capacity review wants this; the ledger keeps content, this keeps
arithmetic. → Core. *Unblocks:* any external accounting without touching the
database; retirement of ad-hoc SQL against `usage_entries`.

**(d) Tenant suspend / resume / offboard / purge.**
*What:* `POST /v1/admin/orgs/{slug}/suspend|resume` writing the
already-honored `tenants.status`, with a kill-switch inventory executed on
suspend: cancel active sessions, revoke PATs and web sessions, pause schedules
and trigger subscriptions, evict the tenant upstream key
(`evict_tenant_llm_key` finally gets its caller). `offboard` + `purge` follow
as a second phase with retention semantics (design of their own). *Test:* a
self-hosted operator decommissioning a business unit needs exactly this;
today's answer is a manual runbook labeled incomplete. → Core.
*Unblocks:* real containment; replaces the rev-3 "suspend removed from scope"
note with its designed resolution.

**(e) Machine credential for a tenant's data plane (org service accounts).**
*What:* operator- or org-admin-mintable service credentials
(`fbx_svc_`-prefixed PAT-shaped rows: `kind='service'`, role-scoped, expiring,
sha256-at-rest like every other token; Redactor already covers the pattern
family by prefix addition). Mint via `POST /v1/admin/orgs/{slug}/service-tokens`
(operator plane) and `POST /v1/auth/service-tokens` (org admin). *Test:* any
self-hosted operator automating tenant operations — seeding agents, CI-driven
runs, support tooling, pausing subscriptions during an incident — needs a
non-browser credential; today they cannot have one. → Core. *Unblocks:* gap 1
wholesale; per-tenant API consumption by any external tooling.

**(f) Version/build introspection.**
*What:* `GET /v1/health` gains (or a sibling `GET /v1/version` provides)
`{version, git_sha, built_at, schema_version}`. Trivial; the server has
`CARGO_PKG_VERSION` and the migration table. *Test:* any operator triaging a
deployment wants "what is running" from the API. → Core. *Unblocks:* fleet
upgrade orchestration; support triage.

**(g) Membership preauthorization / invites.**
*What:* a per-org preauthorized-subject (or email) list consulted at OIDC JIT
so that "anyone the IdP admits" can be narrowed to "anyone the org invited",
per the identity design's deferred item. *Deferral note:* while an operated
IdP controls membership on the IdP side this is not urgent; it becomes
necessary when orgs bring their own IdP and want fluidbox-side membership
control. *Test:* a self-hosted org on a big corporate IdP wants only invited
subjects to materialize memberships. → Core. *Unblocks:* BYO-IdP self-serve
onboarding at scale.

Also worth fixing while in the area (small, from §5): the org policy-seeding
repair endpoint (gap 10), session list filters (gap 11), and the two
undocumented surfaces entering `openapi.yaml` (gap 13).

## 7. Rollout-gate re-scoring and rev-3 phase disposition

Against `docs/hosted/rollout-gates.md`, scored on the **live GCP deployment**:

| Gate | Verdict | Evidence / what's missing |
|---|---|---|
| 0 — prerequisites | **OPEN on one criterion** | `FLUIDBOX_REQUIRE_SSO=1` ✓, posture-valid runtime role ✓, runner images from this branch ✓ (all `production.yaml` + smoke/isolation suites). **KMS KEK backup: no documented backup location exists in the GCP docs** — `gcp-handoff.md` §4 records the KEK as "UNRECOVERABLE" if lost but names no backup. Closing Gate 0 = writing the backup procedure and recording where the copy lives. |
| 1 — internal single-org | **Partially closed** | Auth0 drill org live; smoke, isolation, and browser journeys green in CI. Missing: the 20-consecutive-runs record and the one-week dogfood-without-Sev-1 decision, as recorded evidence. |
| 2 — 10–25 user pilot | Open | Requires observed-data outputs (concurrency, connections/user, per-run cost distribution) — nothing recorded yet. |
| 3 — 60-run capacity | Open | Load harness against production-shaped deployment; costs money; single replica today makes the multi-replica criterion unmeetable as-is. |
| 4 — multi-org beta | Open | Needs Gate 2/3 + the `go_url` residual decision in writing + per-tenant cost attribution reconcile. §6(a)/(b) materially help the noisy-neighbour criterion. |
| 5 — 300-seat target | Open | Far; depends on replica story (org-policy lift) and fault injection. |
| 6 — BYOC/private MCP | Deferred by design | Unchanged. |

Rev-3 phase list disposition (P0–P7 were AWS-era):

| Phase | Disposition |
|---|---|
| P0 guardrails + proofs | **Superseded/done-differently:** design doc = this document + the private-repo half; IAM/budget guardrails exist on GCP (`bootstrap` stack); the WorkOS spike is moot (identity re-decided); the Vercel SSE probe and dual-session proof were carried out (`scripts/cloud/vercel-sse-probe.sh`, reviews evidence). |
| P1 cloud scaffold | **Moved** — lives in the private repository now. |
| P2 EKS environment | **Superseded** by the live GCP estate (torn down → rebuilt on GKE). |
| P3 live provisioning | **Partially done** — org provisioning is scripted (`auth0-idp-setup.sh`), not yet productized; productization is private-repo work. |
| P4 web cloud mode | **Partially done** — sso-mode dashboard live on Vercel; onboarding surfaces are private-repo work. |
| P5 metering + plans | **Moved** — commercial; private repo. The OSS-side share is §6(c). |
| P6 acceptance + docs | **Done for the estate** (smoke/isolation/browser + handoff docs); repeatable per release. |
| P7 public-readiness + M3 | **Remaining** — the M3 proposals are §6 of this document; public self-serve stays off until the §6(a)(+ b, d) enforcement set lands, exactly as rev 3 gated it. |

## 8. Repository disposition

| Stays in this repository | Rationale |
|---|---|
| Everything under `crates/`, `images/`, `apps/web` (dashboard + site), `docs/guides`, `docs/plans`, `docs/hosted` (posture docs), the Helm chart, compose files | The product. |
| `deploy/helm/fluidbox` + `values/{gke,eks,aks,doks,kind}.yaml` | Generic, self-host-valuable, OCI-published. |
| §6 capabilities when approved | They pass the deciding test. |

| Migrates to the private repository (follow-up, not this change) | Rationale |
|---|---|
| `deploy/cloud/gcp/` (three stacks + production values) and the deploy half of `.github/workflows/deploy.yml` | Estate-specific operations of one hosted deployment, project-pinned by validation; nothing a self-hoster can apply. Migration is real work — WIF providers are bound to this repository name and must be re-bound — and is explicitly out of scope here. Until it happens, this tree remains where it is and CI keeps deploying. |
| `scripts/cloud/*` operational scripts | Same. |
| `docs/hosted/gcp-*.md` | Estate runbooks; move with the estate. Posture docs (threat model, rollout gates, kms/observability/run-queue operations) stay — they describe the product's hosted posture, which any operator adopts. |

## 9. Hygiene findings (pre-existing, surfaced by this audit)

1. **Four Terraform plan files are tracked in git**:
   `deploy/cloud/gcp/bootstrap/bootstrap.tfplan`,
   `deploy/cloud/gcp/platform/{platform,cilium,ccnp}.tfplan`. `.gitignore`
   covers the literal name `tfplan` but not `*.tfplan`. Plan files embed the
   prior state, and the platform stack's state includes Terraform-generated
   secret material (the SQL password, the admin token, the credential key, the
   static KEK) — the exact values `deploy/cloud/gcp/README.md` says must never
   be on a laptop or in git. **Remediation is its own security task, not part
   of this change:** extend `.gitignore` to `*.tfplan`, remove the files,
   scrub history (`git filter-repo`), and run a rotation assessment for every
   embedded secret class (the KEK cannot be rotated by re-apply —
   `ignore_changes` — and KEK rotation has custody implications per
   `docs/hosted/kms-operations.md`). Evidence belongs in `docs/reviews/`.
   No secret values are reproduced in this document.
2. **`docs/hosted/gcp-architecture.md` disagrees with the applied values** —
   the §1 figure's `× 2` replicas and §4's two-replica connection sizing
   predate the org-policy discovery recorded in `production.yaml:36-58`.
   One-line fix plus a footnote when that doc is next touched.
3. Smaller, already noted: `openapi.yaml` version drift + duplicate copy
   (§3.3), Gate-0 KEK backup documentation (§7).

## 10. Named omissions

- **No change to the compiled price estimator** (`usage.rs`): it is a
  fail-safe technical estimator, not a rate card, and making it configurable
  invites treating it as one. The operational rule instead: served models stay
  within priced families (§5 gap 6).
- **No per-org sandbox resource tiering** (gap 7) in the §6 set: real, but
  second-order until (a)–(e) exist; revisit when differentiated org sizing is
  actually needed.
- **No SCIM**: (g)'s preauth list is the 90% answer at current scale.
- **No numeric SLOs anywhere in this document** — rollout-gates.md's closing
  section explains why; observed pilot data (Gate 2) comes first.
- **No API version negotiation scheme**: §3.3 proposes additive-only + a
  freeze list, not versioned media types; pre-1.0 that is the right weight.
- **No multi-region, no HA redesign**: the single-replica/`Recreate` reality
  and its org-policy cause are stated in §2; lifting it is estate work with a
  known path (`production.yaml:55` comment), not a design question.

## 11. Verification of this document

Checks run before commit, results recorded here:

- **Deciding-test audit:** every §6 capability carries an explicit verdict
  line; §3.2/§4 grant the external layer no authority Core does not already
  grant any API consumer. ✓
- **Boundary-vocabulary check:** this document and the rev-4 header edit
  introduce no commercial machinery into this repository; the single pointer
  to the private repository's subject matter lives in the rev-4 status note of
  the cloud PLAN, deliberately worded as a pointer. ✓
- **Authority rules:** no `docs/hosted/` file gains a decision in this change;
  this document proposes, and each §6 item still requires its own design +
  approval (stated in §6's preamble). ✓
- **Settled decisions preserved:** the deciding test quoted verbatim (§1);
  BYO-IdP-per-org + operated-Auth0 stated as settled with evidence pointers
  (§2); WorkOS appears only as disproven history; the public site's
  commitments restated and bound (§1). ✓
- **No invented tiers, prices, or SLOs.** ✓
- **Live-state claims cite files** (`production.yaml`, handoff, decision
  sheet, evidence dirs) and the whole document pins `main @ 61838d8`. ✓
- **Links resolve** within this tree. ✓
