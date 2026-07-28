# PR #92 — two-environment end-to-end validation (DB-native policies)

**Subject:** `feat/db-native-policies` @ `adaa74c` vs `main` — 32 files, +6707 / −1196, migration `0026_policy_versions.sql`.
**Date:** 2026-07-27/28 (UTC)
**Method:** independent static review plus two parallel validation agents, each of which **deployed the control plane and drove it over real HTTP** — one on Docker, one on AWS EKS. No conclusion below rests on reading code alone.

**Verdict: PASS WITH RISKS.** Every functional, data-integrity, isolation, concurrency and
fail-closed property in the change was exercised against a running deployment and held. The
residual risk is documentation, not code — one operator-facing upgrade instruction was wrong in
both directions, and is corrected in this PR. Coverage gaps are enumerated in §8 and are real.

---

## 1. Why this validation was needed

CI's nine green checks are the **cheap gates only**. `.github/workflows/ci.yml:417` gates the
`e2e` job on `github.event_name == 'workflow_dispatch'`, and this PR's status rollup records
`e2e: SKIPPED` and `coverage: SKIPPED`. Nothing in CI deployed the control plane, applied `0026`
to a database carrying real pre-0026 data, or exercised the policy API over HTTP. For a change
whose centrepiece is a migration that **drops four columns** and whose safety argument rests on
byte-identical frozen `RunSpec`s, that is the gap worth closing.

## 2. Scope and affected workflows

Policies become versioned, authorable and attachable:

- **Spec B — versioned storage.** `0026` splits identity (`policies`, the stable FK target for
  `agent_revisions.policy_id`) from content (append-only `policy_versions`). The latest version
  governs future runs; `RunSpec` still freezes. `managed_overrides` folds into ordinary head rules.
- **Spec A — attachment.** Policy select in the run composer and revision modal; autonomy forced
  off when the governing policy forbids unattended runs.
- **Spec C — authoring UI.** `/governance/[name]` becomes a draft editor with version history,
  diff and one-click revert.

`just policy-sync` retires; YAML survives as boot seed and import/export format.

**Workflows exercised:** policy create / edit / publish / revert / clone / delete / import /
export; revision→policy attachment; run creation and `RunSpec` freeze; boot seed; database upgrade;
rollback.

## 3. Environments

| | Docker | EKS |
|---|---|---|
| Deployment | image built from `deploy/server.Dockerfile`, run as a container | Helm chart `fluidbox-0.3.0`, chart-default + `values/eks.yaml` |
| Cluster | — | EKS 1.33, 2× `t4g.medium` (arm64), vpc-cni netpol **standard** mode, gp3 default SC |
| Images | `fbx-val-dkr-server:adaa74c` (353 MB) | ECR: pre0026 = `main@7b75b20`, PR = `adaa74c` |
| Database | `postgres:16.14`, isolated container | in-cluster `postgres:16` |
| DB owner | `fluidbox_owner` — `rolsuper=f`, `rolbypassrls=f` | `fbxowner` — `rolsuper=f`, `rolbypassrls=f` |
| Runtime role | `FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime` | chart default `fluidbox_runtime` |
| RLS | boot log: *"row-level security is ENFORCED for this pool"* | same, on both images |
| Model spend | zero (`LLM_UPSTREAM_URL` black-holed) | zero |

**Image provenance.** The EKS images were built from `git archive adaa74c | tar -x` into clean
contexts, not from a working tree, so build-time `HEAD` is irrelevant. Verified three ways: the PR
context's migrations end at `0026_policy_versions.sql` with `put_policy_override` count 0, the
baseline context ends at `0025` with count 1, and empirically only the PR image migrated the
database to 26 and dropped the four columns. This matters because both worktrees were initially
created at the wrong ref (`7b75b20`, post-v0.3.0 *without* the PR); validating the wrong tree would
have voided the run silently.

A non-superuser owner was used deliberately in **both** environments. Under a superuser or
`BYPASSRLS` role, migration 0018's `FORCE`d RLS is silently inert and every RLS/append-only
assertion becomes vacuous. Verifying `rolsuper=f, rolbypassrls=f` is what makes §5 and §6 mean
anything.

**The production Neon database was never touched by either agent.** Both used isolated
throwaway databases; `DATABASE_URL` was asserted non-Neon before every database command.

## 4. Test execution — claimed vs actual

| Suite | PR claim | Measured |
|---|---|---|
| Rust workspace | 837 (body) / 850 (later commits) | **850 passed / 0 failed** — matches the later figure |
| Web unit | 51/51 | **58 passed / 0** (7 files) |
| `pnpm build` | clean | clean |
| `scripts/version-check.sh` | passes | PASS, all sites agree at 0.3.0 |

Per-crate: core 119, db 138, server 419, provider 52, provider_k8s 32, workspace 64, catalog 24,
workspaced 2. Every test named in the traceability matrix — including the
`override_fold_preserves_every_verdict` proptest and the `0026` upgrade harness
`migration_0026_folds_legacy_policies_and_never_touches_runspecs` — was confirmed present and
passing.

*Observed and explained, not a defect:* run as the **non-superuser owner**, two targets fail on
fixture inserts hitting RLS (`42501` on `tenants` / `org_idp_configs`). CI's `rust` job runs as
`postgres` by design; the RLS-enforcement tests open their own `SET ROLE` connections.

## 5. Migration `0026` — reproduced independently, twice

Rather than trust the committed upgrade harness, both agents rebuilt the scenario: migrate a
scratch database to `0025`, plant realistic legacy data (policies with `parsed`, `yaml_source`,
`version`, ordered `managed_overrides`, a trailing-wildcard entry, a mid-string `fo*o` entry;
agent revisions; sessions with frozen `run_spec`s), then apply `0026`.

| Property | Result |
|---|---|
| Backfill parity (C1.1) | Docker 4→4, EKS 2→2 — the `system_worker` bypass GUC works; **not** a silent zero-row backfill |
| Bypass GUC scope | transaction-local; does not leak to a fresh connection |
| Fold ordering (C1.6) | overrides prepended in stored order — observed `[["Bash"],["Edit"],["Read","Glob"],["WebFetch"]]` / `[deny,approve,allow,deny]`; `managed_overrides` key stripped |
| `yaml_source` nulling (C1.7) | NULL for the folded policy, preserved for the clean one |
| Wildcard drop (C1.3) | trailing `mcp__*` dropped with a warning; `fo*o` folded to exact match |
| Columns dropped (C1.8) | `policies` = `id, tenant_id, name, created_at, updated_at` only |
| Constraints (C1.5) | version 0 → `23514`; duplicate → `23505`; bad author → `23514`; cross-tenant FK → `23503` |
| Preflight aborts (C1.2) | all four malformed shapes abort naming the row; database left unchanged |
| **Frozen `RunSpec` byte-identity (P7)** | md5 `4bc33fa8` (Docker, containerized deployment) and md5 `7c073c08…`, len 2975 (the EKS agent's local non-superuser lab) — **identical before and after** in both. See the attribution note below. |

**Attribution note on P7.** The second measurement was taken in the EKS agent's *local*
non-superuser lab — a faithful mirror of the chart-default posture — **not on the cluster
itself**. The EKS deployment could not create a session at all (the netpol run-gate returns 503;
see §8), so there was no in-cluster `run_spec` to diff. Byte-identity across `0026` is therefore
established twice on Docker-provider deployments and **not** established on EKS proper. It is a
property of the migration SQL, which never references the `sessions` table, so the risk of it
differing by environment is low — but the evidence does not cover it, and this report does not
claim otherwise.

The `RunSpec` byte-identity result is the load-bearing one: it is the evidence that in-flight
runs keep exactly the governance they froze while the schema moves underneath them.

**No binary rollback (C1.8), confirmed in both environments.** A pre-0026 binary against a 0026
database fails with `Error: migration 26 was previously applied but is missing in the resolved
migrations`. On EKS this manifested as `CrashLoopBackOff` — the old binary **never served and
never touched the schema**. Fail-closed and loud, as the migration header claims. Forward
recovery (`helm rollback` to the PR revision) restored `1/1 Running`.

## 6. Append-only and tenant isolation are database properties

Probed as `fluidbox_runtime` (`rolbypassrls=f`) against the **actual chart-default EKS
deployment**, and independently on Docker:

- `relrowsecurity=t`, `relforcerowsecurity=t` on `policy_versions`; `tenant_isolation` policy present.
- Tenant A's GUC → only A's rows (2). Tenant B's GUC → only B's (1). No GUC → 0. Bypass → all.
  **No cross-tenant leakage.**
- Cross-tenant **write** as tenant B naming tenant A's policy → `new row violates row-level
  security policy` (the `WITH CHECK` arm closes it).
- `UPDATE policy_versions` → `42501`. `DELETE policy_versions` → `42501`. `INSERT` → succeeds.
- Parent-cascade erasure still works despite the child having no `DELETE` grant.

The PR's claim that history is append-only *at the database level, not by application
convention* is therefore substantiated in the deployment shape operators actually run.

## 7. Upgrade rollout on EKS — the marquee test

`helm upgrade` from the pre-0026 image to the PR image, chart-default + `values/eks.yaml`:

```
00:50:17  old pod dc8548cd (pre-0026)  Running/ready
00:50:58  old pod  Failed/gone (terminated)
00:51:00  NEW pod f58f87d7b (PR)       Pending   <- created only AFTER old gone
00:51:05  new pod  Running
```

Deployment events are unambiguous: *"Scaled down replica set …dc8548cd from 1 to 0"* precedes
*"Scaled up replica set …f58f87d7b from 0 to 1"* by 31s. **There was no window in which the old
binary queried the dropped columns.** `0026` ran only on the new pod's boot. Post-upgrade the
database was at v26 with the four columns gone and backfill parity intact.

Rendered `strategy` per configuration (`helm template`):

| Configuration | `strategy.type` | `replicas` |
|---|---|---|
| default values | **Recreate** | 1 |
| `values/eks.yaml` | **Recreate** | 1 |
| `--set server.archiveStore=s3 --set server.replicas=2` | RollingUpdate | 2 |

The live deployment confirmed `spec.strategy.type = Recreate`.

## 8. Defects, risks and gaps

### D1 — Upgrade guidance was wrong in both directions *(Medium; fixed in this PR)*

`CHANGELOG.md:20` and the `0026` header both asserted *"The Helm chart's Deployment uses
`RollingUpdate`: scale the server to zero first."* Established false by three independent
routes — static reading of `server.yaml:12` (`$nodeLocalArchive := ne .Values.server.archiveStore
"s3"`), `helm template` output, and the observed live rollout.

Two failures in one sentence: it prescribes unnecessary downtime for the **default** (already
`Recreate`, already safe), and it never names the one configuration that **is** hazardous —
`server.archiveStore: "s3"`, which is also the multi-replica production shape. There, old and new
pods coexist, and an old pod's `select version, parsed, … from policies` returns `ERROR: column
"version" does not exist` (42703) until it is replaced; its in-flight transactions can also block
the migration's `ACCESS EXCLUSIVE` DDL against the 5s `lock_timeout`.

A third problem sits inside the original remedy itself: *"switch it to `Recreate` for one
release"* **cannot be done.** `values.yaml:57` states that strategy and PVC are "both derived from
archiveStore … so there is no separate strategy" knob, and `server.yaml:107-117` confirms it —
the strategy is a pure function of `archiveStore`. Patching the Deployment does not help either,
because the same `helm upgrade` rewrites the field. The only workable remedy in `s3` mode is to
scale the Deployment to zero, upgrade, and scale back.

**Fixed:** `CHANGELOG.md` now states that the default needs no action, scopes the precaution to
`archiveStore: "s3"`, prescribes scale-to-zero as the *only* workable remedy, and says explicitly
that no values knob exists. The 42703 symptom is quoted so an operator can recognise it.

**Deliberately not fixed:** the identical claim inside `migrations/0026_policy_versions.sql`.
Editing an applied migration changes its sqlx checksum, and any database that already ran `0026`
would then refuse to boot with *"migration 26 was previously applied but has been modified"*. That
is a worse failure than a stale comment. The operator-facing text — the one an operator actually
reads — is now correct.

### D2 — Seed policy advertised a removed command *(Low; fixed in this PR)*

`policies/default.yaml:7` still read *"Applying edits to a running deployment: `just
policy-sync`"* — the recipe this PR deletes. The file ships inside the server image, so the stale
instruction would be distributed. Replaced with the current model (Governance page, or
`POST /v1/policies`), and re-validated: `cargo test -p fluidbox-core policy::` → 42 passed / 0
failed, including `seed_policy_semantics` and `tool_matrix_of_the_seed_policy`, which both read
this file via `include_str!` and pin its evaluated verdicts.

### D3 — `RunSpec` snapshot byte-equality is fresh-database-specific *(Informational; not fixed)*

`ToolRule`'s `Option` fields carry `#[serde(default)]` but no `skip_serializing_if`, so Rust
re-serializes them as explicit `null`s, while `0026`'s SQL fold emits minimal
`jsonb_build_object('match', …, 'action', …)`. For a **migrated-and-not-yet-republished** policy
carrying folded overrides, `run_spec.policy_snapshot` is therefore semantically equal but **not
jsonb-byte-equal** to `policy_versions.content`. `scripts/governance-e2e.sh` asserts byte-equality
and would fail on such a deployment.

Not a correctness defect — the load-bearing invariant (frozen `sessions.run_spec` immutability) is
unaffected, because nothing re-serializes it, which is precisely why not rewriting RunSpecs was the
right design. Worth knowing before running the e2e against an upgraded database.

### Untested / not established

| Area | Status | Why |
|---|---|---|
| Non-admin RBAC 403 (C4.12) | **Not tested** | Both environments ran single-admin; standing up OIDC was out of proportion. The `rbac::can_mutate_resources` gate is present in every mutating handler and is covered by CI's identity-e2e. |
| Live agent run (model round-trip) | **Now tested — see §8b** | Four real runs on `claude-haiku-4-5`, ~$0.08 total. The PR's loop (author → publish → attach → run → freeze → gate → approval) is proven. It also surfaced a platform-level finding, unrelated to this PR, that a live agent's tool calls do not reach the gate. |
| Run path on Kubernetes | **Now covered on kind+Calico — see §8b** | EKS `POST /v1/sessions` → `503 sandbox network isolation is not yet verified`. Re-run on kind with **Calico**, which genuinely enforces NetworkPolicy: the same call returns **200** and the full gate chain executes. That identifies the EKS refusal as the **vpc-cni standard-mode probe false-negativing** (a pre-existing chart follow-up), not a PR regression and not a real isolation failure. Still untested on EKS specifically. |
| `archiveStore: s3` RollingUpdate hazard | **Mechanism established, not live-reproduced** | Needs an S3 bucket. The rendered strategy and the `42703` error were both observed directly; the two coexisting under load were not. |
| API-level cross-tenant isolation | **DB layer only** | Single-tenant deployments; proven at the database layer under the runtime role, which is the stronger claim. |
| `RunSpec` byte-identity on EKS proper | **Not established** | The cluster could not create a session (netpol 503), so there was no in-cluster `run_spec` to diff. Established twice on Docker-provider deployments instead. |
| Neon-specific RLS behaviour | **Not exercised** | Both environments used a self-managed Postgres with a non-superuser owner. Neon's default `neon_superuser` carries `BYPASSRLS`, which would make these RLS assertions vacuous — that interaction is covered by the existing boot refusal, not by this validation. |

### Evidence strength, stated honestly

Docker's matrix records 64 PASS / 1 N/A-env; EKS's 34 PASS / 11 N/A-env (the N/A rows are the
environment-independent ones Docker owned, plus the blocked run path). Raw artifacts —
request/response pairs, schema dumps, RLS probe transcripts, rollout timelines, boot logs — are
retained. Not every assertion has an independent raw capture; some are recorded as observed values
in the agents' matrices. Findings I regarded as load-bearing (D1, D2, D3, backfill parity, RunSpec
byte-identity, the rendered strategies) were re-verified directly rather than accepted from an
agent summary.

## 8b. Live agent run — the end-to-end governance loop, on BOTH providers

Added after the initial report, because a validation that never ran a real agent had not exercised
the workflow this PR exists to enable. Run on the **Docker provider** and then, separately, on the
**Kubernetes provider**. Real `ANTHROPIC_API_KEY` via the pinned LiteLLM gateway,
`claude-haiku-4-5` only, hermetic `postgres:16` with a non-superuser owner and
`FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime` in both (boot log: *"row-level security is ENFORCED for
this pool"*). Total model spend: **~$0.08**.

### Kubernetes provider (kind + Calico)

The EKS run could not create sessions at all (`503 sandbox network isolation is not yet verified`).
This closes that gap on a real Kubernetes deployment, and explains the EKS refusal. Cluster: kind
with `disableDefaultCNI` + **Calico v3.28** — chosen precisely because Calico genuinely enforces
NetworkPolicy, where the EKS vpc-cni standard-mode probe false-negatives. Chart installed from
`deploy/helm/fluidbox` with `values/kind.yaml`, server image the **same `adaa74c` build the EKS
agent verified** (`sha256:1e35c588…`), in-cluster `postgres:16`.

Observed on the cluster:

- `strategy.type = Recreate` on the live Deployment — a **third** independent confirmation of D1.
- *"row-level security is ENFORCED for this pool"* under `fluidbox_runtime`; `policy_versions`
  `relrowsecurity=t relforcerowsecurity=t`; schema at 26.
- **`POST /v1/sessions` → HTTP 200.** The netpol gate that blocked EKS passes under an enforcing
  CNI, confirming the EKS `503` was the probe, not a genuine isolation failure.
- Sandbox pod `2/2 Running`, and its per-run Secret carried exactly the four audience-scoped keys
  — `llm-token`, `session-token`, `tool-token`, `workspace-token` (Phase E invariant 19, live).
- `run_spec.policy_version == 2`, snapshot carrying the authored head rule.
- Driving `/internal/.../permission` with the **tool-audience** token produced the complete chain:
  `tool.requested` → `approval.requested` with
  `risk: "k8s-demo: v2 escalates ALL shell to a human (kubernetes provider)"` → (approve) →
  `approval.decided` `approved_once` → `tool.decision` **`verdict: allow`, `source: human`,
  `reason: human:operator`**.

So the loop — author, publish, attach, run, freeze, gate, approve, allow — is proven on **both**
providers, with the policy text authored through the new API surfacing verbatim in a human
approval prompt in each.

### Docker provider

**The PR's own loop is PROVEN end to end.**

1. `POST /v1/policies/clone` — `default` → `live-demo` v1.
2. `POST /v1/policies/live-demo/publish` with `base_version: 1` — v2, prepending a head rule
   `{match:["Bash"], action:"approve", risk:"live-demo: v2 escalates ALL shell to a human"}`.
3. `POST /v1/agents` — a new agent attached to `live-demo`, pinning an explicit runner image.
4. `POST /v1/sessions` — a real supervised run. Sandbox launched, real model traffic
   (`model.response` events carrying genuine token counts and cost).
5. **`run_spec.policy_version == 2`, and `run_spec.policy_snapshot` equals v2's `content` exactly**
   — the freeze, observed on a live run rather than inferred.
6. Driving `/internal/sessions/{id}/permission` with the session's **tool-audience** token and a
   `Bash` call produced `tool.requested` → `approval.requested`, a pending approval row, and —
   decisively — `risk: "live-demo: v2 escalates ALL shell to a human"`, **the exact string authored
   through the API in step 2**.

Step 6 is the load-bearing evidence: a policy authored through the new versioned API reached a
real human approval prompt, verbatim, via a frozen RunSpec. That is the user-facing loop, closed.

**A serious finding OUTSIDE this PR's scope, surfaced by the same exercise.**

A real agent's tool calls **did not reach the permission gate at all**. Proven, not inferred:

- Task designed so the answer cannot be fabricated — `printf '<random-nonce>' | sha256sum`. The
  agent returned the exact digest of a nonce generated seconds earlier
  (`cbd2c6c1…`, and again `6191925f…` on a second nonce). Executing the tool is the only way to
  produce that. **Bash really ran.**
- The ledger for those runs contains **zero** `tool.requested` / `tool.decision` /
  `approval.requested` events. That absence is meaningful: `internal.rs:1857-1865` *drops*
  runner-submitted `tool.requested` precisely because "tool.requested is server-authoritative —
  the gate writes it". If the gate had run, the event would exist.
- The governing frozen snapshot said `Bash → approve`.
- **Not a stale-image artifact:** reproduced with a runner image built fresh from current source
  during this session, carrying the same pinned `@anthropic-ai/claude-agent-sdk 0.3.205`.
- The runner is wired correctly in source — `canUseTool` passed to `query()`,
  `permissionMode: "default"`, `settingSources: []`, with the comment *"Everything routes through
  canUseTool → our gateway"* (`images/sandbox-runner/runner/index.mjs:102-157`).
- The sandbox could reach the control plane throughout — it posted `agent.message` events,
  heartbeats and its final `/result`. It simply never asked for permission.

So the **server-side gate is sound** (step 6 above, plus `governance-e2e.sh`, which drives
`/permission` directly). What is not happening is the **SDK harness invoking `canUseTool`**, which
means a live agent's tool calls are not being gated in this configuration.

**Attribution.** This is **not** a regression from PR #92. The PR touches the migration, policy
engine, storage layer, the policy handlers in `api.rs`, two lines of `run_service.rs`, `seed.rs`
and the dashboard. It does not touch `images/`, `internal.rs`, or the permission path. The
behaviour would be identical on `main`. It is reported here because this validation is what
surfaced it, and it warrants its own investigation — the most likely locus is how SDK 0.3.205
decides whether to consult `canUseTool`.

**Consequence for this report:** the PR's governance loop is validated; the *platform's* live
enforcement of it is not, and that gap is independent of the change under review.

## 9. Cross-environment parity

Consistent across both: migration behaviour and backfill parity, fold ordering, dropped columns,
constraint violations, `RunSpec` byte-identity, no-rollback failure mode, RLS enforcement,
append-only `42501` refusals, tenant isolation, the policy API's status codes and bodies, the
optimistic-concurrency 409 writing nothing, and restart persistence.

Two environment-specific differences, both explained and neither a PR regression:

1. **EKS blocks run creation** behind the NetworkPolicy enforcement probe (`503`). Docker has no
   equivalent gate. Fail-closed; pre-existing.
2. **EKS upgrade is `Recreate`** (~31s downtime) where a single-binary Docker deploy satisfies
   stop-the-old-binary trivially by construction.

## 10. Reproduction steps for the defects

**D1** — `helm template deploy/helm/fluidbox | grep -A2 'strategy:'` → `Recreate`;
`helm template deploy/helm/fluidbox --set server.archiveStore=s3 --set server.replicas=2 | grep -A2 'strategy:'`
→ `RollingUpdate`. Compare against the pre-fix `CHANGELOG.md:20`.

**D2** — `git show adaa74c:policies/default.yaml | sed -n '7p'` → the `just policy-sync` line;
`just --list | grep policy-sync` → absent.

**D3** — migrate a `0025` database holding a policy with `managed_overrides` to `0026`, create a
run on it, then compare `sessions.run_spec->'policy_snapshot'` with
`policy_versions.content` — semantically equal, not byte-equal.

## 11. Infrastructure

All validation infrastructure was ephemeral and labelled. Docker: `fbx-val-dkr-*` containers,
network and image, removed. EKS: cluster `fluidbox-eks` in `us-east-1` (account `471112572248`),
everything tagged `fluidbox-ephemeral=true`, torn down with a zero-orphan audit covering clusters,
instances, NAT gateways, EIPs, ENIs, security groups, VPCs, EBS volumes, load balancers,
CloudFormation stacks, ECR repositories and IAM/OIDC. Pre-existing unrelated infrastructure in the
same account (the `forceplatforms` VPC/NAT and a `DELETE_FAILED` ECS stack dating to 2025-01-08)
was identified and left untouched.

## 12. Verdict

**PASS WITH RISKS — merge-ready.**

The change does what it claims where it matters most: the migration folds and backfills correctly
under FORCEd RLS, frozen `RunSpec`s are byte-identical across it, append-only and tenant isolation
hold as database properties in the real deployment posture, optimistic concurrency is correct
under genuine simultaneity, and every "bug, not a state" path fails closed before provisioning or
spend. The upgrade is safe in the shipped default configuration, and the no-rollback boundary
fails loudly rather than silently.

The user-facing loop is proven on a real agent run (§8b): a policy version authored through the
new API reached a live human approval prompt verbatim, through a frozen RunSpec.

The risks are bounded and stated: one operator-facing instruction was wrong (now corrected), the
`s3`/multi-replica upgrade hazard is real but reproduced only at the mechanism level, and
non-admin RBAC was not exercised.

**One finding outside this PR's scope should not be lost in a PR review** (§8b): a live agent's
tool calls do not reach the permission gate — proven with an unfabricatable nonce digest and a
ledger with zero gate events, reproduced on a runner image built fresh from current source. The
server-side gate is sound; the SDK harness is not consulting it. This behaviour is identical on
`main` and blocks nothing here, but it deserves its own investigation.

This report describes what was validated and how strongly. It is not a correctness or robustness
guarantee.
