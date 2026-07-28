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
| **Frozen `RunSpec` byte-identity (P7)** | Docker md5 `4bc33fa8`, EKS md5 `7c073c08…` (len 2975) — **identical before and after** |

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

**Fixed:** `CHANGELOG.md` now states that the default needs no action and that only
`archiveStore: "s3"` requires the scale-to-zero. The mechanism is quoted so an operator can
recognise the symptom.

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
| Live agent run (model round-trip) | **Not tested** | Zero-spend mandate. The control-plane side — `RunSpec` freeze, fail-closed ordering, approval choreography — was exercised. |
| Run path on EKS (C5.1/C5.2/C6.3) | **Docker only** | EKS `POST /v1/sessions` → `503 sandbox network isolation is not yet verified on this cluster`. This is the **pre-existing** netpol boot gate under vpc-cni standard mode (a known chart follow-up), not a PR regression — and it is correct fail-closed behaviour. |
| `archiveStore: s3` RollingUpdate hazard | **Mechanism established, not live-reproduced** | Needs an S3 bucket. The rendered strategy and the `42703` error were both observed directly; the two coexisting under load were not. |
| API-level cross-tenant isolation | **DB layer only** | Single-tenant deployments; proven at the database layer under the runtime role, which is the stronger claim. |

### Evidence strength, stated honestly

Docker's matrix records 64 PASS / 1 N/A-env; EKS's 34 PASS / 11 N/A-env (the N/A rows are the
environment-independent ones Docker owned, plus the blocked run path). Raw artifacts —
request/response pairs, schema dumps, RLS probe transcripts, rollout timelines, boot logs — are
retained. Not every assertion has an independent raw capture; some are recorded as observed values
in the agents' matrices. Findings I regarded as load-bearing (D1, D2, D3, backfill parity, RunSpec
byte-identity, the rendered strategies) were re-verified directly rather than accepted from an
agent summary.

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

The risks are bounded and stated: one operator-facing instruction was wrong (now corrected), the
`s3`/multi-replica upgrade hazard is real but reproduced only at the mechanism level, and
non-admin RBAC and a live model run were not exercised here.

This report describes what was validated and how strongly. It is not a correctness or robustness
guarantee.
