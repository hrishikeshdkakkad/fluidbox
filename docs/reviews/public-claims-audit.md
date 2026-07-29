# Public claims audit

**Date:** 2026-07-29
**Tree:** `9515069` (main), worktree `worktree-prime-time-red-team`
**Method:** every material claim in the public-facing documents was extracted, then traced to executable evidence — a named test, an acceptance-script assertion, or a measured live observation. Claims traceable only to prose are classified accordingly. No implementation, test, or README was modified.

**Sources audited:** `README.md`, `SECURITY.md`, `docs/ARCHITECTURE.md`, `CHANGELOG.md`, `ROADMAP.md`, `PLAN.md` §2, `docs/hosted/*`, `deploy/helm/fluidbox/values.yaml`, and the GHCR/OCI install instructions.

## Classification scheme

| Class | Meaning |
|---|---|
| **PROVEN** | An executable artifact asserts the claim, and that artifact runs somewhere that gates change (CI on PRs, or a recorded live acceptance). |
| **PARTIALLY PROVEN** | The claim is true of part of its stated scope, or its evidence is real but narrower than the claim's wording. The narrowing is named. |
| **INFERRED** | Correct by reading the code, with no executable assertion — or the assertion exists but never runs automatically. |
| **CONTRADICTED** | Measured evidence shows the claim false, in whole or in a material part of its stated scope. |
| **UNTESTED** | No evidence either way was found in this pass. |

> **Evidence-strength caveat that colours this whole table.** `.github/workflows/ci.yml:417` gates the `e2e` job on `github.event_name == 'workflow_dispatch'`. The `identity`, `bindings`, `secrets`, `hardening`, and `scale` suites *do* run on every PR, and they are substantial. But **no CI job on any PR builds either runner image or runs a live agent**, and `.github/dependabot.yml` says so in its own comment: *"CI does not build these images."* Every claim about end-to-end agent behaviour therefore rests on manual runs, not on a gate.

---

## A. Enforcement and governance claims

### A1 — the central claim

> **"Canonical tool intents and MCP calls flow through the server-side decision gate for capability, trust, policy, approval, and budget checks."** — `README.md:72`
> **"A capability must exist in the frozen set and still pass trust, policy, approval, and budget checks at call time."** — `README.md:245`
> **"Every tool call still flows through the policy gateway and lands in the ledger in both modes."** — `PLAN.md:39` (convergence invariant 6)
> **"Each tool call passes the single decision gate."** — `docs/ARCHITECTURE.md:29`

**Verdict: CONTRADICTED for in-sandbox tools; PROVEN for brokered MCP tools.**

| | |
|---|---|
| **Contradicting evidence** | `docs/reviews/2026-07-27-pr92-two-environment-validation.md` §8b — live Claude Agent SDK run, Docker provider: `Bash` demonstrably executed (agent returned the SHA-256 of a nonce created seconds earlier, twice, two different nonces) while the ledger held **zero** `tool.requested` / `tool.decision` / `approval.requested` events, under a frozen `policy_snapshot` head rule of `{match:["Bash"], action:"approve"}`. Reproduced on an image built fresh from current source. Private advisory `GHSA-74v8-gg34-28q8` (draft). |
| **Why the absence is meaningful** | `internal.rs:1857-1865` *drops* runner-submitted `tool.requested` because the gate writes it server-authoritatively. If the gate had run, the event would exist. |
| **Where the claim holds** | Brokered MCP tools are executed **by the control plane** (`broker.rs`), so the gate is structural. Asserted by `scripts/hardening-e2e.sh` (CI job `hardening`, every PR). |
| **Why it is a class, not a one-off** | `@anthropic-ai/claude-agent-sdk@0.3.205`'s own `sdk.d.ts:4005` states the *"ask path surfaces via a can_use_tool control_request"* and that *"PreToolUse hook denies bypass canUseTool"*; `:3481` enumerates `sandboxOverride`/`rule`/`mode`/`hook`/`classifier` decision sources; `:5943` documents `autoAllowBashIfSandboxed`. `canUseTool` is an ask-path callback, not a chokepoint. |
| **Corrected wording that would be true** | *"Brokered MCP calls cannot execute without a server-side decision. In-sandbox tool calls are gated when the harness routes them; containment is the control that binds a harness that does not."* |

### A2

> **"Attach does not mean allow."** — `README.md:245`

**PARTIALLY PROVEN.** The frozen-set availability check, frozen-schema validation, and drift denial are real and asserted by `scripts/hardening-e2e.sh` (CI, every PR) — for tools the gate sees. It inherits A1's qualification for in-sandbox tools.

### A3

> **"Fork PRs lose their MCP surface and receive a read-only trust floor that approvals cannot widen."** — `README.md:245`

**PARTIALLY PROVEN — the two halves have different strengths, and only the weaker one is load-bearing against a hostile PR.**

- *MCP stripping:* **PROVEN and structural.** `bindings.rs:143` and `run_service.rs:532` strip MCP for `TrustTier::ReadOnly` **before provisioning**; unit-tested at `bindings.rs:1650`. No gate involvement.
- *Read-only floor on `Bash`/`Edit`/`Write`:* **CONTRADICTED in composition.** `read_only_denial()` is applied **inside the permission gate** (`internal.rs:444-445`), so it inherits A1 wholesale. A fork PR checks out **attacker-controlled content** at the PR head SHA (`connectors/github.rs:148-158`) into a sandbox whose default network mode is `HostDev`.
- *Fork detection itself:* **PROVEN.** Fails toward fork; `connectors/github.rs:1602-1618`.

### A4

> **"The permission callback stays wired in both autonomy modes — never the SDK's `bypassPermissions`."** — `PLAN.md:39`, `docs/ARCHITECTURE.md:54`, `docs/hosted/threat-model.md:67`

**PROVEN as literally written, but it answers the wrong question.** `images/sandbox-runner/runner/index.mjs:148-156` sets `permissionMode: "default"` and `settingSources: []`; `bypassPermissions` appears nowhere. The claim establishes *the callback is wired*. The security property needed is *the callback is invoked* — which A1 shows is not established. The hosted threat model lists this control against the attack *"Bypass the permission callback"*; the control does not address that attack.

### A5

> **"Autonomous ≠ ungoverned … never *whether* it is asked."** — `PLAN.md:39`

**PROVEN in the evaluator, INHERITS A1 end to end.** `policy.rs` rewrites `RequireApproval` to the fallback inside `evaluate()`, recording both verdicts; `AutonomousFallback::default() == Deny` (`policy.rs:223-225`) is fail-closed. Asserted by `scripts/governance-e2e.sh` — which, per issue #99, *kills the real runner and drives `/permission` itself*, so it validates the server and cannot validate the harness.

### A6

> **"Approvals are idempotent by `(session_id, tool_call_id)`."** — `CLAUDE.md`, `docs/ARCHITECTURE.md:29`

**PROVEN.** `internal.rs:224-268` — one intent row per `(session, tool_call_id)`, digest-bound, mismatch hard-denies without touching the stored verdict. Asserted by `scripts/governance-e2e.sh` and `scripts/hardening-e2e.sh`.

### A7

> **"Authority is frozen before spend. Policy, capability schemas, trust tier, budgets, workspace, agent revision, and invocation are stored in the `RunSpec`; later edits affect future runs only."** — `README.md:244`

**PROVEN, and unusually well.** Frozen `run_spec` measured **byte-identical** across migration `0026` — which drops four columns — on two independent Docker-provider deployments (`docs/reviews/2026-07-27-pr92-two-environment-validation.md` §5, P7). Live run confirmed `run_spec.policy_snapshot == policy_versions[v2].content` exactly (ibid. §8b). *Caveat recorded there:* not established on EKS, because that cluster could not create a session (see C3).

### A8

> **"Audit is redacted by construction. The append path accepts only `Redacted<EventEnvelope>` values."** — `README.md:246`

**PROVEN.** Type-level: constructible solely via `Redactor::scrub` (`fluidbox-core/src/event.rs`). Tests pin that `fbx_sess_`/`fbx_web_`/`fbx_pat_` are scrubbed. `scripts/secrets-e2e.sh` section (k) greps every per-boot server log for secret leakage (CI job `secrets`, every PR).

### A9

> **"`append_event()` assigns a gapless per-session `seq` under a row lock and `pg_notify`s."** — `CLAUDE.md`

**INFERRED.** Correct by reading the SQL function; no adversarial gap/forgery test found. Note the composition risk: a ledger with no gate events is indistinguishable from a run that used no tools — the audit trail is gapless with respect to *recorded* intents, which is not the same as complete with respect to *executed* actions.

---

## B. Credential and isolation claims

### B1

> **"No real upstream credential is placed in a sandbox."** — `README.md:242`

**PROVEN.** The strongest claim in the product and it holds. Sandbox env is built from `spec.env` only (`fluidbox-provider/src/lib.rs:103`); the LLM key lives solely in the LiteLLM container; git credentials ride ephemeral `GIT_CONFIG_*`; brokered credentials are unsealed only inside `broker.rs`. Asserted by `scripts/secrets-e2e.sh` and the k8s `token-never-leaks` manifest test (`.github/workflows/k8s.yml` job `unit`, every relevant PR).

### B2

> **"Isolation is provider- and profile-specific. Kubernetes defaults to a `zeroEgress` sandbox namespace and blocks run admission until a probe proves the cluster's CNI enforces NetworkPolicy. Docker hardened mode uses an internal bridge. Docker's default `host-dev` mode is intentionally convenient and is not a structural zero-egress boundary."** — `README.md:243`

**PROVEN as a statement about defaults and admission — and it is commendably honest about `host-dev`.** Two qualifications the wording does not carry:

1. **[Docker]** `HostDev` is not merely "not zero-egress" — it also injects `host.docker.internal:host-gateway` (`fluidbox-provider/src/lib.rs:118`), giving the sandbox the host's LAN position. It is the `#[default]` (`fluidbox-core/src/traits.rs:88`), so the *recommended quickstart* runs it.
2. **[Kubernetes]** The probe proves the CNI enforces policy *for one probe pod at boot*. `netpol.rs:98-105` samples both assertions once, at container start; the 90 s deadline at `:120` bounds scheduling, not the assertions. It cannot establish enforcement for a sandbox pod created later, during that pod's own programming window. See C3.

### B3

> **"The sandbox holds four audience-scoped tokens, not one bearer."** — `CHANGELOG.md` v0.3.0, `docs/hosted/threat-model.md:68`

**PROVEN.** `require_audience` as the first statement of every guarded handler (`internal.rs:1846`, `:1880`); `scripts/hardening-e2e.sh` runs an **exhaustive route × audience matrix** asserting the body is byte-equal to `{"error":"wrong_audience"}` (CI, every PR). Observed live on kind: the per-run Secret carried exactly `llm-token`, `session-token`, `tool-token`, `workspace-token` (`2026-07-27` report §8b). The `ptrace` residual is correctly disclosed.

### B4

> **"Workspace init is control-plane-side … The original repo is never touched, and the sandbox stays egress-free."** — `CLAUDE.md`; `docs/ARCHITECTURE.md:26`

**PARTIALLY PROVEN / MISLEADING.** Control-plane-side materialisation: **PROVEN**. *"The sandbox stays egress-free"*: **CONTRADICTED on the Docker default** — that is a property of `Hardened` and of the Kubernetes `zeroEgress` profile, not of `HostDev`. The README (B2) is accurate about this; `docs/ARCHITECTURE.md:26` and `CLAUDE.md` are not.

### B5

> **"Tenant isolation is a signature requirement, not a remember-to-filter convention."** + RLS depth — `README.md:103`, `CHANGELOG.md` v0.3.0

**PROVEN — the best-evidenced claim in the product.** `TenantScope` in every tenant-owned repository signature; 37 tables `ENABLE`+`FORCE` RLS. Probed as the non-owner `fluidbox_runtime` role (`rolbypassrls=f`) on a live EKS deployment *and* independently on Docker: correct rows per tenant GUC, zero rows without it, cross-tenant write refused by the `WITH CHECK` arm, `UPDATE`/`DELETE` → `42501` (`2026-07-27` report §6). CI runs the negative matrix under the runtime role in three jobs on every PR. The disclosed caveats (shared catalog rows readable by design; RLS inert for SUPERUSER/BYPASSRLS; `SET ROLE` is not a credential boundary) are all stated correctly in `docs/hosted/threat-model.md:93-113`.

### B6

> **"Per-tenant envelope encryption with static or AWS KMS KEKs."** — `README.md:103`

**PROVEN.** `scripts/secrets-e2e.sh` sections (a)–(k) cover the KMS boot matrix, the bidirectional retirement gate, re-seal count parity, and a dump/wipe/restore drill (CI job `secrets`, every PR). AAD binding `fbx:v2:{tenant}:{table.column}` makes a blob untransplantable across tenants and columns.

### B7

> **"Credentials are supposed to be sealed at rest and only ever used control-plane-side."** — `SECURITY.md:20`

**PROVEN**, with one honest gap already disclosed: `FLUIDBOX_CREDENTIAL_KEY` rotation orphans v1 blobs unless the re-seal ran first — stated at `SECURITY.md:36` and in the KMS runbook.

---

## C. Deployment and operations claims

### C1

> **"Docker — fastest path … The eval stack uses bundled Postgres and a well-known admin token … It is for trying the run loop, not for exposing to a network."** — `README.md:118-129`

**CONTRADICTED.** The sentence states an intent the file does not implement.

- `deploy/docker-compose.eval.yml:48-49` publishes `"8787:8787"`; `:77-78` publishes `"3000:3000"`. Docker's short syntax with no host-IP prefix binds **`0.0.0.0`** — every interface. The sibling `docker-compose.dev.yml:21,42` *does* prefix with `127.0.0.1`, so this is an omission, not a house style.
- `:53` defaults `FLUIDBOX_ADMIN_TOKEN` to the literal `fluidbox-eval-only`, published in this repository.
- `:63` bind-mounts `/var/run/docker.sock` into the server container.
- An Operator may name **any** control-plane host path as a `local_copy` workspace — the guard is *operator-only*, not path-constrained (`api.rs:105-140`).

Net: on any shared network, the quickstart the README lists **first** hands full admin authority — and thence host-file disclosure via `local_copy` + `HostDev` egress — to any adjacent host. See [`prime-time-red-team.md`](prime-time-red-team.md) §BLK-04.

### C2

> **"`just check` — Run format, Clippy with `-D warnings`, Rust tests, and the web build."** — `README.md:172`

**PROVEN.** Matches CI job `rust` + `web`, both on every PR. `850 passed / 0 failed` independently reproduced (`2026-07-27` report §4).

### C3

> **"Kubernetes … Required acceptance check: `helm test fluidbox` proves +:8788 internal reachability and −:8787 public-plane isolation from the sandbox namespace."** — `README.md:270-272`

**CONTRADICTED on EKS; PROVEN on kind + Calico.**

- **[MEASURED]** On EKS 1.33 with VPC CNI `standard` mode — the configuration `scripts/eks-cluster.yaml` itself prescribes — the probe can **never** pass, so `POST /v1/sessions` is permanently `503` and no run can be created (`2026-07-27` report §8c; issue #96). Fails closed.
- Root cause is in this tree: `netpol.rs:98-105` samples both assertions the instant the probe container starts; the CNI programs policy asynchronously and fails **open** meanwhile (measured: reachable at t=0, blocked at t=20s).
- **[INFERRED]** The same window applies to sandbox pods, so a sandbox has unrestricted egress for its first seconds on `standard` mode — and a *passing* probe (Calico) certifies a different pod at a different time, not the sandbox that runs later.

### C4

> **"Live EKS acceptance evidence: 2026-07-17 … 2026-07-22 …"** — `README.md:279`

**PROVEN as history, STALE as current-state evidence.** Both acceptances are real and AWS-audited. Both predate the 2026-07-28 measurement of C3. A reader takes "live EKS acceptance" to mean *EKS works today*; on the prescribed configuration, run creation does not.

### C5

> **"The Helm chart … Production should pin image digests and supply credentials through the existing Secret; the chart never generates credential material."** — `README.md:275`

**PROVEN.** Verified by reading `deploy/helm/fluidbox/templates/*`; asserted by `deploy/helm/chart-assertions.sh` in the `k8s` workflow `chart` job.

### C6

> **"`just doctor` checks the documented failure points … and prints the concrete fix."** — `README.md:154`

**INFERRED.** `scripts/doctor.sh` (26.7 kB) covers the documented gotchas including the unbootable RLS combination. No test asserts doctor's own correctness; it is not run in CI.

### C7

> **"Multi-replica deployments additionally require the S3 archive backend."** — `README.md:112`

**PROVEN.** Boot refuses `fs` with `replicas > 1` (`values.yaml:52`). Note the coupled hazard, correctly documented in `CHANGELOG.md` after the 2026-07-27 validation: `archiveStore: "s3"` is the *only* configuration rendering `RollingUpdate`, and it is also the production multi-replica shape — so the column-dropping-migration precaution applies exactly there, with no values knob to change it.

---

## D. Scope, maturity, and supply-chain claims

### D1

> **"`v0.3.0` therefore does not claim a proven 300-run production ceiling; capacity and residual-risk sign-off remain deployment gates."** — `README.md:114`

**PROVEN — and a model of how to state a limit.** Matches `docs/hosted/rollout-gates.md` Gates 3–5 and issue #34. No correction needed.

### D2

> **"The acceptance suites cover the Rust control plane, dashboard, both harnesses, event paths, connectors, identity and tenant isolation, and provider-specific isolation checks."** — `README.md:316`

**PARTIALLY PROVEN.** The suites exist and are substantial. Two omissions the sentence does not carry:

- The suites covering **both harnesses** (`scripts/e2e*.sh`) run only on `workflow_dispatch` (`ci.yml:417`); they do not gate a PR or a release.
- Issue #100 records **4 pre-existing failures** in the full e2e (phases 7/8/9). "Cover" is true; "pass" is not currently true.

### D3

> **"Contributions … run `just check`, and run `just e2e` for changes that touch a governance path."** — `README.md:322`

**PROVEN as instruction, UNENFORCED as gate.** Nothing in CI verifies that `just e2e` was run. This is precisely the hole through which A1 reached a release: the only suite that runs a live agent is the one no gate requires.

### D4

> **"Pin both runner images to this release."** — `README.md:112`

**PROVEN as advice, INFERRED as achievable, and materially weakened by D5.** `runner_image` is a per-revision field, so pinning works. But an image tag does not identify content here — see D5.

### D5 — supply chain *(claim by omission)*

No public document claims signed or reproducible artifacts, but `README.md:257-273` instructs users to `helm install oci://ghcr.io/...` and `docker compose pull` published images. Audited against what a consumer can verify:

| Property | Status | Evidence |
|---|---|---|
| Images signed | **No** | `release.yml` has no cosign/sigstore step |
| SBOM published | **No** | `docker/build-push-action` invoked without `sbom:` (`release.yml:69-76`) |
| Build provenance attested | **No** | multi-arch index assembled via `docker buildx imagetools create` from bare digests (`:125-127`), which does not carry attestations forward |
| Helm chart signed | **No** | `helm package` without `--sign` (`:166`) |
| Actions pinned by SHA | **No** | `actions/checkout@v7`, `docker/build-push-action@v7`, `docker/login-action@v4`, `azure/setup-helm@v4` — mutable tags in a job holding `packages: write` |
| Release gated on tests | **No** | `release-please.yml:15-16`: *"Publishing is UNGATED by deliberate choice."* |
| **Runner images reproducible** | **No** | No lockfile exists for either runner (`find . -name package-lock.json` → only `apps/web/pnpm-lock.yaml`). Both Dockerfiles run `npm install --omit=dev` against exact-pinned *direct* deps with a **floating transitive tree**. Two builds of `:0.3.0` are different artifacts. |
| **Runner deps monitored** | **No** | `.github/dependabot.yml` covers cargo `/`, npm `/apps/web`, github-actions, and docker *base images* for `/images/*` — **no npm ecosystem entry for either runner directory**. The code that runs beside the workspace gets no CVE alerts. |

**Classified UNTESTED→CONTRADICTED by implication:** `SECURITY.md:3` states fluidbox's core promise is *"containment and accountability for AI coding agents."* Unsigned, unattested, non-reproducible artifacts are a mismatch with that promise, and `docs/hosted/threat-model.md:167` places this out of scope on the grounds that *"release signing"* is a process control — but there is no release signing.

### D6

> **"You can expect an acknowledgement within 72 hours and an assessment … within a week."** — `SECURITY.md:13`

**UNTESTED** — a process commitment; no evidence sought. Noted only because a public launch materially raises the inbound volume against a single maintainer (`.github/CODEOWNERS`).

### D7

> **"fluidbox is pre-1.0 security software. Its guarantees come from explicit boundaries, not from the agent behaving well."** — `README.md:240`

**CONTRADICTED in the specific case that matters most.** For in-sandbox tools the guarantee currently *does* depend on the harness behaving well — not the agent's *reasoning*, but the agent runtime's *cooperation*. This sentence is the clearest single statement of the property A1 shows is not held, which is why it is listed here rather than under A.

---

## E. Summary

| Class | Count | Claims |
|---|---:|---|
| **PROVEN** | 13 | A4*, A6, A7, A8, B1, B3, B5, B6, B7, C2, C5, C7, D1 |
| **PARTIALLY PROVEN** | 6 | A2, A3, B2, B4, D2, D4 |
| **INFERRED** | 3 | A9, C6, D3 |
| **CONTRADICTED** | 6 | **A1**, A3 (read-only floor half), **C1**, **C3**, B4 (egress-free half), **D7**, D5 (by implication) |
| **UNTESTED** | 1 | D6 |

\* A4 is proven as written but does not establish the property it is cited for.

**The four that block a public launch on their own:** **A1** (the central enforcement claim, measured false for in-sandbox tools), **C1** (the first-listed install path is remotely exploitable by default), **C3** (the flagship cloud target cannot create runs, and the enforcement proof measures the wrong pod), **D5** (unsigned, unmonitored, non-reproducible sandbox-resident artifacts). Ranked with reproduction paths and acceptance tests in [`../launch/launch-blockers.md`](../launch/launch-blockers.md).

**What deserves explicit credit.** D1, B2's `host-dev` sentence, `docs/hosted/threat-model.md`'s 17-row residual table, and its self-correction at `:194-204` retracting a previously-claimed closure are all examples of a project stating its limits before an auditor forces it to. The findings above are concentrated in claims about the *default* paths — the quickstart, the harness, the cloud preset — not in the deliberately-scoped hosted claims, which largely hold.
