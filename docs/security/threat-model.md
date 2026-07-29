# fluidbox security threat model — adversarial edition

**Date:** 2026-07-29
**Author:** independent red-team pass (no implementation changes; reports only)
**Scope:** the whole product as shipped at `9515069` — Docker profile, Kubernetes profile, eval profile, both harnesses, hosted multi-user posture.
**Relationship to [`../hosted/threat-model.md`](../hosted/threat-model.md):** that document is the *builder's* threat model for the hosted multi-user deployment. It is unusually honest and most of its rows hold. This document is the *attacker's* model for the whole product, and it exists because the hosted model has one structural blind spot (§1) plus a set of defaults (§4) that fall outside its stated scope. Where the two disagree, the disagreement is stated explicitly and the evidence is cited.

> **Reading rule.** Every claim below is tagged with how it was established:
> **[MEASURED]** — observed against a running deployment (citation given);
> **[CODE]** — read from source at a named file:line in this tree;
> **[INFERRED]** — reasoned from [CODE]/[MEASURED] facts, not directly observed.
> Nothing here is asserted from documentation alone.

---

## 1. The structural finding: the gate is a control against T1, not against T2

### 1.1 What the documents claim

Four load-bearing statements, from four different documents:

| Source | Claim |
|---|---|
| `README.md:245` (Security boundaries) | *"A capability must exist in the frozen set and still pass trust, policy, approval, and budget checks at call time."* |
| `README.md:72` (One event, one governed run) | *"Canonical tool intents and MCP calls flow through the server-side decision gate."* |
| `PLAN.md:39` (convergence invariant 6) | *"Every tool call still flows through the policy gateway and lands in the ledger in both modes."* |
| `docs/hosted/threat-model.md:11` (core assumption) | *"everything the sandbox **can** do passes the control plane's single decision gate."* |

### 1.2 What the architecture actually provides

fluidbox has **two structurally different tool classes**, and the documents describe them with one sentence:

| Class | Who executes the tool | What the gate is |
|---|---|---|
| **Brokered MCP** (`mcp__*` on a connection) | **The control plane** (`broker.rs`), holding the sealed credential | A **chokepoint**. The call cannot happen without the server doing it. Enforcement is structural. |
| **In-sandbox** (`Bash`, `Edit`, `Write`, `Read`, sandbox-class stdio MCP) | **The sandbox itself**, via the harness process | An **advisory callback**. The server answers a question; it never executes anything and never observes execution. |

**[CODE]** The gate for in-sandbox tools is reached only when the runner posts to `/internal/sessions/{id}/permission`. The Claude harness does this from `canUseTool` (`images/sandbox-runner/runner/index.mjs:102-123`); the Codex harness does it from an approval-request handler driven by `approval_policy = "untrusted"` plus an execpolicy `prompt` rule (`images/codex-runner/config.toml:29`, `images/codex-runner/rules/default.rules`).

**[CODE]** The server explicitly refuses to trust the runner's *reported* events — `internal.rs:1857-1865` drops a runner-submitted `tool.requested` because "the gate writes it server-authoritatively." That is a defence against **double-counting and forgery**. There is **no** corresponding defence against **omission**: nothing in `internal.rs`, `orchestrator.rs`, or `workers.rs` detects or penalises a session that reaches a terminal state having produced a diff with zero `tool.decision` events.

**[CODE]** The comment at `internal.rs:1859` reads *"budget parity never trusts runner cooperation."* Precisely stated, the system does not trust what the runner **says**; it depends entirely on the runner **asking**.

### 1.3 The consequence for the declared adversaries

`docs/hosted/threat-model.md:29-30` declares:

- **T1** — prompt-injected / misbehaving model: *"Full control of tool-call intents and sandbox-side output."*
- **T2** — compromised sandbox workload: *"Arbitrary code execution inside the pod/container, including reading the process environment."*

Against **T1** the gate is a real control: a misled model emits a tool *intent*, the harness routes it, the server decides. Against **T2** it is not a control at all, because a workload with arbitrary code execution is not obliged to route anything. Both adversaries are declared in scope and the same mitigation is claimed for both.

**[INFERRED]** This is not a subtle gap. The claim *"everything the sandbox can do passes the control plane's single decision gate"* cannot be true of a workload that, by the same document's assumption, executes arbitrary code. The only controls that bind T2 are containment controls: network egress, filesystem scope, disposability, and credential absence.

### 1.4 The measured instance

**[MEASURED]** `docs/reviews/2026-07-27-pr92-two-environment-validation.md` §8b: a live Claude Agent SDK run on the Docker provider executed `Bash` — proven by returning the SHA-256 of a nonce generated seconds earlier, twice, with two different nonces — while the session ledger contained **zero** `tool.requested`, `tool.decision`, or `approval.requested` events, under a frozen `policy_snapshot` whose head rule was `{match:["Bash"], action:"approve"}`. Reproduced on a runner image built fresh from current source. Filed as private advisory `GHSA-74v8-gg34-28q8` (draft).

This is the **benign** manifestation: not an attacker suppressing the callback, but the SDK never issuing it.

### 1.5 Why it is a class, not a one-off

**[CODE]** `@anthropic-ai/claude-agent-sdk@0.3.205` — the exact pinned version (`images/sandbox-runner/runner/package.json:8`) — documents `canUseTool` as the handler for the **ask** path only. From its own bundled type definitions:

| `package/sdk.d.ts` | What it establishes |
|---|---|
| `:4005` | *"Emitted when a tool call is auto-denied without an interactive permission prompt (e.g. auto-mode classifier, dontAsk mode, headless-agent auto-deny, or a deny rule). **The 'ask' path surfaces via a can_use_tool control_request**… **PreToolUse hook denies bypass canUseTool**."* |
| `:3481` | `decision_reason_type` includes `'sandboxOverride'`, `'rule'`, `'mode'`, `'hook'`, `'classifier'` — five decision sources that resolve a call without an ask. |
| `:5943` | `sandbox.autoAllowBashIfSandboxed?: boolean` — a setting whose entire purpose is to auto-allow `Bash` when the CLI believes it is sandboxed. |
| `:1335` | `allowedTools?: string[]` — pre-approval that never reaches the callback. |
| `:1716` | `permissionPromptToolName` — routes permission requests to a different handler entirely. |

**[INFERRED]** fluidbox sets `permissionMode: "default"` and `settingSources: []` (`index.mjs:148-156`), which is the correct and careful configuration. But the security property fluidbox needs — *"no tool executes without the server deciding"* — is not a property the SDK offers under any configuration. `canUseTool` is a **UI hook for the ask path**, and the set of paths that resolve without asking is defined by the SDK, changes between SDK versions, and is not under fluidbox's control.

**[INFERRED]** The same class applies to Codex by a different mechanism. `images/codex-runner/rules/default.rules` is a hand-enumerated list of ~29 basenames plus ~150 absolute-path spellings, written to defeat Codex's built-in `is_known_safe_command` auto-run. The file discloses its own residual: a relative-path spelling (`./cat`) is not caught (tracked as issue #15). An enumeration of spellings is a denylist; the gate's reachability is only as complete as the enumeration.

### 1.6 Restating the model honestly

The accurate statement of what fluidbox enforces is:

> **Brokered MCP tools cannot execute without a server-side decision — structurally, because the server executes them.**
> **In-sandbox tools are gated when the harness cooperates.** Cooperation is a property of a pinned third-party agent runtime, not of the control plane. For in-sandbox tools the control plane provides *evidence and intent-time policy for a cooperating harness*, and **containment** — not the gate — is the control that binds a non-cooperating one.

Every downstream claim (fork-PR read-only floor, autonomy fallbacks, per-tool policy, budget-per-tool-call counting) inherits this qualification for in-sandbox tools, because all of them are evaluated at the same gate.

---

## 2. Assets

Unchanged from `docs/hosted/threat-model.md:15-24` — A1 credentials, A2 identity secrets, A3 tenant data, A4 spend, A5 audit integrity, A6 infra secrets, A7 external side-effect authority. One asset is under-weighted there and is promoted here:

| # | Asset | Where it lives | Why promoted |
|---|---|---|---|
| **A8** | **The workspace content itself** — the operator's source code, or, for a fork-PR run, the *base repository's* source | Bind-mounted at `/workspace` in the sandbox (`fluidbox-provider/src/lib.rs:111`) | The credential-inversion design deliberately keeps A1 out of the sandbox and succeeds at it. But the whole point of a coding agent is that A8 **is** in the sandbox. On the default Docker profile A8 is exfiltratable by any code the agent runs, with no gate and no egress boundary. |
| **A9** | **The control-plane host's filesystem and LAN position** | Reachable from the sandbox in `NetworkMode::HostDev` via the injected `host.docker.internal:host-gateway` (`fluidbox-provider/src/lib.rs:118`) | Not modelled anywhere today. |

---

## 3. Adversaries

T1–T10 as declared in the hosted model, with three corrections and two additions.

| # | Adversary | Correction / addition |
|---|---|---|
| **T1** | Prompt-injected model | Unchanged. The gate **is** a real control here. |
| **T2** | Compromised sandbox workload | **Correction: the single decision gate is not a mitigation for this adversary on in-sandbox tools** (§1). Only containment binds T2. |
| **T3** | Malicious remote MCP server | Unchanged and well-covered — the broker path is the structurally-enforced one. |
| **T4/T5** | Insider / cross-tenant | Unchanged. `TenantScope` + RLS is genuinely strong and independently validated (`docs/reviews/2026-07-27-pr92-two-environment-validation.md` §6). |
| **T6** | Unauthenticated network attacker | **Extended: on the eval profile the attacker needs no credential at all** (§4.1). |
| **T7** | Stolen-credential holder | Unchanged. |
| **T8** | Compromised org IdP | Unchanged. |
| **T9** | Malicious connector definition | Unchanged; Phase E admission is real. |
| **T10** | Operator error | **Extended: the shipped defaults are themselves an operator-error amplifier** (§4). |
| **T11** | **Unauthenticated GitHub user (new)** | Anyone with a GitHub account who can open a pull request against a repository carrying a fluidbox automation. Controls: the entire workspace contents, the PR title/body/diff, and therefore the agent's prompt context. Requires no membership, no token, no prior relationship. **This is the lowest-privilege adversary in the model and the one with the widest reach.** |
| **T12** | **Upstream harness/runtime maintainer (new)** | Whoever ships `@anthropic-ai/claude-agent-sdk` or `@openai/codex` and their transitive trees. Not an attacker per se — but §1.5 and §5.2 show fluidbox's central security property and its sandbox-resident code are both delegated to this party, with no lockfile and no monitoring. |

---

## 4. Attack chains

Each chain is composed only of facts established above. Deployment profile is stated because the chains do not all apply everywhere.

### 4.1 Chain A — remote takeover of the eval quickstart *(profile: eval; adversary: T6)*

The README's **first** and most prominent installation path (`README.md:118-129`).

| Step | Fact | Citation |
|---|---|---|
| 1 | The compose publishes the control plane as `"8787:8787"` and the dashboard as `"3000:3000"`. Docker's short syntax without a host-IP prefix binds **`0.0.0.0`**. The sibling dev compose *does* prefix (`"127.0.0.1:5433:5432"`), so the omission is not a house style. | `deploy/docker-compose.eval.yml:48-49,77-78` vs `deploy/docker-compose.dev.yml:21,42` **[CODE]** |
| 2 | `FLUIDBOX_ADMIN_TOKEN` defaults to the literal `fluidbox-eval-only`, published in this repository. | `deploy/docker-compose.eval.yml:53` **[CODE]** |
| 3 | Therefore any host on the same L2/L3 segment — coffee shop, hotel, corporate LAN, a compromised device on a home network — holds full `/v1` admin authority. | **[INFERRED]** |
| 4 | An Operator principal may specify a `local_copy` workspace naming **any control-plane host path**, with no allowlist. The restriction is *"operator only"*, not *"path-constrained"*. | `crates/fluidbox-server/src/api.rs:105-140` **[CODE]** |
| 5 | The server container has `/var/run/docker.sock` bind-mounted. | `deploy/docker-compose.eval.yml:63` **[CODE]** |
| 6 | Sandboxes default to `NetworkMode::HostDev` — general egress, plus `host.docker.internal:host-gateway`. | `crates/fluidbox-core/src/traits.rs:88`, `crates/fluidbox-provider/src/lib.rs:118` **[CODE]** |

**Chain:** LAN attacker → admin API with a published token → create a run whose workspace is `local_copy: /` (or `~/.ssh`, `/etc`) → control plane copies host files into the workspace → agent reads them → HostDev egress exfiltrates. Steps 1–2 are also sufficient on their own for full tenant data disclosure (all sessions, ledgers, artifacts, connection metadata) and for unbounded model spend against the operator's `ANTHROPIC_API_KEY`.

`README.md:129` says *"It is for trying the run loop, not for exposing to a network."* **The compose exposes it to the network by default**; the sentence describes an intent the file does not implement.

### 4.2 Chain B — ungated execution from a fork pull request *(profile: Docker + GitHub App; adversary: T11)*

This is the highest-severity chain because the adversary is unauthenticated and the trigger is a normal, welcome action on a public repository.

| Step | Fact | Citation |
|---|---|---|
| 1 | A fork PR is detected and the run is frozen at `TrustTier::ReadOnly` with `CheckoutMode::ReadOnly`. Detection fails *toward* fork. This part is correct and well-built. | `crates/fluidbox-server/src/connectors/github.rs:132-145` **[CODE]** |
| 2 | The workspace is materialised at the **PR head SHA** — i.e. **content the attacker fully controls** — served from the base repo's clone URL. | `crates/fluidbox-server/src/connectors/github.rs:148-158` **[CODE]** |
| 3 | MCP surfaces *are* stripped structurally for `ReadOnly` (in `bindings.rs:143` and `run_service.rs:532`, before provisioning). **This half genuinely holds.** | **[CODE]** |
| 4 | The read-only floor for `Bash`/`Edit`/`Write` is **not** structural. `read_only_denial()` is applied **inside the permission gate**. | `crates/fluidbox-server/src/internal.rs:444-445`; `crates/fluidbox-core/src/policy.rs:991-996` **[CODE]** |
| 5 | Therefore, wherever the gate is not reached (§1.4, measured), the read-only floor is not reached either. | **[INFERRED]** |
| 6 | Default sandbox egress is `HostDev`. | `crates/fluidbox-core/src/traits.rs:88` **[CODE]** |

**Chain:** attacker opens a PR from a fork → fluidbox provisions a sandbox and mounts the attacker's code → attacker's `README`, source comments, PR title/body and diff are all prompt-injection surface reaching the model → agent runs `Bash` → (measured) no gate, no read-only floor, no ledger record → arbitrary command execution inside a container on the operator's host, with general network egress and reachability of the host gateway.

**Bounded by:** no upstream credentials in the sandbox (that inversion holds); `cap_drop: ALL` + `no-new-privileges` + 2 GB / 512-pid limits (`fluidbox-provider/src/lib.rs:127-130`); the container is disposable. **Not bounded by:** the policy engine, the trust tier, approvals, or the ledger.

**On Kubernetes** step 6 is materially better — `egressProfile: zeroEgress` is the chart default (`deploy/helm/fluidbox/values.yaml:243`) and `netpol.requireEnforced: true` (`:315`) blocks run admission without proof. Steps 1–5 are identical. §4.3 qualifies how much step 6 actually buys.

### 4.3 Chain C — the network-enforcement probe measures the wrong thing *(profile: Kubernetes; adversary: T2/T11)*

**[CODE]** `crates/fluidbox-provider-k8s/src/netpol.rs:98-105` builds the probe as a single shell line: `nc -z -w 4 <internal> 8788` then `nc -z -w 4 <public> 8787`, both executed **the instant the probe container starts**. The 90-second deadline at `:120` bounds *pod scheduling*, not the assertions — there is no retry of the connectivity tests.

**[MEASURED]** `docs/reviews/2026-07-27-pr92-two-environment-validation.md` §8c, on EKS 1.33 with VPC CNI in `standard` enforcing mode, from a pod carrying the sandbox's own `fluidbox.dev/managed=true` label:

```
t=0s   1.1.1.1:443 -> REACHABLE   <- policy not yet programmed
t=20s  1.1.1.1:443 -> BLOCKED
t=60s  1.1.1.1:443 -> BLOCKED
```

Two consequences, and the second is the one that is not yet tracked:

**Availability (tracked as issue #96).** Every probe pod is new, so it always samples the fail-open window; the gate can never pass on the configuration `scripts/eks-cluster.yaml` prescribes, so `POST /v1/sessions` is permanently `503`. **Fails closed** — an availability defect, not a vulnerability.

**Security (untracked, and the more important half).** **[INFERRED]** The same asynchronous programming applies to **sandbox** pods. A sandbox therefore has unrestricted egress for the first seconds of its life on `standard` mode. And structurally: the boot probe certifies **a different pod, at a different time, once per process lifetime**. It cannot establish a property of a sandbox pod created ten minutes later. A *passing* probe on Calico is evidence that the CNI enforces policy in general — it is **not** evidence that any given sandbox was isolated during its own startup window.

`README.md:243` says Kubernetes *"blocks run admission until a probe proves the cluster's CNI enforces NetworkPolicy."* That is a true statement about admission. It is routinely read as *"every sandbox is enforced from t=0,"* which the mechanism does not establish. `strict` mode would close the window but is documented as starving CoreDNS/EBS-CSI. **Neither shipped mode delivers per-pod enforcement at t=0.**

### 4.4 Chain D — supply chain into the sandbox *(all profiles; adversary: T12)*

| Step | Fact | Citation |
|---|---|---|
| 1 | Both runner Dockerfiles run `npm install --omit=dev` against a `package.json` with **no lockfile anywhere in the repository**. | `images/sandbox-runner/Dockerfile:17`, `images/codex-runner/Dockerfile:30`; `find . -name package-lock.json` → only `apps/web/pnpm-lock.yaml` exists **[CODE]** |
| 2 | Direct dependencies are exact-pinned (`0.3.205`, `1.29.0`, `0.144.1`); **the transitive tree is resolved fresh at every build**. | `images/*/runner/package.json` **[CODE]** |
| 3 | `.github/dependabot.yml` covers cargo `/`, npm `/apps/web`, github-actions, and **docker base images** for `/images/*` — there is **no npm ecosystem entry for the runner directories**. | `.github/dependabot.yml` **[CODE]** |
| 4 | CI never builds these images. The dependabot file says so in its own comment: *"CI does not build these images."* | `.github/dependabot.yml` **[CODE]** |

**Consequences.** The code that runs *inside the sandbox*, next to the workspace and holding the LLM and tool tokens, has (a) an unpinned transitive dependency tree, (b) no automated vulnerability alerting, (c) no reproducibility — `fluidbox-sandbox-runner:0.3.0` rebuilt today and rebuilt at release time are different artifacts with the same tag — and (d) no CI coverage. A compromise anywhere below the two pinned direct dependencies lands in the next published image silently.

**[INFERRED]** This is also the mechanism by which the §1.4 gate behaviour could change under the operator's feet in either direction without any fluidbox change.

### 4.5 Chain E — release artifacts *(all profiles; adversary: T12)*

**[CODE]** `.github/workflows/release.yml` publishes five images and an OCI Helm chart with:

- **no signing** — no `cosign`, no keyless sigstore step; `helm package` is invoked without `--sign` (`:166`);
- **no SBOM and no attested provenance** — `docker/build-push-action` is called without `sbom:`/`provenance:` (`:69-76`), and the multi-arch index is assembled with `docker buildx imagetools create` from bare digests (`:125-127`), which does not carry attestations forward;
- **mutable action references** — `actions/checkout@v7`, `docker/build-push-action@v7`, `docker/login-action@v4`, `azure/setup-helm@v4` are tags, not SHAs, in a job holding `packages: write` (`:32`);
- **no test gate** — the workflow is `workflow_call`/`workflow_dispatch` only and runs no tests itself. `release-please.yml:15-16` states the choice plainly: *"Publishing is UNGATED by deliberate choice."*

**[INFERRED]** A consumer following `README.md:257-273` (`helm install oci://ghcr.io/...`) has no cryptographic means to verify the artifact's origin, and no bill of materials for the sandbox runner. For a product whose value proposition is *containment and accountability for untrusted code*, unsigned artifacts are a category mismatch with the pitch.

### 4.6 Chain F — resource and spend exhaustion *(Docker profile; adversaries: T11, T7)*

**[CODE]** Run admission has no deployment-wide concurrency cap. `run_service.rs:201-210` enforces only a **per-subscription** `concurrency_policy`, whose default is `allow` (documented at `CLAUDE.md` §schedules and in `docs/guides/triggers.md`). The Kubernetes path has a `ResourceQuota` (`deploy/helm/fluidbox/values.yaml:292-294`); **the Docker provider has no equivalent** — `fluidbox-provider/src/lib.rs` sets per-container limits (2 GB, 512 pids) but nothing caps the number of containers.

**[INFERRED]** An attacker who can open PRs (T11), or who holds one trigger token (T7), can create runs faster than they finish. Each costs a container (2 GB reserved) plus model spend up to the per-run budget. With `synchronize` opt-in this is bounded per PR, but not across PRs. Impact: host memory exhaustion, and spend equal to *per-run budget × N* against the operator's provider key.

---

## 5. What holds — verified, not assumed

Red-teaming is only credible if it says what survived. These were examined and found sound.

| Property | Evidence |
|---|---|
| **Credential inversion for A1** | No upstream credential path reaches the sandbox. LLM key confined to LiteLLM; git credentials via ephemeral `GIT_CONFIG_*`; brokered credentials unsealed only inside `broker.rs`. **[CODE]** Verified by reading the sandbox env construction at `fluidbox-provider/src/lib.rs:103`. |
| **Brokered MCP enforcement** | Structural — the server executes the call. Frozen-set availability → frozen-schema validation → trust tier → policy → approvals, in that order, with the schema stage inserted without moving anything else. **[CODE]** `internal.rs:159-193`, `:194-268`. |
| **Tenant isolation** | `TenantScope` as a *signature requirement* is a genuinely strong design; RLS `ENABLE`+`FORCE` on 37 tables is real depth. Independently probed as the non-owner `fluidbox_runtime` role on two live deployments: correct rows per GUC, cross-tenant write refused by the `WITH CHECK` arm, `UPDATE`/`DELETE` → `42501`. **[MEASURED]** `docs/reviews/2026-07-27-pr92-two-environment-validation.md` §6. |
| **RunSpec immutability across a column-dropping migration** | Frozen `run_spec` byte-identical before and after `0026`, measured twice. **[MEASURED]** ibid. §5 (P7). |
| **Ledger redaction by construction** | `Redacted<EventEnvelope>` constructible only via `Redactor::scrub`; the type system, not a convention. **[CODE]** `fluidbox-core/src/event.rs`. |
| **Webhook authentication** | HMAC over the raw body, verify-before-store, hash-then-compare (a sound constant-time mitigation), two DB-unique dedup levels. **[CODE]** `connectors/github.rs:34-72`. |
| **Admin token comparison** | `sha256_hex(presented) == sha256_hex(expected)` — hashing both sides removes the token-recovery timing channel. **[CODE]** `auth.rs:128,244`. |
| **Fail-safe policy defaults** | `RuleAction::default() == Approve`; `AutonomousFallback::default() == Deny`. Both fail toward asking/denying. **[CODE]** `fluidbox-core/src/policy.rs:223-225,231-235`. |
| **Fork detection** | Fails *toward* fork when the payload hides the head repo. **[CODE]** `connectors/github.rs:134-140`. |
| **Kubernetes chart defaults** | `zeroEgress`, `requireEnforced: true`, non-root `runAsUser: 10001`, non-owner `runtimeRole`, `Recreate` strategy by default. **[CODE]** `deploy/helm/fluidbox/values.yaml`. |
| **Metrics exposure** | `/v1/admin/metrics` is admin-gated; the unauthenticated listener is opt-in and warns at boot. **[CODE]** `main.rs:458,611-618`. |
| **Documentary honesty** | `docs/hosted/threat-model.md` carries a 17-row accepted-residual table, marks two Phase E rows *partially shipped*, and contains an explicit self-correction (`:194-204`) retracting a previously-claimed closure. This is materially better than most projects at this stage and should be preserved. |

---

## 6. Where this model disagrees with `docs/hosted/threat-model.md`

| Row there | Status here | Reason |
|---|---|---|
| T1/T2 · *"Bypass the permission callback (autonomy modes)"* → **shipped** | **Contradicted for in-sandbox tools** | The row answers *"is the callback wired?"* (yes — `index.mjs:148-156`, never `bypassPermissions`). The attack is *"is the callback invoked?"* — measured **no** (§1.4). The row's control does not address the row's own attack. |
| Core assumption · *"everything the sandbox can do passes the control plane's single decision gate"* | **False as written** | §1.2–1.3. True of brokered tools; not true of in-sandbox tools; the two are not distinguished. |
| T1/T2 · *"Reach the internet / metadata endpoints"* → **shipped (Kubernetes)** | **Qualified further** | The existing residual at `:176` names the EKS pod-start window. What is not stated is that the boot probe structurally cannot certify a later pod (§4.3), so the qualification applies to *every* CNI, not only EKS. |
| Out of scope · *"Malicious code changes in fluidbox itself… CI, review, and release signing are process controls outside this document"* | **Should be brought in scope** | There is no release signing (§4.5) and the sandbox-resident dependency tree is unpinned and unmonitored (§4.4). Declaring it out of scope is defensible for *this repo's commits*; it is not defensible for *artifacts the README tells users to install*. |
| Adversary list | **Two missing** | T11 (unauthenticated fork-PR author) is the lowest-privilege, widest-reach adversary and is absent. T12 (harness/runtime supply chain) is absent. |

---

## 7. Residuals this model accepts

Carried forward from `docs/hosted/threat-model.md:171-188` unchanged and re-affirmed as correctly characterised: the transferable connector-OAuth `go_url` lure (with its 2026-07-20 correction — the analysis there is right); at-most-once brokered dispatch; at-least-once delivery; same-uid `ptrace` of the runner-control token; per-replica rate limits before `0023`; git clone TOCTOU; no `outputSchema` result validation; deferred per-tenant egress allowlists; the LLM reservation sole-claimant carve-out; the old-image/new-server incompatibility.

Added here:

| Residual | Rationale for accepting |
|---|---|
| **In-sandbox tool gating is cooperative** (§1) | Cannot be fully closed while the harness executes tools in-process. It can be *bounded* (containment) and *detected* (the control plane can observe a run that produced a diff with no decisions). Both are cheap; neither is built. |
| **Codex execpolicy is spelling-enumerated** | Disclosed in the rules file itself and filed as #15. Bounded to reads of a disposable workspace *when* egress is genuinely closed — which on the Docker default it is not. |

---

## 8. Design directions (not prescriptions)

Stated because a threat model that only enumerates problems is not actionable. Deliberately not fixes — this pass changes no implementation.

1. **Detection is cheaper than enforcement and is not built.** The control plane already knows a run's terminal artifact set. A run that produced a non-empty diff with zero `tool.decision` events is, by construction, a run whose tools were not gated. That is a query, an alarm, and optionally a fail-closed finalizer verdict. It converts §1 from silent to loud without touching the harness.
2. **Make containment carry the weight the gate cannot.** If in-sandbox gating is cooperative, then the egress boundary is the real control. Defaulting Docker to `Hardened`, or refusing to run untrusted-tier work (fork PRs) under `HostDev`, aligns the default with the threat model.
3. **Per-pod enforcement proof, not per-boot.** A netpol assertion inside the sandbox pod's own init container — before the runner starts — measures the pod that matters at the moment that matters.
4. **Pin what executes next to the workspace.** A lockfile for both runner images, an npm dependabot entry per runner directory, and image signing + SBOM at release.
5. **Bound admission.** A deployment-wide concurrent-run ceiling for the Docker provider.

---

## 9. Verification gaps in this pass

Stated so the next reviewer knows what is *not* covered.

| Area | Why not covered |
|---|---|
| Live reproduction of §1.4 | Deliberate: the goal forbade model spend. Relies on the 2026-07-27 measurement, which is strong (unfabricatable nonce, two trials, fresh image). |
| Kubernetes live agent gate behaviour | The 2026-07-27 report drove `/permission` directly on kind and EKS; it did **not** re-run the nonce test with a live agent there. Same image, same SDK ⇒ likely identical, but that is inference. |
| `apps/web` dashboard | Not reviewed. Presentation-only by constraint, but the proxy's credential handling in `sso` mode deserves its own pass. |
| Cryptographic review of `seal.rs`/`kms.rs` | Structure reviewed (versioned envelopes, AAD binding `fbx:v2:{tenant}:{table.column}`, dual retirement gates) and the design is sound. Primitive usage not audited line by line. |
| `fluidbox-db` (25.7 kLOC) | Only the tenant-scoping pattern and RLS posture were examined. |
| Runtime behaviour of `broker.rs` (224 kB) | Read at the level of gate ordering and credential re-resolution; not exhaustively. |
| Dependency CVE status | `cargo deny check` not executed in this pass; `deny.toml` reviewed (one documented RUSTSEC ignore with a sound rationale). |

---

## Related documents

- [`../reviews/prime-time-red-team.md`](../reviews/prime-time-red-team.md) — the full red-team pass this model summarises
- [`../reviews/public-claims-audit.md`](../reviews/public-claims-audit.md) — every material public claim, mapped to evidence
- [`../launch/launch-blockers.md`](../launch/launch-blockers.md) — ranked blockers with acceptance tests
- [`../hosted/threat-model.md`](../hosted/threat-model.md) — the hosted-deployment builder's model (still authoritative for T3–T9)
- [`../reviews/2026-07-27-pr92-two-environment-validation.md`](../reviews/2026-07-27-pr92-two-environment-validation.md) — the source of every **[MEASURED]** claim here
