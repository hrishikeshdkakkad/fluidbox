# Launch blockers — public-launch go/no-go

**Date:** 2026-07-29
**Tree:** `9515069` (main)
**Purpose:** a decision instrument. Each item carries a reproduction path, an impact statement, the deployment profiles it applies to, the evidence it rests on, and an **acceptance test written so that another engineer can tell, without judgement, whether it is closed.**

**Recommendation: NO-GO for a broad public launch until BLK-01 and BLK-04 are closed or the product's public claims are rewritten around them.**

The engineering here is, in most places, unusually good — the tenant-isolation floor, the credential inversion, the frozen-`RunSpec` immutability across a column-dropping migration, and the audience-scoped tokens are all real, independently measured, and better-evidenced than the norm at this stage. The blockers are concentrated in three places: **the one property the product is named for** (BLK-01), **the defaults on the paths users are told to take first** (BLK-03, BLK-04), and **the gap between what CI gates and what the README claims** (BLK-06), which is the mechanism that let BLK-01 reach a release.

---

## Ranking scheme

| Priority | Definition |
|---|---|
| **P0** | Blocks launch. Either a public claim is measurably false in a way a user would rely on, or an unauthenticated/low-privilege attacker gains code execution or data disclosure on a default path. |
| **P1** | Blocks launch unless explicitly and publicly accepted in writing. Materially misleads an operator, or removes a control the documents say exists. |
| **P2** | Ship-with-disclosure. Real, bounded, must appear in release notes or the threat model. |
| **P3** | Track. Correctness/quality debt with no launch-day consequence. |

---

## P0 — blocks launch

### BLK-01 · The permission gate is not enforced for in-sandbox tools

| | |
|---|---|
| **Priority** | **P0** |
| **Profiles** | Docker **(measured)**; Kubernetes **(inferred — same image, same SDK)**; eval. Both harnesses, by different mechanisms. |
| **Claims contradicted** | `README.md:72`, `README.md:245`, `PLAN.md:39` (invariant 6), `docs/ARCHITECTURE.md:29`, `docs/hosted/threat-model.md:11` and its T1/T2 *"Bypass the permission callback"* row. |
| **Tracking** | Private advisory `GHSA-74v8-gg34-28q8` (draft). **Not** in README, SECURITY.md, CHANGELOG, or the hosted threat model. |

**Reproduction (measured 2026-07-27, Docker provider, image built fresh from source):**

1. Author a policy whose head rule is `{match:["Bash"], action:"approve"}`; publish it; attach it to an agent.
2. Create a supervised run whose task forces a shell round-trip with an unfabricatable answer — `printf '<random-nonce>' | sha256sum`.
3. Observe: the agent returns the **exact** digest of a nonce generated seconds earlier. `Bash` demonstrably executed.
4. Query the session ledger: **zero** `tool.requested`, `tool.decision`, `approval.requested` events.
5. The absence is decisive, not circumstantial: `internal.rs:1857-1865` *drops* runner-submitted `tool.requested` on the grounds that the gate writes it server-authoritatively. If the gate had run, the event would exist.
6. Repeated with a second nonce. Same result.

**Impact.** The product's central promise — *policy-gated, audited agent execution* — does not hold for the tools an agent actually uses to change code. Every property evaluated at the gate is affected for in-sandbox tools: per-tool policy, human approvals, autonomous fallbacks, the fork-PR read-only floor (BLK-02), per-tool-call budget counting, and the completeness of the audit ledger. A ledger showing no tool activity is currently indistinguishable from a run that gated correctly and used no tools.

**Why it is a class, not a one-off.** The server-side gate is **sound** — driving `/permission` directly with the tool-audience token produces the full chain on Docker, kind, and EKS. The gap is *runner → gate*. `@anthropic-ai/claude-agent-sdk@0.3.205` documents `canUseTool` as the **ask-path** handler only: `sdk.d.ts:4005` (*"the 'ask' path surfaces via a can_use_tool control_request"*, *"PreToolUse hook denies bypass canUseTool"*), `:3481` (`sandboxOverride`/`rule`/`mode`/`hook`/`classifier` decision sources), `:5943` (`autoAllowBashIfSandboxed`), `:1335` (`allowedTools`), `:1716` (`permissionPromptToolName`). fluidbox's configuration (`permissionMode: "default"`, `settingSources: []`) is correct; the property it needs is not one the SDK offers under any configuration. The Codex harness reaches the same gate through an enumerated list of ~29 basenames and ~150 absolute-path spellings (`images/codex-runner/rules/default.rules`) whose own comment discloses a relative-path bypass (issue #15) — a denylist, with the same reachability character.

**Acceptance test — all four must pass:**

- **AT-01a (detection, server-side, no harness dependency).** A run that reaches a terminal state having produced a non-empty diff while its ledger contains zero `tool.decision` events is flagged. Assert: create such a run; the control plane emits a named event/metric and the run's terminal record carries the flag. *This is the cheapest closure and it converts a silent failure into a loud one without touching any harness.*
- **AT-01b (live enforcement, Claude harness).** Under a policy of `{match:["Bash"], action:"approve"}`, a live agent instructed to run a shell command **either** produces `tool.requested` → `approval.requested` in the ledger **or** does not execute. Proven with an unfabricatable-nonce task, run in CI or a recorded acceptance — not by driving `/permission` directly.
- **AT-01c (live enforcement, Codex harness).** AT-01b repeated on `images/codex-runner`, including the disclosed relative-path spelling `./cat`.
- **AT-01d (regression gate).** AT-01b/c run automatically on any change to `images/**`, on any bump of the pinned agent-runtime versions, and before every release. Today `ci.yml:417` gates all live-agent coverage on `workflow_dispatch`, and `.github/dependabot.yml` states *"CI does not build these images."*

**If not fixed before launch:** BLK-01 must be disclosed in `README.md` §Security boundaries and in `SECURITY.md`, and the four claim sites above rewritten to the true property: *brokered MCP calls are structurally gated; in-sandbox calls are gated when the harness routes them, and containment is the control that binds one that does not.*

---

### BLK-02 · Fork-PR read-only trust is gate-enforced, so an unauthenticated GitHub user gets ungated execution

| | |
|---|---|
| **Priority** | **P0** (composition of BLK-01 + BLK-03; listed separately because it is the lowest-privilege path to the highest impact) |
| **Profiles** | Docker + GitHub App **(worst)**; Kubernetes + GitHub App **(bounded by `zeroEgress`, subject to BLK-05)** |
| **Claim contradicted** | `README.md:245` — *"Fork PRs … receive a read-only trust floor that approvals cannot widen."* |
| **Tracking** | **None.** Not in the advisory, not an issue. |

**Reproduction (static; not executed — executing it means running a live agent):**

1. Operator connects a GitHub App and creates a subscription on `pull_request` `opened` for a public repository. This is the documented, intended configuration.
2. Any GitHub user — no membership, no token, no prior relationship — opens a PR from a fork.
3. `connectors/github.rs:132-145` correctly detects the fork and freezes `TrustTier::ReadOnly` + `CheckoutMode::ReadOnly`. *This half is right.*
4. `connectors/github.rs:148-158` materialises the workspace at the **PR head SHA** — content the attacker fully controls — served by SHA from the base repo's clone URL.
5. MCP surfaces are stripped structurally before provisioning (`bindings.rs:143`, `run_service.rs:532`). *This half is also right.*
6. The read-only floor on `Bash`/`Edit`/`Write` is **not** structural: `read_only_denial()` is applied **inside the gate** (`internal.rs:444-445`, `policy.rs:991-996`). Per BLK-01, the gate is not reached.
7. Default sandbox network is `NetworkMode::HostDev` (`fluidbox-core/src/traits.rs:88`), which also injects `host.docker.internal:host-gateway` (`fluidbox-provider/src/lib.rs:118`).

**Impact.** An unauthenticated third party obtains **arbitrary command execution inside a container on the operator's host, with general network egress and the host's LAN position**, by opening a pull request. The attacker controls the workspace contents *and* the PR title/body/diff, so they control the prompt-injection surface reaching the model. Exfiltration target A8 — the base repository's source — is in the container by design.

**Bounded by (verified):** no upstream credentials in the sandbox (that inversion holds); `cap_drop: ALL`, `no-new-privileges`, 2 GB memory, 512 pids (`fluidbox-provider/src/lib.rs:127-130`); the container is disposable; MCP surfaces genuinely absent.
**Not bounded by:** policy, trust tier, approvals, or the ledger.

**Acceptance test:**

- **AT-02a.** With `TrustTier::ReadOnly` frozen, a live agent instructed to run a non-read-safe `Bash` command and to write a file **cannot** do either — proven with an unfabricatable-nonce task on a real fork-PR-shaped run, not by driving `/permission`.
- **AT-02b (structural alternative, if AT-02a cannot be met).** Untrusted-tier runs are refused admission under `NetworkMode::HostDev`, so the read-only floor is never the only thing standing between an anonymous PR author and the host network. Assert: creating a `ReadOnly` run with `HostDev` configured returns a refusal naming the reason.

---

## P1 — blocks launch unless explicitly accepted in writing

### BLK-03 · Docker's default sandbox network is `HostDev` — full egress plus the host gateway

| | |
|---|---|
| **Priority** | **P1** (P0 in composition with BLK-01/02) |
| **Profiles** | Docker, eval |
| **Status of claim** | `README.md:243` is **honest** — *"Docker's default `host-dev` mode is intentionally convenient and is not a structural zero-egress boundary."* `docs/ARCHITECTURE.md:26` and `CLAUDE.md` are **not**: both say *"the sandbox stays egress-free."* |

**Reproduction:** `crates/fluidbox-core/src/traits.rs:82-92` — `#[default] HostDev`. `crates/fluidbox-provider/src/lib.rs:81` sets the Docker network `internal` only for `Hardened`; `:118` injects `host.docker.internal:host-gateway` for `HostDev`. `orchestrator.rs:1309` takes the mode from config, whose default is the enum default. Nothing in `just setup`/`just dev` changes it.

**Impact.** Under the threat model's own T2 (*"arbitrary code execution inside the container"*), containment is the **only** remaining control once BLK-01 is granted. On the default Docker profile that control is absent: the sandbox has general internet egress and the host's LAN position. This is the difference between "an agent did something unapproved to a disposable copy" and "an attacker has a network foothold."

**Acceptance test:**

- **AT-03a.** Either the default flips to `Hardened` and a network census from inside a default-profile sandbox shows no route to any address other than the control plane; **or** `just doctor`, the server boot log, and the dashboard each state prominently that this deployment's sandboxes have unrestricted egress.
- **AT-03b.** `docs/ARCHITECTURE.md:26` and `CLAUDE.md` are corrected to match `README.md:243`.

---

### BLK-04 · The eval quickstart binds an admin API with a published token to all interfaces

| | |
|---|---|
| **Priority** | **P1** — arguably P0: it is the **first** install path in the README and needs no attacker sophistication. |
| **Profiles** | eval |
| **Claim contradicted** | `README.md:129` — *"It is for trying the run loop, not for exposing to a network."* |
| **Tracking** | **None.** |

**Reproduction:**

1. Run the README's first command block verbatim (`README.md:122-127`).
2. `deploy/docker-compose.eval.yml:48-49` publishes `"8787:8787"`; `:77-78` publishes `"3000:3000"`. Docker's short syntax without a host-IP prefix binds **`0.0.0.0`**. The sibling `docker-compose.dev.yml:21,42` *does* prefix with `127.0.0.1`, so this is an omission rather than a convention.
3. `:53` defaults `FLUIDBOX_ADMIN_TOKEN` to `fluidbox-eval-only` — published in this repository.
4. From any host on the same segment: `curl -H "authorization: Bearer fluidbox-eval-only" http://<victim>:8787/v1/sessions` → full admin authority.
5. Escalate: an Operator may name **any** control-plane host path as a `local_copy` workspace. The guard is *operator-only*, not path-constrained (`crates/fluidbox-server/src/api.rs:105-140`). Create a run with `workspace: {kind: "local_copy", path: "/root"}`.
6. The control plane copies those host files into the workspace; the sandbox reads them; `HostDev` egress (BLK-03) carries them out.
7. Aggravating: `:63` bind-mounts `/var/run/docker.sock` into the server container.

**Impact.** Anyone on a shared network — café, hotel, office, or a compromised device on a home LAN — gets full tenant data disclosure, arbitrary host-file read, and unbounded model spend against the operator's `ANTHROPIC_API_KEY`, from the install path the project recommends first.

**Acceptance test:**

- **AT-04a.** `deploy/docker-compose.eval.yml` publishes both ports as `127.0.0.1:…`. Assert from a second host on the same LAN: connection refused on `:8787` and `:3000`.
- **AT-04b.** The eval stack either generates a random admin token at first boot and prints it, or refuses to start with the default token when either port is bound to a non-loopback address.
- **AT-04c.** A test asserts every published port in `deploy/docker-compose.eval.yml` carries a `127.0.0.1:` prefix, so the property cannot silently regress.

---

### BLK-05 · The NetworkPolicy proof measures the wrong pod at the wrong time — and blocks all EKS runs

| | |
|---|---|
| **Priority** | **P1** (availability half is P0 *for the EKS story specifically*, but it fails **closed**) |
| **Profiles** | Kubernetes — acute on EKS/VPC CNI; structural on every CNI |
| **Claims affected** | `README.md:243`, `README.md:270-272`, `README.md:279` |
| **Tracking** | Availability half → issue **#96**. **Security half → untracked.** |

**Reproduction (availability, measured on EKS 1.33 / VPC CNI `standard`):** deploy per `scripts/eks-cluster.yaml` and the chart defaults; every `POST /v1/sessions` returns `503`. Root cause in this tree: `crates/fluidbox-provider-k8s/src/netpol.rs:98-105` runs `nc -z -w 4 <internal> 8788` then `nc -z -w 4 <public> 8787` **the instant the probe container starts**; the 90 s deadline at `:120` bounds pod scheduling, not the assertions. The CNI programs policy asynchronously and fails **open** meanwhile — measured: internet reachable at t=0, blocked at t=20s and t=60s. Every probe pod is new, so it always races. Both failure codes reproduce (`exit 2 → Unschedulable`, `exit 3 → NotEnforced`).

**Reproduction (security, inferred from the same measurement):** the identical window applies to **sandbox** pods, so a sandbox has unrestricted egress for its first seconds on `standard` mode. More generally, a once-per-process boot probe certifies **a different pod at a different time** — a *passing* probe on Calico is evidence the CNI enforces policy in general, not that the sandbox created ten minutes later was isolated during its own programming window.

**Impact.** The flagship cloud target cannot create runs on its own prescribed configuration, and the mechanism sold as *"proves the cluster's CNI enforces NetworkPolicy"* does not establish the per-sandbox property readers take from it. `strict` mode closes the window but is documented to starve CoreDNS/EBS-CSI. **Neither shipped mode delivers per-pod enforcement at t=0.** The workaround used to obtain a live EKS result was `netpol.requireEnforced=false` — i.e. turning the control off.

**Acceptance test:**

- **AT-05a.** The probe retries its assertions for a bounded period before concluding. Assert on EKS/VPC CNI `standard`: the boot gate passes unaided and `POST /v1/sessions` returns 200 with `requireEnforced: true`.
- **AT-05b.** Enforcement is asserted **from inside the sandbox pod's own network namespace, before the agent process starts** (e.g. in the workspace-init container). Assert: a sandbox whose policy has not landed does not reach the agent stage.
- **AT-05c.** `README.md:279` states the date and configuration each EKS acceptance covers, and notes that the prescribed EKS configuration currently requires AT-05a.

---

### BLK-06 · Release and CI do not gate the paths the claims depend on

| | |
|---|---|
| **Priority** | **P1** |
| **Profiles** | all |
| **Tracking** | Partially — issues **#99** (governance-e2e cannot catch runner-side regressions) and **#100** (4 pre-existing e2e failures). |

**Reproduction:**

- `.github/workflows/ci.yml:417` — the `e2e` job is `if: github.event_name == 'workflow_dispatch'`. It is the only suite that builds the runner images and runs a live agent.
- `.github/dependabot.yml` states in its own comment: *"CI does not build these images."*
- `scripts/governance-e2e.sh` **kills the real runner and drives `/permission` itself** (issue #99), so it validates the server and structurally cannot validate the harness. This is exactly why BLK-01 survived.
- Issue #100: 4 pre-existing red phases (7/8/9) in the full e2e.
- `.github/workflows/release-please.yml:15-16`: *"Publishing is UNGATED by deliberate choice."* `release.yml` runs no tests.

**Impact.** The claim at `README.md:316` — *"The acceptance suites cover … both harnesses"* — is true of the suites' *content* and false of their *effect*: nothing requires them to pass before a change lands or a release ships. A release can publish five images and an OCI chart with the live-agent suite never having run and four of its phases known red.

**Acceptance test:**

- **AT-06a.** The live-agent suite (or a minimal governance-critical subset — AT-01b/c) runs on every PR touching `images/**`, `crates/fluidbox-server/src/internal.rs`, or the pinned agent-runtime versions.
- **AT-06b.** The release workflow refuses to publish unless that suite passed on the released commit.
- **AT-06c.** Issue #100's four red phases are green or explicitly quarantined with a written rationale.

---

### BLK-07 · Sandbox-resident code is unpinned, unmonitored, and the artifacts are unsigned

| | |
|---|---|
| **Priority** | **P1** |
| **Profiles** | all |
| **Tracking** | **None.** `docs/hosted/threat-model.md:167` places this out of scope citing *"release signing"* as a process control — there is no release signing. |

**Reproduction:**

| Property | Evidence |
|---|---|
| No lockfile for either runner | `find . -name 'package-lock.json' -o -name 'pnpm-lock.yaml' \| grep -v node_modules` → only `apps/web/pnpm-lock.yaml` |
| Floating transitive tree | `images/sandbox-runner/Dockerfile:17` and `images/codex-runner/Dockerfile:30` run `npm install --omit=dev`; direct deps are exact-pinned (`0.3.205`, `1.29.0`, `0.144.1`), transitive deps are not |
| No CVE alerting for runner deps | `.github/dependabot.yml` has cargo `/`, npm `/apps/web`, github-actions, and docker *base images* for `/images/*` — **no npm entry for either runner directory** |
| No signing | `release.yml` — no cosign/sigstore; `helm package` without `--sign` (`:166`) |
| No SBOM, no attested provenance | `docker/build-push-action` without `sbom:`/`provenance:` (`:69-76`); index built by `docker buildx imagetools create` from bare digests (`:125-127`), which does not carry attestations forward |
| Mutable action refs with `packages: write` | `actions/checkout@v7`, `docker/build-push-action@v7`, `docker/login-action@v4`, `azure/setup-helm@v4` |

**Impact.** The code that executes **inside the sandbox**, beside the workspace and holding the LLM and tool tokens, has no reproducibility (`:0.3.0` rebuilt today ≠ `:0.3.0` at release), no vulnerability alerting, and no CI coverage. A compromise anywhere below the two pinned direct dependencies lands in the next published image silently. Consumers following `README.md:257-273` cannot verify artifact origin. For a product whose stated promise is *containment and accountability for untrusted code* (`SECURITY.md:3`), this is a category mismatch with the pitch.

**Acceptance test:**

- **AT-07a.** A committed lockfile for each runner; Dockerfiles use `npm ci`. Assert: two builds of the same commit produce identical dependency trees.
- **AT-07b.** `.github/dependabot.yml` gains an npm entry for `/images/sandbox-runner/runner` and `/images/codex-runner/runner`.
- **AT-07c.** Release publishes cosign signatures and an SBOM for all five images and the chart; the README documents the verification command.
- **AT-07d.** All third-party actions in `release.yml` are pinned by commit SHA.

---

## P2 — ship with disclosure

### BLK-08 · No deployment-wide run-concurrency cap on the Docker provider

**P2 · Docker, eval.** `run_service.rs:201-210` enforces only per-subscription `concurrency_policy`, default `allow`. Kubernetes has a `ResourceQuota` (`values.yaml:292-294`); Docker has per-container limits (2 GB, 512 pids) but nothing caps container count. A fork-PR flood (BLK-02) or one trigger token creates runs faster than they finish → host memory exhaustion and spend of *per-run budget × N*.
**AT-08:** a configurable deployment-wide concurrent-run ceiling; exceeding it returns a documented 429/409 rather than provisioning.

### BLK-09 · Codex execpolicy is an enumeration of spellings

**P2 · all profiles, Codex harness.** `images/codex-runner/rules/default.rules` enumerates ~29 basenames and ~150 absolute-path spellings to defeat Codex's built-in `is_known_safe_command` auto-run, and discloses its own relative-path residual (`./cat`, issue #15). `sandbox_mode = "danger-full-access"` (`config.toml:29`) is justified by the container being the boundary — a justification BLK-03 weakens on the Docker default. Bounded to *reads* of a disposable workspace **only when egress is genuinely closed**.
**AT-09:** AT-01c covers the enforcement half; the composition with `HostDev` is covered by AT-03a.

### BLK-10 · `docs/hosted/threat-model.md` rows now contradicted or incomplete

**P2 · documentation.** Three rows need revision before launch: the T1/T2 *"Bypass the permission callback"* row (its control answers *is the callback wired?*, the attack is *is it invoked?*); the core assumption at `:11` (*"everything the sandbox can do passes the … gate"* — true of brokered, false of in-sandbox); and the adversary table, which omits the unauthenticated fork-PR author and the harness supply chain. Detail in [`../security/threat-model.md`](../security/threat-model.md) §6.
**AT-10:** the three rows are revised and the two adversaries added.

### BLK-11 · Stale live-acceptance framing

**P2 · documentation.** `README.md:279` presents two AWS-audited EKS acceptances (2026-07-17, 2026-07-22) as current evidence. Both predate the 2026-07-28 measurement that run creation cannot succeed on the prescribed EKS configuration (BLK-05).
**AT-11:** covered by AT-05c.

---

## P3 — track

| # | Item | Evidence |
|---|---|---|
| **BLK-12** | Migration `0026`'s header still misdescribes the chart's update strategy. Deliberately unfixed — editing an applied migration breaks its sqlx checksum, which is a worse failure. CHANGELOG is corrected. | issue **#97** |
| **BLK-13** | `RunSpec` snapshot byte-equality is fresh-database-specific: `ToolRule`'s `Option` fields lack `skip_serializing_if`, so a migrated-not-yet-republished policy is semantically but not jsonb-byte equal. `governance-e2e.sh` asserts byte-equality and would fail on such a deployment. | `2026-07-27` report §D3 |
| **BLK-14** | Serializer asymmetry, a grep-provable tenant predicate, an N+1, clone bounds, import `yaml_source` drift. | issue **#98** |
| **BLK-15** | `sso` mode: approver role 403s on the Automations page (trigger list/get gated at manage tier). | issue **#76** |
| **BLK-16** | GitHub App lifecycle sub-statement race — per-(tenant, installation) advisory locks not taken. | issue **#16** |
| **BLK-17** | `docs/ARCHITECTURE.md` has no diagram; README ASCII sketch stands in. | issue **#17** |
| **BLK-18** | Single maintainer in `.github/CODEOWNERS` against a 72-hour advisory-acknowledgement commitment (`SECURITY.md:13`). A public launch raises inbound volume; consider stating capacity honestly. | — |

---

## Go / no-go

**NO-GO for a broad public launch** in the current state.

**Two conditions, either of which converts this to GO:**

**Path A — fix.** Close **BLK-01** (at minimum AT-01a, the server-side detection, which is cheap and needs no harness cooperation) and **BLK-04** (AT-04a/b, a one-line compose change plus a token default). Accept BLK-02 as bounded once BLK-01's detection exists, and disclose BLK-03/05/06/07 in release notes.

**Path B — reframe.** Launch with the claims rewritten to what is actually enforced:

- *"Brokered MCP calls cannot execute without a server-side decision"* — true, structural, well-tested.
- *"In-sandbox tool calls are gated when the harness routes them; containment binds one that does not"* — true, and the honest version.
- *"The eval stack binds to loopback and generates its own admin token"* — requires BLK-04 anyway; it is the smallest change on the list.

**What must not happen:** launching with `README.md:72`, `README.md:245`, and `PLAN.md:39` unchanged. Those are the sentences a security-conscious adopter will rely on, and a competent reviewer will reach the same measurement inside a day — the project's own validation did, and wrote it down.

**What deserves saying out loud:** `README.md:114` already declines to claim a 300-run ceiling it has not proven; `README.md:243` already says `host-dev` is not a boundary; `docs/hosted/threat-model.md` carries a 17-row residual table and an explicit self-correction retracting a previously-claimed closure. This project states its limits before an auditor forces it to. Applying that same standard to the four sentences in BLK-01 is a smaller change than it looks, and it is the one that makes the launch defensible.

---

## Related documents

- [`../reviews/prime-time-red-team.md`](../reviews/prime-time-red-team.md) — full red-team pass, method, and audit gaps
- [`../reviews/public-claims-audit.md`](../reviews/public-claims-audit.md) — every material public claim, classified
- [`../security/threat-model.md`](../security/threat-model.md) — attacker model, chains A–F, T11/T12
- [`../reviews/2026-07-27-pr92-two-environment-validation.md`](../reviews/2026-07-27-pr92-two-environment-validation.md) — source of the measured evidence
