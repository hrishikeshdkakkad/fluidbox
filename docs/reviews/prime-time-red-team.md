# Prime-time red team — independent readiness assessment

**Date:** 2026-07-29
**Tree:** `9515069` (main), worktree `worktree-prime-time-red-team`
**Mandate:** independently assess whether fluidbox is ready for a public launch. Adversarial by design: find what a competent attacker or a competent skeptical reviewer would find, and say so without softening.
**Constraints observed:** no runtime, deployment, test, or README changes; no cloud resources created; no model API spend; no other worktree touched. Output is four documents and nothing else.

> ## ⚠ STATUS ADDENDUM — 2026-07-29 (integration review)
>
> Assessed against `9515069` (main). The central finding below (§3, BLK-01) has
> since been **root-caused and fixed**, and the fix is integrated on this branch
> and independently verified. §5's BLK-05 is also closed. Everything else stands.
> Current status per blocker, and the superseding evidence, is in
> [`overnight-integration-review.md`](overnight-integration-review.md).
>
> Two corrections to this document specifically:
>
> 1. **§2.2 and §7 say live reproduction of the gate finding was impossible
>    without model spend.** That turned out to be false. Pointing the runner's
>    `ANTHROPIC_BASE_URL` at a mock upstream that returns a canned `tool_use`
>    drives the *real* runner image and the *real* Claude Code CLI through the
>    *real* hook/callback path for **$0**, and yields a stronger witness than a
>    live model does: the harness is deterministic and the probe's nonce digest
>    is unfabricatable. The gap was a missing test technique, not a budget.
> 2. **§3.2's diagnosis is confirmed and sharpened.** `canUseTool` is indeed
>    ask-path only, and the fix is upstream's own documented remedy — a
>    `PreToolUse` hook. Measured here on the unfixed image: a read-only-classified
>    `Bash` command executed while the gate was configured to deny everything,
>    with **zero** `/permission` calls. A *mutating* command in the same image
>    **was** gated — which is exactly why the failure looked intermittent.

**Original verdict (pre-integration): NO-GO for a broad public launch in the current state.** The reasoning, the two paths to GO, and the acceptance tests are in [`../launch/launch-blockers.md`](../launch/launch-blockers.md).

---

## 1. Headline

fluidbox is a well-engineered system with one central claim that does not currently hold.

The parts that are hard to get right are, mostly, right. Tenant isolation is a *signature requirement* backed by a database floor and probed live under a non-bypassing role. Credential inversion — the discipline of never letting an upstream secret enter a sandbox — is implemented consistently across four independent paths and holds. Frozen `RunSpec` immutability was measured byte-identical across a migration that drops four columns. Audience-scoped sandbox tokens are enforced by an exhaustive route × audience matrix in CI. The archive unpacker defers symlinks and validates the full resolved chain. The documentation carries a 17-row accepted-residual table and an explicit self-correction retracting a previously-claimed closure.

Against that: **the permission gate — the thing the product is named for — is not enforced for the tools an agent actually uses to change code.** This was measured on 2026-07-27 by the project's own validation, with an unfabricatable-nonce task and a ledger containing zero gate events, reproduced on a freshly-built image. It is filed as a draft private advisory and appears in no public document.

The finding is not a bug to patch. It is a **structural mismatch**: fluidbox treats the harness's permission callback as a chokepoint, and the harness treats it as an ask-path UI hook. That difference is the subject of §3.

Everything else in this report is smaller, and most of it is fixable in an afternoon.

---

## 2. Method and coverage

### 2.1 What was done

- Read the repository structure, all four CI/release workflows, `deny.toml`, `dependabot.yml`, both compose files, the Helm chart values and templates, both runner Dockerfiles, and both runner entry points.
- Read the security-relevant Rust surface at the level of *where a decision is made and what reaches it*: the permission gate (`internal.rs`), principal resolution and RBAC (`auth.rs`, `rbac.rs`), run creation and freeze (`run_service.rs`), binding resolution (`bindings.rs`), the Docker and Kubernetes providers, the netpol probe, the policy engine (`policy.rs`), the workspace archive and git materialisation (`fluidbox-workspace`), the GitHub connector, and the SSE/ledger paths.
- Downloaded and inspected the **pinned** `@anthropic-ai/claude-agent-sdk@0.3.205` type definitions to establish, from the vendor's own contract rather than from inference, what `canUseTool` does and does not guarantee. This is the evidence that turns a one-off observation into a class (§3.2).
- Extracted every material public claim and traced it to executable evidence. Result: [`public-claims-audit.md`](public-claims-audit.md).
- Reviewed the existing `docs/hosted/threat-model.md` adversarially — looking for rows whose *control* does not address the row's own *attack*.
- Read the open issue tracker (#15, #16, #17, #34, #75, #76, #96, #97, #98, #99, #100) and the 2026-07-27 two-environment validation report, which is the source of every measured claim here.

### 2.2 What was deliberately not done

Live reproduction of the gate finding — that requires model spend, which the mandate forbade. The measurement it relies on is strong (unfabricatable nonce, two independent trials, image built fresh from source during the session, behaviour confirmed identical on `main`), and it was produced by the project's own validation, not by this pass.

### 2.3 Coverage honesty

| Area | Depth |
|---|---|
| Permission gate, trust tiers, policy engine | **Deep** — the central question |
| Providers (Docker, Kubernetes), network modes, netpol probe | **Deep** |
| CI, release, supply chain | **Deep** |
| GitHub connector, fork handling | **Deep** |
| Workspace archive / git materialisation | **Moderate** — hardening reviewed, not fuzzed |
| Identity, RLS, sealing, KMS | **Moderate** — designs reviewed and found sound; relied on the existing acceptance suites and the 2026-07-27 live probes rather than re-deriving |
| `broker.rs` (224 kB), `oauth.rs` (172 kB), `governor.rs` (106 kB) | **Targeted** — read at the level of gate ordering, credential re-resolution, and admission; not exhaustively |
| `fluidbox-db` (25.7 kLOC) | **Shallow** — tenant-scoping pattern and RLS posture only |
| `apps/web` dashboard | **Not reviewed** |
| Cryptographic primitive usage in `seal.rs`/`kms.rs` | **Structure only** — envelope design, AAD binding, retirement gates reviewed; primitives not audited |

Full gap list in §7.

---

## 3. The central finding

### 3.1 What was measured

`docs/reviews/2026-07-27-pr92-two-environment-validation.md` §8b, Docker provider, image built fresh from current source:

- Task designed so the answer cannot be fabricated: `printf '<random-nonce>' | sha256sum`. The agent returned the **exact** digest of a nonce generated seconds earlier. Twice, with two different nonces. `Bash` demonstrably executed.
- The session ledger contained **zero** `tool.requested`, `tool.decision`, `approval.requested` events.
- The governing frozen `policy_snapshot` head rule was `{match:["Bash"], action:"approve"}` — a human approval was required and never requested.
- The absence is decisive rather than circumstantial: `internal.rs:1857-1865` *drops* runner-submitted `tool.requested` because the gate writes it server-authoritatively. Had the gate run, the event would exist.
- The sandbox was reachable throughout — it posted `agent.message` events, heartbeats, and its `/result`. It simply never asked.

Driving `/internal/sessions/{id}/permission` directly with the tool-audience token produces the complete chain on Docker, on kind+Calico, and on real EKS. **The server-side gate is sound.** The gap is *runner → gate*.

### 3.2 Why it is a class

The runner source is correct as written. `images/sandbox-runner/runner/index.mjs:102-123` passes `canUseTool` to `query()`; `:148-156` sets `permissionMode: "default"` and `settingSources: []`; `bypassPermissions` appears nowhere. A reviewer reading only fluidbox's code would conclude the gate is wired, and would be right.

The problem is what `canUseTool` *is*. From the pinned SDK's own bundled `package/sdk.d.ts`:

| Line | What it establishes |
|---|---|
| `:4005` | *"Emitted when a tool call is auto-denied without an interactive permission prompt (e.g. auto-mode classifier, dontAsk mode, headless-agent auto-deny, or a deny rule). **The 'ask' path surfaces via a can_use_tool control_request**… **PreToolUse hook denies bypass canUseTool**."* |
| `:3481` | `decision_reason_type` ∈ `{rule, mode, subcommandResults, permissionPromptTool, hook, asyncAgent, sandboxOverride, workingDir, safetyCheck, classifier, other}` — eleven ways a call is resolved, of which the ask is one. |
| `:5943` | `sandbox.autoAllowBashIfSandboxed?: boolean` — a setting whose purpose is to auto-allow `Bash` when the CLI believes it is sandboxed. |
| `:1335` | `allowedTools?: string[]` — pre-approval that never reaches the callback. |
| `:1716` | `permissionPromptToolName` — routes permission requests elsewhere entirely. |

`canUseTool` is the handler for **the ask path**. The set of paths that resolve *without* asking is defined by the SDK, varies by version, and is not under fluidbox's control. fluidbox needs *"no tool executes without the server deciding"*; the SDK offers *"you may render the prompt when one is shown."* Those are different contracts.

The Codex harness reaches the same gate by a different mechanism with the same character: `images/codex-runner/rules/default.rules` enumerates ~29 basenames and ~150 absolute-path spellings to defeat Codex's built-in `is_known_safe_command` auto-run, and its own comment discloses that a relative-path spelling (`./cat`) escapes prefix matching (issue #15). An enumeration of spellings is a denylist. Gate reachability is only as complete as the enumeration.

### 3.3 The deeper point: which adversary the gate binds

`docs/hosted/threat-model.md:29-31` declares two adversaries and claims the same mitigation for both:

- **T1** — prompt-injected model: *"full control of tool-call intents."*
- **T2** — compromised sandbox workload: *"arbitrary code execution inside the pod/container."*

For **brokered MCP tools** the gate binds both, because the **control plane executes the call**. Nothing the sandbox does can produce that side effect. This half is structural, well-tested, and genuinely strong.

For **in-sandbox tools** — `Bash`, `Edit`, `Write`, `Read`, sandbox-class stdio MCP — the sandbox executes the tool itself. The control plane never executes anything and never observes execution; it only answers a question the runner chooses to ask. Against T1 that is a real control: a misled model emits an intent and the harness routes it. **Against T2 it is not a control at all** — a workload with arbitrary code execution is not obliged to route anything.

So `docs/hosted/threat-model.md:11` — *"everything the sandbox **can** do passes the control plane's single decision gate"* — cannot be true of a workload that, by the same document's stated assumption, executes arbitrary code. The measured 2026-07-27 behaviour is the **benign** instance of a property that is unenforceable against the adversary the model declares.

The honest statement is in [`../security/threat-model.md`](../security/threat-model.md) §1.6.

### 3.4 What the control plane does not do, and cheaply could

The system refuses to trust what the runner **says** — runner-posted `tool.requested` is dropped, decisions are server-authoritative, budget counting never depends on runner honesty. There is no corresponding treatment of what the runner **omits**.

Nothing in `internal.rs`, `orchestrator.rs`, or `workers.rs` observes that a session reached a terminal state having produced a non-empty diff with zero `tool.decision` events. That is a query the control plane already has all the inputs for. It does not make the gate enforceable — nothing can, while the harness executes tools in-process — but it converts a **silent** failure into a **loud** one, needs no harness cooperation, and would have caught this on the first run. It is AT-01a in the blocker list, and it is the single highest-value change identified by this pass.

---

## 4. Composition: how the findings stack

Individually most findings are moderate. The launch risk comes from three of them landing on the *same default path*.

```
  T11: any GitHub user opens a fork PR          ← no credential, no membership
            │
            ▼
  workspace = attacker-controlled PR head SHA    connectors/github.rs:148-158
  prompt context = attacker's README/code/PR body
            │
            ▼
  TrustTier::ReadOnly frozen                     ✔ correct
    ├── MCP surfaces stripped structurally       ✔ HOLDS (bindings.rs:143)
    └── Bash/Edit/Write floor enforced AT THE GATE   internal.rs:444
            │
            ▼
  BLK-01: gate not reached for in-sandbox tools  ✘ MEASURED
            │
            ▼
  arbitrary ungated command execution in the sandbox
            │
            ▼
  BLK-03: NetworkMode::HostDev is the DEFAULT    traits.rs:88
    ├── general internet egress
    └── host.docker.internal:host-gateway        → the host's LAN position
            │
            ▼
  exfiltration of A8 (the base repo's source) + a network foothold
```

Two of the threat model's three declared layers — *capability ≠ permission ≠ containment*, `PLAN.md:36`, *"weakening one never weakens the others"* — are down simultaneously on the recommended quickstart. The invariant is stated as independence; in the default configuration the layers fail together.

A parallel composition exists for the eval profile, where the entry point is an unauthenticated LAN host rather than a GitHub user, and the escalation runs through a published admin token to an unconstrained `local_copy` host path. Detail in [`../launch/launch-blockers.md`](../launch/launch-blockers.md) BLK-04.

---

## 5. Findings summary

Full detail, reproduction paths, and acceptance tests in [`../launch/launch-blockers.md`](../launch/launch-blockers.md).

| ID | Priority | Finding | Profiles | Tracked? |
|---|---|---|---|---|
| **BLK-01** | **P0** | Permission gate not enforced for in-sandbox tools; `canUseTool` is an ask-path callback, not a chokepoint | all | draft advisory only |
| **BLK-02** | **P0** | Fork-PR read-only floor is gate-enforced ⇒ unauthenticated GitHub user gets ungated execution | Docker+GitHub worst | **no** |
| **BLK-03** | **P1** | `NetworkMode::HostDev` is the default: full egress + host gateway | Docker, eval | README honest; ARCHITECTURE/CLAUDE.md contradict |
| **BLK-04** | **P1** | Eval quickstart binds admin API with a published token to `0.0.0.0` | eval | **no** |
| **BLK-05** | **P1** | Netpol probe samples once at t=0: no runs on EKS, and it certifies the wrong pod | Kubernetes | #96 (availability half only) |
| **BLK-06** | **P1** | Live-agent suite is `workflow_dispatch`-only; release publishing ungated; 4 e2e phases red | all | #99, #100 |
| **BLK-07** | **P1** | Runner images: no lockfile, no dependabot npm entry, unsigned/unattested release artifacts | all | **no** |
| **BLK-08** | P2 | No deployment-wide run-concurrency cap on Docker | Docker, eval | no |
| **BLK-09** | P2 | Codex execpolicy is a spelling enumeration; `danger-full-access` composes with `HostDev` | all (Codex) | #15 |
| **BLK-10** | P2 | Three `docs/hosted/threat-model.md` rows now contradicted; two adversaries missing | docs | no |
| **BLK-11** | P2 | EKS acceptance evidence presented as current; predates BLK-05 | docs | no |
| **BLK-12–18** | P3 | Migration header, serializer asymmetry, RBAC UX, App advisory locks, diagram, maintainer capacity | — | #97, #98, #76, #16, #17 |

**Claims audit result:** 13 PROVEN · 6 PARTIALLY PROVEN · 3 INFERRED · **6 CONTRADICTED** · 1 UNTESTED. The contradicted set is `README.md:72`, `README.md:129`, `README.md:240`, `README.md:245` (read-only half), `README.md:270-272` (on EKS), `PLAN.md:39`, plus supply-chain claims by implication.

---

## 6. What holds

Stated at length because a red team that only enumerates problems is not a useful instrument, and because several of these are better than the norm for a pre-1.0 project.

**Credential inversion (A1) is the strongest property in the product and it holds.** Four independent paths — LLM facade, git fetch via ephemeral `GIT_CONFIG_*`, brokered MCP via `broker.rs`, GitHub App token minting — all keep the secret control-plane-side. The sandbox env is built from `spec.env` alone (`fluidbox-provider/src/lib.rs:103`). Asserted by `scripts/secrets-e2e.sh` and the Kubernetes `token-never-leaks` manifest test, both on every PR. This is the claim most products in this space get wrong, and fluidbox gets it right.

**Tenant isolation is genuinely defence-in-depth.** `TenantScope` as a *signature* requirement is a better design than a filtering convention, because forgetting it is a compile error rather than a leak. Migration 0018's 37-table `ENABLE`+`FORCE` RLS is real depth underneath. Independently probed as the non-owner `fluidbox_runtime` role on both a live EKS deployment and Docker: correct rows per tenant GUC, zero without it, cross-tenant write refused by the `WITH CHECK` arm, `UPDATE`/`DELETE` → `42501`. The caveats — shared catalog rows readable by design, RLS inert for SUPERUSER/BYPASSRLS, `SET ROLE` is not a credential boundary — are all stated correctly and prominently by the project itself.

**Frozen `RunSpec` immutability survived a hostile test.** Byte-identical across migration `0026`, which drops four columns, measured on two independent deployments. A live run confirmed `run_spec.policy_snapshot == policy_versions[v2].content` exactly. This is the property that makes the audit trail meaningful, and it was verified rather than asserted.

**The brokered MCP path is the enforcement story done right.** Because the control plane executes the call, the gate is structural. Layered on top: frozen-set availability, frozen-schema validation with the dialect chosen from the snapshot's protocol version, protocol-drift denial, four-state durable execution claims where only positively-proven `failed_before_send` is re-claimable, live credential re-resolution on the terminal `DELETE`, and per-run session registries never shared across runs. If the in-sandbox path had this shape, BLK-01 would not exist.

**Audience-scoped sandbox tokens.** Four separate `api_tokens` rows, `require_audience` as the first statement of every guarded handler, and — importantly — an **exhaustive** route × audience matrix in CI asserting the response body is byte-equal to `{"error":"wrong_audience"}`. Observed live on kind carrying exactly the four expected keys. The `ptrace` residual is disclosed accurately.

**The archive unpacker is carefully hardened.** Symlink entries are deferred to a second phase and each validated with `canonicalize`, which resolves the full chain — the only correct approach, since lexical analysis cannot resolve a target routed through other symlinks. Bounded symlink-entry count, no absolute paths, no `..`, refuses a symlinked destination. `git` invocations pin `GIT_ALLOW_PROTOCOL`, disable LFS smudging, and disable redirect following, asserted against the production argv builders.

**Fail-safe defaults where it matters.** `RuleAction::default() == Approve`; `AutonomousFallback::default() == Deny`; fork detection fails *toward* fork; the netpol gate fails *closed*; a pre-0026 binary against a 0026 database refuses to boot loudly rather than serving wrong results.

**Documentary honesty.** `README.md:114` declines to claim a 300-run ceiling it has not proven. `README.md:243` says plainly that `host-dev` is not a boundary. `docs/hosted/threat-model.md` carries a 17-row residual table, marks two Phase E rows *partially shipped*, and contains an explicit self-correction (`:194-204`) retracting a closure a previous revision claimed. The 2026-07-27 validation reports its own evidence strength, distinguishes measured from inferred, and flags the finding that damages it most. **This is the disposition that makes the recommendation in §8 realistic** — the project already writes down inconvenient truths; four sentences need to join them.

---

## 7. Remaining audit gaps

| Gap | Why it remains | To close it |
|---|---|---|
| Live reproduction of BLK-01 | Mandate forbade model spend | One haiku-class run under a `Bash → approve` policy with a nonce task (~$0.02) |
| BLK-01 on Kubernetes with a live agent | The 2026-07-27 report drove `/permission` directly on kind and EKS; it did not re-run the nonce test with a live agent. Same image, same SDK ⇒ likely identical, but that is inference | AT-01b on kind |
| Root cause of BLK-01 *within* the SDK | The SDK ships minified (`sdk.mjs`); only the type contract was readable. §3.2 establishes the **class** — that `canUseTool` is ask-path-only — not **which** of the eleven decision paths fired | SDK-side instrumentation, or a vendor question |
| `apps/web` dashboard | Out of time; presentation-only by constraint | A pass on `proxy.ts` cookie/CSRF handling in `sso` mode |
| Cryptographic primitive usage in `seal.rs`/`kms.rs` | Structure reviewed and sound; primitives not audited | Dedicated crypto review |
| `fluidbox-db` (25.7 kLOC) | Only tenant-scoping and RLS posture examined | Systematic pass on the remaining repository functions |
| `broker.rs` / `oauth.rs` / `governor.rs` internals | Read at the level of ordering and admission, not exhaustively | Targeted review of the OAuth state machine, which is the most intricate surface |
| Dependency CVE status | `cargo deny check` not executed in this pass | Run it; `deny.toml` itself is well-configured with one documented, well-reasoned RUSTSEC ignore |
| Fuzzing of the archive unpacker and diff collector | Hardening read, not exercised adversarially | Fuzz `unpack_archive_reader` with hostile tar |
| Multi-replica fault injection | Requires infrastructure | Rollout Gate 5 already schedules this |
| Load/capacity | Explicitly out of scope for this pass and correctly disclaimed by the project | Rollout Gates 3–5, issue #34 |

---

## 8. Recommendation

**NO-GO for a broad public launch** in the current state, because a security-conscious adopter would rely on `README.md:72`, `README.md:245`, and `PLAN.md:39`, and those sentences are measurably false for the tools an agent uses to change code.

Two paths convert this to GO. Either is defensible; the second is cheaper and, given this project's demonstrated disposition, more in character.

**Path A — fix the two that need fixing.**
- **AT-01a** — server-side detection: flag a run that reached a terminal state with a non-empty diff and zero `tool.decision` events. Needs no harness cooperation, no SDK change, and converts a silent failure into a loud one. Highest value per unit of work identified by this pass.
- **AT-04a/b** — bind the eval compose to `127.0.0.1` and stop shipping a published admin token as a default. A one-line change plus a token default.

With those two, BLK-02 becomes bounded-and-observable rather than silent, and BLK-03/05/06/07 are disclosable in release notes.

**Path B — reframe the claims to what is actually enforced.**
- *"Brokered MCP calls cannot execute without a server-side decision."* — true, structural, well-tested.
- *"In-sandbox tool calls are gated when the harness routes them; containment is the control that binds a harness that does not."* — true, and the honest version.
- BLK-04 still needs fixing under either path; it is the smallest item on the list.

**What must not happen** is a launch with those four sentences unchanged. A competent reviewer will reach the same measurement inside a day — this project's own validation did, and wrote it down in §8b of a report that was then merged. Publishing the claim after that measurement exists is the difference between an honest pre-1.0 project with a known gap and a project that shipped a security claim it had already disproved.

**The counterweight, stated as plainly as the finding.** The engineering underneath is good, the tenant and credential boundaries are real and independently verified, and the project has a consistent record of writing down what it has not proven. Four sentences and two default values stand between this assessment and a defensible GO.

---

## Related documents

- [`public-claims-audit.md`](public-claims-audit.md) — every material public claim, classified against executable evidence
- [`../security/threat-model.md`](../security/threat-model.md) — attacker model, assets A1–A9, adversaries T1–T12, chains A–F
- [`../launch/launch-blockers.md`](../launch/launch-blockers.md) — ranked P0–P3 with reproduction paths and acceptance tests
- [`2026-07-27-pr92-two-environment-validation.md`](2026-07-27-pr92-two-environment-validation.md) — source of every measured claim
- [`../hosted/threat-model.md`](../hosted/threat-model.md) — the hosted builder's model; still authoritative for T3–T9
- [`../hosted/rollout-gates.md`](../hosted/rollout-gates.md) — capacity and promotion gates, correctly scoped and unchanged by this pass
