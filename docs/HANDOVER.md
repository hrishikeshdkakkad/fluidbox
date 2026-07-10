# fluidbox — Session Handover

**Date:** 2026-07-10 (rev 2: §6.A hardening shipped) · **State:** M0 + M1 complete + near-term hardening done; one-command acceptance suite green.

Read `CLAUDE.md` (commands + invariants + gotchas) and `PLAN.md` (authoritative design + roadmap) alongside this. This doc is the "where we are right now / how to pick up" note.

---

## 1. Current status: what works

M1 (the local-first governed MVP) is **done and proven live**, not just compiled:

- **Full run lifecycle** `created → provisioning → initializing → running ↔ awaiting_approval → completed|failed|cancelled|budget_exceeded`, server as single status writer.
- **Live agent demo (demo A)** ran from both the CLI and the dashboard: the Claude Agent SDK agent provisioned a sandbox, ran a failing test, diagnosed the `multiply` bug, edited the file, re-ran to confirm, and completed — clean diff + accurate cost. Isolation confirmed (original repo untouched; only the sandbox copy changed).
- **Governance plane (demos B & C mechanics)** proven via `scripts/governance-e2e.sh` — 14/14 checks over real HTTP: policy allow/deny, approval pause→resume, `tool_call_id` idempotency, autonomous instant-deny with the ledger recording `source=autonomy_rewrite` + `original_verdict`.
- **LLM gateway** (LiteLLM, pinned by digest) + Rust facade with SSE tee metering; the sandbox's fake `ANTHROPIC_API_KEY` is its session token, real key isolated to the gateway.
- **Dashboard** (Next.js 16, control-room UI): Operations, New Run, live SSE timeline, agents registry + add-revision, approvals inbox, policies YAML editor + validate, settings/health.
- **Quality bar:** `cargo clippy --workspace -D warnings` clean; 28 unit/integration tests green; **`just e2e` = 45 acceptance checks green** (9 live demo A + 14 governance + 22 failure-path). ~5,000 lines of Rust across 5 crates.

## 2. What's running right now (dev environment)

| Service | Where | Notes |
|---|---|---|
| fluidbox-server | host, `:8787` | `cargo run -p fluidbox-server`; bound `0.0.0.0` |
| dashboard | host, `:3000` | `pnpm dev` in `apps/web` |
| LiteLLM gateway | docker `deploy-litellm-1`, `:4000` | holds the real Anthropic key; pinned by digest in `.env` |
| Neon Postgres | cloud project `fluidbox` | endpoint `ep-fancy-recipe-a6lovnla` (us-west-2) |

To restart from cold: `just gateway-up` then `just dev` (needs `.env` populated, incl. `ANTHROPIC_API_KEY`).

Seeded state: agent `claude-fixer` is on **rev 4 = haiku** (current, so new runs are cheap); opus rev 3 preserved in history. Default policy seeded from `policies/default.yaml`. A `test-seq-agent` exists as a leftover from the db integration test (harmless).

## 3. Locked decisions (don't re-litigate without reason)

- **North star** (PLAN.md §2): agent-registry platform. The MVP is the final architecture at n=1 (one harness, one provider, one bundle) — never mock scaffolding. Every milestone must preserve the §2 convergence invariants.
- **Model gateway = LiteLLM behind a thin Rust facade** (not a hand-built proxy). Facade upstream is `LLM_UPSTREAM_URL` → direct-Anthropic + in-facade tee metering is the one-line fallback.
- **Autonomy from M1**: `supervised | autonomous` on the RunSpec; autonomous rewrites `RequireApproval` to the policy fallback (default deny), `canUseTool` always wired.
- **GitHub integration is descoped to the roadmap** — "Connect GitHub" is just a stored fetch token consumed by the control-plane-side workspace-init phase.
- **Runtime:** Docker now; Lambda MicroVMs are M2. **Harness:** Claude Agent SDK now; Codex + capability catalog are M3.

## 4. Known rough edges (small, non-blocking)

- **New Run modal button toggles on each click** — a double-click opens-then-closes it. Cosmetic; make the header button open-only if it annoys.
- **Add-revision can't clear a system prompt** — omitting it inherits the previous revision's prompt (there's no "set to none" path). Minor API gap.
- **No delete for agents/policies/sessions** — registry only grows in the UI. Fine for M1.
- **LiteLLM runs under amd64 emulation on this arm64 Mac** — works, slightly slower boot. A native arm64 tag or `platform` override would speed it up.
- **`git-url` repos are not enabled** — `RepoSource::GitUrl` bails in `orchestrator.rs`; only local paths / scratch workspaces work in M1 (by design — GitHub is roadmap).

## 5. How to resume common tasks

- **Run the acceptance suite:** `just e2e` (stop `just dev` first — the suite owns the stack). Phases: live demo A (self-skips without `ANTHROPIC_API_KEY`), governance plane, failure paths. Unit tests: `set -a; source .env; set +a; cargo test --workspace`.
- **Edit the seed policy:** change `policies/default.yaml` **and** the `seed_policy_semantics` test that pins it, then `just policy-sync` to push it to the running control plane (version++; in-flight runs keep their frozen snapshot).
- **Live agent run:** ensure `ANTHROPIC_API_KEY` in `.env` + `just gateway-up`, then `cargo run -p fluidbox-cli -- run --task "…" --repo /abs/path` or use New Run in the dashboard.
- **Change the default model:** Agents page → expand `claude-fixer` → Add revision (or `POST /v1/agents/{id}/revisions`). The current (latest) revision is what runs use.
- **Rebuild the sandbox image** after editing `images/sandbox-runner/`: `just sandbox-build`.

---

## 6. Logical next steps

Ordered by leverage. The seams for all of these already exist (that's the point of the M1 architecture) — none require reworking the core.

### A. Near-term hardening — ✅ DONE 2026-07-10
All three items shipped (plan: `docs/superpowers/plans/2026-07-10-6a-hardening.md`):
1. **`just e2e`** — one command, three phases, 45 checks: `scripts/e2e.sh` orchestrates `e2e-live.sh` (demo A: live agent fixes a failing test → completed + diff + cost + isolation), `governance-e2e.sh`, `e2e-failures.sh`, over a shared `e2e-lib.sh`.
2. **Failure paths automated** (`scripts/e2e-failures.sh`): tool-call budget stop, dead-container watchdog, restart orphan sweep (reaps unknown-session containers, spares live sessions), **plus a newly-found gap fixed**: sessions stuck in `created`/`provisioning`/`initializing` after a control-plane crash are now failed by a 15-min stale-launch sweep (`Created→Failed` edge added; two real zombie rows in Neon got cleaned by it).
3. **PLAN §10 #1 + #3 resolved** from ledger data: classifier tuned (read-only utils allowed; any force-push spelling and split-flag `rm -rf /` denied) and budgets set to 1800 s / 1 M tokens / $2.50 / 100 tool calls — pinned by `seed_policy_semantics`. Bonus fix: `policy.budgets` was parsed but never read; it's now a **ceiling** at session creation. Live DB policy synced (v4).

### B. M2 — Lambda MicroVM provider + BYOC (the flagship runtime) — the big one
Implement `LambdaMicrovmProvider` behind the existing `ExecutionProvider` trait. This is where "customer-owned execution" becomes real. Key work (all validated in PLAN.md §2/§7):
- `RunMicrovm` + image pipeline (S3 zip → snapshot), in-VM supervisor serving the runner contract, JWE token minting/refresh inside `EndpointHandle` (60-min TTL → refresh loop), 8-hour lease rollover + `Harness::checkpoint()` in the orchestrator, idle-suspend/resume for long-running autonomous agents.
- Terraform BYOC module + S3 workspace/artifact store.
- **Why it's the seam it is:** `SandboxHandle` is already serializable jsonb and the `initializing` workspace phase is provider-agnostic, so nothing above the trait changes. Prove it by running the *same* demo A on the MicroVM provider with only a `runs_on: lambda-microvm` toggle.

### C. M3 — Multi-harness + capability catalog (completes the north star)
- **Codex runner:** second first-party image (`codex mcp-server` via rmcp, or the TS Codex SDK as payload). OpenAI key custody moves into the same LiteLLM gateway. This proves the harness abstraction with n=2.
- **Capability-bundle catalog:** tool/MCP bundles as first-class registry objects with credential brokering; UI to attach/narrow them per revision. Every MCP call policy-gated like any tool.
- **Customer-signed runner images** — the "bring your own agent" endgame.

### D. Roadmap — triggers & integrations (descoped from MVP)
GitHub App (webhook ingress, trigger router, fork-PR trust tier, Checks/PR-comment writers), then Slack/Jira. The seams (`sessions.trigger` jsonb, `trust_tier`, event-ingress boundary) already ship in M1 — a trigger just *creates a run of a registered agent*, so the run model doesn't change.

**Sequence (user decision 2026-07-10):** ~~A~~ done → **next is the "borrow the agent, on demand" axis (D + the M3 bundle piece), ahead of B/M2 MicroVMs**. The user's priority list: (5) API + scheduled triggers, (6) custom tools/MCP bundles, (7) git sign-in + repo on agent config (enable `RepoSource::GitUrl`), (8) GitHub PR-review triggers / vertical integrations. Slice ordering within 5–8 is still open — brainstorm it first. **Read `docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md` (user-authored, same day): it is the product/architecture direction for this exact phase** (workspace / invocation context / capabilities / result destination as the four optional inputs around an unchanged agent definition). PLAN.md roadmap order: trigger tokens → scheduled runs → result delivery → git sign-in → GitHub App.
