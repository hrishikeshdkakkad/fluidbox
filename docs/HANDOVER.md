# fluidbox — Session Handover

**Date:** 2026-07-10 · **State:** M0 + M1 complete, built and verified end-to-end with a live agent.

Read `CLAUDE.md` (commands + invariants + gotchas) and `PLAN.md` (authoritative design + roadmap) alongside this. This doc is the "where we are right now / how to pick up" note.

---

## 1. Current status: what works

M1 (the local-first governed MVP) is **done and proven live**, not just compiled:

- **Full run lifecycle** `created → provisioning → initializing → running ↔ awaiting_approval → completed|failed|cancelled|budget_exceeded`, server as single status writer.
- **Live agent demo (demo A)** ran from both the CLI and the dashboard: the Claude Agent SDK agent provisioned a sandbox, ran a failing test, diagnosed the `multiply` bug, edited the file, re-ran to confirm, and completed — clean diff + accurate cost. Isolation confirmed (original repo untouched; only the sandbox copy changed).
- **Governance plane (demos B & C mechanics)** proven via `scripts/governance-e2e.sh` — 14/14 checks over real HTTP: policy allow/deny, approval pause→resume, `tool_call_id` idempotency, autonomous instant-deny with the ledger recording `source=autonomy_rewrite` + `original_verdict`.
- **LLM gateway** (LiteLLM, pinned by digest) + Rust facade with SSE tee metering; the sandbox's fake `ANTHROPIC_API_KEY` is its session token, real key isolated to the gateway.
- **Dashboard** (Next.js 16, control-room UI): Operations, New Run, live SSE timeline, agents registry + add-revision, approvals inbox, policies YAML editor + validate, settings/health.
- **Quality bar:** `cargo clippy --workspace -D warnings` clean; 25 unit/integration tests + 14 governance E2E checks green. ~4,900 lines of Rust across 5 crates.

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

- **Run the acceptance suite:** `set -a; source .env; set +a; cargo test --workspace` then `bash scripts/governance-e2e.sh`.
- **Live agent run:** ensure `ANTHROPIC_API_KEY` in `.env` + `just gateway-up`, then `cargo run -p fluidbox-cli -- run --task "…" --repo /abs/path` or use New Run in the dashboard.
- **Change the default model:** Agents page → expand `claude-fixer` → Add revision (or `POST /v1/agents/{id}/revisions`). The current (latest) revision is what runs use.
- **Rebuild the sandbox image** after editing `images/sandbox-runner/`: `just sandbox-build`.

---

## 6. Logical next steps

Ordered by leverage. The seams for all of these already exist (that's the point of the M1 architecture) — none require reworking the core.

### A. Near-term hardening (before scaling out) — ~1 short session
The system is demo-proven but thin on failure-mode coverage. Highest-value before building M2:
1. **Automate the demos as CI-runnable tests** — wrap demo A + `governance-e2e.sh` behind a `just e2e` that spins the gateway, seeds a temp repo, asserts `completed` + diff + cost. Right now they're manual.
2. **Failure-path tests that PLAN.md lists but aren't automated:** kill a running container mid-run → watchdog fails + reaps; `max_tool_calls: 2` → `budget_exceeded`; restart server with a live sandbox → boot orphan sweep. The code paths exist; they need assertions.
3. **The two reserved policy decisions** (PLAN.md §10): tune the shell-risk classifier (`policies/default.yaml` deny_regex/allow_prefixes) against real agent behavior, and pick real seed budget numbers. These are judgment calls best made now that you can watch real runs.

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

**Recommended sequence:** do **A** first (cheap, de-risks everything downstream), then **B** (it's the product's headline promise and the hardest integration — worth tackling while the design is fresh), then **C**, then **D**.
