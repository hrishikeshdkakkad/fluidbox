# Session handover — 2026-07-14 (codex MCP bug + connector catalog)

Branch: `claude/repo-roadmap-next-steps-2u5cky`. Everything below is on that branch.

## TL;DR
- **Shipped/committed:** synced PR #25 (catalog bulk import) into the branch; committed a real bug fix — `ca72462 fix(facade): keep codex's client-executed tool_search…`.
- **Biggest open item:** a **codex↔MCP bug has TWO parts.** Part 1 is fixed & committed. **Part 2 is root-caused but NOT fixed** — it needs a codex runner-image change. This is the thing to pick up next.
- **Catalog now:** 17 cards = 7 fluidbox seeds + 10 hand-curated OAuth remote-MCP cards. The trial bulk-import (migration 0010) was applied then **fully reverted**; latest migration is back to `0009`.
- **DB was fully reset** at the user's request: all `integration_connections` + `github_app_registrations` wiped → **the live GitHub App is disconnected** (re-run seamless connect to restore).
- **Uncommitted dashboard WIP:** a "render tools in the connector modal" feature + a Geist restyle live in `apps/web/app/capabilities/page.tsx` and `apps/web/app/geist.css` (alongside pre-existing dashboard redesign WIP).

---

## 1. The codex ↔ MCP bug (MAIN THREAD — has an open half)

**Symptom:** codex-harness runs with a brokered bundle frozen (e.g. `cloudflare@1`, 23 tools) couldn't use the tools. Claude harness unaffected.

### Bug #1 — facade stripped `tool_search` — FIXED (commit `ca72462`)
`crates/fluidbox-server/src/facade.rs`. codex 0.144.1 **always defers MCP tools behind `tool_search`** (`tool_search_always_defer_mcp_tools` is baked `true` — confirm with `codex features list`). `strip_server_tools`/`is_client_tool` classified `tool_search` as server-executed and removed it → the model never received the only handle to the MCP tools → agent reported "MCP registry is empty." Fix: keep `tool_search` when `execution == "client"` (still strips `web_search` + server-executed variants); each real MCP call still crosses the gate at `/tools/call`. Regression test `openai_client_executed_tool_search_survives_the_strip` added. Verified: agent flipped from "MCP registry is empty" → "I found the Cloudflare MCP actions for KV/D1/R2/Workers" and now actually *calls* the tools.

### Bug #2 — codex-runner drops `item/tool/call` — ROOT-CAUSED, **NOT FIXED**
After #1, the agent calls e.g. `kv_namespace_create`, but every call returns **`user rejected MCP tool call`** with **ZERO `tool.requested`/`tool.brokered` events** in the fluidbox ledger — the call is rejected **inside the codex runner**, before the broker-shim / gate. Confirmed across runs `019f62a7`, `019f62aa`, incl. `autonomy=autonomous` (so it's below fluidbox's policy layer).

Root cause: `images/codex-runner/runner/index.mjs` → `handleServerRequest` only handles `item/{commandExecution,fileChange,permissions}/requestApproval`, `item/tool/requestUserInput`, `mcpServer/elicitation/request`; everything else hits `default` → JSON-RPC `-32601` (method-not-found). Codex fires **`item/tool/call`** (server→client) to run client-executed tools (`tool_search`, and MCP-tool routing). Unhandled → codex treats it as rejected. Reference supervisor handles it at `/private/tmp/openclaw-audit.MSbLJG/extensions/codex/src/app-server/client.ts:569` (and `:613`).

**Fix direction:** add an `item/tool/call` handler in the codex runner that (a) runs `tool_search`, and (b) for brokered MCP tools AUTO-ALLOWS (the broker-shim + server-side `/internal/sessions/{id}/tools/call` gate is the real authority — mirror the Claude runner's `canUseTool` brokered auto-allow). Then **rebuild the codex image** (`fluidbox-codex-runner:dev`, ~1.36 GB) and restart. **Confirm the exact method/shape first** by capturing codex's server→client requests during a real MCP call — the repro harness is in the session scratchpad: `drive*.mjs` + `mock-mcp.mjs` + `sink.mjs` drive `codex app-server` inside the image; or run codex with `RUST_LOG=codex=debug`.

Full write-up in memory: `fluidbox-codex-mcp-toolsearch-bug.md`.

---

## 2. Connector catalog
- **Bulk import is a dead end** — the MCP Registry has **no popularity signal** and is flooded with `ai.smithery/*` proxy re-hosts. Migration `0010` (a 558-row sample) was applied then **fully reverted** (rows deleted, `_sqlx_migrations` v10 dropped, file removed, binary rebuilt clean). Latest migration = `0009`.
- **10 curated OAuth remote-MCP cards added** (direct SQL, `tier=verified`, `transport=streamable_http`, `auth_mode=oauth`, `provenance.source=curated`): cloudflare, supabase, vercel, neon, paypal, square, asana, canva, webflow, zapier. Endpoints (use the `/mcp` streamable-http variant) are listed in memory `fluidbox-catalog-import.md`. OAuth Connect verified initiating (Canva returned an `authorize_url` via CIMD/ngrok). Excluded Figma (local) + Intercom (non-standard OAuth discovery).

## 3. Database state
- **Full reset performed** (user-chosen): wiped ALL `integration_connections` (117), ALL `github_app_registrations` (20) + flows, `capability_bundles`, run history (`sessions`/`events`), trigger subs, custom catalog rows. **Kept** agents + the 17-card catalog.
- ⚠️ **GitHub App is disconnected** — fluidbox no longer custodies it. Re-run the seamless GitHub connect/sync (admin intent) to restore. (See memory `fluidbox-ngrok-deployment.md`.)
- The `cloudflare-mcp-test` automation: subscription `019f62a9-3e60-7131-9667-5d30cf4fbd14`, agent `clouflare-mcp-test-resource`, cloudflare@1 attached.

## 4. Dashboard (UNCOMMITTED WIP)
`apps/web/app/capabilities/page.tsx` + `apps/web/app/geist.css`:
- **Feature:** the connector detail modal now renders a connected bundle's photographed tools (fetches `GET /capabilities/{entry.bundle.id}`, renders via a shared `<ServerTools>` component reused by the Bundles tab). Pure frontend, no API change.
- **Geist restyle** of that modal: structured egress chip, color-coded policy-hint pills, status line + bundle chip, a scrollable sticky-header tool list (2-line-clamped descriptions). Verified in-browser on the Cloudflare card.
- These sit **on top of** pre-existing dashboard-redesign WIP (`ResourceOverview.tsx`, `RunComposer.tsx`, `AutomationPanel.tsx`, `geist.css`, etc.) — all uncommitted.

## 5. Git state
- **Committed on branch:** merge of `origin/main` (PR #24 + #25) as `63f16cb`; then `ca72462` (facade fix, `facade.rs` only).
- **Uncommitted:** all the dashboard WIP (`M apps/web/...`, `?? geist.css`, new components) + helper scripts below. `main` is PR-only (ruleset) — merge via `gh pr merge --admin`.

## 6. Helper artifacts (local, untracked)
- `./run-agent.sh <agent-name> [task…]` — repo-dir CLI: creates a session for ANY agent via the admin API (reads `FLUIDBOX_ADMIN_TOKEN` from `.env`). e.g. `./run-agent.sh clouflare-mcp-test-resource "…"`.
- `invoke-cloudflare-mcp-test.sh` (scratchpad, sent to user) — curl that fires the `cloudflare-mcp-test` trigger with a fresh `Idempotency-Key` each run.
- codex repro harness in the session scratchpad: `drive*.mjs`, `mock-mcp.mjs`, `sink.mjs`.

## 7. Next steps (priority order)
1. **Fix bug #2** — add the `item/tool/call` handler to the codex runner, rebuild `fluidbox-codex-runner:dev`, restart, then re-run `./run-agent.sh clouflare-mcp-test-resource` → expect a real brokered `kv_namespace_create` reaching the ledger (pauses on `writes → approve`). This is the one thing standing between "agent finds the tools" and "agent uses them."
2. Decide whether to commit the dashboard WIP (tools-in-modal + Geist restyle) or keep iterating.
3. Reconnect the GitHub App if you need GitHub automations again.
4. (Optional) apply the same modal treatment to the other connector states for consistency.

## Environment reminders
- Server on `:8787`, web on `:3000`, LiteLLM gateway container up; run via `just dev` (currently running the fixed build).
- `FLUIDBOX_DEFAULT_MODEL=claude-haiku-4-5`; codex tier = `gpt-5.4-mini` (small — tends to explore with Bash on scratch workspaces; give it a clear "use the MCP tools directly" task).
- Relevant memory files: `fluidbox-codex-mcp-toolsearch-bug.md`, `fluidbox-catalog-import.md`, `fluidbox-ngrok-deployment.md`, `fluidbox-sequencing.md`.
