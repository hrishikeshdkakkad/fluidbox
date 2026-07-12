# Codex `app-server` JSON-RPC protocol reference (verified, codex-cli 0.144.1)

**Binary:** `/opt/homebrew/bin/codex` — `codex-cli 0.144.1`. Start with `codex app-server` (stdio is the default transport).
**Date:** 2026-07-12.
**Purpose:** wire-accurate reference for a Node "supervisor" that starts a coding session, streams events, and answers approval requests over `codex app-server`.

Sources for every claim below are either:
- **[schema]** — a file under the generated bundle `…/scratchpad/codex-schema.json/` (top-level `*.json`, plus `v2/*.json`). `ClientRequest.json` = requests we send; `ServerRequest.json` = requests codex sends us (approvals); `ServerNotification.json` = the event stream.
- **[live]** — captured from actually spawning `codex app-server` on this machine.
- **[ref-impl]** — the OpenClaw Codex app-server client at `/private/tmp/openclaw-audit.MSbLJG/extensions/codex/src/app-server/` (a production Node supervisor speaking this exact protocol; treat as a second witness, not spec).
- **[docs]** — `learn.chatgpt.com/docs/config-file/*` (the current home of the Codex config reference; `developers.openai.com/codex/*` 308-redirects there).

---

## 0. TL;DR — the load-bearing facts

1. **Framing is newline-delimited JSON (NDJSON), NOT LSP `Content-Length`.** One JSON object per line, `\n`-terminated. **[live]**
2. **This build's app-server is the v2 `thread/*` + `turn/*` surface.** `ClientRequest.json` has `initialize`, `thread/start`, `turn/start`, `turn/interrupt`, `turn/steer`, `item/*` — and **no** legacy `newConversation`/`sendUserTurn`. **[schema: ClientRequest.json]**
3. **Approvals fire as the v2 `item/*/requestApproval` requests, NOT the legacy `execCommandApproval`/`applyPatchApproval`.** The reference supervisor registers handlers for exactly `item/commandExecution/requestApproval`, `item/fileChange/requestApproval`, `item/permissions/requestApproval` and nothing else. **[ref-impl: client.ts:790-792, approval-bridge.ts:275-289]**
4. **The v2 approval decision enum is `accept` / `acceptForSession` / `decline` / `cancel`** — **not** `approved`/`denied`. Single-approval (the design's requirement) = **`{"decision":"accept"}`**. Session-scope grant (forbidden by design) = `acceptForSession`. **[schema: CommandExecutionRequestApprovalParams.json, FileChangeRequestApprovalResponse.json]**
5. **System prompt goes in `thread/start.developerInstructions`** (a first-class app-server field — no repo `AGENTS.md` needed). **[schema: v2/ThreadStartParams.json; ref-impl: attempt-startup.ts:371]**
6. **To force EVERY exec (incl. `cat`/`ls`) to an approval request:** set `approvalPolicy:"untrusted"` **and** load an execpolicy rule file with a universal `prompt` rule (`~/.codex/rules/*.rules`). `untrusted` alone still auto-runs "known-safe" reads; the execpolicy rule removes that exception. **[docs: config-reference, agent-configuration/rules; live: `codex execpolicy check`]**

### Divergences from the design's stated assumptions

| Design assumed | Reality in 0.144.1 | Action |
|---|---|---|
| `execCommandApproval` / `applyPatchApproval` fire | v2 `item/commandExecution/requestApproval` / `item/fileChange/requestApproval` fire (legacy methods exist in `ServerRequest.json` but are dead on the v2 surface) | Handle the `item/*` methods |
| Reply `{"decision":"approved"}` | v2 wants `{"decision":"accept"}` (`approved` is the *legacy* `ReviewDecision`) | Send `accept`; deny with `decline` (or `cancel` to also abort the turn) |
| Approval `command` is an argv array | v2 exec approval gives `command` as a **nullable display string** + parsed `commandActions[]` (only the *legacy* `ExecCommandApprovalParams` carries argv `command: string[]` + `parsedCmd`) | Read `command` string; parse if you need argv, or correlate `itemId` to the `commandExecution` thread item |
| Stable id = `callId` | v2 ties the request to `itemId` (+ `threadId`/`turnId`); `approvalId` only appears for zsh-exec-bridge subcommands | Dedup on `itemId` (fall back to `approvalId` when present) |

---

## 1. Transport & framing (verified live)

**NDJSON.** No `Content-Length` headers. Each JSON-RPC message is a single line terminated by `\n`. Requests you send should carry `"jsonrpc":"2.0"`; **codex's responses/notifications omit the `jsonrpc` field** — parse tolerantly. **[live]**

Live probe (sent one line, read stdout):
```
→ {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"clientInfo":{"name":"probe","title":"probe","version":"0.0.1"}}}
← {"id":0,"result":{"userAgent":"probe/0.144.1 (Mac OS 26.6.0; arm64) …","codexHome":"/Users/<you>/.codex","platformFamily":"unix","platformOs":"macos"}}
← {"method":"remoteControl/status/changed","params":{"status":"disabled", …}}   ← unsolicited notification after init
```

- **No auth needed for `initialize`.** It answered with no `OPENAI_API_KEY` and no ChatGPT session. Running an actual *turn* needs auth (this machine is `Logged in using ChatGPT`; a fresh box needs `codex login` or `OPENAI_API_KEY`).
- Default transport is `stdio://`. Other transports (`--listen unix://…`, `ws://…`) exist but stdio is correct for a spawned child. **[live: `codex app-server --help`]**
- Codex emits unsolicited notifications immediately after `initialize` (e.g. `remoteControl/status/changed`). The supervisor must tolerate notifications interleaved at any time.

---

## 2. Handshake — `initialize` (+ `initialized`)

**Request** `initialize` **[schema: v1/InitializeParams.json, ClientRequest.json]**
```json
{"jsonrpc":"2.0","id":0,"method":"initialize",
 "params":{"clientInfo":{"name":"fluidbox-supervisor","title":"Fluidbox","version":"0.1.0"}}}
```
- `params.clientInfo` **required** (`ClientInfo`: `name`, plus optional `title`, `version`). `params.capabilities` optional (`InitializeCapabilities`).

**Response** `InitializeResponse` **[schema: v1/InitializeResponse.json; live]**
```json
{"id":0,"result":{"userAgent":"…/0.144.1 …","codexHome":"/Users/<you>/.codex",
 "platformFamily":"unix","platformOs":"macos"}}
```
Required result fields: `userAgent`, `codexHome`, `platformFamily`, `platformOs`.

**Then send the `initialized` client notification** (no params) to complete the handshake, LSP-style. **[schema: ClientNotification.json → `initialized`]**
```json
{"jsonrpc":"2.0","method":"initialized"}
```

---

## 3. Start a session + first turn

Minimal happy path: `initialize` → `initialized` → **`thread/start`** → **`turn/start`**.

### 3a. `thread/start` → `ThreadStartResponse` **[schema: v2/ThreadStartParams.json, v2/ThreadStartResponse.json]**

All params optional. The ones that matter:

```json
{"jsonrpc":"2.0","id":1,"method":"thread/start","params":{
  "cwd":"/abs/path/to/workspace",
  "model":"gpt-5.6-sol",
  "approvalPolicy":"untrusted",
  "approvalsReviewer":"user",
  "sandbox":"read-only",
  "developerInstructions":"<YOUR SYSTEM PROMPT — who the agent is>",
  "config":{ "tools.web_search":false, "tools.view_image":false }
}}
```

| param | type | notes |
|---|---|---|
| `cwd` | string | working dir for the thread. |
| `model` | string | e.g. `gpt-5.6-sol`; omit to use config default. |
| `approvalPolicy` | `AskForApproval` | `"untrusted"` \| `"on-request"` \| `"never"` \| `{"granular":{…}}`. **Use `"untrusted"`** (strictest built-in). |
| `approvalsReviewer` | enum | `"user"` \| `"auto_review"` \| `"guardian_subagent"`. **Set `"user"`** so approvals route to the supervisor; `auto_review` hands them to an LLM subagent (defeats governance). Default is `user`. |
| `sandbox` | `SandboxMode` | `"read-only"` \| `"workspace-write"` \| `"danger-full-access"`. (Typed field; equivalent to config `sandbox_mode`.) |
| `developerInstructions` | string | **the system prompt / developer message.** This is the app-server-native injection point the design wants. |
| `baseInstructions` | string | **replaces** Codex's built-in base prompt entirely — avoid unless you intend to own the whole prompt. |
| `config` | object (freeform) | raw `config.toml` overrides merged for this thread (`additionalProperties:true`). Where you set `tools.*`, `features.*`, etc. **[ref-impl passes `config: threadConfig` here — attempt-startup.ts]** |
| `ephemeral` | bool | don't persist thread to disk. |

**Response** `ThreadStartResponse`: `{ thread: Thread, approvalPolicy, approvalsReviewer, sandbox (SandboxPolicy), cwd, model, modelProvider, instructionSources[] }`. Grab **`result.thread.id`** — that's the `threadId` for `turn/start`. `instructionSources[]` lists the instruction files Codex actually loaded — check it to confirm no stray `AGENTS.md` leaked in.

### 3b. `turn/start` → `TurnStartResponse` **[schema: v2/TurnStartParams.json, v2/TurnStartResponse.json]**

```json
{"jsonrpc":"2.0","id":2,"method":"turn/start","params":{
  "threadId":"<thread.id from thread/start>",
  "input":[{"type":"text","text":"<THE TASK — what to do this run>"}]
}}
```

- `threadId` **required**.
- `input` **required** — array of `UserInput`. Text item = `{"type":"text","text":"…"}`. Other variants: `image` (`url`), `localImage` (`path`), `skill`, `mention`.
- Per-turn overrides (all optional, and they **persist to subsequent turns**): `approvalPolicy`, `sandboxPolicy` (note: object form `SandboxPolicy`, not the `SandboxMode` string), `model`, `effort`, `cwd`, `summary`, `outputSchema` (JSON Schema to constrain the final message).
- **No `developerInstructions` on `turn/start`** — the system prompt is a thread-level concern (set it once on `thread/start`). The task is per-turn.

**Response** `TurnStartResponse`: `{ turn: Turn }` (turn `id`, `status`, `items`). The turn then streams via notifications (§4).

> **System-prompt vs task split (matches the design's invariant):** `developerInstructions` on `thread/start` = *who the agent is*; `input` on `turn/start` = *what to do this time*.

---

## 4. Approval requests codex sends us (ServerRequest — the governance hook)

These arrive as **JSON-RPC requests** (they have an `id`) on the same stdout stream. Reply with a JSON-RPC result carrying the same `id`.

**Which ones actually fire on the v2 surface:** `item/commandExecution/requestApproval` (shell/exec), `item/fileChange/requestApproval` (apply_patch / edits), `item/permissions/requestApproval` (sandbox-escalation). **[schema: ServerRequest.json; ref-impl: client.ts:790-792, approval-bridge.ts:275-289, bounded-turn.ts:259-267]** The legacy `execCommandApproval` / `applyPatchApproval` (also in `ServerRequest.json`) belong to the old `newConversation`/`sendUserTurn` surface and do **not** fire here — the reference supervisor never registers them.

### 4a. Shell/exec → `item/commandExecution/requestApproval`

**Params** `CommandExecutionRequestApprovalParams` **[schema: CommandExecutionRequestApprovalParams.json]**
```json
{"jsonrpc":"2.0","id":7,"method":"item/commandExecution/requestApproval","params":{
  "itemId":"<stable item id>",
  "threadId":"<thread id>",
  "turnId":"<turn id>",
  "startedAtMs":1752300000000,
  "command":"rm -rf build",              // display string, NULLABLE (not argv)
  "commandActions":[{"type":"unknown","command":"rm -rf build"}],
  "cwd":"/abs/workspace",                 // nullable
  "approvalId":null,                      // non-null only for zsh-exec-bridge subcommands
  "reason":null,
  "proposedExecpolicyAmendment":null,     // present when the model proposes a trust rule
  "networkApprovalContext":null
}}
```
- **Correlation / stable id across retries:** `itemId` (+ `threadId`, `turnId`). Use `approvalId` when non-null (zsh-exec-bridge subcommands share one parent `itemId`). **[schema field docs]**
- **The command:** `command` is a nullable *string* (+ parsed `commandActions[]`), **not** an argv array. If you need argv, parse it or correlate `itemId` to the `commandExecution` thread item from `item/started` (which carries `command`, `commandActions`, `cwd`). **[schema: v2/ItemStartedNotification.json → CommandExecutionThreadItem]**

**Response** `CommandExecutionRequestApprovalResponse` **[schema: CommandExecutionRequestApprovalResponse.json → `CommandExecutionApprovalDecision`]**

Decision enum (this is the whole security surface):
| value | meaning | use for design? |
|---|---|---|
| `"accept"` | run this one command | ✅ **single-approval** |
| `"acceptForSession"` | run + auto-approve matching commands for the rest of the session | ❌ forbidden (session grant) |
| `{"acceptWithExecpolicyAmendment":{"execpolicy_amendment":[…]}}` | run + persist an execpolicy trust rule | ❌ forbidden (persists trust) |
| `{"applyNetworkPolicyAmendment":{…}}` | persist an allow/deny host rule | ❌ (network trust) |
| `"decline"` | reject; the turn continues, agent tries something else | ✅ deny |
| `"cancel"` | reject; the turn is **immediately interrupted** | ✅ deny-and-stop |

Single-approval reply:
```json
{"id":7,"result":{"decision":"accept"}}
```
Deny (let the agent continue): `{"id":7,"result":{"decision":"decline"}}`. Deny and kill the turn: `{"id":7,"result":{"decision":"cancel"}}`.

> **Robustness:** the approval params may carry an optional `availableDecisions` array advertising which decision strings are valid for *this* request. If present and it lacks `accept`, fall back (e.g. to `acceptForSession`→then immediately re-tighten, or `decline`); if absent, assume all are available and send `accept`. The reference supervisor guards on exactly this field. **[ref-impl: approval-bridge.ts:1143-1149 `hasAvailableDecision` → `requestParams.availableDecisions`]**

> The reference supervisor sends exactly `accept` for approve-once and `decline`/`cancel` for reject — never `acceptForSession` unless the outcome is explicitly session-scoped. **[ref-impl: approval-bridge.ts:760-781, 1168-1177]**

### 4b. File edit (apply_patch) → `item/fileChange/requestApproval`

**Params** `FileChangeRequestApprovalParams` **[schema: FileChangeRequestApprovalParams.json]**
```json
{"jsonrpc":"2.0","id":8,"method":"item/fileChange/requestApproval","params":{
  "itemId":"<stable item id>","threadId":"…","turnId":"…","startedAtMs":1752300000001,
  "grantRoot":null,"reason":null
}}
```
- Correlation id = `itemId` (+ `threadId`/`turnId`). **The diff itself is not in the approval params** — read it from the `fileChange` thread item (`item/started`/`item/fileChange/patchUpdated`), whose `changes[]` carry `{path, kind, diff}`. **[schema: v2/ItemStartedNotification.json → FileChangeThreadItem; ServerNotification.json → `item/fileChange/patchUpdated`]**

**Response** `FileChangeRequestApprovalResponse` **[schema: FileChangeRequestApprovalResponse.json → `FileChangeApprovalDecision`]** — smaller enum: `"accept"` \| `"acceptForSession"` \| `"decline"` \| `"cancel"`.
```json
{"id":8,"result":{"decision":"accept"}}
```

### 4c. Sandbox escalation → `item/permissions/requestApproval`

**Params** `PermissionsRequestApprovalParams`; **Response** shape is `{ "permissions": {…}, "scope": "turn"|"session" }` (grant) or `{ "permissions": {}, "scope":"turn" }` (deny). **[schema: PermissionsRequestApprovalParams.json / PermissionsRequestApprovalResponse.json; ref-impl: approval-bridge.ts:281-289]** For a lock-everything-down supervisor, deny by returning empty permissions.

### 4d. Legacy shapes (for reference only — do NOT expect these)

- `execCommandApproval` → `ExecCommandApprovalParams` `{callId, command:[…]string, conversationId, cwd, parsedCmd[], approvalId?, reason?}`; response `{decision: ReviewDecision}` where `ReviewDecision` = `approved` \| `approved_for_session` \| `{approved_execpolicy_amendment:…}` \| `{network_policy_amendment:…}` \| `denied` \| `timed_out` \| `abort`. **[schema: ExecCommandApprovalParams.json, ExecCommandApprovalResponse.json]**
- `applyPatchApproval` → `ApplyPatchApprovalParams` `{callId, conversationId, fileChanges:{path→FileChange}, grantRoot?, reason?}`; same `ReviewDecision`. **[schema: ApplyPatchApprovalParams.json, ApplyPatchApprovalResponse.json]**

This is the origin of the design's `{decision:"approved"}` assumption. On the v2 surface it is `accept`, and these methods don't fire.

---

## 5. The notification/event stream (ServerNotification)

Notifications have a `method` and `params`, no `id`. Method strings + the fields the supervisor needs. **[schema: ServerNotification.json + the per-type files under `v2/`]**

### 5a. Keep these

| method | params type | what to read |
|---|---|---|
| `turn/started` | `TurnStartedNotification` | `{threadId, turn}` — turn began. |
| `item/started` | `ItemStartedNotification` | `{item, startedAtMs, threadId, turnId}` — `item.type` ∈ `commandExecution`/`fileChange`/`agentMessage`/`mcpToolCall`/… Use for exec-begin and to fetch the full command/diff. |
| `item/completed` | `ItemCompletedNotification` | `{item, completedAtMs, threadId, turnId}` — **one completed item.** For an agent message: `item.type=="agentMessage"`, text at **`item.text`**, optional `item.phase` ∈ `"final_answer"`/`"commentary"`. For exec-end: `item.type=="commandExecution"` with `status` (`completed`/`failed`/`declined`), `exitCode`, `aggregatedOutput`, `durationMs`. |
| `turn/completed` | `TurnCompletedNotification` | `{threadId, turn}` — `turn.status` ∈ `completed`/`interrupted`/`failed`/`inProgress`; `turn.items[]` is the full item list; on failure `turn.error` = `{message, codexErrorInfo?, additionalDetails?}`. |
| `thread/tokenUsage/updated` | `ThreadTokenUsageUpdatedNotification` | `{threadId, turnId, tokenUsage}` where `tokenUsage.last` and `tokenUsage.total` are `TokenUsageBreakdown` = `{inputTokens, cachedInputTokens, outputTokens, reasoningOutputTokens, totalTokens}`; plus `tokenUsage.modelContextWindow`. **This is the usage/cost source.** |
| `error` | `ErrorNotification` | `{error:TurnError, threadId, turnId, willRetry}` — turn-level error; `willRetry` says whether codex will retry. |

**Agent message text (design's "one agent.message per completed message"):** take one `agent.message` per `item/completed` where `item.type=="agentMessage"`; text = `item.text`. **Final result** = the last such message in the turn (prefer the one with `phase=="final_answer"`); equivalently, the last `agentMessage` in `turn/completed.turn.items[]`. **[schema: v2/ItemCompletedNotification.json → AgentMessageThreadItem; v2/TurnCompletedNotification.json]**

### 5b. Drop these (deltas / noise the design wants suppressed)

| method | params | why drop |
|---|---|---|
| `item/agentMessage/delta` | `{delta, itemId, threadId, turnId}` | streaming text chunks — dup of the final `item/completed`. **[schema: v2/AgentMessageDeltaNotification.json]** |
| `item/reasoning/textDelta` | `ReasoningTextDeltaNotification` | model reasoning stream — never surface. |
| `item/reasoning/summaryTextDelta`, `item/reasoning/summaryPartAdded` | reasoning summaries | drop. |
| `item/commandExecution/outputDelta` | `{delta, itemId, threadId, turnId}` | live command stdout chunks; the aggregate lands on `item/completed`. **[schema: v2/CommandExecutionOutputDeltaNotification.json]** |
| `item/fileChange/outputDelta`, `item/fileChange/patchUpdated` | partial diffs | keep only if you want a live diff; otherwise use the completed item. |
| `item/plan/delta`, `turn/plan/updated` | plan streaming | drop unless surfacing a plan. |
| `item/autoApprovalReview/*` | guardian-subagent review | only relevant if `approvalsReviewer:"auto_review"` (which you should not use). |

(There are also `thread/*` lifecycle, `mcpServer/*`, `account/*`, `remoteControl/status/changed`, `fuzzyFileSearch/*`, realtime audio notifications — all ignorable for a headless coding run.)

---

## 6. Config keys — approval / sandbox / execpolicy / tool lockdown

Set these either as `-c key=value` on the `codex app-server` command line, in `$CODEX_HOME/config.toml`, or (per-thread, preferred) in the `thread/start.config` object. **[ref-impl uses the thread `config` object]**

> ⚠️ This machine's `~/.codex/config.toml` is wide open (`approval_policy = "never"`, `sandbox_mode = "danger-full-access"`, many `[projects."…"] trust_level = "trusted"`). **The supervisor must set its own `approvalPolicy`/`sandbox` per-thread and must not run inside a `trust_level="trusted"` project dir** — a trusted project short-circuits approvals. **[live: ~/.codex/config.toml]**

### 6a. Approval policy **[schema: AskForApproval; docs: config-reference]**
`approval_policy` (or `thread/start.approvalPolicy`): `"untrusted"` \| `"on-request"` \| `"never"` \| `{granular={sandbox_approval,rules,mcp_elicitations,request_permissions,skill_approval}}`.
- `"untrusted"` = ask before running anything except known-safe reads. **Use this.**
- `"on-request"` = model self-runs reads/edits/local commands, asks only for network/out-of-workspace. Too permissive for "approve every exec".
- `"never"` = never ask (fails instead). `on-failure` is deprecated/removed.
- Also set `approvals_reviewer = "user"` (thread `approvalsReviewer`) so requests come to you, not an LLM auto-reviewer. **[docs; schema: ApprovalsReviewer]**

### 6b. Sandbox **[schema: SandboxMode / SandboxPolicy; docs: config-reference]**
`sandbox_mode`: `"read-only"` \| `"workspace-write"` \| `"danger-full-access"`.
- `[sandbox_workspace_write]` sub-keys: `network_access` (bool), `writable_roots` (array<string>), `exclude_tmpdir_env_var` (bool), `exclude_slash_tmp` (bool).
- `thread/start.sandbox` takes the **string** `SandboxMode`; `turn/start.sandboxPolicy` takes the **object** `SandboxPolicy` (`{"type":"readOnly"|"workspaceWrite"|"dangerFullAccess"|"externalSandbox", …}`). Don't mix them up.
- For a governed run, `read-only` + `untrusted` means the agent must request approval to run essentially anything.

### 6c. Execpolicy / rules — force EVERY command (incl. `cat`, `ls`) to prompt **[live: `codex execpolicy check`; docs: agent-configuration/rules]**

`approval_policy="untrusted"` alone still auto-runs Codex's built-in "known-safe" reads. To defeat that, load an **execpolicy rule file** (Starlark) with a universal `prompt` rule.

- **Where rules load from (at startup, across config layers):** `~/.codex/rules/*.rules` (user layer, e.g. `default.rules`), team layers, and project-local `<repo>/.codex/rules/` (only in a *trusted* project). **[docs]**
- **Rule decisions:** `"allow"` (run silently), `"prompt"` (request approval), `"forbidden"` (block). **Strictest wins:** `forbidden` > `prompt` > `allow`. **[docs; web-search]**
- **Universal "prompt everything" rule** (an empty prefix matches every command):
  ```python
  prefix_rule(
      pattern = [""],
      decision = "prompt",
      justification = "Every command must be approved by the supervisor",
  )
  ```
- **Validate** a rule file offline: `codex execpolicy check --pretty --rules <path> -- <cmd tokens>` (emits JSON with the strictest decision + matching rules). **[live: `codex execpolicy check --help`]**
- **Do NOT pass `--ignore-rules`** (a real flag on `codex exec`) — it disables the rules layer. **[live: `codex exec --help`]**
- Practical wiring for a supervised session: point `CODEX_HOME` at a controlled dir containing `rules/default.rules` (universal prompt) and leave the workspace out of any `[projects] trust_level="trusted"` entry.

> Note: the model can *propose* an execpolicy amendment (`proposedExecpolicyAmendment` in the approval params, and the `acceptWithExecpolicyAmendment` decision). The supervisor must **ignore/decline** these to keep the trust set empty.

### 6d. Tool-surface lockdown **[schema: v2/ThreadStartParams.config (freeform); ref-impl: web-search.ts; docs: config-reference]**

Set in `thread/start.config` (or `-c`). Confirmed keys:
- **Web search OFF:** `tools.web_search = false` (also `features.web_search = false`; the ref-impl additionally sets `features.standalone_web_search = false`). **[ref-impl: web-search.ts:60-77; docs]**
- **Image viewing OFF:** `tools.view_image = false`. **[docs: config-reference]**
- **`[features]` toggles** (disable via `features.<name>=false`, or `--disable <name>` / `--enable <name>` on the command line, equivalent to `-c features.<name>=…`): documented flag names include `features.apps`, `features.shell_tool`, `features.unified_exec`, `features.web_search`, `features.multi_agent`, `features.hooks`, `features.memories`, `features.goals`, `features.personality`, `features.fast_mode`, and the experimental `features.experimental_use_exec_command_tool`. Disable the ones you don't want (e.g. `features.unified_exec=false` to drop the PTY/streamable-shell tool, `features.multi_agent=false`, `features.apps=false`). **[docs: config-reference/advanced; live: `codex features list`]**
- **MCP:** don't configure any `[mcp_servers]` / user MCP servers, and (ref-impl) gate `userMcpServersEnabled`. No servers configured ⇒ no MCP tools. **[schema: ClientRequest mcpServer/* are opt-in]**

> The public config reference does not document dedicated `include_apply_patch_tool` / `include_view_image_tool` keys for 0.144; `tools.view_image=false` is the documented view-image switch, and file edits are gated by the `item/fileChange/requestApproval` path + sandbox regardless of whether apply_patch is surfaced as a tool. Treat apply_patch as "always governed by the fileChange approval + read-only sandbox" rather than relying on a tool toggle.

---

## 7. RECOMMENDED SUPERVISOR PROTOCOL

**Spawn:** `codex app-server` with stdio, `CODEX_HOME` pointed at a controlled dir (holding `rules/default.rules` with the universal `prompt` rule; no trusted-project entry for the workspace). Auth via existing `codex login` or `OPENAI_API_KEY` in the env.

**Framing:** read stdout line-by-line; each line is one JSON message. Write one compact JSON line + `\n` per message. Send `"jsonrpc":"2.0"` on your requests; tolerate its absence in responses.

**Sequence:**
1. `→ initialize` `{clientInfo:{name,version}}` → await `result` (userAgent/codexHome).
2. `→ initialized` (notification, no params).
3. `→ thread/start` `{ cwd, model, approvalPolicy:"untrusted", approvalsReviewer:"user", sandbox:"read-only", developerInstructions:"<system prompt>", config:{ "tools.web_search":false, "tools.view_image":false, "features.unified_exec":false, "features.multi_agent":false, "features.apps":false } }` → capture `result.thread.id`. (Optionally assert `result.instructionSources` contains no unexpected `AGENTS.md`.)
4. `→ turn/start` `{ threadId, input:[{type:"text",text:"<task>"}] }` → capture `result.turn.id`.
5. **Event loop** — dispatch incoming messages by shape:
   - **has `id` + `method`** ⇒ server *request* (approval). Route by method:
     - `item/commandExecution/requestApproval` → decide → `{id, result:{decision:"accept"|"decline"|"cancel"}}` (single-approve = `accept`; **never** `acceptForSession`/`acceptWithExecpolicyAmendment`).
     - `item/fileChange/requestApproval` → `{id, result:{decision:"accept"|"decline"|"cancel"}}`.
     - `item/permissions/requestApproval` → deny with `{id, result:{permissions:{}, scope:"turn"}}`.
     - Dedup on `itemId` (+ `approvalId` if present) so retries re-use the same decision.
   - **has `method`, no `id`** ⇒ notification. Keep `item/completed` (agentMessage→text, commandExecution→exit/output), `turn/started|completed`, `thread/tokenUsage/updated`, `error`. **Drop** every `*Delta`, `item/reasoning/*`, `item/plan/*`, `turn/plan/updated`, `item/autoApprovalReview/*`.
   - **has `id` + `result`/`error`** ⇒ response to one of your requests.
6. On `turn/completed`: read `turn.status`. `completed` ⇒ final answer = last `agentMessage` (prefer `phase=="final_answer"`) from the `item/completed` stream / `turn.items`. `failed` ⇒ `turn.error.message` (+ `codexErrorInfo`). Read final usage from the last `thread/tokenUsage/updated` (`tokenUsage.total`).
7. To abort mid-turn: `→ turn/interrupt` `{threadId,turnId}` (or answer an approval with `cancel`). To continue the conversation: another `turn/start` on the same `threadId`.

**Invariants to enforce in code:**
- Approval decision set is `accept`/`decline`/`cancel` **only** — reject any code path that would emit `acceptForSession`, `acceptWithExecpolicyAmendment`, or `applyNetworkPolicyAmendment`.
- `approvalsReviewer` must be `"user"`; never `"auto_review"`.
- Keep the execpolicy universal-`prompt` rule loaded; never send `--ignore-rules`; ignore model-proposed execpolicy amendments.
- System prompt only via `developerInstructions`; the workspace should contain no `AGENTS.md` you didn't author.

---

## 8. Appendix — schema file → concept map

| Concept | Schema file(s) |
|---|---|
| Methods we send | `ClientRequest.json` (`initialize`, `thread/start`, `turn/start`, `turn/interrupt`, `turn/steer`, `item/*`, `config/read`, …) |
| Client notifications | `ClientNotification.json` (`initialized`) |
| Requests codex sends us | `ServerRequest.json` (v2: `item/commandExecution/requestApproval`, `item/fileChange/requestApproval`, `item/permissions/requestApproval`, `item/tool/requestUserInput`, `item/tool/call`, `mcpServer/elicitation/request`; legacy: `execCommandApproval`, `applyPatchApproval`) |
| Event stream | `ServerNotification.json` + `v2/*Notification.json` |
| initialize | `v1/InitializeParams.json`, `v1/InitializeResponse.json` |
| thread/start | `v2/ThreadStartParams.json`, `v2/ThreadStartResponse.json` |
| turn/start | `v2/TurnStartParams.json`, `v2/TurnStartResponse.json` |
| exec approval | `CommandExecutionRequestApprovalParams.json`, `CommandExecutionRequestApprovalResponse.json` |
| file approval | `FileChangeRequestApprovalParams.json`, `FileChangeRequestApprovalResponse.json` |
| permissions approval | `PermissionsRequestApprovalParams.json`, `PermissionsRequestApprovalResponse.json` |
| legacy approvals | `ExecCommandApprovalParams.json`/`…Response.json`, `ApplyPatchApprovalParams.json`/`…Response.json` |
| agent message / items | `v2/ItemStartedNotification.json`, `v2/ItemCompletedNotification.json` (→ `ThreadItem` → `AgentMessageThreadItem.text`/`.phase`, `CommandExecutionThreadItem`, `FileChangeThreadItem`) |
| turn lifecycle | `v2/TurnStartedNotification.json`, `v2/TurnCompletedNotification.json` (`Turn.status`, `Turn.error`) |
| token usage | `v2/ThreadTokenUsageUpdatedNotification.json` (`TokenUsageBreakdown`) |
| deltas to drop | `v2/AgentMessageDeltaNotification.json`, `v2/CommandExecutionOutputDeltaNotification.json`, `v2/ReasoningTextDeltaNotification.json`, … |
| errors | `v2/ErrorNotification.json` (`TurnError` + `CodexErrorInfo`) |

**Reference supervisor (second witness):** `/private/tmp/openclaw-audit.MSbLJG/extensions/codex/src/app-server/` — notably `client.ts` (request dispatch, method allow-list), `approval-bridge.ts` (decision builders `commandApprovalDecision`/`fileChangeApprovalDecision`), `config.ts` (approval/sandbox resolution), `web-search.ts` (`tools.web_search` shape), `attempt-startup.ts` / `thread-lifecycle.ts` (thread/start with `developerInstructions` + `config`). This path is a scratch/audit checkout and may not persist — cite the schema as the authority.
