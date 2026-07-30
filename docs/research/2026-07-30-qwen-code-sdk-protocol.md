# Qwen Code SDK protocol + interception facts (verified against pinned binaries)

**Date:** 2026-07-30
**Pins verified:** `@qwen-code/qwen-code@0.21.1` (the CLI; zero-dep bundle, `bin: qwen -> cli-entry.js`, Node ≥ 22) and `@qwen-code/sdk@0.1.8` (deps: `@modelcontextprotocol/sdk`, `zod`). Everything below was extracted from the actual published bundles and/or **proven live** by driving the real CLI through the SDK against a loopback fake OpenAI endpoint — not taken from docs. This is the Qwen analogue of `docs/research/2026-07-12-codex-app-server-protocol.md`; the supervisor in `images/qwen-runner/` is written against these facts, and a version bump re-runs this checklist.

## 1. Embedding surface

`@qwen-code/sdk`'s `query()` spawns the bundled CLI (`ProcessTransport`) with
`--input-format stream-json --output-format stream-json --channel=SDK` and speaks
NDJSON over stdio. Two message planes:

- **SDK messages** (the async iterator): `{type: "system"|"assistant"|"user"|"result"|"stream_event"}`.
  `SDKResultMessage` carries `subtype: "success" | "error_max_turns" | "error_during_execution"`,
  `is_error`, `result` (final text), `usage` (`input_tokens`, `output_tokens`,
  `cache_read_input_tokens`, `cache_creation_input_tokens`), `modelUsage`, `num_turns`,
  `permission_denials`.
- **Control plane**: `{type:"control_request", request_id, request:{subtype:"can_use_tool",
  tool_name, tool_use_id, input, permission_suggestions, blocked_path}}` from the CLI;
  the SDK answers `{type:"control_response", response:{subtype:"success", request_id,
  response:{behavior:"allow", updatedInput} | {behavior:"deny", message}}}`. Other
  subtypes: `initialize`, `interrupt`, `set_permission_mode`, `set_model`, `hook_callback`,
  `mcp_message`, `get_usage_info`, … (`CLIControlRequest` union in the SDK's `index.d.ts`).

Rejected alternatives: plain `-p` headless (an `ask` confirmation cannot prompt →
degrades to deny; `canPromptForAskBounce()` requires interactive, Zed, or
`--input-format stream-json`); ACP `--acp` (workable, richest payloads, but needs a
full ACP client incl. `fs/*` + `terminal/*` and carries `unstable_*` churn — kept as
the documented pivot); importing `@qwen-code/qwen-code-core` (npm package frozen at
0.0.14 while the monorepo is at 0.21.x — dead end).

## 2. The interception model (THE load-bearing section)

`canUseTool` is only consulted for tool calls that need confirmation, and two defaults
break governance out of the box:

- `tools.approvalMode` defaults to **`auto`** — an LLM classifier auto-approves "safe"
  calls (bypasses the gate AND burns facade calls). Must be forced to `"default"`.
- Read-only tools (`read_file`, `grep_search`, `glob`, `list_directory`) have default
  permission `allow` — they execute without ever reaching `canUseTool`.

The closure is **`permissions.ask` rules in SYSTEM-scope settings**. Verified in the
bundle (`evaluatePermissionRules` → priority `deny > ask > allow > mode default`;
`needsConfirmation()` returns true for `finalPermission === "ask"`), and **proven
live**: with `permissions.ask: ["Read", "Edit", "Write", "NotebookEdit", "Bash",
"WebFetch", "mcp__"]` + `approvalMode: "default"`, a model-initiated `read_file`
crossed `canUseTool` with its full input, and a denied `write_file` provably did NOT
create its target file.

**Outcome persistence is safe by construction on the SDK channel**: the CLI maps an
SDK `allow` to `proceed_once` and a deny to `cancel` — verbatim from the bundle's
SDK-channel confirmation handler. There is no `proceed_always` path through
`canUseTool`, so no session-scoped grant can bypass the server's digest binding.

Settings scope precedence: system (`QWEN_CODE_SYSTEM_SETTINGS_PATH`, read by
`getSystemSettingsPath()`) outranks workspace and user scopes for scalars, and the
`permissions.*` arrays merge as a UNION across scopes — a repo-committed
`.qwen/settings.json` can only ADD rules, and `ask` beats `allow`, so a hostile
workspace cannot silently re-enable an ungated tool. The system settings file ships
root-owned read-only in the image.

`--safe-mode` disables permission rules and must never be used. `QueryOptions.extraArgs`
refuses security-sensitive flags (`--approval-mode`, `--dangerously-skip-permissions`, …)
— defense in depth on the SDK side.

## 3. Tool census + schemas (0.21.1)

`ToolNames` (bundle `chunk-Y6AXW2OG.js`): `edit`, `write_file`, `read_file`,
`zoom_image`, `grep_search`, `glob`, `run_shell_command`, `todo_write`, `save_memory`,
`agent` (the subagent tool — NOT `task`), `skill`, `exit_plan_mode`, `enter_plan_mode`,
`web_fetch`, `web_search`, `image_gen`, `list_directory`, `lsp`, `ask_user_question`,
`cron_create`, `cron_list`, `cron_delete`, `loop_wakeup`, `create_sub_session`,
`list_agents`, `task_stop`, `task_create`, `task_update`, `task_list`, `team_create`,
`team_delete`, `team_plan_approval`, `send_message`, `structured_output`, `monitor`,
`notebook_edit`, `tool_search`, `read_mcp_resource`, `enter_worktree`, `exit_worktree`,
plus the generated `computer_use__*` family (35 tools) and MCP `mcp__<server>__<tool>`.

Input schemas (extracted from the tool class declarations, then confirmed live):

| Qwen tool | schema (required in bold) | canonical mapping |
|---|---|---|
| `read_file` | **file_path**, offset, limit, pages | `Read{file_path}` |
| `write_file` | **file_path**, **content** | `Write{file_path, content}` |
| `edit` | **file_path**, **old_string**, **new_string**, replace_all | `Edit{...}` (same fields) |
| `notebook_edit` | **notebook_path**, cell_id, new_source, cell_type, edit_mode | `NotebookEdit{notebook_path,...}` |
| `run_shell_command` | **command**, is_background, timeout, description, directory | `Bash{command}` (+ `directory` containment) |
| `grep_search` | **pattern**, glob, path, limit | `Grep{pattern, path, ...}` |
| `glob` | **pattern**, path | `Glob{pattern, path}` |
| `list_directory` | **path**, respect_git_ignore, respect_qwen_ignore | `LS{path}` |
| `todo_write` | todos | `TodoWrite{...}` |

Qwen 0.21.x deliberately converged on Claude-Code-style names (`file_path`, not
Gemini's `absolute_path`; ripgrep-backed `grep_search` with `pattern`/`glob`/`path`) —
so fluidbox's `policy::extract_paths` (`file_path`/`path`/`notebook_path`) reads them
natively. `run_shell_command.command` is the raw command string (executed as
`bash -c <command>`); the CLI does NOT wrap it in a `bash -lc` argv the way codex did,
so no unwrap pass is needed — the canonicalizer still applies one defensively.
`directory` is an optional absolute cwd "within the workspace" per its own description;
the supervisor enforces that containment itself (realpath, fail-closed).

## 4. Lockdown (proven census)

`tools.disabled` unregisters tools (they disappear from the request schema — stronger
than a deny rule). **Trap found live: disabling `tool_search` surfaces the deferred-tool
registry** — with `tool_search` off, `computer_use__*` (35 tools), `cron_*`,
`create_sub_session`, `send_message`, `task_stop`, `loop_wakeup` all appeared directly
in the model's tool schema. The shipped lockdown therefore disables `tool_search` AND
every deferred/agentic tool explicitly, plus `tools.computerUse.enabled: false`.

With the shipped `settings.json` the live census is EXACTLY:
`edit, glob, grep_search, list_directory, notebook_edit, read_file, run_shell_command,
todo_write, write_file` — all nine gated via `permissions.ask`. (`web_search` is
opt-in-only upstream; `web_fetch` is on by default and must be — and is — disabled.)

## 5. Model egress (chat-completions dialect)

Proven live against a loopback endpoint:

- `POST {OPENAI_BASE_URL}/chat/completions` — so `OPENAI_BASE_URL` must be
  `{control}/internal/llm/v1` and the facade allowlists suffix `v1/chat/completions`.
- Auth: `Authorization: Bearer <OPENAI_API_KEY>` (the fake key = the llm-audience token).
- Streaming requests carry `stream: true` + **`stream_options: {"include_usage": true}`**;
  usage arrives in a final chunk with `choices: []`. Non-stream requests set an explicit
  `stream: false`. Output cap rides **`max_tokens`** (32768 by default) — the
  reservation field for this dialect.
- `model` comes from `OPENAI_MODEL`/`options.model` and must equal the RunSpec model
  (facade pin). Tools are all `{type:"function"}`; no server-executed tool types exist
  in this dialect. `usage` fields: `prompt_tokens`/`completion_tokens` (+
  `prompt_tokens_details.cached_tokens` for cached input on providers that report it).
- Auth selection: `security.auth.selectedType: "openai"` in settings +
  `authType: "openai"` in QueryOptions — no interactive auth menu, no OAuth.

## 6. Runtime state writes (Dockerfile ownership facts)

At boot the CLI writes under `$HOME/.qwen/`: `extension-store/`, `extensions/`,
`installation_id`, `output-language.md`, `projects/` (session transcripts), `skills/`,
`tmp/`, `usage/`, `usage_record.jsonl`. The runner user therefore needs a writable
HOME; the governance-critical system `settings.json` lives OUTSIDE it, root-owned
`0444` in a root-owned `0555` dir, pointed at by `QWEN_CODE_SYSTEM_SETTINGS_PATH`
(user/workspace scopes can only union-add restrictions, never relax — §2).

## 7. Timeouts

`QueryOptions.timeout.canUseTool` defaults to **60 s and auto-denies** on expiry. The
supervisor sets it above the runner-contract approval window (12 min client / 10 min
server TTL): 13 min, so a slow human approval can never be converted into a silent
deny by the SDK layer.

## 8. Version-bump checklist

Re-verify on ANY pin change: (1) `read_file` still crosses `canUseTool` under the
shipped settings (the live-tier canary automates this); (2) the tool census is still
exactly the nine core tools; (3) SDK `allow` still maps to `proceed_once`; (4) tool
input field names unchanged (`file_path`/`notebook_path`/`command`/`pattern`/`path`);
(5) chat-completions request still carries `stream_options.include_usage` and
`max_tokens`; (6) the `$HOME/.qwen` write set hasn't grown past the writable dirs.
