// fluidbox codex runner — the OpenAI Codex `app-server` harness, governed.
//
// EXACT behavioral parity with the Claude runner: every exec and every file
// edit crosses the fluidbox permission gate as a CANONICAL tool call
// (Bash{command}, MultiEdit{edits:[{file_path}]}), decided server-side,
// ledgered, budgeted. The governance wiring (permission gate, events,
// heartbeat, token renewal, result) is the shared runner contract; this file
// drives codex's app-server and CANONICALIZES its protocol into that contract.
//
// Protocol (verified, codex 0.144.1 — docs/research/2026-07-12-codex-app-server-protocol.md):
//   - NDJSON JSON-RPC over the child's stdio.
//   - initialize → initialized → thread/start → turn/start.
//   - approvals fire as item/{commandExecution,fileChange,permissions}/requestApproval;
//     reply {decision:"accept"|"decline"} (NEVER acceptForSession).
//   - MCP TOOL CALLS are approved separately, as mcpServer/elicitation/request
//     with _meta.codex_approval_kind=="mcp_tool_call", fired BEFORE the stdio
//     child is touched; reply {action:"accept"|"decline", content, _meta}.
//     (item/tool/call is codex's DYNAMIC-tool channel — MCP never uses it.)
//   - model egress: a custom [model_providers] pointed at the facade (HTTP
//     POST /v1/responses, session token as the bearer).

import { spawn } from "node:child_process";
import path from "node:path";
import fs from "node:fs";
import {
  loadRunnerEnv,
  RunnerClient,
  BROKER_SHIM,
  SANDBOX_GATE_SHIM,
  brokerShimEnv,
  gateShimEnv,
} from "/opt/fluidbox-codex/lib/contract.mjs";

const env = loadRunnerEnv();
const client = new RunnerClient(env);
const MODEL = env.MODEL || "gpt-5.4-mini";

// Gap 10 / invariant 19: capture the runner-control credential in memory
// (env.TOKEN, held by the RunnerClient) and REMOVE it from process.env before
// ANY spawn — the codex child below and the MCP shims (whose env is built from
// process.env at module load) must never inherit it, because codex runs under
// sandbox_mode=danger-full-access and its exec children inherit its env.
// Afterwards codex sees only the LLM token (its model-provider env_key) and the
// tool-intent token; neither can post /result, forge /events, or renew tokens.
//
// DISCLOSED RESIDUALS, both of them:
//  1. This is an env-VISIBILITY boundary, not a process one. Same-uid children
//     can still read THIS process's INITIAL environment via /proc/<pid>/environ,
//     which the delete does not rewrite; true isolation needs a uid split or a
//     sidecar, which the current cap_drop=ALL + no-new-privileges hardening
//     blocks (design :1326-1329). Identical to the claude runner's residual.
//  2. codex COUPLES model egress and exec — it needs the LLM credential in its
//     env, so codex-spawned shells can read the LLM token. That is inherent to
//     env_key auth (survey B §5). Runner-control is what this delete closes.
delete process.env.FLUIDBOX_SESSION_TOKEN;
const CONTROL = env.CONTROL.replace(/\/$/, "");
// Codex appends /responses to base_url; the facade route is /internal/llm/{*rest}.
const FACADE_BASE = `${CONTROL}/internal/llm/v1`;

// ─── The canonical workspace, for cwd containment ─────────────────────────
const WORKSPACE = (() => {
  try {
    return fs.realpathSync(env.WORKSPACE);
  } catch {
    return path.resolve(env.WORKSPACE);
  }
})();

// A cwd is acceptable only if it EXISTS and its FULLY-RESOLVED real path is
// inside the frozen workspace (reject outside / missing / symlink escape). A
// `cat x` verdict is not equivalent if codex runs it from $CODEX_HOME, and a
// non-existent path under a symlink must not be waved through lexically.
function cwdInWorkspace(cwd) {
  if (cwd == null) return WORKSPACE; // codex omitted it → the thread cwd (= workspace)
  let resolved;
  try {
    // realpathSync resolves EVERY symlink component and throws if the path
    // (or any component) does not exist — no lexical fallback for cwd.
    resolved = fs.realpathSync(path.resolve(WORKSPACE, cwd));
  } catch {
    return null;
  }
  const rel = path.relative(WORKSPACE, resolved);
  const inside = resolved === WORKSPACE || (!rel.startsWith("..") && !path.isAbsolute(rel));
  return inside ? resolved : null;
}

// argv/command → canonical Bash{command}. Codex 0.144.1 gives the exec
// approval a display `command` STRING. If it's a shell wrapper
// ([bash|sh|zsh] -lc|-c "<script>"), unwrap to the inner script so the
// policy's allow-prefix match + metachar screen see the real command (a
// naive wrapper would match no allow-prefix → over-escalation / ReadOnly
// over-deny). Else use the string as-is.
const SHELL_WRAP = /^(?:\/usr\/bin\/|\/bin\/|\/usr\/local\/bin\/)?(?:ba|z)?sh\s+-l?c\s+([\s\S]+)$/;
export function canonicalizeCommand(commandStr) {
  if (typeof commandStr !== "string") return "";
  const m = commandStr.trim().match(SHELL_WRAP);
  if (!m) return commandStr.trim();
  let inner = m[1].trim();
  // Strip ONE layer of surrounding quotes from the unwrapped script.
  if (
    (inner.startsWith('"') && inner.endsWith('"')) ||
    (inner.startsWith("'") && inner.endsWith("'"))
  ) {
    inner = inner.slice(1, -1);
  }
  return inner.trim();
}

// fileChange item changes[] → canonical MultiEdit edits[]. Codex 0.144.1's
// change shape (verified against the generated schema): each element is
// `{path, kind, diff}` where `kind` is the PatchChangeKind tagged union
// {type:"add"} | {type:"delete"} | {type:"update", move_path: string|null}.
// A MOVE is type:"update" with a non-null `kind.move_path` (source =
// change.path, dest = change.kind.move_path) — BOTH must reach the gate so a
// rename to an unlisted path (e.g. /workspace/.env) can't hide its
// destination. op-type + cwd ride ADDITIVELY (policy ignores unknown fields;
// the ledger keeps them).
function canonicalizeEdits(changes) {
  const edits = [];
  for (const c of changes || []) {
    const kind = c?.kind || {};
    const op = typeof kind === "string" ? kind : kind.type || "update";
    if (typeof c?.path === "string") edits.push({ file_path: c.path, op });
    const dest = kind?.move_path;
    if (typeof dest === "string" && dest) edits.push({ file_path: dest, op: "move_dest" });
  }
  return edits;
}

// ─── NDJSON JSON-RPC over the codex child ─────────────────────────────────
let child = null;
let nextId = 1;
const pending = new Map();
let threadId = null;
let turnId = null;
// itemId → tracked thread item (command/cwd for exec; changes for fileChange).
const items = new Map();
let finalText = "";
let hadError = null;
let turnDone = false;

function rpcSend(obj) {
  if (child && !child.killed) child.stdin.write(JSON.stringify(obj) + "\n");
}
function rpcRequest(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    rpcSend({ jsonrpc: "2.0", id, method, params });
  });
}

function handleLine(line) {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return; // codex logs non-JSON to stderr; tolerate stray stdout
  }
  if (msg.id !== undefined && msg.method) {
    handleServerRequest(msg).catch((e) =>
      console.error("fluidbox-codex: approval handler error:", e?.message || e),
    );
  } else if (msg.method) {
    handleNotification(msg);
  } else if (msg.id !== undefined) {
    const p = pending.get(msg.id);
    if (p) {
      pending.delete(msg.id);
      if (msg.error) p.reject(new Error(JSON.stringify(msg.error)));
      else p.resolve(msg.result);
    }
  }
}

// ─── Approvals → the fluidbox gate (the governance parity core) ───────────
// Each server-request kind has its OWN response schema; a wrong-shape reply
// can stall the turn. Dispatch every kind explicitly and fail closed with the
// correct schema; a truly unknown method gets a JSON-RPC method-not-found.
async function handleServerRequest(msg) {
  const { method, params, id } = msg;
  switch (method) {
    case "item/commandExecution/requestApproval":
      return decideExec(id, params);
    case "item/fileChange/requestApproval":
      return decideFileChange(id, params);
    case "item/permissions/requestApproval":
      // Sandbox escalation — deny by granting no permissions (the container
      // is the containment boundary; we never widen it).
      rpcSend({ id, result: { permissions: {}, scope: "turn" } });
      return;
    case "item/tool/requestUserInput":
      // We never provide interactive input (headless). The 0.144.1 response
      // schema is {answers:{}} — an empty answer map.
      rpcSend({ id, result: { answers: {} } });
      return;
    case "mcpServer/elicitation/request":
      // An MCP tool-call approval for a server we wired → accept; the shim +
      // the control-plane gate are the authority (see mcpToolCallAutoAllow).
      // content:null is valid because the requestedSchema carries no
      // properties. _meta:null deliberately DROPS codex's
      // persist:["session","always"] hint — every call re-asks, so every call
      // crosses the gate. A cached "always" would let later calls skip it.
      if (mcpToolCallAutoAllow(params)) {
        rpcSend({ id, result: { action: "accept", content: null, _meta: null } });
        return;
      }
      // Any other elicitation (interactive input, a server we never attached)
      // — decline. We are headless and nothing else is shim-gated.
      rpcSend({ id, result: { action: "decline", content: null, _meta: null } });
      return;
    // Legacy exec/patch approvals do not fire on the v2 surface, but if they
    // ever did, their decision enum is ReviewDecision ("denied", not
    // "decline") — fail closed with the correct value.
    case "execCommandApproval":
    case "applyPatchApproval":
      rpcSend({ id, result: { decision: "denied" } });
      return;
    default:
      // Unknown/unsupported request → JSON-RPC method-not-found, never a
      // malformed decision that could wedge the turn.
      rpcSend({ id, error: { code: -32601, message: `unsupported request: ${method}` } });
      return;
  }
}

async function decideExec(id, params) {
  const key = params.approvalId || params.itemId;
  // A model-proposed execpolicy / network amendment is an attempt to persist
  // trust — refuse outright (never let the trust set grow).
  if (params.proposedExecpolicyAmendment != null || params.proposedNetworkPolicyAmendments != null) {
    rpcSend({ id, result: { decision: "decline" } });
    return;
  }
  const cwd = cwdInWorkspace(params.cwd ?? items.get(params.itemId)?.cwd);
  if (cwd === null) {
    rpcSend({ id, result: { decision: "decline" } });
    return;
  }
  const rawCommand = params.command ?? items.get(params.itemId)?.command ?? "";
  const command = canonicalizeCommand(rawCommand);
  const decision = await gate(key, "Bash", { command, cwd }, params.availableDecisions);
  rpcSend({ id, result: decision });
}

async function decideFileChange(id, params) {
  const key = params.approvalId || params.itemId;
  const changes = items.get(params.itemId)?.changes || [];
  const edits = canonicalizeEdits(changes);
  // Fail closed when the changes never arrived (item/started or patchUpdated
  // out of order, or a protocol drift): an empty edit set would gate as
  // MultiEdit{edits:[]}, which hides the real paths — and which a SUPERVISED
  // human could approve as a blind patch. Never gate a patch we can't see;
  // decline and let codex re-propose.
  if (edits.length === 0) {
    rpcSend({ id, result: { decision: "decline" } });
    client.emit("harness", {
      type: "agent.message",
      data: {
        role: "system",
        text: "declined a fileChange approval carrying no visible changes (fail-closed)",
      },
    });
    return;
  }
  const decision = await gate(key, "MultiEdit", { edits, cwd: WORKSPACE }, params.availableDecisions);
  rpcSend({ id, result: decision });
}

// Gate ONE call through /permission and map to a v2 approval decision. NO
// local decision cache: the SERVER is idempotent by tool_call_id AND enforces
// the digest binding (Phase 6) — a reused id with CHANGED input is
// hard-rejected server-side, which a local cache would silently bypass. If
// `availableDecisions` is present and excludes "accept", we can only decline
// (never substitute a session grant). Returns the {decision} result object.
async function gate(callId, tool, input, availableDecisions) {
  const verdict = await client.requestPermission(tool, input, callId);
  const allow = !!(verdict && verdict.decision === "allow");
  if (!allow) return { decision: "decline" };
  if (Array.isArray(availableDecisions) && !availableDecisions.includes("accept")) {
    // The server allowed it, but codex won't take a plain accept here — never
    // escalate to acceptForSession; decline (the agent can retry differently).
    return { decision: "decline" };
  }
  return { decision: "accept" };
}

// ─── Notifications → the timeline (deltas suppressed) ─────────────────────
function handleNotification(msg) {
  const { method, params } = msg;
  switch (method) {
    case "item/started": {
      const it = params?.item;
      if (it?.id) items.set(it.id, it);
      break;
    }
    case "item/fileChange/patchUpdated": {
      const prev = items.get(params?.itemId) || {};
      if (params?.changes) items.set(params.itemId, { ...prev, changes: params.changes });
      break;
    }
    case "item/completed": {
      const it = params?.item;
      if (it?.id) items.set(it.id, it);
      if (it?.type === "agentMessage" && typeof it.text === "string" && it.text.trim()) {
        finalText = it.text; // last completed message wins (prefer final_answer)
        client.emit("agent", { type: "agent.message", data: { role: "assistant", text: it.text } });
      }
      break;
    }
    case "turn/completed": {
      const st = params?.turn?.status;
      // ONLY "completed" is success. interrupted / failed / anything else is a
      // failed run — never post "completed" for a non-completed turn.
      if (st !== "completed") {
        hadError =
          hadError || new Error(params?.turn?.error?.message || `codex turn ${st || "did not complete"}`);
      }
      // Prefer the final_answer message from the completed turn's items.
      const items2 = params?.turn?.items || [];
      const finals = items2.filter((i) => i.type === "agentMessage");
      const fa = finals.find((i) => i.phase === "final_answer") || finals[finals.length - 1];
      if (fa?.text) finalText = fa.text;
      turnDone = true;
      break;
    }
    case "error": {
      // Only a non-retrying, turn-fatal error ends the run.
      if (params?.willRetry === false) hadError = new Error(params?.error?.message || "codex error");
      break;
    }
    // thread/tokenUsage/updated: advisory only — the facade is the metering
    // source of truth (it meters codex's /v1/responses upstream). Dropped,
    // along with every *Delta, item/reasoning/*, item/plan/*, and
    // item/autoApprovalReview/*.
    default:
      break;
  }
}

// ─── MCP capability wiring (frozen manifest → shims) ──────────────────────
// Brokered servers reuse broker-shim (control-plane gate + execute). Sandbox
// servers use sandbox-gate-shim (preflights /permission, then spawns the real
// stdio child). codex's own approval plumbing is never trusted for MCP.
function mcpServersConfig() {
  const servers = {};
  for (const srv of env.CAPABILITIES.servers) {
    if (srv.class === "brokered") {
      servers[srv.name] = { command: "node", args: [BROKER_SHIM], env: brokerShimEnv(env, srv) };
    } else if (srv.class === "sandbox") {
      servers[srv.name] = { command: "node", args: [SANDBOX_GATE_SHIM], env: gateShimEnv(env, srv) };
    }
  }
  return servers;
}

// The MCP servers WE wired into codex — derived from the same frozen manifest
// that builds the thread config, so the auto-allow set can never drift from
// the set actually attached.
const WIRED_MCP_SERVERS = new Set(Object.keys(mcpServersConfig()));

// Codex asks approval for EVERY MCP tool call as an elicitation carrying
// `_meta.codex_approval_kind == "mcp_tool_call"` (verified against codex
// 0.144.1; it fires BEFORE the stdio child is touched). That prompt is
// redundant: the shims force every MCP call through the control-plane gate
// (/internal/sessions/{id}/tools/call), which is the real authority — the
// same inversion as the Claude runner's brokered auto-allow in canUseTool.
// Declining it rejects the call INSIDE codex, before the shim, so the gate
// never sees it ("user rejected MCP tool call", zero tool.requested events).
//
// Auto-allow is scoped to the servers we wired: codex's own prompt is only
// redundant for servers that actually terminate in a shim. Anything else —
// an unknown server, a non-tool-call elicitation — still declines.
export function mcpToolCallAutoAllow(params, wired = WIRED_MCP_SERVERS) {
  return (
    params?._meta?.codex_approval_kind === "mcp_tool_call" &&
    typeof params?.serverName === "string" &&
    wired.has(params.serverName)
  );
}

// ─── Lifecycle ────────────────────────────────────────────────────────────
function spawnCodex() {
  // Security-critical settings are asserted as -c CLI overrides (defense in
  // depth beyond the root-owned config.toml + thread/start).
  const args = [
    "app-server",
    "-c", `model=${MODEL}`,
    "-c", "model_provider=fluidbox",
    "-c", "model_providers.fluidbox.name=fluidbox",
    "-c", `model_providers.fluidbox.base_url=${FACADE_BASE}`,
    "-c", "model_providers.fluidbox.wire_api=responses",
    "-c", "model_providers.fluidbox.requires_openai_auth=false",
    // Gap 10: model egress authenticates with the LLM-AUDIENCE token. This used
    // to be FLUIDBOX_SESSION_TOKEN, which is now runner-control only (and is
    // deleted from the env above, so codex could not read it even by name).
    "-c", "model_providers.fluidbox.env_key=FLUIDBOX_LLM_TOKEN",
    "-c", "approval_policy=untrusted",
    "-c", "approvals_reviewer=user",
    // Codex's own sandbox is OFF: bubblewrap can't run under the container's
    // cap_drop=ALL + no-new-privileges. The container + the /permission gate
    // are the boundary (claude parity). Governance is unchanged — untrusted +
    // the universal execpolicy rule still force every exec through the gate.
    "-c", "sandbox_mode=danger-full-access",
    "-c", "model_reasoning_effort=low",
    // Writable runtime state OUTSIDE the read-only CODEX_HOME.
    "-c", "sqlite_home=/opt/fluidbox-codex/state",
    "-c", "log_dir=/opt/fluidbox-codex/state/log",
  ];
  child = spawn("codex", args, {
    cwd: env.WORKSPACE,
    // process.env no longer holds the runner-control token (deleted at load);
    // codex receives the LLM-audience credential its env_key names, and that is
    // the only credential it needs.
    env: { ...process.env, FLUIDBOX_LLM_TOKEN: env.LLM_TOKEN },
    stdio: ["pipe", "pipe", "inherit"],
  });
  let buf = "";
  child.stdout.on("data", (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      handleLine(buf.slice(0, i));
      buf = buf.slice(i + 1);
    }
  });
  child.on("exit", (code, signal) => {
    if (!turnDone && !shuttingDown) {
      hadError = hadError || new Error(`codex exited unexpectedly (code=${code} signal=${signal})`);
      turnDone = true;
      finishRun();
    }
  });
}

let shuttingDown = false;
let quiesced = false;

async function main() {
  await client.emit("harness", {
    type: "agent.message",
    data: { role: "system", text: `codex runner starting (autonomy=${env.AUTONOMY}, model=${MODEL})` },
  });
  // Cancellation quiesce (shared runner contract): on the heartbeat signal we
  // interrupt the codex turn and finish WITHOUT posting /result — the control
  // plane's cancel finalizer owns the terminal outcome and collects the diff.
  client.onQuiesce(() => {
    quiesced = true;
    try {
      if (threadId && turnId) {
        rpcSend({ jsonrpc: "2.0", id: nextId++, method: "turn/interrupt", params: { threadId, turnId } });
      }
    } catch {
      /* best effort */
    }
    turnDone = true;
    finishRun();
  });
  client.startHeartbeat();
  client.startTokenRenew();
  spawnCodex();

  try {
    await rpcRequest("initialize", {
      clientInfo: { name: "fluidbox-supervisor", version: "0.1.0" },
    });
    rpcSend({ jsonrpc: "2.0", method: "initialized" });

    const threadConfig = {
      "tools.web_search": false,
      "tools.view_image": false,
      "features.web_search": false,
      "features.standalone_web_search": false,
      "features.unified_exec": false,
      "features.multi_agent": false,
      "features.apps": false,
      "features.goals": false,
      "features.plugins": false,
      "features.shell_snapshot": false,
      "features.browser_use": false,
      "features.computer_use": false,
      "features.image_generation": false,
      "features.tool_suggest": false,
      "features.tool_search": false,
    };
    const mcp = mcpServersConfig();
    if (Object.keys(mcp).length > 0) threadConfig.mcp_servers = mcp;

    const ts = await rpcRequest("thread/start", {
      cwd: env.WORKSPACE,
      model: MODEL,
      approvalPolicy: "untrusted",
      approvalsReviewer: "user",
      // See spawnCodex: codex's own sandbox is off (bubblewrap is incompatible
      // with the container hardening); the container + gate are the boundary.
      sandbox: "danger-full-access",
      developerInstructions: env.SYSTEM_PROMPT || undefined,
      // ephemeral: no durable thread/session rollout under the read-only
      // CODEX_HOME (sqlite runtime state rides the writable sqlite_home).
      ephemeral: true,
      config: threadConfig,
    });
    threadId = ts?.thread?.id;
    if (!threadId) throw new Error("thread/start returned no thread id");

    const tr = await rpcRequest("turn/start", {
      threadId,
      input: [{ type: "text", text: env.TASK }],
    });
    turnId = tr?.turn?.id;
  } catch (e) {
    hadError = e;
    turnDone = true;
  }

  // Wait for turn/completed (or an unexpected codex exit). A TIMEOUT is a
  // failure, never a silent success — interrupt the turn and mark the error.
  const timedOut = await waitFor(() => turnDone, 55 * 60 * 1000);
  if (timedOut && !turnDone) {
    hadError = hadError || new Error("codex turn timed out");
    try {
      if (threadId && turnId) rpcSend({ jsonrpc: "2.0", id: nextId++, method: "turn/interrupt", params: { threadId, turnId } });
    } catch {
      /* best effort */
    }
  }
  await finishRun();
}

// Resolve when `cond()` holds; resolve true on timeout (the caller treats a
// timeout as a failure, not a completion).
function waitFor(cond, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now();
    const t = setInterval(() => {
      if (cond()) {
        clearInterval(t);
        resolve(false);
      } else if (Date.now() - started > timeoutMs) {
        clearInterval(t);
        resolve(true);
      }
    }, 200);
    t.unref?.();
  });
}

let finished = false;
async function finishRun() {
  if (finished) return;
  finished = true;
  shuttingDown = true;
  if (hadError && !quiesced) {
    await client.emit("harness", {
      type: "run.error",
      data: { message: String(hadError?.message || hadError) },
    });
  }
  client.stopHeartbeat();
  client.stopTokenRenew();
  try {
    if (child && !child.killed) child.kill("SIGKILL");
  } catch {
    /* ignore */
  }
  // Quiesced (cancelled): exit WITHOUT posting /result — the cancel finalizer
  // records the terminal outcome and collects the diff.
  if (quiesced) {
    console.error("fluidbox-codex: quiesced on cancel — exiting without /result");
    process.exit(0);
  }
  try {
    await client.postResult(hadError ? "failed" : "completed", hadError ? String(hadError.message || hadError) : finalText);
  } catch (e) {
    console.error("fluidbox-codex: failed to post result:", e.message);
    process.exit(1);
  }
  process.exit(hadError ? 1 : 0);
}

main().catch(async (e) => {
  console.error("fluidbox-codex: fatal:", e);
  hadError = e;
  await finishRun();
});
