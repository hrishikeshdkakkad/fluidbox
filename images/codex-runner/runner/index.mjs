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

// A cwd is acceptable only if it normalizes to a path INSIDE the frozen
// workspace (reject outside / missing-that-escapes / symlink escape). A
// `cat x` verdict is not equivalent if codex runs it from $CODEX_HOME.
function cwdInWorkspace(cwd) {
  if (cwd == null) return WORKSPACE; // codex omitted it → the thread cwd (= workspace)
  let resolved = path.resolve(WORKSPACE, cwd);
  try {
    if (fs.existsSync(resolved)) resolved = fs.realpathSync(resolved);
  } catch {
    /* fall through with the lexical resolution */
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

// fileChange item changes[] → canonical MultiEdit edits[]. A move carries
// BOTH source and dest paths; the op-type + cwd ride ADDITIVELY (policy
// ignores unknown fields; the ledger keeps them).
function canonicalizeEdits(changes) {
  const edits = [];
  for (const c of changes || []) {
    if (typeof c?.path === "string") edits.push({ file_path: c.path, op: c.kind || "update" });
    for (const k of ["movePath", "dest", "newPath", "destination"]) {
      if (typeof c?.[k] === "string") edits.push({ file_path: c[k], op: "move_dest" });
    }
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
// itemId → cached gate decision (dedup a retried approval to one decision).
const decided = new Map();
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
async function handleServerRequest(msg) {
  const { method, params, id } = msg;
  if (method === "item/permissions/requestApproval") {
    // Sandbox escalation — deny by returning no permissions (the container is
    // the containment boundary; we never widen it).
    rpcSend({ id, result: { permissions: {}, scope: "turn" } });
    return;
  }
  if (method === "item/commandExecution/requestApproval") {
    return decideExec(id, params);
  }
  if (method === "item/fileChange/requestApproval") {
    return decideFileChange(id, params);
  }
  // Any other server request (item/tool/requestUserInput, mcp elicitation,
  // legacy execCommandApproval/applyPatchApproval): fail closed — deny.
  rpcSend({ id, result: { decision: "decline" } });
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
  const decision = await gate(key, "Bash", { command, cwd });
  rpcSend({ id, result: { decision: decision ? "accept" : "decline" } });
}

async function decideFileChange(id, params) {
  const key = params.approvalId || params.itemId;
  const changes = items.get(params.itemId)?.changes || [];
  const edits = canonicalizeEdits(changes);
  const decision = await gate(key, "MultiEdit", { edits, cwd: WORKSPACE });
  rpcSend({ id, result: { decision: decision ? "accept" : "decline" } });
}

// One decision per stable id; a retried approval re-uses it (the server is
// also idempotent by tool_call_id, but caching avoids a second round-trip).
async function gate(callId, tool, input) {
  if (decided.has(callId)) return decided.get(callId);
  const verdict = await client.requestPermission(tool, input, callId);
  const allow = !!(verdict && verdict.decision === "allow");
  decided.set(callId, allow);
  return allow;
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
      if (st === "failed") hadError = new Error(params?.turn?.error?.message || "codex turn failed");
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
    "-c", "model_providers.fluidbox.env_key=FLUIDBOX_SESSION_TOKEN",
    "-c", "approval_policy=untrusted",
    "-c", "approvals_reviewer=user",
    "-c", "sandbox_mode=read-only",
    "-c", "model_reasoning_effort=low",
  ];
  child = spawn("codex", args, {
    cwd: env.WORKSPACE,
    env: { ...process.env, FLUIDBOX_SESSION_TOKEN: env.TOKEN },
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

async function main() {
  await client.emit("harness", {
    type: "agent.message",
    data: { role: "system", text: `codex runner starting (autonomy=${env.AUTONOMY}, model=${MODEL})` },
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
    };
    const mcp = mcpServersConfig();
    if (Object.keys(mcp).length > 0) threadConfig.mcp_servers = mcp;

    const ts = await rpcRequest("thread/start", {
      cwd: env.WORKSPACE,
      model: MODEL,
      approvalPolicy: "untrusted",
      approvalsReviewer: "user",
      sandbox: "read-only",
      developerInstructions: env.SYSTEM_PROMPT || undefined,
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

  // Wait for turn/completed (or an unexpected codex exit).
  await waitFor(() => turnDone, 55 * 60 * 1000);
  await finishRun();
}

function waitFor(cond, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now();
    const t = setInterval(() => {
      if (cond() || Date.now() - started > timeoutMs) {
        clearInterval(t);
        resolve();
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
  if (hadError) {
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
