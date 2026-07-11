// fluidbox sandbox runner — the Claude Agent SDK harness, governed.
//
// Contract with the control plane (identical for every future harness):
//   - canUseTool  → POST /internal/sessions/{id}/permission   (blocks; retried by tool_call_id)
//   - messages    → POST /internal/sessions/{id}/events
//   - heartbeats  → POST /internal/sessions/{id}/heartbeat     (every 10s)
//   - final       → POST /internal/sessions/{id}/result
//
// Model calls leave via ANTHROPIC_BASE_URL (the fluidbox LLM facade) using
// the session token as a fake ANTHROPIC_API_KEY. The real provider key lives
// only in the gateway; this process never sees it.

import { query } from "@anthropic-ai/claude-agent-sdk";

const CONTROL = requireEnv("FLUIDBOX_CONTROL_URL");
const SESSION = requireEnv("FLUIDBOX_SESSION_ID");
const TOKEN = requireEnv("FLUIDBOX_SESSION_TOKEN");
const TASK = requireEnv("FLUIDBOX_TASK");
const AUTONOMY = process.env.FLUIDBOX_AUTONOMY || "supervised";
const MODEL = process.env.FLUIDBOX_MODEL || "claude-haiku-4-5";
const WORKSPACE = process.env.FLUIDBOX_WORKSPACE || "/workspace";
const SYSTEM_PROMPT = process.env.FLUIDBOX_SYSTEM_PROMPT || undefined;
const MAX_TURNS = parseInt(process.env.FLUIDBOX_MAX_TURNS || "60", 10);
// The FROZEN capability manifest (control plane strips broker internals —
// this process never sees upstream URLs or credentials).
const CAPABILITIES = (() => {
  const raw = process.env.FLUIDBOX_CAPABILITIES;
  if (!raw) return { servers: [] };
  try {
    const parsed = JSON.parse(raw);
    return { servers: Array.isArray(parsed?.servers) ? parsed.servers : [] };
  } catch (e) {
    console.error("fluidbox-runner: bad FLUIDBOX_CAPABILITIES (ignoring):", e.message);
    return { servers: [] };
  }
})();
// Brokered server aliases: their calls are gated (and executed) by the
// control plane's /tools/call endpoint — canUseTool waves them through so
// each call is decided exactly once, server-side.
const BROKERED = new Set(
  CAPABILITIES.servers.filter((s) => s.class === "brokered").map((s) => s.name),
);

function requireEnv(k) {
  const v = process.env[k];
  if (!v) {
    console.error(`fluidbox-runner: missing required env ${k}`);
    process.exit(2);
  }
  return v;
}

function base() {
  return `${CONTROL.replace(/\/$/, "")}/internal/sessions/${SESSION}`;
}

async function post(path, body, { retries = 0, timeoutMs = 30000 } = {}) {
  for (let attempt = 0; ; attempt++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(`${base()}${path}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${TOKEN}`,
        },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`${path} → HTTP ${res.status}: ${text}`);
      }
      return res.status === 204 ? null : await res.json().catch(() => null);
    } catch (e) {
      clearTimeout(timer);
      if (attempt >= retries) throw e;
      const backoff = Math.min(2000 * (attempt + 1), 8000);
      await sleep(backoff);
    }
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function emit(actor, body) {
  try {
    await post("/events", { actor, body }, { retries: 3 });
  } catch (e) {
    console.error("fluidbox-runner: emit failed (continuing):", e.message);
  }
}

// The permission gate. Blocks until the control plane answers (supervised
// mode may hold it up to its 10-min bound; autonomous answers instantly).
// The tool_call_id makes the POST idempotent, so we retry hard on socket
// drops without risking a double-decision — the server always wins.
async function requestPermission(toolName, input, toolUseId) {
  const body = {
    tool_call_id: toolUseId,
    tool: toolName,
    input,
  };
  // Long timeout: supervised approvals can take minutes. Retry forever on
  // transient network errors; the server dedupes by tool_call_id.
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await post("/permission", body, { timeoutMs: 12 * 60 * 1000 });
      return res; // { decision: "allow" | "deny", message?, updated_input? }
    } catch (e) {
      console.error(`fluidbox-runner: permission attempt ${attempt} failed:`, e.message);
      await sleep(Math.min(2000 * (attempt + 1), 10000));
    }
  }
}

function summarizeInput(tool, input) {
  if (!input || typeof input !== "object") return tool;
  if (typeof input.command === "string") return input.command.slice(0, 200);
  if (typeof input.file_path === "string") return input.file_path;
  if (typeof input.path === "string") return input.path;
  if (typeof input.pattern === "string") return `pattern: ${input.pattern}`;
  return tool;
}

let heartbeatTimer = null;
function startHeartbeat() {
  heartbeatTimer = setInterval(() => {
    post("/heartbeat", {}, { retries: 1 }).catch(() => {});
  }, 10000);
  heartbeatTimer.unref?.();
}

function textFromMessage(msg) {
  // BetaMessage content is an array of blocks.
  const content = msg?.message?.content;
  if (!Array.isArray(content)) return "";
  return content
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("");
}

// `mcp__<server>__<tool>` → server alias (server aliases contain no
// underscores, so the first `__` after the prefix splits unambiguously).
function mcpServerOf(toolName) {
  if (!toolName.startsWith("mcp__")) return null;
  const rest = toolName.slice(5);
  const i = rest.indexOf("__");
  return i > 0 ? rest.slice(0, i) : null;
}

// Build the SDK mcpServers config from the frozen manifest: sandbox-class
// servers launch as stdio subprocesses inside this container; brokered
// servers get the broker shim, which forwards intents to the control plane.
function mcpServersConfig() {
  const servers = {};
  for (const srv of CAPABILITIES.servers) {
    if (srv.class === "sandbox") {
      servers[srv.name] = {
        type: "stdio",
        command: srv.command,
        args: srv.args || [],
        env: { ...process.env },
      };
    } else if (srv.class === "brokered") {
      servers[srv.name] = {
        type: "stdio",
        command: "node",
        args: ["/opt/fluidbox-runner/broker-shim.mjs"],
        env: {
          ...process.env,
          FLUIDBOX_BROKER_SERVER: srv.name,
          FLUIDBOX_BROKER_TOOLS: JSON.stringify(srv.tools || []),
        },
      };
    }
  }
  return servers;
}

async function main() {
  await emit("harness", {
    type: "agent.message",
    data: { role: "system", text: `runner starting (autonomy=${AUTONOMY}, model=${MODEL})` },
  });
  startHeartbeat();

  const canUseTool = async (toolName, input, opts) => {
    // Brokered tools are gated (and executed) server-side at /tools/call —
    // the broker owns their whole ledger trail, so waving them through here
    // decides each call exactly once, always on the control plane. A runner
    // that "forgot" this callback entirely would change nothing: the broker
    // gates regardless.
    const mcpServer = mcpServerOf(toolName);
    if (mcpServer && BROKERED.has(mcpServer)) {
      return { behavior: "allow", updatedInput: input };
    }
    const toolUseId = opts?.toolUseID || `tu_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    await emit("agent", {
      type: "tool.requested",
      data: {
        tool_call_id: toolUseId,
        tool: toolName,
        summary: summarizeInput(toolName, input),
        input_digest: "",
      },
    });
    const verdict = await requestPermission(toolName, input, toolUseId);
    if (verdict && verdict.decision === "allow") {
      return { behavior: "allow", updatedInput: verdict.updated_input || input };
    }
    return {
      behavior: "deny",
      message: (verdict && verdict.message) || "denied by fluidbox policy",
    };
  };

  const mcpServers = mcpServersConfig();
  if (Object.keys(mcpServers).length > 0) {
    await emit("harness", {
      type: "agent.message",
      data: {
        role: "system",
        text: `capability servers mounted: ${CAPABILITIES.servers
          .map((s) => `${s.name} (${s.class})`)
          .join(", ")}`,
      },
    });
  }

  let finalText = "";
  let hadError = null;
  try {
    const response = query({
      prompt: TASK,
      options: {
        model: MODEL,
        systemPrompt: SYSTEM_PROMPT,
        cwd: WORKSPACE,
        canUseTool,
        maxTurns: MAX_TURNS,
        // The FROZEN capability manifest, mounted (sandbox stdio servers +
        // broker shims). Undefined when the run carries no capabilities.
        mcpServers: Object.keys(mcpServers).length > 0 ? mcpServers : undefined,
        // Clean sandbox: do not load host/user/project settings files.
        settingSources: [],
        // Everything routes through canUseTool → our gateway.
        permissionMode: "default",
      },
    });

    for await (const msg of response) {
      if (msg.type === "assistant") {
        const text = textFromMessage(msg);
        if (text.trim()) {
          await emit("agent", { type: "agent.message", data: { role: "assistant", text } });
        }
      } else if (msg.type === "result") {
        finalText = msg.result || "";
        if (typeof msg.total_cost_usd === "number") {
          // Advisory only; the facade is the metering source of truth.
          await emit("harness", {
            type: "agent.message",
            data: { role: "system", text: `agent reported cost ~$${msg.total_cost_usd.toFixed(4)}` },
          });
        }
      }
    }
  } catch (e) {
    hadError = e;
    console.error("fluidbox-runner: query failed:", e);
    await emit("harness", { type: "run.error", data: { message: String(e?.message || e) } });
  } finally {
    if (heartbeatTimer) clearInterval(heartbeatTimer);
  }

  try {
    await post(
      "/result",
      {
        outcome: hadError ? "failed" : "completed",
        summary: hadError ? String(hadError?.message || hadError) : finalText.slice(0, 4000),
      },
      { retries: 5 },
    );
  } catch (e) {
    console.error("fluidbox-runner: failed to post result:", e.message);
    process.exit(1);
  }
  process.exit(hadError ? 1 : 0);
}

main().catch((e) => {
  console.error("fluidbox-runner: fatal:", e);
  process.exit(1);
});
