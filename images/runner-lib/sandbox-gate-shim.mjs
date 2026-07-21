// fluidbox sandbox gate-shim — a GATING stdio MCP proxy for ONE sandbox-class
// capability server under the Codex harness. Claude gates sandbox servers via
// canUseTool and never spawns this; codex's approval plumbing is not trusted,
// so the shim is the gate for sandbox tools:
//   - it serves the FROZEN tools/list snapshot itself (never the child's live
//     list — a drifted child changes nothing, and the server-side gate denies
//     anything outside the snapshot anyway),
//   - it spawns the REAL sandbox subprocess (stdio MCP) with a scrubbed env,
//   - on every tools/call it preflights POST /permission (the SAME gate the
//     claude runner reaches through canUseTool) and forwards to the child
//     ONLY on allow.
// Sandbox tools EXECUTE in the sandbox (the child), so we gate (decision) then
// run locally — unlike brokered tools, which execute control-plane-side.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import crypto from "node:crypto";

function requireEnv(k) {
  const v = process.env[k];
  if (!v) {
    console.error(`fluidbox-gate-shim: missing required env ${k}`);
    process.exit(2);
  }
  return v;
}

const CONTROL = requireEnv("FLUIDBOX_CONTROL_URL");
const SESSION = requireEnv("FLUIDBOX_SESSION_ID");
// Gap 10: this shim preflights /permission, so it holds the TOOL-INTENT
// credential only — never the runner-control token.
const TOKEN = requireEnv("FLUIDBOX_TOOL_TOKEN");
const SERVER_NAME = requireEnv("FLUIDBOX_GATE_SERVER");
const CHILD_COMMAND = requireEnv("FLUIDBOX_GATE_COMMAND");
const CHILD_ARGS = JSON.parse(process.env.FLUIDBOX_GATE_ARGS || "[]");
const TOOLS = JSON.parse(requireEnv("FLUIDBOX_GATE_TOOLS"));
const PERM_TIMEOUT_MS = 12 * 60 * 1000;

const errText = (text) => ({ content: [{ type: "text", text }], isError: true });

// Preflight the fluidbox permission gate (the same endpoint the claude runner
// hits from canUseTool). A fresh tool_call_id per call — the server's approval
// idempotency + digest binding key on it.
async function gate(toolName, args) {
  const url = `${CONTROL.replace(/\/$/, "")}/internal/sessions/${SESSION}/permission`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PERM_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({
        tool_call_id: `sbx_${crypto.randomUUID()}`,
        tool: `mcp__${SERVER_NAME}__${toolName}`,
        input: args ?? {},
      }),
      signal: ctrl.signal,
    });
    const body = await res.json().catch(() => null);
    if (!res.ok || !body) return { allow: false, message: `gate HTTP ${res.status}` };
    return { allow: body.decision === "allow", message: body.message };
  } catch (e) {
    return { allow: false, message: `gate unreachable: ${String(e?.message || e)}` };
  } finally {
    clearTimeout(timer);
  }
}

// Spawn the REAL sandbox server as an MCP child with a SCRUBBED env — it never
// sees the session token, control URL, or any fluidbox wiring.
const childEnv = { ...process.env };
for (const k of Object.keys(childEnv)) {
  if (k.startsWith("FLUIDBOX_") || k === "ANTHROPIC_API_KEY" || k === "OPENAI_API_KEY") {
    delete childEnv[k];
  }
}
const child = new Client({ name: `fluidbox-gate-${SERVER_NAME}`, version: "0.1.0" }, { capabilities: {} });
const childTransport = new StdioClientTransport({
  command: CHILD_COMMAND,
  args: CHILD_ARGS,
  env: childEnv,
});

const server = new Server(
  { name: `fluidbox-gate-${SERVER_NAME}`, version: "0.1.0" },
  { capabilities: { tools: {} } },
);

// The FROZEN snapshot IS the tool list.
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS.map((t) => ({
    name: t.name,
    description: t.description || "",
    inputSchema: t.input_schema || { type: "object" },
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;
  // A tool not in the frozen snapshot doesn't exist for this run.
  if (!TOOLS.some((t) => t.name === name)) {
    return errText(`fluidbox: '${name}' is not in the frozen capability set`);
  }
  const verdict = await gate(name, args);
  if (!verdict.allow) {
    return errText(`fluidbox denied this call: ${verdict.message || "denied by policy"}`);
  }
  try {
    const result = await child.callTool({ name, arguments: args ?? {} });
    return result;
  } catch (e) {
    return errText(`sandbox tool execution failed: ${String(e?.message || e)}`);
  }
});

await child.connect(childTransport);
await server.connect(new StdioServerTransport());
