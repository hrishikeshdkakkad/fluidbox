// fluidbox broker shim — a stdio MCP server the harness talks to for ONE
// brokered capability server. It advertises the FROZEN tool snapshot
// verbatim (never a live list) and forwards every tools/call as an intent
// to the fluidbox internal gateway, which gates it (policy, trust tier,
// approvals, budgets) and executes it control-plane-side with the sealed
// credential. This process holds only the session token — no upstream
// URL, no upstream credential. Harness-agnostic by design: any MCP-capable
// harness (Claude Agent SDK today, Codex later) gets brokered tools by
// spawning this shim.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import crypto from "node:crypto";

function requireEnv(k) {
  const v = process.env[k];
  if (!v) {
    console.error(`fluidbox-broker-shim: missing required env ${k}`);
    process.exit(2);
  }
  return v;
}

const CONTROL = requireEnv("FLUIDBOX_CONTROL_URL");
const SESSION = requireEnv("FLUIDBOX_SESSION_ID");
const TOKEN = requireEnv("FLUIDBOX_SESSION_TOKEN");
const SERVER_NAME = requireEnv("FLUIDBOX_BROKER_SERVER");
const TOOLS = JSON.parse(requireEnv("FLUIDBOX_BROKER_TOOLS"));

// Supervised approvals can hold a call for many minutes (the gate's
// approval TTL bounds it); the timeout only guards a wedged control plane.
const CALL_TIMEOUT_MS = 12.5 * 60 * 1000;

async function forward(toolName, args) {
  const url = `${CONTROL.replace(/\/$/, "")}/internal/sessions/${SESSION}/tools/call`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), CALL_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${TOKEN}`,
      },
      body: JSON.stringify({
        // Fresh id per MCP request: the gate's approvals are idempotent by
        // this id, so a lost response never re-asks a human — but we do NOT
        // blind-retry either (brokered execution is at-least-once and the
        // model can retry deliberately on a visible error).
        tool_call_id: `bkr_${crypto.randomUUID()}`,
        tool: `mcp__${SERVER_NAME}__${toolName}`,
        input: args ?? {},
      }),
      signal: ctrl.signal,
    });
    const body = await res.json().catch(() => null);
    if (!res.ok || !body) {
      return errText(`fluidbox broker returned HTTP ${res.status}`);
    }
    if (body.ok) {
      const content = Array.isArray(body.result?.content) ? body.result.content : [];
      const out = { content, isError: Boolean(body.result?.is_error) };
      // E7: relay structured output when the broker passed it through (MCP
      // CallToolResult.structuredContent, paired with an outputSchema tool).
      const structured = body.result?.structured_content;
      if (structured !== undefined && structured !== null) {
        out.structuredContent = structured;
      }
      return out;
    }
    if (body.denied) {
      return errText(`fluidbox denied this call: ${body.message || "denied by policy"}`);
    }
    return errText(`brokered execution failed: ${body.error || "unknown error"}`);
  } catch (e) {
    return errText(`fluidbox broker unreachable: ${String(e?.message || e)}`);
  } finally {
    clearTimeout(timer);
  }
}

const errText = (text) => ({ content: [{ type: "text", text }], isError: true });

const server = new Server(
  { name: `fluidbox-broker-${SERVER_NAME}`, version: "0.1.0" },
  { capabilities: { tools: {} } },
);

// The frozen snapshot IS the tool list — a drifted upstream changes nothing
// here, and the server-side gate denies anything outside the snapshot anyway.
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS.map((t) => ({
    name: t.name,
    description: t.description || "",
    inputSchema: t.input_schema || { type: "object" },
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (req) =>
  forward(req.params.name, req.params.arguments),
);

await server.connect(new StdioServerTransport());
