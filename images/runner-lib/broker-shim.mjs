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
import {
  audienceMismatchDiagnostic,
  isWrongAudienceRefusal,
  EXIT_AUDIENCE_MISMATCH,
} from "./contract.mjs";

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
// Gap 10: this shim forwards intents to /tools/call, so it holds the TOOL-INTENT
// credential and nothing else — never the runner-control token (which the
// harness deletes from the environment before spawning anything).
const TOKEN = requireEnv("FLUIDBOX_TOOL_TOKEN");
const SERVER_NAME = requireEnv("FLUIDBOX_BROKER_SERVER");
const TOOLS = JSON.parse(requireEnv("FLUIDBOX_BROKER_TOOLS"));

// Supervised approvals can hold a call for many minutes (the gate's
// approval TTL bounds it); the timeout only guards a wedged control plane.
const CALL_TIMEOUT_MS = 12.5 * 60 * 1000;

// Transport retries of ONE logical invocation (review I4). Bounded and small:
// the control-plane request is idempotent by `tool_call_id`, so a retry lands on
// the SAME durable execution claim — it adopts a terminal outcome, or polls an
// in-flight one. It never dispatches a second time upstream.
const MAX_TRANSPORT_ATTEMPTS = 3;
const TRANSPORT_BACKOFF_MS = [500, 1500];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/// One control-plane POST. Resolves `{ res, text }`, or throws (transport loss).
async function post(url, body) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), CALL_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${TOKEN}`,
      },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    // Read the body as TEXT first (see the caller): a truncated read is itself
    // transport loss, so it must be able to throw out of here.
    const text = await res.text();
    return { res, text };
  } finally {
    clearTimeout(timer);
  }
}

async function forward(toolName, args) {
  const url = `${CONTROL.replace(/\/$/, "")}/internal/sessions/${SESSION}/tools/call`;
  // ONE id per logical tool invocation, minted OUTSIDE the retry loop (review
  // I4). This is what makes the control plane's at-most-one-dispatch guarantee
  // reach the model: every re-presentation of this call carries the same
  // idempotency key, so a lost RESPONSE can be re-asked instead of turning into
  // a fresh claim (a fresh id was a second upstream write waiting to happen —
  // upstream had already committed, the claim already said `succeeded`, and
  // only the answer was lost). It also keeps approvals idempotent: a retry
  // never re-asks a human.
  const body = {
    tool_call_id: `bkr_${crypto.randomUUID()}`,
    tool: `mcp__${SERVER_NAME}__${toolName}`,
    input: args ?? {},
  };
  let lastLoss = "no response";
  for (let attempt = 1; attempt <= MAX_TRANSPORT_ATTEMPTS; attempt += 1) {
    let res;
    let text;
    try {
      ({ res, text } = await post(url, body));
    } catch (e) {
      // Transport loss: the request may have been fully served upstream and
      // only the answer lost. Re-present the SAME id rather than giving up.
      lastLoss = String(e?.message || e);
      if (attempt < MAX_TRANSPORT_ATTEMPTS) {
        await sleep(TRANSPORT_BACKOFF_MS[attempt - 1] ?? 1500);
        continue;
      }
      break;
    }
    const answer = interpret(res, text);
    if (answer.retry) {
      lastLoss = answer.loss;
      if (attempt < MAX_TRANSPORT_ATTEMPTS) {
        await sleep(TRANSPORT_BACKOFF_MS[attempt - 1] ?? 1500);
        continue;
      }
      break;
    }
    return answer.result;
  }
  // Unresolved after a bounded re-presentation of the same idempotency key. We
  // do NOT know whether the tool ran — say so in those words. A generic
  // "unreachable" reads as "nothing happened" and invites the model to re-run a
  // write that may already have landed.
  return errText(
    `fluidbox broker outcome UNKNOWN: the control plane did not answer ` +
      `${MAX_TRANSPORT_ATTEMPTS} attempts at this call (${lastLoss}). This call MAY HAVE ` +
      `EXECUTED upstream — do not assume it did not, and do not repeat it blindly; ` +
      `check the upstream state or ask the user before retrying.`,
  );
}

/// Classify ONE control-plane response. `{ retry: true, loss }` means the answer
/// was lost or the control plane is momentarily sick (re-present the same id);
/// otherwise `{ result }` is the MCP result for the model. PURE apart from the
/// audience-mismatch exit.
function interpret(res, text) {
  // `wrong_audience` has to be told apart from an ordinary refusal BEFORE it is
  // flattened into an isError result the model would read as "denied by policy"
  // and route around.
  if (isWrongAudienceRefusal(res.status, text)) {
    // Gap 10 fatal (same treatment as the runner contract): the shim's
    // TOOL-INTENT credential is not the one this control plane's route
    // guards expect. Exiting takes the stdio MCP server down loudly instead
    // of serving denials for the rest of the run.
    console.error(audienceMismatchDiagnostic(`${SERVER_NAME} tools/call`));
    process.exit(EXIT_AUDIENCE_MISMATCH);
  }
  const body = (() => {
    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  })();
  // A 5xx, or an OK status whose body did not arrive intact, says nothing about
  // whether the tool ran — re-present the same id. A 4xx is a DECIDED refusal
  // (terminal session, bad audience, malformed intent): re-presenting it would
  // only get the same answer.
  if (res.status >= 500 || (res.ok && !body)) {
    return { retry: true, loss: `HTTP ${res.status}${body ? "" : " (unreadable body)"}` };
  }
  if (!res.ok || !body) {
    return { result: errText(`fluidbox broker returned HTTP ${res.status}`) };
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
    return { result: out };
  }
  if (body.denied) {
    return { result: errText(`fluidbox denied this call: ${body.message || "denied by policy"}`) };
  }
  // A DECIDED failure (upstream error, ambiguous outcome, exhausted attempts) —
  // the control plane already classified it; relay it verbatim, never retry it.
  return { result: errText(`brokered execution failed: ${body.error || "unknown error"}`) };
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
