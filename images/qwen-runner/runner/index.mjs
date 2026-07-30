// fluidbox qwen runner — the Qwen Code harness, governed. Third harness.
//
// Governance wiring (permission gate, events, heartbeat, token renewal,
// result) lives in the shared runner contract lib; this file is the
// qwen-specific supervisor: it drives `@qwen-code/sdk`'s query() (which
// spawns the PINNED @qwen-code/qwen-code CLI over the stream-json control
// protocol) and bridges its canUseTool callback onto /permission with the
// canonical tool vocabulary. Protocol facts + the interception proof live in
// docs/research/2026-07-30-qwen-code-sdk-protocol.md; the settings lockdown
// that forces EVERY tool (including reads and MCP) through canUseTool is
// ../settings.json, baked root-owned read-only.

import { query } from "@qwen-code/sdk";
import { createRequire } from "node:module";
import {
  loadRunnerEnv,
  RunnerClient,
  mcpServerOf,
  BROKER_SHIM,
  brokerShimEnv,
} from "/opt/fluidbox-qwen/lib/contract.mjs";
import { canonicalize } from "./canonicalize.mjs";

const env = loadRunnerEnv();
const client = new RunnerClient(env);
const MODEL = env.MODEL || "qwen3-coder-plus";
const SETTINGS_PATH = "/opt/fluidbox-qwen/settings.json";
// Pin the CLI the SDK spawns to OUR @qwen-code/qwen-code install (the
// settings/census/interception proof were all verified against this exact
// version), never the SDK's own bundled copy. Resolved through the package's
// `main` so an image layout change fails loudly at boot instead of silently
// launching the wrong binary. The tier-0 replay bind-mounts a fake CLI over
// this path.
const QWEN_CLI = createRequire(import.meta.url).resolve("@qwen-code/qwen-code");

// Gap 10 / invariant 19: the runner-control credential is captured in memory
// (env.TOKEN, held by the RunnerClient) and REMOVED from process.env BEFORE
// anything else spawns — the SDK spawns the qwen CLI (and, through it, the
// agent's shell and every stdio MCP server) with an inherited env.
// FLUIDBOX_LLM_TOKEN goes too: the CLI receives it as OPENAI_API_KEY via the
// spawn env below, under the var its openai client actually reads. What the
// agent's children CAN still see afterwards is the tool-intent token and the
// model key — the same two-credential exposure as the claude harness
// (ANTHROPIC_API_KEY there), neither of which any runner-control route
// accepts. Same ptrace residual as both siblings; see the claude runner.
const LLM_TOKEN = env.LLM_TOKEN;
delete process.env.FLUIDBOX_SESSION_TOKEN;
delete process.env.FLUIDBOX_SESSION_TOKEN_FD;
delete process.env.FLUIDBOX_LLM_TOKEN;

// /permission blocks up to 12 min client-side (server TTL 10 min) while a
// human decides; the SDK's canUseTool timeout DEFAULT of 60s would convert a
// slow approval into a silent deny. 13 min keeps the SDK's failsafe strictly
// outside the contract window.
const CAN_USE_TOOL_TIMEOUT_MS = 13 * 60 * 1000;

function textFromMessage(msg) {
  const content = msg?.message?.content;
  if (!Array.isArray(content)) return "";
  return content
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("");
}

// Build the SDK mcpServers config from the frozen manifest — same split as
// the claude runner: sandbox-class servers launch as stdio subprocesses (with
// a SCRUBBED env) and are gated per-call by canUseTool (the settings' `mcp__`
// ask rule forces the confirmation); brokered servers get the broker shim,
// auto-allowed here because the control plane re-runs the identical gate at
// /tools/call before touching any credential.
function mcpServersConfig() {
  const servers = {};
  for (const srv of env.CAPABILITIES.servers) {
    if (srv.class === "sandbox") {
      const childEnv = { ...process.env };
      for (const k of Object.keys(childEnv)) {
        if (
          k.startsWith("FLUIDBOX_") ||
          k === "ANTHROPIC_API_KEY" ||
          k === "OPENAI_API_KEY"
        ) {
          delete childEnv[k];
        }
      }
      servers[srv.name] = {
        command: srv.command,
        args: srv.args || [],
        env: childEnv,
      };
    } else if (srv.class === "brokered") {
      servers[srv.name] = {
        command: "node",
        args: [BROKER_SHIM],
        env: brokerShimEnv(env, srv),
      };
    }
  }
  return servers;
}

async function main() {
  await client.emit("harness", {
    type: "agent.message",
    data: { role: "system", text: `runner starting (autonomy=${env.AUTONOMY}, model=${MODEL})` },
  });
  client.startHeartbeat();
  client.startTokenRenew();

  const canUseTool = async (toolName, input) => {
    // Brokered tools are gated (and executed) server-side at /tools/call —
    // waving them through here decides each call exactly once, on the control
    // plane. A runner that "forgot" this callback changes nothing.
    const mcpServer = mcpServerOf(toolName);
    if (mcpServer && env.BROKERED.has(mcpServer)) {
      return { behavior: "allow", updatedInput: input };
    }
    const toolCallId = `tu_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    if (mcpServer) {
      // Sandbox-class MCP: already canonical (mcp__<server>__<tool>) — gate
      // under the native name, input untouched.
      const verdict = await client.requestPermission(toolName, input, toolCallId);
      if (verdict && verdict.decision === "allow") {
        return { behavior: "allow", updatedInput: verdict.updated_input || input };
      }
      return {
        behavior: "deny",
        message: (verdict && verdict.message) || "denied by fluidbox policy",
      };
    }
    // Core tools: canonicalize (fail-closed) then gate. NO local decision
    // cache — every call round-trips so the server's digest binding sees it.
    const canon = canonicalize(toolName, input, env.WORKSPACE);
    if (canon.deny) {
      return { behavior: "deny", message: canon.deny };
    }
    const verdict = await client.requestPermission(canon.tool, canon.input, toolCallId);
    if (verdict && verdict.decision === "allow") {
      return {
        behavior: "allow",
        updatedInput: verdict.updated_input ? canon.mapBack(verdict.updated_input) : input,
      };
    }
    return {
      behavior: "deny",
      message: (verdict && verdict.message) || "denied by fluidbox policy",
    };
  };

  const mcpServers = mcpServersConfig();
  if (Object.keys(mcpServers).length > 0) {
    await client.emit("harness", {
      type: "agent.message",
      data: {
        role: "system",
        text: `capability servers mounted: ${env.CAPABILITIES.servers
          .map((s) => `${s.name} (${s.class})`)
          .join(", ")}`,
      },
    });
  }

  let finalText = "";
  let hadError = null;
  let quiesced = false;
  try {
    const q = query({
      prompt: env.TASK,
      options: {
        pathToQwenExecutable: QWEN_CLI,
        model: MODEL,
        systemPrompt: env.SYSTEM_PROMPT,
        cwd: env.WORKSPACE,
        canUseTool,
        // 'default' + the settings' permissions.ask rules = every tool call
        // (reads included) confirms through canUseTool. NEVER 'yolo'/'auto'.
        permissionMode: "default",
        authType: "openai",
        maxSessionTurns: env.MAX_TURNS,
        timeout: { canUseTool: CAN_USE_TOOL_TIMEOUT_MS },
        mcpServers: Object.keys(mcpServers).length > 0 ? mcpServers : undefined,
        // The spawn env is MERGED over this process's env by the SDK. The
        // fake provider key IS the llm-audience token; the facade swaps in
        // the real upstream identity. The system settings path is re-asserted
        // here (defense in depth over the Dockerfile ENV).
        env: {
          OPENAI_API_KEY: LLM_TOKEN,
          OPENAI_BASE_URL: `${env.CONTROL.replace(/\/$/, "")}/internal/llm/v1`,
          OPENAI_MODEL: MODEL,
          QWEN_CODE_SYSTEM_SETTINGS_PATH: SETTINGS_PATH,
          NO_COLOR: "1",
        },
        stderr: (line) => {
          if (line && line.trim()) console.error(`[qwen] ${line.trim()}`);
        },
      },
    });

    // Cancellation quiesce: the control plane signals via the heartbeat
    // response; interrupt the turn and exit WITHOUT posting /result so the
    // cancel finalizer owns the outcome.
    client.onQuiesce(() => {
      quiesced = true;
      Promise.resolve(q.interrupt?.()).catch(() => {
        /* best effort; the break below stops iteration regardless */
      });
    });

    for await (const msg of q) {
      if (quiesced) break;
      if (msg.type === "assistant") {
        const text = textFromMessage(msg);
        if (text.trim()) {
          await client.emit("agent", { type: "agent.message", data: { role: "assistant", text } });
        }
      } else if (msg.type === "result") {
        // subtype: success | error_max_turns | error_during_execution.
        if (msg.is_error) {
          hadError = new Error(
            msg.error?.message || `qwen run ended with ${msg.subtype || "an error"}`,
          );
        } else {
          finalText = msg.result || "";
        }
        if (msg.usage && typeof msg.usage.total_tokens === "number") {
          // Advisory only; the facade tee is the metering source of truth.
          await client.emit("harness", {
            type: "agent.message",
            data: {
              role: "system",
              text: `agent reported usage ~${msg.usage.total_tokens} tokens (advisory)`,
            },
          });
        }
      }
    }
  } catch (e) {
    if (quiesced) {
      // An interrupt during quiesce surfaces as a throw — expected.
    } else {
      hadError = e;
      console.error("fluidbox-qwen: query failed:", e);
      await client.emit("harness", {
        type: "run.error",
        data: { message: String(e?.message || e) },
      });
    }
  } finally {
    client.stopHeartbeat();
    client.stopTokenRenew();
  }

  if (quiesced) {
    console.error("fluidbox-qwen: quiesced on cancel — exiting without /result");
    process.exit(0);
  }

  if (hadError) {
    await client.emit("harness", {
      type: "run.error",
      data: { message: String(hadError?.message || hadError) },
    });
  }

  try {
    await client.postResult(
      hadError ? "failed" : "completed",
      hadError ? String(hadError?.message || hadError) : finalText,
    );
  } catch (e) {
    console.error("fluidbox-qwen: failed to post result:", e.message);
    process.exit(1);
  }
  process.exit(hadError ? 1 : 0);
}

main().catch((e) => {
  console.error("fluidbox-qwen: fatal:", e);
  process.exit(1);
});
