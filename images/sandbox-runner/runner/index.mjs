// fluidbox sandbox runner — the Claude Agent SDK harness, governed.
//
// Governance wiring (permission gate, events, heartbeat, token renewal,
// result) lives in the shared runner contract lib; this file is only the
// Claude-specific agent loop. The identical contract powers the Codex
// supervisor — that is the harness seam.

import { query } from "@anthropic-ai/claude-agent-sdk";
import {
  loadRunnerEnv,
  RunnerClient,
  mcpServerOf,
  BROKER_SHIM,
  brokerShimEnv,
} from "/opt/fluidbox-runner/lib/contract.mjs";

const env = loadRunnerEnv();
const client = new RunnerClient(env);
const MODEL = env.MODEL || "claude-haiku-4-5";

// Gap 10 / invariant 19: the runner-control credential is captured in memory
// (env.TOKEN, held by the RunnerClient) and REMOVED from process.env BEFORE
// anything else spawns. The Agent SDK runs the agent's Bash/Edit tools and every
// stdio MCP server as children of THIS process with an inherited env, so leaving
// it there would hand agent-authored shell the ability to post /result or forge
// /events. After this delete those children see only the tool-intent token and
// the model key (ANTHROPIC_API_KEY) — neither of which any runner-control route
// accepts.
//
// PHASE F: under the shipped image the credential never reached this
// environment in the first place — lib/entrypoint.sh hands it over on an
// unlinked-file descriptor and execve's this process with an environ region that
// never held it, so /proc/<pid>/environ is now clean too. The delete below stays
// because it is still exactly right for (a) the COMPATIBILITY path, where the
// entrypoint was bypassed and the token really is in the environment, and (b)
// the spawned environment either way. FLUIDBOX_SESSION_TOKEN_FD goes with it:
// the descriptor is already closed, so an inherited pointer to it would only
// mislead.
//
// DISCLOSED RESIDUAL, narrowed but not gone: a same-uid child can still
// ptrace(2) this process and read the token out of live memory. cap_drop=ALL,
// no-new-privileges and seccomp RuntimeDefault do not block same-uid ptrace —
// only a uid split or a separate container (its own PID namespace) does.
delete process.env.FLUIDBOX_SESSION_TOKEN;
delete process.env.FLUIDBOX_SESSION_TOKEN_FD;

function textFromMessage(msg) {
  // BetaMessage content is an array of blocks.
  const content = msg?.message?.content;
  if (!Array.isArray(content)) return "";
  return content
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("");
}

// Build the SDK mcpServers config from the frozen manifest: sandbox-class
// servers launch as stdio subprocesses inside this container and are gated by
// canUseTool; brokered servers get the broker shim, which forwards intents to
// the control plane (auto-allowed here; gated server-side).
function mcpServersConfig() {
  const servers = {};
  for (const srv of env.CAPABILITIES.servers) {
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

  const canUseTool = async (toolName, input, opts) => {
    // Brokered tools are gated (and executed) server-side at /tools/call —
    // waving them through here decides each call exactly once, on the control
    // plane. A runner that "forgot" this callback changes nothing.
    const mcpServer = mcpServerOf(toolName);
    if (mcpServer && env.BROKERED.has(mcpServer)) {
      return { behavior: "allow", updatedInput: input };
    }
    // NOTE: the runner no longer emits its own tool.requested — the SERVER
    // writes the canonical event exactly once per intent inside the gate
    // (Phase 6), so budget/audit parity never depends on runner cooperation.
    const toolCallId =
      opts?.toolUseID || `tu_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const verdict = await client.requestPermission(toolName, input, toolCallId);
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
    const response = query({
      prompt: env.TASK,
      options: {
        model: MODEL,
        systemPrompt: env.SYSTEM_PROMPT,
        cwd: env.WORKSPACE,
        canUseTool,
        maxTurns: env.MAX_TURNS,
        // The FROZEN capability manifest, mounted (sandbox stdio servers +
        // broker shims). Undefined when the run carries no capabilities.
        mcpServers: Object.keys(mcpServers).length > 0 ? mcpServers : undefined,
        // Clean sandbox: do not load host/user/project settings files.
        settingSources: [],
        // Everything routes through canUseTool → our gateway.
        permissionMode: "default",
      },
    });

    // Cancellation quiesce: the control plane signals via the heartbeat
    // response; we interrupt the SDK stream and exit WITHOUT posting /result,
    // so the cancel finalizer owns the outcome and collects a settled tree.
    client.onQuiesce(() => {
      quiesced = true;
      try {
        response.interrupt?.();
      } catch {
        /* best effort; the break below stops iteration regardless */
      }
    });

    for await (const msg of response) {
      if (quiesced) break;
      if (msg.type === "assistant") {
        const text = textFromMessage(msg);
        if (text.trim()) {
          await client.emit("agent", { type: "agent.message", data: { role: "assistant", text } });
        }
      } else if (msg.type === "result") {
        finalText = msg.result || "";
        if (typeof msg.total_cost_usd === "number") {
          // Advisory only; the facade is the metering source of truth.
          await client.emit("harness", {
            type: "agent.message",
            data: { role: "system", text: `agent reported cost ~$${msg.total_cost_usd.toFixed(4)}` },
          });
        }
      }
    }
  } catch (e) {
    if (quiesced) {
      // An interrupt during quiesce surfaces as a throw — expected, not a
      // failure. Fall through to the quiesce exit below.
    } else {
      hadError = e;
      console.error("fluidbox-runner: query failed:", e);
      await client.emit("harness", { type: "run.error", data: { message: String(e?.message || e) } });
    }
  } finally {
    client.stopHeartbeat();
    client.stopTokenRenew();
  }

  // Quiesced (cancelled): exit WITHOUT posting /result — the control plane's
  // cancel finalizer records the terminal outcome and collects the diff.
  if (quiesced) {
    console.error("fluidbox-runner: quiesced on cancel — exiting without /result");
    process.exit(0);
  }

  try {
    await client.postResult(
      hadError ? "failed" : "completed",
      hadError ? String(hadError?.message || hadError) : finalText,
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
