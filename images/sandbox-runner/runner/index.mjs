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
  forceGateDecision,
  GateWitness,
  EXIT_UNGOVERNED_TOOL,
  ungovernedToolDiagnostic,
} from "/opt/fluidbox-runner/lib/contract.mjs";
import { createLogger } from "/opt/fluidbox-runner/lib/log.mjs";

const log = createLogger({ target: "sandbox-runner" });

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

// BetaMessage content is an array of blocks — or a bare string on some user
// messages, which carries no tool blocks and is normalized away here.
function blocksOf(msg) {
  const content = msg?.message?.content;
  return Array.isArray(content) ? content : [];
}

function textFromMessage(msg) {
  return blocksOf(msg)
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
      // SCRUBBED child env, mirroring runner-lib/sandbox-gate-shim.mjs: a
      // sandbox-class server is credential-free by definition, so it must not
      // inherit the tool/llm session tokens or any fluidbox wiring this
      // runner still holds (the codex path already scrubs; keep the two
      // harnesses aligned).
      const childEnv = { ...process.env };
      for (const k of Object.keys(childEnv)) {
        if (k.startsWith("FLUIDBOX_") || k === "ANTHROPIC_API_KEY" || k === "OPENAI_API_KEY") {
          delete childEnv[k];
        }
      }
      servers[srv.name] = {
        type: "stdio",
        command: srv.command,
        args: srv.args || [],
        env: childEnv,
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

/// Stop the run because a tool executed without a fluidbox decision.
///
/// Never returns. Mirrors the audience-mismatch abort in the contract lib and
/// for the same reason: this is a broken harness, not a governance verdict, so
/// it must not be laundered into an ordinary outcome. The diagnostic is
/// best-effort recorded on the run timeline (unlike the audience case, the
/// runner-control credential here is known good), and NO /result is posted —
/// a runner that just proved it cannot mediate tool calls has not earned the
/// right to write this run's terminal outcome. The heartbeat watchdog
/// terminalizes the exited run exactly as it does for any runner crash.
async function abortUngoverned(tool, toolCallId) {
  const diag = ungovernedToolDiagnostic(tool, toolCallId);
  log.error(diag);
  await client.emit("harness", {
    type: "run.error",
    data: { message: diag, tool, tool_call_id: toolCallId },
  });
  client.stopHeartbeat();
  client.stopTokenRenew();
  process.exit(EXIT_UNGOVERNED_TOOL);
}

async function main() {
  await client.emit("harness", {
    type: "agent.message",
    data: { role: "system", text: `runner starting (autonomy=${env.AUTONOMY}, model=${MODEL})` },
  });
  client.startHeartbeat();
  client.startTokenRenew();

  // Every tool call this run's gate decided, and every one it merely watched
  // being emitted. See GateWitness: the hook below is the guarantee, this is
  // the regression tripwire behind it.
  const witness = new GateWitness();

  const canUseTool = async (toolName, input, opts) => {
    const toolCallId =
      opts?.toolUseID || `tu_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    // Brokered tools are gated (and executed) server-side at /tools/call —
    // waving them through here decides each call exactly once, on the control
    // plane. A runner that "forgot" this callback changes nothing.
    const mcpServer = mcpServerOf(toolName);
    if (mcpServer && env.BROKERED.has(mcpServer)) {
      witness.sawDecision(toolCallId);
      return { behavior: "allow", updatedInput: input };
    }
    // NOTE: the runner no longer emits its own tool.requested — the SERVER
    // writes the canonical event exactly once per intent inside the gate
    // (Phase 6), so budget/audit parity never depends on runner cooperation.
    const verdict = await client.requestPermission(toolName, input, toolCallId);
    witness.sawDecision(toolCallId);
    if (verdict && verdict.decision === "allow") {
      return { behavior: "allow", updatedInput: verdict.updated_input || input };
    }
    return {
      behavior: "deny",
      message: (verdict && verdict.message) || "denied by fluidbox policy",
    };
  };

  // THE reason every tool call reaches canUseTool at all. Without this hook the
  // Claude Code CLI auto-approves whole classes of calls — its read-only and
  // safe-command classifications — and the callback above is simply never
  // invoked for them, so the run executes tools the control plane never saw.
  // Read the note above forceGateDecision() in the contract lib before changing
  // ANY of this, including the fact that the hook does no I/O.
  const preToolUseGate = async () => forceGateDecision();

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
        // NOT sufficient on its own: 'default' still lets the CLI auto-approve
        // calls it judges safe, without consulting canUseTool. The PreToolUse
        // hook below is what actually routes everything through our gateway.
        permissionMode: "default",
        // The mandatory leg of the gate. Fires for EVERY tool call, below the
        // CLI's auto-approval short-circuit, and answers `ask` so the call has
        // to come back through canUseTool for a control-plane decision.
        hooks: { PreToolUse: [{ hooks: [preToolUseGate] }] },
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
        for (const block of blocksOf(msg)) {
          if (block?.type === "tool_use") witness.sawToolUse(block.id, block.name);
        }
        const text = textFromMessage(msg);
        if (text.trim()) {
          await client.emit("agent", { type: "agent.message", data: { role: "assistant", text } });
        }
      } else if (msg.type === "user") {
        // A result for a call the gate never decided means a tool ran
        // ungoverned. Fail the run closed rather than let it finish with an
        // audit trail that silently omits the call.
        for (const block of blocksOf(msg)) {
          if (block?.type !== "tool_result") continue;
          const ungoverned = witness.ungovernedResult(block.tool_use_id);
          if (ungoverned) {
            await abortUngoverned(ungoverned, block.tool_use_id);
          }
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
      log.error("agent query failed", { error: e });
      await client.emit("harness", { type: "run.error", data: { message: String(e?.message || e) } });
    }
  } finally {
    client.stopHeartbeat();
    client.stopTokenRenew();
  }

  // Quiesced (cancelled): exit WITHOUT posting /result — the control plane's
  // cancel finalizer records the terminal outcome and collects the diff.
  if (quiesced) {
    log.info("quiesced on cancel — exiting without posting /result");
    process.exit(0);
  }

  try {
    await client.postResult(
      hadError ? "failed" : "completed",
      hadError ? String(hadError?.message || hadError) : finalText,
    );
  } catch (e) {
    log.error("posting the run result failed", { error: e.message });
    process.exit(1);
  }
  process.exit(hadError ? 1 : 0);
}

main().catch((e) => {
  log.error("fatal", { error: e });
  process.exit(1);
});
