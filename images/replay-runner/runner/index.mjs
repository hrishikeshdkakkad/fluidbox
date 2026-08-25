// fluidbox replay runner — a deterministic, model-free harness.
//
// It replays a canned transcript of tool calls through the REAL runner
// contract: every tool step crosses /permission (the same gate a live agent
// crosses), allowed steps execute for real against /workspace, and the run
// ends with a real /result. There is no model and no LLM-facade traffic; the
// first timeline message says so, and nothing here may pretend otherwise.
//
// The harness seam is identical to the other two runners: shared contract
// client from runner-lib, audience-scoped tokens, heartbeats, quiesce.
import { pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
import { executeStep } from "./steps.mjs";

// Test seam: FLUIDBOX_RUNNER_LIB points at a checked-out runner-lib; the baked
// image uses the same path the sandbox runner bakes.
const LIB = process.env.FLUIDBOX_RUNNER_LIB || "/opt/fluidbox-runner/lib/contract.mjs";
const { loadRunnerEnv, RunnerClient, sleep } = await import(pathToFileURL(LIB));
// The logger lives beside the contract, so it is resolved the same way rather
// than by a second hard-coded path that could drift from it.
const { createLogger } = await import(pathToFileURL(LIB.replace(/contract\.mjs$/, "log.mjs")));
const log = createLogger({ target: "replay-runner" });

const env = loadRunnerEnv();
const client = new RunnerClient(env);

// Same posture as the sandbox runner: the control credential lives only in
// client memory; children spawned by Bash steps must never see it.
delete process.env.FLUIDBOX_SESSION_TOKEN;
delete process.env.FLUIDBOX_SESSION_TOKEN_FD;

const TRANSCRIPT_PATH = process.env.REPLAY_TRANSCRIPT || "/opt/fluidbox-replay/transcript.json";
const DELAY_MS = Number.parseInt(process.env.FLUIDBOX_REPLAY_DELAY_MS ?? "400", 10);

function loadTranscript(path) {
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error(`transcript at ${path} must be a non-empty array`);
  }
  for (const [i, step] of parsed.entries()) {
    const isSay = typeof step.say === "string";
    const isTool = typeof step.tool === "string" && step.input && typeof step.input === "object";
    if (isSay === isTool) {
      throw new Error(`transcript step ${i} must be exactly one of {say} or {tool,input}`);
    }
  }
  return parsed;
}

function narrateExecution(step, res) {
  if (step.tool === "Bash") {
    const body = (res.output || "").trim();
    const tail = res.ok ? "" : `\n→ exit ${res.exit_code ?? "?"}`;
    return `$ ${step.input.command}\n${body}${tail}`.trim();
  }
  return res.output || `${step.tool} done`;
}

async function main() {
  await client.emit("harness", {
    type: "agent.message",
    data: {
      role: "system",
      text:
        "deterministic replay runner starting — scripted transcript, no model calls " +
        `(autonomy=${env.AUTONOMY})`,
    },
  });
  client.startHeartbeat();
  client.startTokenRenew();
  // Cancellation: stop replaying and exit without /result — the control
  // plane's cancel finalizer owns the terminal outcome.
  client.onQuiesce(() => process.exit(0));

  const transcript = loadTranscript(TRANSCRIPT_PATH);
  let toolSeq = 0;
  let executed = 0;
  let denied = 0;
  let deployWithheld = false;

  for (const step of transcript) {
    if (typeof step.say === "string") {
      await client.emit("agent", {
        type: "agent.message",
        data: { role: "assistant", text: step.say },
      });
      await sleep(DELAY_MS);
      continue;
    }

    toolSeq += 1;
    const toolCallId = `rp_${String(toolSeq).padStart(3, "0")}`;
    const verdict = await client.requestPermission(step.tool, step.input, toolCallId);

    if (verdict?.decision === "allow") {
      executed += 1;
      const input = verdict.updated_input || step.input;
      const res = await executeStep({ ...step, input }, env.WORKSPACE);
      await client.emit("agent", {
        type: "agent.message",
        data: { role: "assistant", text: narrateExecution({ ...step, input }, res) },
      });
    } else {
      denied += 1;
      if ((step.input.command || "").includes("deploy")) deployWithheld = true;
      const text =
        step.on_deny_say || `${step.tool} denied: ${verdict?.message || "denied by policy"}`;
      await client.emit("agent", {
        type: "agent.message",
        data: { role: "assistant", text },
      });
    }
    await sleep(DELAY_MS);
  }

  const summary =
    `Replay complete: ${executed} executed, ${denied} denied.` +
    (deployWithheld ? " Deploy withheld — nothing was released." : "");
  await client.postResult("completed", summary);
  client.stopHeartbeat();
  client.stopTokenRenew();
  process.exit(0);
}

main().catch(async (e) => {
  log.error("fatal", { error: e });
  try {
    await client.emit("harness", {
      type: "run.error",
      data: { message: `replay runner failed: ${e?.message || e}` },
    });
    await client.postResult("failed", `replay runner failed: ${e?.message || e}`);
  } catch {}
  process.exit(1);
});
