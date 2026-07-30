// Tests for the mandatory tool gate (the canUseTool bypass, closed).
//
// The property under test is NOT "the runner asks for permission" — it did
// that before and the bypass happened anyway. It is:
//
//   1. the harness hands the SDK a PreToolUse hook that forces EVERY tool call
//      onto the gate, and that hook is pure (no I/O, so it cannot time out,
//      throw, or lose a decision while a supervised approval blocks); and
//   2. a tool that produces a result without a decision is detected and fails
//      the run closed, instead of finishing with an audit trail that omits it.
//
// (1) is asserted structurally against the shipped runner source, because that
// is where the regression would reappear: the gap was never a wrong decision,
// it was a callback that was simply never invoked, which no assertion about
// decision logic can catch.
//
// Zero dependencies, node's built-in runner. From the repo root:
//     node --test images/runner-lib/

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  forceGateDecision,
  GATE_ASK_REASON,
  GateWitness,
  EXIT_UNGOVERNED_TOOL,
  ungovernedToolDiagnostic,
} from "./contract.mjs";

const LIB_DIR = fileURLToPath(new URL(".", import.meta.url)).replace(/\/$/, "");
const CLAUDE_RUNNER = path.join(LIB_DIR, "..", "sandbox-runner", "runner", "index.mjs");

// ─── The hook itself ───────────────────────────────────────────────────────

test("forceGateDecision answers 'ask', which is what defeats the CLI auto-approval", () => {
  const out = forceGateDecision();
  assert.equal(out.hookSpecificOutput.hookEventName, "PreToolUse");
  // 'ask' specifically: 'allow' would short-circuit canUseTool (the gate would
  // never run) and 'deny' would refuse every call outright. Only 'ask' routes
  // the call to the permission callback for a control-plane decision.
  assert.equal(out.hookSpecificOutput.permissionDecision, "ask");
  assert.equal(out.hookSpecificOutput.permissionDecisionReason, GATE_ASK_REASON);
});

test("forceGateDecision is synchronous and I/O-free, so a blocking approval cannot break it", () => {
  // A hook that awaited the gate would put a multi-minute approval wait inside
  // a callback with its own timeout semantics. This one returns a literal.
  const out = forceGateDecision();
  assert.equal(typeof out.then, "undefined", "hook result must not be a promise");
  assert.deepEqual(forceGateDecision(), out, "must be pure — same input, same output");
});

// ─── The tripwire ──────────────────────────────────────────────────────────

test("a decided call is governed", () => {
  const w = new GateWitness();
  w.sawToolUse("toolu_1", "Bash");
  w.sawDecision("toolu_1");
  assert.equal(w.ungovernedResult("toolu_1"), null);
});

test("an emitted-but-undecided call is reported with its tool name", () => {
  const w = new GateWitness();
  w.sawToolUse("toolu_2", "Bash");
  // No sawDecision: this is exactly the observed bypass — the CLI ran the tool
  // and the gate was never consulted.
  assert.equal(w.ungovernedResult("toolu_2"), "Bash");
});

test("a brokered wave-through counts as a decision", () => {
  // Brokered tools are decided AND executed server-side at /tools/call; the
  // runner's wave-through is that decision arriving locally, not a bypass.
  const w = new GateWitness();
  w.sawToolUse("toolu_3", "mcp__linear__create_issue");
  w.sawDecision("toolu_3");
  assert.equal(w.ungovernedResult("toolu_3"), null);
});

test("a result for a call we never watched is ignored, not failed", () => {
  // Deliberately conservative: only calls observed on the message stream can
  // trip the wire, so an unfamiliar message shape cannot kill a healthy run.
  const w = new GateWitness();
  assert.equal(w.ungovernedResult("toolu_unseen"), null);
});

test("malformed tool_call_ids never trip the wire", () => {
  const w = new GateWitness();
  for (const id of [undefined, null, "", 0, {}, []]) {
    assert.equal(w.ungovernedResult(id), null, `id ${JSON.stringify(id)} must not trip`);
    w.sawToolUse(id, "Bash");
    w.sawDecision(id);
  }
  assert.equal(w.emittedTools.size, 0);
  assert.equal(w.decidedCalls.size, 0);
});

test("the ungoverned diagnostic names the tool, the call, and the consequence", () => {
  const d = ungovernedToolDiagnostic("Bash", "toolu_9");
  assert.match(d, /Bash/);
  assert.match(d, /toolu_9/);
  assert.match(d, /NEVER received a fluidbox decision/);
  assert.notEqual(EXIT_UNGOVERNED_TOOL, 0, "an ungoverned tool must never exit success");
});

// ─── The wiring, asserted against the shipped runner source ────────────────
//
// A unit test cannot prove the SDK invokes our hook — only a live run does
// (scripts/e2e-tool-gate.sh). What it CAN prove is that the harness still
// passes one, which is the half that silently regressed before: `canUseTool`
// was wired correctly the whole time and the gate still never ran.

test("the Claude runner passes a PreToolUse hook to query()", () => {
  const src = fs.readFileSync(CLAUDE_RUNNER, "utf8");
  assert.match(
    src,
    /hooks:\s*\{\s*PreToolUse:\s*\[\s*\{\s*hooks:\s*\[\s*preToolUseGate\s*\]/,
    "query() must receive the PreToolUse gate hook — without it the CLI " +
      "auto-approves whole tool classes and canUseTool is never invoked",
  );
});

// The two tests below close a hole found by mutation testing during the
// 2026-07-29 integration review: the suite caught "hook deleted" but passed
// 12/12 on two mutations that fully restore the bypass, because nothing
// asserted what the WIRED hook returns or that it is unscoped.

test("the wired PreToolUse hook delegates to forceGateDecision, so it answers `ask`", () => {
  const src = fs.readFileSync(CLAUDE_RUNNER, "utf8");
  // Mutation this catches: `const preToolUseGate = async () => ({})`. The
  // `hooks:` wiring above stays intact, so the wiring test cannot see it — but
  // a hook that returns {} lets the CLI execute the call with no decision
  // (measured: hook fires, canUseTool does not, command runs).
  assert.match(
    src,
    /const\s+preToolUseGate\s*=\s*async\s*\([^)]*\)\s*=>\s*forceGateDecision\(\)\s*;/,
    "preToolUseGate must delegate to forceGateDecision() — any other return " +
      "value (including {} or a hardcoded allow) un-governs the call",
  );
});

test("the PreToolUse hook carries no matcher, so it fires for every tool", () => {
  const src = fs.readFileSync(CLAUDE_RUNNER, "utf8");
  // Mutation this catches: `[{ hooks: [preToolUseGate], matcher: "Write" }]`.
  // A matcher scopes the hook to a subset; every tool outside that subset goes
  // straight back to being auto-approved with the gate never consulted.
  assert.doesNotMatch(
    src,
    /matcher/,
    "a PreToolUse matcher scopes the gate to a subset of tools — the hook " +
      "must stay unscoped for the gate to be mandatory",
  );
});

test("the Claude runner never asks for a permission mode that skips the callback", () => {
  const src = fs.readFileSync(CLAUDE_RUNNER, "utf8");
  // bypassPermissions auto-approves before the callback; acceptEdits does the
  // same for the entire edit class. Either silently un-governs the run.
  assert.doesNotMatch(src, /permissionMode:\s*["']bypassPermissions["']/);
  assert.doesNotMatch(src, /permissionMode:\s*["']acceptEdits["']/);
  assert.doesNotMatch(src, /allowDangerouslySkipPermissions/);
});

test("the Claude runner passes no allowedTools, which would auto-approve before the gate", () => {
  const src = fs.readFileSync(CLAUDE_RUNNER, "utf8");
  // The SDK warns about this one by name: "Bare allowedTools entries
  // auto-approve the whole tool before the callback is consulted."
  assert.doesNotMatch(src, /^\s*allowedTools:/m);
});

test("the Claude runner reconciles tool results against decisions", () => {
  const src = fs.readFileSync(CLAUDE_RUNNER, "utf8");
  assert.match(src, /witness\.sawToolUse\(/, "must watch emitted tool_use blocks");
  assert.match(src, /witness\.sawDecision\(/, "must record gate decisions");
  assert.match(src, /witness\.ungovernedResult\(/, "must check results against decisions");
  assert.match(src, /abortUngoverned\(/, "must abort on an ungoverned execution");
});
