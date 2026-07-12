// fluidbox sandbox gate-shim — PLACEHOLDER (completed in Phase 6 Step 7).
//
// A gating stdio MCP proxy for ONE sandbox-class capability server under the
// Codex harness (Claude gates sandbox servers through canUseTool and never
// spawns this). It will:
//   - serve the FROZEN tools/list snapshot itself (never the child's live list),
//   - spawn the real stdio subprocess with a scrubbed env,
//   - on every tools/call, preflight POST /permission and forward only on allow.
//
// Until Step 7 lands the full implementation, refuse to run so a
// mis-wired codex image fails loudly rather than ungoverned.
console.error("fluidbox-sandbox-gate-shim: not yet implemented (Phase 6 Step 7)");
process.exit(2);
