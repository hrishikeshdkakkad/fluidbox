#!/usr/bin/env bash
# Tier-0 supervisor protocol replay: the REAL qwen supervisor (index.mjs, in a
# manually-launched qwen container) drives a FAKE qwen CLI (vendored
# stream-json control protocol) against the REAL control plane — no model, no
# real qwen binary. Proves the supervisor CANONICALIZES + GATES correctly:
# read_file→Read, run_shell_command→Bash (incl. the bash -lc unwrap and cwd
# containment), fail-closed supervisor denies (empty command, unmapped tool),
# sandbox MCP gated under its native name — every gated call crossing the
# real /permission gate + ledger. The fake was protocol-validated against the
# real @qwen-code/sdk (docs/research/2026-07-30-qwen-code-sdk-protocol.md).
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
SB="${1:?scratch dir}"; mkdir -p "$SB/replay"
QIMG="${FLUIDBOX_QWEN_SANDBOX_IMAGE:-fluidbox-qwen-runner:dev}"
rp=0; rf=0
rok(){ printf "    \033[1;32m✓\033[0m %s\n" "$1"; rp=$((rp+1)); }
rno(){ printf "    \033[1;31m✗\033[0m %s\n" "$1"; rf=$((rf+1)); }

# The FAKE qwen CLI: emits scripted can_use_tool control_requests over the
# stream-json channel and records every response the supervisor sends back.
# ESM (the shadowed package is "type":"module").
cat > "$SB/replay/fake-cli.js" <<'FAKE'
#!/usr/bin/env node
import fs from "node:fs";
const OUT = process.env.FAKE_OUT || "/out/replies.jsonl";
const send = (o) => process.stdout.write(JSON.stringify(o) + "\n");
const record = (label, r) => fs.appendFileSync(OUT, JSON.stringify({ label, ...r }) + "\n");
const SID = "fake-session-1";
let started = false, reqSeq = 0;
const pending = {};
const CASES = [
  ["read", "read_file", { file_path: "/workspace/NOTE.txt" }],
  ["cat", "run_shell_command", { command: "cat NOTE.txt", directory: "/workspace" }],
  ["rm", "run_shell_command", { command: "rm -rf /" }],
  ["wrapped-git", "run_shell_command", { command: 'bash -lc "git status"' }],
  ["cwd-escape", "run_shell_command", { command: "cat secret", directory: "/etc" }],
  ["empty-cmd", "run_shell_command", {}],
  ["unmapped", "save_memory", { fact: "x" }],
  ["mcp-unattached", "mcp__ws__read", { path: "x" }],
];
let ci = 0;
function step() {
  if (ci >= CASES.length) return finish();
  const [label, tool_name, input] = CASES[ci++];
  const request_id = `fake_req_${++reqSeq}`;
  pending[request_id] = label;
  send({ type: "control_request", request_id, request: {
    subtype: "can_use_tool", tool_name, tool_use_id: `tu_fake_${reqSeq}`,
    input, permission_suggestions: null, blocked_path: null } });
}
function finish() {
  send({ type: "assistant", uuid: "a1", session_id: SID, parent_tool_use_id: null,
    message: { id: "m1", type: "message", role: "assistant", model: "fake",
      content: [{ type: "text", text: "replay done" }],
      usage: { input_tokens: 1, output_tokens: 1 } } });
  send({ type: "result", subtype: "success", uuid: "r1", session_id: SID,
    is_error: false, duration_ms: 1, duration_api_ms: 1, num_turns: 1,
    result: "replay done", usage: { input_tokens: 1, output_tokens: 1 },
    permission_denials: [] });
  process.exit(0);
}
function onMsg(m) {
  if (m.type === "control_request") {
    send({ type: "control_response", response: { subtype: "success", request_id: m.request_id, response: {} } });
    return;
  }
  if (m.type === "control_response") {
    const rid = m.response?.request_id, label = pending[rid];
    if (!label) return;
    delete pending[rid];
    const r = m.response?.response || {};
    record(label, { behavior: r.behavior ?? null, message: r.message ?? null, updatedInput: r.updatedInput ?? null });
    step();
    return;
  }
  if (m.type === "user" && !started) {
    started = true;
    send({ type: "system", subtype: "init", uuid: "s1", session_id: SID,
      cwd: process.cwd(), model: "fake", permission_mode: "default", tools: [] });
    setTimeout(step, 20);
  }
}
let buf = "";
process.stdin.on("data", (d) => {
  buf += d; let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (line.trim()) { try { onMsg(JSON.parse(line)); } catch { /* non-JSON */ } }
  }
});
process.stdin.on("end", () => {});
FAKE
: > "$SB/replay/replies.jsonl"
chmod -R 0777 "$SB/replay"  # the runner uid (10001) writes replies to /out

# A qwen session (for real tokens + a ledger to assert against). Kill the
# orchestrator's real container; we run our OWN with the fake CLI shadowing
# the pinned package's entry (the supervisor resolves @qwen-code/qwen-code →
# cli.js and passes it as pathToQwenExecutable).
SID=$(curl -s -X POST -H "$H" -H 'content-type: application/json' \
  -d '{"agent":"qwen-fixer","task":"replay","repo":{"kind":"none"},"autonomous":true}' "$API/v1/sessions" | j "['session']['id']")
for _ in $(seq 1 100); do C=$(docker ps -a --filter "label=fluidbox.session=$SID" --format '{{.ID}}' | head -1); [ -n "$C" ] && break; sleep 0.15; done
sess_env() { docker inspect "$1" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep "^$2=" | cut -d= -f2-; }
TOK=$(sess_env "$C" FLUIDBOX_SESSION_TOKEN)
TOOLTOK=$(sess_env "$C" FLUIDBOX_TOOL_TOKEN)
LLMTOK=$(sess_env "$C" FLUIDBOX_LLM_TOKEN)
docker rm -f "$C" >/dev/null 2>&1
[ -n "$TOK" ] || { rno "no session token for replay"; exit 1; }
[ -n "$TOOLTOK" ] || { rno "no tool-audience token for replay"; exit 1; }

# Run the real supervisor in a manual container: the fake CLI shadows the
# pinned package's cli.js; the session env points at the control plane.
docker run --rm --add-host host.docker.internal:host-gateway \
  -v "$SB/replay/fake-cli.js:/opt/fluidbox-qwen/node_modules/@qwen-code/qwen-code/cli.js:ro" \
  -v "$SB/replay:/out" \
  -e FAKE_OUT=/out/replies.jsonl \
  -e FLUIDBOX_CONTROL_URL="$FLUIDBOX_PUBLIC_CONTROL_URL" \
  -e FLUIDBOX_SESSION_ID="$SID" -e FLUIDBOX_SESSION_TOKEN="$TOK" \
  -e FLUIDBOX_TOOL_TOKEN="$TOOLTOK" -e FLUIDBOX_LLM_TOKEN="$LLMTOK" \
  -e FLUIDBOX_TASK="replay" -e FLUIDBOX_AUTONOMY=autonomous \
  -e FLUIDBOX_MODEL=qwen3-coder-plus -e FLUIDBOX_WORKSPACE=/workspace \
  "$QIMG" >/dev/null 2>&1 || true

R="$SB/replay/replies.jsonl"
fld(){ grep "\"label\":\"$1\"" "$R" | head -1 | python3 -c "import sys,json;print(json.load(sys.stdin).get('$2'))" 2>/dev/null; }
[ "$(fld read behavior)" = "allow" ] && rok "read_file → allow (canonical Read crossed the gate)" || rno "read: $(fld read behavior)"
[ "$(fld cat behavior)" = "allow" ] && rok "'cat NOTE.txt' → allow (autonomous read)" || rno "cat: $(fld cat behavior)"
[ "$(fld rm behavior)" = "deny" ] && rok "'rm -rf /' → deny (policy)" || rno "rm: $(fld rm behavior)"
[ "$(fld wrapped-git behavior)" = "allow" ] && rok "wrapped 'bash -lc \"git status\"' → allow (unwrap)" || rno "wrapped-git: $(fld wrapped-git behavior)"
[ "$(fld cwd-escape behavior)" = "deny" ] && rok "directory=/etc → deny (workspace containment, supervisor-side)" || rno "cwd-escape: $(fld cwd-escape behavior)"
[ "$(fld empty-cmd behavior)" = "deny" ] && rok "empty command → deny (fail-closed, never a blind-approvable Bash{})" || rno "empty-cmd: $(fld empty-cmd behavior)"
[ "$(fld unmapped behavior)" = "deny" ] && rok "unmapped tool (save_memory) → deny (census-drift backstop)" || rno "unmapped: $(fld unmapped behavior)"
[ "$(fld mcp-unattached behavior)" = "deny" ] && rok "unattached mcp__ws__read → deny (capability, via the gate)" || rno "mcp-unattached: $(fld mcp-unattached behavior)"

# Ledger truth: canonical names only; the wrapped spelling UNWRAPPED (the gate
# saw `git status`, not `bash -lc …`); the supervisor-side denies never gated.
EV=$(curl -s -H "$H" "$API/v1/sessions/$SID/events?limit=500")
LEDGER=$(echo "$EV" | python3 -c "
import sys,json; evs=json.load(sys.stdin)['events']
req=[e['payload']['data'] for e in evs if e['type']=='tool.requested']
tools={r.get('tool') for r in req}
summaries=' '.join((r.get('summary') or '') for r in req)
flags=[]
if 'Read' in tools: flags.append('READ')
if 'Bash' in tools: flags.append('BASH')
if 'git status' in summaries and 'bash -lc' not in summaries: flags.append('UNWRAPPED')
if not any(t not in ('Read','Bash','mcp__ws__read') for t in tools): flags.append('CANON')
if 'cat secret' not in summaries: flags.append('NOESCAPE')
print(' '.join(flags))
")
echo "$LEDGER" | grep -q READ && rok "canonical Read tool.requested ledgered" || rno "no canonical Read in ledger"
echo "$LEDGER" | grep -q UNWRAPPED && rok "unwrapped 'git status' reached the gate (never 'bash -lc')" || rno "unwrap not in ledger"
echo "$LEDGER" | grep -q CANON && rok "ledger carries ONLY canonical/native-mcp names" || rno "non-canonical name in ledger"
echo "$LEDGER" | grep -q NOESCAPE && rok "cwd-escape never reached the gate (denied supervisor-side)" || rno "cwd-escape leaked to the gate"

printf "  replay: \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$rp" "$rf"
exit $(( rf > 0 ? 1 : 0 ))
