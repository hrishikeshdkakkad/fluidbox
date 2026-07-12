#!/usr/bin/env bash
# Tier-0 supervisor protocol replay: the REAL codex supervisor (index.mjs, in a
# manually-launched codex container) drives a FAKE codex app-server (vendored
# NDJSON JSON-RPC) against the REAL control plane — no model, no real codex.
# Proves the supervisor CANONICALIZES + GATES exec/patch approvals correctly:
# argv unwrap, cwd containment, move-dest capture, env-amendment refusal,
# approve-once — every allow crossing the real /permission gate + ledger.
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
SB="${1:?scratch dir}"; mkdir -p "$SB/replay"
CIMG="${FLUIDBOX_CODEX_SANDBOX_IMAGE:-fluidbox-codex-runner:dev}"
rp=0; rf=0
rok(){ printf "    \033[1;32m✓\033[0m %s\n" "$1"; rp=$((rp+1)); }
rno(){ printf "    \033[1;31m✗\033[0m %s\n" "$1"; rf=$((rf+1)); }

# The FAKE codex app-server: on `app-server`, replay scripted approvals over
# NDJSON and record every {decision} reply the supervisor sends back.
cat > "$SB/replay/fake-codex" <<'FAKE'
#!/usr/bin/env node
if (process.argv[2] !== "app-server") { console.log("codex-cli 0.144.1"); process.exit(0); }
const fs = require("fs");
const OUT = process.env.FAKE_OUT || "/out/replies.jsonl";
let buf = "", nextId = 100;
const send = (o) => process.stdout.write(JSON.stringify(o) + "\n");
const pending = {}; // our-request id -> case label (for exec/patch approvals)
function record(label, decision) { fs.appendFileSync(OUT, JSON.stringify({ label, decision }) + "\n"); }
process.stdin.on("data", (d) => {
  buf += d; let i;
  while ((i = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 1); if (line.trim()) onMsg(JSON.parse(line)); }
});
function onMsg(m) {
  if (m.method === "initialize") return send({ id: m.id, result: { userAgent: "fake/0.144.1", codexHome: "/x", platformFamily: "unix", platformOs: "linux" } });
  if (m.method === "initialized") return;
  if (m.method === "thread/start") return send({ id: m.id, result: { thread: { id: "th_fake" }, instructionSources: [] } });
  if (m.method === "turn/start") { send({ id: m.id, result: { turn: { id: "tn_fake" } } }); return setTimeout(replay, 50); }
  if (m.method === "turn/interrupt") return send({ id: m.id, result: {} });
  // a RESULT to one of OUR approval requests → record the supervisor's decision
  if (m.id !== undefined && m.result && pending[m.id]) { record(pending[m.id], m.result.decision); delete pending[m.id]; step(); }
}
// scripted cases: [label, method, params]
const CASES = [
  ["cat", "item/commandExecution/requestApproval", { itemId: "i1", threadId: "th_fake", turnId: "tn_fake", command: "cat NOTE.txt", cwd: "/workspace" }],
  ["rm", "item/commandExecution/requestApproval", { itemId: "i2", threadId: "th_fake", turnId: "tn_fake", command: "rm -rf /", cwd: "/workspace" }],
  ["wrapped-git", "item/commandExecution/requestApproval", { itemId: "i3", threadId: "th_fake", turnId: "tn_fake", command: 'bash -lc "git status"', cwd: "/workspace" }],
  ["cwd-escape", "item/commandExecution/requestApproval", { itemId: "i4", threadId: "th_fake", turnId: "tn_fake", command: "cat secret", cwd: "/etc" }],
  ["env-amendment", "item/commandExecution/requestApproval", { itemId: "i5", threadId: "th_fake", turnId: "tn_fake", command: "cat NOTE.txt", cwd: "/workspace", proposedExecpolicyAmendment: [{ trust: "always" }] }],
];
let ci = 0;
function replay() {
  // patch case first needs an item/started (fileChange with a MOVE) so the
  // supervisor can canonicalize the changes it isn't given in the approval.
  send({ method: "item/started", params: { threadId: "th_fake", turnId: "tn_fake", item: { id: "p1", type: "fileChange", status: "in_progress", changes: [{ path: "src/a.js", kind: { type: "update", move_path: "/workspace/.env" }, diff: "..." }] } } });
  step();
}
function step() {
  if (ci === 0) { // fire the move-patch approval once, before the exec cases
    const id = nextId++; pending[id] = "patch-move"; send({ jsonrpc: "2.0", id, method: "item/fileChange/requestApproval", params: { itemId: "p1", threadId: "th_fake", turnId: "tn_fake" } }); ci = 1; return;
  }
  const k = ci - 1;
  if (k >= CASES.length) return finish();
  const [label, method, params] = CASES[k]; ci++;
  const id = nextId++; pending[id] = label; send({ jsonrpc: "2.0", id, method, params });
}
function finish() {
  send({ method: "item/completed", params: { threadId: "th_fake", turnId: "tn_fake", item: { id: "m1", type: "agentMessage", phase: "final_answer", text: "replay done" } } });
  send({ method: "turn/completed", params: { threadId: "th_fake", turnId: "tn_fake", turn: { status: "completed", items: [] } } });
}
FAKE
chmod +x "$SB/replay/fake-codex"
: > "$SB/replay/replies.jsonl"

# A codex session (for a real token + a ledger to assert against). Kill the
# orchestrator's real container; we run our OWN with the fake codex.
SID=$(curl -s -X POST -H "$H" -H 'content-type: application/json' \
  -d '{"agent":"codex-fixer","task":"replay","repo":{"kind":"none"},"autonomous":true}' "$API/v1/sessions" | j "['session']['id']")
for _ in $(seq 1 30); do C=$(docker ps --filter "label=fluidbox.session=$SID" --format '{{.ID}}' | head -1); [ -n "$C" ] && break; sleep 1; done
TOK=$(docker inspect "$C" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep '^FLUIDBOX_SESSION_TOKEN=' | cut -d= -f2-)
docker kill "$C" >/dev/null 2>&1
[ -n "$TOK" ] || { rno "no session token for replay"; exit 1; }

# Run the real supervisor in a manual container: fake codex shadows the real
# binary; the session env points at the control plane (host.docker.internal).
docker run --rm --add-host host.docker.internal:host-gateway \
  -v "$SB/replay/fake-codex:/opt/fluidbox-codex/node_modules/.bin/codex:ro" \
  -v "$SB/replay:/out" \
  -e FAKE_OUT=/out/replies.jsonl \
  -e FLUIDBOX_CONTROL_URL="$FLUIDBOX_PUBLIC_CONTROL_URL" \
  -e FLUIDBOX_SESSION_ID="$SID" -e FLUIDBOX_SESSION_TOKEN="$TOK" \
  -e FLUIDBOX_TASK="replay" -e FLUIDBOX_AUTONOMY=autonomous \
  -e FLUIDBOX_MODEL=gpt-5.4-mini -e FLUIDBOX_WORKSPACE=/workspace \
  "$CIMG" >/dev/null 2>&1 || true

R="$SB/replay/replies.jsonl"
dec(){ grep "\"label\":\"$1\"" "$R" | head -1 | python3 -c "import sys,json;print(json.load(sys.stdin)['decision'])" 2>/dev/null; }
[ "$(dec cat)" = "accept" ] && rok "benign 'cat NOTE.txt' → accept (autonomous read)" || rno "cat decision: $(dec cat)"
[ "$(dec rm)" = "decline" ] && rok "'rm -rf /' → decline (policy)" || rno "rm decision: $(dec rm)"
[ "$(dec wrapped-git)" = "accept" ] && rok "wrapped 'bash -lc \"git status\"' → accept (argv unwrap)" || rno "wrapped-git decision: $(dec wrapped-git)"
[ "$(dec cwd-escape)" = "decline" ] && rok "cwd=/etc → decline (workspace containment)" || rno "cwd-escape decision: $(dec cwd-escape)"
[ "$(dec env-amendment)" = "decline" ] && rok "proposed execpolicy amendment → decline (no gate)" || rno "env-amendment decision: $(dec env-amendment)"

# the move destination reached the gate (canonical MultiEdit ledgered with .env)
EV=$(curl -s -H "$H" "$API/v1/sessions/$SID/events?limit=500")
echo "$EV" | python3 -c "
import sys,json; evs=json.load(sys.stdin)['events']
req=[e['payload']['data'] for e in evs if e['type']=='tool.requested']
bash=[r for r in req if r.get('tool')=='Bash']
me=[r for r in req if r.get('tool')=='MultiEdit']
# canonical Bash names present; the move-dest .env visible in a MultiEdit summary
print('BASH' if bash else 'NOBASH')
print('MOVEDEST' if any('.env' in (r.get('summary') or '') for r in me) else 'NOMOVEDEST')
" | { read a; read b; [ "$a" = "BASH" ] && rok "canonical Bash tool.requested ledgered" || rno "no canonical Bash in ledger"; [ "$b" = "MOVEDEST" ] && rok "move destination (/workspace/.env) reached the gate" || rno "move dest not in ledger"; }

printf "  replay: \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$rp" "$rf"
exit $(( rf > 0 ? 1 : 0 ))
