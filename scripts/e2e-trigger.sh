#!/usr/bin/env bash
# Phase 2 acceptance — generic API borrowing + signed result callbacks
# (design doc §12 Phase 2):
#   • scoped trigger tokens: can invoke, can poll own runs, CANNOT touch the
#     admin API; admin token cannot invoke
#   • §17 #6: task/workspace overrides opt-in per subscription (default off)
#   • task templates render invoke context; missing keys are 400s
#   • Idempotency-Key: retries return the same run; body drift → 422
#   • InvocationContext kind=api frozen into the session + RunSpec
#   • signed terminal callback (HMAC verified out-of-band with openssl);
#     the run stays terminal even when its callback destination is dead
#   • live: external service borrows claude-fixer and receives a signed
#     callback with status/summary/artifacts/cost (self-skips without key)
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker python3 curl git cargo openssl
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
CT="content-type: application/json"

if ! port_in_use; then
  cargo build -q -p fluidbox-server || exit 1
  trap 'stop_server' EXIT
  start_server || exit 1
fi

B=/tmp/fbx-trig-body.json
post() { curl -s -o "$B" -w "%{http_code}" -X POST -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }
tpost() { # token path body [extra-header]
  curl -s -o "$B" -w "%{http_code}" -X POST -H "authorization: Bearer $1" -H "$CT" \
    ${4:+-H "$4"} -d "$3" "$API/v1$2"
}
sfield() { curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']$2"; }
wait_terminal() {
  local deadline=$(( $(date +%s) + ${2:-240} )) st=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    st=$(sfield "$1" "['status']")
    case "$st" in completed|failed|cancelled|budget_exceeded) echo "$st"; return 0 ;; esac
    sleep 3
  done
  echo "timeout(last=$st)"; return 1
}

say "RECEIVER — the 'external service' capturing signed callbacks"
RCV_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fbx-trig-rcv.XXXXXX")
RCV_PORT=8899
python3 - "$RCV_PORT" "$RCV_DIR" <<'PYEOF' &
import http.server, json, sys, pathlib
port, out = int(sys.argv[1]), pathlib.Path(sys.argv[2])
n = 0
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global n
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        n += 1
        (out / f"delivery-{n}.json").write_text(json.dumps({
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode()}))
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
PYEOF
RCV_PID=$!
trap 'kill $RCV_PID 2>/dev/null; stop_server' EXIT
sleep 0.5
ok "callback receiver on :$RCV_PORT"

say "FIXTURE — git repo for workspace-narrowing + callback runs"
FX=$(mktemp -d "${TMPDIR:-/tmp}/fbx-trig-fx.XXXXXX")
git -C "$FX" init -q -b main
git -C "$FX" config user.email e2e@fluidbox.dev
git -C "$FX" config user.name fbx-e2e
echo "v1" > "$FX/f.txt"; git -C "$FX" add -A; git -C "$FX" commit -qm c1
SHA1=$(git -C "$FX" rev-parse HEAD)
git -C "$FX" branch feature
echo "v2" > "$FX/f.txt"; git -C "$FX" add -A; git -C "$FX" commit -qm c2
URL="file://$FX"
ok "fixture ready (feature=$(echo "$SHA1" | cut -c1-8))"

say "SUBSCRIPTIONS — template-only (SUB1), overrides-on (SUB2), dead callback (SUB3)"
AGENT="trig-agent-$$"
post "/agents" "{\"name\":\"$AGENT\",\"policy\":\"default\"}" >/dev/null
AGENT_GIT="trig-agent-git-$$"
post "/agents" "{\"name\":\"$AGENT_GIT\",\"policy\":\"default\",
  \"default_workspace\":{\"kind\":\"git_repository\",\"clone_url\":\"$URL\",\"ref\":\"main\"}}" >/dev/null

# autonomous: a live model may reach for approval-gated tools (git/file
# writes) on any of these tasks; supervised would hang the run at
# awaiting_approval with nobody to approve. Auto-deny keeps runs terminal —
# supervision itself is the governance phase's job.
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"sub1-$$\",
  \"task_template\":\"Investigate {{ticket}} and report.\",\"autonomous\":true,
  \"callback_url\":\"http://127.0.0.1:$RCV_PORT/cb\"}")
SUB1=$(cat "$B" | j "['subscription']['id']")
TOK1=$(cat "$B" | j "['token']")
SEC1=$(cat "$B" | j "['callback_secret']")
[ "$CODE" = "200" ] && [ -n "$SUB1" ] && ok "SUB1 created" || { no "SUB1 create → $CODE: $(cat "$B")"; exit 1; }
case "$TOK1" in fbx_trig_*) ok "token minted (shown once, fbx_trig_ prefix)";; *) no "bad token '$TOK1'";; esac
case "$SEC1" in fbx_whsec_*) ok "callback secret minted (fbx_whsec_ prefix)";; *) no "bad secret '$SEC1'";; esac
LEAKS=$(curl -s -H "$H" "$API/v1/triggers" | grep -c "fbx_whsec_\|fbx_trig_\|callback_secret_sealed" || true)
[ "${LEAKS:-1}" = "0" ] && ok "list endpoint never re-exposes token/secret" || no "secret material leaked in list"

CODE=$(post "/triggers" "{\"agent\":\"$AGENT_GIT\",\"name\":\"sub2-$$\",\"autonomous\":true,
  \"task_template\":\"noop\",\"allow_task_override\":true,\"allow_workspace_override\":true}")
SUB2=$(cat "$B" | j "['subscription']['id']"); TOK2=$(cat "$B" | j "['token']")
[ "$CODE" = "200" ] && ok "SUB2 (overrides on) created" || no "SUB2 create → $CODE"

CODE=$(post "/triggers" "{\"agent\":\"$AGENT_GIT\",\"name\":\"sub3-$$\",
  \"task_template\":\"noop\",\"allow_workspace_override\":true,\"autonomous\":true,
  \"callback_url\":\"http://127.0.0.1:9/dead\"}")
SUB3=$(cat "$B" | j "['subscription']['id']"); TOK3=$(cat "$B" | j "['token']")
[ "$CODE" = "200" ] && ok "SUB3 (dead callback) created" || no "SUB3 create → $CODE"

CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"sub-bad-$$\"}")
[ "$CODE" = "400" ] && ok "template-less + no override → 400 (dead config refused)" || no "wanted 400, got $CODE"

say "TOKEN SCOPE — a trigger token is not an admin token (and vice versa)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "authorization: Bearer $TOK1" "$API/v1/sessions")
[ "$CODE" = "401" ] && ok "trigger token → GET /v1/sessions 401" || no "wanted 401, got $CODE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "authorization: Bearer $TOK1" "$API/v1/agents")
[ "$CODE" = "401" ] && ok "trigger token → GET /v1/agents 401" || no "wanted 401, got $CODE"
CODE=$(tpost "$TOK1" "/sessions" "{\"agent\":\"$AGENT\",\"task\":\"x\"}")
[ "$CODE" = "401" ] && ok "trigger token → POST /v1/sessions 401" || no "wanted 401, got $CODE"
CODE=$(tpost "$FLUIDBOX_ADMIN_TOKEN" "/triggers/$SUB1/invoke" "{}")
[ "$CODE" = "401" ] && ok "admin token cannot invoke" || no "wanted 401, got $CODE"
CODE=$(tpost "fbx_trig_garbage" "/triggers/$SUB1/invoke" "{}")
[ "$CODE" = "401" ] && ok "garbage token → 401" || no "wanted 401, got $CODE"
CODE=$(tpost "$TOK2" "/triggers/$SUB1/invoke" "{}")
[ "$CODE" = "401" ] && ok "SUB2's token cannot invoke SUB1" || no "wanted 401, got $CODE"

say "INVOKE — template + context; InvocationContext frozen"
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"context":{"ticket":"INC-42"}}' "Idempotency-Key: key-A")
S1=$(cat "$B" | j "['session_id']")
[ "$CODE" = "200" ] && [ -n "$S1" ] && ok "invoke created run $S1" || { no "invoke → $CODE: $(cat "$B")"; exit 1; }
TASK1=$(sfield "$S1" "['task']")
[ "$TASK1" = "Investigate INC-42 and report." ] && ok "template rendered the context" || no "task wrong: '$TASK1'"
TKIND=$(sfield "$S1" "['trigger']['kind']")
[ "$TKIND" = "api" ] && ok "sessions.trigger kind=api" || no "trigger kind '$TKIND'"
RSKIND=$(sfield "$S1" "['run_spec']['invocation']['kind']")
[ "$RSKIND" = "api" ] && ok "RunSpec froze invocation kind=api" || no "run_spec invocation '$RSKIND'"
RSSUB=$(sfield "$S1" "['run_spec']['invocation']['subscription_id']")
[ "$RSSUB" = "$SUB1" ] && ok "RunSpec froze the subscription id" || no "frozen subscription '$RSSUB'"

CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"context":{"wrong":"x"}}')
[ "$CODE" = "400" ] && ok "missing template key → 400" || no "wanted 400, got $CODE"

say "§17 #6 — overrides are opt-in (SUB1 off, SUB2 on)"
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"task":"pwned","context":{"ticket":"x"}}')
[ "$CODE" = "400" ] && ok "task override w/o opt-in → 400" || no "wanted 400, got $CODE"
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"workspace":{"ref":"main"},"context":{"ticket":"x"}}')
[ "$CODE" = "400" ] && ok "workspace override w/o opt-in → 400" || no "wanted 400, got $CODE"

CODE=$(tpost "$TOK2" "/triggers/$SUB2/invoke" '{"task":"custom task from caller","workspace":{"ref":"feature"}}')
S2=$(cat "$B" | j "['session_id']")
[ "$CODE" = "200" ] && ok "SUB2 override invoke accepted" || no "SUB2 invoke → $CODE: $(cat "$B")"
[ "$(sfield "$S2" "['task']")" = "custom task from caller" ] && ok "caller task honored (opt-in)" || no "task not overridden"
[ "$(sfield "$S2" "['repo_source']['ref']")" = "feature" ] && ok "workspace narrowed to ref=feature" || no "ref not narrowed"
CODE=$(tpost "$TOK2" "/triggers/$SUB2/invoke" '{"workspace":{"repository":"a/b"}}')
[ "$CODE" = "400" ] && ok "repo retarget of a file:// base → 400 (cannot escape)" || no "wanted 400, got $CODE"

say "IDEMPOTENCY — retries create exactly one run"
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"context":{"ticket":"INC-42"}}' "Idempotency-Key: key-A")
S1B=$(cat "$B" | j "['session_id']"); REPLAY=$(cat "$B" | j "['replay']")
[ "$CODE" = "200" ] && [ "$S1B" = "$S1" ] && [ "$REPLAY" = "True" ] \
  && ok "same key → same run (replay=true)" || no "replay wrong: code=$CODE id=$S1B replay=$REPLAY"
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"context":{"ticket":"OTHER"}}' "Idempotency-Key: key-A")
[ "$CODE" = "422" ] && ok "key reuse with different body → 422" || no "wanted 422, got $CODE"
N_RUNS=$(curl -s -H "$H" "$API/v1/triggers/$SUB1" | python3 -c "
import sys, json; print(len(json.load(sys.stdin)['sessions']))")
[ "$N_RUNS" = "1" ] && ok "subscription has exactly one run" || no "expected 1 run, got $N_RUNS"

say "DISABLE / ENABLE / ROTATE"
post "/triggers/$SUB1/disable" "{}" >/dev/null
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"context":{"ticket":"x"}}')
[ "$CODE" = "409" ] && ok "disabled subscription → 409" || no "wanted 409, got $CODE"
post "/triggers/$SUB1/enable" "{}" >/dev/null
post "/triggers/$SUB1/rotate_token" "{}" >/dev/null
TOK1_NEW=$(cat "$B" | j "['token']")
CODE=$(tpost "$TOK1" "/triggers/$SUB1/invoke" '{"context":{"ticket":"INC-42"}}' "Idempotency-Key: key-A")
[ "$CODE" = "401" ] && ok "old token dead after rotation" || no "wanted 401, got $CODE"
CODE=$(tpost "$TOK1_NEW" "/triggers/$SUB1/invoke" '{"context":{"ticket":"INC-42"}}' "Idempotency-Key: key-A")
[ "$CODE" = "200" ] && ok "new token works (and key-A still replays)" || no "wanted 200, got $CODE"

say "SIGNED CALLBACK — terminal run → one verified delivery"
FINAL1=$(wait_terminal "$S1" 240) || true
case "$FINAL1" in completed|failed) ok "S1 terminal ($FINAL1)";; *) no "S1 not terminal: $FINAL1";; esac
DFILE=""
for _ in $(seq 1 30); do
  DFILE=$(ls "$RCV_DIR"/delivery-*.json 2>/dev/null | head -1)
  [ -n "$DFILE" ] && break
  sleep 2
done
[ -n "$DFILE" ] && ok "callback received by the external service" || no "no callback within 60s"
if [ -n "$DFILE" ]; then
  TS=$(python3 -c "import json;print(json.load(open('$DFILE'))['headers']['x-fluidbox-timestamp'])")
  SIG=$(python3 -c "import json;print(json.load(open('$DFILE'))['headers']['x-fluidbox-signature'])")
  BODY=$(python3 -c "import json;print(json.load(open('$DFILE'))['body'])")
  CALC="v1=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SEC1" | sed 's/^.* //')"
  [ "$CALC" = "$SIG" ] && ok "HMAC signature verifies with the shown-once secret" || no "signature mismatch"
  RUN_ID=$(python3 -c "import json;print(json.loads(json.load(open('$DFILE'))['body'])['run']['id'])")
  [ "$RUN_ID" = "$S1" ] && ok "payload carries the right run" || no "payload run '$RUN_ID'"
  PSTATUS=$(python3 -c "import json;print(json.loads(json.load(open('$DFILE'))['body'])['run']['status'])")
  [ "$PSTATUS" = "$FINAL1" ] && ok "payload status matches terminal state" || no "payload status '$PSTATUS'"
  python3 -c "
import json
p = json.loads(json.load(open('$DFILE'))['body'])
assert 'cost_usd' in p['usage'] and isinstance(p['artifacts'], list) and 'summary' in p['run']
" && ok "payload has status/summary/artifacts/cost" || no "payload missing acceptance fields"
  DSTAT=$(curl -s -H "$H" "$API/v1/sessions/$S1/deliveries" | j "['deliveries'][0]['status']")
  [ "$DSTAT" = "delivered" ] && ok "delivery row marked delivered" || no "delivery status '$DSTAT'"
fi

say "DEAD DESTINATION — the run stays terminal; only the delivery retries"
CODE=$(tpost "$TOK3" "/triggers/$SUB3/invoke" '{"workspace":{"ref":"feature"},"context":{}}')
S3=$(cat "$B" | j "['session_id']")
[ "$CODE" = "200" ] && ok "SUB3 invoke accepted" || no "SUB3 invoke → $CODE: $(cat "$B")"
FINAL3=$(wait_terminal "$S3" 240) || true
case "$FINAL3" in completed|failed) ok "S3 terminal ($FINAL3) despite dead callback";; *) no "S3 terminal: $FINAL3";; esac
D3A=""; D3S=""
for _ in $(seq 1 10); do
  D3=$(curl -s -H "$H" "$API/v1/sessions/$S3/deliveries")
  D3A=$(echo "$D3" | j "['deliveries'][0]['attempts']")
  D3S=$(echo "$D3" | j "['deliveries'][0]['status']")
  [ "${D3A:-0}" -ge 1 ] 2>/dev/null && break
  sleep 2
done
[ "${D3A:-0}" -ge 1 ] && [ "$D3S" != "delivered" ] && ok "dead destination: attempts=$D3A status=$D3S" \
  || no "delivery not retrying (attempts=$D3A status=$D3S)"
[ "$(sfield "$S3" "['status']")" = "$FINAL3" ] && ok "run status untouched by callback failure" || no "run status mutated!"

say "SCOPED POLLING"
CODE=$(curl -s -o "$B" -w "%{http_code}" -H "authorization: Bearer $TOK1_NEW" "$API/v1/triggers/$SUB1/runs/$S1")
[ "$CODE" = "200" ] && [ "$(cat "$B" | j "['run']['id']")" = "$S1" ] \
  && ok "trigger token polls its own run" || no "poll → $CODE"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "authorization: Bearer $TOK1_NEW" "$API/v1/triggers/$SUB1/runs/$S3")
[ "$CODE" = "404" ] && ok "cannot poll another subscription's run" || no "wanted 404, got $CODE"

say "LIVE — external service borrows claude-fixer, gets the full callback"
if [ "${E2E_SKIP_LIVE:-0}" = "1" ] || [ -z "${ANTHROPIC_API_KEY:-}" ] \
   || ! curl -fsS -m 3 http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1; then
  echo "  SKIP: live tier needs ANTHROPIC_API_KEY + gateway (E2E_SKIP_LIVE=${E2E_SKIP_LIVE:-0})"
else
  CODE=$(post "/triggers" "{\"agent\":\"claude-fixer\",\"name\":\"sub-live-$$\",
    \"task_template\":\"State the result of {{a}} plus {{b}}, then stop.\",\"autonomous\":true,
    \"callback_url\":\"http://127.0.0.1:$RCV_PORT/cb\"}")
  SUBL=$(cat "$B" | j "['subscription']['id']"); TOKL=$(cat "$B" | j "['token']"); SECL=$(cat "$B" | j "['callback_secret']")
  CODE=$(tpost "$TOKL" "/triggers/$SUBL/invoke" '{"context":{"a":"2","b":"3"}}' "Idempotency-Key: live-1")
  SL=$(cat "$B" | j "['session_id']")
  [ "$CODE" = "200" ] && ok "live borrow started ($SL)" || no "live invoke → $CODE"
  FINALL=$(wait_terminal "$SL" 420) || true
  [ "$FINALL" = "completed" ] && ok "live run completed" || no "live terminal: $FINALL"
  LFILE=""
  for _ in $(seq 1 30); do
    LFILE=$(grep -l "$SL" "$RCV_DIR"/delivery-*.json 2>/dev/null | head -1)
    [ -n "$LFILE" ] && break
    sleep 2
  done
  if [ -n "$LFILE" ]; then
    LTS=$(python3 -c "import json;print(json.load(open('$LFILE'))['headers']['x-fluidbox-timestamp'])")
    LSIG=$(python3 -c "import json;print(json.load(open('$LFILE'))['headers']['x-fluidbox-signature'])")
    LBODY=$(python3 -c "import json;print(json.load(open('$LFILE'))['body'])")
    LCALC="v1=$(printf '%s.%s' "$LTS" "$LBODY" | openssl dgst -sha256 -hmac "$SECL" | sed 's/^.* //')"
    [ "$LCALC" = "$LSIG" ] && ok "live callback signature verifies" || no "live signature mismatch"
    python3 -c "
import json
p = json.loads(json.load(open('$LFILE'))['body'])
assert p['run']['status'] == 'completed'
assert p['usage']['cost_usd'] > 0, 'live run must have real cost'
assert p['run']['summary'], 'live run must carry a summary'
" && ok "live callback: completed + real cost + summary" || no "live payload incomplete"
  else
    no "no live callback within 60s"
  fi
fi

rm -rf "$FX" "$RCV_DIR"

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
