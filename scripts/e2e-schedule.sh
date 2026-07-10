#!/usr/bin/env bash
# Phase 3 acceptance — scheduled borrowing (design doc §12 Phase 3):
#   • a schedule is a trigger subscription with a clock; each firing is an
#     ordinary run with InvocationContext.kind=schedule via create_run
#   • config-time validation: cron / timezone / template / policies
#   • EXACTLY-ONCE: deterministic claim key (subscription + fire time) —
#     a restarted scheduler replays a stale fire time, never duplicates it
#   • overlap policies enforced for ALL invocations (§17 #5): schedule
#     skip_if_running + replace, API-invoke skip (409) + default allow
#   • missed-run policies: skip records ONE visible skip; catch_up fires
#     exactly ONE make-up run (never fire-all-missed)
#   • terminal schedule-fired runs publish signed callbacks (Phase 2 reused)
#   • live: a repository-maintenance agent on a sub-minute schedule
#     completes, overlapping firings skip visibly (self-skips without key)
# Owns the stack (restarts the server mid-phase). Time travel via psql.
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker psql python3 curl git cargo openssl
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
CT="content-type: application/json"

if port_in_use; then
  echo "port 8787 already serving — this phase owns the stack; stop 'just dev' first"
  exit 1
fi
cargo build -q -p fluidbox-server || exit 1
trap 'stop_server' EXIT
start_server || exit 1

B=/tmp/fbx-sched-body.json
post()   { curl -s -o "$B" -w "%{http_code}" -X POST -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }
tpost()  { curl -s -o "$B" -w "%{http_code}" -X POST -H "authorization: Bearer $1" -H "$CT" ${4:+-H "$4"} -d "$3" "$API/v1$2"; }
sfield() { curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']$2"; }
tget()   { curl -s -H "$H" "$API/v1/triggers/$1"; }
pq()     { psql "$DATABASE_URL" -qtA -c "$1" | head -1; }

# Poll GET /v1/triggers/{id} until a python expression over it is truthy.
wait_trig() { # sub-id python-expr [tries=20] [sleep=1]
  local sub=$1 expr=$2 tries=${3:-20} pause=${4:-1}
  for _ in $(seq 1 "$tries"); do
    if tget "$sub" | python3 -c "
import sys, json
d = json.load(sys.stdin)
sys.exit(0 if ($expr) else 1)" 2>/dev/null; then return 0; fi
    sleep "$pause"
  done
  return 1
}
run_count()  { tget "$1" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['sessions']))"; }
skip_count() { # sub-id reason-prefix
  tget "$1" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(sum(1 for i in d['invocations'] if (i.get('skip_reason') or '').startswith('$2')))"
}
wait_terminal() {
  local deadline=$(( $(date +%s) + ${2:-120} )) st=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    st=$(sfield "$1" "['status']")
    case "$st" in completed|failed|cancelled|budget_exceeded) echo "$st"; return 0 ;; esac
    sleep 3
  done
  echo "timeout(last=$st)"; return 1
}
rewind() { # sub-id timestamp-sql (e.g. "now()" or "now() - interval '10 minutes'")
  pq "update schedules set next_fire_at = $2 where subscription_id = '$1' returning id" >/dev/null
}
# Fake an in-flight run (test seam for overlap policies). started_at is
# nulled and the heartbeat freshened so the budget sweeper / watchdog can't
# re-terminate it mid-assertion.
fake_running() { pq "update sessions set status = 'running', started_at = null, last_heartbeat_at = now() where id = '$1' returning id" >/dev/null; }
set_status()   { pq "update sessions set status = '$2' where id = '$1' returning id" >/dev/null; }

say "RECEIVER — captures signed callbacks from schedule-fired runs"
RCV_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fbx-sched-rcv.XXXXXX")
RCV_PORT=8898
python3 - "$RCV_PORT" "$RCV_DIR" <<'PYEOF' &
import http.server, json, sys, pathlib
port, out = int(sys.argv[1]), pathlib.Path(sys.argv[2])
n = 0
class Hh(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global n
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        n += 1
        (out / f"delivery-{n}.json").write_text(json.dumps({
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode()}))
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), Hh).serve_forever()
PYEOF
RCV_PID=$!
trap 'kill $RCV_PID 2>/dev/null; stop_server' EXIT
sleep 0.5
ok "callback receiver on :$RCV_PORT"

AGENT="sched-agent-$$"
post "/agents" "{\"name\":\"$AGENT\",\"policy\":\"default\"}" >/dev/null
# Every no-model subscription tightens max_wall_clock_secs to 1: the budget
# sweeper (10s tick) forces terminal within ~15s — cheap and deterministic
# even when a live model key is present.
TB='{"max_wall_clock_secs": 1}'

say "VALIDATION — bad schedule config is refused at create time"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"v1-$$\",\"task_template\":\"t\",\"schedule\":{\"cron\":\"not a cron\"}}")
[ "$CODE" = "400" ] && ok "bad cron → 400" || no "wanted 400, got $CODE"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"v2-$$\",\"task_template\":\"t\",\"schedule\":{\"cron\":\"*/5 * * * * *\",\"timezone\":\"Mars/Olympus\"}}")
[ "$CODE" = "400" ] && ok "bad timezone → 400" || no "wanted 400, got $CODE"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"v3-$$\",\"allow_task_override\":true,\"schedule\":{\"cron\":\"*/5 * * * * *\"}}")
[ "$CODE" = "400" ] && ok "schedule without template → 400 (no caller to supply a task)" || no "wanted 400, got $CODE"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"v4-$$\",\"task_template\":\"do {{ticket}}\",\"schedule\":{\"cron\":\"*/5 * * * * *\"}}")
[ "$CODE" = "400" ] && ok "template with caller keys on a schedule → 400" || no "wanted 400, got $CODE"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"v5-$$\",\"task_template\":\"t\",\"schedule\":{\"cron\":\"*/5 * * * * *\",\"missed_run_policy\":\"fire_all_missed\"}}")
[ "$CODE" = "400" ] && ok "unknown missed_run_policy → 400 (fire-all-missed is not a thing)" || no "wanted 400, got $CODE"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"v6-$$\",\"task_template\":\"t\",\"concurrency_policy\":\"sometimes\"}")
[ "$CODE" = "400" ] && ok "unknown concurrency_policy → 400" || no "wanted 400, got $CODE"

say "SUB A — every-5s schedule fires ordinary runs (kind=schedule, signed callback)"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"schedA-$$\",
  \"task_template\":\"Maintenance sweep at {{fire_time}}.\",\"budgets\":$TB,
  \"concurrency_policy\":\"skip_if_running\",
  \"schedule\":{\"cron\":\"*/5 * * * * *\",\"timezone\":\"UTC\"},
  \"callback_url\":\"http://127.0.0.1:$RCV_PORT/cb\"}")
SUBA=$(cat "$B" | j "['subscription']['id']"); SECA=$(cat "$B" | j "['callback_secret']")
[ "$CODE" = "200" ] && [ -n "$SUBA" ] && ok "SUB A created" || { no "SUB A create → $CODE: $(cat "$B")"; exit 1; }
[ "$(cat "$B" | j "['subscription']['trigger_kind']")" = "schedule" ] && ok "trigger_kind=schedule" || no "wrong trigger_kind"
[ -n "$(cat "$B" | j "['schedule']['next_fire_at']")" ] && ok "next_fire_at computed at create" || no "no next_fire_at"
LEAKS=$(curl -s -H "$H" "$API/v1/triggers" | grep -c "fbx_whsec_\|fbx_trig_\|callback_secret_sealed" || true)
[ "${LEAKS:-1}" = "0" ] && ok "list (with schedules) still never re-exposes secrets" || no "secret material leaked in list"
wait_trig "$SUBA" "len(d['sessions']) >= 1" 20 1 && ok "schedule fired within 20s" || no "no firing within 20s"
SA=$(tget "$SUBA" | j "['sessions'][-1]['id']")
[ "$(sfield "$SA" "['trigger']['kind']")" = "schedule" ] && ok "sessions.trigger kind=schedule" || no "trigger kind wrong: $(sfield "$SA" "['trigger']['kind']")"
[ "$(sfield "$SA" "['run_spec']['invocation']['kind']")" = "schedule" ] && ok "RunSpec froze invocation kind=schedule" || no "run_spec kind wrong"
[ "$(sfield "$SA" "['run_spec']['invocation']['subscription_id']")" = "$SUBA" ] && ok "RunSpec froze the subscription id" || no "sub id wrong"
FT=$(sfield "$SA" "['run_spec']['invocation']['attributes']['fire_time']")
[ -n "$FT" ] && ok "fire_time frozen into the invocation ($FT)" || no "no fire_time attribute"
case "$(sfield "$SA" "['task']")" in "Maintenance sweep at 20"*) ok "task rendered {{fire_time}}";; *) no "task not rendered: $(sfield "$SA" "['task']")";; esac
wait_trig "$SUBA" "d['schedule']['last_fired_at'] is not None" 10 1 \
  && ok "last_fired_at recorded" || no "last_fired_at not set"

say "SUB A — disable stops the clock (the schedule does not advance)"
post "/triggers/$SUBA/disable" "{}" >/dev/null
sleep 2   # let an in-flight tick settle
INV_A=$(tget "$SUBA" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['invocations']))")
sleep 7
INV_A2=$(tget "$SUBA" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['invocations']))")
[ "$INV_A" = "$INV_A2" ] && ok "no invocations while disabled ($INV_A)" || no "fired while disabled ($INV_A → $INV_A2)"

say "EXACTLY-ONCE — a restarted scheduler replays a stale fire time, never re-fires it"
KEY=$(tget "$SUBA" | python3 -c "
import sys, json
d = json.load(sys.stdin)
b = [i for i in d['invocations'] if i['session_id']]
print(b[-1]['idempotency_key'])")   # oldest bound firing
T="${KEY#sched:}"
DUP_BEFORE=$(pq "select count(*) from trigger_invocations where idempotency_key = '$KEY'")
stop_server
pq "update schedules set next_fire_at = '$T' where subscription_id = '$SUBA' returning id" >/dev/null
pq "update trigger_subscriptions set enabled = true where id = '$SUBA' returning id" >/dev/null
start_server || exit 1
sleep 5
DUP_AFTER=$(pq "select count(*) from trigger_invocations where idempotency_key = '$KEY'")
[ "$DUP_BEFORE" = "1" ] && [ "$DUP_AFTER" = "1" ] && ok "fire time $T claimed exactly once across restart" || no "claims: before=$DUP_BEFORE after=$DUP_AFTER"
BOUND=$(pq "select count(distinct session_id) from trigger_invocations where idempotency_key = '$KEY' and session_id is not null")
[ "$BOUND" = "1" ] && ok "…and bound to exactly one run" || no "bound to $BOUND runs"
# Race-free advance check: while a 5s cadence is live, next_fire_at is
# briefly ≤ now() between a boundary passing and the tick handling it — the
# invariant is that the clock moved PAST the replayed fire time.
NEXT_PAST_T=$(pq "select (next_fire_at > '$T'::timestamptz) from schedules where subscription_id = '$SUBA'")
[ "$NEXT_PAST_T" = "t" ] && ok "replayed fire time advanced the clock" || no "next_fire_at still at/behind $T"
post "/triggers/$SUBA/disable" "{}" >/dev/null

say "OVERLAP skip_if_running — SUB B (daily cron; fired on demand via time travel)"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"schedB-$$\",
  \"task_template\":\"sweep {{fire_time}}\",\"budgets\":$TB,
  \"concurrency_policy\":\"skip_if_running\",
  \"schedule\":{\"cron\":\"0 0 3 * * *\",\"timezone\":\"UTC\"}}")
SUBB=$(cat "$B" | j "['subscription']['id']")
[ "$CODE" = "200" ] && ok "SUB B created" || no "SUB B → $CODE: $(cat "$B")"
rewind "$SUBB" "now()"
wait_trig "$SUBB" "len(d['sessions']) >= 1" 15 1 && ok "manual-fire seam works (1 run)" || no "SUB B did not fire"
SB1=$(tget "$SUBB" | j "['sessions'][-1]['id']")
FINAL_B=$(wait_terminal "$SB1" 90) || true
case "$FINAL_B" in completed|failed|budget_exceeded) ok "SUB B run terminal ($FINAL_B)";; *) no "SUB B run: $FINAL_B";; esac
fake_running "$SB1"
rewind "$SUBB" "now()"
wait_trig "$SUBB" "any((i.get('skip_reason') or '') == 'overlap' for i in d['invocations'])" 15 1 \
  && ok "overlapping firing skipped (recorded, reason=overlap)" || no "no overlap skip recorded"
[ "$(run_count "$SUBB")" = "1" ] && ok "no second run created" || no "run count: $(run_count "$SUBB")"
set_status "$SB1" "$FINAL_B"

say "OVERLAP replace — SUB C: the clock cancels the stale run and starts fresh"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"schedC-$$\",
  \"task_template\":\"sweep {{fire_time}}\",\"budgets\":$TB,
  \"concurrency_policy\":\"replace\",
  \"schedule\":{\"cron\":\"0 0 3 * * *\",\"timezone\":\"UTC\"}}")
SUBC=$(cat "$B" | j "['subscription']['id']")
[ "$CODE" = "200" ] && ok "SUB C created" || no "SUB C → $CODE: $(cat "$B")"
rewind "$SUBC" "now()"
wait_trig "$SUBC" "len(d['sessions']) >= 1" 15 1 || no "SUB C did not fire"
SC1=$(tget "$SUBC" | j "['sessions'][-1]['id']")
FINAL_C=$(wait_terminal "$SC1" 90) || true
fake_running "$SC1"
rewind "$SUBC" "now()"
wait_trig "$SUBC" "len(d['sessions']) >= 2" 15 1 && ok "replace fired a new run" || no "no replacement run"
[ "$(sfield "$SC1" "['status']")" = "cancelled" ] && ok "stale run cancelled" || no "stale run status: $(sfield "$SC1" "['status']")"
sfield "$SC1" "['status_reason']" | grep -q "replaced" && ok "cancel reason names the replacement" || no "reason: $(sfield "$SC1" "['status_reason']")"

say "MISSED skip — SUB D: a 10-minute gap records ONE skip and resumes the cadence"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"schedD-$$\",
  \"task_template\":\"sweep {{fire_time}}\",\"budgets\":$TB,
  \"schedule\":{\"cron\":\"0 0 3 * * *\",\"timezone\":\"UTC\",\"missed_run_policy\":\"skip\"}}")
SUBD=$(cat "$B" | j "['subscription']['id']")
rewind "$SUBD" "now() - interval '10 minutes'"
wait_trig "$SUBD" "any((i.get('skip_reason') or '') == 'missed' for i in d['invocations'])" 15 1 \
  && ok "missed firing recorded as skipped (reason=missed)" || no "no missed skip"
[ "$(run_count "$SUBD")" = "0" ] && ok "no run created for the missed slot" || no "runs: $(run_count "$SUBD")"
[ "$(skip_count "$SUBD" missed)" = "1" ] && ok "exactly ONE skip row for the whole gap" || no "skips: $(skip_count "$SUBD" missed)"
[ "$(pq "select (next_fire_at > now()) from schedules where subscription_id = '$SUBD'")" = "t" ] \
  && ok "clock resumed at the next future firing" || no "clock not advanced"

say "MISSED catch_up — SUB E: a 10-minute gap fires exactly ONE make-up run"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"schedE-$$\",
  \"task_template\":\"sweep {{fire_time}}\",\"budgets\":$TB,
  \"schedule\":{\"cron\":\"0 0 3 * * *\",\"timezone\":\"UTC\",\"missed_run_policy\":\"catch_up\"}}")
SUBE=$(cat "$B" | j "['subscription']['id']")
rewind "$SUBE" "now() - interval '10 minutes'"
wait_trig "$SUBE" "len(d['sessions']) >= 1" 15 1 && ok "catch-up run fired" || no "no catch-up run"
sleep 4   # give a would-be second catch-up time to (wrongly) appear
[ "$(run_count "$SUBE")" = "1" ] && ok "exactly ONE catch-up (never fire-all-missed)" || no "runs: $(run_count "$SUBE")"
SE1=$(tget "$SUBE" | j "['sessions'][-1]['id']")
[ "$(sfield "$SE1" "['run_spec']['invocation']['attributes']['catch_up']")" = "True" ] \
  && ok "run is marked catch_up=true in its frozen invocation" || no "catch_up attr: $(sfield "$SE1" "['run_spec']['invocation']['attributes']['catch_up']")"
[ "$(pq "select (next_fire_at > now()) from schedules where subscription_id = '$SUBE'")" = "t" ] \
  && ok "clock resumed after catch-up" || no "clock not advanced"

say "§17 #5 — concurrency_policy governs API invokes too (same create_run gate)"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"apiF-$$\",
  \"task_template\":\"api noop\",\"budgets\":$TB,\"concurrency_policy\":\"skip_if_running\"}")
SUBF=$(cat "$B" | j "['subscription']['id']"); TOKF=$(cat "$B" | j "['token']")
CODE=$(tpost "$TOKF" "/triggers/$SUBF/invoke" '{}' "Idempotency-Key: f1")
SF1=$(cat "$B" | j "['session_id']")
[ "$CODE" = "200" ] && ok "first invoke → run" || no "invoke → $CODE: $(cat "$B")"
FINAL_F=$(wait_terminal "$SF1" 90) || true
fake_running "$SF1"
CODE=$(tpost "$TOKF" "/triggers/$SUBF/invoke" '{}' "Idempotency-Key: f2")
[ "$CODE" = "409" ] && ok "API invoke against an active run → 409 skipped" || no "wanted 409, got $CODE"
[ "$(skip_count "$SUBF" overlap)" = "1" ] && ok "API skip visibly recorded (reason=overlap)" || no "skip not recorded: $(skip_count "$SUBF" overlap)"
CODE=$(tpost "$TOKF" "/triggers/$SUBF/invoke" '{}' "Idempotency-Key: f2")
[ "$CODE" = "409" ] && ok "replaying the skipped key returns the skip (409)" || no "wanted 409, got $CODE"
set_status "$SF1" "$FINAL_F"
CODE=$(tpost "$TOKF" "/triggers/$SUBF/invoke" '{}' "Idempotency-Key: f3")
[ "$CODE" = "200" ] && ok "invoke succeeds once the run is terminal (it was the policy)" || no "wanted 200, got $CODE"

say "§17 #5 — default allow: overlapping API invokes still stack (back-compat)"
CODE=$(post "/triggers" "{\"agent\":\"$AGENT\",\"name\":\"apiG-$$\",\"task_template\":\"api noop\",\"budgets\":$TB}")
SUBG=$(cat "$B" | j "['subscription']['id']"); TOKG=$(cat "$B" | j "['token']")
tpost "$TOKG" "/triggers/$SUBG/invoke" '{}' "Idempotency-Key: g1" >/dev/null
SG1=$(cat "$B" | j "['session_id']")
wait_terminal "$SG1" 90 >/dev/null || true
fake_running "$SG1"
CODE=$(tpost "$TOKG" "/triggers/$SUBG/invoke" '{}' "Idempotency-Key: g2")
[ "$CODE" = "200" ] && ok "default allow: second invoke → 200 while first is active" || no "wanted 200, got $CODE"
set_status "$SG1" "failed"

say "PUBLISH — a schedule-fired run's terminal result arrives signed (Phase 2 reused)"
DFILE=""
for _ in $(seq 1 30); do
  DFILE=$(grep -l "$SA" "$RCV_DIR"/delivery-*.json 2>/dev/null | head -1)
  [ -n "$DFILE" ] && break
  sleep 2
done
[ -n "$DFILE" ] && ok "callback received for schedule-fired run" || no "no callback within 60s"
if [ -n "$DFILE" ]; then
  TS=$(python3 -c "import json;print(json.load(open('$DFILE'))['headers']['x-fluidbox-timestamp'])")
  SIG=$(python3 -c "import json;print(json.load(open('$DFILE'))['headers']['x-fluidbox-signature'])")
  BODY=$(python3 -c "import json;print(json.load(open('$DFILE'))['body'])")
  CALC="v1=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SECA" | sed 's/^.* //')"
  [ "$CALC" = "$SIG" ] && ok "HMAC signature verifies" || no "signature mismatch"
  python3 -c "
import json
p = json.loads(json.load(open('$DFILE'))['body'])
assert p['run']['invocation']['kind'] == 'schedule'
" && ok "payload carries the schedule invocation" || no "payload invocation wrong"
fi

say "LIVE — §12: repository-maintenance agent on a schedule; overlaps skip; result published"
if [ "${E2E_SKIP_LIVE:-0}" = "1" ] || [ -z "${ANTHROPIC_API_KEY:-}" ] \
   || ! curl -fsS -m 3 http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1; then
  echo "  SKIP: live tier needs ANTHROPIC_API_KEY + gateway (E2E_SKIP_LIVE=${E2E_SKIP_LIVE:-0})"
else
  FX=$(mktemp -d "${TMPDIR:-/tmp}/fbx-sched-fx.XXXXXX")
  git -C "$FX" init -q -b main
  git -C "$FX" config user.email e2e@fluidbox.dev
  git -C "$FX" config user.name fbx-e2e
  echo "maintenance-target v1" > "$FX/f.txt"; git -C "$FX" add -A; git -C "$FX" commit -qm c1
  # autonomous: a supervised live run can hang at awaiting_approval if the
  # model reaches for an approval-gated tool; auto-deny keeps it terminal.
  CODE=$(post "/triggers" "{\"agent\":\"claude-fixer\",\"name\":\"sched-live-$$\",
    \"task_template\":\"Repository maintenance run (fired {{fire_time}}): read f.txt in the workspace and state its exact contents, then stop. Do not modify anything.\",
    \"autonomous\":true,\"concurrency_policy\":\"skip_if_running\",
    \"workspace\":{\"kind\":\"git_repository\",\"clone_url\":\"file://$FX\",\"ref\":\"main\"},
    \"schedule\":{\"cron\":\"*/5 * * * * *\",\"timezone\":\"UTC\"},
    \"callback_url\":\"http://127.0.0.1:$RCV_PORT/cb\"}")
  SUBL=$(cat "$B" | j "['subscription']['id']"); SECL=$(cat "$B" | j "['callback_secret']")
  [ "$CODE" = "200" ] && ok "live maintenance schedule created" || no "live create → $CODE: $(cat "$B")"
  wait_trig "$SUBL" "len(d['sessions']) >= 1" 20 1 && ok "live schedule fired" || no "live schedule did not fire"
  SL=$(tget "$SUBL" | j "['sessions'][-1]['id']")
  FINALL=$(wait_terminal "$SL" 420) || true
  post "/triggers/$SUBL/disable" "{}" >/dev/null
  # A follow-up firing may have started in the completion→disable window; cancel strays.
  tget "$SUBL" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for s in d['sessions']:
    if s['status'] not in ('completed','failed','cancelled','budget_exceeded'):
        print(s['id'])" | while read -r sid; do
    curl -s -X POST -H "$H" "$API/v1/sessions/$sid/cancel" >/dev/null
  done
  [ "$FINALL" = "completed" ] && ok "live maintenance run completed" || no "live terminal: $FINALL"
  SKIPS=$(skip_count "$SUBL" overlap)
  [ "${SKIPS:-0}" -ge 1 ] && ok "overlapping firings skipped while it worked ($SKIPS)" || no "no overlap skips during live run"
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
assert p['run']['invocation']['kind'] == 'schedule'
" && ok "live callback: completed + cost + summary + schedule invocation" || no "live payload incomplete"
  else
    no "no live callback within 60s"
  fi
  rm -rf "$FX"
fi

# Housekeeping: silence every schedule this phase created.
for S in "${SUBA:-}" "${SUBB:-}" "${SUBC:-}" "${SUBD:-}" "${SUBE:-}"; do
  [ -n "$S" ] && post "/triggers/$S/disable" "{}" >/dev/null
done
rm -rf "$RCV_DIR"

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
