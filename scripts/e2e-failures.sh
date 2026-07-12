#!/usr/bin/env bash
# Failure-path E2E — the PLAN.md M1 step-12 acceptance list the demos don't
# cover. Owns its control-plane lifecycle (it must restart the server for the
# orphan-sweep case), so it refuses to run when something else holds :8787.
# No model, no gateway, no key needed. Requires: docker, psql, python3, .env.
#
#   F1  max_tool_calls: 2 → third call refused + session budget_exceeded
#   F2  container killed mid-run → watchdog fails + reaps
#   F3  server restart → boot sweep reaps unknown-session orphan, spares the
#       live session's sandbox; cancel then reaps it
#   F4  session stalled in 'created' → stale-launch sweep fails it
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker psql python3 curl cargo
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"

if port_in_use; then
  echo "port 8787 already serving — stop 'just dev' first (this suite restarts the control plane)"
  exit 1
fi
echo "building server…"
cargo build -q -p fluidbox-server || exit 1
trap 'stop_server' EXIT
start_server || exit 1

new_session() { # task budgets_json -> session id
  curl -s -X POST -H "$H" -H 'content-type: application/json' \
    -d "{\"agent\":\"claude-fixer\",\"task\":\"$1\",\"repo\":{\"kind\":\"none\"},\"autonomous\":false,\"budgets\":$2}" \
    "$API/v1/sessions" | j "['session']['id']"
}
wait_container() { # session -> running container id
  for _ in $(seq 1 60); do
    C=$(docker ps --filter "label=fluidbox.session=$1" --format '{{.ID}}' | head -1)
    [ -n "$C" ] && { echo "$C"; return 0; }
    sleep 0.5
  done
  echo ""
}
token_for() { # container -> session token
  docker inspect "$1" --format '{{range .Config.Env}}{{println .}}{{end}}' \
    | grep '^FLUIDBOX_SESSION_TOKEN=' | head -1 | cut -d= -f2-
}
status_of() { curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']['status']"; }
reason_of() { curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']['status_reason']"; }
wait_status() { # id want tries [sleep]
  for _ in $(seq 1 "$3"); do
    [ "$(status_of "$1")" = "$2" ] && return 0
    sleep "${4:-1}"
  done
  return 1
}
containers_for() { docker ps -a --filter "label=fluidbox.session=$1" -q | wc -l | tr -d ' '; }
# Phase 6: tool_call_count counts server-registered INTENTS (one per unique
# tool_call_id crossing the gate); runner-posted tool.requested events are
# DROPPED at ingest. The posts below stay to prove exactly that — if they
# counted, call 2 would already blow a budget of 2.
emit_tool_requested() { # token session call_id
  curl -s -X POST -H "authorization: Bearer $1" -H 'content-type: application/json' \
    -d "{\"actor\":\"agent\",\"body\":{\"type\":\"tool.requested\",\"data\":{\"tool_call_id\":\"$3\",\"tool\":\"Read\",\"summary\":\"budget probe\",\"input_digest\":\"\"}}}" \
    "$API/internal/sessions/$2/events" >/dev/null
}
perm() { # token session body -> decision json
  curl -s -X POST -H "authorization: Bearer $1" -H 'content-type: application/json' \
    -d "$3" "$API/internal/sessions/$2/permission"
}

# ── F1: tool-call budget ────────────────────────────────────────────────
say "F1 — max_tool_calls: 2 → third call refused, session budget_exceeded"
S1=$(new_session "budget probe — reply DONE, use no tools" '{"max_tool_calls":2}')
[ -n "$S1" ] && ok "session created ($S1)" || { no "session create failed"; exit 1; }
C1=$(wait_container "$S1")
[ -n "$C1" ] && ok "sandbox launched" || { no "no sandbox"; exit 1; }
T1=$(token_for "$C1")
docker kill "$C1" >/dev/null 2>&1   # silence the real runner; this script IS the runner now
for i in 1 2 3; do
  emit_tool_requested "$T1" "$S1" "bp$i"
  D=$(perm "$T1" "$S1" "{\"tool_call_id\":\"bp$i\",\"tool\":\"Read\",\"input\":{\"file_path\":\"/workspace/f$i\"}}")
  DEC=$(echo "$D" | j "['decision']")
  if [ "$i" -le 2 ]; then
    [ "$DEC" = "allow" ] && ok "call $i → allow (within budget)" || no "call $i expected allow, got $DEC"
  else
    [ "$DEC" = "deny" ] && ok "call 3 → deny (budget gate)" || no "call 3 expected deny, got $DEC"
    echo "$D" | j "['message']" | grep -q "budget" \
      && ok "deny message names the budget" || no "deny message: $(echo "$D" | j "['message']")"
  fi
done
wait_status "$S1" budget_exceeded 30 1 \
  && ok "session → budget_exceeded" || no "expected budget_exceeded, got $(status_of "$S1")"
NBE=$(curl -s -H "$H" "$API/v1/sessions/$S1/events?limit=200" | python3 -c "
import sys, json
evs = json.load(sys.stdin)['events']
print(sum(1 for e in evs if e['type'] == 'budget.exceeded'
          and e['payload']['data'].get('budget') == 'max_tool_calls'))")
[ "${NBE:-0}" -ge 1 ] 2>/dev/null && ok "budget.exceeded ledgered" || no "no budget.exceeded event"

# ── F2: dead container → watchdog ───────────────────────────────────────
say "F2 — kill container mid-run → watchdog fails + reaps (takes ~90s)"
S2=$(new_session "watchdog probe — reply DONE, use no tools" '{}')
C2=$(wait_container "$S2")
[ -n "$C2" ] && ok "sandbox launched" || { no "no sandbox"; exit 1; }
wait_status "$S2" running 20 0.5 || true
docker kill "$C2" >/dev/null 2>&1
ok "container killed while session running"
wait_status "$S2" failed 150 1 \
  && ok "watchdog failed the session" || no "expected failed, got $(status_of "$S2")"
reason_of "$S2" | grep -qi "heartbeat" \
  && ok "reason names the stale heartbeat" || no "reason: $(reason_of "$S2")"
[ "$(containers_for "$S2")" = "0" ] \
  && ok "sandbox reaped" || no "container still present"

# ── F3: restart → boot orphan sweep ─────────────────────────────────────
say "F3 — restart: orphan reaped, live session's sandbox spared"
S3=$(new_session "restart probe — reply DONE, use no tools" '{}')
C3=$(wait_container "$S3")
[ -n "$C3" ] && ok "live session sandbox up" || { no "no sandbox"; exit 1; }
docker kill "$C3" >/dev/null 2>&1   # freeze it: container stays (Exited), no completion race
BOGUS_SID=$(python3 -c 'import uuid; print(uuid.uuid4())')
BOGUS=$(docker run -d --label fluidbox.managed=1 --label "fluidbox.session=$BOGUS_SID" \
  --entrypoint sleep "$FLUIDBOX_SANDBOX_IMAGE" 600)
[ -n "$BOGUS" ] && ok "planted orphan container (unknown session)" || { no "could not start orphan container"; exit 1; }
stop_server
start_server || exit 1              # boot_orphan_sweep runs before the port opens
if [ -z "$(docker ps -aq --no-trunc --filter "id=$BOGUS")" ]; then
  ok "boot sweep reaped the unknown-session orphan"
else
  no "orphan container survived the boot sweep"
  docker rm -f "$BOGUS" >/dev/null 2>&1
fi
[ "$(containers_for "$S3")" = "1" ] \
  && ok "live session's sandbox spared by the sweep" || no "live sandbox was reaped"
# The stop can race the initializing→running write; either state proves the
# sweep spared a live (non-terminal) session, which is the invariant here.
ST3=$(status_of "$S3")
case "$ST3" in
  running|initializing) ok "session still live after restart ($ST3)" ;;
  *) no "session status after restart: $ST3 (expected running/initializing)" ;;
esac
curl -s -X POST -H "$H" "$API/v1/sessions/$S3/cancel" >/dev/null
for _ in $(seq 1 15); do [ "$(containers_for "$S3")" = "0" ] && break; sleep 1; done
[ "$(containers_for "$S3")" = "0" ] \
  && ok "cancel reaped the sandbox" || no "sandbox not reaped after cancel"

# ── F4: stalled-launch sweep ────────────────────────────────────────────
say "F4 — session stalled in 'created' → stale-launch sweep fails it"
# -q + head -1: psql prints the INSERT command tag even under -tA.
S4=$(psql "$DATABASE_URL" -qtA -c "
  insert into sessions (id, tenant_id, agent_id, agent_revision_id, status, autonomy,
                        trust_tier, task, repo_source, run_spec, budgets, created_at, updated_at)
  select gen_random_uuid(), tenant_id, agent_id, agent_revision_id, 'created', 'supervised',
         'trusted', 'fbx-e2e stale probe', repo_source, run_spec, budgets,
         now() - interval '30 minutes', now() - interval '30 minutes'
  from sessions where id = '$S3'
  returning id;" | head -1)
[ -n "$S4" ] && ok "injected stalled 'created' session" || { no "fixture insert failed"; exit 1; }
wait_status "$S4" failed 30 1 \
  && ok "stale-launch sweep failed it" || no "expected failed, got $(status_of "$S4")"
reason_of "$S4" | grep -qi "stalled before launch" \
  && ok "reason names the stall" || no "reason: $(reason_of "$S4")"

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
