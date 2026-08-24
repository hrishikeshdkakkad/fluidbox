#!/usr/bin/env bash
# Hermetic queue-admission E2E (run admission design 2026-08-23 §12, layer 3).
#
# Real HTTP, real Postgres, real dispatcher — and ZERO sandboxes, ZERO model
# spend, ZERO keys. FLUIDBOX_PROVIDER=null (feature-gated, see
# crates/fluidbox-provider/src/null.rs) provisions a synthetic handle instantly,
# which is enough because admission is entirely a control-plane concern:
# nothing about the queue depends on what a sandbox does once it exists.
#
# SELF-ISOLATED BY CONSTRUCTION, which is what makes this the one e2e safe to
# run unprompted:
#   * its own database (fluidbox_queue_e2e), dropped and recreated per run
#   * its own ports (18791 / 18792), away from the dev stack's 8787/8788
#   * its own data dir (mktemp), removed on exit
# The only credential here is a DUMMY LiteLLM key. Boot fails closed on an empty
# upstream key ("there is no silent fallback"), and that refusal is exactly what
# proves the isolation works — the real key is no longer reachable. It is never
# used: the null provider starts no agent, so no model request can be made.
#
#   * it never sources .env, AND it runs the server from a scratch directory —
#     because the SERVER calls dotenvy::dotenv() itself (main.rs), so a server
#     started with the repo root as its cwd would read the operator's real .env
#     no matter what the script does. Running it elsewhere is what actually
#     isolates it: no live Neon URL, no real provider key, no GitHub App secret.
#
# Phases:
#   P0  INERT BY DEFAULT: with the cap unset, nothing queues and 0034's columns
#       are never written — the epic's hard requirement, asserted rather than
#       argued
#   P1  cap=1 FIFO: three runs, one admitted, two parked; cancel releases the
#       next in creation order; queue_position reports the wait
#   P2  depth bound: a full queue answers 429 + Retry-After
#   P3  capacity bounce: an injected provider denial re-parks with backoff
#       instead of failing the run
#   P4  age expiry: a run that waits past the bound fails with an explained
#       reason, and its ledger says so
set -uo pipefail
cd "$(dirname "$0")/.."

PGBASE=${PGBASE:-postgres://fluidbox:fluidbox@127.0.0.1:5433}
DB=fluidbox_queue_e2e
PORT=18791
INTERNAL_PORT=18792
API="http://127.0.0.1:$PORT"
TOKEN=queue-e2e-token
H="authorization: Bearer $TOKEN"

pass=0; fail=0
ok()  { printf "  \033[1;32m✓\033[0m %s\n" "$1"; pass=$((pass+1)); }
no()  { printf "  \033[1;31m✗\033[0m %s\n" "$1"; fail=$((fail+1)); }
say() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }
# Trim the ends only: `tr -d ' '` would mangle the text columns these
# assertions read (a status_reason is a sentence, not a token).
q() { psql "$PGBASE/$DB" -tAc "$1" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

# How long to wait for a cancelled run to RELEASE its capacity slot. Generous on
# purpose: `cancelling` and `finalizing` are deliberately counted as occupied
# (they still hold a sandbox until it is reaped), and with a runnerless provider
# the wind-down always costs the full 30s quiesce deadline plus a watchdog tick
# plus a finalize-worker tick. See the note at P1's first cancel.
SLOT_RELEASE_WAIT=240

DATA_DIR=$(mktemp -d)
# Absolute, because the server is started from DATA_DIR (see start_server).
BIN="$PWD/target/debug/fluidbox-server"
SRV=""
cleanup() {
  [ -n "$SRV" ] && kill "$SRV" 2>/dev/null
  wait "$SRV" 2>/dev/null
  rm -rf "$DATA_DIR"
}
trap cleanup EXIT

# Start the server with the queue knobs this phase needs. Every invocation gets
# a fresh process, because the knobs are read once at boot.
start_server() { # env assignments as "K=V" args
  [ -n "$SRV" ] && { kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; SRV=""; }
  # `cd "$DATA_DIR"` is load-bearing, not tidiness: the server calls
  # dotenvy::dotenv(), which reads `.env` FROM THE WORKING DIRECTORY. Started at
  # the repo root it would inherit the operator's real keys and settings, and
  # this suite would stop being hermetic. The scratch dir has no `.env`, so the
  # only configuration is what `env -i` passes below.
  (
    cd "$DATA_DIR" || exit 1
    exec env -i \
      PATH="$PATH" HOME="$HOME" \
      DATABASE_URL="$PGBASE/$DB" \
      FLUIDBOX_BIND="127.0.0.1:$PORT" \
      FLUIDBOX_INTERNAL_BIND="127.0.0.1:$INTERNAL_PORT" \
      FLUIDBOX_ADMIN_TOKEN="$TOKEN" \
      FLUIDBOX_PROVIDER=null \
      FLUIDBOX_DATA_DIR="$DATA_DIR" \
      LITELLM_MASTER_KEY=queue-e2e-unused-no-model-call-is-possible \
      "$@" \
      "$BIN"
  ) >"$DATA_DIR/server.log" 2>&1 &
  SRV=$!
  for _ in $(seq 1 60); do
    curl -fsS -m 2 "$API/v1/health" >/dev/null 2>&1 && return 0
    kill -0 "$SRV" 2>/dev/null || { echo "server died:"; tail -20 "$DATA_DIR/server.log"; return 1; }
    sleep 0.5
  done
  echo "server never became healthy:"; tail -20 "$DATA_DIR/server.log"; return 1
}

new_run() { # task -> session_id (empty on non-2xx; the body lands in last.json)
  curl -s -X POST -H "$H" -H 'content-type: application/json' \
    -d "{\"agent\":\"$AGENT\",\"task\":\"$1\",\"repo\":{\"kind\":\"none\"}}" \
    "$API/v1/sessions" > "$DATA_DIR/last.json"
  j "['session']['id']" < "$DATA_DIR/last.json"
}

# The agent every phase runs. Seeded at boot when the deployment has none;
# resolved (not assumed) so a seed-name change fails here with a clear message
# rather than as an empty session id three assertions later.
resolve_agent() {
  curl -s -H "$H" "$API/v1/agents" > "$DATA_DIR/agents.json"
  AGENT=$(python3 -c \
    "import sys,json;a=json.load(sys.stdin).get('agents') or [];print(a[0]['name'] if a else '')" \
    < "$DATA_DIR/agents.json" 2>/dev/null)
  [ -n "$AGENT" ] || echo "    agents list: $(cat "$DATA_DIR/agents.json")"
}

status_of() { q "select status from sessions where id = '$1'"; }

# Poll until a session leaves 'queued' (or the deadline passes).
await_status() { # session_id, wanted-regex, seconds
  local deadline=$(( $(date +%s) + $3 )) s
  while [ "$(date +%s)" -lt "$deadline" ]; do
    s=$(status_of "$1")
    [[ "$s" =~ $2 ]] && { echo "$s"; return 0; }
    sleep 0.5
  done
  echo "$(status_of "$1")"; return 1
}

# A phase that begins with leftover rows is not testing what it says. Deleting
# from `sessions` is not enough — the child tables make it a cascade question —
# and a silently-failing delete is exactly how a phase ends up asserting against
# the previous phase's queue (observed while writing this: P2's leftovers
# consumed P3's injected provider denial). Recreating the database is
# unambiguous, and the next boot re-migrates and re-seeds it.
reset_db() {
  [ -n "$SRV" ] && { kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; SRV=""; }
  psql "$PGBASE/postgres" -c "drop database if exists $DB with (force)" >/dev/null 2>&1 \
    || { echo "cannot reach Postgres at $PGBASE — start it with: docker compose -f deploy/docker-compose.dev.yml up -d postgres"; return 1; }
  psql "$PGBASE/postgres" -c "create database $DB" >/dev/null
}

say "setup"
reset_db || exit 1
ok "throwaway database $DB created"
cargo build -q -p fluidbox-server --features test-provider || { no "build"; exit 1; }
ok "server built with the test-provider feature (NullProvider available)"

# ── P0 ─────────────────────────────────────────────────────────────────────
# The epic's hard requirement is "with FLUIDBOX_MAX_CONCURRENT_RUNS unset,
# behaviour is byte-identical to before the feature existed". That is a claim
# about ABSENCE, which is exactly the kind of claim that quietly stops being
# true — a stray call site, a check that forgot its feature gate — and which no
# other phase can catch, because every other phase turns the feature ON.
say "P0 — inert by default: the feature off changes nothing"
start_server || exit 1
grep -q "run admission: off" "$DATA_DIR/server.log" \
  && ok "boot reports admission off" \
  || no "boot did not report admission off: $(grep -o 'run admission:.*' "$DATA_DIR/server.log" | head -1)"
resolve_agent
[ -n "$AGENT" ] && ok "agent '$AGENT' available" || no "no agent resolved"

Z=$(new_run "inert mode")
[ -n "$Z" ] && ok "run created with no cap configured" || no "create failed: $(cat "$DATA_DIR/last.json")"
SZ=$(await_status "$Z" '^(provisioning|initializing|running)$' 30)
[[ "$SZ" =~ ^(provisioning|initializing|running)$ ]] \
  && ok "it launched directly, with no dispatcher involved (status $SZ)" \
  || no "the run did not launch (status $SZ)"
[ "$(q "select count(*) from sessions where status = 'queued'")" = 0 ] \
  && ok "nothing ever entered 'queued'" || no "a run was parked with the feature off"

# Migration 0034's columns must sit unused. `launched_at` is the ONE exception
# and is deliberate: it is the design §3.10 fix for the stale-launch watchdog,
# which is a bug fix for network grants and is NOT feature-gated.
[ "$(q "select coalesce(queued_at::text,'NULL') from sessions where id = '$Z'")" = NULL ] \
  && ok "queued_at is unwritten" || no "queued_at was written with the feature off"
[ "$(q "select coalesce(dispatch_after::text,'NULL') from sessions where id = '$Z'")" = NULL ] \
  && ok "dispatch_after is unwritten" || no "dispatch_after was written"
[ "$(q "select dispatch_attempts from sessions where id = '$Z'")" = 0 ] \
  && ok "dispatch_attempts is 0 (nothing claimed it)" || no "dispatch_attempts moved"
[ "$(q "select coalesce(launched_at::text,'NULL') from sessions where id = '$Z'")" != NULL ] \
  && ok "launched_at IS stamped — the stale-launch fix is deliberately not gated" \
  || no "launched_at was not stamped"

# And no depth check runs: a create that WOULD be past a bound is accepted.
for i in 1 2 3 4 5; do new_run "inert $i" >/dev/null; done
RESP=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$H" -H 'content-type: application/json' \
  -d '{"agent":"'"$AGENT"'","task":"no bound exists","repo":{"kind":"none"}}' "$API/v1/sessions")
[ "$RESP" = 200 ] || [ "$RESP" = 201 ] \
  && ok "no depth bound is enforced (create returns $RESP, never 429)" \
  || no "a create was shed with the feature off: $RESP"
curl -s -o /dev/null -X POST -H "$H" "$API/v1/sessions/$Z/cancel"

# ── P1 ─────────────────────────────────────────────────────────────────────
say "P1 — cap 1: one runs, the rest queue FIFO"
reset_db || exit 1
start_server FLUIDBOX_MAX_CONCURRENT_RUNS=1 FLUIDBOX_QUEUE_MAX_DEPTH=50 || exit 1
grep -q "run admission: ENABLED" "$DATA_DIR/server.log" \
  && ok "boot announces admission is enabled" || no "boot did not announce admission"
resolve_agent
[ -n "$AGENT" ] && ok "agent '$AGENT' available" || no "no agent could be resolved or created"

A=$(new_run "queue A"); sleep 0.3
B=$(new_run "queue B"); sleep 0.3
C=$(new_run "queue C")
[ -n "$A" ] && [ -n "$B" ] && [ -n "$C" ] || {
  no "three runs created (A=$A B=$B C=$C)"
  echo "    last create response: $(cat "$DATA_DIR/last.json" 2>/dev/null)"
  echo "    server log:"; tail -15 "$DATA_DIR/server.log" | sed 's/^/      /'
  exit 1
}
ok "three runs created under cap 1"

SA=$(await_status "$A" '^(provisioning|initializing|running)$' 20)
[[ "$SA" =~ ^(provisioning|initializing|running)$ ]] \
  && ok "A was admitted (status $SA)" || no "A never left the queue (status $SA)"
[ "$(status_of "$B")" = queued ] && ok "B is parked in 'queued'" || no "B status: $(status_of "$B")"
[ "$(status_of "$C")" = queued ] && ok "C is parked in 'queued'" || no "C status: $(status_of "$C")"

# The park is auditable through the existing ledger funnel — zero new event
# types was a design goal, so prove the StatusChanged carries the reason.
REASON=$(q "select status_reason from sessions where id = '$B'")
[[ "$REASON" == *"capacity slot"* ]] \
  && ok "B's status_reason explains the park: $REASON" || no "B reason: $REASON"
[ -n "$(q "select queued_at from sessions where id = '$B'")" ] \
  && ok "B carries queued_at (the wait clock)" || no "B has no queued_at"

# queue_position (design §13): B is next, C is behind it.
POS_B=$(curl -s -H "$H" "$API/v1/sessions/$B" | j "['queue_position']")
POS_C=$(curl -s -H "$H" "$API/v1/sessions/$C" | j "['queue_position']")
[ "$POS_B" = 0 ] && ok "B reports queue_position 0 (next up)" || no "B position: $POS_B"
[ "$POS_C" = 1 ] && ok "C reports queue_position 1 (behind B)" || no "C position: $POS_C"

# Cancelling A frees the slot; B goes next because FIFO orders by created_at.
#
# Wait for A to reach a TERMINAL state, not merely for the cancel to be
# accepted. `cancelling` and `finalizing` are deliberately counted as OCCUPIED
# by the occupancy query — they still hold a sandbox until it is reaped — so the
# slot is not free until A releases it.
#
# B's dispatch IS the proof that A released the slot, so that is the only thing
# asserted. An intermediate "A reached a terminal state" assertion was tried and
# removed: it couples the test to how long wind-down takes, which with a
# RUNNERLESS provider is both slow and variable — a cancel can never be
# acknowledged, so it always costs the full 30s quiesce deadline plus a watchdog
# tick plus a finalize-worker tick, and it flaked at both 60s and 120s budgets.
# None of that is queue behaviour. Assert the property, not the mechanism.
curl -s -o /dev/null -X POST -H "$H" "$API/v1/sessions/$A/cancel"
SB=$(await_status "$B" '^(provisioning|initializing|running)$' "$SLOT_RELEASE_WAIT")
[[ "$SB" =~ ^(provisioning|initializing|running)$ ]] \
  && ok "cancelling A admitted B next (FIFO, status $SB)" || no "B never dispatched (status $SB)"
[ "$(status_of "$C")" = queued ] && ok "C still waits (the cap is still 1)" || no "C: $(status_of "$C")"

curl -s -o /dev/null -X POST -H "$H" "$API/v1/sessions/$B/cancel"
SC=$(await_status "$C" '^(provisioning|initializing|running)$' "$SLOT_RELEASE_WAIT")
[[ "$SC" =~ ^(provisioning|initializing|running)$ ]] \
  && ok "cancelling B admitted C (status $SC)" || no "C never dispatched (status $SC)"
curl -s -o /dev/null -X POST -H "$H" "$API/v1/sessions/$C/cancel"

# ── P2 ─────────────────────────────────────────────────────────────────────
say "P2 — depth bound: a full queue sheds with 429 + Retry-After"
reset_db || exit 1
start_server FLUIDBOX_MAX_CONCURRENT_RUNS=1 FLUIDBOX_QUEUE_MAX_DEPTH=3 || exit 1
resolve_agent
# Fill deterministically. The naive version — create four back to back and
# hope — RACES the dispatcher: while the first run is still `queued` it counts
# toward depth, so the fourth create is shed at the bound and the queue settles
# at two once the first is admitted. (That race is itself the depth bound
# working; it just makes the phase assert the wrong number.) So: put one run in
# the SLOT first, wait until it has actually left the queue, and only then add
# exactly `bound` runs to fill it.
HOLD=$(new_run "holds the slot")
await_status "$HOLD" '^(provisioning|initializing|running)$' 30 >/dev/null \
  && ok "one run occupies the single slot" || no "the holder never dispatched"
for i in 1 2 3; do new_run "depth $i" >/dev/null; done
for _ in $(seq 1 40); do
  [ "$(q "select count(*) from sessions where status = 'queued'")" -ge 3 ] && break
  sleep 0.5
done
DEPTH=$(q "select count(*) from sessions where status = 'queued'")
[ "$DEPTH" -eq 3 ] && ok "queue filled to its depth bound (3)" || no "queue depth: $DEPTH"

RESP=$(curl -s -i -X POST -H "$H" -H 'content-type: application/json' \
  -d '{"agent":"claude-fixer","task":"over the bound","repo":{"kind":"none"}}' \
  "$API/v1/sessions")
echo "$RESP" | head -1 | grep -q " 429 " \
  && ok "a create past the bound answers 429" || no "expected 429, got: $(echo "$RESP" | head -1)"
echo "$RESP" | grep -qi "^retry-after: *30" \
  && ok "…with Retry-After: 30" || no "no Retry-After header"
echo "$RESP" | grep -qi "at capacity" \
  && ok "…and the house error envelope names the reason" || no "unexpected body"

# The shed must not have created anything.
BEFORE=$(q "select count(*) from sessions")
curl -s -o /dev/null -X POST -H "$H" -H 'content-type: application/json' \
  -d '{"agent":"claude-fixer","task":"shed again","repo":{"kind":"none"}}' "$API/v1/sessions"
[ "$(q "select count(*) from sessions")" = "$BEFORE" ] \
  && ok "a shed create writes no session row" || no "a shed create created a row"

# ── P3 ─────────────────────────────────────────────────────────────────────
say "P3 — capacity bounce: a provider denial re-parks instead of failing"
reset_db || exit 1
start_server FLUIDBOX_MAX_CONCURRENT_RUNS=2 FLUIDBOX_QUEUE_MAX_DEPTH=50 \
  FLUIDBOX_NULL_CAPACITY_DENIALS=1 || exit 1
resolve_agent
grep -q "null provider: 1 injected capacity denial" "$DATA_DIR/server.log" \
  && ok "the provider armed exactly one injected denial" \
  || no "denial injection did not arm: $(grep -o 'null provider:.*' "$DATA_DIR/server.log" | head -1)"
D=$(new_run "bounced run")
[ -n "$D" ] && ok "run created against a provider that will refuse once" || no "create failed"

# The dispatcher admits it, the provider refuses, and it comes BACK to queued
# with a backoff gate — the whole point: capacity pressure is not a failure.
BOUNCED=0
for _ in $(seq 1 60); do
  if [ "$(q "select dispatch_attempts from sessions where id = '$D'")" -ge 1 ] \
     && [ "$(status_of "$D")" = queued ] \
     && [ -n "$(q "select dispatch_after from sessions where id = '$D'")" ]; then
    BOUNCED=1; break
  fi
  sleep 0.5
done
if [ "$BOUNCED" = 1 ]; then
  ok "the refused run is back in 'queued' with a backoff gate"
else
  no "no bounce observed (status $(status_of "$D"), attempts $(q "select dispatch_attempts from sessions where id = '$D'"), after '$(q "select dispatch_after from sessions where id = '$D'")')"
  echo "    all sessions: $(q "select id||' '||status||' a='||dispatch_attempts||' handle='||coalesce(sandbox_handle::text,'NULL') from sessions")"
  echo "    server log tail:"
  tail -25 "$DATA_DIR/server.log" | sed 's/^/      /'
fi
[ "$(status_of "$D")" != failed ] \
  && ok "…and the run did NOT fail (this is the headline behaviour change)" || no "the run failed"
BR=$(q "select status_reason from sessions where id = '$D'")
[[ "$BR" == *"provider at capacity"* ]] \
  && ok "…with the verbatim provider message in the ledger reason: $BR" || no "bounce reason: $BR"
GATE=$(q "select extract(epoch from (dispatch_after - now()))::int from sessions where id = '$D'")
[ -n "$GATE" ] && [ "$GATE" -gt 20 ] \
  && ok "the backoff gate clears the lease TTL (${GATE}s out)" || no "backoff gate: ${GATE}s"
# The bounced attempt must not leave live credentials behind.
[ "$(q "select count(*) from api_tokens where session_id = '$D' and revoked_at is null")" = 0 ] \
  && ok "the bounced attempt's session tokens were revoked" \
  || no "live tokens survived the bounce: $(q "select count(*) from api_tokens where session_id = '$D' and revoked_at is null")"

# ── P4 ─────────────────────────────────────────────────────────────────────
say "P4 — age bound: a run that waits too long fails with an explained reason"
reset_db || exit 1
start_server FLUIDBOX_MAX_CONCURRENT_RUNS=1 FLUIDBOX_QUEUE_MAX_DEPTH=50 \
  FLUIDBOX_QUEUE_MAX_WAIT_SECS=5 || exit 1
resolve_agent
E=$(new_run "holds the slot"); sleep 0.3
F=$(new_run "waits too long")
await_status "$E" '^(provisioning|initializing|running)$' 20 >/dev/null
[ "$(status_of "$F")" = queued ] && ok "F is parked behind E" || no "F: $(status_of "$F")"
# 5s age bound + the ~15s sweep cadence + margin.
SF=$(await_status "$F" '^(cancelling|finalizing|failed)$' 45)
[[ "$SF" =~ ^(cancelling|finalizing|failed)$ ]] \
  && ok "F was expired by the age sweeper (status $SF)" || no "F never expired (status $SF)"
FR=$(q "select status_reason from sessions where id = '$F'")
[[ "$FR" == *"maximum wait"* ]] \
  && ok "…with a reason an operator can act on: $FR" || no "expiry reason: $FR"
[ "$(status_of "$E")" != failed ] \
  && ok "the running run was untouched by the sweep" || no "the sweep hit a running run"

say "result"
[ -n "$SRV" ] && { kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; SRV=""; }
psql "$PGBASE/postgres" -c "drop database if exists $DB with (force)" >/dev/null 2>&1
printf "  %d passed, %d failed\n" "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
