#!/usr/bin/env bash
# Live queue admission on the REPLAY tier (run admission design 2026-08-23 §12,
# layer 4). MAINTAINER-RUN as part of `just e2e`.
#
# This is the wiring proof the hermetic suite deliberately cannot give. The
# hermetic `scripts/e2e-queue.sh` runs against a provider that provisions
# NOTHING, so it proves the admission LOGIC. This phase runs the same logic
# against REAL Docker provisioning with the replay-runner image — the `just
# demo` machinery — so it also proves that a dispatched run reaches a real
# sandbox, that a queued run has none, and that a cancel while queued winds
# down with nothing to reap.
#
# Still ZERO KEYS and ZERO MODEL SPEND: the replay runner is a scripted agent,
# and the LLM upstream points at a closed port so a model call cannot happen
# even by accident.
#
# ISOLATED like the demo and the recipes phase, so the shared `just e2e`
# control plane on :8787 is never touched:
#   * compose project fluidbox-queue-live (its own Postgres volume)
#   * ports 19794 (API) / 19795 (internal) / 15436 (Postgres)
#   * state under .queue-live/, cleared at the end
#
# Phases:
#   L1  cap 1: A dispatches to a REAL container; B and C park with no sandbox
#   L2  depth bound 2: the next create answers 429
#   L3  cancel while queued: C winds down without ever having been provisioned
#   L4  FIFO through real provisioning: freeing the slot dispatches B
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/.queue-live"
PORT="${FLUIDBOX_QUEUE_LIVE_PORT:-19794}"
INTERNAL_PORT="${FLUIDBOX_QUEUE_LIVE_INTERNAL_PORT:-19795}"
DB_PORT="${FLUIDBOX_QUEUE_LIVE_DB_PORT:-15436}"
REPLAY_IMAGE="${FLUIDBOX_REPLAY_IMAGE:-fluidbox-replay-runner:dev}"
API="http://127.0.0.1:$PORT"
COMPOSE=(docker compose -p fluidbox-queue-live -f "$ROOT/deploy/docker-compose.demo.yml")

pass=0; fail=0
ok()  { printf "    \033[1;32m✓\033[0m %s\n" "$1"; pass=$((pass+1)); }
no()  { printf "    \033[1;31m✗\033[0m %s\n" "$1"; fail=$((fail+1)); }
say() { printf "\n  \033[1;36m-- %s --\033[0m\n" "$1"; }

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }
q() { psql "postgres://fluidbox:fluidbox@127.0.0.1:$DB_PORT/fluidbox" -tAc "$1" 2>/dev/null \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

teardown() {
  if [ -f "$WORK/server.pid" ]; then
    kill "$(cat "$WORK/server.pid")" 2>/dev/null
    wait "$(cat "$WORK/server.pid")" 2>/dev/null
  fi
  # The control plane reaps its own sandboxes on the terminal path; this is the
  # backstop for a phase that failed before reaching one. Scoped to the session
  # ids THIS phase created (recorded as they are made) so a concurrently-running
  # `just dev` sandbox is never touched.
  if [ -f "$WORK/sessions" ]; then
    while read -r sid; do
      [ -n "$sid" ] || continue
      for c in $(docker ps -aq --filter "label=fluidbox.session=$sid" 2>/dev/null); do
        docker rm -f "$c" >/dev/null 2>&1
      done
    done < "$WORK/sessions"
  fi
  "${COMPOSE[@]}" down -v >/dev/null 2>&1
  rm -rf "$WORK"
}
trap teardown EXIT

# ── preflight ──────────────────────────────────────────────────────────────
say "preflight"
docker info >/dev/null 2>&1 || { no "docker daemon not running"; exit 1; }
for p in "$PORT" "$INTERNAL_PORT" "$DB_PORT"; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    no "port $p is already in use — set FLUIDBOX_QUEUE_LIVE_{PORT,INTERNAL_PORT,DB_PORT}"
    exit 1
  fi
done
ok "ports $PORT/$INTERNAL_PORT/$DB_PORT are free"

mkdir -p "$WORK/data"
: > "$WORK/sessions"
if ! docker image inspect "$REPLAY_IMAGE" >/dev/null 2>&1; then
  docker build -q -t "$REPLAY_IMAGE" -f "$ROOT/images/replay-runner/Dockerfile" "$ROOT/images" \
    >/dev/null || { no "replay image build failed"; exit 1; }
fi
ok "replay runner image ready ($REPLAY_IMAGE)"

# The demo's mount probe, for the demo's reason: a daemon that cannot share this
# checkout does not FAIL the bind mount, it mounts an EMPTY directory — and the
# run then "succeeds" while proving nothing. Cheap to check, expensive to debug.
printf 'fluidbox-mount-probe' > "$WORK/data/.marker"
SEEN=$(docker run --rm --entrypoint sh -v "$WORK/data:/probe" "$REPLAY_IMAGE" \
         -c 'cat /probe/.marker 2>/dev/null' 2>/dev/null || true)
[ "$SEEN" = "fluidbox-mount-probe" ] \
  && ok "the daemon can read this checkout (workspace bind mount verified)" \
  || { no "the daemon mounted an EMPTY workspace — see scripts/demo.sh for the colima / File Sharing fix"; exit 1; }

FLUIDBOX_DEMO_DB_PORT="$DB_PORT" "${COMPOSE[@]}" up -d --wait --quiet-pull postgres >/dev/null 2>&1 \
  || { no "queue-live Postgres failed to start"; exit 1; }
ok "isolated Postgres healthy on 127.0.0.1:$DB_PORT"

TOKEN=$(python3 -c "import secrets;print(secrets.token_hex(32))")
H="authorization: Bearer $TOKEN"

# Explicit environment for the same reason demo.sh is explicit: `just e2e` has
# already loaded .env, so every load-bearing knob is overridden here and the
# multi-user / KMS / RLS knobs are cleared for a single-admin posture.
#
# FLUIDBOX_BIND is 0.0.0.0, NOT loopback: sandboxes reach the control plane via
# host.docker.internal, which resolves to the host's gateway IP — a 127.0.0.1
# bind is unreachable from inside a container. (The hermetic suite CAN use
# loopback precisely because its null provider starts no container.)
env -u FLUIDBOX_REQUIRE_SSO -u FLUIDBOX_RUNTIME_ROLE -u FLUIDBOX_KMS_MODE \
    -u FLUIDBOX_LLM_KEY_MODE -u FLUIDBOX_METRICS_BIND -u FLUIDBOX_ALLOW_RLS_BYPASS \
    -u FLUIDBOX_CREDENTIAL_KEY -u ANTHROPIC_API_KEY -u FLUIDBOX_GITHUB_API_URL \
    -u FLUIDBOX_EGRESS_PROXY \
  DATABASE_URL="postgres://fluidbox:fluidbox@127.0.0.1:$DB_PORT/fluidbox" \
  FLUIDBOX_ADMIN_TOKEN="$TOKEN" \
  FLUIDBOX_BIND="0.0.0.0:$PORT" \
  FLUIDBOX_INTERNAL_BIND="127.0.0.1:$INTERNAL_PORT" \
  FLUIDBOX_PUBLIC_CONTROL_URL="http://host.docker.internal:$PORT" \
  FLUIDBOX_DATA_DIR="$WORK/data" \
  FLUIDBOX_SANDBOX_IMAGE="$REPLAY_IMAGE" \
  FLUIDBOX_MAX_CONCURRENT_RUNS=1 \
  FLUIDBOX_QUEUE_MAX_DEPTH=2 \
  FLUIDBOX_QUEUE_MAX_WAIT_SECS=3600 \
  LITELLM_MASTER_KEY="queue-live-unused-no-model-calls" \
  LLM_UPSTREAM_URL="http://127.0.0.1:9" \
  RUST_LOG="${RUST_LOG:-info}" \
  "$ROOT/target/debug/fluidbox-server" > "$WORK/server.log" 2>&1 &
echo $! > "$WORK/server.pid"

HEALTHY=""
for _ in $(seq 1 120); do
  curl -fsS -m 2 "$API/v1/health" >/dev/null 2>&1 && { HEALTHY=1; break; }
  kill -0 "$(cat "$WORK/server.pid")" 2>/dev/null || break
  sleep 0.5
done
[ -n "$HEALTHY" ] || { no "control plane never became healthy"; tail -20 "$WORK/server.log"; exit 1; }
grep -q "run admission: ENABLED" "$WORK/server.log" \
  && ok "control plane up with admission enabled (cap 1, depth 2)" \
  || no "boot did not announce admission"

new_run() { # task -> session_id (also recorded, for teardown)
  curl -s -X POST -H "$H" -H 'content-type: application/json' \
    -d "{\"agent\":\"claude-fixer\",\"task\":\"$1\",\"repo\":{\"kind\":\"none\"}}" \
    "$API/v1/sessions" > "$WORK/last.json"
  local sid
  sid=$(j "['session']['id']" < "$WORK/last.json")
  [ -n "$sid" ] && echo "$sid" >> "$WORK/sessions"
  echo "$sid"
}
status_of() { q "select status from sessions where id = '$1'"; }
await_status() { # id, regex, seconds
  local deadline=$(( $(date +%s) + $3 )) s
  while [ "$(date +%s)" -lt "$deadline" ]; do
    s=$(status_of "$1"); [[ "$s" =~ $2 ]] && { echo "$s"; return 0; }
    sleep 1
  done
  status_of "$1"; return 1
}
sandbox_for() { docker ps -aq --filter "label=fluidbox.session=$1" 2>/dev/null | head -1; }

# ── L1 ─────────────────────────────────────────────────────────────────────
say "L1 — cap 1 through REAL provisioning"
A=$(new_run "live queue A"); sleep 1
B=$(new_run "live queue B"); sleep 1
C=$(new_run "live queue C")
[ -n "$A" ] && [ -n "$B" ] && [ -n "$C" ] \
  && ok "three runs created" \
  || { no "create failed: $(cat "$WORK/last.json")"; exit 1; }

# 180s: a real image start on a cold daemon is slow, and this phase is about
# admission, not about how fast Docker is.
SA=$(await_status "$A" '^(initializing|running)$' 180)
[[ "$SA" =~ ^(initializing|running)$ ]] \
  && ok "A launched through real Docker provisioning (status $SA)" \
  || no "A never launched (status $SA)"
[ -n "$(sandbox_for "$A")" ] \
  && ok "A has a REAL sandbox container" || no "A has no container"

[ "$(status_of "$B")" = queued ] && ok "B is parked in 'queued'" || no "B: $(status_of "$B")"
[ "$(status_of "$C")" = queued ] && ok "C is parked in 'queued'" || no "C: $(status_of "$C")"
# The whole point of parking BEFORE provisioning: a queued run costs nothing.
# This is the assertion the hermetic suite structurally cannot make.
[ -z "$(sandbox_for "$B")" ] && [ -z "$(sandbox_for "$C")" ] \
  && ok "neither queued run has a container (the park is pre-provisioning)" \
  || no "a queued run has a sandbox — the park is not pre-provisioning"
[ "$(q "select count(*) from api_tokens where session_id in ('$B','$C')")" = 0 ] \
  && ok "…and neither has minted a session token (nothing that could spend)" \
  || no "a queued run holds session tokens"

# ── L2 ─────────────────────────────────────────────────────────────────────
say "L2 — depth bound 2"
RESP=$(curl -s -i -X POST -H "$H" -H 'content-type: application/json' \
  -d '{"agent":"claude-fixer","task":"over the bound","repo":{"kind":"none"}}' \
  "$API/v1/sessions")
echo "$RESP" | head -1 | grep -q " 429 " \
  && ok "a create past the depth bound answers 429" \
  || no "expected 429, got: $(echo "$RESP" | head -1)"
echo "$RESP" | grep -qi "^retry-after:" && ok "…with a Retry-After header" || no "no Retry-After"

# ── L3 ─────────────────────────────────────────────────────────────────────
say "L3 — cancel while queued"
curl -s -o /dev/null -X POST -H "$H" "$API/v1/sessions/$C/cancel"
SC=$(await_status "$C" '^(cancelled|failed|finalizing|cancelling)$' 60)
[[ "$SC" =~ ^(cancelled|failed|finalizing|cancelling)$ ]] \
  && ok "a queued run cancels cleanly (status $SC)" || no "C did not cancel (status $SC)"
[ -z "$(sandbox_for "$C")" ] \
  && ok "…and no sandbox was ever created for it (nothing to reap)" \
  || no "a cancelled queued run left a container behind"

# ── L4 ─────────────────────────────────────────────────────────────────────
say "L4 — FIFO release through real provisioning"
curl -s -o /dev/null -X POST -H "$H" "$API/v1/sessions/$A/cancel"
SB=$(await_status "$B" '^(initializing|running)$' 180)
[[ "$SB" =~ ^(initializing|running)$ ]] \
  && ok "freeing the slot dispatched B (status $SB)" || no "B never dispatched (status $SB)"
[ -n "$(sandbox_for "$B")" ] \
  && ok "…with its own real sandbox container" || no "B has no container"
curl -s -o /dev/null -X POST -H "$H" "$API/v1/sessions/$B/cancel"

printf "\n  live queue phase: %d passed, %d failed\n" "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
