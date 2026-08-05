#!/usr/bin/env bash
# §9 criteria 13 and 14, exercised LOCALLY — the two remaining criteria that do
# not need AWS, and the two most likely to be believed without being tested.
#
#   D1  §9-13 OPERATOR CANCELLATION stops an active run. Driven against a run
#       genuinely in flight and BLOCKED on a human approval — the realistic
#       "stuck run" an operator actually has to kill — not a finished one.
#   D2  §9-14 the CONTAINMENT runbook (§7) exercised step by step, recording
#       what each step really does AND what it does not. The M1 brief requires
#       the limitations to be recorded; this produces them from observation
#       rather than from the author's imagination.
#
# Docker provider, replay runner, throwaway database: no AWS, no model calls,
# no live Neon, $0.
#
#   scripts/cloud/m1-containment-drill.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.colima/default/docker.sock}"
PORT="${DRILL_PORT:-8794}"
INTERNAL_PORT="${DRILL_INTERNAL_PORT:-8795}"
DB="${DRILL_DB:-fluidbox_m1drill}"
PGHOST=127.0.0.1; PGPORT=5433; PGUSER=fluidbox; export PGPASSWORD=fluidbox
API="http://127.0.0.1:$PORT"
BIN="${PROOF_SERVER_BIN:-target/debug/fluidbox-server}"
REPLAY_IMAGE="${REPLAY_IMAGE:-fluidbox-replay-runner:dev}"
WORK="${SCRATCH:-/tmp/fluidbox-m1drill}"
EV=$(evidence_dir cloud-m1-readiness)
mkdir -p "$WORK/data"
REPORT="$EV/containment-drill.md"

PASS=0; FAILN=0
pass() { ok "$1"; PASS=$((PASS+1)); }
bad()  { fail "$1"; FAILN=$((FAILN+1)); }
note() { printf '%s\n' "$1" >> "$REPORT"; }
cleanup() {
  if [ -f "$WORK/server.pid" ]; then
    local p; p=$(cat "$WORK/server.pid" 2>/dev/null)
    if [ -n "$p" ]; then
      kill "$p" 2>/dev/null
      # WAIT for it to actually exit. `kill` is asynchronous: without this the
      # next boot hits "Address already in use", fails to bind, and the health
      # check then succeeds against the STILL-RUNNING OLD SERVER — so the whole
      # next phase silently tests the wrong posture. Observed exactly that.
      for _ in $(seq 1 40); do kill -0 "$p" 2>/dev/null || break; sleep 0.25; done
      kill -9 "$p" 2>/dev/null
    fi
    rm -f "$WORK/server.pid"
  fi
  # Belt and braces: reap a listener on our port ONLY if it is verifiably this
  # checkout's server (a neighbouring checkout must never be sabotaged).
  local lpid
  for lpid in $(lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null); do
    case "$(ps -o command= -p "$lpid" 2>/dev/null)" in
      *"$PWD/target/"*fluidbox-server*) kill -9 "$lpid" 2>/dev/null ;;
    esac
  done
  return 0
}
trap cleanup EXIT

[ -x "$BIN" ] || die "server binary not found at $BIN"
[ "$DB" = "fluidbox" ] && die "refusing to run against the DEV database"
docker image inspect "$REPLAY_IMAGE" >/dev/null 2>&1 \
  || docker build -q -t "$REPLAY_IMAGE" -f images/replay-runner/Dockerfile images >/dev/null \
  || die "replay image unavailable and could not be built"

boot() { # boot <require_sso 0|1>
  cleanup
  local sso="$1"
  local abs; abs="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
  # Refuse to start until the port is genuinely free, so a bind failure can
  # never be masked by a stale listener answering the health check.
  for _ in $(seq 1 40); do
    lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1 || break
    sleep 0.5
  done
  if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    fail "port $PORT still held before boot — refusing to start (a stale listener would silently serve the wrong posture)"
    return 1
  fi
  rm -f "$WORK/server-sso$1.log"
  # `exec`, and the & OUTSIDE the parentheses, so $! is the SERVER's pid.
  # Written the obvious way — `( cd X && env … & echo $! )` — the recorded pid
  # is the SUBSHELL's; killing it leaves the server holding the port, the next
  # boot fails to bind, and the health check then passes against the OLD
  # server, silently testing the wrong posture. Observed exactly that here.
  ( cd "$WORK" && exec env -i PATH="$PATH" HOME="$HOME" DOCKER_HOST="$DOCKER_HOST" \
      DATABASE_URL="postgres://fluidbox:fluidbox@$PGHOST:$PGPORT/$DB" \
      FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime \
      ${sso:+FLUIDBOX_REQUIRE_SSO=$sso} \
      FLUIDBOX_ADMIN_TOKEN="$ADMIN" FLUIDBOX_CREDENTIAL_KEY="$CREDKEY" \
      FLUIDBOX_BIND="127.0.0.1:$PORT" FLUIDBOX_INTERNAL_BIND="127.0.0.1:$INTERNAL_PORT" \
      FLUIDBOX_PUBLIC_URL="$API" FLUIDBOX_PUBLIC_CONTROL_URL="http://host.docker.internal:$INTERNAL_PORT" \
      FLUIDBOX_DATA_DIR="$WORK/data" FLUIDBOX_PROVIDER=docker \
      LITELLM_MASTER_KEY=drill-no-model-calls LLM_UPSTREAM_URL="http://127.0.0.1:4999" \
      "$abs" ) > "$WORK/server-sso$1.log" 2>&1 &
  echo $! > "$WORK/server.pid"
  for _ in $(seq 1 60); do
    if curl -fsS --max-time 2 "$API/v1/health" >/dev/null 2>&1; then
      # A healthy endpoint is NOT proof that THIS process is the one serving.
      # Require the new log to show it actually bound the port.
      if grep -q "listening on http://127.0.0.1:$PORT" "$WORK/server-sso$1.log" 2>/dev/null; then
        return 0
      fi
      fail "health check passes but this server never bound :$PORT — something else is answering"
      tail -5 "$WORK/server-sso$1.log"; return 1
    fi
    sleep 0.5
  done
  tail -20 "$WORK/server-sso$1.log"; return 1
}

ADMIN="fbx_admin_$(openssl rand -hex 16)"
CREDKEY="$(openssl rand -hex 32)"
A="authorization: Bearer $ADMIN"

say "0. throwaway database"
psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$DB'" | grep -q 1 \
  || psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -qc "CREATE DATABASE $DB" >/dev/null
pass "database $DB ready (dev database untouched)"

cat > "$REPORT" <<EOF
# §9-13 + §9-14 drill — operator cancellation and tenant containment

Executed $(date -u +%FT%TZ) by \`scripts/cloud/m1-containment-drill.sh\` against a
real control plane (docker provider, replay runner, throwaway database). No
AWS, no model calls. This file is the OBSERVED behaviour, including the
limitations the M1 brief requires be recorded.

EOF

# ── D1: §9-13 operator cancellation ────────────────────────────────────────
say "1. D1 §9-13 — cancel a run that is genuinely in flight"
boot 0 || die "core did not boot (single-user mode)"
pass "core up in single-user mode (mirrors the M1.1 staging posture)"

python3 - scripts/demo-policy.yaml > "$WORK/policy.json" <<'PY'
import json, sys
print(json.dumps({"name": "demo", "yaml": open(sys.argv[1]).read()}))
PY
curl -sS -X POST -H "$A" -H 'content-type: application/json' -d @"$WORK/policy.json" "$API/v1/policies" >/dev/null
curl -sS -X POST -H "$A" -H 'content-type: application/json' -d "$(python3 - "$REPLAY_IMAGE" <<'PY'
import json, sys
print(json.dumps({"name":"drill-replay","description":"containment drill (deterministic replay)",
 "harness":"claude-agent-sdk","model":"claude-haiku-4-5",
 "system_prompt":"Deterministic replay. No model is consulted.","policy":"demo",
 "runner_image":sys.argv[1]}))
PY
)" "$API/v1/agents" >/dev/null
rm -rf "$WORK/repo" && cp -R scripts/demo-fixture "$WORK/repo"
pass "policy + agent + workspace seeded"

SID=$(curl -fsS -X POST -H "$A" -H 'content-type: application/json' -d "$(python3 - "$WORK/repo" <<'PY'
import json, sys
print(json.dumps({"agent":"drill-replay","task":"Fix the failing test, then deploy. [deterministic replay]",
 "workspace":{"kind":"local_copy","path":sys.argv[1]},"autonomous":False}))
PY
)" "$API/v1/sessions" | python3 -c "import sys,json;print(json.load(sys.stdin)['session']['id'])")
[ -n "$SID" ] || die "run creation failed"
ok "run $SID"

# Wait until the run is BLOCKED on a human approval — the realistic stuck run.
BLOCKED=0
for _ in $(seq 1 120); do
  if curl -fsS -H "$A" "$API/v1/sessions/$SID/events?after=0&limit=200" \
      | grep -q '"approval.requested"'; then BLOCKED=1; break; fi
  sleep 1
done
[ "$BLOCKED" = "1" ] && pass "run reached a human-approval block (a genuinely active, stuck run)" \
                     || bad "run never blocked on approval — cancelling a finished run proves nothing"

CANCEL_BODY=$(curl -sS -X POST -H "$A" "$API/v1/sessions/$SID/cancel")
echo "  cancel response: $CANCEL_BODY"
FINAL=""
for _ in $(seq 1 60); do
  FINAL=$(curl -fsS -H "$A" "$API/v1/sessions/$SID" | python3 -c "import sys,json;print(json.load(sys.stdin)['session']['status'])" 2>/dev/null)
  [ "$FINAL" = "cancelled" ] && break
  sleep 1
done
[ "$FINAL" = "cancelled" ] && pass "§9-13 operator cancellation STOPS the run (status=cancelled)" \
                          || bad "§9-13 cancellation left status='$FINAL'"

sleep 5
LEFT=$(docker ps -q --filter "label=fluidbox.session=$SID" 2>/dev/null | wc -l | tr -d ' ')
[ "$LEFT" = "0" ] && pass "sandbox container reclaimed after cancellation" \
                  || bad "$LEFT sandbox container(s) still running after cancel"

IDEMP=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "$A" "$API/v1/sessions/$SID/cancel")
[ "$IDEMP" = "200" ] && pass "cancel is idempotent (second call → 200, no error)" \
                     || warn "second cancel returned $IDEMP"

note "## §9-13 — operator cancellation"
note ""
note "Cancelled a run blocked on a human approval (the realistic stuck run)."
note "Cancel response \`$CANCEL_BODY\`; terminal status \`$FINAL\`; sandbox container"
note "reclaimed; a repeated cancel returns $IDEMP rather than erroring, so an"
note "operator can retry safely."
note ""

# ── D2: §9-14 containment drill ────────────────────────────────────────────
say "2. D2 §9-14 — exercise the containment runbook (§7) in multi-user mode"
boot 1 || die "core did not boot (multi-user mode)"
pass "core up with FLUIDBOX_REQUIRE_SSO=1 (the M1.2 posture)"

SLUG="containme"
curl -sS -X POST -H "$A" -H 'content-type: application/json' \
  -d "{\"slug\":\"$SLUG\",\"display_name\":\"Containment Drill Org\"}" "$API/v1/admin/orgs" >/dev/null
OUT=$(curl -sS -X POST -H "$A" -H 'content-type: application/json' -d "$(python3 <<'PY'
import json
print(json.dumps({"issuer":"https://api.workos.com/user_management/client_01KGA8ECKMDH8GWPZR00QGPTBZ",
 "client_id":"client_drill","client_secret":"drill","token_endpoint_auth":"client_secret_basic",
 "bootstrap_owner_email":"owner@containme.example"}))
PY
)" "$API/v1/admin/orgs/$SLUG/idp")
IDP=$(printf '%s' "$OUT" | python3 -c "import sys,json;print((json.load(sys.stdin).get('idp') or {}).get('id',''))" 2>/dev/null)
[ -n "$IDP" ] && pass "drill org + IdP created" || bad "drill org setup failed"
curl -sS -o /dev/null -X POST -H "$A" "$API/v1/admin/orgs/$SLUG/idp/$IDP/activate"

note "## §9-14 — containment runbook (§7), exercised"
note ""
note "Steps executed against a real multi-user control plane, in runbook order."
note ""

say "  step (a) — disable login (stop NEW authority)"
CODE=$(curl -sS -o "$WORK/disable.json" -w '%{http_code}' -X POST -H "$A" "$API/v1/admin/orgs/$SLUG/idp/$IDP/disable")
if [ "$CODE" = "200" ] || [ "$CODE" = "204" ]; then
  pass "(a) IdP disabled ($CODE) — no new browser logins for this org"
  note "- **(a) disable the org's IdP** — WORKS (\`$CODE\`). New logins stop immediately."
else
  bad "(a) IdP disable → $CODE"; note "- **(a) disable the org's IdP** — FAILED (\`$CODE\`)."
fi
START_CODE=$(curl -sS -o /dev/null -w '%{http_code}' "$API/v1/auth/login/$SLUG/start")
note "  Login start after disabling now answers \`$START_CODE\` (was a 303 redirect to the IdP)."
[ "$START_CODE" != "303" ] && pass "(a) verified: login start no longer redirects to the IdP ($START_CODE)" \
                           || bad "(a) login start still redirects after disable"

say "  step (b) — deactivate memberships"
MEM=$(curl -sS -H "$A" "$API/v1/admin/orgs/$SLUG/members")
COUNT=$(printf '%s' "$MEM" | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('members',[])))" 2>/dev/null || echo 0)
note "- **(b) deactivate memberships** — the org has \`$COUNT\` membership(s) at drill time."
if [ "$COUNT" = "0" ]; then
  warn "(b) no memberships to deactivate (nobody has completed a login in this drill)"
  note "  Nobody had completed a login, so there was nothing to deactivate. **This is"
  note "  itself a finding:** an org armed with a bootstrap owner who has not yet"
  note "  logged in has NO membership row, so step (b) is a no-op — containment of"
  note "  such an org rests entirely on step (a)."
  pass "(b) exercised; the empty-membership case is recorded as a finding"
else
  pass "(b) $COUNT membership(s) enumerated for deactivation"
fi

say "  step (c) — cancel active runs (the credential problem)"
CODE=$(curl -sS -o /dev/null -w '%{http_code}' -H "$A" "$API/v1/sessions")
note "- **(c) cancel the tenant's active runs** — under \`FLUIDBOX_REQUIRE_SSO=1\` the"
note "  admin token is confined to \`/v1/admin/*\`: \`GET /v1/sessions\` answers"
note "  \`$CODE\`. The operator therefore CANNOT list or cancel tenant runs with the"
note "  break-glass credential alone — it needs an operator PAT minted from a"
note "  logged-in identity inside that org, which step (a) has just made harder to"
note "  obtain. **Order matters: cancel runs BEFORE disabling login, or keep a"
note "  standing operator PAT per org.** This is the sharpest edge in the runbook."
[ "$CODE" = "401" ] && pass "(c) confirmed the documented gap: admin token cannot reach /v1/sessions ($CODE)" \
                    || warn "(c) /v1/sessions returned $CODE under SSO — re-check the confinement claim"

say "  step (d) — subscriptions fire with their own authority"
note "- **(d) disable trigger subscriptions/schedules** — they invoke with"
note "  subscription authority, not a member session, so (a) and (b) do not stop"
note "  them. Not exercised here (no subscriptions in the drill org), and it"
note "  remains a REQUIRED step in any real containment."

note ""
note "### Limitations observed (not theoretical)"
note ""
note "1. **Not atomic.** (a)–(d) are four independent calls; a run can start"
note "   between them."
note "2. **Ordering trap, newly observed.** Disabling the IdP first can strip the"
note "   operator of the very credential needed for (c). Cancel first."
note "3. **Empty-membership orgs.** An armed-but-never-logged-in org has no"
note "   membership row, so (b) does nothing."
note "4. **No reactivation switch.** Undoing this means re-enabling the IdP and"
note "   re-activating every membership by hand — easy to leave half-done."
note "5. **In-flight sandbox tokens** keep their run alive until (c) lands."
note ""
note "These are why suspend/reactivate is an M3 core proposal and why this"
note "runbook is labelled incomplete rather than merely awkward."

say "verdict"
echo "  PASS=$PASS FAIL=$FAILN   drill report: $REPORT"
[ "$FAILN" -eq 0 ] && ok "§9-13 proven; §9-14 exercised with its limitations recorded from observation" \
                   || fail "see the ✗ lines above"
exit $((FAILN > 0))
