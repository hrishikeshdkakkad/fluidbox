#!/usr/bin/env bash
# The MANDATORY TOOL GATE acceptance.
#
# Every other suite proves the gate DECIDES correctly once it is asked. This one
# proves it is ASKED — the property that silently broke. The Claude Agent SDK's
# `canUseTool` is not an interception point: the SDK turns it into
# `--permission-prompt-tool stdio` on the Claude Code CLI it spawns, and the CLI
# consults that prompt tool only for calls it decides to ASK about. Everything
# it auto-approves first (its read-only and safe-command classifications) ran
# with the control plane never seeing it. Measured pre-fix on the shipped image:
# an ordinary workload produced FOUR tool calls and ZERO gate consultations.
#
# governance-e2e.sh cannot catch that class: it kills the real runner and drives
# the contract itself, so it only exercises the half that always worked. Hence
# PHASE 1 here, which runs a REAL agent against the REAL Docker provider and
# asserts on an UNPREDICTABLE NONCE — the task asks for
# `printf '<nonce>' | sha256sum`, the exact shape that bypassed the gate, and
# the digest of a nonce minted seconds earlier cannot be guessed or replayed.
# Digest in the timeline ⇒ the command really ran. Digest absent ⇒ it did not.
#
# PHASES 2-4 are the fail-closed properties. They drive /permission directly
# with the sandbox's own tool-audience token and KILL the runner first
# (`silence_runner`, the governance-e2e pattern) — deliberately, so they cost no
# model tokens and cannot flake on talking a live model into misbehaving.
#
# Owns nothing: expects a control plane already running at FLUIDBOX_API_URL.
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker curl python3 openssl shasum
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
CT="content-type: application/json"

if ! port_in_use; then
  echo "  SKIP: no control plane at $API (start one with: just server)"; exit 0
fi

jq_get() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
sstatus() { curl -s -H "$H" "$API/v1/sessions/$1" | jq_get "d['session']['status']"; }
events()  { curl -s -H "$H" "$API/v1/sessions/$1/events?limit=300"; }
perm() { curl -s -X POST -H "authorization: Bearer $1" -H "$CT" -d "$3" \
           "$API/internal/sessions/$2/permission"; }

# Is a model reachable? The live phase needs one; the rest deliberately do not,
# so an exhausted key degrades this suite to its fail-closed half instead of
# reporting failures that are really billing.
model_available() {
  [ -n "${ANTHROPIC_API_KEY:-}" ] || return 1
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -m 25 \
    "${LLM_UPSTREAM_URL:-http://127.0.0.1:4000}/v1/messages" \
    -H "authorization: Bearer ${LITELLM_MASTER_KEY:-}" -H "$CT" \
    -d '{"model":"claude-haiku-4-5","max_tokens":4,"messages":[{"role":"user","content":"hi"}]}')
  [ "$code" = "200" ]
}

token_for() { # session_id [env-var] -> token from the live sandbox
  local sid=$1 var=${2:-FLUIDBOX_TOOL_TOKEN} cid
  for _ in $(seq 1 60); do
    cid=$(docker ps --filter "label=fluidbox.session=$sid" --format '{{.ID}}' | head -1)
    if [ -n "$cid" ]; then
      docker inspect "$cid" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
        | sed -n "s/^$var=//p" | head -1 && return 0
    fi
    sleep 1
  done
  return 1
}
# Kill the real runner so it can neither race our choreography nor spend model
# tokens. The session stays `running` (no /result posted) until the heartbeat
# watchdog terminalizes it, which is the window these phases drive.
silence_runner() {
  local cid
  cid=$(docker ps -q --filter "label=fluidbox.session=$1" | head -1)
  [ -n "$cid" ] && docker kill "$cid" >/dev/null 2>&1
}

mkpolicy() { curl -s -o /dev/null -X POST -H "$H" -H "$CT" \
  -d "$(python3 -c "import json,sys;print(json.dumps({'name':sys.argv[1],'yaml':open(sys.argv[2]).read()}))" "$1" "$2")" \
  "$API/v1/policies"; }
mkagent() { curl -s -o /dev/null -X POST -H "$H" -H "$CT" -d "$(python3 -c "
import json,sys
b={'name':sys.argv[1],'harness':'claude-agent-sdk','policy':sys.argv[2],'model':'claude-haiku-4-5'}
if len(sys.argv)>3 and sys.argv[3]: b['runner_image']=sys.argv[3]
print(json.dumps(b))" "$1" "$2" "${3:-}")" "$API/v1/agents"; }
start_run() { curl -s -X POST -H "$H" -H "$CT" -d "$(python3 -c "
import json,sys
print(json.dumps({'agent':sys.argv[1],'task':sys.argv[2],'repo':{'kind':'none'},
                  'autonomous':sys.argv[3]=='true'}))" "$1" "$2" "$3")" \
  "$API/v1/sessions" | jq_get "d['session']['id']"; }
wait_status() { local s=$1 want=$2 secs=${3:-180} st
  for _ in $(seq 1 "$secs"); do
    st=$(sstatus "$s"); [ "$st" = "$want" ] && return 0
    case "$st" in completed|failed|cancelled|budget_exceeded) return 1 ;; esac
    sleep 1
  done; return 1; }

# ── policies (both deny anything unmatched: an unclassified tool must never
#    slip through on a permissive default) ───────────────────────────────────
POLICY_HEAD='defaults:
  tool_action: deny
budgets:
  max_wall_clock_secs: 900
  max_tokens: 300000
  max_cost_usd: 0.50
  max_tool_calls: 20
autonomy:
  permitted: true
  on_approval_rule: deny
'
READ_ONLY='  - match: ["Read", "Glob", "Grep", "LS", "TodoWrite", "Task", "NotebookRead", "ToolSearch"]
    action: allow
'
policy_file() { # name ttl bash-action risk
  { echo "name: $1"; echo "$POLICY_HEAD";
    echo 'approvals:'; echo "  default_ttl_secs: $2"; echo '  scope: once'; echo '  timeout_action: deny';
    echo 'tools:'; echo "$READ_ONLY";
    echo '  - match: ["Bash"]'; echo "    action: $3"; echo "    risk: $4";
  } > "${TMPDIR:-/tmp}/$1.yaml"; echo "${TMPDIR:-/tmp}/$1.yaml"; }

mkpolicy tg-deny    "$(policy_file tg-deny 300 deny 'shell denied for the tool-gate acceptance')"
mkpolicy tg-approve "$(policy_file tg-approve 600 approve 'every shell command needs a human decision')"
mkpolicy tg-expire  "$(policy_file tg-expire 5 approve 'expires fast on purpose')"
mkagent tg-deny-agent    tg-deny    "${FLUIDBOX_SANDBOX_IMAGE:-}"
mkagent tg-approve-agent tg-approve "${FLUIDBOX_SANDBOX_IMAGE:-}"
mkagent tg-expire-agent  tg-expire  "${FLUIDBOX_SANDBOX_IMAGE:-}"

BASH_BODY='{"tool_call_id":"%s","tool":"Bash","input":{"command":"%s"}}'

# ═══ PHASE 1 — LIVE agent: a denied tool never executes ════════════════════
say "PHASE 1 — deny at the gate prevents execution (LIVE agent, Docker provider)"
if [ "${E2E_SKIP_LIVE:-0}" = "1" ]; then
  echo "  SKIP: E2E_SKIP_LIVE=1"
elif ! model_available; then
  echo "  SKIP: no reachable model (LLM upstream refused a 4-token probe —"
  echo "        an exhausted key or a gateway that is down). The fail-closed"
  echo "        phases below do not need one and still run."
else
  N1=$(openssl rand -hex 12); D1=$(printf '%s' "$N1" | shasum -a 256 | cut -d' ' -f1)
  S1=$(start_run tg-deny-agent \
    "Run this exact shell command with the Bash tool and report its output verbatim: printf '$N1' | sha256sum" true)
  if [ -z "$S1" ]; then no "could not start the live run"; else
    ok "live run started (session $S1)"
    wait_status "$S1" completed 300 || true
    EV1=$(events "$S1")
    REQ=$(echo "$EV1" | python3 -c "
import sys,json;print(sum(1 for e in json.load(sys.stdin)['events'] if e['type']=='tool.requested'))")
    # THE regression assertion: pre-fix this was ZERO for exactly this command.
    [ "${REQ:-0}" -ge 1 ] \
      && ok "the gate SAW the call — $REQ tool.requested event(s)" \
      || no "ZERO tool.requested: the gate was bypassed (the original P0)"
    DEC=$(echo "$EV1" | python3 -c "
import sys,json
d=[e for e in json.load(sys.stdin)['events'] if e['type']=='tool.decision']
print(d[0]['payload']['data']['verdict'] if d else 'NONE')")
    [ "$DEC" = "deny" ] && ok "policy verdict recorded: deny" || no "expected deny, got '$DEC'"
    echo "$EV1" | grep -q "$D1" \
      && no "EXECUTED ANYWAY — the nonce digest is in the timeline despite a deny" \
      || ok "command never executed (digest of a fresh nonce appears nowhere)"
  fi
fi

# ═══ PHASE 2 — approval blocks the call until a human decides ══════════════
say "PHASE 2 — an approval holds the tool call, then releases it exactly once"
S2=$(start_run tg-approve-agent "tool gate probe" false)
T2=$(token_for "$S2")
silence_runner "$S2"
[ -n "$T2" ] && ok "sandbox tool-audience token extracted (session $S2)" || no "no sandbox token"

if [ -n "$T2" ]; then
  BODY2=$(printf "$BASH_BODY" "tg-approve-1" "git push origin main")
  OUT2="${TMPDIR:-/tmp}/tg-perm2.json"
  ( perm "$T2" "$S2" "$BODY2" > "$OUT2" ) & PERM_PID=$!

  wait_status "$S2" awaiting_approval 90 \
    && ok "session paused at awaiting_approval" \
    || no "never reached awaiting_approval (status: $(sstatus "$S2"))"

  # The ORDERING property: the runner's call has not been answered yet, so the
  # tool cannot have run. A gate that returned early here would be the bug.
  kill -0 "$PERM_PID" 2>/dev/null \
    && ok "the tool call is still blocked — no verdict issued yet" \
    || no "the gate answered before a human decided"

  AID=$(curl -s -H "$H" "$API/v1/sessions/$S2/approvals" | python3 -c "
import sys,json
a=[x for x in json.load(sys.stdin)['approvals'] if x['status']=='pending']
print(a[0]['id'] if a else '')")
  [ -n "$AID" ] && ok "a pending approval is queued for a human" || no "no pending approval row"

  APPROVED=$(curl -s -X POST -H "$H" -H "$CT" -d '{"decision":"approved_once"}' \
    "$API/v1/approvals/$AID/decision")
  echo "$APPROVED" | grep -q '"status"' \
    && ok "approval recorded by a human decision" \
    || no "approve call failed: $(echo "$APPROVED" | head -c 160)"
  wait "$PERM_PID" 2>/dev/null
  D2=$(jq_get "d['decision']" < "$OUT2")
  [ "$D2" = "allow" ] && ok "after approval the blocked call returns allow" \
    || no "post-approval decision was '$D2'"

  # Exactly once: the SAME id+input replayed adopts the recorded verdict and
  # must NOT register a second intent (that would double-count and re-decide).
  perm "$T2" "$S2" "$BODY2" > /dev/null
  CNT=$(events "$S2" | python3 -c "
import sys,json
print(sum(1 for e in json.load(sys.stdin)['events']
          if e['type']=='tool.requested'
          and e['payload']['data'].get('tool_call_id')=='tg-approve-1'))")
  [ "${CNT:-0}" = "1" ] \
    && ok "approved_once decided exactly once (a faithful replay adopts, 1 intent)" \
    || no "expected exactly 1 tool.requested for the id, got $CNT"
fi

# ═══ PHASE 3 — fail-closed properties ══════════════════════════════════════
say "PHASE 3 — the gate fails closed"
S3=$(start_run tg-approve-agent "tool gate probe" false)
T3=$(token_for "$S3")
CTRL3=$(token_for "$S3" FLUIDBOX_SESSION_TOKEN)
silence_runner "$S3"

if [ -n "$T3" ]; then
  UNK=$(perm "$T3" "$S3" '{"tool_call_id":"tg-unknown-1","tool":"TotallyMadeUpTool","input":{}}' | jq_get "d['decision']")
  [ "$UNK" = "deny" ] && ok "unknown tool → deny (policy default, never an implicit allow)" \
    || no "unknown tool returned '$UNK'"

  BAD=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "authorization: Bearer fbx_sess_not_a_real_token" -H "$CT" \
    -d "$(printf "$BASH_BODY" "tg-badtok-1" "echo hi")" \
    "$API/internal/sessions/$S3/permission")
  { [ "$BAD" = "401" ] || [ "$BAD" = "403" ]; } \
    && ok "invalid token refused ($BAD) — no verdict issued at all" \
    || no "invalid token got HTTP $BAD"

  if [ -n "$CTRL3" ]; then
    perm "$CTRL3" "$S3" "$(printf "$BASH_BODY" "tg-aud-1" "echo hi")" | grep -q wrong_audience \
      && ok "runner-control credential rejected by audience (fatal, not a deny)" \
      || no "the control token was not rejected by audience"
  fi

  # A reused id carrying DIFFERENT arguments is a protocol violation, not a
  # cache hit — otherwise an approved call could be swapped for another one.
  # Read (not Bash) on purpose: this policy makes Read an immediate allow, so
  # the pair is allow-then-deny, which proves the violation path rather than
  # two indistinguishable denies — and it never blocks on an approval.
  RP1=$(perm "$T3" "$S3" '{"tool_call_id":"tg-replay-1","tool":"Read","input":{"file_path":"/workspace/a"}}' | jq_get "d['decision']")
  [ "$RP1" = "allow" ] && ok "first use of a tool_call_id decided normally (allow)" \
    || no "expected the first Read to allow, got '$RP1'"
  RP=$(perm "$T3" "$S3" '{"tool_call_id":"tg-replay-1","tool":"Read","input":{"file_path":"/workspace/DIFFERENT"}}' | jq_get "d['decision']")
  [ "$RP" = "deny" ] && ok "same tool_call_id replayed with different input → deny" \
    || no "replay with different input returned '$RP'"

  curl -s -o /dev/null -X POST -H "$H" "$API/v1/sessions/$S3/cancel"
  for _ in $(seq 1 30); do
    case "$(sstatus "$S3")" in cancelled|failed) break ;; esac; sleep 1
  done
  # Two fail-closed shapes are correct here and which one you get is a race
  # with token revocation on the terminal transition:
  #   • a deny verdict ("session is not active"), or
  #   • an outright 401 — the terminal transition revoked the session's tokens,
  #     so no verdict is issued at all. The runner maps 401/403 at this route to
  #     a hard deny (contract.mjs::requestPermission), so the tool still cannot
  #     run. What must NEVER appear is an allow.
  CN=$(perm "$T3" "$S3" '{"tool_call_id":"tg-cancel-1","tool":"Read","input":{"file_path":"/workspace/x"}}')
  if echo "$CN" | grep -q '"decision": *"allow"'; then
    no "AFTER CANCELLATION THE GATE ALLOWED A TOOL: $CN"
  elif echo "$CN" | grep -q '"decision": *"deny"'; then
    ok "after cancellation the gate denies even a normally-allowed tool"
  elif echo "$CN" | grep -qE 'unauthorized|forbidden'; then
    ok "after cancellation the session credential is revoked (no verdict issued)"
  else
    no "post-cancel response was neither a deny nor a refusal: $(echo "$CN" | head -c 120)"
  fi
fi

# ═══ PHASE 4 — an approval that times out denies ═══════════════════════════
say "PHASE 4 — an approval that expires denies, never allows"
S4=$(start_run tg-expire-agent "tool gate probe" false)
T4=$(token_for "$S4")
silence_runner "$S4"
if [ -n "$T4" ]; then
  D4=$(perm "$T4" "$S4" "$(printf "$BASH_BODY" "tg-expire-1" "git push origin main")" | jq_get "d['decision']")
  [ "$D4" = "deny" ] && ok "expired approval → deny (timeout_action)" \
    || no "expired approval returned '$D4'"
  curl -s -o /dev/null -X POST -H "$H" "$API/v1/sessions/$S4/cancel"
fi

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
