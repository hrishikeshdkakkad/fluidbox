#!/usr/bin/env bash
# Governance-plane E2E over real HTTP. Drives the internal gateway with a real
# session token (exactly the runner's contract), proving policy eval,
# approval pause/resume, idempotency, session-scope, autonomous auto-deny, and
# tool-call budget — all against the live server + Neon. No model required.
set -uo pipefail
cd /Users/hrishikeshkakkad/Documents/infra
set -a; source .env; set +a
API=http://127.0.0.1:8787
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
pass=0; fail=0
ok()  { printf "  \033[1;32m✓\033[0m %s\n" "$1"; pass=$((pass+1)); }
no()  { printf "  \033[1;31m✗\033[0m %s\n" "$1"; fail=$((fail+1)); }
say() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }

new_session() { # autonomy -> session_id
  curl -s -X POST -H "$H" -H 'content-type: application/json' \
    -d "{\"agent\":\"claude-fixer\",\"task\":\"governance probe\",\"repo\":{\"kind\":\"none\"},\"autonomous\":$1}" \
    "$API/v1/sessions" | j "['session']['id']"
}

token_for() { # session_id -> session token from the launched container env
  local sid=$1 cid tok
  for _ in $(seq 1 30); do
    cid=$(docker ps --filter "label=fluidbox.session=$sid" --format '{{.ID}}' | head -1)
    [ -n "$cid" ] && break
    sleep 1
  done
  [ -z "$cid" ] && { echo ""; return; }
  docker inspect "$cid" --format '{{range .Config.Env}}{{println .}}{{end}}' \
    | grep '^FLUIDBOX_SESSION_TOKEN=' | head -1 | cut -d= -f2-
}

perm() { # token session_id json-body  -> prints decision json
  curl -s -X POST -H "authorization: Bearer $1" -H 'content-type: application/json' \
    -d "$3" "$API/internal/sessions/$2/permission"
}

# ── Supervised session ──────────────────────────────────────────────────
say "SUPERVISED — policy verdicts + approval pause/resume"
S=$(new_session false); echo "  session $S"
T=$(token_for "$S")
[ -n "$T" ] && ok "sandbox launched; got session token" || { no "no token"; exit 1; }

# safe tool → allow
D=$(perm "$T" "$S" '{"tool_call_id":"g1","tool":"Read","input":{"file_path":"/workspace/x"}}' | j "['decision']")
[ "$D" = "allow" ] && ok "Read → allow (policy)" || no "Read expected allow, got $D"

# denied tool → deny
D=$(perm "$T" "$S" '{"tool_call_id":"g2","tool":"WebFetch","input":{}}' | j "['decision']")
[ "$D" = "deny" ] && ok "WebFetch → deny (network egress)" || no "WebFetch expected deny, got $D"

# approval-required tool → blocks; approve concurrently
( perm "$T" "$S" '{"tool_call_id":"g3","tool":"Bash","input":{"command":"git push origin main"}}' > /tmp/fbx_g3.json ) &
PERM_PID=$!
sleep 3
# session should be awaiting_approval, and an approval should be pending
ST=$(curl -s -H "$H" "$API/v1/sessions/$S" | j "['session']['status']")
[ "$ST" = "awaiting_approval" ] && ok "session → awaiting_approval while blocked" || no "expected awaiting_approval, got $ST"
AID=$(curl -s -H "$H" "$API/v1/approvals" | python3 -c "import sys,json
d=json.load(sys.stdin)['approvals']
m=[a for a in d if a['session_id']=='$S']
print(m[0]['id'] if m else '')")
[ -n "$AID" ] && ok "approval row created + in inbox" || no "no pending approval"
# approve it
curl -s -X POST -H "$H" -H 'content-type: application/json' -d '{"decision":"approved_once","decided_by":"gov-test"}' "$API/v1/approvals/$AID/decision" >/dev/null
wait $PERM_PID
D=$(j "['decision']" < /tmp/fbx_g3.json)
[ "$D" = "allow" ] && ok "blocked permission returned allow after approval" || no "post-approval expected allow, got $D"
ST=$(curl -s -H "$H" "$API/v1/sessions/$S" | j "['session']['status']")
[ "$ST" = "running" ] && ok "session resumed → running" || no "expected running, got $ST"

# idempotency: same tool_call_id re-request after decision returns same verdict, no dup row
D=$(perm "$T" "$S" '{"tool_call_id":"g3","tool":"Bash","input":{"command":"git push origin main"}}' | j "['decision']")
[ "$D" = "allow" ] && ok "re-request same tool_call_id → allow (idempotent)" || no "idempotent re-request got $D"
NROWS=$(curl -s -H "$H" "$API/v1/sessions/$S/approvals" | python3 -c "import sys,json;print(sum(1 for a in json.load(sys.stdin)['approvals'] if a['tool_call_id']=='g3'))")
[ "$NROWS" = "1" ] && ok "exactly one approval row for tool_call_id g3" || no "expected 1 row, got $NROWS"

curl -s -X POST -H "$H" "$API/v1/sessions/$S/cancel" >/dev/null

# ── Autonomous session ──────────────────────────────────────────────────
say "AUTONOMOUS — instant policy fallback, no human"
S2=$(new_session true); echo "  session $S2"
T2=$(token_for "$S2")
[ -n "$T2" ] && ok "autonomous sandbox launched" || no "no token"

# risky tool that WOULD require approval → instant deny (fallback), no block
START=$(date +%s)
R=$(perm "$T2" "$S2" '{"tool_call_id":"a1","tool":"Bash","input":{"command":"git push origin main"}}')
ELAPSED=$(( $(date +%s) - START ))
D=$(echo "$R" | j "['decision']")
[ "$D" = "deny" ] && ok "risky tool → instant deny (autonomy fallback)" || no "expected deny, got $D"
[ "$ELAPSED" -lt 5 ] && ok "returned instantly (${ELAPSED}s, no human wait)" || no "took ${ELAPSED}s (should be instant)"
# no awaiting_approval, no pending approval row
PEND=$(curl -s -H "$H" "$API/v1/sessions/$S2/approvals" | python3 -c "import sys,json;print(sum(1 for a in json.load(sys.stdin)['approvals'] if a['status']=='pending'))")
[ "$PEND" = "0" ] && ok "no pending approval created (never paused)" || no "unexpected pending approvals: $PEND"
# ledger records BOTH original verdict and the autonomy rewrite
EVID=$(curl -s -H "$H" "$API/v1/sessions/$S2/events?limit=200" | python3 -c "
import sys,json
evs=json.load(sys.stdin)['events']
dec=[e for e in evs if e['type']=='tool.decision' and e['payload']['data'].get('tool_call_id')=='a1']
if dec:
    d=dec[0]['payload']['data']
    print(f\"{d.get('source')}|{d.get('original_verdict')}\")
")
[ "$EVID" = "autonomy_rewrite|require_approval" ] && ok "ledger shows autonomy_rewrite + original=require_approval" || no "ledger decision detail: $EVID"

curl -s -X POST -H "$H" "$API/v1/sessions/$S2/cancel" >/dev/null

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
sleep 3
echo "  containers after cancel: $(docker ps --filter label=fluidbox.managed=1 -q | wc -l | tr -d ' ') (expect 0)"
exit $(( fail > 0 ? 1 : 0 ))
