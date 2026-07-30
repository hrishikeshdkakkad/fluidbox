#!/usr/bin/env bash
# Qwen live tier: a real qwen agent runs a task end-to-end through the facade
# → LiteLLM → DashScope, governed by /permission. Asserts: completed, THE
# DRIFT CANARY (a read produced a canonical Read tool.requested — proof the
# permissions.ask interception still holds on the pinned CLI; this is the
# invariant most likely to silently regress on a version bump), canonical
# names throughout, non-zero usage+cost from the facade chat meter, and no
# leaked secrets. Requires DASHSCOPE_API_KEY (caller checks).
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
lp=0; lf=0
lok(){ printf "    \033[1;32m✓\033[0m %s\n" "$1"; lp=$((lp+1)); }
lno(){ printf "    \033[1;31m✗\033[0m %s\n" "$1"; lf=$((lf+1)); }

WS="$(cd "$(dirname "$0")/.." && pwd)/scratch-qwen/live-ws"; mkdir -p "$WS"
echo "the answer is 42" > "$WS/NOTE.txt"

curl -s -X POST -H "$H" -H 'content-type: application/json' \
  -d '{"name":"qwen-live","harness":"qwen-code","policy":"default"}' "$API/v1/agents" >/dev/null 2>&1 || true

SID=$(curl -s -X POST -H "$H" -H 'content-type: application/json' -d "{
  \"agent\":\"qwen-live\",\"autonomous\":true,
  \"task\":\"Read NOTE.txt (use the read_file tool) and reply with exactly the number it contains.\",
  \"repo\":{\"kind\":\"local_copy\",\"path\":\"$WS\"},
  \"budgets\":{\"max_cost_usd\":0.25,\"max_tool_calls\":20}
}" "$API/v1/sessions" | j "['session']['id']")
[ -n "$SID" ] && lok "qwen live session created ($SID)" || { lno "session create failed"; exit 1; }

for _ in $(seq 1 90); do
  ST=$(curl -s -H "$H" "$API/v1/sessions/$SID" | j "['session']['status']")
  case "$ST" in completed|failed|budget_exceeded|cancelled) break;; esac; sleep 3
done
[ "$ST" = "completed" ] && lok "qwen run completed" || lno "qwen run status: $ST"

EV=$(curl -s -H "$H" "$API/v1/sessions/$SID/events?limit=500")
# Verdicts read in the PARENT shell via process substitution (a pipe tail
# would run in a subshell and discard the counters — the codex lesson).
{ IFS= read -r CANON; IFS= read -r DECIDED; IFS= read -r READCANARY; } < <(python3 -c "
import sys,json; evs=json.load(sys.stdin)['events']
treq=[e for e in evs if e['type']=='tool.requested']
tdec=[e for e in evs if e['type']=='tool.decision']
canonical=all(e['payload']['data'].get('tool') in ('Bash','Read','Edit','Write','MultiEdit','NotebookEdit','Glob','Grep','LS','TodoWrite') or e['payload']['data'].get('tool','').startswith('mcp__') for e in treq)
print('CANON' if (treq and canonical) else 'NOCANON')
print('DECIDED' if tdec else 'NODEC')
print('READGATED' if any(e['payload']['data'].get('tool')=='Read' for e in treq) else 'NOREAD')
" <<<"$EV")
[ "$CANON" = "CANON" ] && lok "qwen tool calls ledgered as CANONICAL names" || lno "non-canonical/absent tool.requested"
[ "$DECIDED" = "DECIDED" ] && lok "tool.decision events present (gated)" || lno "no tool.decision"
# THE CANARY: the task forces a read; permissions.ask must have routed it
# through canUseTool → the gate, so a canonical Read intent MUST exist.
[ "$READCANARY" = "READGATED" ] && lok "READ CANARY: read_file crossed the gate as canonical Read" \
  || lno "READ CANARY FAILED — permissions.ask interception regressed (version drift?)"

# usage/cost via the facade chat-completions meter
UC=$(curl -s -H "$H" "$API/v1/sessions/$SID/cost")
NZ=$(echo "$UC" | python3 -c "import sys,json;d=json.load(sys.stdin)['usage'];print(1 if (d.get('output_tokens',0)>0 and d.get('cost_usd',0)>0) else 0)" 2>/dev/null)
[ "$NZ" = "1" ] && lok "facade metered non-zero usage + cost (chat completions)" || lno "usage/cost: $(echo "$UC" | j "['usage']")"

# no leaked secrets in the ledger (herestring, not a pipe — subshell lesson).
grep -qiE 'DASHSCOPE_API_KEY=sk|fbx_sess_[A-Za-z0-9]' <<<"$EV" \
  && lno "secret leaked in ledger!" \
  || lok "no secrets in the ledger"

printf "  live: \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$lp" "$lf"
exit $(( lf > 0 ? 1 : 0 ))
