#!/usr/bin/env bash
# Codex live tier (§12): a real codex agent runs a task end-to-end through the
# facade → LiteLLM → OpenAI, governed by /permission. Asserts: completed,
# non-zero usage+cost (the facade OpenAI meter), the ledger shows canonical
# tool.requested (Bash/MultiEdit) with no leaked secrets, and a benign exec
# gated (the strict force-ask parity). Requires OPENAI_API_KEY (caller checks).
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
lp=0; lf=0
lok(){ printf "    \033[1;32m✓\033[0m %s\n" "$1"; lp=$((lp+1)); }
lno(){ printf "    \033[1;31m✗\033[0m %s\n" "$1"; lf=$((lf+1)); }

# A scratch workspace with a file to read + a failing thing to reason about.
WS="$(cd "$(dirname "$0")/.." && pwd)/scratch-codex/live-ws"; mkdir -p "$WS"
echo "the answer is 42" > "$WS/NOTE.txt"

curl -s -X POST -H "$H" -H 'content-type: application/json' \
  -d '{"name":"codex-live","harness":"codex","policy":"default"}' "$API/v1/agents" >/dev/null 2>&1 || true

SID=$(curl -s -X POST -H "$H" -H 'content-type: application/json' -d "{
  \"agent\":\"codex-live\",\"autonomous\":true,
  \"task\":\"Read NOTE.txt with a shell command and reply with exactly the number it contains.\",
  \"repo\":{\"kind\":\"local_copy\",\"path\":\"$WS\"},
  \"budgets\":{\"max_cost_usd\":0.25,\"max_tool_calls\":20}
}" "$API/v1/sessions" | j "['session']['id']")
[ -n "$SID" ] && lok "codex live session created ($SID)" || { lno "session create failed"; exit 1; }

for _ in $(seq 1 90); do
  ST=$(curl -s -H "$H" "$API/v1/sessions/$SID" | j "['session']['status']")
  case "$ST" in completed|failed|budget_exceeded|cancelled) break;; esac; sleep 3
done
[ "$ST" = "completed" ] && lok "codex run completed" || lno "codex run status: $ST"

EV=$(curl -s -H "$H" "$API/v1/sessions/$SID/events?limit=500")
# Read the two verdict lines in the PARENT shell via process substitution.
# A `python3 -c … | { read a; read b; lok/lno … }` tail runs the group in a
# SUBSHELL, so its lp/lf increments are discarded and these two assertions
# could print ✗ yet never fail the run.
{ IFS= read -r CANON; IFS= read -r DECIDED; } < <(python3 -c "
import sys,json; evs=json.load(sys.stdin)['events']
treq=[e for e in evs if e['type']=='tool.requested']
tdec=[e for e in evs if e['type']=='tool.decision']
canonical=all(e['payload']['data'].get('tool') in ('Bash','Read','Edit','Write','MultiEdit','Glob','Grep','LS') or e['payload']['data'].get('tool','').startswith('mcp__') for e in treq)
print('CANON' if (treq and canonical) else 'NOCANON')
print('DECIDED' if tdec else 'NODEC')
" <<<"$EV")
[ "$CANON" = "CANON" ] && lok "codex tool calls ledgered as CANONICAL names" || lno "non-canonical/absent tool.requested"
[ "$DECIDED" = "DECIDED" ] && lok "tool.decision events present (gated)" || lno "no tool.decision"

# usage/cost via the facade OpenAI meter
UC=$(curl -s -H "$H" "$API/v1/sessions/$SID/cost")
NZ=$(echo "$UC" | python3 -c "import sys,json;d=json.load(sys.stdin)['usage'];print(1 if (d.get('output_tokens',0)>0 and d.get('cost_usd',0)>0) else 0)" 2>/dev/null)
[ "$NZ" = "1" ] && lok "facade metered non-zero usage + cost (OpenAI Responses)" || lno "usage/cost: $(echo "$UC" | j "['usage']")"

# no leaked secrets in the ledger. Grep a herestring (NOT a pipe: a pipeline
# element that expands an unset var under `set -u` dies in its subshell, the
# `&&` is skipped, and `|| lok` fires — a guaranteed vacuous pass). The
# Redactor scrubs fbx_sess_* → ‹redacted›, so a raw `fbx_sess_` prefix in the
# ledger IS the leak; the per-session token value is never needed here.
grep -qiE 'sk-proj-|OPENAI_API_KEY=sk|fbx_sess_[A-Za-z0-9]' <<<"$EV" \
  && lno "secret leaked in ledger!" \
  || lok "no secrets in the ledger"

printf "  live: \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$lp" "$lf"
exit $(( lf > 0 ? 1 : 0 ))
