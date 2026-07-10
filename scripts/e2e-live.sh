#!/usr/bin/env bash
# Acceptance demo A, automated: a live agent finds and fixes a failing unit
# test in a governed sandbox. Asserts completed + diff + cost + isolation.
# Self-skips (exit 0) without a key or gateway so the suite stays runnable
# offline; set E2E_SKIP_LIVE=1 to skip explicitly.
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker python3 curl git cargo
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"

if [ "${E2E_SKIP_LIVE:-0}" = "1" ]; then
  echo "  SKIP: E2E_SKIP_LIVE=1"; exit 0
fi
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "  SKIP: no ANTHROPIC_API_KEY in .env (the gateway needs it for live runs)"; exit 0
fi
if ! curl -fsS -m 3 http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1; then
  echo "  SKIP: LiteLLM gateway not reachable on :4000 (just gateway-up)"; exit 0
fi

if ! port_in_use; then
  cargo build -q -p fluidbox-server || exit 1
  trap 'stop_server' EXIT
  start_server || exit 1
fi

sstatus() { curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']['status']"; }

say "DEMO A — live agent fixes a failing test"
TMP_REPO=$(mktemp -d "${TMPDIR:-/tmp}/fbx-demoa.XXXXXX")
cat > "$TMP_REPO/calculator.py" <<'EOF'
def add(a, b):
    return a + b


def multiply(a, b):
    return a + b
EOF
cat > "$TMP_REPO/test_calculator.py" <<'EOF'
import unittest

from calculator import add, multiply


class TestCalculator(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_multiply(self):
        self.assertEqual(multiply(2, 3), 6)
        self.assertEqual(multiply(4, 5), 20)


if __name__ == "__main__":
    unittest.main()
EOF
git -C "$TMP_REPO" init -q
git -C "$TMP_REPO" add -A
git -C "$TMP_REPO" -c user.email=e2e@fluidbox.dev -c user.name=fbx-e2e commit -qm fixture
ORIG_SHA=$(git -C "$TMP_REPO" rev-parse HEAD)

cargo build -q -p fluidbox-cli || exit 1
OUT=$("$ROOT/target/debug/fluidbox" run --agent claude-fixer \
  --task "The unit tests fail. Run python3 -m unittest -v to see the failure, fix the bug in the source file, then re-run python3 -m unittest -v and confirm everything passes." \
  --repo "$TMP_REPO" --detach)
echo "  $OUT"
S=$(echo "$OUT" | sed -n 's/.*session \([0-9a-f-]\{36\}\).*/\1/p')
[ -n "$S" ] && ok "run started from the CLI (session $S)" || { no "no session id in CLI output"; exit 1; }

FINAL=""
DEADLINE=$(( $(date +%s) + 420 ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  ST=$(sstatus "$S")
  case "$ST" in
    completed|failed|cancelled|budget_exceeded) FINAL=$ST; break ;;
    awaiting_approval)
      PEND=$(curl -s -H "$H" "$API/v1/sessions/$S/approvals" | python3 -c "
import sys, json
a = [x for x in json.load(sys.stdin)['approvals'] if x['status'] == 'pending']
print(a[0]['summary'] if a else '')")
      no "agent paused for approval — demo A expects none. Pending: '$PEND' (allow_prefixes candidate?)"
      curl -s -X POST -H "$H" "$API/v1/sessions/$S/cancel" >/dev/null
      exit 1 ;;
  esac
  sleep 5
done
if [ "$FINAL" = "completed" ]; then
  ok "session completed"
else
  no "terminal state: ${FINAL:-timeout-after-420s} (wanted completed)"
  echo "  last events:"
  curl -s -H "$H" "$API/v1/sessions/$S/events?limit=200" | python3 -c "
import sys, json
for e in json.load(sys.stdin)['events'][-8:]:
    print('   ', e['type'], json.dumps(e['payload']['data'])[:140])"
  exit 1
fi

AID=$(curl -s -H "$H" "$API/v1/sessions/$S/artifacts" | python3 -c "
import sys, json
d = [a for a in json.load(sys.stdin)['artifacts'] if a['kind'] == 'diff']
print(d[0]['id'] if d else '')")
[ -n "$AID" ] && ok "diff artifact present" || no "no diff artifact"
PATCH=$(curl -s -H "$H" "$API/v1/sessions/$S/artifacts/$AID" | j "['artifact']['content']")
echo "$PATCH" | grep -q "calculator.py" && ok "diff touches calculator.py" || no "diff does not touch calculator.py"
echo "$PATCH" | grep -q 'a \* b' && ok "diff contains the multiply fix" || no "diff lacks 'a * b': $(echo "$PATCH" | head -3)"

COST=$(curl -s -H "$H" "$API/v1/sessions/$S/cost" | j "['usage']['cost_usd']")
python3 -c "import sys; sys.exit(0 if float('${COST:-0}' or 0) > 0 else 1)" \
  && ok "cost ledgered (\$${COST})" || no "no cost recorded (gateway usage callback broken?)"
TOOLS=$(curl -s -H "$H" "$API/v1/sessions/$S/cost" | j "['tool_calls']")
[ "${TOOLS:-0}" -ge 1 ] 2>/dev/null && ok "tool calls ledgered ($TOOLS)" || no "no tool.requested events"

[ -z "$(git -C "$TMP_REPO" status --porcelain)" ] && [ "$(git -C "$TMP_REPO" rev-parse HEAD)" = "$ORIG_SHA" ] \
  && ok "original repo untouched (isolation)" || no "ORIGINAL REPO WAS MODIFIED"
grep -q "return a + b" "$TMP_REPO/calculator.py" \
  && ok "original still has the bug (agent worked on the copy)" || no "original source changed"

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
