#!/usr/bin/env bash
# Phase 1 acceptance — connected git workspaces (design doc §12 Phase 1):
#   • workspace resolution precedence (revision default vs explicit override)
#   • exact ref + exact commit checkout, frozen into the RunSpec
#   • workspace-init failure terminates before model spend
#   • diff capture + idempotent per-session workspace cleanup
#   • API validation (malformed workspaces rejected)
#   • live: an agent fixes a bug inside a cloned git workspace; the remote
#     repository is never modified (self-skips without a key/gateway)
# Uses a local file:// fixture so the clone path runs without GitHub.
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker python3 curl git cargo
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
CT="content-type: application/json"
DATA_DIR="${FLUIDBOX_DATA_DIR:-$ROOT/data}"
case "$DATA_DIR" in /*) ;; *) DATA_DIR="$ROOT/${DATA_DIR#./}" ;; esac

if ! port_in_use; then
  cargo build -q -p fluidbox-server || exit 1
  trap 'stop_server' EXIT
  start_server || exit 1
fi

sfield() { curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']$2"; }
post_status() { curl -s -o /tmp/fbx-gitws-body.json -w "%{http_code}" -X POST -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }

wait_terminal() { # session [deadline_secs]
  local deadline=$(( $(date +%s) + ${2:-240} )) st=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    st=$(sfield "$1" "['status']")
    case "$st" in completed|failed|cancelled|budget_exceeded) echo "$st"; return 0 ;; esac
    sleep 3
  done
  echo "timeout(last=$st)"; return 1
}

say "FIXTURE — local git repo served over file://"
FX=$(mktemp -d "${TMPDIR:-/tmp}/fbx-gitws.XXXXXX")
git -C "$FX" init -q -b main
git -C "$FX" config user.email e2e@fluidbox.dev
git -C "$FX" config user.name fbx-e2e
cat > "$FX/calculator.py" <<'EOF'
def add(a, b):
    return a + b


def multiply(a, b):
    return a + b
EOF
cat > "$FX/test_calculator.py" <<'EOF'
import unittest

from calculator import add, multiply


class TestCalculator(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_multiply(self):
        self.assertEqual(multiply(2, 3), 6)


if __name__ == "__main__":
    unittest.main()
EOF
git -C "$FX" add -A
git -C "$FX" commit -qm c1
SHA1=$(git -C "$FX" rev-parse HEAD)
git -C "$FX" branch feature          # feature pinned at c1
echo "# readme" > "$FX/README.md"
git -C "$FX" add -A
git -C "$FX" commit -qm c2
SHA2=$(git -C "$FX" rev-parse HEAD)
URL="file://$FX"
ok "fixture repo ready (main=$( echo "$SHA2" | cut -c1-8 ), feature=$( echo "$SHA1" | cut -c1-8 ))"

say "AGENT — default workspace stored on the revision"
AGENT="git-ws-agent-$$"
CODE=$(post_status "/agents" "{\"name\":\"$AGENT\",\"policy\":\"default\",
  \"default_workspace\":{\"kind\":\"git_repository\",\"clone_url\":\"$URL\",\"ref\":\"feature\"}}")
[ "$CODE" = "200" ] && ok "agent created with git default workspace" || no "agent create returned $CODE: $(cat /tmp/fbx-gitws-body.json)"
DW_URL=$(cat /tmp/fbx-gitws-body.json | j "['revision']['default_workspace']['clone_url']")
[ "$DW_URL" = "$URL" ] && ok "revision froze the default workspace" || no "default_workspace not on revision (got '$DW_URL')"

# Derivation-only check: owner/name without a connection → github clone URL.
CODE=$(post_status "/agents" "{\"name\":\"$AGENT-derived\",\"policy\":\"default\",
  \"default_workspace\":{\"kind\":\"git_repository\",\"repository\":\"octo/hello\"}}")
DERIVED=$(cat /tmp/fbx-gitws-body.json | j "['revision']['default_workspace']['clone_url']")
[ "$DERIVED" = "https://github.com/octo/hello.git" ] \
  && ok "owner/name derives the github clone URL" || no "derived clone_url wrong: '$DERIVED'"

say "VALIDATION — malformed workspaces are rejected before anything runs"
CODE=$(post_status "/sessions" "{\"agent\":\"$AGENT\",\"task\":\"x\",\"workspace\":{\"kind\":\"git_repository\"}}")
[ "$CODE" = "400" ] && ok "git workspace without url/repository → 400" || no "wanted 400, got $CODE"
CODE=$(post_status "/sessions" "{\"agent\":\"$AGENT\",\"task\":\"x\",
  \"workspace\":{\"kind\":\"scratch\"},\"repo\":{\"kind\":\"none\"}}")
[ "$CODE" = "400" ] && ok "workspace + legacy repo together → 400" || no "wanted 400, got $CODE"
CODE=$(post_status "/sessions" "{\"agent\":\"$AGENT\",\"task\":\"x\",
  \"workspace\":{\"kind\":\"git_repository\",\"clone_url\":\"$URL\",\"commit_sha\":\"xyz\"}}")
[ "$CODE" = "400" ] && ok "malformed commit_sha → 400" || no "wanted 400, got $CODE"
CODE=$(post_status "/sessions" "{\"agent\":\"$AGENT\",\"task\":\"x\",
  \"workspace\":{\"kind\":\"git_repository\",\"connection_id\":\"00000000-0000-0000-0000-000000000000\",\"repository\":\"o/r\"}}")
[ "$CODE" = "400" ] && ok "unknown connection → 400" || no "wanted 400, got $CODE"
CODE=$(post_status "/sessions" "{\"agent\":\"$AGENT\",\"task\":\"x\",
  \"workspace\":{\"kind\":\"git_repository\",\"repository\":\"no-slash\"}}")
[ "$CODE" = "400" ] && ok "malformed repository name → 400" || no "wanted 400, got $CODE"

say "RUN A — revision default applies (precedence: no workspace sent)"
CODE=$(post_status "/sessions" "{\"agent\":\"$AGENT\",\"task\":\"Do nothing. Immediately report that you are done.\"}")
SA=$(cat /tmp/fbx-gitws-body.json | j "['session']['id']")
[ "$CODE" = "200" ] && [ -n "$SA" ] && ok "run started without a workspace input" || { no "session create failed ($CODE)"; exit 1; }
FROZEN_KIND=$(cat /tmp/fbx-gitws-body.json | j "['session']['repo_source']['kind']")
FROZEN_REF=$(cat /tmp/fbx-gitws-body.json | j "['session']['repo_source']['ref']")
[ "$FROZEN_KIND" = "git_repository" ] && [ "$FROZEN_REF" = "feature" ] \
  && ok "frozen workspace = revision default (git@feature)" || no "frozen repo_source wrong: kind=$FROZEN_KIND ref=$FROZEN_REF"

FINAL_A=$(wait_terminal "$SA" 240) || true
case "$FINAL_A" in
  completed|failed) ok "run A terminal ($FINAL_A — live key optional here)" ;;
  *) no "run A did not reach terminal: $FINAL_A" ;;
esac
BC=$(sfield "$SA" "['base_commit']")
[ "$BC" = "$SHA1" ] && ok "checked out the exact ref head (base=$(echo "$BC" | cut -c1-8) = feature)" \
  || no "base_commit '$BC' ≠ feature head $SHA1"
DIFF_N=$(curl -s -H "$H" "$API/v1/sessions/$SA/artifacts" | python3 -c "
import sys, json
print(len([a for a in json.load(sys.stdin)['artifacts'] if a['kind'] == 'diff']))")
[ "${DIFF_N:-0}" -ge 1 ] && ok "diff artifact captured at finalize" || no "no diff artifact"
[ ! -d "$DATA_DIR/workspaces/$SA" ] && ok "per-session workspace cleaned up" \
  || no "workspace dir still present: $DATA_DIR/workspaces/$SA"
git -C "$FX" diff --quiet && [ "$(git -C "$FX" rev-parse HEAD)" = "$SHA2" ] \
  && ok "remote (fixture) repository untouched" || no "FIXTURE REPO WAS MODIFIED"

say "RUN B — explicit override wins + exact commit pin"
CODE=$(post_status "/sessions" "{\"agent\":\"$AGENT\",\"task\":\"Do nothing. Immediately report that you are done.\",
  \"workspace\":{\"kind\":\"git_repository\",\"clone_url\":\"$URL\",\"ref\":\"main\",\"commit_sha\":\"$SHA1\"}}")
SB=$(cat /tmp/fbx-gitws-body.json | j "['session']['id']")
[ "$CODE" = "200" ] && [ -n "$SB" ] && ok "run started with explicit workspace override" || { no "session create failed ($CODE)"; exit 1; }
OV_SHA=$(cat /tmp/fbx-gitws-body.json | j "['session']['repo_source']['commit_sha']")
[ "$OV_SHA" = "$SHA1" ] && ok "override frozen into RunSpec (not the revision default)" || no "frozen commit_sha wrong: $OV_SHA"
FINAL_B=$(wait_terminal "$SB" 240) || true
BCB=$(sfield "$SB" "['base_commit']")
[ "$BCB" = "$SHA1" ] && ok "exact commit checked out (immune to branch movement)" \
  || no "base_commit '$BCB' ≠ pinned $SHA1 (terminal=$FINAL_B)"

say "RUN C — workspace failure stops the run before model spend"
CODE=$(post_status "/sessions" "{\"agent\":\"$AGENT\",\"task\":\"x\",
  \"workspace\":{\"kind\":\"git_repository\",\"clone_url\":\"file:///nonexistent/fbx-$$\"}}")
SC=$(cat /tmp/fbx-gitws-body.json | j "['session']['id']")
FINAL_C=$(wait_terminal "$SC" 90) || true
[ "$FINAL_C" = "failed" ] && ok "bad clone URL → failed (during initializing)" || no "wanted failed, got $FINAL_C"
COST_C=$(curl -s -H "$H" "$API/v1/sessions/$SC/cost" | j "['usage']['cost_usd']")
python3 -c "import sys; sys.exit(0 if float('${COST_C:-0}' or 0) == 0 else 1)" \
  && ok "zero model spend on workspace failure" || no "cost recorded on failed init: \$$COST_C"
[ ! -d "$DATA_DIR/workspaces/$SC" ] && ok "failed clone left no partial workspace" \
  || no "partial workspace left behind"

say "LIVE — agent fixes a bug inside a cloned git workspace"
if [ "${E2E_SKIP_LIVE:-0}" = "1" ] || [ -z "${ANTHROPIC_API_KEY:-}" ] \
   || ! curl -fsS -m 3 http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1; then
  echo "  SKIP: live tier needs ANTHROPIC_API_KEY + gateway (E2E_SKIP_LIVE=${E2E_SKIP_LIVE:-0})"
else
  cargo build -q -p fluidbox-cli || exit 1
  OUT=$("$ROOT/target/debug/fluidbox" run --agent claude-fixer \
    --task "The unit tests fail. Run python3 -m unittest -v to see the failure, fix the bug in the source file, then re-run python3 -m unittest -v and confirm everything passes." \
    --git-url "$URL" --git-ref main --detach)
  SD=$(echo "$OUT" | sed -n 's/.*session \([0-9a-f-]\{36\}\).*/\1/p')
  [ -n "$SD" ] && ok "live git-workspace run started ($SD)" || no "no session id from CLI"
  FINAL_D=$(wait_terminal "$SD" 420) || true
  [ "$FINAL_D" = "completed" ] && ok "live run completed" || no "live run terminal: $FINAL_D"
  PATCH=$(curl -s -H "$H" "$API/v1/sessions/$SD/artifacts" | python3 -c "
import sys, json
d = [a for a in json.load(sys.stdin)['artifacts'] if a['kind'] == 'diff']
print(d[0]['content'] if d else '')")
  echo "$PATCH" | grep -q 'a \* b' && ok "diff contains the multiply fix" || no "diff lacks the fix"
  git -C "$FX" diff --quiet && [ "$(git -C "$FX" rev-parse HEAD)" = "$SHA2" ] \
    && ok "remote repository untouched by the live run" || no "FIXTURE REPO WAS MODIFIED"
fi

rm -rf "$FX"

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
