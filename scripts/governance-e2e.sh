#!/usr/bin/env bash
# Governance-plane E2E over real HTTP. Two halves, both against the live
# server + Neon, no model required:
#   1. the POLICY API — the Governance page's server: the tool matrix, the
#      per-tool override write/clear, and the policy-sync merge
#   2. the INTERNAL GATEWAY driven with a real session token (exactly the
#      runner's contract): policy eval, approval pause/resume, idempotency,
#      session-scope, autonomous auto-deny
# (Budget/watchdog/restart failure paths live in scripts/e2e-failures.sh.)
set -uo pipefail
cd "$(dirname "$0")/.."
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

# The script drives the runner contract itself; kill the real runner so it
# can't race our choreography (finish its probe task and complete the
# session mid-assertion) or spend model tokens.
silence_runner() {
  local cid
  cid=$(docker ps -q --filter "label=fluidbox.session=$1" | head -1)
  [ -n "$cid" ] && docker kill "$cid" >/dev/null 2>&1
}

# ── Policy API — the Governance page's server ───────────────────────────
# The dashboard is presentation-only: every fact it renders and every write
# it offers is decided HERE. Two things must never happen, both of them real
# review finds:
#
#   A. A CONDITIONAL rule cannot be flattened. A rule carrying paths/shell
#      has a verdict that depends on the path touched or the command run
#      ("allow in /workspace · deny .env · ask elsewhere"). Setting it to one
#      action would DELETE paths.deny **/.env. The server refuses — never the
#      UI alone.
#   B. policy-sync cannot silently kill a constraint. Overrides are consulted
#      BEFORE the rules, so a shell/paths block added to a rule that already
#      holds a live override could never fire — silently, forever, while the
#      page still displayed it. So upsert merges the stored overrides in and
#      validates the MERGED policy: the override survives a pristine re-POST,
#      and a yaml that would strand a constraint is refused outright.
#
# Writes go to a THROWAWAY policy carrying the seed's rule shapes (paths on
# Edit, shell on Bash, flat deny on WebFetch) — a policy with zero agents is
# a much safer subject than the seed. The seed policy is only READ here; the
# shape of its rules is pinned by fluidbox-core's `tool_matrix_of_the_seed_policy`
# / `autonomy_summary_of_the_seed_policy` tests, which parse the real yaml.
say "POLICY API — matrix, per-tool overrides, and the sync merge"
CT='content-type: application/json'
GB=/tmp/fbx-gov-body.json
post() { curl -s -o "$GB" -w "%{http_code}" -X POST    -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }
put()  { curl -s -o "$GB" -w "%{http_code}" -X PUT     -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }
del()  { curl -s -o "$GB" -w "%{http_code}" -X DELETE  -H "$H"                  "$API/v1$1"; }
get()  { curl -s -H "$H" "$API/v1$1"; }

# One matrix row, flattened for comparison: "status|action|overridable".
prow() { # policy tool
  get "/policies/$1" | python3 -c "
import sys, json
rows = json.load(sys.stdin)['matrix']
r = next((x for x in rows if x['tool'] == '$2'), None)
print('MISSING' if r is None else '%s|%s|%s' % (
    r['status']['status'], r['status'].get('action'), r['overridable']))
" 2>/dev/null
}
pver() { get "/policies/$1" | j "['policy']['version']"; }
# The API takes {name, yaml} — exactly the shape scripts/policy-sync.sh POSTs.
gov_body() { python3 -c "import json,sys;print(json.dumps({'name':'gov-e2e','yaml':sys.stdin.read()}))"; }

# 1. The seed policy's detail payload — read-only, and override-independent.
SEED=$(get "/policies/default")
FB=$(echo "$SEED" | j "['autonomy_summary']['default_fallback']")
[ "$FB" = "deny" ] && ok "seed policy: autonomy fallback is deny (human absence narrows, never widens)" \
  || no "autonomy_summary.default_fallback expected deny, got '$FB'"
AU=$(echo "$SEED" | j "['agents_using']")
[ -n "$AU" ] && ok "policy detail carries agents_using ($AU) — the blast radius the page headlines" \
  || no "agents_using missing from the policy detail payload"

# 2. A throwaway with the seed's shapes. Quoted heredoc: the deny_regex must
# reach YAML as "\\bcurl\\b" (→ the regex \bcurl\b), unmangled by the shell.
GOV=gov-e2e
GOV_YAML=$(cat <<'EOF'
name: gov-e2e
defaults:
  tool_action: approve
autonomy:
  permitted: true
  on_approval_rule: deny
tools:
  - match: ["Read", "Glob", "Grep", "LS"]
    action: allow
  - match: ["Edit", "Write", "MultiEdit", "NotebookEdit"]
    action: allow
    paths:
      allow: ["/workspace/**"]
      deny: ["**/.env", "**/.env.*", "**/.git/config"]
  - match: ["Bash", "BashOutput", "KillShell"]
    action: allow
    shell:
      allow_prefixes: ["ls", "cat", "git status"]
      deny_regex: ["\\bcurl\\b", "\\bsudo\\b"]
      on_no_match: approve
  - match: ["WebFetch", "WebSearch"]
    action: deny
    risk: network egress from sandbox
EOF
)
# The SAME yaml, plus a shell classifier on the WebFetch rule — the exact
# constraint an override consulted first would strand (invariant B).
POISON_YAML=$(printf '%s' "$GOV_YAML" | python3 -c "
import sys
y = sys.stdin.read()
print(y.replace('    risk: network egress from sandbox',
                '    risk: network egress from sandbox\n    shell:\n      on_no_match: approve'), end='')
")
CODE=$(post "/policies" "$(printf '%s' "$GOV_YAML" | gov_body)")
[ "$CODE" = "200" ] \
  && ok "throwaway policy '$GOV' published (seed shapes: paths on Edit, shell on Bash, flat deny on WebFetch)" \
  || { no "policy create → $CODE: $(cat "$GB")"; exit 1; }

# 3. The matrix resolves each tool's REAL status.
R=$(prow "$GOV" Edit)
[ "$R" = "conditional|allow|False" ] \
  && ok "Edit → conditional, overridable=false ('Edit → Allow' would be a lie)" || no "Edit row: $R"
EDENY=$(get "/policies/$GOV" | python3 -c "
import sys, json
r = next(x for x in json.load(sys.stdin)['matrix'] if x['tool'] == 'Edit')
print(','.join(r['status']['constraints']['paths_deny']))" 2>/dev/null)
echo "$EDENY" | grep -q '\.env' \
  && ok "Edit's row carries the paths.deny **/.env that flattening would delete" || no "Edit constraints: $EDENY"
R=$(prow "$GOV" Read)
[ "$R" = "unconditional|allow|True" ] && ok "Read → unconditional allow, overridable" || no "Read row: $R"
R=$(prow "$GOV" WebFetch)
[ "$R" = "unconditional|deny|True" ] && ok "WebFetch → unconditional deny, overridable" || no "WebFetch row: $R"

# 4. INVARIANT A — the server refuses to flatten a conditional rule.
CODE=$(put "/policies/$GOV/overrides/Edit" '{"action":"allow"}')
[ "$CODE" = "400" ] \
  && ok "INVARIANT A: PUT override Edit=allow → 400 (paths.deny **/.env survives the click)" \
  || no "wanted 400, got $CODE: $(cat "$GB")"
grep -q "conditional rule" "$GB" && ok "…and the refusal says WHY (conditional rule)" || no "refusal body: $(cat "$GB")"

# 5. Exact names only — a wildcard/unknown override would be un-reviewable.
CODE=$(put "/policies/$GOV/overrides/NotARealTool" '{"action":"allow"}')
[ "$CODE" = "400" ] && ok "unknown tool → 400 (overrides take exact canonical or mcp__* names)" \
  || no "wanted 400, got $CODE: $(cat "$GB")"

# 5b. `mcp__*` is a NAMESPACE, not a roster — the name shape alone proves
# nothing exists. Such an override would be consulted FIRST by every future
# evaluation while the matrix (canonical + currently-attached tools only)
# rendered no row for it: a permission granted once, invisibly, and never
# re-decided when the bundle finally arrives. The write must pass the same
# roster the matrix is drawn from.
CODE=$(put "/policies/$GOV/overrides/mcp__nonexistent__tool" '{"action":"allow"}')
[ "$CODE" = "400" ] \
  && ok "unattached mcp tool → 400 (an override no page could render never lands)" \
  || no "wanted 400, got $CODE: $(cat "$GB")"
grep -q "MCP tools this policy" "$GB" \
  && ok "…and the refusal names the roster, not the name shape" || no "refusal body: $(cat "$GB")"

# 6. The one click a human makes.
CODE=$(put "/policies/$GOV/overrides/WebFetch" '{"action":"allow"}')
[ "$CODE" = "200" ] && ok "PUT override WebFetch=allow → 200 (unconditional rows are safe to control)" \
  || no "wanted 200, got $CODE: $(cat "$GB")"
R=$(prow "$GOV" WebFetch)
[ "$R" = "overridden|allow|True" ] && ok "WebFetch row → overridden (the underlying rule is kept, not rewritten)" \
  || no "after override: $R"

# 7. INVARIANT B (survival) — the yaml is never the policy that RUNS.
CODE=$(post "/policies" "$(printf '%s' "$GOV_YAML" | gov_body)")
[ "$CODE" = "200" ] && ok "pristine policy-sync re-POST → 200" || no "re-sync → $CODE: $(cat "$GB")"
R=$(prow "$GOV" WebFetch)
[ "$R" = "overridden|allow|True" ] \
  && ok "INVARIANT B: the override SURVIVED policy-sync (upsert merges the column back in)" \
  || no "override dropped by sync: $R"

# 8. INVARIANT B (rejection) — a constraint that could never fire is refused,
# and the refusal must be a real block, not just a reported one.
VER=$(pver "$GOV")
CODE=$(post "/policies" "$(printf '%s' "$POISON_YAML" | gov_body)")
[ "$CODE" = "422" ] \
  && ok "INVARIANT B: yaml adding shell to WebFetch (which holds a live override) → 422" \
  || no "wanted 422, got $CODE: $(cat "$GB")"
NOW=$(pver "$GOV")
[ "$NOW" = "$VER" ] && ok "…and the refused sync wrote NOTHING (version still $VER — a dead constraint never landed)" \
  || no "version moved $VER → $NOW: the write was NOT blocked"

# 9. Clearing removes; it never rewrites the rule underneath.
CODE=$(del "/policies/$GOV/overrides/WebFetch")
[ "$CODE" = "200" ] && ok "DELETE override → 200" || no "wanted 200, got $CODE: $(cat "$GB")"
R=$(prow "$GOV" WebFetch)
[ "$R" = "unconditional|deny|True" ] && ok "WebFetch fell back to the rule's own deny" || no "after clear: $R"

# 10. Leave the subject exactly as found: pristine yaml, zero overrides.
OVR=$(get "/policies/$GOV" | python3 -c "
import sys, json
print(sum(1 for x in json.load(sys.stdin)['matrix'] if x['status']['status'] == 'overridden'))" 2>/dev/null)
[ "$OVR" = "0" ] && ok "'$GOV' left as found — pristine yaml, no lingering overrides" || no "lingering overrides: $OVR"
rm -f "$GB"

# ── Supervised session ──────────────────────────────────────────────────
say "SUPERVISED — policy verdicts + approval pause/resume"
S=$(new_session false); echo "  session $S"
T=$(token_for "$S")
[ -n "$T" ] && ok "sandbox launched; got session token" || { no "no token"; exit 1; }
silence_runner "$S"

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
silence_runner "$S2"

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
