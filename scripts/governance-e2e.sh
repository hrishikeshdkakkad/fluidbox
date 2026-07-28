#!/usr/bin/env bash
# Governance-plane E2E over real HTTP. Two halves, both against the live
# server + Neon, no model required:
#   1. the POLICY API — the Governance page's server: the tool matrix,
#      append-only versions (import / publish / revert / clone), the
#      optimistic-concurrency guard, and the strict authoring parser
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

# Gap 10: the sandbox now carries FOUR audience-scoped tokens. This script drives
# the runner contract itself, and the ONLY internal-gateway route it calls is
# /permission — the TOOL-INTENT audience — so it extracts FLUIDBOX_TOOL_TOKEN.
# (Its /events reads go through the admin `/v1` API, not the internal gateway,
# so no runner-control credential is needed here.) The env var name is a
# parameter so a future control-plane call can ask for FLUIDBOX_SESSION_TOKEN.
token_for() { # session_id [env-var, default FLUIDBOX_TOOL_TOKEN] -> token
  local sid=$1 var=${2:-FLUIDBOX_TOOL_TOKEN} cid
  for _ in $(seq 1 30); do
    cid=$(docker ps --filter "label=fluidbox.session=$sid" --format '{{.ID}}' | head -1)
    [ -n "$cid" ] && break
    sleep 1
  done
  [ -z "$cid" ] && { echo ""; return; }
  docker inspect "$cid" --format '{{range .Config.Env}}{{println .}}{{end}}' \
    | grep "^${var}=" | head -1 | cut -d= -f2-
}

perm() { # tool-audience token, session_id, json-body -> prints decision json
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
# it offers is decided HERE. The storage model is append-only versions
# (design 2026-07-14, §17 #11): the identity row is stable, every edit is an
# immutable policy_versions row, the LATEST governs future runs, and the
# RunSpec still freezes. What must never happen, and is asserted below:
#
#   A. History is immutable: an old version stays readable, byte-equal,
#      after any number of publishes — and revert publishes FORWARD.
#   B. A stale editor cannot silently overwrite a newer publish: base_version
#      is compared under the append lock, and the loser gets a 409 that
#      wrote nothing.
#   C. The authoring parser is STRICT: a typo'd field is a 422, never a
#      silently-dropped key publishing a weaker policy than reviewed.
#   D. Versions are not just numbers: a publish CHANGES what the matrix (and
#      the gate) resolves, and a revert changes it back.
#
# Writes go to a THROWAWAY policy carrying the seed's rule shapes (paths on
# Edit, shell on Bash, flat deny on WebFetch). The seed policy is only READ
# here; its rule shapes are pinned by fluidbox-core's tests.
say "POLICY API — matrix, append-only versions, publish/revert/clone"
CT='content-type: application/json'
GB=/tmp/fbx-gov-body.json
post() { curl -s -o "$GB" -w "%{http_code}" -X POST    -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }
put()  { curl -s -o "$GB" -w "%{http_code}" -X PUT     -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }
del()  { curl -s -o "$GB" -w "%{http_code}" -X DELETE  -H "$H"                  "$API/v1$1"; }
get()  { curl -s -H "$H" "$API/v1$1"; }

# One matrix row, flattened for comparison: "status|action".
prow() { # policy tool
  get "/policies/$1" | python3 -c "
import sys, json
rows = json.load(sys.stdin)['matrix']
r = next((x for x in rows if x['tool'] == '$2'), None)
print('MISSING' if r is None else '%s|%s' % (
    r['status']['status'], r['status'].get('action')))
" 2>/dev/null
}
pver() { get "/policies/$1" | j "['policy']['version']"; }
# The API takes {name, yaml} — the historical import wire shape.
gov_body() { python3 -c "import json,sys;print(json.dumps({'name':'gov-e2e','yaml':sys.stdin.read()}))"; }
# The current content with the WebFetch rule's action rewritten, wrapped as a
# publish body {content, summary, base_version}. Reads the DETAIL payload on
# stdin — the editor's exact flow: load content, edit structure, publish.
publish_body() { # action summary
  python3 -c "
import sys, json
d = json.load(sys.stdin)
c = d['content']
for rule in c['tools']:
    if 'WebFetch' in rule['match']:
        rule['action'] = '$1'
print(json.dumps({'content': c, 'summary': '$2', 'base_version': d['policy']['version']}))"
}

# 1. The seed policy's detail payload — read-only.
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
# Start from nothing: a previous run's versions would make the version numbers
# below depend on history. DELETE makes the suite idempotent AND trace-free —
# it is cleaned up again at the end of this section.
del "/policies/gov-e2e" >/dev/null
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
CODE=$(post "/policies" "$(printf '%s' "$GOV_YAML" | gov_body)")
[ "$CODE" = "200" ] \
  && ok "throwaway policy '$GOV' imported (seed shapes: paths on Edit, shell on Bash, flat deny on WebFetch)" \
  || { no "policy import → $CODE: $(cat "$GB")"; exit 1; }
BASE_VER=$(pver "$GOV")
[ "$BASE_VER" = "1" ] \
  && ok "…at v1 — the pre-run delete made the version numbers below deterministic" \
  || no "expected a fresh v1, got v$BASE_VER (stale rows from a previous run?)"
AUTHOR=$(get "/policies/$GOV" | j "['versions'][-1]['author']")
[ "$AUTHOR" = "api" ] && ok "the import minted a version with author 'api' (provenance recorded)" \
  || no "oldest version author: $AUTHOR"
V1_CONTENT=$(get "/policies/$GOV/versions/$BASE_VER" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['content'],sort_keys=True))")

# A typo'd key in imported YAML is refused too (strict parse on every
# authoring path, not just structured publish). 'permited' is the misspelling
# that would otherwise silently leave autonomy.permitted at its default.
TYPO_YAML=$(printf '%s' "$GOV_YAML" | python3 -c "
import sys
print(sys.stdin.read().replace('  permitted: true', '  permited: true'), end='')")
CODE=$(post "/policies" "$(printf '%s' "$TYPO_YAML" | gov_body)")
[ "$CODE" = "422" ] && grep -q "permited" "$GB" \
  && ok "typo'd key in imported YAML → 422 naming 'permited' (strict on the import path too)" \
  || no "typo import: $CODE: $(cat "$GB")"

# 3. The matrix resolves each tool's REAL status.
R=$(prow "$GOV" Edit)
[ "$R" = "conditional|allow" ] \
  && ok "Edit → conditional ('Edit → Allow' would be a lie)" || no "Edit row: $R"
EDENY=$(get "/policies/$GOV" | python3 -c "
import sys, json
r = next(x for x in json.load(sys.stdin)['matrix'] if x['tool'] == 'Edit')
print(','.join(r['status']['constraints']['paths_deny']))" 2>/dev/null)
echo "$EDENY" | grep -q '\.env' \
  && ok "Edit's row carries the paths.deny **/.env a flat action would delete" || no "Edit constraints: $EDENY"
R=$(prow "$GOV" WebFetch)
[ "$R" = "unconditional|deny" ] && ok "WebFetch → unconditional deny" || no "WebFetch row: $R"

# 4. Idempotent import: a byte-equal re-POST appends NOTHING.
CODE=$(post "/policies" "$(printf '%s' "$GOV_YAML" | gov_body)")
APPENDED=$(j "['appended']" < "$GB")
NOW=$(pver "$GOV")
[ "$CODE" = "200" ] && [ "$APPENDED" = "False" ] && [ "$NOW" = "$BASE_VER" ] \
  && ok "byte-equal re-import → appended=false, still v$BASE_VER (history cannot inflate)" \
  || no "re-import: code=$CODE appended=$APPENDED version=$BASE_VER→$NOW"

# 5. PUBLISH (the structured path) flips WebFetch deny→allow: version+1 AND
# the resolved matrix changes with it (a version is meaning, not a number).
CODE=$(get "/policies/$GOV" | publish_body allow "open egress for the e2e" | \
       curl -s -o "$GB" -w "%{http_code}" -X POST -H "$H" -H "$CT" -d @- "$API/v1/policies/$GOV/publish")
V_ALLOW=$(pver "$GOV")
R=$(prow "$GOV" WebFetch)
[ "$CODE" = "200" ] && [ "$V_ALLOW" = "$((BASE_VER + 1))" ] && [ "$R" = "unconditional|allow" ] \
  && ok "publish → v$V_ALLOW and WebFetch now resolves ALLOW (the edit is live for future runs)" \
  || no "publish: code=$CODE version=$V_ALLOW row=$R"

# 6. IMMUTABILITY — the pre-publish version reads back BYTE-EQUAL (canonical
# json compare), deny and all.
V1_AGAIN=$(get "/policies/$GOV/versions/$BASE_VER" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['content'],sort_keys=True))")
[ "$V1_AGAIN" = "$V1_CONTENT" ] \
  && ok "INVARIANT A: v$BASE_VER reads back byte-equal after the publish — history is immutable" \
  || no "v$BASE_VER content changed across the publish"

# 7. STALE GUARD — a publish carrying the OLD base_version is a 409 that
# wrote nothing (editor B cannot silently overwrite editor A).
STALE=$(get "/policies/$GOV" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(json.dumps({'content': d['content'], 'summary': 'stale write', 'base_version': $BASE_VER}))")
VERS_BEFORE=$(get "/policies/$GOV" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['versions']))")
CODE=$(post "/policies/$GOV/publish" "$STALE")
NOW=$(pver "$GOV")
VERS_AFTER=$(get "/policies/$GOV" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['versions']))")
[ "$CODE" = "409" ] && [ "$NOW" = "$V_ALLOW" ] && [ "$VERS_AFTER" = "$VERS_BEFORE" ] \
  && ok "INVARIANT B: stale base_version → 409; still v$V_ALLOW, version count unchanged (nothing written)" \
  || no "stale publish: code=$CODE version=$V_ALLOW→$NOW versions=$VERS_BEFORE→$VERS_AFTER: $(cat "$GB")"

# 8. STRICT PARSER — a typo'd field ('pathz') is a 422, never silently dropped.
TYPO=$(get "/policies/$GOV" | python3 -c "
import sys, json
d = json.load(sys.stdin)
c = d['content']; c['tools'][1]['pathz'] = {'deny': []}
print(json.dumps({'content': c, 'summary': 'typo', 'base_version': d['policy']['version']}))")
CODE=$(post "/policies/$GOV/publish" "$TYPO")
NOW=$(pver "$GOV")
[ "$CODE" = "422" ] && [ "$NOW" = "$V_ALLOW" ] \
  && ok "INVARIANT C: unknown field 'pathz' → 422, nothing written" \
  || no "typo publish: code=$CODE version=$NOW: $(cat "$GB")"
grep -q "pathz" "$GB" && ok "…and the refusal names the typo'd key" || no "refusal body: $(cat "$GB")"

# 8b. A blank summary is refused — the review beat is not optional.
NOSUM=$(get "/policies/$GOV" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(json.dumps({'content': d['content'], 'summary': '  ', 'base_version': d['policy']['version']}))")
CODE=$(post "/policies/$GOV/publish" "$NOSUM")
[ "$CODE" = "400" ] && ok "blank summary → 400 (publish states what changed and why)" \
  || no "blank summary: code=$CODE: $(cat "$GB")"

# 9. PREVIEW resolves a DRAFT server-side and persists nothing.
DRAFT=$(get "/policies/$GOV" | python3 -c "
import sys, json
d = json.load(sys.stdin)
c = d['content']
for rule in c['tools']:
    if 'WebFetch' in rule['match']:
        rule['action'] = 'approve'
print(json.dumps({'content': c, 'name': 'gov-e2e'}))")
PREV=$(curl -s -X POST -H "$H" -H "$CT" -d "$DRAFT" "$API/v1/policies/preview" | python3 -c "
import sys, json
rows = json.load(sys.stdin)['matrix']
r = next(x for x in rows if x['tool'] == 'WebFetch')
print('%s|%s' % (r['status']['status'], r['status'].get('action')))" 2>/dev/null)
NOW=$(pver "$GOV")
[ "$PREV" = "unconditional|approve" ] && [ "$NOW" = "$V_ALLOW" ] \
  && ok "preview resolves the draft (WebFetch→approve) and persisted nothing (still v$V_ALLOW)" \
  || no "preview: row=$PREV version=$NOW"

# 10. REVERT publishes the old content FORWARD: version+1, deny restored.
CODE=$(post "/policies/$GOV/revert" "{\"version\": $BASE_VER, \"base_version\": $V_ALLOW}")
V_REVERT=$(pver "$GOV")
R=$(prow "$GOV" WebFetch)
SUM=$(get "/policies/$GOV" | j "['versions'][0]['summary']")
[ "$CODE" = "200" ] && [ "$V_REVERT" = "$((V_ALLOW + 1))" ] && [ "$R" = "unconditional|deny" ] \
  && ok "revert → v$V_REVERT with v$BASE_VER's content: WebFetch resolves DENY again" \
  || no "revert: code=$CODE version=$V_REVERT row=$R"
[ "$SUM" = "revert to v$BASE_VER" ] && ok "…and the version says so: '$SUM'" || no "revert summary: $SUM"

# 11. CLONE mints a new policy (identity + v1) from the source's content.
# Names are DETERMINISTIC, not $RANDOM: this suite deletes what it creates
# (below), so a fixed name is re-runnable, while a random one both leaks a row
# per run and can collide into a spurious 409.
CLONE="gov-e2e-clone"
del "/policies/$CLONE" >/dev/null   # a previous run that died mid-suite
CODE=$(post "/policies/clone" "{\"name\": \"$CLONE\", \"from\": \"$GOV\"}")
CV=$(pver "$CLONE")
CR=$(prow "$CLONE" WebFetch)
[ "$CODE" = "200" ] && [ "$CV" = "1" ] && [ "$CR" = "unconditional|deny" ] \
  && ok "clone '$CLONE' → v1 carrying the source's rules" \
  || no "clone: code=$CODE v=$CV row=$CR: $(cat "$GB")"
CODE=$(post "/policies/clone" "{\"name\": \"$CLONE\", \"from\": \"$GOV\"}")
[ "$CODE" = "409" ] && ok "cloning onto an existing name → 409" || no "dup clone: $CODE"
CODE=$(post "/policies/clone" '{"name": "bad/name"}')
[ "$CODE" = "400" ] && ok "an unroutable policy name → 400" || no "bad name: $CODE"
CODE=$(post "/policies/clone" '{"name": "preview"}')
[ "$CODE" = "400" ] && ok "a route-reserved name ('preview') → 400" || no "reserved name: $CODE"
# Pin to v$V_ALLOW (WebFetch=allow) — the ONE version that differs from the
# current head (the revert restored deny), so the row below proves the PIN
# was honored, not just that a clone happened.
PIN="gov-e2e-pin"
del "/policies/$PIN" >/dev/null
CODE=$(post "/policies/clone" "{\"name\": \"$PIN\", \"from\": \"$GOV\", \"from_version\": $V_ALLOW}")
PINROW=$(prow "$PIN" WebFetch)
[ "$CODE" = "200" ] && [ "$PINROW" = "unconditional|allow" ] \
  && ok "clone pinned to from_version=$V_ALLOW carries THAT version's allow (head says deny)" \
  || no "pinned clone: code=$CODE row=$PINROW"
CODE=$(post "/policies/clone" '{"name": "gov-e2e-orphan", "from_version": 1}')
[ "$CODE" = "400" ] && ok "from_version without from → 400" || no "orphan from_version: $CODE"

# 12. DELETE closes the loop on create. Without it every run of this suite
# would leave two permanent policies in the tenant — visible in Governance and
# in the run composer's policy picker, forever, with no way to remove them.
VERS=$(get "/policies/$PIN" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['versions']))")
CODE=$(del "/policies/$PIN")
GONE=$(curl -s -o /dev/null -w "%{http_code}" -H "$H" "$API/v1/policies/$PIN")
[ "$CODE" = "200" ] && [ "$GONE" = "404" ] \
  && ok "DELETE '$PIN' → 200; the policy and its $VERS version(s) are gone" \
  || no "delete: code=$CODE then GET=$GONE: $(cat "$GB")"
CODE=$(del "/policies/$PIN")
[ "$CODE" = "404" ] && ok "deleting it again → 404 (not an error path that lingers)" \
  || no "second delete: $CODE"
CODE=$(del "/policies/$CLONE")
[ "$CODE" = "200" ] && ok "DELETE '$CLONE' → 200" || no "delete clone: $CODE"

# …but a policy an agent revision still names is REFUSED. `default` governs the
# seeded agent, so it is the honest subject — and the refusal proves the delete
# cannot orphan an immutable revision.
DEFV_BEFORE=$(pver default)
CODE=$(del "/policies/default")
DEFV_AFTER=$(pver default)
[ "$CODE" = "409" ] && [ "$DEFV_AFTER" = "$DEFV_BEFORE" ] \
  && ok "DELETE 'default' → 409 (an agent revision names it) and nothing changed" \
  || no "delete in-use: code=$CODE v=$DEFV_BEFORE→$DEFV_AFTER: $(cat "$GB")"
grep -q "agent revision" "$GB" && ok "…and the refusal says what is holding it" \
  || no "refusal body: $(cat "$GB")"

# 13. The override routes are GONE — the fold retired the mechanism.
CODE=$(put "/policies/$GOV/overrides/WebFetch" '{"action":"allow"}')
{ [ "$CODE" = "404" ] || [ "$CODE" = "405" ]; } \
  && ok "PUT /overrides/{tool} → $CODE (retired: an override IS a head rule now)" \
  || no "override route still answers: $CODE"

# Leave NO trace: every policy this section created is removed again. Test
# fixtures are indistinguishable from real data in a shared tenant, so a suite
# that mints governance objects has to clean them up.
CODE=$(del "/policies/$GOV")
[ "$CODE" = "200" ] && ok "'$GOV' removed — the suite leaves the tenant as it found it" \
  || no "final cleanup of $GOV: $CODE"
rm -f "$GB"

# ── Supervised session ──────────────────────────────────────────────────
say "SUPERVISED — policy verdicts + approval pause/resume"
S=$(new_session false); echo "  session $S"
T=$(token_for "$S")
[ -n "$T" ] && ok "sandbox launched; got tool-audience session token" || { no "no token"; exit 1; }
silence_runner "$S"

# The RunSpec froze the policy's LATEST version at creation (design §4.2):
# the run's law is a specific immutable version row, not "whatever the
# policy says later".
DEFV=$(pver default)
FROZE=$(curl -s -H "$H" "$API/v1/sessions/$S" | python3 -c "
import sys, json
spec = json.load(sys.stdin)['session']['run_spec']
print('%s|%s' % (spec.get('policy_version'), json.dumps(spec.get('policy_snapshot'), sort_keys=True)))")
WANT=$(get "/policies/default/versions/$DEFV" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['content'],sort_keys=True))")
[ "$FROZE" = "$DEFV|$WANT" ] \
  && ok "RunSpec froze default v$DEFV — snapshot BYTE-EQUAL to that version's content" \
  || no "frozen snapshot differs from default v$DEFV's content"

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
curl -s -X POST -H "$H" -H 'content-type: application/json' -d '{"decision":"approved_once"}' "$API/v1/approvals/$AID/decision" >/dev/null
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
