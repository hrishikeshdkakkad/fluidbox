#!/usr/bin/env bash
# Recipes acceptance — catalog, deploy engine, instance lifecycle (design
# docs/plans/2026-07-31-enterprise-recipes-design.md).
#
# HERMETIC: derives a THROWAWAY database (fluidbox_recipes_e2e) from
# DATABASE_URL's server and recreates it every run — the caller's named
# database is never touched. Boots its own control plane on a private port
# (18797), RLS-ENFORCING (FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime), against a
# fake GitHub API (18899) and a file:// clone fixture. Sandbox provisioning
# uses an absent image by default so run-creation paths are exercised without
# docker images; export FLUIDBOX_RECIPES_SANDBOX_IMAGE=fluidbox-replay-runner:dev
# (and have the image built) to run the execution phase through a REAL sandbox
# via the deterministic replay harness — $0, no model key.
#
# Local:   DATABASE_URL=postgres://fluidbox:fluidbox@127.0.0.1:5433/fluidbox \
#            bash scripts/recipes-e2e.sh
# (any database name on that server works — the suite swaps it for its own)
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
require_cmd psql python3 curl git cargo

[ -n "${DATABASE_URL:-}" ] || { echo "DATABASE_URL must point at a LOCAL postgres server (the suite creates its own throwaway database on it)"; exit 1; }
case "$DATABASE_URL" in
  *neon.tech*) echo "refusing to run against a hosted database"; exit 1 ;;
esac

# Prefer a modern psql (multi-statement -c behaves; macOS default is 14).
if command -v brew >/dev/null 2>&1 && [ -d "$(brew --prefix postgresql@15 2>/dev/null)/bin" ]; then
  export PATH="$(brew --prefix postgresql@15)/bin:$PATH"
fi

PORT=18797
INTERNAL_PORT=18798
GH_PORT=18899
API="http://127.0.0.1:$PORT"
for p in $PORT $INTERNAL_PORT $GH_PORT; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $p is already in use — the recipes suite owns 18797/18798/18899"; exit 1
  fi
done
ADMIN="recipes-e2e-admin-$$"
H="authorization: Bearer $ADMIN"
CT="content-type: application/json"
# WORK must live under a path the docker VM bind-mounts ($HOME is mounted in
# every supported setup; /var/folders — BSD mktemp's home — often is NOT, and
# an unmounted path silently becomes an EMPTY directory inside the sandbox).
WORK=$(mktemp -d "$HOME/.fbx-recipes-e2e.XXXXXX")
B="$WORK/body.json"

# ── Throwaway DB: <server>/fluidbox_recipes_e2e, recreated every run ───────
BASE_URL="${DATABASE_URL%/*}"
ADMIN_DB_URL="$DATABASE_URL"
E2E_DB="fluidbox_recipes_e2e"
psql "$ADMIN_DB_URL" -X -q -c "drop database if exists $E2E_DB" || exit 1
psql "$ADMIN_DB_URL" -X -q -c "create database $E2E_DB" || exit 1
export DATABASE_URL="$BASE_URL/$E2E_DB"

post()   { curl -s -o "$B" -w "%{http_code}" -X POST -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }
patch_() { curl -s -o "$B" -w "%{http_code}" -X PATCH -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }
del()    { curl -s -o "$B" -w "%{http_code}" -X DELETE -H "$H" "$API/v1$1"; }
getc()   { curl -s -o "$B" -w "%{http_code}" -H "$H" "$API/v1$1"; }
jb()     { python3 -c "import sys,json;d=json.load(open('$B'));print(d$1)" 2>/dev/null; }
pq()     { psql "$DATABASE_URL" -qtAX -c "set fluidbox.bypass = 'system_worker'; $1" | head -1; }

# ── Fake GitHub API (subset: app + installation resolve, token mint, empty
#    publish listings) — enough for github_app connections + git workspaces ──
GH_LOG="$WORK/gh.jsonl"; : > "$GH_LOG"
PEM="$WORK/app.pem"
openssl genrsa -out "$PEM" 2048 2>/dev/null
python3 - "$GH_PORT" "$GH_LOG" <<'PYEOF' &
import http.server, json, re, sys, time
port, log = int(sys.argv[1]), sys.argv[2]
class Gh(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def _log(self):
        with open(log, "a") as f:
            f.write(json.dumps({"m": self.command, "p": self.path}) + "\n")
    def do_GET(self):
        self._log()
        if self.path == "/app":
            return self._send(200, {"id": 4242, "slug": "fbx-recipes-e2e"})
        if re.fullmatch(r"/app/installations/\d+", self.path):
            return self._send(200, {"id": int(self.path.rsplit("/", 1)[1]),
                                    "account": {"login": "acme"}, "suspended_at": None})
        if self.path.startswith("/installation/repositories"):
            return self._send(200, {"repositories": [
                {"id": 1, "full_name": "acme/site", "private": False,
                 "default_branch": "main", "html_url": "https://x/acme/site"}]})
        if re.fullmatch(r"/repos/[^/]+/[^/]+/issues/\d+/comments", self.path.split("?")[0]):
            return self._send(200, [])
        if re.fullmatch(r"/repos/[^/]+/[^/]+/commits/[^/]+/check-runs", self.path.split("?")[0]):
            return self._send(200, {"total_count": 0, "check_runs": []})
        return self._send(404, {"message": "not found"})
    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        self.rfile.read(n)
        self._log()
        if re.fullmatch(r"/app/installations/\d+/access_tokens", self.path):
            exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
            return self._send(201, {"token": "ghs_recipes_fake", "expires_at": exp})
        if re.fullmatch(r"/repos/[^/]+/[^/]+/issues/\d+/comments", self.path):
            return self._send(201, {"id": 1, "html_url": "https://x/c1"})
        if re.fullmatch(r"/repos/[^/]+/[^/]+/check-runs", self.path):
            return self._send(201, {"id": 2, "html_url": "https://x/chk"})
        return self._send(404, {"message": "not found"})
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", port), Gh).serve_forever()
PYEOF
GH_PID=$!

# ── file:// clone fixture — the demo-fixture repo, so the replay runner's
#    baked transcript (fix the failing greet() test) does REAL work when the
#    execution phase runs it in a sandbox ─────────────────────────────────────
FIXROOT="$WORK/fixtures"
mkdir -p "$FIXROOT/acme"
git init -q -b main "$FIXROOT/acme/site"
cp "$ROOT"/scripts/demo-fixture/* "$FIXROOT/acme/site/"
chmod +x "$FIXROOT/acme/site/run_tests.sh" "$FIXROOT/acme/site/deploy.sh"
( cd "$FIXROOT/acme/site" \
  && git config user.email e2e@fluidbox.local && git config user.name e2e \
  && git add -A && git commit -qm init )

# ── Control plane we own ───────────────────────────────────────────────────
SERVER_BIN="${FLUIDBOX_SERVER_BIN:-$ROOT/target/debug/fluidbox-server}"
[ -x "$SERVER_BIN" ] || { cargo build -q -p fluidbox-server || exit 1; }
SANDBOX_IMAGE="${FLUIDBOX_RECIPES_SANDBOX_IMAGE:-localhost:1/fluidbox-absent:ci}"
SERVER_LOG="$WORK/server.log"
( cd "$ROOT" && exec env \
    DATABASE_URL="$DATABASE_URL" \
    ${DOCKER_HOST:+DOCKER_HOST="$DOCKER_HOST"} \
    FLUIDBOX_BIND="0.0.0.0:$PORT" \
    FLUIDBOX_INTERNAL_BIND="0.0.0.0:$INTERNAL_PORT" \
    FLUIDBOX_PUBLIC_URL="http://127.0.0.1:$PORT" \
    FLUIDBOX_PUBLIC_CONTROL_URL="http://host.docker.internal:$PORT" \
    FLUIDBOX_ADMIN_TOKEN="$ADMIN" \
    FLUIDBOX_CREDENTIAL_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')" \
    FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime \
    FLUIDBOX_DATA_DIR="$WORK/data" \
    FLUIDBOX_SANDBOX_IMAGE="$SANDBOX_IMAGE" \
    FLUIDBOX_GITHUB_API_URL="http://127.0.0.1:$GH_PORT" \
    FLUIDBOX_GITHUB_CLONE_BASE="file://$FIXROOT" \
    "$SERVER_BIN" >>"$SERVER_LOG" 2>&1 ) &
SRV_PID=$!
cleanup() {
  kill "$SRV_PID" "$GH_PID" 2>/dev/null
  wait "$SRV_PID" "$GH_PID" 2>/dev/null
  # Keep $WORK on failure for postmortems; wipe it on success.
  [ "${fail:-1}" = "0" ] && rm -rf "$WORK"
}
trap cleanup EXIT

for _ in $(seq 1 120); do
  curl -fsS -m 2 "$API/v1/health" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS -m 2 "$API/v1/health" >/dev/null 2>&1 || {
  echo "server failed to boot; log tail:"; tail -30 "$SERVER_LOG"; exit 1; }

# ═══ 1. Catalog ════════════════════════════════════════════════════════════
say "CATALOG — seeded v1, facets, detail, reserved routes"
CODE=$(getc "/recipes")
[ "$CODE" = "200" ] && ok "GET /recipes → 200" || { no "GET /recipes → $CODE"; exit 1; }
N=$(jb "['recipes'].__len__()")
[ "${N:-0}" -ge 5 ] && ok "catalog lists $N recipes (≥5 seeded)" || no "catalog has $N"
for slug in pr-review-panel ci-failure-triage repo-compliance-sweep ticket-investigator codebase-brief; do
  python3 -c "import json;d=json.load(open('$B'));assert any(r['slug']=='$slug' for r in d['recipes'])" \
    && ok "seeded: $slug" || no "missing seed: $slug"
done
python3 - "$B" <<'PY' && ok "pr-review-panel facets: 3 agents, multi-agent, cost ceiling 3.0" || no "panel facets wrong"
import json, sys
d = json.load(open(sys.argv[1]))
r = next(x for x in d["recipes"] if x["slug"] == "pr-review-panel")
f = r["facets"]
assert f["agent_count"] == 3 and f["multi_agent"] is True, f
assert abs(f["cost_ceiling_usd"] - 3.0) < 0.01, f
assert "event" in f["trigger_kinds"], f
assert any(c["provider"] == "github" for c in f["connectors"]), f
PY

CODE=$(getc "/recipes/pr-review-panel")
[ "$CODE" = "200" ] && ok "detail → 200" || no "detail → $CODE"
python3 - "$B" <<'PY' && ok "detail: ordered params, manifest, embedded policy summary" || no "detail shape wrong"
import json, sys
d = json.load(open(sys.argv[1]))
names = [p["name"] for p in d["params"]]
assert names[0] == "github_connection" and "repositories" in names, names
assert d["manifest"]["policy"] is True and len(d["manifest"]["agents"]) == 3
assert d["policy_summary"]["embedded"] is True
assert d["policy_summary"]["autonomy_permitted"] is True
assert len(d["versions"]) == 1
PY
CODE=$(getc "/recipes/no-such-recipe"); [ "$CODE" = "404" ] && ok "unknown slug → 404" || no "unknown slug → $CODE"
CODE=$(getc "/recipes/instances"); [ "$CODE" = "200" ] && ok "/recipes/instances routes to instances (not slug)" || no "instances route → $CODE"

# ═══ 2. Custom authoring ═══════════════════════════════════════════════════
say "CUSTOM AUTHORING — validation, collisions, versions"
BADREF='{"slug":"my-brief","name":"My brief","definition":{"schema":1,"agents":[{"slot":"a","name":"{{recipe.ghost}}","harness":"claude-agent-sdk"}]},"params_schema":{"type":"object","additionalProperties":false,"properties":{}}}'
CODE=$(post "/recipes" "$BADREF")
[ "$CODE" = "422" ] && grep -q "ghost" "$B" && ok "undeclared param reference → 422 naming it" || no "undeclared ref → $CODE $(cat "$B")"
OFFICIAL='{"slug":"codebase-brief","name":"x","definition":{"schema":1,"agents":[{"slot":"a","name":"n","harness":"claude-agent-sdk"}]},"params_schema":{"type":"object","additionalProperties":false,"properties":{}}}'
CODE=$(post "/recipes" "$OFFICIAL")
[ "$CODE" = "409" ] && ok "official slug collision → 409" || no "official slug → $CODE"
GOOD='{"slug":"team-brief","name":"Team brief","tagline":"custom","definition":{"schema":1,"agents":[{"slot":"a","name":"{{instance.name}}","harness":"claude-agent-sdk","system_prompt":"You answer questions."}],"subscriptions":[{"slot":"ask","agent_slot":"a","kind":"api","name":"{{instance.name}}","allow_task_override":true}]},"params_schema":{"type":"object","additionalProperties":false,"properties":{}}}'
CODE=$(post "/recipes" "$GOOD")
[ "$CODE" = "200" ] && ok "custom recipe created" || no "custom create → $CODE $(cat "$B")"
CODE=$(post "/recipes/team-brief/versions" '{"definition":{"schema":1,"agents":[{"slot":"a","name":"{{instance.name}} v2","harness":"claude-agent-sdk"}],"subscriptions":[{"slot":"ask","agent_slot":"a","kind":"api","name":"{{instance.name}}","allow_task_override":true}]},"params_schema":{"type":"object","additionalProperties":false,"properties":{}},"changelog":"v2"}')
[ "$CODE" = "200" ] && [ "$(jb "['version']['version']")" = "2" ] && ok "custom version appended → v2" || no "append → $CODE"
CODE=$(post "/recipes/codebase-brief/versions" '{"definition":{},"params_schema":{}}')
[ "$CODE" = "403" ] && ok "official recipes refuse API versioning → 403" || no "official version → $CODE"

# ═══ 3. Deploy validation (no writes) ══════════════════════════════════════
say "DEPLOY VALIDATION — schema, semantics, dry-run purity"
CODE=$(post "/recipes/codebase-brief/deploy" '{"name":"Acme brief","params":{}}')
[ "$CODE" = "422" ] && ok "missing required params → 422" || no "missing params → $CODE"
CODE=$(post "/recipes/codebase-brief/deploy" "{\"name\":\"Acme brief\",\"params\":{\"github_connection\":\"$(python3 -c 'import uuid;print(uuid.uuid4())')\",\"repository\":\"acme/site\",\"question\":\"How does auth work?\"}}")
[ "$CODE" = "422" ] && grep -q "unknown connection" "$B" && ok "unknown connection → 422" || no "unknown conn → $CODE $(cat "$B")"
CODE=$(post "/recipes/codebase-brief/deploy" '{"name":"","params":{}}')
[ "$CODE" = "400" ] && ok "empty name → 400" || no "empty name → $CODE"
CODE=$(getc "/recipes/instances")
[ "$(jb "['instances'].__len__()")" = "0" ] && ok "no instances created by failed deploys" || no "phantom instances!"

# ═══ 4. Connection fixture (github_app via fake API) ═══════════════════════
say "CONNECTION — github_app against the fake API"
python3 - "$PEM" > "$WORK/conn.json" <<'PY'
import json, sys
print(json.dumps({"provider": "github_app", "app_id": "4242", "installation_id": "77",
                  "private_key": open(sys.argv[1]).read(),
                  "webhook_secret": "whsec-recipes", "display_name": "recipes-e2e"}))
PY
CODE=$(post "/connections" "$(cat "$WORK/conn.json")")
[ "$CODE" = "200" ] && ok "github_app connection created" || { no "connection → $CODE $(cat "$B")"; exit 1; }
CONN=$(jb "['connection']['id']")

# model must belong to the harness — semantic 422 now that params can resolve
CODE=$(post "/recipes/codebase-brief/deploy" "{\"name\":\"Bad model\",\"params\":{\"github_connection\":\"$CONN\",\"repository\":\"acme/site\",\"question\":\"How does auth work here?\",\"model\":\"gpt-5.4\"}}")
[ "$CODE" = "422" ] && ok "cross-harness model → 422" || no "bad model → $CODE $(cat "$B")"
CODE=$(post "/recipes/codebase-brief/deploy" "{\"name\":\"Acme brief\",\"dry_run\":true,\"params\":{\"github_connection\":\"$CONN\",\"repository\":\"acme/site\",\"question\":\"How does the math module work?\"}}")
[ "$CODE" = "200" ] && python3 -c "
import json;d=json.load(open('$B'))
p=d['plan'];assert p['agents'][0]['slot']=='guide' and p['policy']['name']=='acme-brief-policy'
assert p['first_run'] and p['cost_ceiling_usd']>0" \
  && ok "dry-run → 200 plan (policy name, agents, cost)" || no "dry-run → $CODE $(cat "$B")"
CODE=$(getc "/recipes/instances")
[ "$(jb "['instances'].__len__()")" = "0" ] && ok "dry-run wrote nothing" || no "dry-run wrote instances!"

# ═══ 5. Deploy for real — atomic stamp + first run ═════════════════════════
say "DEPLOY — codebase-brief stamps policy + agent + subscription + fires"
CODE=$(post "/recipes/codebase-brief/deploy" "{\"name\":\"Acme brief\",\"params\":{\"github_connection\":\"$CONN\",\"repository\":\"acme/site\",\"question\":\"Explain src/math.js and how it is tested.\"}}")
[ "$CODE" = "201" ] && ok "deploy → 201" || { no "deploy → $CODE $(cat "$B")"; exit 1; }
INST=$(jb "['instance']['id']")
TOKEN=$(jb "['secrets']['trigger_tokens']['ask']")
SUB=$(python3 -c "import json;d=json.load(open('$B'));print(next(o['id'] for o in d['objects'] if o['kind']=='subscription'))")
FIRST_SID=$(jb "['first_run']['session_id']")
[ -n "$TOKEN" ] && ok "trigger token minted once: ${TOKEN:0:12}…" || no "no trigger token"
[ -n "$FIRST_SID" ] && ok "first run started: $FIRST_SID" || no "first run: $(jb "['first_run']")"
python3 -c "
import json;d=json.load(open('$B'))
kinds=sorted(o['kind'] for o in d['objects'])
assert kinds==['agent','policy','subscription'], kinds" \
  && ok "stamped objects: policy + agent + subscription" || no "objects wrong: $(jb "['objects']")"
AGENTS_JSON=$(curl -s -H "$H" "$API/v1/agents")
echo "$AGENTS_JSON" | grep -q "Acme brief" && ok "stamped agent visible in /v1/agents" || no "agent missing from /v1/agents"
curl -s -H "$H" "$API/v1/policies" | grep -q "acme-brief-policy" && ok "stamped policy visible in /v1/policies" || no "policy missing"

CODE=$(getc "/recipes/instances")
[ "$(jb "['instances'].__len__()")" = "1" ] && ok "instance listed" || no "instance list: $(cat "$B")"
CODE=$(getc "/recipes/instances/$INST")
python3 -c "
import json;d=json.load(open('$B'))
assert d['instance']['recipe_slug']=='codebase-brief' and d['instance']['status']=='active'
assert d['update_available'] is False
assert any(o['kind']=='session' for o in d['objects'])
assert len(d['sessions'])>=1
assert d['contracts'][0]['invoke_url'].endswith('/invoke')" \
  && ok "instance detail: provenance, session link, contracts" || no "detail wrong: $(cat "$B" | head -c 400)"

# duplicate name → 409, atomically (object counts unchanged)
AG_BEFORE=$(pq "select count(*) from agents")
CODE=$(post "/recipes/codebase-brief/deploy" "{\"name\":\"Acme brief\",\"params\":{\"github_connection\":\"$CONN\",\"repository\":\"acme/site\",\"question\":\"Another question entirely?\"}}")
[ "$CODE" = "409" ] && ok "duplicate deployment name → 409" || no "duplicate → $CODE"
AG_AFTER=$(pq "select count(*) from agents")
[ "$AG_BEFORE" = "$AG_AFTER" ] && ok "failed stamp left zero objects (atomic)" || no "agents leaked: $AG_BEFORE → $AG_AFTER"

# ═══ 6. Trigger contract — invoke, poll, idempotency ═══════════════════════
say "TRIGGER — subscription-scoped invoke + poll + idempotency"
IK="recipes-e2e-$$"
CODE=$(curl -s -o "$B" -w "%{http_code}" -X POST -H "authorization: Bearer $TOKEN" -H "$CT" \
  -H "Idempotency-Key: $IK" -d '{}' "$API/v1/triggers/$SUB/invoke")
[ "$CODE" = "200" ] || [ "$CODE" = "201" ] && ok "invoke with minted token → $CODE" || no "invoke → $CODE $(cat "$B")"
SID=$(jb "['session_id']")
CODE=$(curl -s -o "$B" -w "%{http_code}" -X POST -H "authorization: Bearer $TOKEN" -H "$CT" \
  -H "Idempotency-Key: $IK" -d '{}' "$API/v1/triggers/$SUB/invoke")
[ "$(jb "['replay']")" = "True" ] && [ "$(jb "['session_id']")" = "$SID" ] \
  && ok "idempotency replay returns the same run" || no "replay: $(cat "$B")"
CODE=$(curl -s -o "$B" -w "%{http_code}" -H "authorization: Bearer $TOKEN" "$API/v1/triggers/$SUB/runs/$SID")
[ "$CODE" = "200" ] && ok "trigger token polls its run" || no "poll → $CODE"
CODE=$(curl -s -o "$B" -w "%{http_code}" -H "authorization: Bearer $TOKEN" "$API/v1/agents")
[ "$CODE" = "401" ] || [ "$CODE" = "403" ] && ok "trigger token cannot reach the admin API ($CODE)" || no "token reached /agents → $CODE"

# ═══ 7. Pause / resume ═════════════════════════════════════════════════════
say "LIFECYCLE — pause disables firing, resume restores it"
CODE=$(post "/recipes/instances/$INST/pause" '{}')
[ "$CODE" = "200" ] && [ "$(jb "['instance']['status']")" = "paused" ] && ok "paused" || no "pause → $CODE"
CODE=$(curl -s -o "$B" -w "%{http_code}" -X POST -H "authorization: Bearer $TOKEN" -H "$CT" -d '{}' "$API/v1/triggers/$SUB/invoke")
[ "$CODE" = "409" ] && ok "paused deployment refuses invoke → 409" || no "paused invoke → $CODE"
CODE=$(post "/recipes/instances/$INST/run" '{}')
[ "$CODE" = "409" ] && ok "paused deployment refuses run-now → 409" || no "paused run → $CODE"
CODE=$(post "/recipes/instances/$INST/resume" '{}')
[ "$CODE" = "200" ] && ok "resumed" || no "resume → $CODE"
CODE=$(curl -s -o "$B" -w "%{http_code}" -X POST -H "authorization: Bearer $TOKEN" -H "$CT" -d '{}' "$API/v1/triggers/$SUB/invoke")
{ [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; } && ok "resume restores invoke" || no "post-resume invoke → $CODE"

# ═══ 8. Schedule recipe — stamp carries the clock ══════════════════════════
say "SCHEDULE — compliance sweep stamps a live clock"
CODE=$(post "/recipes/repo-compliance-sweep/deploy" "{\"name\":\"Weekly sweep\",\"params\":{\"github_connection\":\"$CONN\",\"repository\":\"acme/site\",\"cron\":\"0 9 * * 1\",\"timezone\":\"UTC\"}}")
[ "$CODE" = "201" ] && ok "sweep deployed" || no "sweep deploy → $CODE $(cat "$B")"
SWEEP_INST=$(jb "['instance']['id']")
SWEEP_SUB=$(python3 -c "import json;d=json.load(open('$B'));print(next(o['id'] for o in d['objects'] if o['kind']=='subscription'))")
CODE=$(getc "/triggers/$SWEEP_SUB")
python3 -c "
import json;d=json.load(open('$B'))
assert d['schedule'] and d['schedule']['cron']=='0 9 * * 1'
assert d['schedule']['next_fire_at'], d['schedule']
assert d['subscription']['trigger_kind']=='schedule'" \
  && ok "schedule row live with future next_fire_at" || no "schedule: $(cat "$B" | head -c 300)"
CODE=$(post "/recipes/instances/$SWEEP_INST/run" '{}')
[ "$CODE" = "400" ] && ok "trigger-driven deployment refuses run-now → 400" || no "sweep run-now → $CODE"
BADCRON=$(post "/recipes/repo-compliance-sweep/deploy" "{\"name\":\"Bad cron\",\"params\":{\"github_connection\":\"$CONN\",\"repository\":\"acme/site\",\"cron\":\"not a cron\"}}")
[ "$BADCRON" = "422" ] && ok "invalid cron → 422" || no "bad cron → $BADCRON"

# ═══ 9. Upgrade — versioned catalog, compatible in-place upgrade ═══════════
say "UPGRADE — v2 appended, instance upgrades in place, structural refused"
RID=$(pq "select id from recipes where slug='codebase-brief' and tenant_id is null")
V1DEF=$(pq "select definition::text from recipe_versions where recipe_id='$RID' and version=1")
python3 - "$WORK" "$V1DEF" <<'PY'
import json, sys
work, raw = sys.argv[1], sys.argv[2]
d = json.loads(raw)
d["agents"][0]["system_prompt"] = (d["agents"][0].get("system_prompt") or "") + " Cite line numbers for every claim."
open(f"{work}/v2def.json", "w").write(json.dumps(d))
v3 = json.loads(raw)
v3["agents"][0]["slot"] = "renamed-guide"
v3["subscriptions"][0]["agent_slot"] = "renamed-guide"
if v3.get("first_run"): v3["first_run"]["agent_slot"] = "renamed-guide"
open(f"{work}/v3def.json", "w").write(json.dumps(v3))
PY
SCHEMA_JSON=$(pq "select params_schema::text from recipe_versions where recipe_id='$RID' and version=1")
pq "insert into recipe_versions (id, tenant_id, recipe_id, version, definition, params_schema, changelog, author)
    values (gen_random_uuid(), null, '$RID', 2, '$(sed "s/'/''/g" "$WORK/v2def.json")'::jsonb, '$(printf %s "$SCHEMA_JSON" | sed "s/'/''/g")'::jsonb, 'sharper prompt', 'seed')" >/dev/null
CODE=$(getc "/recipes/instances/$INST")
[ "$(jb "['update_available']")" = "True" ] && ok "instance reports update available (v1 → v2)" || no "update_available: $(jb "['update_available']")"
CODE=$(post "/recipes/instances/$INST/upgrade" '{"dry_run":true}')
[ "$CODE" = "200" ] && python3 -c "
import json;d=json.load(open('$B'))
p=d['plan'];assert p['to_version']==2 and p['agents_updated']==['guide'], p" \
  && ok "upgrade dry-run plans exactly the changed agent" || no "upgrade dry → $CODE $(cat "$B")"
REV_BEFORE=$(pq "select count(*) from agent_revisions")
CODE=$(post "/recipes/instances/$INST/upgrade" '{}')
[ "$CODE" = "200" ] && [ "$(jb "['instance']['recipe_version']")" = "2" ] && ok "upgraded to v2" || no "upgrade → $CODE $(cat "$B")"
REV_AFTER=$(pq "select count(*) from agent_revisions")
[ "$REV_AFTER" = "$((REV_BEFORE + 1))" ] && ok "upgrade appended exactly one agent revision" || no "revisions $REV_BEFORE → $REV_AFTER"
CODE=$(post "/recipes/instances/$INST/upgrade" '{}')
[ "$CODE" = "409" ] && ok "re-upgrade at latest → 409" || no "re-upgrade → $CODE"
pq "insert into recipe_versions (id, tenant_id, recipe_id, version, definition, params_schema, changelog, author)
    values (gen_random_uuid(), null, '$RID', 3, '$(sed "s/'/''/g" "$WORK/v3def.json")'::jsonb, '$(printf %s "$SCHEMA_JSON" | sed "s/'/''/g")'::jsonb, 'structural', 'seed')" >/dev/null
CODE=$(post "/recipes/instances/$INST/upgrade" '{}')
[ "$CODE" = "422" ] && grep -q "structural" "$B" && ok "structural change refused with named 422" || no "structural → $CODE $(cat "$B")"

# ═══ 10. Delete — soft, consequences stated ════════════════════════════════
say "DELETE — subscriptions die, history survives, name frees"
CODE=$(del "/recipes/instances/$INST")
[ "$CODE" = "200" ] && ok "deleted" || no "delete → $CODE"
CODE=$(curl -s -o "$B" -w "%{http_code}" -X POST -H "authorization: Bearer $TOKEN" -H "$CT" -d '{}' "$API/v1/triggers/$SUB/invoke")
[ "$CODE" = "409" ] && ok "deleted deployment refuses invoke" || no "post-delete invoke → $CODE"
CODE=$(getc "/recipes/instances")
[ "$(jb "['instances'].__len__()")" = "1" ] && ok "deleted instance leaves the list (sweep remains)" || no "list after delete: $(cat "$B")"
curl -s -H "$H" "$API/v1/agents" | grep -q "Acme brief" && ok "stamped agent survives delete (history)" || no "agent vanished on delete"
CODE=$(post "/recipes/codebase-brief/deploy" "{\"name\":\"Acme brief\",\"params\":{\"github_connection\":\"$CONN\",\"repository\":\"acme/site\",\"question\":\"Round two: what changed?\"}}")
[ "$CODE" = "409" ] && ok "agent-name collision from redeploy surfaces as 409 (atomic, retryable with a new name)" || {
  # A redeploy with the same name works only when object names are freed too —
  # agents survive deliberately, so a NEW deployment name is the documented path.
  [ "$CODE" = "201" ] && ok "redeploy after delete succeeded" || no "redeploy → $CODE $(cat "$B")"; }
CODE=$(post "/recipes/codebase-brief/deploy" "{\"name\":\"Acme brief 2\",\"params\":{\"github_connection\":\"$CONN\",\"repository\":\"acme/site\",\"question\":\"Fresh name deploys cleanly?\"}}")
[ "$CODE" = "201" ] && ok "fresh name deploys cleanly after delete" || no "fresh redeploy → $CODE $(cat "$B")"

# ═══ 11. Execution (optional, real sandbox via replay image) ═══════════════
wait_terminal() { # $1 = session id → echoes final status; tails runner logs
  local deadline=$(( $(date +%s) + 240 )) st="" cid="" logpid=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ -z "$cid" ]; then
      # "sandbox launched (<id>)" — start tailing before cleanup can remove it.
      cid=$(curl -s -H "$H" "$API/v1/sessions/$1/events" | python3 -c "
import sys, json, re
d = json.load(sys.stdin)
for e in d.get('events', []):
    t = (e.get('payload') or {}).get('data', {}).get('text') or ''
    m = re.search(r'sandbox launched \(([0-9a-f]+)\)', t)
    if m: print(m.group(1)); break" 2>/dev/null)
      if [ -n "$cid" ]; then
        docker logs -f "$cid" > "$WORK/runner-$1.log" 2>&1 &
        logpid=$!
      fi
    fi
    st=$(curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']['status']")
    case "$st" in completed|failed|cancelled) break ;; esac
    sleep 2
  done
  [ -n "$logpid" ] && { sleep 1; kill "$logpid" 2>/dev/null; }
  echo "$st"
}

# The replay runner has a KNOWN, pre-existing intermittent silent death (~5%
# of runs: container exits without stderr or /result; the watchdog correctly
# terminalizes the run as "sandbox died (stale heartbeat)"). That is the
# PLATFORM's crash handling working — not a recipes defect — so the execution
# phases retry exactly once on that one signature, loudly. Anything else
# still fails after a single strike.
run_with_retry() { # $1 = instance id, $2 = session id from deploy ('' = start via /run)
  RUN_SID="$2"; RUN_ST=""
  local att reason
  for att in 1 2; do
    if [ -z "$RUN_SID" ]; then
      post "/recipes/instances/$1/run" '{}' >/dev/null
      RUN_SID=$(jb "['session_id']")
      [ -n "$RUN_SID" ] || { RUN_ST="not-started"; return; }
    fi
    RUN_ST=$(wait_terminal "$RUN_SID")
    [ "$RUN_ST" = "completed" ] && return
    reason=$(curl -s -H "$H" "$API/v1/sessions/$RUN_SID" | j "['session']['status_reason']")
    if [ "$att" = "1" ] && [ "$reason" = "sandbox died (stale heartbeat)" ]; then
      printf "  \033[1;33m⚠\033[0m replay runner died silently (known pre-existing flake; session %s) — retrying once\n" "$RUN_SID"
      RUN_SID=""
      continue
    fi
    return
  done
}

if [ "$SANDBOX_IMAGE" != "localhost:1/fluidbox-absent:ci" ]; then
  say "EXECUTION A — custom recipe, policy PERMITS the work: real diff lands"
  # A custom recipe whose policy allows exactly what the replay transcript
  # does (run tests, edit app.js, deploy) — proving the FULL pipeline:
  # recipe → deploy → real sandbox → gate allows → workspace diff artifact.
  FIXPOL='{"name":"replay-fix","defaults":{"tool_action":"deny"},"budgets":{"max_wall_clock_secs":600,"max_cost_usd":0.5,"max_tool_calls":40},"autonomy":{"permitted":true,"on_approval_rule":"deny"},"tools":[{"match":["Read","Glob","Grep","LS"],"action":"allow"},{"match":["Edit","Write","MultiEdit"],"action":"allow"},{"match":["Bash"],"action":"allow","shell":{"allow_prefixes":["./run_tests.sh","./deploy.sh","ls","cat","node"],"on_no_match":"deny"}}]}'
  FIXDEF="{\"schema\":1,\"policy\":{\"content\":$FIXPOL},\"agents\":[{\"slot\":\"fixer\",\"name\":\"{{instance.name}}\",\"harness\":\"claude-agent-sdk\",\"system_prompt\":\"Fix the failing test.\",\"workspace\":{\"kind\":\"git_repository\",\"connection_id\":\"\$param:github_connection\",\"repository\":\"\$param:repository\"}}],\"subscriptions\":[{\"slot\":\"go\",\"agent_slot\":\"fixer\",\"kind\":\"api\",\"name\":\"{{instance.name}}\",\"allow_task_override\":true}],\"first_run\":{\"agent_slot\":\"fixer\",\"task\":\"Fix the failing test and deploy.\",\"autonomous\":true}}"
  FIXSCHEMA='{"type":"object","additionalProperties":false,"required":["github_connection","repository"],"properties":{"github_connection":{"type":"string","x-fluidbox":{"widget":"connection","provider":"github"}},"repository":{"type":"string","x-fluidbox":{"widget":"text"}}}}'
  CODE=$(post "/recipes" "{\"slug\":\"replay-fix\",\"name\":\"Replay fix\",\"definition\":$FIXDEF,\"params_schema\":$FIXSCHEMA}")
  [ "$CODE" = "200" ] && ok "custom execution recipe created" || no "custom exec recipe → $CODE $(cat "$B")"
  CODE=$(post "/recipes/replay-fix/deploy" "{\"name\":\"Fixer run\",\"params\":{\"github_connection\":\"$CONN\",\"repository\":\"acme/site\"}}")
  [ "$CODE" = "201" ] && ok "deployed with instant first run" || { no "exec deploy → $CODE $(cat "$B")"; }
  FIX_INST=$(jb "['instance']['id']")
  FIX_SID=$(jb "['first_run']['session_id']")
  run_with_retry "$FIX_INST" "$FIX_SID"
  FIX_SID="$RUN_SID"; ST="$RUN_ST"
  [ "$ST" = "completed" ] && ok "sandboxed run completed" || no "run status: $ST (log: $SERVER_LOG, runner: $WORK/runner-$FIX_SID.log)"
  curl -s -H "$H" "$API/v1/sessions/$FIX_SID/events" > "$B"
  python3 - "$B" <<'PY' && ok "gate verdicts: allows executed, the curl step denied, all on the ledger" || no "verdict mix wrong (see events)"
import json, sys
d = json.load(open(sys.argv[1]))
verdicts = [((e.get("payload") or {}).get("data") or {}).get("verdict")
            for e in d["events"] if e["type"] == "tool.decision"]
assert verdicts.count("allow") >= 3, verdicts
assert verdicts.count("deny") == 1, verdicts
result = next((((e.get("payload") or {}).get("data") or {}) for e in d["events"]
               if e["type"] == "run.result"), {})
assert "executed" in json.dumps(result), result
PY
  curl -s -H "$H" "$API/v1/sessions/$FIX_SID/artifacts" > "$B"
  DIFF_ID=$(python3 -c "
import json;d=json.load(open('$B'))
print(next((a['id'] for a in d['artifacts'] if a['kind']=='diff'), ''))")
  [ -n "$DIFF_ID" ] && ok "terminal diff artifact collected" || no "no diff artifact: $(cat "$B" | head -c 200)"
  curl -s -H "$H" "$API/v1/sessions/$FIX_SID/artifacts/$DIFF_ID" > "$B"
  grep -q 'Hello, ' "$B" && ok "diff carries the real fix (app.js greet)" || no "diff missing the fix: $(cat "$B" | head -c 300)"
  curl -s -H "$H" "$API/v1/sessions/$FIX_SID/cost" > "$B"
  COST=$(jb "['usage']['cost_usd']")
  python3 -c "assert float('$COST' or 0) == 0" 2>/dev/null \
    && ok "zero model spend (deterministic replay)" || no "unexpected spend: $COST"

  say "EXECUTION B — official brief, policy DENIES writes: run completes, empty diff"
  getc "/recipes/instances" >/dev/null
  BRIEF2=$(python3 -c "
import json;d=json.load(open('$B'))
print(next(i['instance']['id'] for i in d['instances'] if i['instance']['name']=='Acme brief 2'))")
  CODE=$(post "/recipes/instances/$BRIEF2/run" '{}')
  [ "$CODE" = "201" ] && ok "run-now started" || no "run-now → $CODE $(cat "$B")"
  run_with_retry "$BRIEF2" "$(jb "['session_id']")"
  B_SID="$RUN_SID"; ST="$RUN_ST"
  [ "$ST" = "completed" ] && ok "read-only run completed" || no "brief run status: $ST (runner: $WORK/runner-$B_SID.log)"
  curl -s -H "$H" "$API/v1/sessions/$B_SID/events" > "$B"
  python3 - "$B" <<'PY' && ok "policy denied the write steps in a real sandbox" || no "expected denies"
import json, sys
d = json.load(open(sys.argv[1]))
verdicts = [((e.get("payload") or {}).get("data") or {}).get("verdict")
            for e in d["events"] if e["type"] == "tool.decision"]
assert "deny" in verdicts, verdicts
PY
  curl -s -H "$H" "$API/v1/sessions/$B_SID/artifacts" > "$B"
  python3 - "$B" <<'PY' && ok "no-change diff — the gate really prevented modification" || no "diff not empty under deny policy"
import json, sys
d = json.load(open(sys.argv[1]))
diff = next((a for a in d["artifacts"] if a["kind"] == "diff"), None)
content = ((diff or {}).get("content") or "").strip()
# An untouched workspace collects as the literal "(no changes)" sentinel.
assert content in ("", "(no changes)"), content[:200]
PY
else
  say "EXECUTION — skipped (set FLUIDBOX_RECIPES_SANDBOX_IMAGE=fluidbox-replay-runner:dev to run in a real sandbox)"
fi

# ═══ Result ════════════════════════════════════════════════════════════════
say "RESULT"
echo "  pass=$pass fail=$fail  (db: $DATABASE_URL, log: $SERVER_LOG)"
[ "$fail" = "0" ] || exit 1
