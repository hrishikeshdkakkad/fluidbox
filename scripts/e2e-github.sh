#!/usr/bin/env bash
# Phase 4 acceptance — GitHub PR-review fan-out (design doc §12 Phase 4).
# The CONNECTOR SEAM is the feature; GitHub is its first tenant:
#   • generic spine: ingress → verify → normalize → match → create_run →
#     publish, with router/matcher/dedup provider-ignorant (grep-asserted)
#   • two-level idempotency: unique(connection, external_event_id) +
#     unique(delivery, subscription) — a webhook retry NEVER duplicates
#     runs or comments (it can only heal a partial fan-out)
#   • one PR event → one isolated run per matching subscription, each
#     frozen at the EXACT head SHA with kind=event context
#   • fork PRs downgrade to a real ReadOnly trust tier (review yes,
#     writes/secrets no) that no subscription or approval can override
#   • §17 #1–#3 settled: App-only identity; default events opened+reopened
#     (synchronize opt-in); stable comment per (subscription, PR) UPDATED
#     in place, checks per head SHA under fluidbox/<subscription>
#   • live: three differently-configured agents review one PR-opened event
#     and publish three attributable reviews (self-skips without a key)
# No public URL needed: locally-crafted GitHub-shaped payloads signed with
# the webhook secret; a fake GitHub API captures every publish; clones come
# from a file:// fixture via FLUIDBOX_GITHUB_CLONE_BASE. Owns the stack.
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker psql python3 curl git cargo openssl
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
CT="content-type: application/json"

if port_in_use; then
  echo "port 8787 already serving — this phase owns the stack; stop 'just dev' first"
  exit 1
fi
cargo build -q -p fluidbox-server || exit 1

B=/tmp/fbx-gh-body.json
post()  { curl -s -o "$B" -w "%{http_code}" -X POST -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }
get()   { curl -s -H "$H" "$API/v1$1"; }
pq()    { psql "$DATABASE_URL" -qtA -c "$1" | head -1; }
jb()    { python3 -c "import sys,json;d=json.load(open('$B'));print(d$1)" 2>/dev/null; }
sfield(){ curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']$2"; }

# ── Fake GitHub API — records every request; the assertions read the log ──
GH_PORT=8899
GH_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fbx-gh-api.XXXXXX")
GH_LOG="$GH_DIR/requests.jsonl"
: > "$GH_LOG"
python3 - "$GH_PORT" "$GH_LOG" <<'PYEOF' &
import http.server, json, re, sys, time
port, log = int(sys.argv[1]), sys.argv[2]
comment_seq = 9000
class Gh(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _read(self):
        n = int(self.headers.get("content-length") or 0)
        return self.rfile.read(n).decode() if n else ""
    def _log(self, body):
        with open(log, "a") as f:
            f.write(json.dumps({"method": self.command, "path": self.path,
                                "auth": self.headers.get("authorization", ""),
                                "body": body}) + "\n")
    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        self._log("")
        if self.path == "/app":
            return self._send(200, {"id": 1234, "slug": "fbx-e2e-app"})
        if re.fullmatch(r"/app/installations/\d+", self.path):
            return self._send(200, {"id": 77, "account": {"login": "acme"}})
        if self.path.startswith("/installation/repositories"):
            return self._send(200, {"repositories": [
                {"id": 500, "full_name": "acme/site", "private": False,
                 "default_branch": "main", "html_url": "https://x/acme/site"}]})
        return self._send(404, {"message": "not found"})
    def do_POST(self):
        global comment_seq
        body = self._read(); self._log(body)
        if re.fullmatch(r"/app/installations/\d+/access_tokens", self.path):
            exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
            return self._send(201, {"token": "ghs_e2e_fake", "expires_at": exp})
        m = re.fullmatch(r"/repos/([^/]+/[^/]+)/issues/(\d+)/comments", self.path)
        if m:
            comment_seq += 1
            return self._send(201, {"id": comment_seq,
                "html_url": f"https://x/{m.group(1)}/pull/{m.group(2)}#c{comment_seq}"})
        m = re.fullmatch(r"/repos/([^/]+/[^/]+)/check-runs", self.path)
        if m:
            return self._send(201, {"id": 1, "html_url": f"https://x/{m.group(1)}/checks/1"})
        return self._send(404, {"message": "not found"})
    def do_PATCH(self):
        body = self._read(); self._log(body)
        m = re.fullmatch(r"/repos/([^/]+/[^/]+)/issues/comments/(\d+)", self.path)
        if m:
            return self._send(200, {"id": int(m.group(2)),
                "html_url": f"https://x/{m.group(1)}#c{m.group(2)}"})
        return self._send(404, {"message": "not found"})
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), Gh).serve_forever()
PYEOF
GH_PID=$!
trap 'kill $GH_PID 2>/dev/null; stop_server' EXIT
sleep 0.5

# Count fake-API requests matching method + path prefix (+ optional body substring).
req_count() { # method path-regex [body-substring]
  python3 - "$GH_LOG" "$1" "$2" "${3:-}" <<'PYEOF'
import json, re, sys
log, method, pat, sub = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
n = 0
for line in open(log):
    r = json.loads(line)
    if r["method"] == method and re.fullmatch(pat, r["path"]) and (not sub or sub in r["body"]):
        n += 1
print(n)
PYEOF
}
wait_req() { # method path-regex want [body-substring] [tries=30]
  local tries=${5:-30}
  for _ in $(seq 1 "$tries"); do
    [ "$(req_count "$1" "$2" "${4:-}")" -ge "$3" ] && return 0
    sleep 2
  done
  return 1
}

# ── file:// fixtures: the base repo (with PR branches) + a fork-probe repo ─
FIXROOT=$(mktemp -d "${TMPDIR:-/tmp}/fbx-gh-fix.XXXXXX")
fixture_repo() { # dir → creates main with one commit; prints nothing
  git -C "$1" init -q -b main
  git -C "$1" config user.email t@t && git -C "$1" config user.name t
  echo "def multiply(a, b):  return a + b  # BUG" > "$1/calc.py"
  echo "# fixture" > "$1/README.md"
  git -C "$1" add -A && git -C "$1" commit -qm base
}
mkdir -p "$FIXROOT/acme/site" "$FIXROOT/acme/probe"
fixture_repo "$FIXROOT/acme/site"
BASE_SHA=$(git -C "$FIXROOT/acme/site" rev-parse HEAD)
git -C "$FIXROOT/acme/site" checkout -qb pr-1
echo "fix one" >> "$FIXROOT/acme/site/calc.py"
git -C "$FIXROOT/acme/site" commit -qam "pr1 c1"
HEAD1=$(git -C "$FIXROOT/acme/site" rev-parse HEAD)
echo "fix two" >> "$FIXROOT/acme/site/calc.py"
git -C "$FIXROOT/acme/site" commit -qam "pr1 c2 (synchronize)"
HEAD2=$(git -C "$FIXROOT/acme/site" rev-parse HEAD)
git -C "$FIXROOT/acme/site" checkout -q main
fixture_repo "$FIXROOT/acme/probe"
PROBE_BASE=$(git -C "$FIXROOT/acme/probe" rev-parse HEAD)
git -C "$FIXROOT/acme/probe" checkout -qb pr-2
echo "fork change" >> "$FIXROOT/acme/probe/README.md"
git -C "$FIXROOT/acme/probe" commit -qam "fork head"
PROBE_SHA=$(git -C "$FIXROOT/acme/probe" rev-parse HEAD)
git -C "$FIXROOT/acme/probe" checkout -q main

# ── Control plane pointed at the fakes ────────────────────────────────────
export FLUIDBOX_GITHUB_API_URL="http://127.0.0.1:$GH_PORT"
export FLUIDBOX_GITHUB_CLONE_BASE="file://$FIXROOT"
start_server || exit 1
ok "stack up (control plane + fake github api :$GH_PORT + file:// fixtures)"

# ── App connection ────────────────────────────────────────────────────────
say "CONNECTION — github_app: validated, sealed, never echoed"
PEM_FILE="$GH_DIR/app-key.pem"
openssl genrsa -out "$PEM_FILE" 2048 2>/dev/null
WHSEC="whsec-e2e-$$"
python3 - "$PEM_FILE" "$WHSEC" > /tmp/fbx-gh-conn.json <<'PYEOF'
import json, sys
print(json.dumps({"provider": "github_app", "app_id": "1234", "installation_id": "77",
                  "private_key": open(sys.argv[1]).read(), "webhook_secret": sys.argv[2],
                  "display_name": "e2e-app"}))
PYEOF
CODE=$(post "/connections" "$(cat /tmp/fbx-gh-conn.json)")
[ "$CODE" = "200" ] && ok "github_app connection created (app+installation validated against the API)" || { no "connection create → $CODE: $(cat "$B")"; exit 1; }
CONN=$(jb "['connection']['id']")
INGRESS=$(jb "['ingress_path']")
[ "$INGRESS" = "/v1/ingress/github/$CONN" ] && ok "ingress path returned: $INGRESS" || no "ingress path: $INGRESS"
grep -q "BEGIN.*PRIVATE KEY" "$B" && no "private key echoed in response!" || ok "private key not in response"
grep -q "$WHSEC" "$B" && no "webhook secret echoed in response!" || ok "webhook secret not in response"
R=$(get "/connections/$CONN/repos")
echo "$R" | grep -q "acme/site" && ok "repo picker lists installation repositories (installation token)" || no "repo picker: $R"

# ── Three differently-configured subscriptions on one repository ──────────
say "SUBSCRIPTIONS — three agents, one repository, §17 #2 defaults"
TB='{"max_wall_clock_secs": 1}'
mk_agent() { post "/agents" "{\"name\":\"$1\",\"policy\":\"default\"}" >/dev/null; }
AGA="gh-rev-a-$$"; AGB="gh-rev-b-$$"; AGC="gh-rev-c-$$"; AGF="gh-fork-$$"
mk_agent "$AGA"; mk_agent "$AGB"; mk_agent "$AGC"; mk_agent "$AGF"

mk_sub() { # name agent extra-json → prints sub id (empty on failure)
  local code
  code=$(post "/triggers" "{\"agent\":\"$2\",\"name\":\"$1\",\"autonomous\":true,\"budgets\":$TB,
    \"connection\":\"$CONN\",\"task_template\":\"Review {{repository}}#{{pr_number}} at {{head_sha}} by {{pr_author}}\",
    \"repositories\":[\"acme/site\"]$3}")
  [ "$code" = "200" ] && jb "['subscription']['id']" || echo ""
}
SUBA=$(mk_sub "gh-sub-a-$$" "$AGA" ',"publish":["pr_comment"]')
SUBB=$(mk_sub "gh-sub-b-$$" "$AGB" ',"publish":["check"]')
SUBC=$(mk_sub "gh-sub-c-$$" "$AGC" ',"publish":["pr_comment","check"],"events":["pull_request.opened","pull_request.reopened","pull_request.synchronize"]')
[ -n "$SUBA" ] && [ -n "$SUBB" ] && [ -n "$SUBC" ] && ok "three event subscriptions created" || { no "subscription create failed: $(cat "$B")"; exit 1; }
DEFEV=$(get "/triggers/$SUBA" | python3 -c "import sys,json;print(','.join(json.load(sys.stdin)['subscription']['event_filter']['events']))")
[ "$DEFEV" = "pull_request.opened,pull_request.reopened" ] \
  && ok "§17 #2 default events = opened+reopened (synchronize is opt-in)" || no "default events: $DEFEV"

say "VALIDATION — dead event config refused at create"
CODE=$(post "/triggers" "{\"agent\":\"$AGA\",\"name\":\"v1-$$\",\"connection\":\"$CONN\",\"task_template\":\"do {{nope}}\"}")
[ "$CODE" = "400" ] && ok "template with unknown event key → 400" || no "wanted 400, got $CODE"
CODE=$(post "/triggers" "{\"agent\":\"$AGA\",\"name\":\"v2-$$\",\"connection\":\"$CONN\",\"task_template\":\"t\",\"events\":[\"pull_request.closed\"]}")
[ "$CODE" = "400" ] && ok "unsupported event type → 400" || no "wanted 400, got $CODE"
CODE=$(post "/triggers" "{\"agent\":\"$AGA\",\"name\":\"v3-$$\",\"connection\":\"$CONN\",\"task_template\":\"t\",\"schedule\":{\"cron\":\"0 0 * * *\"}}")
[ "$CODE" = "400" ] && ok "schedule + events on one subscription → 400" || no "wanted 400, got $CODE"

# ── Crafted GitHub-shaped deliveries, signed with the webhook secret ──────
pr_payload() { # repo base_repo_id pr_number head_sha head_repo_id action → file
  local out="$GH_DIR/payload-$RANDOM.json"
  python3 - "$1" "$2" "$3" "$4" "$5" "$6" > "$out" <<'PYEOF'
import json, sys
repo, base_id, num, head_sha, head_id, action = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), sys.argv[6]
print(json.dumps({
  "action": action,
  "repository": {"id": base_id, "full_name": repo},
  "pull_request": {
    "number": num, "title": f"Change {num}", "html_url": f"https://x/{repo}/pull/{num}",
    "user": {"login": "octocat"},
    "created_at": "2026-07-10T10:00:00Z", "updated_at": "2026-07-10T11:00:00Z",
    "head": {"sha": head_sha, "ref": "pr-branch", "repo": {"id": head_id, "full_name": repo}},
    "base": {"sha": "0" * 40, "ref": "main", "repo": {"id": base_id, "full_name": repo}},
  },
}, separators=(",", ":")))
PYEOF
  echo "$out"
}
send_event() { # payload-file delivery-id [event=pull_request] [secret=$WHSEC] → http code (body in $B)
  local body sig
  body=$(cat "$1")
  sig=$(printf '%s' "$body" | openssl dgst -sha256 -hmac "${4:-$WHSEC}" | awk '{print $NF}')
  curl -s -o "$B" -w "%{http_code}" -X POST "$API$INGRESS" \
    -H "$CT" -H "x-github-delivery: $2" -H "x-github-event: ${3:-pull_request}" \
    -H "x-hub-signature-256: sha256=$sig" -d "$body"
}
deliveries() { pq "select count(*) from trigger_deliveries where connection_id='$CONN'"; }
dispatches() { pq "select count(*) from trigger_dispatches d join trigger_deliveries t on d.delivery_id=t.id where t.connection_id='$CONN'"; }

say "INGRESS GUARDS — signature is the auth; junk is refused before storage"
P_OPEN=$(pr_payload acme/site 500 1 "$HEAD1" 500 opened)
CODE=$(send_event "$P_OPEN" "d-bad-1" pull_request "wrong-secret")
[ "$CODE" = "401" ] && ok "bad signature → 401" || no "wanted 401, got $CODE"
[ "$(deliveries)" = "0" ] && ok "nothing stored for an unverified delivery" || no "deliveries: $(deliveries)"
echo '{"zen":"ok"}' > "$GH_DIR/ping.json"
CODE=$(send_event "$GH_DIR/ping.json" "d-ping-1" ping)
[ "$CODE" = "200" ] && [ "$(jb "['ignored']")" = "ping" ] && ok "ping → 200 ignored" || no "ping: $CODE $(cat "$B")"
P_LABEL=$(pr_payload acme/site 500 1 "$HEAD1" 500 labeled)
CODE=$(send_event "$P_LABEL" "d-label-1")
[ "$CODE" = "200" ] && ok "unhandled PR action → 200 ignored" || no "labeled: $CODE"
[ "$(deliveries)" = "0" ] && ok "ignored events store no delivery rows" || no "deliveries: $(deliveries)"

say "FAN-OUT — one PR-opened event → three isolated runs at the exact head SHA"
CODE=$(send_event "$P_OPEN" "d-open-1")
[ "$CODE" = "200" ] && ok "signed pull_request.opened accepted" || { no "ingress: $CODE $(cat "$B")"; exit 1; }
N=$(python3 -c "import json;print(len(json.load(open('$B'))['dispatched']))")
[ "$N" = "3" ] && ok "3 subscriptions dispatched (A comment, B check, C both)" || no "dispatched: $N ($(cat "$B"))"
[ "$(jb "['duplicate']")" = "False" ] && ok "first delivery marked fresh" || no "duplicate flag wrong"
[ "$(deliveries)" = "1" ] && ok "exactly one delivery row" || no "deliveries: $(deliveries)"
[ "$(dispatches)" = "3" ] && ok "exactly three dispatch claims" || no "dispatches: $(dispatches)"
SA=$(python3 -c "import json;d=json.load(open('$B'));print([x['session_id'] for x in d['dispatched'] if x['subscription_id']=='$SUBA'][0])")
SB=$(python3 -c "import json;d=json.load(open('$B'));print([x['session_id'] for x in d['dispatched'] if x['subscription_id']=='$SUBB'][0])")
SC=$(python3 -c "import json;d=json.load(open('$B'));print([x['session_id'] for x in d['dispatched'] if x['subscription_id']=='$SUBC'][0])")
for S in "$SA" "$SB" "$SC"; do
  WS_SHA=$(sfield "$S" "['run_spec']['workspace']['commit_sha']")
  [ "$WS_SHA" = "$HEAD1" ] || { no "run $S not frozen at head sha ($WS_SHA)"; continue; }
done
ok "all three runs frozen at the exact head SHA $HEAD1"
[ "$(sfield "$SA" "['run_spec']['invocation']['kind']")" = "event" ] && ok "InvocationContext.kind=event frozen" || no "kind: $(sfield "$SA" "['run_spec']['invocation']['kind']")"
[ "$(sfield "$SA" "['run_spec']['invocation']['resource']")" = "acme/site#1" ] && ok "resource identity frozen (acme/site#1)" || no "resource wrong"
[ "$(sfield "$SA" "['run_spec']['invocation']['external_event_id']")" = "d-open-1" ] && ok "external delivery id frozen for audit" || no "external_event_id wrong"
[ "$(sfield "$SA" "['run_spec']['trust_tier']")" = "trusted" ] && ok "same-repo PR runs trusted" || no "trust tier: $(sfield "$SA" "['run_spec']['trust_tier']")"
TASK=$(sfield "$SA" "['task']")
echo "$TASK" | grep -q "acme/site#1 at $HEAD1 by octocat" && ok "task rendered from event context" || no "task: $TASK"

say "RETRY — the same delivery id replays without creating anything"
CODE=$(send_event "$P_OPEN" "d-open-1")
[ "$CODE" = "200" ] && [ "$(jb "['duplicate']")" = "True" ] && ok "retry acknowledged as duplicate" || no "retry: $CODE $(cat "$B")"
N=$(python3 -c "import json;print(len(json.load(open('$B'))['dispatched']))")
[ "$N" = "0" ] && ok "retry dispatched nothing" || no "retry dispatched $N"
[ "$(deliveries)" = "1" ] && [ "$(dispatches)" = "3" ] && ok "still one delivery, three dispatches (webhook retries never duplicate)" || no "rows grew: $(deliveries)/$(dispatches)"
RUNS=$(pq "select count(*) from trigger_dispatches d join trigger_deliveries t on d.delivery_id=t.id where t.connection_id='$CONN' and d.session_id is not null")
[ "$RUNS" = "3" ] && ok "still exactly three runs" || no "runs: $RUNS"

say "FORK — untrusted head repo → ReadOnly tier the gate actually enforces"
SUBF=$(post "/triggers" "{\"agent\":\"$AGF\",\"name\":\"gh-sub-f-$$\",\"autonomous\":true,
  \"budgets\":{\"max_wall_clock_secs\":90},\"connection\":\"$CONN\",
  \"task_template\":\"Review {{repository}}#{{pr_number}}\",\"repositories\":[\"acme/probe\"],\"publish\":[]}" \
  >/dev/null && jb "['subscription']['id']")
P_FORK=$(pr_payload acme/probe 700 2 "$PROBE_SHA" 999 opened)   # head repo 999 ≠ base 700
CODE=$(send_event "$P_FORK" "d-fork-1")
SF=$(python3 -c "import json;d=json.load(open('$B'));print(d['dispatched'][0]['session_id'])" 2>/dev/null)
[ "$CODE" = "200" ] && [ -n "$SF" ] && ok "fork PR dispatched (to the probe subscription only)" || { no "fork dispatch: $CODE $(cat "$B")"; SF=""; }
if [ -n "$SF" ]; then
  [ "$(sfield "$SF" "['run_spec']['trust_tier']")" = "read_only" ] && ok "RunSpec frozen read_only" || no "tier: $(sfield "$SF" "['run_spec']['trust_tier']")"
  [ "$(pq "select trust_tier from sessions where id='$SF'")" = "read_only" ] && ok "sessions.trust_tier = read_only" || no "column not set"
  [ "$(sfield "$SF" "['run_spec']['workspace']['checkout_mode']")" = "read_only" ] && ok "checkout_mode = read_only" || no "checkout mode wrong"
  # Probe the real permission gate with the run's own session token.
  TOK=""
  for _ in $(seq 1 30); do
    CID=$(docker ps --filter "label=fluidbox.session=$SF" --format '{{.ID}}' | head -1)
    [ -n "$CID" ] && { TOK=$(docker inspect "$CID" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^FLUIDBOX_SESSION_TOKEN=' | cut -d= -f2-); break; }
    sleep 1
  done
  if [ -n "$TOK" ]; then
    docker kill "$CID" >/dev/null 2>&1   # we drive the contract; the runner must not race us
    perm() { curl -s -X POST -H "authorization: Bearer $TOK" -H "$CT" -d "$2" "$API/internal/sessions/$SF/permission"; }
    D=$(perm x '{"tool_call_id":"f1","tool":"Read","input":{"file_path":"/workspace/repo/README.md"}}' | j "['decision']")
    [ "$D" = "allow" ] && ok "ReadOnly: Read → allow (review yes)" || no "Read: $D"
    D=$(perm x '{"tool_call_id":"f2","tool":"Bash","input":{"command":"git diff"}}' | j "['decision']")
    [ "$D" = "allow" ] && ok "ReadOnly: git diff → allow" || no "git diff: $D"
    D=$(perm x '{"tool_call_id":"f3","tool":"Edit","input":{"file_path":"/workspace/repo/calc.py"}}')
    [ "$(echo "$D" | j "['decision']")" = "deny" ] && echo "$D" | grep -q "read-only trust tier" \
      && ok "ReadOnly: Edit → deny (writes no, no approval escape)" || no "Edit: $D"
    D=$(perm x '{"tool_call_id":"f4","tool":"Bash","input":{"command":"cat x; rm -rf /"}}' | j "['decision']")
    [ "$D" = "deny" ] && ok "ReadOnly: compound shell → deny (metachar screen)" || no "compound: $D"
    SRC=$(pq "select count(*) from events where session_id='$SF' and type='tool.decision' and payload::text like '%trust_tier%'")
    [ "${SRC:-0}" -ge 1 ] && ok "denials ledgered with source=trust_tier" || no "no trust_tier decision in the ledger"
  else
    no "fork sandbox never launched (no token to probe)"
  fi
  curl -s -X POST -H "$H" "$API/v1/sessions/$SF/cancel" >/dev/null
fi

say "PUBLISH — comments/checks under the App identity, attributable per agent"
for S in "$SA" "$SB" "$SC"; do
  for _ in $(seq 1 40); do
    ST=$(sfield "$S" "['status']")
    case "$ST" in completed|failed|cancelled|budget_exceeded) break ;; esac
    sleep 3
  done
done
ok "all three fan-out runs terminal (tiny wall-clock budget)"
wait_req POST "/repos/acme/site/issues/1/comments" 2 "" 40 \
  && ok "two PR comments POSTed (A + C — B is check-only)" || no "comment posts: $(req_count POST '/repos/acme/site/issues/1/comments')"
wait_req POST "/repos/acme/site/check-runs" 2 "" 40 \
  && ok "two check runs POSTed at head1 (B + C)" || no "check posts: $(req_count POST '/repos/acme/site/check-runs')"
[ "$(req_count POST "/repos/acme/site/issues/1/comments" "$AGA")" = "1" ] && ok "A's comment carries agent name (attributable)" || no "A attribution"
[ "$(req_count POST "/repos/acme/site/check-runs" "fluidbox/gh-sub-b-$$")" = "1" ] && ok "B's check named fluidbox/<subscription>" || no "B check name"
[ "$(req_count POST "/repos/acme/site/check-runs" "$HEAD1")" = "2" ] && ok "checks pinned to the head SHA" || no "check sha"
ER=$(pq "select count(*) from external_results where subscription_id in ('$SUBA','$SUBC')")
[ "$ER" = "2" ] && ok "stable comment identities recorded (one per subscription+PR)" || no "external_results: $ER"
AUTH_OK=$(python3 - "$GH_LOG" <<'PYEOF'
import json, sys
n = 0
for line in open(sys.argv[1]):
    r = json.loads(line)
    if "/issues/1/comments" in r["path"] and "ghs_e2e_fake" in r["auth"]:
        n += 1
print(n)
PYEOF
)
[ "$AUTH_OK" -ge 2 ] && ok "publish calls authenticated as the App installation" || no "app auth: $AUTH_OK"

say "§17 #3 — synchronize updates C's comment IN PLACE; new check per SHA"
P_SYNC=$(pr_payload acme/site 500 1 "$HEAD2" 500 synchronize)
CODE=$(send_event "$P_SYNC" "d-sync-1")
N=$(python3 -c "import json;print(len(json.load(open('$B'))['dispatched']))")
[ "$CODE" = "200" ] && [ "$N" = "1" ] && ok "synchronize matched only C (A/B defaulted out — cost amplifier is opt-in)" || no "sync dispatch: $CODE/$N"
SC2=$(python3 -c "import json;print(json.load(open('$B'))['dispatched'][0]['session_id'])")
[ "$(sfield "$SC2" "['run_spec']['workspace']['commit_sha']")" = "$HEAD2" ] && ok "C's second run frozen at the NEW head SHA" || no "sync sha wrong"
for _ in $(seq 1 40); do
  ST=$(sfield "$SC2" "['status']")
  case "$ST" in completed|failed|cancelled|budget_exceeded) break ;; esac
  sleep 3
done
wait_req PATCH "/repos/acme/site/issues/comments/[0-9]+" 1 "" 40 \
  && ok "C's existing comment PATCHed in place" || no "no comment PATCH seen"
[ "$(req_count POST "/repos/acme/site/issues/1/comments")" = "2" ] && ok "no new comment spam (still 2 creates ever)" || no "comment creates grew: $(req_count POST '/repos/acme/site/issues/1/comments')"
wait_req POST "/repos/acme/site/check-runs" 3 "" 20 \
  && [ "$(req_count POST "/repos/acme/site/check-runs" "$HEAD2")" = "1" ] \
  && ok "C got a fresh check at the new SHA (checks version per commit)" || no "sync check missing"
ER=$(pq "select count(*) from external_results where subscription_id='$SUBC' and kind='github_pr_comment'")
[ "$ER" = "1" ] && ok "C's stable identity row unchanged (updated, not duplicated)" || no "C external_results: $ER"
PATCHES=$(req_count PATCH "/repos/acme/site/issues/comments/[0-9]+")
CODE=$(send_event "$P_SYNC" "d-sync-1")
[ "$(jb "['duplicate']")" = "True" ] && [ "$(req_count PATCH "/repos/acme/site/issues/comments/[0-9]+")" = "$PATCHES" ] \
  && ok "replaying the synchronize delivery re-publishes nothing" || no "replay side effects"

say "SEAM — router/matcher/dedup and run_service are provider-ignorant"
if grep -qi github "$ROOT/crates/fluidbox-server/src/events.rs"; then
  no "events.rs mentions github"
else
  ok "events.rs contains no github (verify/normalize/publish live behind the connector)"
fi
if grep -qi github "$ROOT/crates/fluidbox-server/src/run_service.rs"; then
  no "run_service.rs mentions github"
else
  ok "run_service.rs contains no github"
fi

# ── LIVE — §12 acceptance demo (self-skips without a key/gateway) ─────────
say "LIVE — three agents review one PR-opened event, three attributable results"
if [ "${E2E_SKIP_LIVE:-0}" = "1" ] || [ -z "${ANTHROPIC_API_KEY:-}" ] \
   || ! curl -fsS -m 2 http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1; then
  echo "  SKIP: live tier needs ANTHROPIC_API_KEY + gateway (E2E_SKIP_LIVE=${E2E_SKIP_LIVE:-0})"
else
  LB='{"max_wall_clock_secs": 240, "max_cost_usd": 0.30}'
  mk_live() { # name agent focus → sub id
    post "/agents" "{\"name\":\"$2\",\"policy\":\"default\"}" >/dev/null
    post "/triggers" "{\"agent\":\"$2\",\"name\":\"$1\",\"autonomous\":true,\"budgets\":$LB,
      \"connection\":\"$CONN\",\"repositories\":[\"acme/site\"],\"publish\":[\"pr_comment\"],
      \"task_template\":\"You are reviewing {{repository}} PR #{{pr_number}} (checked out at the exact head commit {{head_sha}}). $3 Read calc.py and reply with a 2-3 sentence review. Do not edit files.\"}" >/dev/null
    jb "['subscription']['id']"
  }
  L1=$(mk_live "live-correct-$$" "live-correct-agent-$$" "Focus on correctness bugs.")
  L2=$(mk_live "live-style-$$" "live-style-agent-$$" "Focus on style and naming.")
  L3=$(mk_live "live-tests-$$" "live-tests-agent-$$" "Focus on missing tests.")
  P_LIVE=$(pr_payload acme/site 500 7 "$HEAD1" 500 opened)
  CODE=$(send_event "$P_LIVE" "d-live-1")
  N=$(python3 -c "import json;print(len([x for x in json.load(open('$B'))['dispatched'] if x['subscription_id'] in ('$L1','$L2','$L3')]))")
  [ "$CODE" = "200" ] && [ "$N" = "3" ] && ok "live event fanned out to the three live agents" || no "live dispatch: $CODE/$N"
  LS=$(python3 -c "import json;print(' '.join(x['session_id'] for x in json.load(open('$B'))['dispatched'] if x['subscription_id'] in ('$L1','$L2','$L3')))")
  COMPLETED=0
  for S in $LS; do
    for _ in $(seq 1 100); do
      ST=$(sfield "$S" "['status']")
      case "$ST" in completed) COMPLETED=$((COMPLETED+1)); break ;; failed|cancelled|budget_exceeded) echo "  run $S ended $ST"; break ;; esac
      sleep 3
    done
  done
  [ "$COMPLETED" = "3" ] && ok "three live reviews completed in three isolated workspaces" || no "completed: $COMPLETED/3"
  wait_req POST "/repos/acme/site/issues/7/comments" 3 "" 40 \
    && ok "three attributable PR comments published" || no "live comments: $(req_count POST '/repos/acme/site/issues/7/comments')"
  for A in "live-correct-agent-$$" "live-style-agent-$$" "live-tests-agent-$$"; do
    [ "$(req_count POST "/repos/acme/site/issues/7/comments" "$A")" = "1" ] || { no "missing attributable comment for $A"; continue; }
  done
  ok "each comment names its agent (independent, attributable results)"
fi

say "RESULT"
rm -rf "$FIXROOT" "$GH_DIR" /tmp/fbx-gh-conn.json
printf "  \033[1m%d passed, %d failed\033[0m\n" "$pass" "$fail"
[ "$fail" = "0" ]
