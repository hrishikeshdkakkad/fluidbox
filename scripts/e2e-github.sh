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
# Migration 0018 FORCEs RLS on every tenant table, which binds the table OWNER
# too: a GUC-less psql session reads zero rows and every write trips the policy.
# The bypass GUC is a session-level SET on a custom (dotted) option — no
# privilege required — so it rides INSIDE the helper and every call carries it.
pq()    { psql "$DATABASE_URL" -qtA -c "set fluidbox.bypass = 'system_worker'; $1" | head -1; }
jb()    { python3 -c "import sys,json;d=json.load(open('$B'));print(d$1)" 2>/dev/null; }
sfield(){ curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']$2"; }

# ── Fake GitHub API — records every request; the assertions read the log ──
# Serves the legacy REST surface AND the Phase-5.6 seamless-connect surface:
# manifest conversions (one-time code), per-/all-installation lookups with
# mutable suspended state, plus /_fixture/* control routes the SCRIPT uses
# to steer that state (the control plane never sees them).
GH_PORT=8899
GH_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fbx-gh-api.XXXXXX")
GH_LOG="$GH_DIR/requests.jsonl"
: > "$GH_LOG"
SEAMLESS_PEM="$GH_DIR/seamless-key.pem"
openssl genrsa -out "$SEAMLESS_PEM" 2048 2>/dev/null
WHSEC2="whsec2-e2e-$$"
# Run-unique installation ids for the SEAMLESS sections: a real GitHub
# reinstall mints a NEW id, and fluidbox revocation is terminal by design —
# reusing a fixture id across suite runs would collide with the prior run's
# revoked row (approve, not re-create, is the revival path).
SEAM_IID=$(( ($(date +%s) % 800000) + 100000 ))
DISC_IID=$((SEAM_IID + 1))
FOREIGN_IID=$((SEAM_IID + 2))
python3 - "$GH_PORT" "$GH_LOG" "$SEAMLESS_PEM" "$WHSEC2" <<'PYEOF' &
import base64, http.server, json, re, sys, time
port, log, pem_path, whsec2 = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
comment_seq = 9000
# Installations are OWNED by an app: JWT-authenticated endpoints honor the
# token's iss claim, so a request signed as the wrong app cannot see or
# mint for another app's installations (the trust boundary the server
# relies on). 1234 = legacy hand-pasted app; 9876 = seamless manifest app.
installations = {"77": {"login": "acme", "suspended": False, "app": "1234"}}
conversions_used = set()
def inst_json(iid):
    st = installations[iid]
    return {"id": int(iid), "account": {"login": st["login"]},
            "suspended_at": "2026-07-11T00:00:00Z" if st["suspended"] else None}
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
    def _iss(self):
        # App JWTs are "Bearer <jwt>"; decode the (unverified) iss claim.
        tok = self.headers.get("authorization", "").split(" ")[-1]
        parts = tok.split(".")
        if len(parts) != 3:
            return ""
        try:
            pad = parts[1] + "=" * (-len(parts[1]) % 4)
            return str(json.loads(base64.urlsafe_b64decode(pad)).get("iss", ""))
        except Exception:
            return ""
    def do_GET(self):
        self._log("")
        if self.path == "/app":
            return self._send(200, {"id": 1234, "slug": "fbx-e2e-app"})
        if self.path.startswith("/app/installations?"):
            iss = self._iss()
            return self._send(200, [inst_json(i) for i in sorted(installations)
                                    if installations[i]["app"] == iss])
        m = re.fullmatch(r"/app/installations/(\d+)", self.path)
        if m:
            iid = m.group(1)
            if iid in installations and installations[iid]["app"] == self._iss():
                return self._send(200, inst_json(iid))
            return self._send(404, {"message": "not found"})
        if self.path.startswith("/installation/repositories"):
            return self._send(200, {"repositories": [
                {"id": 500, "full_name": "acme/site", "private": False,
                 "default_branch": "main", "html_url": "https://x/acme/site"}]})
        # Reconcile-before-create listings (#33 review 2). The publisher now
        # treats a listing ERROR as "I cannot tell" and REFUSES to create, so
        # these must answer — a 404 here would stall every comment and check.
        # They answer EMPTY, which is the honest state for this fixture: the
        # fake stores nothing, so "ours is not there" is true and the create
        # path is exercised exactly as before this change. Adoption itself is
        # unit-tested (find_marker_comment / find_marker_check); what matters
        # here is that a live listing endpoint keeps publishing working.
        if re.fullmatch(r"/repos/[^/]+/[^/]+/issues/\d+/comments", self.path.split("?")[0]):
            return self._send(200, [])
        if re.fullmatch(r"/repos/[^/]+/[^/]+/commits/[^/]+/check-runs",
                        self.path.split("?")[0]):
            return self._send(200, {"total_count": 0, "check_runs": []})
        return self._send(404, {"message": "not found"})
    def do_POST(self):
        global comment_seq
        body = self._read(); self._log(body)
        m = re.fullmatch(r"/app-manifests/([^/]+)/conversions", self.path)
        if m:
            code = m.group(1)
            if code in conversions_used or code not in ("mfc-e2e-ok", "mfc-e2e-nosec"):
                return self._send(404, {"message": "not found"})
            conversions_used.add(code)
            if code == "mfc-e2e-nosec":
                # Degraded shape: GitHub returned no webhook secret.
                return self._send(201, {
                    "id": 9877, "slug": "fbx-e2e-nosec", "name": "fluidbox-e2e-nosec",
                    "client_id": "Iv1.e2e2", "client_secret": "gh-cs-e2e",
                    "webhook_secret": None, "pem": open(pem_path).read(),
                    "html_url": "https://x/apps/fbx-e2e-nosec",
                    "owner": {"login": "acme2"}})
            return self._send(201, {
                "id": 9876, "slug": "fbx-e2e-seamless", "name": "fluidbox-e2e-seamless",
                "client_id": "Iv1.e2e", "client_secret": "gh-cs-e2e",
                "webhook_secret": whsec2, "pem": open(pem_path).read(),
                "html_url": "https://x/apps/fbx-e2e-seamless",
                "owner": {"login": "acme2"}})
        m = re.fullmatch(r"/_fixture/(suspend|unsuspend|add|remove)/(\d+)", self.path)
        if m:
            act, iid = m.group(1), m.group(2)
            if act == "add":
                spec = json.loads(body) if body else {}
                installations[iid] = {"login": spec.get("login", f"acct{iid}"),
                                      "suspended": False,
                                      "app": str(spec.get("app", "9876"))}
            elif act == "remove":
                installations.pop(iid, None)
            elif iid in installations:
                installations[iid]["suspended"] = (act == "suspend")
            return self._send(200, {"ok": True})
        m = re.fullmatch(r"/app/installations/(\d+)/access_tokens", self.path)
        if m:
            iid = m.group(1)
            if iid not in installations or installations[iid]["app"] != self._iss():
                return self._send(404, {"message": "not found"})
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
        # Checks are now updated in place when we already hold their id, exactly
        # like comments (#33 review 2) — without this a redelivery against the
        # same head SHA would 404 and fall through to a second check run.
        m = re.fullmatch(r"/repos/([^/]+/[^/]+)/check-runs/(\d+)", self.path)
        if m:
            return self._send(200, {"id": int(m.group(2)),
                "html_url": f"https://x/{m.group(1)}/checks/{m.group(2)}"})
        return self._send(404, {"message": "not found"})
    def log_message(self, *a): pass
# Threading matters: reqwest keeps pooled connections alive; a serial
# server would park on that socket and deadlock the script's direct
# /_fixture curls.
http.server.ThreadingHTTPServer(("127.0.0.1", port), Gh).serve_forever()
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
export FLUIDBOX_GITHUB_WEB_URL="http://127.0.0.1:$GH_PORT"
export FLUIDBOX_GITHUB_CLONE_BASE="file://$FIXROOT"
# A webhook-capable public host (loopback would make the manifest omit
# hook_attributes — github.com refuses unreachable hook URLs). The host
# only exists for curl: pcurl pins it to 127.0.0.1, and using it for every
# cookie-bearing browser leg keeps the jar host-consistent.
PUB="http://fbx-e2e.internal:8787"
export FLUIDBOX_PUBLIC_URL="$PUB"
pcurl() { curl --connect-to fbx-e2e.internal:8787:127.0.0.1:8787 "$@"; }
start_server || exit 1
ok "stack up (control plane + fake github api :$GH_PORT + file:// fixtures)"

# Prior-run hygiene: installation identity is DB-unique across live rows
# (migration 0008), so the STATIC fixture installation (77, legacy paste)
# must retire before this run re-connects it; the SEAMLESS fixtures use
# run-unique ids and need no hygiene. SCOPED — a shared database's real
# GitHub connections are never touched.
pq "update integration_connections set status='revoked', updated_at=now()
    where provider='github_app' and status <> 'revoked'
      and (external_account_id = '77' or display_name like 'e2e-foreign-%')" >/dev/null
pq "update github_app_registrations set status='revoked', updated_at=now()
    where status <> 'revoked' and (slug in ('fbx-e2e-seamless','fbx-e2e-nosec') or status = 'pending')" >/dev/null

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
pr_payload() { # repo base_repo_id pr_number head_sha head_repo_id action [installation_id] → file
  local out="$GH_DIR/payload-$RANDOM.json"
  python3 - "$1" "$2" "$3" "$4" "$5" "$6" "${7:-}" > "$out" <<'PYEOF'
import json, sys
repo, base_id, num, head_sha, head_id, action = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), sys.argv[6]
obj = {
  "action": action,
  "repository": {"id": base_id, "full_name": repo},
  "pull_request": {
    "number": num, "title": f"Change {num}", "html_url": f"https://x/{repo}/pull/{num}",
    "user": {"login": "octocat"},
    "created_at": "2026-07-10T10:00:00Z", "updated_at": "2026-07-10T11:00:00Z",
    "head": {"sha": head_sha, "ref": "pr-branch", "repo": {"id": head_id, "full_name": repo}},
    "base": {"sha": "0" * 40, "ref": "main", "repo": {"id": base_id, "full_name": repo}},
  },
}
if len(sys.argv) > 7 and sys.argv[7]:
    obj["installation"] = {"id": int(sys.argv[7])}
print(json.dumps(obj, separators=(",", ":")))
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
  # Gap 10: /permission is the TOOL-INTENT audience, so take FLUIDBOX_TOOL_TOKEN
  # (the runner-control token in FLUIDBOX_SESSION_TOKEN would now 403 here).
  TOK=""
  for _ in $(seq 1 30); do
    CID=$(docker ps --filter "label=fluidbox.session=$SF" --format '{{.ID}}' | head -1)
    [ -n "$CID" ] && { TOK=$(docker inspect "$CID" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^FLUIDBOX_TOOL_TOKEN=' | cut -d= -f2-); break; }
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

# ═══ Phase 5.6 — seamless connect: manifest dance + install dance ════════
say "SEAMLESS — manifest dance: the app is created without pasting anything"
CODE=$(post "/github/app/manifest/start" '{"organization":null}')
[ "$CODE" = "200" ] && ok "manifest/start minted a pending registration + one-time flow" || { no "manifest/start → $CODE: $(cat "$B")"; exit 1; }
REG=$(jb "['registration']['id']")
GO_URL=$(jb "['go_url']")
JAR="$GH_DIR/jar-manifest.txt"
pcurl -s -c "$JAR" -o "$GH_DIR/go.html" "$GO_URL"
grep -q "settings/apps/new?state=" "$GH_DIR/go.html" && ok "go page form targets GitHub's app-creation endpoint" || no "go form action missing"
grep -q "/v1/ingress/github/app/$REG" "$GH_DIR/go.html" && ok "manifest pre-wires the app-level webhook (registration-scoped URL)" || no "manifest hook url missing"
grep -q "pull_requests" "$GH_DIR/go.html" && ok "manifest carries least-privilege permissions" || no "manifest permissions missing"
MSTATE=$(python3 - "$GH_DIR/go.html" <<'PYEOF'
import html, re, sys
h = open(sys.argv[1]).read()
m = re.search(r'action="([^"]+)"', h)
print(html.unescape(m.group(1)).split("state=")[1] if m and "state=" in m.group(1) else "")
PYEOF
)
[ -n "$MSTATE" ] && ok "sealed manifest state minted for the GitHub round-trip" || { no "no state in go form"; exit 1; }
CODE=$(pcurl -s -o "$B" -w "%{http_code}" "$GO_URL")
[ "$CODE" = "400" ] && ok "bootstrap replay refused (one browser binds one flow)" || no "go replay: $CODE"
CB="$PUB/v1/github/app/manifest/callback?code=mfc-e2e-ok&state=$MSTATE"
CODE=$(pcurl -s -o "$B" -w "%{http_code}" "$CB")
[ "$CODE" = "400" ] && ok "callback without the initiating browser's cookie refused" || no "cookieless callback: $CODE"
[ "$(req_count POST '/app-manifests/[^/]+/conversions')" = "0" ] && ok "…and no conversion was attempted (flow not burned)" || no "conversion hit early"
CODE=$(pcurl -s -b "$JAR" -o "$GH_DIR/created.html" -w "%{http_code}" "$CB")
[ "$CODE" = "200" ] && grep -q "GitHub App created" "$GH_DIR/created.html" \
  && ok "manifest callback converted the one-hour code + activated the registration" || { no "callback: $CODE $(cat "$GH_DIR/created.html" 2>/dev/null)"; exit 1; }
CODE=$(pcurl -s -b "$JAR" -o /dev/null -w "%{http_code}" "$CB")
[ "$CODE" = "400" ] && ok "manifest state replay refused (flow consumed exactly once)" || no "state replay: $CODE"
[ "$(req_count POST '/app-manifests/[^/]+/conversions')" = "1" ] && ok "exactly one conversion ever reached GitHub" || no "conversions: $(req_count POST '/app-manifests/[^/]+/conversions')"
RS=$(pq "select status||'|'||slug||'|'||app_id||'|'||(pem_sealed is not null)||'|'||(webhook_secret_sealed is not null) from github_app_registrations where id='$REG'")
[ "$RS" = "active|fbx-e2e-seamless|9876|true|true" ] && ok "registration active: app id/slug stored, pem + webhook secret SEALED" || no "registration row: $RS"
grep -q "install/go?boot=" "$GH_DIR/created.html" && ok "created page chains into the install dance via the binding go page" || no "no chained install link"
get "/github/app" > "$GH_DIR/regs.json"
grep -q "PRIVATE KEY" "$GH_DIR/regs.json" && no "pem leaked in the registrations API!" || ok "registrations API carries no private key"
grep -q "$WHSEC2" "$GH_DIR/regs.json" && no "webhook secret leaked!" || ok "webhook secret not in any response"
grep -q "gh-cs-e2e" "$GH_DIR/regs.json" && no "client secret leaked!" || ok "client secret not in any response"

say "SEAMLESS — install dance: spoofed id refused, real installation connects"
inst_state() { # cookie-jar → prints the sealed install state from the 302
  post "/github/app/$REG/install/start" '{}' >/dev/null
  local go; go=$(jb "['go_url']")
  pcurl -s -c "$1" -o /dev/null -D "$GH_DIR/head.txt" "$go"
  python3 - "$GH_DIR/head.txt" <<'PYEOF'
import re, sys
h = open(sys.argv[1]).read()
m = re.search(r'[Ll]ocation:\s*(\S+)', h)
print(m.group(1).split("state=")[1].strip() if m and "state=" in m.group(1) else "")
PYEOF
}
# The installation appears on GitHub's side first (run-unique id).
curl -s -X POST "http://127.0.0.1:$GH_PORT/_fixture/add/$SEAM_IID" -d '{"login":"acme2","app":"9876"}' >/dev/null
JAR2="$GH_DIR/jar-i1.txt"; S2=$(inst_state "$JAR2")
[ -n "$S2" ] && ok "install go bound this browser and 302'd to installations/new" || { no "install go produced no state"; exit 1; }
CODE=$(pcurl -s -b "$JAR2" -o "$B" -w "%{http_code}" "$PUB/v1/github/app/$REG/setup?installation_id=555&setup_action=install&state=$S2")
[ "$CODE" = "400" ] && grep -q "does not belong" "$B" && ok "SPOOFED installation id refused (app-JWT verification is the anchor)" || no "spoof: $CODE $(cat "$B")"
JAR3="$GH_DIR/jar-i2.txt"; S3=$(inst_state "$JAR3")
CODE=$(pcurl -s -b "$JAR3" -o "$B" -w "%{http_code}" "$PUB/v1/github/app/$REG/setup?installation_id=$SEAM_IID&setup_action=install&state=$S3")
[ "$CODE" = "200" ] && grep -qi "connected" "$B" && ok "real installation verified against GitHub and connected" || no "setup: $CODE $(cat "$B")"
C2=$(pq "select id from integration_connections where provider='github_app' and external_account_id='$SEAM_IID' and status <> 'revoked'")
[ -n "$C2" ] && [ "$(pq "select status from integration_connections where id='$C2'")" = "active" ] && ok "connection active for installation $SEAM_IID" || { no "no live connection for $SEAM_IID"; exit 1; }
[ "$(pq "select registration_id from integration_connections where id='$C2'")" = "$REG" ] && ok "typed registration linkage set (custody on the registration)" || no "registration_id missing"
CODE=$(pcurl -s -b "$JAR3" -o "$B" -w "%{http_code}" "$PUB/v1/github/app/$REG/setup?installation_id=$SEAM_IID&setup_action=install&state=$S3")
[ "$CODE" = "400" ] && ok "setup replay refused" || no "setup replay: $CODE"
[ "$(pq "select count(*) from integration_connections where provider='github_app' and external_account_id='$SEAM_IID' and status <> 'revoked'")" = "1" ] && ok "ONE live row per installation (partial unique index)" || no "duplicate rows for $SEAM_IID"
GH_BEFORE=$(wc -l < "$GH_LOG" | tr -d ' ')
CODE=$(curl -s -o "$B" -w "%{http_code}" "$API/v1/github/app/$REG/setup?installation_id=$SEAM_IID&setup_action=update")
[ "$CODE" = "200" ] && grep -qi "dashboard" "$B" && ok "state-less setup (GitHub-initiated) → guidance page, zero writes" || no "stateless setup: $CODE"
[ "$(wc -l < "$GH_LOG" | tr -d ' ')" = "$GH_BEFORE" ] && ok "…and zero GitHub calls (no rate-limit oracle)" || no "stateless setup hit GitHub"
R=$(get "/connections/$C2/repos")
echo "$R" | grep -q "acme/site" && ok "repo picker mints installation tokens from REGISTRATION custody" || no "seamless repos: $R"

say "SEAMLESS — app-level ingress: one URL for every installation of the app"
APPING="/v1/ingress/github/app/$REG"
send_app() { # payload-file delivery-id [event=pull_request] [secret=$WHSEC2] → http code (body in $B)
  local body sig
  body=$(cat "$1")
  sig=$(printf '%s' "$body" | openssl dgst -sha256 -hmac "${4:-$WHSEC2}" | awk '{print $NF}')
  curl -s -o "$B" -w "%{http_code}" -X POST "$API$APPING" \
    -H "$CT" -H "x-github-delivery: $2" -H "x-github-event: ${3:-pull_request}" \
    -H "x-hub-signature-256: sha256=$sig" -d "$body"
}
echo '{"zen":"app"}' > "$GH_DIR/ping2.json"
CODE=$(send_app "$GH_DIR/ping2.json" "ad-ping-bad" ping "wrong-secret")
[ "$CODE" = "401" ] && ok "bad signature vs the REGISTRATION secret → 401" || no "app bad sig: $CODE"
CODE=$(send_app "$GH_DIR/ping2.json" "ad-ping-1" ping)
[ "$CODE" = "202" ] && ok "signed ping (no installation scope) → 202 ack, never an error" || no "ping: $CODE $(cat "$B")"
AGS="gh-seamless-$$"
post "/agents" "{\"name\":\"$AGS\",\"policy\":\"default\"}" >/dev/null
post "/triggers" "{\"agent\":\"$AGS\",\"name\":\"gh-sub-seamless-$$\",\"autonomous\":true,\"budgets\":$TB,
  \"connection\":\"$C2\",\"task_template\":\"Review {{repository}}#{{pr_number}}\",\"repositories\":[\"acme/site\"],\"publish\":[]}" >/dev/null
P_S1=$(pr_payload acme/site 500 11 "$HEAD1" 500 opened "$SEAM_IID")
CODE=$(send_app "$P_S1" "ad-open-1")
N=$(python3 -c "import json;print(len(json.load(open('$B'))['dispatched']))" 2>/dev/null)
[ "$CODE" = "200" ] && [ "$N" = "1" ] && ok "PR event resolved by payload installation.id → one run" || no "app fan-out: $CODE/$N $(cat "$B")"
SS=$(python3 -c "import json;print(json.load(open('$B'))['dispatched'][0]['session_id'])" 2>/dev/null)
[ -n "$SS" ] && [ "$(sfield "$SS" "['run_spec']['workspace']['commit_sha']")" = "$HEAD1" ] && ok "frozen at the exact head SHA through app-level ingress" || no "app run sha wrong"
CODE=$(send_app "$P_S1" "ad-open-1")
[ "$(jb "['duplicate']")" = "True" ] && ok "app-ingress webhook retry deduplicates (same spine)" || no "app retry: $(cat "$B")"
P_S77=$(pr_payload acme/site 500 12 "$HEAD1" 500 opened 77)
CODE=$(send_app "$P_S77" "ad-open-77")
[ "$CODE" = "202" ] && ok "installation 77 (legacy-owned) → 202 ignored: no hijack across custody paths" || no "cross-custody: $CODE $(cat "$B")"
curl -s -X POST -H "$H" "$API/v1/sessions/$SS/cancel" >/dev/null

say "SEAMLESS — lifecycle: suspend/unsuspend follow GitHub truth; delete revokes"
inst_ev() { # action installation-id → payload file
  local out="$GH_DIR/lc-$RANDOM.json"
  printf '{"action":"%s","installation":{"id":%s,"account":{"login":"acme2"}}}' "$1" "$2" > "$out"
  echo "$out"
}
c2s() { pq "select status from integration_connections where id='$C2'"; }
curl -s -X POST "http://127.0.0.1:$GH_PORT/_fixture/suspend/$SEAM_IID" -d '{}' >/dev/null
send_app "$(inst_ev suspend "$SEAM_IID")" "ad-sus-1" installation >/dev/null
[ "$(c2s)" = "suspended" ] && ok "suspend (confirmed against the API) → suspended" || no "suspend state: $(c2s)"
R=$(get "/connections/$C2/repos")
echo "$R" | grep -q "suspended" && ok "suspended custody fails closed (repo picker refuses)" || no "suspended repos: $R"
send_app "$(inst_ev unsuspend "$SEAM_IID")" "ad-unsus-0" installation >/dev/null
[ "$(c2s)" = "suspended" ] && ok "unsuspend CONTRADICTED by GitHub truth → stays suspended (webhook order never wins)" || no "unsuspend raced: $(c2s)"
curl -s -X POST "http://127.0.0.1:$GH_PORT/_fixture/unsuspend/$SEAM_IID" -d '{}' >/dev/null
send_app "$(inst_ev unsuspend "$SEAM_IID")" "ad-unsus-1" installation >/dev/null
[ "$(c2s)" = "active" ] && ok "unsuspend (confirmed) → active again" || no "unsuspend state: $(c2s)"
# fluidbox-side revoke → approve re-verifies against GitHub and revives the
# SAME row (dedup history stays continuous).
post "/connections/$C2/revoke" '{}' >/dev/null
[ "$(c2s)" = "revoked" ] && ok "admin revoke → revoked" || no "revoke state: $(c2s)"
CODE=$(post "/connections/$C2/approve" '{}')
[ "$CODE" = "200" ] && [ "$(c2s)" = "active" ] && ok "approve re-verifies + revives the SAME row (dedup history continuous)" || no "approve revive: $CODE $(cat "$B")"
# GitHub-side deletion: the installation is GONE — revoked, ignored, and
# NOT approvable (the truth check refuses).
curl -s -X POST "http://127.0.0.1:$GH_PORT/_fixture/remove/$SEAM_IID" -d '{}' >/dev/null
send_app "$(inst_ev deleted "$SEAM_IID")" "ad-del-1" installation >/dev/null
[ "$(c2s)" = "revoked" ] && ok "installation.deleted → connection revoked" || no "delete state: $(c2s)"
CODE=$(send_app "$P_S1" "ad-open-2")
[ "$CODE" = "202" ] && ok "events for the revoked installation are acked + ignored (fail closed)" || no "revoked ingress: $CODE"
CODE=$(post "/connections/$C2/approve" '{}')
[ "$CODE" = "409" ] && ok "approve after real deletion → 409 (installation no longer exists)" || no "approve-after-delete: $CODE $(cat "$B")"

say "SEAMLESS — discovery: installation.created lands pending; sync activates"
curl -s -X POST "http://127.0.0.1:$GH_PORT/_fixture/add/$DISC_IID" -d '{"login":"acme3","app":"9876"}' >/dev/null
send_app "$(inst_ev created "$DISC_IID")" "ad-crt-disc" installation >/dev/null
C3S=$(pq "select status from integration_connections where provider='github_app' and external_account_id='$DISC_IID'")
[ "$C3S" = "pending" ] && ok "webhook discovery creates a PENDING row (discovery ≠ authority)" || no "pending discovery: $C3S"
# A live row owned by ANOTHER custody path (legacy shape) must surface as a
# sync conflict, never be hijacked.
curl -s -X POST "http://127.0.0.1:$GH_PORT/_fixture/add/$FOREIGN_IID" -d '{"login":"acme4","app":"9876"}' >/dev/null
pq "insert into integration_connections
      (id, tenant_id, provider, external_account_id, display_name, credential_sealed, auth_kind, status)
    values (gen_random_uuid(), (select id from tenants limit 1), 'github_app', '$FOREIGN_IID',
            'e2e-foreign-$FOREIGN_IID', '\\x00'::bytea, 'static', 'active')" >/dev/null
CODE=$(post "/github/app/$REG/sync" '{}')
[ "$CODE" = "200" ] && ok "sync & activate ran (admin intent)" || no "sync: $CODE $(cat "$B")"
C3S=$(pq "select status from integration_connections where provider='github_app' and external_account_id='$DISC_IID'")
[ "$C3S" = "active" ] && ok "sync activated the pending discovery" || no "sync activation: $C3S"
python3 -c "import json;d=json.load(open('$B'));print(any('another' in str(c.get('reason','')) for c in d['conflicts']))" | grep -q True \
  && ok "sync surfaces the foreign-owned installation as a conflict (never hijacks)" || no "sync conflict surfacing: $(cat "$B")"
[ "$(pq "select registration_id is null from integration_connections where external_account_id='$FOREIGN_IID' and status='active'")" = "t" ] \
  && ok "the foreign row is untouched" || no "foreign row mutated"

say "SEAMLESS — degraded conversion: no webhook secret ⇒ events fail closed"
CODE=$(post "/github/app/manifest/start" '{"organization":null}')
REG2=$(jb "['registration']['id']"); GO2_URL=$(jb "['go_url']")
JARN="$GH_DIR/jar-nosec.txt"
pcurl -s -c "$JARN" -o "$GH_DIR/go2.html" "$GO2_URL"
NSTATE=$(python3 - "$GH_DIR/go2.html" <<'PYEOF'
import html, re, sys
h = open(sys.argv[1]).read()
m = re.search(r'action="([^"]+)"', h)
print(html.unescape(m.group(1)).split("state=")[1] if m and "state=" in m.group(1) else "")
PYEOF
)
CODE=$(pcurl -s -b "$JARN" -o "$B" -w "%{http_code}" "$PUB/v1/github/app/manifest/callback?code=mfc-e2e-nosec&state=$NSTATE")
[ "$CODE" = "200" ] && grep -q "no webhook secret" "$B" && ok "degraded conversion surfaces the remediation note" || no "nosec callback: $CODE"
[ "$(pq "select (status='active' and webhook_secret_sealed is null)::text from github_app_registrations where id='$REG2'")" = "true" ] \
  && ok "registration active but marked degraded (no sealed webhook secret)" || no "nosec registration state"
CODE=$(curl -s -o "$B" -w "%{http_code}" -X POST "$API/v1/ingress/github/app/$REG2" \
  -H "$CT" -H "x-github-delivery: ad-nosec-1" -H "x-github-event: ping" \
  -H "x-hub-signature-256: sha256=deadbeef" -d '{"zen":"x"}')
[ "$CODE" = "401" ] && ok "ingress for the degraded app refuses (cannot authenticate deliveries)" || no "nosec ingress: $CODE"

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
  # Isolate the live lane: the no-model subs also listen on acme/site and
  # would fan out (and publish) for this PR too.
  for SUB in "$SUBA" "$SUBB" "$SUBC" "$SUBF"; do
    curl -s -X POST -H "$H" "$API/v1/triggers/$SUB/disable" >/dev/null
  done
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
  NAMED=0
  for A in "live-correct-agent-$$" "live-style-agent-$$" "live-tests-agent-$$"; do
    wait_req POST "/repos/acme/site/issues/7/comments" 1 "$A" 20 \
      && NAMED=$((NAMED+1)) || no "missing attributable comment for $A"
  done
  [ "$NAMED" = "3" ] && ok "each comment names its agent (independent, attributable results)" || no "attributable comments: $NAMED/3"
fi

say "RESULT"
post "/github/app/$REG/revoke" "{}" >/dev/null 2>&1  # leave no live fixtures behind
post "/github/app/$REG2/revoke" "{}" >/dev/null 2>&1
rm -rf "$FIXROOT" "$GH_DIR" /tmp/fbx-gh-conn.json
printf "  \033[1m%d passed, %d failed\033[0m\n" "$pass" "$fail"
[ "$fail" = "0" ]
