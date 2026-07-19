#!/usr/bin/env bash
# Phase 5.5 acceptance — connector catalog & OAuth custody.
#   • CATALOG: migration-seeded (API-only settle), superset of registry
#     server.json; tool_hints are UNTRUSTED policy-default seeds; custom
#     entries via POST are forced tier=custom
#   • CONNECT auto-registers the bundle (settle #4): authless → photograph
#     now; api_key → sealed secret (custom header/scheme honored — the
#     Sentry shape) + photograph proves the credential (rollback on refusal);
#     oauth → the increment-2 dance
#   • OAUTH CUSTODY: 401 → RFC 9728 PRM → RFC 8414 AS metadata (S256
#     required) → PKCE S256 + RFC 8707 resource= on BOTH legs → ONE
#     unauthenticated callback with AEAD-sealed state → sealed ROTATING
#     refresh token (atomic overwrite; old token dead) → access tokens
#     minted at call time, cached in memory only
#   • client identity: pre-registered → CIMD (doc served; URL IS the
#     client_id) → DCR fallback (minted id stored, never re-registered)
#   • broker: proactive pre-expiry + reactive-401 refresh; invalid_grant ⇒
#     connection error ⇒ new runs fail closed at zero spend; reconnect on
#     the SAME connection revives it
#   • secrets (api keys, refresh/access tokens, client secrets) never in
#     responses, catalog, RunSpec, ledger, or sandbox env
# The "browser" is curl. Fakes: a Sentry-shaped static MCP (custom auth
# header) + one python process serving MCP resource AND authorization
# server. Live tier (self-skips): an agent uses a catalog connector.
set -uo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env
require_cmd docker psql python3 curl git cargo
H="authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
CT="content-type: application/json"

if port_in_use; then
  echo "port 8787 already serving — this phase owns the stack; stop 'just dev' first"
  exit 1
fi
cargo build -q -p fluidbox-server || exit 1

B=/tmp/fbx-conn-body.json
post()  { curl -s -o "$B" -w "%{http_code}" -X POST -H "$H" -H "$CT" -d "$2" "$API/v1$1"; }
get()   { curl -s -H "$H" "$API/v1$1"; }
pq()    { psql "$DATABASE_URL" -qtA -c "$1" | head -1; }
jb()    { python3 -c "import sys,json;d=json.load(open('$B'));print(d$1)" 2>/dev/null; }
sfield(){ curl -s -H "$H" "$API/v1/sessions/$1" | j "['session']$2"; }

CONN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fbx-conn.XXXXXX")

# ── Fake Sentry-shaped MCP (static key via CUSTOM header) ─────────────────
SN_PORT=8896
SN_KEY="sntrys-e2e-$$"
SN_LOG="$CONN_DIR/sentry-requests.jsonl"
: > "$SN_LOG"
python3 - "$SN_PORT" "$SN_LOG" "$SN_KEY" <<'PYEOF' &
import http.server, json, sys
port, log, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class Sn(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _send(self, code, obj, headers=None):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        try: req = json.loads(raw)
        except Exception: req = {}
        method = req.get("method", "")
        rid = req.get("id")
        with open(log, "a") as f:
            f.write(json.dumps({"path": self.path, "method": method,
                                "sentry_bearer": self.headers.get("Sentry-Bearer", ""),
                                "authorization": self.headers.get("Authorization", "")}) + "\n")
        # The credential arrives as a BARE token in a CUSTOM header — never
        # as Authorization: Bearer.
        if self.headers.get("Sentry-Bearer", "") != key:
            return self._send(401, {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32001, "message": "unauthorized"}})
        if self.path != "/mcp":
            return self._send(404, {"message": "not found"})
        if method == "initialize":
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-sentry", "version": "1.0.0"}}})
        if method == "notifications/initialized":
            self.send_response(202); self.send_header("content-length", "0")
            self.end_headers(); return
        if method == "tools/list":
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
                {"name": "sn_find_issues", "description": "Find recent issues",
                 "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}},
                                 "required": ["query"]},
                 "annotations": {"readOnlyHint": True}},
                {"name": "sn_update_issue", "description": "Update an issue",
                 "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}},
                                 "required": ["id"]}}]}})
        if method == "tools/call":
            name = (req.get("params") or {}).get("name", "")
            args = (req.get("params") or {}).get("arguments") or {}
            if name == "sn_find_issues":
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text",
                                 "text": f"sentry issues for {args.get('query','')}: FBX-1 open"}],
                    "isError": False}})
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"no such tool {name}"}], "isError": True}})
        return self._send(200, {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": "method not found"}})
    def log_message(self, *a): pass
# Threading matters: reqwest keeps its pooled connection alive, and a
# serial HTTPServer would starve every other client (curl) behind it.
http.server.ThreadingHTTPServer(("127.0.0.1", port), Sn).serve_forever()
PYEOF
SN_PID=$!

# ── Fake OAuth MCP resource + authorization server (one process) ──────────
AS_PORT=8897
python3 - "$AS_PORT" <<'PYEOF' &
import base64, hashlib, http.server, json, sys, threading, time, urllib.parse
port = int(sys.argv[1])
S = {"codes": {}, "access": {}, "refresh": [], "mode": {"cimd": False, "access_ttl": 3600},
     "grants": [], "authorize": [], "register": [], "mcp": [], "n": 0}
RESOURCE = f"http://127.0.0.1:{port}/mcp"
LOCK = threading.Lock()
def s256(v):
    return base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
def next_n():
    with LOCK:
        S["n"] += 1
        return S["n"]
def mint():
    n = next_n()
    acc, rt = f"acc-{n}", f"rt-{n}"
    S["access"][acc] = time.time() + S["mode"]["access_ttl"]
    S["refresh"].append(rt)
    return acc, rt
class As(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _send(self, code, obj, headers=None, raw=None):
        data = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)
    def _mcp_auth(self):
        auth = self.headers.get("Authorization", "")
        tok = auth.removeprefix("Bearer ")
        ok = tok in S["access"] and S["access"][tok] > time.time()
        S["mcp"].append({"method": "", "auth": auth, "ok": ok})
        return ok
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/mcp":
            if not self._mcp_auth():
                return self._send(401, {"error": "unauthorized"}, headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="http://127.0.0.1:{port}/.well-known/oauth-protected-resource/mcp"'})
            return self._send(405, {"error": "POST JSON-RPC"})
        if u.path == "/.well-known/oauth-protected-resource/mcp":
            return self._send(200, {"resource": RESOURCE,
                                    "authorization_servers": [f"http://127.0.0.1:{port}"]})
        if u.path == "/.well-known/oauth-authorization-server":
            return self._send(200, {
                "issuer": f"http://127.0.0.1:{port}",
                "authorization_endpoint": f"http://127.0.0.1:{port}/authorize",
                "token_endpoint": f"http://127.0.0.1:{port}/token",
                "registration_endpoint": f"http://127.0.0.1:{port}/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "client_id_metadata_document_supported": S["mode"]["cimd"],
                "scopes_supported": ["read", "offline_access"]})
        if u.path == "/authorize":
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            S["authorize"].append(q)
            need = ["client_id", "redirect_uri", "state", "code_challenge", "resource"]
            if any(k not in q for k in need) or q.get("code_challenge_method") != "S256":
                return self._send(400, {"error": "invalid_request", "got": q})
            code = f"code-{next_n()}"
            S["codes"][code] = q
            sep = "&" if "?" in q["redirect_uri"] else "?"
            loc = f"{q['redirect_uri']}{sep}code={code}&state={urllib.parse.quote(q['state'])}"
            self.send_response(302)
            self.send_header("Location", loc)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        if u.path == "/admin/state":
            return self._send(200, S)
        return self._send(404, {"error": "not found"})
    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        u = urllib.parse.urlparse(self.path)
        if u.path == "/mcp":
            try: req = json.loads(raw)
            except Exception: req = {}
            method, rid = req.get("method", ""), req.get("id")
            auth = self.headers.get("Authorization", "")
            tok = auth.removeprefix("Bearer ")
            ok = tok in S["access"] and S["access"][tok] > time.time()
            S["mcp"].append({"method": method, "auth": auth, "ok": ok})
            if not ok:
                return self._send(401, {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32001, "message": "unauthorized"}}, headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="http://127.0.0.1:{port}/.well-known/oauth-protected-resource/mcp"'})
            if method == "initialize":
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                    "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake-notion", "version": "1.0.0"}}})
            if method == "notifications/initialized":
                self.send_response(202); self.send_header("content-length", "0")
                self.end_headers(); return
            if method == "tools/list":
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
                    {"name": "nt_search", "description": "Search pages",
                     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}},
                                     "required": ["query"]},
                     "annotations": {"readOnlyHint": True}},
                    {"name": "nt_create_page", "description": "Create a page",
                     "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}},
                                     "required": ["title"]}}]}})
            if method == "tools/call":
                name = (req.get("params") or {}).get("name", "")
                args = (req.get("params") or {}).get("arguments") or {}
                if name == "nt_search":
                    return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                        "content": [{"type": "text",
                                     "text": f"notion result for {args.get('query','')} — custody works"}],
                        "isError": False}})
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": f"no such tool {name}"}], "isError": True}})
            return self._send(200, {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": "method not found"}})
        if u.path == "/token":
            f = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
            grant = f.get("grant_type", "")
            rec = {"grant": grant, "resource": f.get("resource", ""),
                   "client_id": f.get("client_id", ""),
                   "client_auth": self.headers.get("Authorization", ""), "ok": False}
            if grant == "authorization_code":
                q = S["codes"].pop(f.get("code", ""), None)  # single-use
                rec["code_verifier_present"] = "code_verifier" in f
                if not q or s256(f.get("code_verifier", "")) != q["code_challenge"]:
                    S["grants"].append(rec)
                    return self._send(400, {"error": "invalid_grant"})
                if f.get("resource", "") != RESOURCE:
                    S["grants"].append(rec)
                    return self._send(400, {"error": "invalid_target"})
                acc, rt = mint()
                rec.update(ok=True, minted_access=acc, minted_refresh=rt)
                S["grants"].append(rec)
                return self._send(200, {"access_token": acc, "token_type": "Bearer",
                    "expires_in": S["mode"]["access_ttl"], "refresh_token": rt,
                    "scope": "read offline_access"})
            if grant == "refresh_token":
                rt_in = f.get("refresh_token", "")
                rec["used_refresh"] = rt_in
                if rt_in not in S["refresh"]:
                    S["grants"].append(rec)
                    return self._send(400, {"error": "invalid_grant"})
                # ROTATION: the old token dies the moment the new one mints.
                S["refresh"].remove(rt_in)
                acc, rt = mint()
                rec.update(ok=True, minted_access=acc, minted_refresh=rt)
                S["grants"].append(rec)
                return self._send(200, {"access_token": acc, "token_type": "Bearer",
                    "expires_in": S["mode"]["access_ttl"], "refresh_token": rt,
                    "scope": "read offline_access"})
            S["grants"].append(rec)
            return self._send(400, {"error": "unsupported_grant_type"})
        if u.path == "/register":
            body = json.loads(raw) if raw else {}
            S["register"].append(body)
            return self._send(201, {"client_id": f"dcr-client-{next_n()}",
                                    "redirect_uris": body.get("redirect_uris", [])})
        if u.path == "/admin/mode":
            S["mode"].update(json.loads(raw))
            return self._send(200, S["mode"])
        if u.path == "/admin/expire-access":
            S["access"].clear()
            return self._send(200, {"ok": True})
        if u.path == "/admin/revoke":
            S["access"].clear(); S["refresh"].clear()
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})
    def log_message(self, *a): pass
# Threading matters: reqwest keeps its pooled connection alive, and a
# serial HTTPServer would starve every other client (curl) behind it.
http.server.ThreadingHTTPServer(("127.0.0.1", port), As).serve_forever()
PYEOF
AS_PID=$!
trap 'kill $SN_PID $AS_PID 2>/dev/null; stop_server' EXIT
sleep 0.5

as_state() { curl -s "http://127.0.0.1:$AS_PORT/admin/state"; }
as_field() { as_state | python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }
as_admin() { curl -s -X POST -d "${2:-{\}}" "http://127.0.0.1:$AS_PORT/admin/$1" >/dev/null; }

export FLUIDBOX_PUBLIC_URL="http://127.0.0.1:8787"
# Rerun hygiene: custom catalog slugs are DB-unique and the API is
# deliberately create-only — drop this suite's previous test entries.
psql "$DATABASE_URL" -qc "delete from connector_catalog where tier='custom' and (slug like 'fx-%' or slug like 'byo-%')" 2>/dev/null
start_server || exit 1
ok "stack up (control plane + fake sentry :$SN_PORT + fake oauth AS/MCP :$AS_PORT)"

# ── Policy: brokered probes need mcp__* verdicts ──────────────────────────
say "SETUP — policy + probe helpers"
PY=$(python3 - <<'PYEOF'
import json
print(json.dumps("""name: conn-e2e
defaults:
  tool_action: approve
autonomy:
  permitted: true
  on_approval_rule: deny
tools:
  - match: ["Read", "Glob", "Grep", "LS", "TodoWrite", "Task", "NotebookRead"]
    action: allow
  - match: ["Bash"]
    action: allow
    shell:
      allow_prefixes: ["ls", "cat", "git status", "git diff", "node"]
      on_no_match: approve
  - match: ["mcp__*"]
    action: allow
"""))
PYEOF
)
CODE=$(post "/policies" "{\"name\":\"conn-e2e\",\"yaml\":$PY}")
[ "$CODE" = "200" ] && ok "conn-e2e policy created" || { no "policy → $CODE: $(cat "$B")"; exit 1; }

PROBE_BUDGET='{"max_wall_clock_secs": 240, "max_cost_usd": 0.05}'
token_for() { # session → token (kills the runner so probes own the contract)
  local sid=$1 cid tok=""
  for _ in $(seq 1 30); do
    cid=$(docker ps -a --filter "label=fluidbox.session=$sid" --format '{{.ID}}' | head -1)
    [ -n "$cid" ] && { tok=$(docker inspect "$cid" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^FLUIDBOX_SESSION_TOKEN=' | cut -d= -f2-); break; }
    sleep 1
  done
  [ -n "$cid" ] && docker kill "$cid" >/dev/null 2>&1
  echo "$tok"
}
broke() { # session token id tool input
  curl -s -X POST -H "authorization: Bearer $2" -H "$CT" \
    -d "{\"tool_call_id\":\"$3\",\"tool\":\"$4\",\"input\":$5}" "$API/internal/sessions/$1/tools/call"
}
probe_session() { # agent → SID (body in $B)
  post "/sessions" "{\"agent\":\"$1\",\"task\":\"connector probe\",\"autonomous\":true,\"budgets\":$PROBE_BUDGET}" >/dev/null
  jb "['session']['id']"
}

# ── Catalog: migration-seeded, API-managed ────────────────────────────────
say "CATALOG — migration seed (API-only settle) + custom entries"
CAT=$(get "/catalog")
N_ENTRIES=$(echo "$CAT" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['connectors']))")
[ "${N_ENTRIES:-0}" -ge 7 ] && ok "catalog lists $N_ENTRIES seeded entries (≥7)" || no "catalog entries: $N_ENTRIES"
cfield() { echo "$CAT" | python3 -c "
import sys, json
d = {c['slug']: c for c in json.load(sys.stdin)['connectors']}
print(d.get('$1', {}).get('$2', ''))"; }
[ "$(cfield notion auth_mode)" = "oauth" ] && ok "notion is seeded oauth-only" || no "notion: $(cfield notion auth_mode)"
[ "$(cfield sentry auth_mode)" = "api_key" ] && echo "$CAT" | grep -q "Sentry-Bearer" \
  && ok "sentry seed carries the custom header hint (Sentry-Bearer)" || no "sentry hints wrong"
[ "$(cfield workspace-info transport)" = "stdio" ] && [ "$(cfield workspace-info tier)" = "verified" ] \
  && ok "workspace-info seeded as verified in-image stdio entry" || no "workspace-info seed wrong"
[ "$(cfield github tier)" = "verified" ] && echo "$CAT" | grep -q "mcp__github__" \
  && ok "github seed carries untrusted tool_hints (policy-default seeds)" || no "github seed wrong"
[ -z "$(cfield slack auth_mode)" ] && ok "no slack seed (deferred to Phase 7 — settle #3)" || no "slack seed exists!"
# Every curated seed is a real connectable transport (streamable_http/stdio),
# so the derived `connectable` decoration is true; imported `rest_action`
# reference cards (bulk-import increment 4) will report false here instead.
[ "$(cfield github connectable)" = "True" ] && [ "$(cfield workspace-info connectable)" = "True" ] \
  && ok "catalog decorates entries with a derived connectable flag" || no "connectable decoration missing"

CODE=$(post "/catalog" "{\"slug\":\"Bad_Slug\",\"name\":\"x\",\"url\":\"http://127.0.0.1:$SN_PORT/mcp\"}")
[ "$CODE" = "400" ] && ok "bad slug → 400 (must fit alias+bundle charset)" || no "bad slug → $CODE"
CODE=$(post "/catalog" "{\"slug\":\"workspace-info\",\"name\":\"dup\",\"url\":\"http://x.test/mcp\"}")
[ "$CODE" = "409" ] && ok "duplicate slug → 409" || no "dup slug → $CODE"
CODE=$(post "/catalog" "{\"slug\":\"no-launch-$$\",\"name\":\"x\",\"transport\":\"stdio\"}")
[ "$CODE" = "400" ] && ok "stdio entry without sandbox_launch → 400" || no "stdio → $CODE"
CODE=$(post "/catalog" "{\"slug\":\"fx-sentry\",\"name\":\"Fake Sentry\",\"auth_mode\":\"api_key\",
  \"url\":\"http://127.0.0.1:$SN_PORT/mcp\",\"categories\":[\"observability\"],
  \"auth_hints\":{\"header_name\":\"Sentry-Bearer\",\"scheme\":\"\",\"placeholder\":\"sntrys_…\"},
  \"tool_hints\":[{\"pattern\":\"mcp__fx-sentry__sn_find_issues\",\"action\":\"allow\",\"note\":\"read\"}]}")
[ "$CODE" = "200" ] && [ "$(jb "['connector']['tier']")" = "custom" ] \
  && ok "custom entry fx-sentry created — tier FORCED custom" || { no "fx-sentry → $CODE: $(cat "$B")"; exit 1; }
CODE=$(post "/catalog" "{\"slug\":\"fx-notion\",\"name\":\"Fake Notion\",\"auth_mode\":\"oauth\",
  \"url\":\"http://127.0.0.1:$AS_PORT/mcp\",\"categories\":[\"docs\"]}")
[ "$CODE" = "200" ] && ok "custom entry fx-notion (oauth) created" || { no "fx-notion → $CODE"; exit 1; }

# ── Authless connect: photograph now, no connection object ────────────────
say "CONNECT (authless) — workspace-info registers its declared bundle"
CODE=$(post "/catalog/workspace-info/connect" "{}")
[ "$CODE" = "200" ] && [ "$(jb "['bundle']['name']")" = "workspace-info" ] \
  && ok "one click → bundle workspace-info@$(jb "['bundle']['version']") registered (declared photograph)" \
  || { no "authless connect → $CODE: $(cat "$B")"; exit 1; }

# ── INC 1: api_key connect with a CUSTOM header (the Sentry shape) ────────
# Phase C: a REMOTE (streamable_http) connect no longer auto-registers a
# capability bundle — it creates a CONNECTION and photographs its tool surface
# into a connection SNAPSHOT ({connection, snapshot}). Bundles now survive only
# for in-image sandbox (stdio) entries (workspace-info above).
say "CONNECT (api_key) — sealed key, custom header honored, snapshot proves it"
CODE=$(post "/catalog/fx-sentry/connect" "{\"token\":\"$SN_KEY\"}")
[ "$CODE" = "200" ] && ok "fx-sentry connected (connection + snapshot in one step)" || { no "connect → $CODE: $(cat "$B")"; exit 1; }
SNCONN=$(jb "['connection']['id']")
[ "$(jb "['snapshot']['version']")" = "1" ] && ok "connection snapshot v1 photographed (Phase C: snapshots, not bundles)" || no "snapshot: $(cat "$B")"
grep -q "$SN_KEY" "$B" && no "api key echoed in connect response!" || ok "api key not in the connect response"
get "/connections" | grep -q "$SN_KEY" && no "api key in connection listing!" || ok "api key not in the listing"
LAST_LIST=$(grep '"method": "tools/list"' "$SN_LOG" | tail -1)
echo "$LAST_LIST" | grep -q "\"sentry_bearer\": \"$SN_KEY\"" \
  && ok "photograph authenticated via Sentry-Bearer: <bare token> (custom header + raw scheme)" || no "header wrong: $LAST_LIST"
echo "$LAST_LIST" | grep -q '"authorization": ""' \
  && ok "no Authorization header sent (custom header REPLACES, not supplements)" || no "authorization leaked: $LAST_LIST"
DECOR=$(get "/catalog" | python3 -c "
import sys, json
d = {c['slug']: c for c in json.load(sys.stdin)['connectors']}
e = d.get('fx-sentry', {})
conn = e.get('connection') or {}
print('ok' if conn.get('status') == 'active' else str(conn))")
[ "$DECOR" = "ok" ] && ok "catalog entries decorate with live connection state (UI renders connected/disconnect)" || no "decoration: $DECOR"

CODE=$(post "/catalog/fx-sentry/connect" "{\"token\":\"wrong-key\",\"bundle_name\":\"fx-sentry-bad\",\"display_name\":\"sentry-bad\"}")
[ "$CODE" = "400" ] && grep -q "rejected this credential" "$B" \
  && ok "wrong key → 400 (the photograph is the credential's proof-of-life)" || no "wrong key → $CODE: $(cat "$B")"
ACTIVE_BAD=$(get "/connections" | python3 -c "
import sys, json
cs = json.load(sys.stdin)['connections']
print(sum(1 for c in cs if c['display_name'] == 'sentry-bad' and c['status'] == 'active'))")
[ "$ACTIVE_BAD" = "0" ] && ok "refused credential's connection rolled back (no active row)" || no "dangling connection!"

say "BROKER (api_key) — end-to-end through the custom header"
# Phase C: the agent DECLARES a connection requirement (slot fx-sentry, organization
# binding — the operator has no personal identity); create_run resolves it to the
# fx-sentry connection's snapshot and freezes a brokered surface in the RunSpec.
post "/agents" "{\"name\":\"conn-sn-$$\",\"policy\":\"conn-e2e\",\"connection_requirements\":[{\"slot\":\"fx-sentry\",\"connector\":{\"url\":\"http://127.0.0.1:$SN_PORT/mcp\",\"slug\":\"fx-sentry\"},\"required_tools\":[\"sn_find_issues\"],\"binding_mode\":\"organization\"}]}" >/dev/null
SID_SN=$(probe_session "conn-sn-$$")
TOK_SN=$(token_for "$SID_SN")
[ -n "$TOK_SN" ] && ok "probe session launched; runner killed (we drive the contract)" || { no "no session token"; exit 1; }
R=$(broke "$SID_SN" "$TOK_SN" s1 "mcp__fx-sentry__sn_find_issues" '{"query":"deploy"}')
echo "$R" | j "['ok']" | grep -q True && echo "$R" | grep -q "FBX-1 open" \
  && ok "brokered call executed via Sentry-Bearer — result returned" || no "broker call: $R"
CID_SN=$(docker ps -a --filter "label=fluidbox.session=$SID_SN" --format '{{.ID}}' | head -1)
docker inspect "$CID_SN" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -q "$SN_KEY" \
  && no "api key found in sandbox env!" || ok "api key never entered the sandbox env"
curl -s -H "$H" "$API/v1/sessions/$SID_SN" | grep -q "$SN_KEY" && no "api key in RunSpec!" || ok "api key not in the frozen RunSpec"
curl -s -H "$H" "$API/v1/sessions/$SID_SN/events?limit=500" | grep -q "$SN_KEY" && no "api key in ledger!" || ok "api key not in the ledger"

# ── BRING YOUR OWN MCP — probe (non-committing) + one-shot connect ─────────
say "BYO MCP — probe detects auth, one-shot connect reuses the catalog seams"

# Probe the OAuth-backed fake (401 → PRM → AS metadata) → oauth, no secrets.
CODE=$(post "/mcp/probe" "{\"url\":\"http://127.0.0.1:$AS_PORT/mcp\"}")
[ "$CODE" = "200" ] && [ "$(jb "['auth_mode']")" = "oauth" ] && [ "$(jb "['oauth_available']")" = "True" ] \
  && ok "probe(oauth server) → auth_mode=oauth, oauth_available (no commitment, nothing stored)" \
  || no "probe oauth → $CODE: $(cat "$B")"
[ -n "$(jb "['oauth']['authorization_endpoint']")" ] && ok "probe surfaces the non-secret AS summary (authorization_endpoint)" || no "no AS summary"
grep -qiE "client_secret|refresh|acc-|rt-" "$B" && no "secret material in probe response!" || ok "probe response carries no secrets"

# Probe the Sentry fake (401, no discoverable AS) → api_key.
CODE=$(post "/mcp/probe" "{\"url\":\"http://127.0.0.1:$SN_PORT/mcp\"}")
[ "$CODE" = "200" ] && [ "$(jb "['auth_mode']")" = "api_key" ] \
  && ok "probe(static-key server) → auth_mode=api_key (401 + no AS metadata)" || no "probe api_key → $CODE: $(cat "$B")"

# Probe a dead port → reachable=false (an error, distinct from a 401 signal).
CODE=$(post "/mcp/probe" "{\"url\":\"http://127.0.0.1:1/mcp\"}")
[ "$CODE" = "200" ] && [ "$(jb "['reachable']")" = "False" ] \
  && ok "probe(unreachable) → reachable=false (not confused with an auth signal)" || no "probe unreachable → $CODE: $(cat "$B")"

# One-shot BYO connect (api_key) — custom entry + connection + photograph in
# ONE call, reusing the catalog seams. The name IS the derived slug here.
BYO="byo-sentry-$$"
CODE=$(post "/mcp/servers" "{\"url\":\"http://127.0.0.1:$SN_PORT/mcp\",\"name\":\"$BYO\",
  \"auth_mode\":\"api_key\",\"token\":\"$SN_KEY\",\"header_name\":\"Sentry-Bearer\",\"scheme\":\"\"}")
[ "$CODE" = "200" ] && ok "one-shot BYO connect → 200 (entry + connection + snapshot in one call)" || { no "byo connect → $CODE: $(cat "$B")"; exit 1; }
BYOCONN=$(jb "['connection']['id']")
[ "$(jb "['slug']")" = "$BYO" ] && ok "slug derived server-side ($BYO)" || no "slug: $(jb "['slug']")"
[ "$(pq "select tier from connector_catalog where slug='$BYO'")" = "custom" ] && ok "BYO server became a tier=custom catalog entry (reuse-the-catalog)" || no "no custom catalog row"
grep -q "sn_find_issues" "$B" && ok "connect response previews the PHOTOGRAPHED snapshot tools (sn_find_issues)" || no "no tool preview in connect response: $(cat "$B")"
grep -q "$SN_KEY" "$B" && no "api key echoed in BYO connect response!" || ok "api key not in the BYO connect response"

# Tool surface API (Phase C): GET /connections/{id}/tools returns the latest
# connection snapshot's per-tool list (name + description) for the UI preview.
PREV=$(get "/connections/$BYOCONN/tools" | python3 -c "
import sys, json
ts = json.load(sys.stdin).get('snapshot', {}).get('tools', [])
print('ok' if any(t.get('name') and 'description' in t for t in ts) else 'no')")
[ "$PREV" = "ok" ] && ok "GET /connections/{id}/tools exposes the snapshot's tools (name + description) for the UI preview" || no "no tool preview in the connection snapshot"

# Orphan cleanup: a refused key rolls BOTH the connection AND the custom entry.
BYO_BAD="byo-bad-$$"
CODE=$(post "/mcp/servers" "{\"url\":\"http://127.0.0.1:$SN_PORT/mcp\",\"name\":\"$BYO_BAD\",
  \"auth_mode\":\"api_key\",\"token\":\"wrong-key\",\"header_name\":\"Sentry-Bearer\",\"scheme\":\"\"}")
[ "$CODE" = "400" ] && ok "BYO connect with a bad key → 400 (photograph is the proof-of-life)" || no "bad byo → $CODE"
[ "$(pq "select count(*) from connector_catalog where slug='$BYO_BAD'")" = "0" ] \
  && ok "failed BYO connect left NO orphan catalog entry (rolled back)" || no "orphan custom entry survived!"

# ── HARNESS + MODEL — the authoritative catalog and the belongs-check ──────
say "HARNESS/MODEL — server is the source of truth; mismatch is a clean 422"
HARN=$(get "/harnesses")
echo "$HARN" | python3 -c "
import sys, json
hs = {h['id']: h for h in json.load(sys.stdin)['harnesses']}
ok = ('claude-agent-sdk' in hs and 'codex' in hs
      and any(m['id'] == 'claude-opus-4-8' for m in hs['claude-agent-sdk']['models'])
      and any(m['id'] == 'gpt-5.4-mini' for m in hs['codex']['models']))
sys.exit(0 if ok else 1)" && ok "GET /harnesses lists claude + codex with their model catalogs" || no "harnesses shape wrong: $HARN"
CODE=$(post "/agents" "{\"name\":\"byo-mismatch-$$\",\"policy\":\"conn-e2e\",\"harness\":\"codex\",\"model\":\"claude-opus-4-8\"}")
[ "$CODE" = "422" ] && ok "codex + a claude model → 422 (caught at agent-write time, not murkily at call time)" || no "model mismatch → $CODE: $(cat "$B")"
CODE=$(post "/agents" "{\"name\":\"byo-match-$$\",\"policy\":\"conn-e2e\",\"harness\":\"codex\",\"model\":\"gpt-5.4-mini\"}")
[ "$CODE" = "200" ] && ok "codex + a codex model → 200 (valid pair accepted)" || no "valid pair → $CODE: $(cat "$B")"

# ── INC 2: the OAuth dance (DCR mode first) ───────────────────────────────
say "OAUTH DANCE — 401 → PRM → AS metadata → PKCE+resource → callback → sealed rotating refresh"
as_admin mode '{"cimd": false, "access_ttl": 3600}'
CODE=$(post "/catalog/fx-notion/connect" "{\"display_name\":\"fx-notion-main\"}")
[ "$CODE" = "200" ] && ok "oauth connect → pending connection + authorize_url" || { no "connect → $CODE: $(cat "$B")"; exit 1; }
NTCONN=$(jb "['connection']['id']")
AUTH_URL=$(jb "['authorize_url']")
[ "$(jb "['connection']['status']")" = "pending" ] && ok "connection starts pending (fail-closed until the exchange)" || no "status: $(jb "['connection']['status']")"
echo "$AUTH_URL" | grep -q "code_challenge_method=S256" && echo "$AUTH_URL" | grep -q "code_challenge=" \
  && ok "authorize URL carries PKCE S256" || no "authorize url: $AUTH_URL"
echo "$AUTH_URL" | grep -q "resource=http%3A%2F%2F127.0.0.1%3A$AS_PORT%2Fmcp" \
  && ok "authorize URL carries resource= (RFC 8707, leg 1)" || no "no resource in: $AUTH_URL"
echo "$AUTH_URL" | grep -q "client_id=dcr-client-" \
  && ok "client identity minted via DCR (AS advertises no CIMD)" || no "client_id in: $AUTH_URL"
[ "$(as_field "['register'].__len__()")" = "1" ] && ok "exactly one DCR registration performed" || no "register count: $(as_field "['register'].__len__()")"
echo "$AUTH_URL" | grep -q "offline_access" \
  && ok "offline_access requested (AS advertises it)" || no "no offline_access in scope"

# The "browser": follow the auto-consent redirect, then hit our callback.
CB_URL=$(curl -s -o /dev/null -w '%{redirect_url}' "$AUTH_URL")
echo "$CB_URL" | grep -q "^http://127.0.0.1:8787/v1/oauth/callback?" \
  && ok "AS redirected to THE one stable callback" || { no "redirect: $CB_URL"; exit 1; }
CB_BODY=$(curl -s "$CB_URL")
echo "$CB_BODY" | grep -q "Connected" && ok "callback (unauthenticated route) completed the exchange" || { no "callback: $CB_BODY"; exit 1; }
# Phase C: the callback photographs the pending_snapshot (not a brokered bundle)
# with the freshly minted access token — the "Connected" page reports the count.
echo "$CB_BODY" | grep -qiE "snapshotted [0-9]+ tool" && echo "$CB_BODY" | grep -qE "\(v[0-9]+\)" \
  && ok "pending_snapshot photographed with the fresh token (connection snapshot, not a bundle)" || no "snapshot note missing: $CB_BODY"
NTSTATUS=$(get "/connections" | python3 -c "
import sys, json
print([c['status'] for c in json.load(sys.stdin)['connections'] if c['id'] == '$NTCONN'][0])")
[ "$NTSTATUS" = "active" ] && ok "connection is active" || no "status: $NTSTATUS"
EXCH=$(as_field "['grants'][0]")
echo "$EXCH" | grep -q "'grant': 'authorization_code'" && echo "$EXCH" | grep -q "'ok': True" \
  && echo "$EXCH" | grep -q "'code_verifier_present': True" \
  && echo "$EXCH" | grep -q "'resource': 'http://127.0.0.1:$AS_PORT/mcp'" \
  && ok "token exchange carried code_verifier + resource= (leg 2)" || no "exchange: $EXCH"
[ "$(as_field "['refresh'].__len__()")" = "1" ] && ok "AS holds exactly one valid refresh token" || no "RTs: $(as_field "['refresh']")"
RT1=$(as_field "['refresh'][0]")
EXCH_ACC=$(as_field "['grants'][0]['minted_access']")
SEALED1=$(pq "select encode(credential_sealed,'hex') from integration_connections where id='$NTCONN'")
[ -n "$SEALED1" ] && ok "refresh token sealed at rest (credential_sealed non-null)" || no "no sealed credential"
get "/connections" | grep -q "$RT1" && no "refresh token echoed in connection listing!" || ok "refresh token never in API responses"
LIST_AUTH=$(as_field "['mcp'][-1]['auth']")
[ -n "$EXCH_ACC" ] && echo "$LIST_AUTH" | grep -q "Bearer $EXCH_ACC" \
  && ok "photograph used the exchange's access token (zero refreshes)" || no "photo auth: $LIST_AUTH (exchange minted $EXCH_ACC)"
[ "$(as_field "['grants'].__len__()")" = "1" ] && ok "no refresh grant needed yet" || no "grants: $(as_field "['grants']")"

# Grant selector by type — indexes are brittle.
last_refresh_grant() {
  as_state | python3 -c "
import sys, json
gs = [g for g in json.load(sys.stdin)['grants'] if g['grant'] == 'refresh_token']
print(json.dumps(gs[-1]) if gs else '')"
}

# ── Broker with OAuth: reactive 401, rotation, proactive pre-expiry ───────
# Fresh probe session per cluster: the dead-runner watchdog reaps a killed
# container's session ~60s after its last heartbeat, so each cluster gets
# its own just-in-time session.
say "REFRESH — reactive 401 + atomic rotation (old token dead) + proactive pre-expiry"
# Phase C: the OAuth custody rides the connection; the agent declares a
# requirement (slot fx-notion) that create_run resolves to the fx-notion
# connection's snapshot — the broker mint/refresh/rotation below is unchanged.
post "/agents" "{\"name\":\"conn-nt-$$\",\"policy\":\"conn-e2e\",\"connection_requirements\":[{\"slot\":\"fx-notion\",\"connector\":{\"url\":\"http://127.0.0.1:$AS_PORT/mcp\",\"slug\":\"fx-notion\"},\"required_tools\":[\"nt_search\"],\"binding_mode\":\"organization\"}]}" >/dev/null
SID_NT=$(probe_session "conn-nt-$$")
TOK_NT=$(token_for "$SID_NT")
R=$(broke "$SID_NT" "$TOK_NT" n1 "mcp__fx-notion__nt_search" '{"query":"roadmap"}')
echo "$R" | j "['ok']" | grep -q True && echo "$R" | grep -q "custody works" \
  && ok "brokered call OK on the cached exchange token" || no "call n1: $R"
[ "$(as_field "['grants'].__len__()")" = "1" ] && ok "still zero refresh grants (cache hit)" || no "unexpected refresh"

as_admin expire-access
R=$(broke "$SID_NT" "$TOK_NT" n2 "mcp__fx-notion__nt_search" '{"query":"after expiry"}')
echo "$R" | j "['ok']" | grep -q True && ok "server-side expiry mid-run → reactive 401 → refresh → retry OK" || no "call n2: $R"
G2=$(last_refresh_grant)
echo "$G2" | grep -q "\"used_refresh\": \"$RT1\"" \
  && echo "$G2" | grep -q "\"resource\": \"http://127.0.0.1:$AS_PORT/mcp\"" \
  && ok "refresh grant used RT#1 and carried resource=" || no "refresh grant: $G2"
[ "$(as_field "['refresh'].__len__()")" = "1" ] && [ "$(as_field "['refresh'][0]")" != "$RT1" ] \
  && ok "ROTATION: exactly one valid RT and it is a NEW one" || no "RTs after rotation: $(as_field "['refresh']")"
SEALED2=$(pq "select encode(credential_sealed,'hex') from integration_connections where id='$NTCONN'")
[ -n "$SEALED2" ] && [ "$SEALED2" != "$SEALED1" ] && ok "rotation persisted atomically (sealed bytes changed)" || no "sealed unchanged!"
DEAD=$(curl -s -X POST -d "grant_type=refresh_token&refresh_token=$RT1&client_id=x" "http://127.0.0.1:$AS_PORT/token")
echo "$DEAD" | grep -q "invalid_grant" && ok "the OLD refresh token is dead at the AS" || no "old RT still works: $DEAD"

as_admin mode '{"cimd": false, "access_ttl": 4}'
as_admin expire-access
SID_P=$(probe_session "conn-nt-$$")
TOK_P=$(token_for "$SID_P")
R=$(broke "$SID_P" "$TOK_P" n3 "mcp__fx-notion__nt_search" '{"query":"short ttl"}')
echo "$R" | j "['ok']" | grep -q True && ok "refresh minted a short-lived (4s) access token" || no "call n3: $R"
GR_BEFORE=$(as_field "['grants'].__len__()")
LAST_ACC=$(last_refresh_grant | python3 -c "import sys,json;print(json.load(sys.stdin).get('minted_access',''))" 2>/dev/null)
R=$(broke "$SID_P" "$TOK_P" n4 "mcp__fx-notion__nt_search" '{"query":"proactive"}')
echo "$R" | j "['ok']" | grep -q True && [ "$(as_field "['grants'].__len__()")" -gt "$GR_BEFORE" ] \
  && ok "PROACTIVE refresh: <5min-to-expiry token replaced before use (no 401 needed)" || no "call n4: $R"
N4_AUTH=$(as_state | python3 -c "
import sys, json
calls = [m for m in json.load(sys.stdin)['mcp'] if m['method'] == 'tools/call']
print(calls[-1]['auth'] if calls else '')")
[ -n "$LAST_ACC" ] && [ "$N4_AUTH" != "Bearer $LAST_ACC" ] \
  && ok "the proactive call carried a NEWER token than the expiring one" || no "n4 auth: $N4_AUTH (expiring was $LAST_ACC)"

# ── CIMD + pre-registered/confidential client identities ──────────────────
say "CLIENT IDENTITY — CIMD document + pre-registered confidential client"
CIMD=$(curl -s http://127.0.0.1:8787/.well-known/fluidbox-client.json)
echo "$CIMD" | grep -q '"client_id": *"http://127.0.0.1:8787/.well-known/fluidbox-client.json"' \
  && echo "$CIMD" | grep -q "/v1/oauth/callback" \
  && echo "$CIMD" | grep -q '"token_endpoint_auth_method": *"none"' \
  && ok "CIMD document served — its URL IS the client_id (no admin token needed)" || no "cimd doc: $CIMD"

as_admin mode '{"cimd": true, "access_ttl": 3600}'
REG_BEFORE=$(as_field "['register'].__len__()")
CODE=$(post "/connections" "{\"provider\":\"mcp_http\",\"auth_kind\":\"oauth\",\"base_url\":\"http://127.0.0.1:$AS_PORT/mcp\",\"display_name\":\"fx-notion-cimd\"}")
[ "$CODE" = "200" ] && ok "direct oauth connection created (non-catalog path)" || { no "conn → $CODE: $(cat "$B")"; exit 1; }
CIMDCONN=$(jb "['connection']['id']")
CODE=$(post "/connections/$CIMDCONN/oauth/start" "{}")
AUTH_URL2=$(jb "['authorize_url']")
# The AS advertises CIMD, but this deployment's public URL is loopback
# http — an AS could never FETCH our client document (real Notion answered
# "Unknown OAuth client" to exactly this). The eligibility guard must fall
# through to DCR, which POSTs our metadata instead.
echo "$AUTH_URL2" | grep -q "client_id=dcr-client-" \
  && ok "CIMD advertised but public URL is loopback http → DCR used (eligibility guard)" || no "guard client_id: $AUTH_URL2"
[ "$(as_field "['register'].__len__()")" = "$((REG_BEFORE + 1))" ] \
  && ok "fresh DCR registration minted for the new connection" || no "register count: $(as_field "['register'].__len__()")"
CB2=$(curl -s "$(curl -s -o /dev/null -w '%{redirect_url}' "$AUTH_URL2")")
echo "$CB2" | grep -q "Connected" && ok "guarded dance completed" || no "guarded callback: $CB2"
# Reconnect re-resolution: seed the pre-guard footgun — a STORED CIMD
# identity from a loopback deployment — and start again; it must be
# re-resolved to DCR, never replayed at the AS.
psql "$DATABASE_URL" -qc "update integration_connections set oauth = oauth || '{\"client_id\": \"http://127.0.0.1:8787/.well-known/fluidbox-client.json\", \"client_id_source\": \"cimd\"}'::jsonb where id = '$CIMDCONN'"
post "/connections/$CIMDCONN/oauth/start" "{}" >/dev/null
AUTH_URL2B=$(jb "['authorize_url']")
echo "$AUTH_URL2B" | grep -q "client_id=dcr-client-" \
  && ok "stale stored CIMD identity re-resolved on reconnect (not replayed)" || no "stale reuse: $AUTH_URL2B"

PRE_SECRET="pre-secret-xyz-$$"
CODE=$(post "/connections" "{\"provider\":\"mcp_http\",\"auth_kind\":\"oauth\",\"base_url\":\"http://127.0.0.1:$AS_PORT/mcp\",
  \"display_name\":\"fx-notion-conf\",\"client_id\":\"pre-client-7\",\"client_secret\":\"$PRE_SECRET\"}")
CONFCONN=$(jb "['connection']['id']")
post "/connections/$CONFCONN/oauth/start" "{}" >/dev/null
AUTH_URL3=$(jb "['authorize_url']")
echo "$AUTH_URL3" | grep -q "client_id=pre-client-7" \
  && ok "pre-registered client_id wins over CIMD/DCR (priority order)" || no "conf client_id: $AUTH_URL3"
CB3=$(curl -s "$(curl -s -o /dev/null -w '%{redirect_url}' "$AUTH_URL3")")
echo "$CB3" | grep -q "Connected" && ok "confidential dance completed" || no "conf callback: $CB3"
CONF_AUTH=$(as_state | python3 -c "
import sys, json, base64
gs = [g for g in json.load(sys.stdin)['grants'] if g['client_id'] == 'pre-client-7' or 'pre-client-7' in g.get('client_auth','')]
print(gs[-1]['client_auth'] if gs else '')")
echo "$CONF_AUTH" | grep -q "^Basic " \
  && python3 -c "
import base64, sys
b = '$CONF_AUTH'.removeprefix('Basic ')
sys.exit(0 if base64.b64decode(b).decode() == 'pre-client-7:$PRE_SECRET' else 1)" \
  && ok "confidential client authenticated client_secret_basic at the token endpoint" || no "client auth: $CONF_AUTH"
get "/connections" | grep -q "$PRE_SECRET" && no "client secret echoed!" || ok "client secret sealed, never in responses"

CODE=$(curl -s -o "$B" -w "%{http_code}" "http://127.0.0.1:8787/v1/oauth/callback?code=x&state=garbage")
[ "$CODE" = "400" ] && ok "tampered/garbage state → 400 (nothing trusted before it verifies)" || no "tamper → $CODE"

# ── Revoke → fail closed → reconnect revives ──────────────────────────────
say "FAIL-CLOSED — invalid_grant ⇒ connection error ⇒ zero-spend refusal ⇒ reconnect"
SID_R=$(probe_session "conn-nt-$$")
TOK_R=$(token_for "$SID_R")
as_admin revoke
as_admin expire-access
R=$(broke "$SID_R" "$TOK_R" n5 "mcp__fx-notion__nt_search" '{"query":"post revoke"}')
echo "$R" | j "['ok']" | grep -q False && echo "$R" | grep -qi "reconnect" \
  && ok "in-flight brokered call failed visibly with a reconnect hint" || no "call n5: $R"
NTSTATUS=$(get "/connections" | python3 -c "
import sys, json
print([c['status'] for c in json.load(sys.stdin)['connections'] if c['id'] == '$NTCONN'][0])")
[ "$NTSTATUS" = "error" ] && ok "connection flipped to error on invalid_grant" || no "status: $NTSTATUS"
get "/connections" | grep -q "invalid_grant" && ok "error note surfaced for the dashboard" || no "no error note"
CODE=$(post "/sessions" "{\"agent\":\"conn-nt-$$\",\"task\":\"should fail closed\",\"autonomous\":true}")
[ "$CODE" = "400" ] && ok "new run with the errored connection → 400 at zero spend" || no "run → $CODE: $(cat "$B")"

CODE=$(post "/connections/$NTCONN/oauth/start" "{}")
[ "$CODE" = "200" ] && ok "reconnect: the dance restarts on the SAME connection" || { no "restart → $CODE: $(cat "$B")"; exit 1; }
AUTH_URL4=$(jb "['authorize_url']")
CB4=$(curl -s "$(curl -s -o /dev/null -w '%{redirect_url}' "$AUTH_URL4")")
echo "$CB4" | grep -q "Connected" && ok "reconnect dance completed" || no "reconnect callback: $CB4"
NTSTATUS=$(get "/connections" | python3 -c "
import sys, json
print([c['status'] for c in json.load(sys.stdin)['connections'] if c['id'] == '$NTCONN'][0])")
[ "$NTSTATUS" = "active" ] && ok "connection revived (error → active)" || no "status after reconnect: $NTSTATUS"
CODE=$(post "/sessions" "{\"agent\":\"conn-nt-$$\",\"task\":\"works again\",\"autonomous\":true,\"budgets\":$PROBE_BUDGET}")
[ "$CODE" = "200" ] && ok "new run creates again after reconnect" || no "run after reconnect → $CODE"
SID_RE=$(jb "['session']['id']")
docker kill "$(docker ps -a --filter "label=fluidbox.session=$SID_RE" --format '{{.ID}}' | head -1)" >/dev/null 2>&1

# ── Secrets sweep ─────────────────────────────────────────────────────────
say "SECRETS — refresh/access tokens and keys appear nowhere"
RT_NOW=$(as_field "['refresh'][0]")
for SECRET in "$RT_NOW" "$RT1" "$SN_KEY" "$PRE_SECRET"; do
  [ -z "$SECRET" ] && continue
  get "/connections" | grep -q "$SECRET" && no "secret '$SECRET' in connections!" || true
  get "/catalog" | grep -q "$SECRET" && no "secret '$SECRET' in catalog!" || true
done
ok "connections + catalog responses are secret-free"
curl -s -H "$H" "$API/v1/sessions/$SID_NT" | grep -qE "acc-[0-9]+|rt-[0-9]+" \
  && no "oauth token material in RunSpec!" || ok "no token material in the frozen RunSpec"
curl -s -H "$H" "$API/v1/sessions/$SID_NT/events?limit=500" | grep -qE "\"acc-[0-9]+\"|\"rt-[0-9]+\"" \
  && no "oauth token material in ledger!" || ok "no token material in the ledger"
CID_NT=$(docker ps -a --filter "label=fluidbox.session=$SID_NT" --format '{{.ID}}' | head -1)
docker inspect "$CID_NT" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -qE "acc-[0-9]+|rt-[0-9]+" \
  && no "oauth token material in sandbox env!" || ok "no token material in the sandbox env"

# ── LIVE — an agent uses a catalog connector end-to-end ───────────────────
say "LIVE — agent uses the catalog-connected workspace-info bundle (self-skips)"
if [ "${E2E_SKIP_LIVE:-0}" = "1" ] || [ -z "${ANTHROPIC_API_KEY:-}" ] \
   || ! curl -fsS -m 2 http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1; then
  echo "  SKIP: live tier needs ANTHROPIC_API_KEY + gateway (E2E_SKIP_LIVE=${E2E_SKIP_LIVE:-0})"
else
  LB='{"max_wall_clock_secs": 240, "max_cost_usd": 0.30}'
  post "/agents" "{\"name\":\"conn-live-$$\",\"policy\":\"conn-e2e\",\"capability_bundles\":[\"workspace-info\"]}" >/dev/null
  CODE=$(post "/sessions" "{\"agent\":\"conn-live-$$\",\"autonomous\":true,\"budgets\":$LB,
    \"task\":\"Call the tool mcp__workspace-info__workspace_file_count once, then reply with one sentence stating the file count. Do not edit files.\"}")
  [ "$CODE" = "200" ] && ok "live run created on the catalog-attached bundle" || no "live run → $CODE: $(cat "$B")"
  LSID=$(jb "['session']['id']")
  LDONE=""
  for _ in $(seq 1 100); do
    ST=$(sfield "$LSID" "['status']")
    case "$ST" in completed) LDONE=1; break ;; failed|cancelled|budget_exceeded) echo "  run ended $ST"; break ;; esac
    sleep 3
  done
  [ -n "$LDONE" ] && ok "live run completed" || no "live run did not complete"
  WSEV=$(pq "select count(*) from events where session_id='$LSID' and type='tool.requested' and payload::text like '%mcp__workspace-info__workspace_file_count%'")
  [ "${WSEV:-0}" -ge 1 ] && ok "the agent used the catalog connector through the real SDK" || no "no workspace-info tool call: $WSEV"
fi

say "RESULT"
rm -rf "$CONN_DIR" /tmp/fbx-conn-body.json
printf "  \033[1m%d passed, %d failed\033[0m\n" "$pass" "$fail"
[ "$fail" = "0" ]
