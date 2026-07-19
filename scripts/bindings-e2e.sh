#!/usr/bin/env bash
# Phase C acceptance E2E — connection ownership + run resource bindings, driven
# end-to-end over real HTTP against a REAL conformant issuer (Dex) and a fake
# brokered MCP server, with FLUIDBOX_REQUIRE_SSO=1. This owns its stack: it boots
# Dex + a bearer-checked fake MCP + the fluidbox control plane and drives
# everything with curl cookie jars (a jar == a browser) and psql fixtures.
#
# Design: docs/plans/2026-07-14-multi-user-mcp-control-plane-design.md (v4),
# Phase C acceptance :1495-1505. It asserts THAT list:
#   - Alice and Bob invoke the same agent and use DIFFERENT connections (d/e);
#   - neither can select or inspect the other's personal connection (c);
#   - the model receives IDENTICAL aliases but the broker resolves the correct
#     binding (d proves aliases; e proves the credential turned server-side);
#   - approval by a THIRD user does not change credential identity (f);
#   - missing/ambiguous bindings — incl. a snapshot missing a required tool —
#     fail BEFORE sandbox provisioning (g);
#   - the bound credential is the one used, never one named in user input (e/f);
#   - new runs from unconverted legacy revisions are refused after the cutoff (j).
# Plus the live-revocation matrix the design reserves at gate step 10:
#   generation fail-closed (h) and membership kill-switch (i); and the
#   personal-connection approval boundary (k).
#
# House style mirrors scripts/identity-e2e.sh: pass/fail counters, section
# banners, curl cookie jars, a `db()` psql helper (-X -q -A -t), fail-fast
# preconditions, a cleanup trap. `set -e` is intentionally OMITTED (this drives
# a large negative matrix); failures are counted and a nonzero `fail` exits 1.
#
# HERMETIC + no model spend: the runs never launch a sandbox (there is no runner
# image in CI, so provisioning fails — that is FINE). The internal permission
# gate is driven directly with a psql-forged session token against a run forced
# to 'running' as a documented test fixture (see forge_running).
#
# File-wide suppressions (must precede the first command to apply file-wide):
#  SC2015: `[ test ] && ok … || no …` is the house idiom; `ok`/`no` return 0.
#  SC2030/SC2031: DATABASE_URL is exported ONLY in the server subshell; the
#          top-level `db()` reads the outer value — false positive.
# shellcheck disable=SC2015,SC2030,SC2031
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)

# ── Preconditions ────────────────────────────────────────────────────────────
if [ -z "${DATABASE_URL:-}" ]; then
  echo "bindings-e2e: DATABASE_URL is required (CI provides the Postgres service)." >&2
  echo "  This script drives real cookies + a real issuer + real bindings against a" >&2
  echo "  real DB; it will not run — and must never silently skip — without one." >&2
  exit 2
fi
command -v docker  >/dev/null 2>&1 || { echo "bindings-e2e: docker is required (for Dex)." >&2; exit 2; }
command -v curl    >/dev/null 2>&1 || { echo "bindings-e2e: curl is required." >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "bindings-e2e: python3 is required (JSON + the fake MCP)." >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "bindings-e2e: openssl is required (sha256 for the forged session token)." >&2; exit 2; }
# psql is REQUIRED, not optional: the acceptance PROVES the binding rows, the
# snapshot versions, the generation bump, and the legacy-bundle fixture directly.
# None of them may silently skip, so a missing psql aborts the whole run.
command -v psql    >/dev/null 2>&1 || { echo "bindings-e2e: psql is required (acceptance must be PROVEN, not skipped)." >&2; exit 2; }

# ── Config ───────────────────────────────────────────────────────────────────
API=http://127.0.0.1:8787
ISSUER=http://127.0.0.1:5556/dex
# Pinned by the multi-arch INDEX digest (same image identity-e2e uses). Dex's
# staticPasswords set email_verified=true by default, which the gate needs.
DEX_IMAGE=${DEX_IMAGE:-ghcr.io/dexidp/dex:v2.45.0@sha256:b8469881d3cb3a73001506f0d3aaefecb9c45d2311c1e0f405d8ac538316c59d}
SLUG=acme
PW=password              # matches the embedded bcrypt hash below (non-secret test creds)
U1=alice@example.com     # bootstrap owner
U2=bob@example.com       # plain member

ADMIN_TOKEN=$(openssl rand -hex 32)
CRED_KEY=$(openssl rand -hex 32)
CLIENT_SECRET=$(openssl rand -hex 16)
CLIENT_ID=fluidbox-acme

# The fake brokered MCP + the three credentials it accepts (test-only, like
# PW above — they DO appear in the request log, which is exactly how we prove
# which credential the broker turned server-side).
MCP_PORT=8898
MCP_URL="http://127.0.0.1:$MCP_PORT/mcp"
TOK_ALICE="kbtok-alice-$$"
TOK_BOB="kbtok-bob-$$"
TOK_ORG="kbtok-org-$$"
SLUG_CAT="kb-fake"       # the custom catalog entry's slug (valid [a-z0-9-])

WORK=$(mktemp -d)
DEX_NAME="fbx-dex-bindings-$$"
MCP_LOG="$WORK/mcp-requests.jsonl"; : > "$MCP_LOG"
SERVER_LOG="$WORK/server.log"
SERVER_PID=""
MCP_PID=""
DATA_DIR="$WORK/data"; mkdir -p "$DATA_DIR"
UB="$WORK/ub"           # scratch body file for the cookie/admin curl helpers

pass=0; fail=0
ok()  { printf "  \033[1;32m✓\033[0m %s\n" "$1"; pass=$((pass+1)); }
no()  { printf "  \033[1;31m✗\033[0m %s\n" "$1"; fail=$((fail+1)); }
say() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }
# Fail-fast precondition guard (identical semantics to identity-e2e): when a
# value a section DEPENDS ON is empty, record ONE loud failure and return nonzero
# so the caller SKIPS the dependent steps — keeping one root failure legible
# instead of fanning it out into dozens of misleading downstream ones. It never
# weakens an assertion: in the healthy path the value is non-empty and every
# guarded assertion runs exactly as before.
need() { # value message
  [ -n "$1" ] && return 0
  no "precondition unmet — $2"
  return 1
}

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }
urlenc() { python3 -c "import sys,urllib.parse as u;print(u.quote(sys.argv[1],safe=''))" "$1"; }
urljoin() { python3 -c "import sys,urllib.parse as u;print(u.urljoin(sys.argv[1],sys.argv[2]))" "$1" "$2"; }

# psql shortcut. -q suppresses the command tag (else "INSERT 0 1" would poison a
# RETURNING capture); -A -t keep tuples-only/unaligned; -X skips ~/.psqlrc.
# stderr flows to the log (not swallowed) so a broken query is visible.
db() { psql "$DATABASE_URL" -X -q -A -t -c "$1"; }

# ── Cleanup ──────────────────────────────────────────────────────────────────
# shellcheck disable=SC2329  # invoked via the EXIT/INT/TERM trap
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  [ -n "$MCP_PID" ] && kill "$MCP_PID" 2>/dev/null
  docker rm -f "$DEX_NAME" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ── Fake brokered MCP server (the "class 2" upstream) ─────────────────────────
# Streamable-HTTP-shaped: JSON-RPC POSTs to /mcp, plain JSON responses. Accepts
# EXACTLY the three test bearers (TOK_ALICE/TOK_BOB/TOK_ORG); anything else is a
# 401 (a real credentialed server). Serves initialize (with a negotiated
# protocolVersion — the snapshot path REQUIRES one), notifications/initialized,
# tools/list (kb_search + kb_write, stable schemas), and tools/call (echo).
# EVERY request is logged as one jsonl line {path, auth, method (jsonrpc), tool}
# — that log is how we prove WHICH credential the control plane turned.
start_mcp() {
  python3 - "$MCP_PORT" "$MCP_LOG" "$TOK_ALICE" "$TOK_BOB" "$TOK_ORG" <<'PYEOF' &
import http.server, json, sys
port, log = int(sys.argv[1]), sys.argv[2]
accepted = {"Bearer " + t for t in sys.argv[3:]}
class Mcp(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        try: req = json.loads(raw)
        except Exception: req = {}
        method = req.get("method", "")
        auth = self.headers.get("authorization", "")
        tool = (req.get("params") or {}).get("name", "") if method == "tools/call" else ""
        with open(log, "a") as f:
            f.write(json.dumps({"path": self.path, "auth": auth,
                                "method": method, "tool": tool}) + "\n")
        rid = req.get("id")
        # Credential check FIRST — a rejected credential never reaches a method.
        if auth not in accepted:
            return self._send(401, {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32001, "message": "unauthorized"}})
        if self.path != "/mcp":
            return self._send(404, {"message": "not found"})
        if method == "initialize":
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-kb", "version": "1.0.0"}}})
        if method == "notifications/initialized":
            self.send_response(202); self.send_header("content-length", "0")
            self.end_headers(); return
        if method == "tools/list":
            tools = [
                {"name": "kb_search", "description": "Search the team knowledge base",
                 "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}},
                                 "required": ["query"]}},
                {"name": "kb_write", "description": "Write a note to the knowledge base",
                 "inputSchema": {"type": "object", "properties": {"note": {"type": "string"}},
                                 "required": ["note"]}},
            ]
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}})
        if method == "tools/call":
            name = (req.get("params") or {}).get("name", "")
            if name == "kb_search":
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": "kb result — deploy checklist v3"}],
                    "isError": False}})
            if name == "kb_write":
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": "wrote note"}], "isError": False}})
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"no such tool {name}"}], "isError": True}})
        return self._send(200, {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": "method not found"}})
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), Mcp).serve_forever()
PYEOF
  MCP_PID=$!
  for _ in $(seq 1 40); do
    # A bare POST (no auth) → 401 proves the listener is up and enforcing.
    if curl -s -o /dev/null -X POST "$MCP_URL" 2>/dev/null; then
      ok "fake MCP up on :$MCP_PORT (bearer-checked, request log at mcp-requests.jsonl)"; return 0
    fi
    sleep 0.25
  done
  echo "bindings-e2e: fake MCP did not become ready" >&2; exit 1
}

# Count logged requests matching a jsonrpc method (optionally a tool).
mcp_count() { # method [tool]
  python3 - "$MCP_LOG" "$1" "${2:-}" <<'PYEOF'
import json, sys
log, method, tool = sys.argv[1], sys.argv[2], sys.argv[3]
n = 0
for line in open(log):
    r = json.loads(line)
    if r["method"] == method and (not tool or r.get("tool") == tool):
        n += 1
print(n)
PYEOF
}

# The Authorization header of the LAST logged request matching a method — how we
# prove which sealed credential the broker turned server-side.
mcp_last_auth() { # [method]
  python3 - "$MCP_LOG" "${1:-}" <<'PYEOF'
import json, sys
log, method = sys.argv[1], sys.argv[2]
last = ""
for line in open(log):
    r = json.loads(line)
    if not method or r.get("method") == method:
        last = r.get("auth", "")
print(last)
PYEOF
}

# ── Dex ──────────────────────────────────────────────────────────────────────
# TWO static users: alice (bootstrap owner) + bob (plain member). Both share the
# embedded bcrypt hash of "password"; Dex sets email_verified=true by default.
# skipApprovalScreen removes the consent form so the curl driver never POSTs it.
start_dex() {
  cat > "$WORK/dex.yaml" <<YAML
issuer: $ISSUER
storage:
  type: memory
web:
  http: 0.0.0.0:5556
oauth2:
  skipApprovalScreen: true
enablePasswordDB: true
staticClients:
  - id: $CLIENT_ID
    name: fluidbox acme
    secret: $CLIENT_SECRET
    redirectURIs:
      - $API/v1/auth/callback
staticPasswords:
  - email: $U1
    hash: "\$2y\$10\$KpzrbYoCGuADz8/.HvAWquPKsITtUSs5TcVTnFIA0F01q43rphRx2"
    username: alice
    userID: "aaaaaaaa-0000-0000-0000-000000000001"
  - email: $U2
    hash: "\$2y\$10\$KpzrbYoCGuADz8/.HvAWquPKsITtUSs5TcVTnFIA0F01q43rphRx2"
    username: bob
    userID: "bbbbbbbb-0000-0000-0000-000000000002"
YAML
  docker rm -f "$DEX_NAME" >/dev/null 2>&1
  docker run -d --name "$DEX_NAME" \
    -p 127.0.0.1:5556:5556 \
    -v "$WORK/dex.yaml:/etc/dex/config.yaml:ro" \
    --entrypoint dex "$DEX_IMAGE" serve /etc/dex/config.yaml >/dev/null || {
      echo "bindings-e2e: failed to start Dex container" >&2; exit 1; }
  for _ in $(seq 1 60); do
    if curl -sf "$ISSUER/.well-known/openid-configuration" >/dev/null 2>&1; then
      ok "Dex up ($DEX_IMAGE) — discovery serving at $ISSUER"; return 0
    fi
    sleep 1
  done
  echo "bindings-e2e: Dex did not become ready" >&2
  docker logs "$DEX_NAME" 2>&1 | tail -30 >&2
  exit 1
}

# ── Server ───────────────────────────────────────────────────────────────────
# FLUIDBOX_SERVER_BIN lets CI reuse a prebuilt binary (recommended). This run is
# REQUIRE_SSO=1 throughout: the admin token reaches ONLY /v1/admin (bootstrap),
# browsers use __Host-fbx_web cookies, and the in-sandbox internal gateway uses a
# per-session token. FLUIDBOX_TRUST_FORWARDED_FOR stays UNSET (client IP is the
# socket peer). The sealer key gates connections/catalog + seals credentials.
start_server() {
  : > "$SERVER_LOG"
  (
    cd "$ROOT" || exit 1
    export DATABASE_URL="$DATABASE_URL"
    export FLUIDBOX_BIND=127.0.0.1:8787
    export FLUIDBOX_PUBLIC_URL=http://127.0.0.1:8787
    export FLUIDBOX_ADMIN_TOKEN="$ADMIN_TOKEN"
    export FLUIDBOX_CREDENTIAL_KEY="$CRED_KEY"
    export FLUIDBOX_PROVIDER=docker
    # Force provisioning to fail INSTANTLY. CI has no sandbox runner image, and the
    # forge_running fixture needs each run to FAIL provisioning to settle terminal.
    # A missing image on a REAL registry takes ~2 min to give up (that blew the
    # settle budget → runs stuck at 'finalizing'); a dead-registry ref (localhost:1,
    # nothing listening → connection-refused in ms) makes the failure immediate.
    # These exports run after the CI job env, so they win over any image set there.
    export FLUIDBOX_SANDBOX_IMAGE=localhost:1/fluidbox-absent:ci
    export FLUIDBOX_CODEX_SANDBOX_IMAGE=localhost:1/fluidbox-absent:ci
    export FLUIDBOX_DATA_DIR="$DATA_DIR"
    export FLUIDBOX_REQUIRE_SSO=1
    unset FLUIDBOX_TRUST_FORWARDED_FOR
    export RUST_LOG="${RUST_LOG:-warn,fluidbox_server=info}"
    if [ -n "${FLUIDBOX_SERVER_BIN:-}" ] && [ -x "${FLUIDBOX_SERVER_BIN}" ]; then
      exec "$FLUIDBOX_SERVER_BIN"
    fi
    exec cargo run -q -p fluidbox-server
  ) >>"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 180); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "bindings-e2e: server process exited during boot" >&2
      tail -40 "$SERVER_LOG" >&2; exit 1
    fi
    if curl -sf "$API/v1/health" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "bindings-e2e: server did not become ready" >&2
  tail -40 "$SERVER_LOG" >&2
  exit 1
}

# ── HTTP helpers ─────────────────────────────────────────────────────────────
AH="authorization: Bearer $ADMIN_TOKEN"
BODY=""; CODE=""
# admin_* — the operator token (reaches ONLY /v1/admin/* under REQUIRE_SSO).
admin_post() { CODE=$(curl -s -o "$UB" -w '%{http_code}' -X POST -H "$AH" -H 'content-type: application/json' -d "$2" "$API$1"); BODY=$(cat "$UB"); }
admin_get()  { CODE=$(curl -s -o "$UB" -w '%{http_code}' -H "$AH" "$API$1"); BODY=$(cat "$UB"); }
# u_* — a browser session (cookie jar). Cookie-authenticated non-GETs carry the
# CSRF header (a cross-site form cannot set it).
u_get()  { CODE=$(curl -s -o "$UB" -w '%{http_code}' -b "$1" "$API$2"); BODY=$(cat "$UB"); }
u_post() { CODE=$(curl -s -o "$UB" -w '%{http_code}' -X POST -b "$1" -H 'content-type: application/json' -H 'x-fluidbox-csrf: 1' -d "$3" "$API$2"); BODY=$(cat "$UB"); }
# The in-sandbox internal gate: authenticated by the per-session bearer token.
sess_call() { # sid token-plaintext json  → prints the tools/call response body
  curl -s -X POST -H "authorization: Bearer $2" -H 'content-type: application/json' -d "$3" "$API/internal/sessions/$1/tools/call"
}

location_from_headers() { grep -i '^location:' "$1" | head -1 | sed -E 's/^[Ll]ocation: *//' | tr -d '\r'; }

# ── OIDC driving (adapted from identity-e2e; no XFF — TRUST_FORWARDED_FOR is
# unset, and this run does only two logins, well under the per-IP cap) ─────────
fbx_start() { # jar slug
  curl -s -c "$1" -b "$1" -D "$WORK/h.start" -o /dev/null \
    "$API/v1/auth/login/$2/start?redirect_to=$(urlenc /)"
  location_from_headers "$WORK/h.start"
}
dex_login() { # jar authorize_url email pw  → echoes the fluidbox callback URL
  local jar=$1 authz=$2 email=$3 pw=$4 raw eff page action post_url loc cur hops abs
  # CRITICAL: the -w argument must NOT begin with '@' (curl would read a file);
  # a '@'-free sentinel keeps every dex_login fail-closed instead.
  raw=$(curl -s -c "$jar" -b "$jar" -L -w '__FBX_EFF__%{url_effective}' "$authz")
  eff=${raw##*__FBX_EFF__}; page=${raw%__FBX_EFF__*}
  action=$(printf '%s' "$page" | grep -oiE 'action="[^"]*"' | head -1 \
    | sed -E 's/[Aa]ction="([^"]*)"/\1/' | sed 's/&amp;/\&/g')
  [ -z "$action" ] && { echo "DEX_NO_FORM"; return 1; }
  post_url=$(urljoin "$eff" "$action")
  curl -s -c "$jar" -b "$jar" -D "$WORK/h.post" -o /dev/null \
    --data-urlencode "login=$email" --data-urlencode "password=$pw" "$post_url"
  loc=$(location_from_headers "$WORK/h.post")
  [ -z "$loc" ] && { echo "DEX_LOGIN_FAILED"; return 1; }
  cur=$post_url; hops=0
  while [ -n "$loc" ] && [ "$hops" -lt 8 ]; do
    abs=$(urljoin "$cur" "$loc")
    case "$abs" in "$API"/v1/auth/callback*) echo "$abs"; return 0;; esac
    curl -s -c "$jar" -b "$jar" -D "$WORK/h.hop" -o /dev/null "$abs"
    cur=$abs; loc=$(location_from_headers "$WORK/h.hop"); hops=$((hops+1))
  done
  echo "DEX_NO_CALLBACK"; return 1
}
# login: full round-trip in a FRESH jar → echoes the callback http code.
login() { # jar email pw slug
  : > "$1"
  local authz cb
  authz=$(fbx_start "$1" "$4"); [ -z "$authz" ] && { echo NOSTART; return 1; }
  cb=$(dex_login "$1" "$authz" "$2" "$3") || { echo "$cb"; return 1; }
  curl -s -c "$1" -b "$1" -D "$WORK/h.cb" -o /dev/null -w '%{http_code}' "$cb"
}
me_line() { # jar → "slug|email|roles|auth_kind"
  curl -s -b "$1" "$API/v1/auth/me" | python3 -c "
import sys,json
try: d=json.load(sys.stdin)
except Exception: print('ERR'); sys.exit()
if d.get('operator'): print('operator'); sys.exit()
o=d.get('org') or {}; u=d.get('user') or {}
print('%s|%s|%s|%s' % (o.get('slug'), u.get('email'), ','.join(d.get('roles') or []), d.get('auth_kind')))
"
}

# ── The forged-run fixture ────────────────────────────────────────────────────
# A run created here NEVER launches a sandbox (no runner image in CI), so the
# orchestrator fails provisioning. We wait for the run to SETTLE — terminal AND
# its finalization intent cleared — which is the race-free quiescent point where
# no background worker writes the row again, then FORCE it to 'running' as a
# documented test fixture so the internal permission gate accepts work.
# started_at + last_heartbeat_at stay NULL, so no watchdog/wall-clock sweeper
# reaps the fixture (the stale-heartbeat reaper only fires when last_heartbeat_at
# is set; the stale-launch sweeper targets created/provisioning/initializing —
# never running; the wall-clock sweeper needs a non-null started_at). Then we
# psql-forge a session token exactly how the orchestrator mints one (kind
# 'session', token_sha256 = sha256(plaintext)). The plaintext is never echoed.
forge_running() { # sid token-plaintext label
  local sid=$1 tok=$2 label=$3 cnt st fin settled=0 sha tid
  need "$sid" "no session id for the $label run" || return 1
  cnt=$(db "select count(*) from sessions where id='$sid'")
  [ "$cnt" = 1 ] || { no "$label: session row missing (count=$cnt)"; return 1; }
  # Wait for the run to settle to a quiescent terminal state. In CI the deliberate
  # provisioning failure has been observed to take up to ~105-140s per run, so the
  # budget is 300s (600 iterations × 0.5s poll) as safety margin — the dead-registry
  # runner-image ref (set in the server env above) normally makes it fail far sooner.
  for _ in $(seq 1 600); do
    st=$(db "select status from sessions where id='$sid'")
    fin=$(db "select count(*) from session_finalizations where session_id='$sid'")
    case "$st" in
      completed|failed|cancelled|budget_exceeded) [ "$fin" = 0 ] && { settled=1; break; };;
    esac
    sleep 0.5
  done
  # Precondition: the run reached a settled terminal state (provisioning failed
  # in CI, as expected) with no pending finalization — nothing else will write it.
  [ "$settled" = 1 ] || { no "$label: run did not settle to a quiescent terminal state (status='$st', finalizations=$fin)"; return 1; }
  # Fixture (documented): force the settled run to a live 'running' state.
  db "update sessions set status='running', status_reason='bindings-e2e fixture (run never launched)' where id='$sid'" >/dev/null
  sha=$(printf '%s' "$tok" | openssl dgst -sha256 | awk '{print $NF}')
  tid=$(db "select tenant_id from sessions where id='$sid'")
  db "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, expires_at)
      values (gen_random_uuid(), '$tid', 'session', '$sid', '$sha', now() + interval '2 hours')" >/dev/null
  return 0
}

# Create a run as a browser session; sets RUN to the session id (empty on failure).
RUN=""
create_run() { # jar agent [autonomous]
  local auton=${3:-false}
  u_post "$1" "/v1/sessions" \
    "{\"agent\":\"$2\",\"task\":\"bindings-e2e\",\"repo\":{\"kind\":\"none\"},\"autonomous\":$auton}"
  RUN=$(echo "$BODY" | j "['session']['id']")
}

# Poll a run's approvals (as an owner/read_all jar) for the first pending id.
pending_approval_id() { # jar sid → prints approval id (empty until one appears)
  local aid=""
  for _ in $(seq 1 60); do
    u_get "$1" "/v1/sessions/$2/approvals"
    aid=$(echo "$BODY" | python3 -c "
import sys,json
rows=[a for a in json.load(sys.stdin).get('approvals',[]) if a.get('status')=='pending']
print(rows[0]['id'] if rows else '')" 2>/dev/null)
    [ -n "$aid" ] && break
    sleep 0.5
  done
  echo "$aid"
}

# ═════════════════════════════════════════════════════════════════════════════
say "BOOT — Dex + fake MCP + control plane (REQUIRE_SSO=1)"
start_dex
start_mcp
start_server
ok "control plane up (REQUIRE_SSO=1, sealer set, provider=docker)"

# ── (a) Operator bootstrap: org + IdP + bootstrap owner alice; alice/bob log in ─
say "(a) Operator bootstrap — org, IdP, bootstrap owner alice; alice + bob log in"
admin_post "/v1/admin/orgs" "{\"slug\":\"$SLUG\",\"display_name\":\"Acme\"}"
[ "$CODE" = 200 ] && ok "org '$SLUG' created (admin token → /v1/admin only)" || no "create org → $CODE: $BODY"
CFG_BODY=$(cat <<JSON
{"issuer":"$ISSUER","client_id":"$CLIENT_ID","client_secret":"$CLIENT_SECRET",
 "token_endpoint_auth":"client_secret_basic","bootstrap_owner_email":"$U1"}
JSON
)
admin_post "/v1/admin/orgs/$SLUG/idp" "$CFG_BODY"
[ "$CODE" = 200 ] && ok "IdP config staged (discovery validated against live Dex)" || no "create idp → $CODE: $BODY"
CFG1=$(echo "$BODY" | j "['idp']['id']")
admin_post "/v1/admin/orgs/$SLUG/idp/$CFG1/activate" '{}'
[ "$CODE" = 200 ] && ok "IdP config activated" || no "activate → $CODE: $BODY"

jarA="$WORK/jarA"; jarB="$WORK/jarB"
C=$(login "$jarA" "$U1" "$PW" "$SLUG")
[ "$C" = 302 ] && ok "alice logs in (jar A) → 302" || no "alice login → $C; server:\n$(tail -5 "$SERVER_LOG")"
case "$(me_line "$jarA")" in "$SLUG|$U1|"*owner*"|browser") ok "alice is the bootstrap OWNER";; *) no "alice /me: $(me_line "$jarA")";; esac
C=$(login "$jarB" "$U2" "$PW" "$SLUG")
[ "$C" = 302 ] && ok "bob logs in (jar B) → 302" || no "bob login → $C"
case "$(me_line "$jarB")" in
  "$SLUG|$U2|"*owner*) no "bob wrongly promoted to owner: $(me_line "$jarB")";;
  "$SLUG|$U2|"*"|browser") ok "bob is a plain MEMBER";;
  *) no "bob /me: $(me_line "$jarB")";;
esac

TID=$(db "select id from tenants where slug='$SLUG'")
need "$TID" "tenant id for '$SLUG' did not resolve" && ok "tenant id captured"

# ── Setup: policies + the shared requirement'd agent ──────────────────────────
say "SETUP — policies + a shared agent that REQUIRES the brokered connector"
# kb-allow: mcp__* allowed outright (so the broker executes and the fake MCP
# logs the credential). kb-approve: mcp__* requires human approval (sections f/k).
PY_ALLOW=$(python3 - <<'PYEOF'
import json
print(json.dumps("""name: kb-allow
defaults:
  tool_action: deny
autonomy:
  permitted: true
  on_approval_rule: deny
tools:
  - match: ["Read", "Glob", "Grep", "LS"]
    action: allow
  - match: ["mcp__*"]
    action: allow
"""))
PYEOF
)
u_post "$jarA" "/v1/policies" "{\"name\":\"kb-allow\",\"yaml\":$PY_ALLOW}"
[ "$CODE" = 200 ] && ok "policy kb-allow created" || no "kb-allow → $CODE: $BODY"
PY_APPROVE=$(python3 - <<'PYEOF'
import json
print(json.dumps("""name: kb-approve
defaults:
  tool_action: deny
autonomy:
  permitted: true
  on_approval_rule: deny
tools:
  - match: ["mcp__*"]
    action: approve
    approval_ttl_secs: 600
"""))
PYEOF
)
u_post "$jarA" "/v1/policies" "{\"name\":\"kb-approve\",\"yaml\":$PY_APPROVE}"
[ "$CODE" = 200 ] && ok "policy kb-approve created (mcp__* requires human approval)" || no "kb-approve → $CODE: $BODY"

# The shared agent: one requirement slot `kb`, binding_mode invoking_user — the
# SAME declaration Alice and Bob run, binding to DIFFERENT personal connections.
u_post "$jarA" "/v1/agents" \
  "{\"name\":\"shared-kb\",\"policy\":\"kb-allow\",\"connection_requirements\":[{\"slot\":\"kb\",\"connector\":{\"url\":\"$MCP_URL\",\"slug\":\"$SLUG_CAT\"},\"required_tools\":[\"kb_search\"],\"binding_mode\":\"invoking_user\"}]}"
[ "$CODE" = 200 ] && ok "shared agent 'shared-kb' created (slot kb, invoking_user)" || no "shared agent → $CODE: $BODY"

# ── (b) Custom catalog entry + three connections + snapshots ──────────────────
say "(b) Catalog api_key entry → alice/bob personal + alice ORG connections; snapshots v1"
u_post "$jarA" "/v1/catalog" \
  "{\"slug\":\"$SLUG_CAT\",\"name\":\"KB Fake\",\"transport\":\"streamable_http\",\"url\":\"$MCP_URL\",\"auth_mode\":\"api_key\",\"auth_hints\":{\"header_name\":\"authorization\",\"scheme\":\"Bearer\"}}"
[ "$CODE" = 200 ] && ok "custom catalog entry '$SLUG_CAT' added (api_key, tier forced custom)" || no "catalog create → $CODE: $BODY"

# alice connects it as a PERSONAL connection with TOK_ALICE (photograph proves
# the credential + freezes the snapshot).
u_post "$jarA" "/v1/catalog/$SLUG_CAT/connect" "{\"owner\":\"personal\",\"token\":\"$TOK_ALICE\",\"display_name\":\"alice-kb\"}"
[ "$CODE" = 200 ] && ok "alice connects owner=personal (TOK_ALICE)" || no "alice connect → $CODE: $BODY"
ALICE_CONN=$(echo "$BODY" | j "['connection']['id']")
[ "$(echo "$BODY" | j "['snapshot']['version']")" = 1 ] && ok "alice snapshot v1 in the connect response" || no "alice snapshot: $BODY"
# bob connects it as HIS personal connection with TOK_BOB.
u_post "$jarB" "/v1/catalog/$SLUG_CAT/connect" "{\"owner\":\"personal\",\"token\":\"$TOK_BOB\",\"display_name\":\"bob-kb\"}"
[ "$CODE" = 200 ] && ok "bob connects owner=personal (TOK_BOB)" || no "bob connect → $CODE: $BODY"
BOB_CONN=$(echo "$BODY" | j "['connection']['id']")
[ "$(echo "$BODY" | j "['snapshot']['version']")" = 1 ] && ok "bob snapshot v1" || no "bob snapshot: $BODY"
# alice (owner) connects an ORGANIZATION connection with TOK_ORG.
u_post "$jarA" "/v1/catalog/$SLUG_CAT/connect" "{\"owner\":\"organization\",\"token\":\"$TOK_ORG\",\"display_name\":\"org-kb\"}"
[ "$CODE" = 200 ] && ok "alice connects owner=organization (TOK_ORG)" || no "org connect → $CODE: $BODY"
ORG_CONN=$(echo "$BODY" | j "['connection']['id']")
[ "$(echo "$BODY" | j "['snapshot']['version']")" = 1 ] && ok "org snapshot v1" || no "org snapshot: $BODY"

need "$ALICE_CONN" "alice connection id missing" && need "$BOB_CONN" "bob connection id missing" && need "$ORG_CONN" "org connection id missing"
# Snapshot rows exist at v1 with a NON-EMPTY negotiated protocol_version.
for pair in "alice:$ALICE_CONN" "bob:$BOB_CONN" "org:$ORG_CONN"; do
  who=${pair%%:*}; cid=${pair#*:}
  SV=$(db "select snapshot_version from connection_tool_snapshots where connection_id='$cid'")
  PV=$(db "select protocol_version from connection_tool_snapshots where connection_id='$cid'")
  { [ "$SV" = 1 ] && [ -n "$PV" ]; } && ok "$who snapshot row: version=$SV protocol_version='$PV' (non-empty)" \
    || no "$who snapshot row wrong (version='$SV' protocol_version='$PV')"
done
# GET /tools reads the latest snapshot (owner-filtered).
u_get "$jarA" "/v1/connections/$ALICE_CONN/tools"
{ [ "$CODE" = 200 ] && [ "$(echo "$BODY" | j "['snapshot']['version']")" = 1 ]; } && ok "GET alice /tools → snapshot v1" || no "alice /tools → $CODE: $BODY"

# ── (c) Isolation: neither can inspect or bind the other's personal connection ─
say "(c) Isolation — bob cannot inspect/list/bind alice's personal connection"
u_get "$jarB" "/v1/connections/$ALICE_CONN/tools"
[ "$CODE" = 404 ] && ok "bob GET alice's connection /tools → 404 (invisible, not forbidden)" || no "bob inspect alice → $CODE (want 404)"
u_get "$jarB" "/v1/connections"
IDS=$(echo "$BODY" | python3 -c "import sys,json;print(' '.join(c['id'] for c in json.load(sys.stdin).get('connections',[])))" 2>/dev/null)
case " $IDS " in *" $BOB_CONN "*) BOBSEE=1;; *) BOBSEE=0;; esac
case " $IDS " in *" $ORG_CONN "*) ORGSEE=1;; *) ORGSEE=0;; esac
case " $IDS " in *" $ALICE_CONN "*) ALSEE=1;; *) ALSEE=0;; esac
{ [ "$BOBSEE" = 1 ] && [ "$ORGSEE" = 1 ] && [ "$ALSEE" = 0 ]; } \
  && ok "bob's connection list shows his personal + the org connection, NOT alice's personal" \
  || no "bob list leak (bob=$BOBSEE org=$ORGSEE alice=$ALSEE)"
# Bob explicitly binds Alice's connection on a run → 4xx (viewer read → not found).
u_post "$jarB" "/v1/sessions" \
  "{\"agent\":\"shared-kb\",\"task\":\"t\",\"repo\":{\"kind\":\"none\"},\"bindings\":{\"kb\":\"$ALICE_CONN\"}}"
{ [ "$CODE" != 200 ] && echo "$BODY" | grep -q "not found"; } \
  && ok "bob explicit-binds alice's connection → $CODE (resolves as 'not found')" \
  || no "bob cross-user explicit bind → $CODE: $BODY (want 4xx / not found)"

# ── (d) Shared agent, per-user bindings; identical aliases ────────────────────
say "(d) Same agent, different connections — per-user bindings, identical aliases"
create_run "$jarA" "shared-kb"; ALICE_RUN="$RUN"
need "$ALICE_RUN" "alice run not created" && ok "alice created a run of shared-kb ($ALICE_RUN)"
ASLOT=$(u_get "$jarA" "/v1/sessions/$ALICE_RUN" >/dev/null; echo "$BODY" | j "['session']['run_spec']['brokered'][0]['slot']")
create_run "$jarB" "shared-kb"; BOB_RUN="$RUN"
need "$BOB_RUN" "bob run not created" && ok "bob created a run of the SAME agent ($BOB_RUN)"
u_get "$jarB" "/v1/sessions/$BOB_RUN"; BSLOT=$(echo "$BODY" | j "['session']['run_spec']['brokered'][0]['slot']")
{ [ "$ASLOT" = "kb" ] && [ "$BSLOT" = "kb" ]; } \
  && ok "both RunSpecs freeze the IDENTICAL brokered alias 'kb' (the model sees the same names)" \
  || no "brokered slots differ (alice='$ASLOT' bob='$BSLOT')"
# The bindings resolved to DIFFERENT connections (psql — the frozen record).
AB=$(db "select connection_id from run_resource_bindings where session_id='$ALICE_RUN' and slot_kind='mcp'")
BB=$(db "select connection_id from run_resource_bindings where session_id='$BOB_RUN' and slot_kind='mcp'")
[ "$AB" = "$ALICE_CONN" ] && ok "alice's run bound HER connection ($AB)" || no "alice binding conn='$AB' (want $ALICE_CONN)"
[ "$BB" = "$BOB_CONN" ]   && ok "bob's run bound HIS connection ($BB)"   || no "bob binding conn='$BB' (want $BOB_CONN)"
{ [ "$AB" != "$BB" ] && [ -n "$AB" ] && [ -n "$BB" ]; } && ok "the two runs bound DIFFERENT connections" || no "bindings not distinct"

# ── (e) The broker resolves the credential FROM THE BINDING ───────────────────
say "(e) The broker turns the BOUND credential server-side (never one from input)"
forge_running "$ALICE_RUN" "sess-alice-$$" "alice" && ok "alice run forced running + session token forged (fixture)" || true
forge_running "$BOB_RUN" "sess-bob-$$" "bob" && ok "bob run forced running + session token forged (fixture)" || true
R=$(sess_call "$ALICE_RUN" "sess-alice-$$" '{"tool_call_id":"e-a","tool":"mcp__kb__kb_search","input":{"query":"deploy"}}')
echo "$R" | j "['ok']" | grep -qi true && ok "alice's brokered kb_search executed (ok:true)" || no "alice broker call: $R"
[ "$(mcp_last_auth tools/call)" = "Bearer $TOK_ALICE" ] \
  && ok "the fake MCP's last tools/call authenticated as Bearer TOK_ALICE (her binding)" \
  || no "alice broker credential wrong: last tools/call auth = $(mcp_last_auth tools/call)"
R=$(sess_call "$BOB_RUN" "sess-bob-$$" '{"tool_call_id":"e-b","tool":"mcp__kb__kb_search","input":{"query":"deploy"}}')
echo "$R" | j "['ok']" | grep -qi true && ok "bob's brokered kb_search executed (ok:true)" || no "bob broker call: $R"
[ "$(mcp_last_auth tools/call)" = "Bearer $TOK_BOB" ] \
  && ok "the fake MCP's last tools/call authenticated as Bearer TOK_BOB (his binding)" \
  || no "bob broker credential wrong: last tools/call auth = $(mcp_last_auth tools/call)"

# ── (f) Approval by a THIRD user does not change credential identity ──────────
say "(f) Approval never changes credential identity — org binding, alice approves, TOK_ORG executes"
u_post "$jarA" "/v1/agents" \
  "{\"name\":\"org-kb\",\"policy\":\"kb-approve\",\"connection_requirements\":[{\"slot\":\"kb\",\"connector\":{\"url\":\"$MCP_URL\",\"slug\":\"$SLUG_CAT\"},\"required_tools\":[\"kb_search\"],\"binding_mode\":\"organization\"}]}"
[ "$CODE" = 200 ] && ok "agent 'org-kb' created (binding_mode organization, approval-required)" || no "org-kb agent → $CODE: $BODY"
create_run "$jarB" "org-kb" false; F_RUN="$RUN"          # bob invokes; supervised
need "$F_RUN" "org-kb run not created" && ok "bob invoked org-kb ($F_RUN)"
forge_running "$F_RUN" "sess-f-$$" "org-kb" && ok "org-kb run forced running + token forged" || true
CALLS_F=$(mcp_count tools/call)
( sess_call "$F_RUN" "sess-f-$$" '{"tool_call_id":"f1","tool":"mcp__kb__kb_search","input":{"query":"x"}}' > "$WORK/out_f" 2>/dev/null ) &
PID_F=$!
FAID=$(pending_approval_id "$jarA" "$F_RUN")   # alice (owner, read_all) sees the queue
if need "$FAID" "no pending approval appeared for bob's supervised org-kb run"; then
  ok "the org-kb tool paused for human approval (pending)"
  u_post "$jarA" "/v1/approvals/$FAID/decision" '{"decision":"approved_once"}'
  [ "$CODE" = 200 ] && ok "ALICE (a third user, decide_org) approved the org call" || no "alice approve → $CODE: $BODY"
  wait "$PID_F"; RF=$(cat "$WORK/out_f")
  echo "$RF" | j "['ok']" | grep -qi true && ok "the approved call executed (ok:true)" || no "org-kb call after approval: $RF"
  [ "$(mcp_count tools/call)" -gt "$CALLS_F" ] && ok "the approved call actually reached the upstream (a new tools/call)" || no "no new upstream call after approval"
  [ "$(mcp_last_auth tools/call)" = "Bearer $TOK_ORG" ] \
    && ok "the executed call authenticated as Bearer TOK_ORG — the BINDING's credential, never alice's" \
    || no "approval changed the credential! last tools/call auth = $(mcp_last_auth tools/call)"
else
  kill "$PID_F" 2>/dev/null; wait "$PID_F" 2>/dev/null
fi

# ── (g) A missing required tool fails BEFORE provisioning ─────────────────────
say "(g) Fail-before-provisioning — a snapshot missing a required tool refuses at creation"
u_post "$jarA" "/v1/agents" \
  "{\"name\":\"needs-missing\",\"policy\":\"kb-allow\",\"connection_requirements\":[{\"slot\":\"kb\",\"connector\":{\"url\":\"$MCP_URL\",\"slug\":\"$SLUG_CAT\"},\"required_tools\":[\"kb_search\",\"kb_absent\"],\"binding_mode\":\"invoking_user\"}]}"
[ "$CODE" = 200 ] && ok "agent 'needs-missing' created (requires a tool the server never advertised)" || no "needs-missing → $CODE: $BODY"
SESS_BEFORE=$(db "select count(*) from sessions where tenant_id='$TID'")
u_post "$jarA" "/v1/sessions" "{\"agent\":\"needs-missing\",\"task\":\"t\",\"repo\":{\"kind\":\"none\"}}"
{ [ "$CODE" != 200 ] && echo "$BODY" | grep -q "missing required tools"; } \
  && ok "run creation → $CODE naming the missing tool (satisfaction:all, before any spend)" \
  || no "missing-tool run → $CODE: $BODY (want 4xx / missing required tools)"
SESS_AFTER=$(db "select count(*) from sessions where tenant_id='$TID'")
[ "$SESS_BEFORE" = "$SESS_AFTER" ] && ok "zero new session rows (no half-created run: $SESS_BEFORE→$SESS_AFTER)" || no "a session row leaked ($SESS_BEFORE→$SESS_AFTER)"

# ── (h) Generation fail-closed ────────────────────────────────────────────────
say "(h) Generation fail-closed — a reauthorized connection stalls in-flight + new runs"
GEN0=$(db "select authorization_generation from integration_connections where id='$ALICE_CONN'")
need "$GEN0" "alice connection generation did not read" && ok "alice connection generation is $GEN0 (pre-bump)"
# Fixture: simulate a re-consent/rotation by bumping the generation past the
# in-flight run's frozen binding (+2 is fine — the precondition read it first).
db "update integration_connections set authorization_generation = authorization_generation + 2, updated_at=now() where id='$ALICE_CONN'" >/dev/null
CALLS_H=$(mcp_count tools/call)
R=$(sess_call "$ALICE_RUN" "sess-alice-$$" '{"tool_call_id":"h1","tool":"mcp__kb__kb_search","input":{"query":"x"}}')
{ echo "$R" | j "['denied']" | grep -qi true && echo "$R" | grep -qi "reauthorized"; } \
  && ok "alice's in-flight run's next call is REFUSED (binding recheck: reauthorized)" \
  || no "in-flight generation refusal: $R"
[ "$(mcp_count tools/call)" = "$CALLS_H" ] && ok "the refused call reached the upstream ZERO times (recheck is before egress)" || no "a refused call still hit the MCP server"
# A NEW run must re-resolve and refuse until the tools are refreshed.
u_post "$jarA" "/v1/sessions" "{\"agent\":\"shared-kb\",\"task\":\"t\",\"repo\":{\"kind\":\"none\"}}"
{ [ "$CODE" != 200 ] && echo "$BODY" | grep -qi "refresh"; } \
  && ok "a NEW run → $CODE (the frozen snapshot's generation is stale — refresh)" \
  || no "new run after bump → $CODE: $BODY (want 4xx / refresh)"
# Re-photograph at the current generation, then a new run resolves cleanly.
u_post "$jarA" "/v1/connections/$ALICE_CONN/tools/refresh" '{}'
{ [ "$CODE" = 200 ] && [ "$(echo "$BODY" | j "['snapshot']['version']")" = 2 ]; } \
  && ok "POST /tools/refresh re-photographs (snapshot v2 at the new generation)" || no "refresh → $CODE: $BODY"
create_run "$jarA" "shared-kb"; H_RUN="$RUN"
need "$H_RUN" "post-refresh run not created" && ok "a new run now SUCCEEDS against the refreshed snapshot ($H_RUN)"

# ── (k) Personal-connection approval boundary (runs BEFORE i deactivates bob) ─
# k must precede i: it needs bob ACTIVE (approver) to prove the 403; i then
# kills bob's membership. There is no member-reactivation endpoint, so the order
# is load-bearing, not cosmetic.
say "(k) Personal-connection approval boundary — only the owner-who-invoked may decide"
admin_get "/v1/admin/orgs/$SLUG/members"
BOB_MID=$(echo "$BODY" | python3 -c "
import sys,json
for m in json.load(sys.stdin).get('members',[]):
    if m.get('email')=='$U2': print(m['membership_id'])" 2>/dev/null)
if need "$BOB_MID" "bob's membership id did not resolve in $BODY"; then
  admin_post "/v1/admin/orgs/$SLUG/members/$BOB_MID/roles" '{"roles":["member","approver"]}'
  [ "$CODE" = 200 ] && ok "granted bob the approver role" || no "grant approver → $CODE: $BODY"
fi
u_post "$jarA" "/v1/agents" \
  "{\"name\":\"personal-approve\",\"policy\":\"kb-approve\",\"connection_requirements\":[{\"slot\":\"kb\",\"connector\":{\"url\":\"$MCP_URL\",\"slug\":\"$SLUG_CAT\"},\"required_tools\":[\"kb_search\"],\"binding_mode\":\"invoking_user\"}]}"
[ "$CODE" = 200 ] && ok "agent 'personal-approve' created (invoking_user + approval-required)" || no "personal-approve agent → $CODE: $BODY"
create_run "$jarA" "personal-approve" false; K_RUN="$RUN"     # alice invokes → HER personal conn
need "$K_RUN" "personal-approve run not created" && ok "alice invoked personal-approve ($K_RUN, binds her personal connection)"
forge_running "$K_RUN" "sess-k-$$" "personal-approve" && ok "personal-approve run forced running + token forged" || true
( sess_call "$K_RUN" "sess-k-$$" '{"tool_call_id":"k1","tool":"mcp__kb__kb_search","input":{"query":"x"}}' > "$WORK/out_k" 2>/dev/null ) &
PID_K=$!
KAID=$(pending_approval_id "$jarA" "$K_RUN")
if need "$KAID" "no pending approval appeared for alice's personal-approve run"; then
  ok "the personal-connection tool paused for approval (pending)"
  # BOB (approver, an active third user) is REFUSED — a personal connection is
  # decidable only by its owner-who-invoked, no role included.
  u_post "$jarB" "/v1/approvals/$KAID/decision" '{"decision":"approved_once"}'
  { [ "$CODE" = 403 ] && echo "$BODY" | grep -qi "personal connection"; } \
    && ok "bob (approver) decides alice's personal-connection approval → 403 (owner-only)" \
    || no "bob decide personal → $CODE: $BODY (want 403 / personal connection)"
  # Alice (owner + invoker) decides her own → works.
  u_post "$jarA" "/v1/approvals/$KAID/decision" '{"decision":"approved_once"}'
  [ "$CODE" = 200 ] && ok "alice (owner who invoked) decides her own → 200" || no "alice decide own → $CODE: $BODY"
  wait "$PID_K"; RK=$(cat "$WORK/out_k")
  echo "$RK" | j "['ok']" | grep -qi true && ok "the approved personal call executed (ok:true)" || no "personal-approve call: $RK"
  [ "$(mcp_last_auth tools/call)" = "Bearer $TOK_ALICE" ] && ok "…under her OWN personal credential (TOK_ALICE)" || no "personal call credential: $(mcp_last_auth tools/call)"
else
  kill "$PID_K" 2>/dev/null; wait "$PID_K" 2>/dev/null
fi

# ── (i) Membership kill switch (deactivates bob — must run AFTER k) ───────────
say "(i) Membership kill switch — deactivating bob refuses his run's bound credential"
if need "$BOB_MID" "bob's membership id missing (see section k)"; then
  admin_post "/v1/admin/orgs/$SLUG/members/$BOB_MID/deactivate" '{}'
  [ "$CODE" = 200 ] && ok "operator deactivated bob's membership" || no "deactivate bob → $CODE: $BODY"
  CALLS_I=$(mcp_count tools/call)
  R=$(sess_call "$BOB_RUN" "sess-bob-$$" '{"tool_call_id":"i1","tool":"mcp__kb__kb_search","input":{"query":"x"}}')
  { echo "$R" | j "['denied']" | grep -qi true && echo "$R" | grep -qi "membership"; } \
    && ok "bob's running session's next call is REFUSED (owner membership not active)" \
    || no "membership kill-switch refusal: $R"
  [ "$(mcp_count tools/call)" = "$CALLS_I" ] && ok "the refused call reached the upstream ZERO times" || no "a refused call still hit the MCP server"
fi

# ── (j) Legacy cutoff — an unconverted brokered-bundle revision is refused ────
say "(j) Legacy cutoff — a revision pinning a brokered capability bundle is refused (Phase C)"
u_post "$jarA" "/v1/agents" "{\"name\":\"legacy-brokered\",\"policy\":\"kb-allow\"}"
[ "$CODE" = 200 ] && ok "agent 'legacy-brokered' created (a plain revision)" || no "legacy agent → $CODE: $BODY"
REV_J=$(echo "$BODY" | j "['revision']['id']")
LEGACY_BUNDLE="legacy-kb-$$"
# Fixture: forge a pre-Phase-C brokered capability bundle + pin it on the latest
# revision (this exact shape can no longer be created through the API — brokered
# tools are connection requirements now, so we psql-insert it directly).
BID=$(db "insert into capability_bundles (id, tenant_id, name, version, description, definition, definition_digest)
  values (gen_random_uuid(), '$TID', '$LEGACY_BUNDLE', 1, 'legacy brokered',
          \$j\${\"servers\":[{\"class\":\"brokered\",\"name\":\"kb\",\"url\":\"$MCP_URL\",\"tools\":[{\"name\":\"kb_search\",\"description\":\"legacy\",\"input_schema\":{\"type\":\"object\"}}]}]}\$j\$::jsonb,
          'sha256:legacy') returning id")
need "$BID" "legacy bundle insert returned no id" && ok "forged a legacy brokered bundle ($LEGACY_BUNDLE)"
need "$REV_J" "legacy revision id missing" && \
  db "update agent_revisions set capability_bundles = jsonb_build_array(jsonb_build_object('id','$BID','name','$LEGACY_BUNDLE','version',1)) where id='$REV_J'" >/dev/null
# Precondition: the pin actually landed on the revision.
PIN=$(db "select capability_bundles->0->>'id' from agent_revisions where id='$REV_J'")
[ "$PIN" = "$BID" ] && ok "the latest revision now pins the brokered bundle (fixture verified)" || no "pin fixture failed (pin='$PIN' want $BID)"
u_post "$jarA" "/v1/sessions" "{\"agent\":\"legacy-brokered\",\"task\":\"t\",\"repo\":{\"kind\":\"none\"}}"
{ [ "$CODE" != 200 ] && echo "$BODY" | grep -q "Phase C"; } \
  && ok "a run from the unconverted revision → $CODE naming Phase C (cutoff enforced)" \
  || no "legacy cutoff → $CODE: $BODY (want 4xx / Phase C)"

# ── Result ───────────────────────────────────────────────────────────────────
say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
