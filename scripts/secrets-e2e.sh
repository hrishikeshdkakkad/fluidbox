#!/usr/bin/env bash
# Phase D acceptance E2E — the secrets/KMS control plane, driven end-to-end over
# real HTTP against fake authorization / MCP / GitHub / LiteLLM servers (python
# stdlib), with NO Dex and NO docker. This owns its stack: it boots the fluidbox
# control plane MANY times across the KMS/LLM boot matrix and drives everything
# with curl cookie jars (a jar == a browser) + psql fixtures.
#
# Design: docs/plans multi-user-mcp-control-plane Gap-5 (envelope sealing +
# re-seal), invariant 20 (one-time browser-bound OAuth flows), D7 (per-tenant
# LiteLLM virtual keys), and RLS enforcement (0018). It proves the #32 acceptance
# matrix — sections lettered (a)–(k) with the acceptance bullet each covers noted
# at its banner. House style mirrors scripts/identity-e2e.sh + bindings-e2e.sh:
# pass/fail counters, `db()` psql helper (-X -q -A -t; the -q lesson — else the
# command tag poisons a RETURNING capture), fail-fast preconditions, a cleanup
# trap, per-boot section-labeled server logs (section (k) greps them all).
#
# HERMETIC + no model spend: runs never launch a sandbox (no runner image in CI,
# so provisioning fails FAST via the dead-registry image ref — exactly what the
# forged-run fixture wants), the facade upstream is a fake LiteLLM, and every
# credential dance is against a local python fake. NEVER executed locally — CI on
# the PR is its proof (`bash -n` + shellcheck are the local bar).
#
# `set -e` is intentionally OMITTED (matching the siblings): this drives a large
# negative matrix incl. several EXPECTED boot refusals; aborting on the first
# non-2xx would defeat it. Failures are counted; a nonzero `fail` exits 1.
#
# File-wide suppressions (must precede the first command to apply file-wide):
#  SC2015: `[ test ] && ok … || no …` is the house idiom; `ok`/`no` return 0, so
#          `|| no` never fires on a passing test.
#  SC2030/SC2031: DATABASE_URL is exported ONLY inside the server subshell; the
#          top-level `db()` reads the unmodified outer value — false positive.
# shellcheck disable=SC2015,SC2030,SC2031
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)

# ── Preconditions ────────────────────────────────────────────────────────────
# DATABASE_URL is REQUIRED — refuse loudly rather than self-skip. CI provides the
# Postgres service. No docker (no Dex): the fakes are python stdlib.
if [ -z "${DATABASE_URL:-}" ]; then
  echo "secrets-e2e: DATABASE_URL is required (CI provides the Postgres service)." >&2
  echo "  This script drives real cookies + KMS + virtual keys + RLS against a real" >&2
  echo "  DB; it will not run — and must never silently skip — without one." >&2
  exit 2
fi
command -v curl    >/dev/null 2>&1 || { echo "secrets-e2e: curl is required." >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "secrets-e2e: python3 is required (fakes + JSON)." >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "secrets-e2e: openssl is required (keys + sha256)." >&2; exit 2; }
# psql is REQUIRED, not optional: the acceptance PROVES key_version flips, RLS
# visibility, the forged session/token fixtures, and the retirement-gate matrix
# directly. None may silently skip, so a missing psql aborts the whole run.
command -v psql    >/dev/null 2>&1 || { echo "secrets-e2e: psql is required (acceptance must be PROVEN, not skipped)." >&2; exit 2; }

# ── Config ───────────────────────────────────────────────────────────────────
API=http://127.0.0.1:8787
# Deterministic keys — the two 32-byte deployment keys (legacy + static KEK) and
# the LiteLLM master. These are TEST secrets (like the sibling bcrypt hash); the
# whole point of section (k) is proving they never reach a server log.
ADMIN_TOKEN=$(openssl rand -hex 32)
CRED_KEY=$(openssl rand -hex 32)      # FLUIDBOX_CREDENTIAL_KEY (legacy v1 key)
STATIC_KEK=$(openssl rand -hex 32)    # FLUIDBOX_KMS_STATIC_KEK (wraps per-tenant DEKs)
MASTER_KEY="sk-litellm-master-$$"     # LITELLM_MASTER_KEY (provisioning-only in tenant mode)

# Fake servers (fixed high ports; readiness-probed like the siblings).
AS_PORT=8951        # fake OAuth AS + OAuth MCP resource + OIDC issuer (org IdP)
GH_PORT=8952        # fake GitHub (manifest conversions)
LLM_PORT=8953       # fake LiteLLM (/key/generate, /key/delete, /v1/messages)
AS_BASE="http://127.0.0.1:$AS_PORT"   # the AS serves its OAuth MCP at /mcp here too
GH_BASE="http://127.0.0.1:$GH_PORT"
LLM_BASE="http://127.0.0.1:$LLM_PORT"

# Custom catalog slugs (valid [a-z0-9-]).
CAT_OAUTH="fxn-oauth"

WORK=$(mktemp -d)
DATA_DIR="$WORK/data"; mkdir -p "$DATA_DIR"
SERVER_PID=""
AS_PID=""; GH_PID=""; LLM_PID=""
SERVER_LOG=""       # set per boot by boot()/boot_expect_refusal()
UB="$WORK/ub"       # scratch body file for the admin curl helpers

pass=0; fail=0
ok()  { printf "  \033[1;32m✓\033[0m %s\n" "$1"; pass=$((pass+1)); }
no()  { printf "  \033[1;31m✗\033[0m %s\n" "$1"; fail=$((fail+1)); }
say() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }
# Fail-fast precondition guard (identical semantics to the siblings): when a value
# a section DEPENDS ON is empty, record ONE loud failure and return nonzero so the
# caller SKIPS the dependent steps — keeping one root failure legible instead of
# fanning it into dozens of misleading downstream ones. Never weakens a passing
# assertion: in the healthy path the value is non-empty and every guard runs.
need() { # value message
  [ -n "$1" ] && return 0
  no "precondition unmet — $2"
  return 1
}

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }
# psql shortcut. -q suppresses the command tag (else "INSERT 0 1" poisons a
# RETURNING capture); -A -t keep tuples-only/unaligned; -X skips ~/.psqlrc.
# stderr flows to the log (not swallowed) so a broken query is visible.
# db_raw is the BARE connection (no GUC) — only section (j)'s RLS negatives want
# it, because they SET ROLE and assert on what the policy alone allows.
db_raw() { psql "$DATABASE_URL" -X -q -A -t -c "$1"; }
# db() carries the audited bypass GUC: migration 0018 FORCEs RLS on every tenant
# table, which binds the table OWNER too, so a GUC-less fixture read returns zero
# rows and a fixture INSERT is refused. A session-level SET on a custom (dotted)
# option needs no privilege, so it rides INSIDE the helper — every call carries it.
db() { db_raw "set fluidbox.bypass = 'system_worker'; $1"; }

# ── Cleanup ──────────────────────────────────────────────────────────────────
# shellcheck disable=SC2329  # invoked via the EXIT/INT/TERM trap
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  [ -n "$AS_PID" ]  && kill "$AS_PID"  2>/dev/null
  [ -n "$GH_PID" ]  && kill "$GH_PID"  2>/dev/null
  [ -n "$LLM_PID" ] && kill "$LLM_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ═════════════════════════════════════════════════════════════════════════════
# Fakes (python stdlib; ThreadingHTTPServer — reqwest keeps pooled connections
# alive, and a serial HTTPServer would starve curl behind them).
# ═════════════════════════════════════════════════════════════════════════════

# ── Fake OAuth AS + OAuth MCP resource + OIDC issuer (one process) ────────────
# Extends scripts/e2e-connectors.sh's AS with: a refresh-grant COUNTER +
# rotating refresh tokens (invariant: the old refresh token dies the instant the
# new one mints), configurable failure injection (fail_next_refresh →
# invalid_grant ONCE), a DCR /register that returns a client_secret (so the
# server seals oauth_client_registrations.client_secret_sealed — a NEW sealed
# family), a /register hit COUNTER, and an OIDC discovery doc + empty JWKS so an
# org IdP config can be staged (sealing org_idp_configs.client_secret_sealed).
# /admin/state dumps server state for bash asserts; /admin/{mode,expire-access,
# revoke} inject conditions.
start_as() {
  python3 - "$AS_PORT" <<'PYEOF' &
import base64, hashlib, http.server, json, os, sys, threading, time, urllib.parse
port = int(sys.argv[1])
BASE = f"http://127.0.0.1:{port}"
RESOURCE = f"{BASE}/mcp"
S = {"codes": {}, "access": {}, "refresh": [],
     "mode": {"cimd": False, "access_ttl": 3600, "fail_next_refresh": False},
     "grants": [], "authorize": [], "register": [], "mcp": [],
     "refresh_grants": 0, "n": 0}
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
# Parse-only JWKS fixture: this suite stages the IdP config to exercise
# client_secret SEALING and never verifies a token from this issuer, but
# save-time validation (correctly) refuses a zero-key JWKS since the PR #27
# review (P2-8) — so publish ONE well-formed RSA public JWK. The modulus is
# random bytes: syntactically valid, never used for a signature check.
_nb = bytearray(os.urandom(256)); _nb[0] |= 0x80
FIXTURE_JWK = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "e2e-fixture",
               "n": base64.urlsafe_b64encode(bytes(_nb)).rstrip(b"=").decode(),
               "e": "AQAB"}
class As(http.server.BaseHTTPRequestHandler):
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
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/mcp":
            auth = self.headers.get("Authorization", "")
            tok = auth[7:] if auth.startswith("Bearer ") else ""
            if not (tok in S["access"] and S["access"][tok] > time.time()):
                return self._send(401, {"error": "unauthorized"}, headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp"'})
            return self._send(405, {"error": "POST JSON-RPC"})
        if u.path == "/.well-known/oauth-protected-resource/mcp":
            return self._send(200, {"resource": RESOURCE, "authorization_servers": [BASE]})
        if u.path == "/.well-known/oauth-authorization-server":
            return self._send(200, {
                "issuer": BASE,
                "authorization_endpoint": f"{BASE}/authorize",
                "token_endpoint": f"{BASE}/token",
                "registration_endpoint": f"{BASE}/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "client_id_metadata_document_supported": S["mode"]["cimd"],
                "scopes_supported": ["read", "offline_access"]})
        # OIDC discovery for org IdP staging (a distinct protocol on the same origin).
        if u.path == "/.well-known/openid-configuration":
            return self._send(200, {
                "issuer": BASE,
                "authorization_endpoint": f"{BASE}/authorize",
                "token_endpoint": f"{BASE}/token",
                "jwks_uri": f"{BASE}/jwks",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "scopes_supported": ["openid", "email", "profile"]})
        if u.path == "/jwks":
            return self._send(200, {"keys": [FIXTURE_JWK]})
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
            tok = auth[7:] if auth.startswith("Bearer ") else ""
            okc = tok in S["access"] and S["access"][tok] > time.time()
            S["mcp"].append({"method": method, "auth": auth, "ok": okc})
            if not okc:
                return self._send(401, {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32001, "message": "unauthorized"}}, headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp"'})
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
                                     "required": ["query"]}, "annotations": {"readOnlyHint": True}},
                    {"name": "nt_create_page", "description": "Create a page",
                     "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}},
                                     "required": ["title"]}}]}})
            if method == "tools/call":
                name = (req.get("params") or {}).get("name", "")
                if name == "nt_search":
                    return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                        "content": [{"type": "text", "text": "notion result — custody works"}],
                        "isError": False}})
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": f"no such tool {name}"}], "isError": True}})
            return self._send(200, {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": "method not found"}})
        if u.path == "/token":
            f = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
            grant = f.get("grant_type", "")
            rec = {"grant": grant, "resource": f.get("resource", ""),
                   "client_id": f.get("client_id", ""), "ok": False}
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
                with LOCK:
                    S["refresh_grants"] += 1
                rt_in = f.get("refresh_token", "")
                rec["used_refresh"] = rt_in
                # Failure injection: force ONE invalid_grant, then clear.
                if S["mode"]["fail_next_refresh"]:
                    S["mode"]["fail_next_refresh"] = False
                    S["grants"].append(rec)
                    return self._send(400, {"error": "invalid_grant"})
                if rt_in not in S["refresh"]:
                    S["grants"].append(rec)
                    return self._send(400, {"error": "invalid_grant"})
                # ROTATION: the old token dies the instant the new one mints.
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
            nn = next_n()
            # Return a client_secret so the server seals it (NEW sealed family:
            # oauth_client_registrations.client_secret_sealed).
            return self._send(201, {"client_id": f"dcr-client-{nn}",
                                    "client_secret": f"dcr-secret-{nn}",
                                    "redirect_uris": body.get("redirect_uris", [])})
        if u.path == "/admin/mode":
            S["mode"].update(json.loads(raw) if raw else {})
            return self._send(200, S["mode"])
        if u.path == "/admin/expire-access":
            S["access"].clear()
            return self._send(200, {"ok": True})
        if u.path == "/admin/revoke":
            S["access"].clear(); S["refresh"].clear()
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", port), As).serve_forever()
PYEOF
  AS_PID=$!
  for _ in $(seq 1 40); do
    curl -sf "$AS_BASE/.well-known/oauth-authorization-server" >/dev/null 2>&1 && {
      ok "fake AS/OIDC/MCP up on :$AS_PORT"; return 0; }
    sleep 0.25
  done
  echo "secrets-e2e: fake AS did not become ready" >&2; exit 1
}
as_state() { curl -s "$AS_BASE/admin/state"; }
as_field() { as_state | python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }
as_admin() { curl -s -X POST -H 'content-type: application/json' -d "${2:-{\}}" "$AS_BASE/admin/$1" >/dev/null; }
# Count the tools/call requests the fake MCP server actually EXECUTED (ok=true).
# `S["mcp"]` records every request — handshake traffic (initialize,
# notifications/initialized, tools/list) and 401s too, and a reactive-401 retry
# records BOTH legs — so a raw `len(mcp)` delta cannot count executions. This can.
as_tool_calls() { as_state | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(sum(1 for m in d.get('mcp',[]) if m.get('method')=='tools/call' and m.get('ok')))" 2>/dev/null; }

# ── Fake GitHub (manifest conversions) ────────────────────────────────────────
# The manifest dance ends by POSTing to {github_api}/app-manifests/{code}/
# conversions; a 201 with pem/client_secret/webhook_secret is sealed into
# github_app_registrations (pem_sealed always; client_secret_sealed when present;
# webhook_secret only when the public URL is webhook-capable — loopback is NOT, so
# pem + client_secret are the sealed columns here). No JWT is minted at
# conversion time, so a placeholder PEM string is fine.
start_gh() {
  python3 - "$GH_PORT" <<'PYEOF' &
import http.server, json, sys
port = int(sys.argv[1])
class Gh(http.server.BaseHTTPRequestHandler):
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
        if n: self.rfile.read(n)
        p = self.path
        if p.startswith("/app-manifests/") and p.endswith("/conversions"):
            return self._send(201, {
                "id": 424242, "name": "fluidbox-ci", "slug": "fluidbox-ci",
                "client_id": "Iv1.ciclientid",
                "client_secret": "ghcs-ci-CLIENTSECRET",
                "webhook_secret": "whs-ci-WEBHOOKSECRET",
                "pem": "-----BEGIN RSA PRIVATE KEY-----\nFAKEKEYMATERIALFORCI\n-----END RSA PRIVATE KEY-----\n",
                "html_url": "http://127.0.0.1/apps/fluidbox-ci",
                "owner": {"login": "ci-owner"}})
        return self._send(404, {"message": "not found"})
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", port), Gh).serve_forever()
PYEOF
  GH_PID=$!
  for _ in $(seq 1 40); do
    curl -s -o /dev/null -X POST "$GH_BASE/app-manifests/x/conversions" 2>/dev/null && {
      ok "fake GitHub up on :$GH_PORT (manifest conversions)"; return 0; }
    sleep 0.25
  done
  echo "secrets-e2e: fake GitHub did not become ready" >&2; exit 1
}

# ── Fake LiteLLM (virtual-key provisioning + model upstream) ──────────────────
# /key/generate mints a UNIQUE virtual key per call (recording the master-key
# Authorization + the alias/tenant it was minted for); /key/delete records;
# /v1/messages records the Authorization the facade presents (the VIRTUAL key,
# never the master) and returns a minimal Anthropic-shaped body. /admin/state
# dumps the records.
start_llm() {
  python3 - "$LLM_PORT" <<'PYEOF' &
import http.server, json, sys, threading
port = int(sys.argv[1])
S = {"generate": [], "delete": [], "messages": [], "n": 0}
LOCK = threading.Lock()
class Llm(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        if self.path == "/admin/state":
            return self._send(200, S)
        return self._send(404, {"error": "not found"})
    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        try: body = json.loads(raw) if raw else {}
        except Exception: body = {}
        auth = self.headers.get("Authorization", "")
        if self.path == "/key/generate":
            with LOCK:
                S["n"] += 1
                key = f"sk-fbx-{S['n']}"
            meta = body.get("metadata") or {}
            S["generate"].append({"auth": auth, "alias": body.get("key_alias", ""),
                                  "tenant": meta.get("tenant_id", ""), "key": key})
            return self._send(200, {"key": key, "token_id": f"tid-{key}"})
        if self.path == "/key/delete":
            S["delete"].append({"auth": auth, "keys": body.get("keys", [])})
            return self._send(200, {"deleted_keys": body.get("keys", [])})
        if self.path in ("/v1/messages", "/v1/messages/count_tokens"):
            S["messages"].append({"auth": auth, "path": self.path})
            return self._send(200, {"id": "msg_ci", "type": "message", "role": "assistant",
                "model": body.get("model", ""), "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}})
        return self._send(404, {"error": "not found"})
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", port), Llm).serve_forever()
PYEOF
  LLM_PID=$!
  for _ in $(seq 1 40); do
    curl -s -o /dev/null "$LLM_BASE/admin/state" 2>/dev/null && {
      ok "fake LiteLLM up on :$LLM_PORT (/key/generate, /v1/messages)"; return 0; }
    sleep 0.25
  done
  echo "secrets-e2e: fake LiteLLM did not become ready" >&2; exit 1
}
llm_state() { curl -s "$LLM_BASE/admin/state"; }
llm_field() { llm_state | python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }
# EVERY recorded call on a provisioning endpoint carried the expected credential.
# The fake accepts any Authorization, so checking one record (e.g. `generate[0]`)
# leaves every later mint — the second org, the default tenant's lazy mint, the
# rotation re-mint, the key deletion — free to present the WRONG credential with
# the suite still green. $1 = endpoint record list, $2 = expected Authorization.
# Prints "OK <n>", "NONE" (endpoint never called), or "BAD <first-offender>".
llm_all_auth() { llm_state | python3 -c "
import sys,json
d=json.load(sys.stdin); rs=d.get('$1') or []
bad=[r.get('auth','') for r in rs if r.get('auth','') != '$2']
print('NONE' if not rs else 'BAD %s' % bad[0] if bad else 'OK %d' % len(rs))" 2>/dev/null; }

# ═════════════════════════════════════════════════════════════════════════════
# Server boots. CI passes FLUIDBOX_SERVER_BIN (a prebuilt binary) so the script
# `exec`s it (clean single-process lifecycle); otherwise `cargo run`. Every boot
# writes a section-labeled log so section (k) can grep them ALL. The KMS/LLM/SSO
# knobs are positional so the matrix is legible at the call site.
# ═════════════════════════════════════════════════════════════════════════════
# _spawn LABEL KMS(off|static) LEGACY(1|0) LLMMODE(shared|tenant) SSO(0|1) MASTER
# Starts the server in the background, sets SERVER_PID + SERVER_LOG. Does NOT wait.
_spawn() {
  local label=$1 kms=$2 legacy=$3 llmmode=$4 sso=$5 master=$6
  SERVER_LOG="$WORK/server-$label.log"; : > "$SERVER_LOG"
  (
    cd "$ROOT" || exit 1
    export DATABASE_URL="$DATABASE_URL"
    export FLUIDBOX_BIND=127.0.0.1:8787
    export FLUIDBOX_PUBLIC_URL=http://127.0.0.1:8787
    export FLUIDBOX_ADMIN_TOKEN="$ADMIN_TOKEN"
    export FLUIDBOX_PROVIDER=docker
    export FLUIDBOX_DATA_DIR="$DATA_DIR"
    # Phase D (#32): run the app pool as the NON-superuser role migration 0018
    # creates, so every HTTP request in this suite executes with RLS actually
    # ENFORCED. Without it the whole surface runs RLS-free (CI's DB user is the
    # superuser `postgres`, for whom policies are skipped entirely) and a
    # repository fn that forgot `scoped_tx` would return rows here and empty in
    # production. 0018 grants the role to current_user, so `SET ROLE` works as-is;
    # if a managed host could not create it the server refuses to boot naming the
    # exact CREATE ROLE fix, which is the signal we want.
    export FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime
    # A dead-registry image ref makes provisioning fail in milliseconds (no runner
    # image in CI), so the forged-run fixtures settle terminal fast.
    export FLUIDBOX_SANDBOX_IMAGE=localhost:1/fluidbox-absent:ci
    export FLUIDBOX_CODEX_SANDBOX_IMAGE=localhost:1/fluidbox-absent:ci
    # GitHub manifest conversion seam → the local fake (no public GitHub).
    export FLUIDBOX_GITHUB_API_URL="$GH_BASE"
    export FLUIDBOX_GITHUB_WEB_URL="$GH_BASE"
    export FLUIDBOX_REQUIRE_SSO="$sso"
    # KMS mode + its required key.
    export FLUIDBOX_KMS_MODE="$kms"
    if [ "$kms" = static ]; then export FLUIDBOX_KMS_STATIC_KEK="$STATIC_KEK"; fi
    # Legacy sealing key — present or retired.
    if [ "$legacy" = 1 ]; then export FLUIDBOX_CREDENTIAL_KEY="$CRED_KEY"; fi
    # LLM upstream mode.
    export FLUIDBOX_LLM_KEY_MODE="$llmmode"
    export LLM_UPSTREAM_URL="$LLM_BASE"
    export FLUIDBOX_LLM_ADMIN_URL="$LLM_BASE"
    # LITELLM_MASTER_KEY — empty string is a REAL value here (the empty-shared-key
    # boot-refusal test passes "" as $master).
    export LITELLM_MASTER_KEY="$master"
    export RUST_LOG="${RUST_LOG:-warn,fluidbox_server=info}"
    if [ -n "${FLUIDBOX_SERVER_BIN:-}" ] && [ -x "${FLUIDBOX_SERVER_BIN}" ]; then
      # The server self-loads ./.env (dotenvy) — booting from $ROOT lets a
      # developer's real .env FILL IN variables this suite deliberately left
      # ABSENT (FLUIDBOX_CREDENTIAL_KEY absent IS the retirement-gate test
      # state), so run the binary from the .env-less work dir. CI has no .env
      # and is unaffected; the cargo fallback below stays on $ROOT (dev seam).
      cd "$WORK" || exit 1
      exec "$FLUIDBOX_SERVER_BIN"
    fi
    exec cargo run -q -p fluidbox-server
  ) >>"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
}

# boot LABEL … — start + wait for /v1/health. Returns 0 healthy, 1 if it exited
# during boot (caller asserts). Sets SERVER_PID/SERVER_LOG.
boot() {
  _spawn "$@"
  for _ in $(seq 1 180); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then SERVER_PID=""; return 1; fi
    curl -sf "$API/v1/health" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# boot_expect_refusal LABEL … — start + wait for the process to EXIT (an expected
# boot refusal). Returns 0 if it exited (refused), 1 if it became healthy (bad).
# Leaves SERVER_LOG for grepping; clears SERVER_PID (process already dead).
boot_expect_refusal() {
  _spawn "$@"
  for _ in $(seq 1 120); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then SERVER_PID=""; return 0; fi
    if curl -sf "$API/v1/health" >/dev/null 2>&1; then
      kill "$SERVER_PID" 2>/dev/null; SERVER_PID=""; return 1
    fi
    sleep 0.5
  done
  kill "$SERVER_PID" 2>/dev/null; SERVER_PID=""; return 1
}

stop_server() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  for _ in $(seq 1 30); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.3; done
  SERVER_PID=""
}

# ── HTTP helpers ─────────────────────────────────────────────────────────────
AH="authorization: Bearer $ADMIN_TOKEN"
BODY=""; CODE=""
admin_post() { CODE=$(curl -s -o "$UB" -w '%{http_code}' -X POST -H "$AH" -H 'content-type: application/json' -d "$2" "$API$1"); BODY=$(cat "$UB"); }
admin_get()  { CODE=$(curl -s -o "$UB" -w '%{http_code}' -H "$AH" "$API$1"); BODY=$(cat "$UB"); }
location_from_headers() { grep -i '^location:' "$1" | head -1 | sed -E 's/^[Ll]ocation: *//' | tr -d '\r'; }
# The in-sandbox internal gate: authenticated by the per-session bearer token.
sess_call() { # sid token-plaintext json → prints the tools/call response body
  curl -s -X POST -H "authorization: Bearer $2" -H 'content-type: application/json' -d "$3" "$API/internal/sessions/$1/tools/call"
}
# The LLM facade: the session's fake ANTHROPIC_API_KEY IS its session token
# (x-api-key). Sets FCODE + FBODY, exactly like admin_post sets CODE + BODY —
# and for the same reason it must be CALLED PLAINLY, never as `X=$(facade_call …)`:
# a command substitution runs the function in a SUBSHELL, so the FCODE assignment
# dies with it and the caller reads a stale (or empty) status. That is precisely
# how a 503 refusal was asserted as a 200 while the body was right.
FCODE=""; FBODY=""
facade_call() { # session-token model → sets FCODE (http code) + FBODY (response body)
  FCODE=$(curl -s -o "$UB" -w '%{http_code}' -X POST \
    -H "x-api-key: $1" -H 'content-type: application/json' \
    -d "{\"model\":\"$2\",\"max_tokens\":16,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" \
    "$API/internal/llm/v1/messages")
  FBODY=$(cat "$UB")
}

# ── The forged-run + forged-session fixtures (proven CI-green in bindings-e2e) ─
# A run created here NEVER launches a sandbox (dead-registry image), so the
# orchestrator fails provisioning. We wait for the run to SETTLE (terminal AND its
# finalization intent cleared — the race-free quiescent point), then FORCE it to
# 'running' as a documented test fixture and psql-forge a session token exactly
# how the orchestrator mints one (kind 'session', token_sha256 = sha256(plaintext);
# the plaintext is never echoed). started_at/last_heartbeat_at stay NULL so no
# watchdog/wall-clock sweeper reaps the fixture.
forge_running() { # sid token-plaintext label
  local sid=$1 tok=$2 label=$3 cnt st fin settled=0 sha tid
  need "$sid" "no session id for the $label run" || return 1
  cnt=$(db "select count(*) from sessions where id='$sid'")
  [ "$cnt" = 1 ] || { no "$label: session row missing (count=$cnt)"; return 1; }
  for _ in $(seq 1 600); do
    st=$(db "select status from sessions where id='$sid'")
    fin=$(db "select count(*) from session_finalizations where session_id='$sid'")
    case "$st" in
      completed|failed|cancelled|budget_exceeded) [ "$fin" = 0 ] && { settled=1; break; };;
    esac
    sleep 0.5
  done
  [ "$settled" = 1 ] || { no "$label: run did not settle to a quiescent terminal state (status='$st', finalizations=$fin)"; return 1; }
  db "update sessions set status='running', status_reason='secrets-e2e fixture (run never launched)' where id='$sid'" >/dev/null
  sha=$(printf '%s' "$tok" | openssl dgst -sha256 | awk '{print $NF}')
  tid=$(db "select tenant_id from sessions where id='$sid'")
  db "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, expires_at)
      values (gen_random_uuid(), '$tid', 'session', '$sid', '$sha', now() + interval '2 hours')" >/dev/null
  return 0
}
# Forge a RUNNING session in an arbitrary tenant by COPYING a real run's row
# (run_spec + agent/revision) — sessions.agent_id is a non-composite FK, so a
# default-tenant agent is reachable from an org-tenant session. Forges a session
# token for it. Prints the new session id.
forge_tenant_session() { # tenant_id source_run token-plaintext → prints sid
  local tid=$1 src=$2 tok=$3 sid sha
  sid=$(db "insert into sessions
      (id, tenant_id, agent_id, agent_revision_id, status, autonomy, trust_tier,
       task, repo_source, run_spec, budgets, invoked_by_kind)
    select gen_random_uuid(), '$tid', agent_id, agent_revision_id, 'running', autonomy,
       trust_tier, task, repo_source, run_spec, budgets, invoked_by_kind
    from sessions where id='$src' returning id")
  [ -n "$sid" ] || { echo ""; return 1; }
  sha=$(printf '%s' "$tok" | openssl dgst -sha256 | awk '{print $NF}')
  db "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, expires_at)
      values (gen_random_uuid(), '$tid', 'session', '$sid', '$sha', now() + interval '2 hours')" >/dev/null
  echo "$sid"
}

# Create a run as the operator; sets RUN to the session id (empty on failure).
RUN=""
create_run() { # agent
  admin_post "/v1/sessions" "{\"agent\":\"$1\",\"task\":\"secrets-e2e\",\"repo\":{\"kind\":\"none\"}}"
  RUN=$(echo "$BODY" | j "['session']['id']")
}

# ── OAuth-flow driving (invariant 20: start → go(cookie) → callback) ──────────
# oauth_connect: catalog connect for an oauth connector → sets CONN + GOURL.
CONN=""; GOURL=""
oauth_connect() { # slug display
  admin_post "/v1/catalog/$1/connect" "{\"display_name\":\"$2\"}"
  CONN=$(echo "$BODY" | j "['connection']['id']")
  GOURL=$(echo "$BODY" | j "['go_url']")
}
# drive_go: GET go_url in `jar` (the flow cookie lands in the jar), follow the AS
# authorize 302, and echo the fluidbox callback URL (code+state) WITHOUT
# completing it — so the caller can replay/expire/tamper/complete at will.
drive_go() { # jar go_url → echoes callback URL (empty on failure)
  curl -s -c "$1" -b "$1" -D "$WORK/h.go" -o /dev/null "$2"
  local authz; authz=$(location_from_headers "$WORK/h.go")
  [ -z "$authz" ] && { echo ""; return 1; }
  # The AS auto-consents (302 to the callback); %{redirect_url} yields it without
  # fetching it (no -L), so the caller drives the callback in its own jar.
  curl -s -o /dev/null -w '%{redirect_url}' "$authz"
}
# complete_cb: GET the callback URL in `jar` (carrying the flow cookie) → echoes
# the http code; the body lands in $WORK/cb.body for message asserts.
complete_cb() { # jar callback_url
  curl -s -c "$1" -b "$1" -o "$WORK/cb.body" -w '%{http_code}' "$2"
}

# ═════════════════════════════════════════════════════════════════════════════
say "BOOT — fake AS/OIDC/MCP + fake GitHub + fake LiteLLM"
start_as
start_gh
start_llm

# ── (a.1) empty-shared-key boot refusal ───────────────────────────────────────
# #32 (a): shared mode + EMPTY LITELLM_MASTER_KEY must refuse boot (no silent
# fallback to a keyless upstream). This is a config-parse refusal (pre-DB), so it
# fails fast. crates/fluidbox-server/src/config.rs validate_llm_key_config.
say "(a) Boot matrix — empty-shared-key refusal"
if boot_expect_refusal "a-emptykey" static 1 shared 0 ""; then
  grep -q "the resolved upstream key is empty" "$SERVER_LOG" \
    && ok "shared mode + empty LITELLM_MASTER_KEY → boot REFUSED naming the empty key" \
    || no "boot refused but the log lacks the empty-key reason: $(tail -3 "$SERVER_LOG")"
else
  no "shared mode + empty upstream key did NOT refuse boot (it became healthy)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1 — KMS OFF, legacy present, shared LLM, admin mode. Boots healthy (KMS
# off is today's behavior), seeds v1 (legacy) sealed rows across ≥5 families, and
# runs the whole invariant-20 OAuth flow matrix (d/e/f), client-registration
# dedup (g), and the refresh/generation/revoke matrix (h). Every credential
# sealed here is v1 because KMS is off.
# ═════════════════════════════════════════════════════════════════════════════
say "(a) Boot matrix — KMS OFF boots healthy (P1)"
boot "p1" off 1 shared 0 "$MASTER_KEY" || { no "KMS-off boot failed: $(tail -20 "$SERVER_LOG")"; exit 1; }
ok "control plane up (KMS off, legacy key present, shared LLM, admin)"

# The custom oauth catalog entry (fake AS /mcp).
admin_post "/v1/catalog" "{\"slug\":\"$CAT_OAUTH\",\"name\":\"Fake Notion\",\"auth_mode\":\"oauth\",\"url\":\"$AS_BASE/mcp\",\"categories\":[\"docs\"]}"
[ "$CODE" = 200 ] && ok "custom oauth catalog entry '$CAT_OAUTH' created" || no "catalog create → $CODE: $BODY"

# ── (g) Client registrations — two connects, same issuer → ONE /register ──────
# #32 (g). The DCR client is shared per (issuer, redirect_uri): the second connect
# ADOPTS the first row (advisory lock + ON CONFLICT). oauth.rs register_dcr_client.
say "(g) Client registrations — two connects to one issuer register ONCE"
REG0=$(as_field "['register'].__len__()")
oauth_connect "$CAT_OAUTH" "conn-1"; CONN1="$CONN"; GO1="$GOURL"
need "$CONN1" "first oauth connect returned no connection id ($BODY)" && ok "connect #1 → pending connection ($CONN1)"
oauth_connect "$CAT_OAUTH" "conn-2"; CONN2="$CONN"
need "$CONN2" "second oauth connect returned no connection id" && ok "connect #2 → pending connection ($CONN2)"
REG1=$(as_field "['register'].__len__()")
[ "$((REG1-REG0))" = 1 ] && ok "the AS recorded EXACTLY ONE /register for two connects (dedup)" || no "register delta = $((REG1-REG0)) (want 1)"
REGROWS=$(db "select count(*) from oauth_client_registrations")
[ "$REGROWS" = 1 ] && ok "exactly ONE oauth_client_registrations row" || no "registration rows = $REGROWS (want 1)"
# NEW sealed family seeded v1: the DCR client_secret the fake returned is sealed.
REGSEAL=$(db "select count(*) from oauth_client_registrations where client_secret_sealed is not null and client_secret_key_version=1")
[ "$REGSEAL" = 1 ] && ok "oauth_client_registrations.client_secret_sealed seeded at v1 (NEW family)" || no "registration client_secret not v1-sealed (count=$REGSEAL)"

# ── (d) Full dance through go+cookie; flow consumed exactly once ──────────────
# #32 (d). start_dance → go (binds the browser cookie) → callback claims the flow
# once. oauth.rs go/callback.
say "(d) State rows — full go+cookie dance; flow consumed exactly once"
jarA="$WORK/jarA"; : > "$jarA"
CB1=$(drive_go "$jarA" "$GO1")
need "$CB1" "go leg produced no callback URL (no 302 to the AS?)" && case "$CB1" in
  "$API"/v1/oauth/callback*) ok "go set the flow cookie + 302'd to the AS → callback URL captured";;
  *) no "unexpected callback URL: $CB1";;
esac
C=$(complete_cb "$jarA" "$CB1")
[ "$C" = 200 ] && ok "callback with the initiating browser → 200 (exchange completed)" || no "callback → $C (want 200); $(head -c160 "$WORK/cb.body")"
NTSTATUS=$(db "select status from integration_connections where id='$CONN1'")
[ "$NTSTATUS" = active ] && ok "connection #1 is active" || no "connection #1 status='$NTSTATUS' (want active)"
CONSUMED=$(db "select count(*) from connector_oauth_flows where connection_id='$CONN1' and consumed_at is not null")
FLOWS1=$(db "select count(*) from connector_oauth_flows where connection_id='$CONN1'")
{ [ "$CONSUMED" = 1 ] && [ "$FLOWS1" = 1 ]; } && ok "exactly ONE flow row, consumed exactly once (consumed=$CONSUMED total=$FLOWS1)" || no "flow-consumption wrong (consumed=$CONSUMED total=$FLOWS1)"
# The completed OAuth connection sealed its refresh token → seeds
# integration_connections.credential_sealed at v1.
CREDSEAL=$(db "select count(*) from integration_connections where id='$CONN1' and credential_sealed is not null and credential_key_version=1")
[ "$CREDSEAL" = 1 ] && ok "integration_connections.credential_sealed seeded at v1 (the sealed refresh token)" || no "connection credential not v1-sealed (count=$CREDSEAL)"

# ── (h) Refresh singleflight + rotation + generation + invalid_grant + revoke ─
# #32 (h). Runs BEFORE e/f so CONN1 is the ONLY active org connection (an
# organization binding to the fake connector url is unambiguous). broker.rs
# recheck_binding + oauth.rs refresh.
say "(h) Refresh singleflight + rotation, generation fail-closed, invalid_grant, revoke"
# kb-allow-shaped policy so mcp__* executes and the AS logs the credential turn.
PY_ALLOW=$(python3 - <<'PYEOF'
import json
print(json.dumps("""name: fxn-allow
defaults:
  tool_action: deny
autonomy:
  permitted: true
  on_approval_rule: deny
tools:
  - match: ["mcp__*"]
    action: allow
"""))
PYEOF
)
admin_post "/v1/policies" "{\"name\":\"fxn-allow\",\"yaml\":$PY_ALLOW}"
[ "$CODE" = 200 ] && ok "policy fxn-allow created" || no "policy → $CODE: $BODY"
admin_post "/v1/agents" \
  "{\"name\":\"fxn-agent\",\"policy\":\"fxn-allow\",\"connection_requirements\":[{\"slot\":\"fxn\",\"connector\":{\"url\":\"$AS_BASE/mcp\",\"slug\":\"$CAT_OAUTH\"},\"required_tools\":[\"nt_search\"],\"binding_mode\":\"organization\"}]}"
[ "$CODE" = 200 ] && ok "agent 'fxn-agent' created (org binding to the oauth connector)" || no "agent → $CODE: $BODY"
create_run "fxn-agent"; HRUN="$RUN"
need "$HRUN" "fxn-agent run not created ($BODY)" && ok "created a run of fxn-agent ($HRUN)"
forge_running "$HRUN" "sess-h-$$" "fxn" && ok "run forced running + session token forged (fixture)" || true
# (h1) singleflight: expire the AS access token, fire TWO concurrent brokered
# calls → the per-connection oauth lock coalesces them into ONE refresh grant.
RG0=$(as_field "['refresh_grants']")
TC0=$(as_tool_calls)
as_admin expire-access
( sess_call "$HRUN" "sess-h-$$" '{"tool_call_id":"h1a","tool":"mcp__fxn__nt_search","input":{"query":"a"}}' > "$WORK/h1a" 2>/dev/null ) &
P1=$!
( sess_call "$HRUN" "sess-h-$$" '{"tool_call_id":"h1b","tool":"mcp__fxn__nt_search","input":{"query":"b"}}' > "$WORK/h1b" 2>/dev/null ) &
P2=$!
wait "$P1"; wait "$P2"
RG1=$(as_field "['refresh_grants']")
[ "$((RG1-RG0))" = 1 ] && ok "two concurrent brokered calls → EXACTLY ONE refresh grant (singleflight)" || no "refresh-grant delta = $((RG1-RG0)) (want 1 — singleflight)"
# BOTH waiters must succeed, not just one. Singleflight means the loser WAITS for
# the winner's rotated token and then executes with it; a loser that dies (401,
# dead-token race, lock timeout) while the winner survives is exactly the
# production bug this section caught — and an `either-or` assertion reports that
# bug as a pass. Same reason the upstream execution count must be 2, not ≥1.
{ grep -qi '"ok": *true' "$WORK/h1a" && grep -qi '"ok": *true' "$WORK/h1b"; } \
  && ok "BOTH concurrent calls executed (the singleflight loser rode the winner's rotated token)" \
  || no "a concurrent call did NOT execute (both must): $(cat "$WORK/h1a" "$WORK/h1b")"
TC1=$(as_tool_calls)
[ "$((TC1-TC0))" = 2 ] \
  && ok "exactly TWO tools/call executions reached the upstream (one per concurrent call)" \
  || no "upstream tools/call delta = $((TC1-TC0)) (want exactly 2 — one execution per concurrent call)"
# The AS holds exactly ONE valid refresh token (rotation: the old one died).
[ "$(as_field "['refresh'].__len__()")" = 1 ] && ok "the AS holds exactly one refresh token (old rotated out)" || no "AS refresh tokens = $(as_field "['refresh']") (want 1 — rotation)"
# (h2) generation fail-closed: bump the connection's authorization_generation past
# the in-flight run's frozen binding → the next call is refused BEFORE egress.
GEN0=$(db "select authorization_generation from integration_connections where id='$CONN1'")
db "update integration_connections set authorization_generation = authorization_generation + 1, updated_at=now() where id='$CONN1'" >/dev/null
CALLS_G=$(as_field "['mcp'].__len__()")
R=$(sess_call "$HRUN" "sess-h-$$" '{"tool_call_id":"h2","tool":"mcp__fxn__nt_search","input":{"query":"x"}}')
{ echo "$R" | grep -qi '"denied": *true' && echo "$R" | grep -qi "reauthorized"; } \
  && ok "generation bump → the in-flight call is REFUSED (binding recheck: reauthorized; gen ${GEN0}→bumped)" \
  || no "generation refusal wrong: $R"
[ "$(as_field "['mcp'].__len__()")" = "$CALLS_G" ] && ok "the refused call reached the upstream ZERO times (recheck is before egress)" || no "a generation-refused call still hit the AS"
# (h3) invalid_grant → connection status='error'. Inject a one-shot invalid_grant
# on the next refresh, expire access, and drive a token refresh via /tools/refresh.
as_admin mode '{"fail_next_refresh": true}'
as_admin expire-access
admin_post "/v1/connections/$CONN1/tools/refresh" '{}'
[ "$CODE" != 200 ] && ok "tools/refresh under injected invalid_grant → $CODE (fail closed)" || no "tools/refresh unexpectedly succeeded under invalid_grant: $BODY"
ERRSTAT=$(db "select status from integration_connections where id='$CONN1'")
[ "$ERRSTAT" = error ] && ok "invalid_grant flipped the connection to status='error'" || no "connection status='$ERRSTAT' after invalid_grant (want error)"
# A NEW run bound to the errored connection fails closed off the status.
admin_post "/v1/sessions" "{\"agent\":\"fxn-agent\",\"task\":\"t\",\"repo\":{\"kind\":\"none\"}}"
[ "$CODE" != 200 ] && ok "a new run against the errored connection → $CODE (fail closed off status)" || no "new run against errored connection unexpectedly created: $BODY"
# (h4) explicit revoke → immediate broker refusal on the in-flight run.
admin_post "/v1/connections/$CONN1/revoke" '{}'
{ [ "$CODE" = 200 ] || [ "$CODE" = 409 ]; } && ok "explicit revoke → $CODE" || no "revoke → $CODE: $BODY"
db "update integration_connections set status='revoked', updated_at=now() where id='$CONN1'" >/dev/null
R=$(sess_call "$HRUN" "sess-h-$$" '{"tool_call_id":"h4","tool":"mcp__fxn__nt_search","input":{"query":"x"}}')
{ echo "$R" | grep -qi '"denied": *true' && echo "$R" | grep -qiE "reconnect|reauthorized"; } \
  && ok "revoked connection → the in-flight call is REFUSED immediately (broker fail-closed)" \
  || no "revoke refusal wrong: $R"
# Clear the one-shot failure injection so later phases' refreshes are clean.
as_admin mode '{"fail_next_refresh": false}'

# ── (e) Invariant-20 negatives ────────────────────────────────────────────────
# #32 (e). Replay (consumed), wrong-browser (403, UNBURNED), expired, tampered
# state, go-on-consumed. oauth.rs callback ordering + go peek.
say "(e) Invariant-20 negatives — replay, wrong-browser (403+unburned), expired, tampered, consumed-go"
# Replay: re-GET the exact callback that section (d) already consumed.
CREP=$(complete_cb "$jarA" "$CB1")
[ "$CREP" = 400 ] && ok "replay of a consumed callback → 400" || no "replay → $CREP (want 400)"
# go on a consumed flow → 400 page (not a 302).
GOCODE=$(curl -s -o "$WORK/gc" -w '%{http_code}' "$GO1")
{ [ "$GOCODE" = 400 ] && grep -qi "expired or was already used" "$WORK/gc"; } && ok "go on a consumed flow → 400 (already used)" || no "consumed-go → $GOCODE: $(head -c120 "$WORK/gc")"
# Wrong-browser: a fresh flow, then a SECOND jar carrying a DIFFERENT flow's
# cookie completes it → 403 UNBURNED; the right jar then still completes → 200.
oauth_connect "$CAT_OAUTH" "conn-wb"; WBGO="$GOURL"
jarWB="$WORK/jarWB"; : > "$jarWB"
CBWB=$(drive_go "$jarWB" "$WBGO")            # jarWB now carries flow-WB's cookie
oauth_connect "$CAT_OAUTH" "conn-other"; OTHGO="$GOURL"
jarOTH="$WORK/jarOTH"; : > "$jarOTH"
drive_go "$jarOTH" "$OTHGO" >/dev/null       # jarOTH now carries a DIFFERENT flow's cookie
if need "$CBWB" "wrong-browser flow produced no callback URL"; then
  CWRONG=$(complete_cb "$jarOTH" "$CBWB")     # a valid cookie, but for the WRONG flow
  [ "$CWRONG" = 403 ] && grep -qi "not started by this browser" "$WORK/cb.body" \
    && ok "a different browser's cookie on this callback → 403 (not started by this browser)" \
    || no "wrong-browser → $CWRONG: $(head -c120 "$WORK/cb.body")"
  CRIGHT=$(complete_cb "$jarWB" "$CBWB")       # the flow was NOT burned — right browser wins
  [ "$CRIGHT" = 200 ] && ok "…and the flow was NOT burned — the initiating browser still completes (200)" || no "right-browser after 403 → $CRIGHT (want 200)"
fi
# Tampered state: a fresh flow, then complete with a mangled state param → 400.
oauth_connect "$CAT_OAUTH" "conn-tamper"; TGO="$GOURL"
jarT="$WORK/jarT"; : > "$jarT"
CBT=$(drive_go "$jarT" "$TGO")
if need "$CBT" "tamper flow produced no callback URL"; then
  CBT_BAD=$(echo "$CBT" | sed -E 's/state=[^&]*/state=TAMPERED000/')
  CTAMP=$(complete_cb "$jarT" "$CBT_BAD")
  [ "$CTAMP" = 400 ] && ok "tampered state param → 400 (unknown flow)" || no "tampered state → $CTAMP (want 400)"
fi
# Expired: a fresh flow, psql-age its expires_at, then complete → 400.
oauth_connect "$CAT_OAUTH" "conn-exp"; ECONN="$CONN"; EGO="$GOURL"
jarE="$WORK/jarE"; : > "$jarE"
CBE=$(drive_go "$jarE" "$EGO")
if need "$CBE" "expired flow produced no callback URL"; then
  db "update connector_oauth_flows set expires_at = now() - interval '1 minute'
      where connection_id='$ECONN' and consumed_at is null" >/dev/null
  CEXP=$(complete_cb "$jarE" "$CBE")
  [ "$CEXP" = 400 ] && ok "expired flow (expires_at aged via psql) → 400" || no "expired flow → $CEXP (want 400)"
fi

# ── (f) A callback cannot activate another flow's connection ──────────────────
# #32 (f). Two connections, two flows, two jars: jar-B (a VALID cookie for its OWN
# flow on connection B) completing connection A's callback fails the per-flow
# cookie predicate → 403; A stays pending, its generation unchanged. (Cross-USER
# reduces to this cross-FLOW binding at the cookie layer; the ownership half is
# Phase-C tested.)
say "(f) Cross-flow binding — B's valid cookie cannot complete A's callback"
oauth_connect "$CAT_OAUTH" "conn-fa"; FA_CONN="$CONN"; FA_GO="$GOURL"
oauth_connect "$CAT_OAUTH" "conn-fb"; FB_GO="$GOURL"
jarFA="$WORK/jarFA"; : > "$jarFA"; jarFB="$WORK/jarFB"; : > "$jarFB"
CB_FA=$(drive_go "$jarFA" "$FA_GO")   # jarFA carries flow-A's cookie
drive_go "$jarFB" "$FB_GO" >/dev/null # jarFB carries flow-B's cookie (a VALID cookie)
if need "$CB_FA" "flow A produced no callback URL" && need "$FA_CONN" "connection A id missing"; then
  GENA0=$(db "select authorization_generation from integration_connections where id='$FA_CONN'")
  CF=$(complete_cb "$jarFB" "$CB_FA")  # B's valid cookie on A's callback
  [ "$CF" = 403 ] && ok "B's cookie completing A's callback → 403 (per-flow binding, not mere cookie presence)" || no "cross-flow → $CF (want 403)"
  STA=$(db "select status from integration_connections where id='$FA_CONN'")
  GENA1=$(db "select authorization_generation from integration_connections where id='$FA_CONN'")
  { [ "$STA" = pending ] && [ "$GENA0" = "$GENA1" ]; } && ok "connection A stayed pending, generation unchanged ($GENA0)" || no "connection A changed (status=$STA gen ${GENA0}→${GENA1})"
  CFA=$(complete_cb "$jarFA" "$CB_FA")  # A's own browser completes
  [ "$CFA" = 200 ] && ok "…A's own browser still completes (200) — A's flow was never burned" || no "A self-complete → $CFA (want 200)"
fi

# ── Seed the remaining sealed families (still KMS off → all v1) ───────────────
say "SEED — subscription callback secret, org IdP client secret, github-app pem/client (all v1)"
# trigger_subscriptions.callback_secret_sealed (a subscription with a callback).
admin_post "/v1/agents" "{\"name\":\"pub-agent\",\"policy\":\"fxn-allow\"}"
[ "$CODE" = 200 ] && ok "agent 'pub-agent' created" || no "pub-agent → $CODE: $BODY"
admin_post "/v1/triggers" "{\"name\":\"pub-sub\",\"agent\":\"pub-agent\",\"task_template\":\"t\",\"callback_url\":\"http://127.0.0.1:9/hook\"}"
[ "$CODE" = 200 ] && ok "subscription 'pub-sub' created (signed-webhook callback secret sealed)" || no "pub-sub → $CODE: $BODY"
SUBSEAL=$(db "select count(*) from trigger_subscriptions where callback_secret_sealed is not null and callback_secret_key_version=1")
[ "${SUBSEAL:-0}" -ge 1 ] && ok "trigger_subscriptions.callback_secret_sealed seeded at v1" || no "subscription secret not v1-sealed (count=$SUBSEAL)"
# org_idp_configs.client_secret_sealed (an org's staged IdP config against the fake OIDC issuer).
admin_post "/v1/admin/orgs" "{\"slug\":\"idp-org\",\"display_name\":\"IdP Org\"}"
[ "$CODE" = 200 ] && ok "org 'idp-org' created" || no "create idp-org → $CODE: $BODY"
IDP_BODY=$(cat <<JSON
{"issuer":"$AS_BASE","client_id":"idp-client","client_secret":"idp-CLIENTSECRET",
 "token_endpoint_auth":"client_secret_basic"}
JSON
)
admin_post "/v1/admin/orgs/idp-org/idp" "$IDP_BODY"
[ "$CODE" = 200 ] && ok "IdP config staged (OIDC discovery validated against the fake issuer)" || no "stage idp → $CODE: $BODY"
IDPSEAL=$(db "select count(*) from org_idp_configs where client_secret_sealed is not null and client_secret_key_version=1")
[ "${IDPSEAL:-0}" -ge 1 ] && ok "org_idp_configs.client_secret_sealed seeded at v1" || no "idp client_secret not v1-sealed (count=$IDPSEAL)"
# github_app_registrations pem/client_secret (the manifest dance against the fake GitHub).
admin_post "/v1/github/app/manifest/start" '{}'
[ "$CODE" = 200 ] && ok "github-app manifest flow started" || no "manifest start → $CODE: $BODY"
GH_GO=$(echo "$BODY" | j "['go_url']")
if need "$GH_GO" "manifest go_url missing"; then
  jarGH="$WORK/jarGH"; : > "$jarGH"
  # The go page binds the browser (cookie) + renders the manifest form; its action
  # carries the sealed state param GitHub would echo back to the callback.
  curl -s -c "$jarGH" -b "$jarGH" -o "$WORK/ghgo.html" "$GH_GO"
  GH_STATE=$(grep -oiE 'action="[^"]*"' "$WORK/ghgo.html" | head -1 | sed -E 's/.*[?&]state=([^"&]*).*/\1/')
  if need "$GH_STATE" "could not extract the manifest state param from the go page"; then
    # Drive the callback ourselves (we ARE the fake GitHub): any code, the real
    # state, the browser cookie → the server exchanges at the fake conversions
    # endpoint and seals pem/client_secret.
    GHCB=$(curl -s -b "$jarGH" -o "$WORK/ghcb.html" -w '%{http_code}' "$API/v1/github/app/manifest/callback?code=ci-manifest-code&state=$GH_STATE")
    [ "$GHCB" = 200 ] && ok "manifest callback → 200 (conversion sealed the app secrets)" || no "manifest callback → $GHCB: $(head -c160 "$WORK/ghcb.html")"
    GHSEAL=$(db "select count(*) from github_app_registrations where pem_sealed is not null and pem_key_version=1")
    [ "${GHSEAL:-0}" -ge 1 ] && ok "github_app_registrations.pem_sealed seeded at v1" || no "github-app pem not v1-sealed (count=$GHSEAL)"
    GHCSEAL=$(db "select count(*) from github_app_registrations where client_secret_sealed is not null and client_secret_key_version=1")
    [ "${GHCSEAL:-0}" -ge 1 ] && ok "github_app_registrations.client_secret_sealed seeded at v1" || no "github-app client_secret not v1-sealed (count=$GHCSEAL)"
  fi
fi

say "P1 seeded — legacy (v1) rows across integration_connections / trigger_subscriptions / org_idp_configs / github_app_registrations / oauth_client_registrations"
stop_server

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2 — KMS STATIC, legacy present. New seals are v2 envelopes (per-tenant DEK
# wrapped by the static KEK). Section (b): a fresh connect → v2, a restart proves
# unseal survives (DEK unwrap from the persisted wrapped_dek), and a dumped→wiped→
# restored sealed row still opens.
# ═════════════════════════════════════════════════════════════════════════════
say "(a/b) Boot matrix — KMS STATIC boots healthy; envelope seals are v2 (P2)"
# The DEK drill's clean-DB precondition, made EXPLICIT instead of left to
# whatever the CI database happened to contain: "a tenant DEK row appeared"
# below only means something if there were none to begin with. Safe here and
# nowhere later — Phase 1 ran KMS OFF, so nothing legitimate has wrapped a DEK
# yet and no v2 blob exists to orphan — and it runs with the server DOWN so no
# in-memory DEK cache can outlive the wipe. (It cannot move any earlier: the
# table only exists once a boot has run the migrations.)
db "delete from tenant_deks" >/dev/null
DEKPRE=$(db "select count(*) from tenant_deks")
[ "${DEKPRE:-1}" = 0 ] && ok "clean-DB precondition: zero tenant_deks rows before the first KMS-mode seal" || no "tenant_deks is not empty entering the KMS phase (count=$DEKPRE)"
boot "p2" static 1 shared 0 "$MASTER_KEY" || { no "KMS-static boot failed: $(tail -20 "$SERVER_LOG")"; exit 1; }
ok "control plane up (KMS static, legacy present)"
# (b1) A fresh oauth connection sealed under KMS static → credential_key_version=2.
oauth_connect "$CAT_OAUTH" "conn-v2"; V2CONN="$CONN"; V2GO="$GOURL"
jarV2="$WORK/jarV2"; : > "$jarV2"
CBV2=$(drive_go "$jarV2" "$V2GO")
if need "$CBV2" "v2 flow produced no callback URL"; then
  CV2=$(complete_cb "$jarV2" "$CBV2")
  [ "$CV2" = 200 ] && ok "connect under KMS static → 200 (dance completed)" || no "v2 connect → $CV2"
  KV=$(db "select credential_key_version from integration_connections where id='$V2CONN'")
  [ "$KV" = 2 ] && ok "the sealed refresh token is a v2 ENVELOPE (credential_key_version=2)" || no "credential_key_version='$KV' (want 2)"
  DEKROW=$(db "select count(*) from tenant_deks")
  [ "${DEKROW:-0}" -ge 1 ] && ok "a per-tenant DEK exists (wrapped by the static KEK): $DEKROW row(s)" || no "no tenant DEK row after a v2 seal (count=$DEKROW)"
fi
stop_server

# (b2) DR/restart drill: a restart re-derives the DEK by UNWRAPPING the persisted
# wrapped_dek, so unsealing the v2 credential still works. /tools/refresh opens
# the sealed refresh token → mints an access token at the AS → re-photographs.
say "(b) DR drill — restart; unseal from the persisted wrapped_dek still works"
boot "p2b" static 1 shared 0 "$MASTER_KEY" || { no "KMS-static restart failed: $(tail -20 "$SERVER_LOG")"; exit 1; }
ok "control plane restarted (KMS static; DEK cache cold)"
if need "${V2CONN:-}" "no v2 connection carried across the restart"; then
  RG_B0=$(as_field "['refresh_grants']")
  admin_post "/v1/connections/$V2CONN/tools/refresh" '{}'
  { [ "$CODE" = 200 ] && [ "$(as_field "['refresh_grants']")" -gt "$RG_B0" ]; } \
    && ok "post-restart /tools/refresh unsealed the v2 credential (DEK unwrapped from wrapped_dek) + refreshed at the AS" \
    || no "post-restart unseal/refresh failed → $CODE: $BODY"
fi
# (b3) Dumped-row restore: capture the sealed bytes, wipe to garbage (unseal must
# FAIL), restore the exact bytes (unseal must SUCCEED again). Proves the v2 blob is
# what opens, portably, given the same KEK + wrapped DEK.
#
# The drill MUST run on a COLD access-token cache, which is the only thing the
# restart below buys — and it is load-bearing. `/tools/refresh` reaches the sealed
# credential ONLY when `oauth::ensure_access_token` has no live cached token: an
# entry is keyed (connection, generation) and served for its whole lifetime, and
# `/admin/expire-access` expires tokens AT THE AS — it cannot reach into the
# control plane's memory. On a warm cache (which is exactly what (b2)'s successful
# refresh leaves behind) discovery photographs with the stale cached bearer, the
# fake MCP 401s, and BOTH steps then report on that 401 instead of on the sealed
# bytes: the garbage step "passes" without ever opening the blob, and the restore
# step fails though the blob is byte-perfect. Cold cache instead ⇒ the garbage
# attempt fails AT THE UNSEAL without leaving the process (grant delta 0), and
# because a failed unseal caches nothing the restore attempt is still cold and
# genuinely mints. A restart is also the honest DR framing: the dumped bytes are
# restored into a process that never saw them sealed.
say "(b) Dumped-row restore — the exact sealed bytes open; garbage does not"
stop_server
boot "p2c" static 1 shared 0 "$MASTER_KEY" || { no "KMS-static restore-drill boot failed: $(tail -20 "$SERVER_LOG")"; exit 1; }
ok "control plane restarted for the restore drill (access-token cache cold)"
if need "${V2CONN:-}" "no v2 connection for the restore drill"; then
  DUMP=$(db "select encode(credential_sealed,'hex') from integration_connections where id='$V2CONN'")
  if need "$DUMP" "could not dump the sealed credential"; then
    RG_G0=$(as_field "['refresh_grants']")
    db "update integration_connections set credential_sealed = decode('00','hex') where id='$V2CONN'" >/dev/null
    admin_post "/v1/connections/$V2CONN/tools/refresh" '{}'
    { [ "$CODE" != 200 ] && echo "$BODY" | grep -qi unseal; } \
      && ok "a garbage sealed blob → the UNSEAL refuses ($CODE)" \
      || no "garbage blob did not fail at the unseal → $CODE: $BODY"
    # …and the refusal is LOCAL: a blob that will not open never becomes egress.
    RG_G1=$(as_field "['refresh_grants']")
    [ "$RG_G1" = "$RG_G0" ] \
      && ok "the garbage-blob refusal never reached the AS (refresh-grant delta 0)" \
      || no "a garbage sealed blob still hit the AS (grants $RG_G0 → $RG_G1)"
    db "update integration_connections set credential_sealed = decode('$DUMP','hex'), status='active' where id='$V2CONN'" >/dev/null
    RG_R0=$(as_field "['refresh_grants']")
    admin_post "/v1/connections/$V2CONN/tools/refresh" '{}'
    { [ "$CODE" = 200 ] && [ "$(as_field "['refresh_grants']")" -gt "$RG_R0" ]; } \
      && ok "restoring the exact dumped bytes → unseal SUCCEEDS again (the blob is portable)" \
      || no "restored sealed blob did not open → $CODE: $BODY"
  fi
fi
stop_server

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3 — KMS STATIC, legacy present. Section (c): run the re-seal job to
# completion and prove count parity flips to ZERO legacy across every seeded
# family; then the D4 retirement-gate matrix (boot WITHOUT the legacy key
# succeeds once parity is zero, and REFUSES with one hand-reverted v1 row).
# ═════════════════════════════════════════════════════════════════════════════
say "(c) Re-seal — legacy→envelope to completion; count parity → zero legacy"
boot "p3" static 1 shared 0 "$MASTER_KEY" || { no "reseal boot failed: $(tail -20 "$SERVER_LOG")"; exit 1; }
ok "control plane up (KMS static, legacy present — reseal can open v1 + write v2)"
# The seeded families must show legacy > 0 BEFORE the job. as_reseal fetches the
# parity endpoint; fam_legacy/fam_envelope pluck one family's counts.
as_reseal() { admin_get "/v1/admin/reseal"; printf '%s' "$BODY"; }
fam_legacy() { as_reseal | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(next((f['legacy'] for f in d['families'] if f['family']=='$1'), 'NA'))" 2>/dev/null; }
fam_envelope() { as_reseal | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(next((f['envelope'] for f in d['families'] if f['family']=='$1'), 'NA'))" 2>/dev/null; }
SEED_FAMILIES="integration_connections.credential_sealed trigger_subscriptions.callback_secret_sealed org_idp_configs.client_secret_sealed github_app_registrations.pem_sealed oauth_client_registrations.client_secret_sealed"
admin_get "/v1/admin/reseal"
LT0=$(echo "$BODY" | j "['legacy_total']")
[ "${LT0:-0}" -gt 0 ] && ok "GET /v1/admin/reseal: legacy_total=$LT0 (>0 — v1 rows await reseal)" || no "legacy_total=$LT0 before reseal (want >0): $BODY"
for f in $SEED_FAMILIES; do
  L=$(fam_legacy "$f")
  [ "${L:-0}" -ge 1 ] && ok "  before: $f legacy=$L" || no "  $f legacy=$L before reseal (want ≥1)"
done
# The connector-OAuth PKCE-verifier family gets the SAME before-state precondition
# as the seeded families. Its after-state (legacy=0, below) is a FALSE GREEN on its
# own: with zero legacy flow rows reaching the job, "counted + drained" passes
# without the job re-sealing a single verifier — precisely the state the assertion
# exists to rule out. The dance sections (d/e/f) left in-flight v1 rows behind, so
# this must be ≥1 here; 'NA' means the family is not counted at all.
CFLOW_L0=$(fam_legacy "connector_oauth_flows.pkce_verifier_sealed")
[ "${CFLOW_L0:-0}" -ge 1 ] 2>/dev/null \
  && ok "  before: connector_oauth_flows.pkce_verifier_sealed legacy=$CFLOW_L0 (v1 rows for the job to drain)" \
  || no "  connector_oauth_flows.pkce_verifier_sealed legacy=$CFLOW_L0 before reseal (want ≥1; 'NA' ⇒ uncounted family — the after-state check below would be vacuous)"
# Start the job → 202.
admin_post "/v1/admin/reseal" '{}'
[ "$CODE" = 202 ] && ok "POST /v1/admin/reseal → 202 Accepted (job started)" || no "reseal start → $CODE: $BODY"
# Poll to completion: legacy_total == 0 AND running == false.
DONE=0
for _ in $(seq 1 120); do
  admin_get "/v1/admin/reseal"
  LT=$(echo "$BODY" | j "['legacy_total']")
  RUNNING=$(echo "$BODY" | j "['running']")
  { [ "$LT" = 0 ] && [ "$RUNNING" = "False" ]; } && { DONE=1; break; }
  sleep 0.5
done
[ "$DONE" = 1 ] && ok "re-seal ran to completion: legacy_total=0, job not running (ZERO legacy)" || no "reseal did not reach zero legacy (legacy_total=$LT running=$RUNNING): $BODY"
# Every seeded family flipped: legacy 0, envelope ≥ 1.
for f in $SEED_FAMILIES; do
  L=$(fam_legacy "$f"); E=$(fam_envelope "$f")
  { [ "$L" = 0 ] && [ "${E:-0}" -ge 1 ]; } && ok "  after: $f legacy=0 envelope=$E (flipped)" || no "  $f did not flip (legacy=$L envelope=$E)"
done
# The connector-OAuth-dance PKCE verifier (connector_oauth_flows.pkce_verifier_sealed)
# is now a COUNTED + re-sealed family, in lockstep with reseal::FAMILIES (Phase D
# review fix, #32) — it is NO LONGER "uncounted by design". The P1 dance sections
# (d/e/f) left in-flight v1 flow rows behind; the re-seal job now walks that family
# too and drains them to v2, so it reports zero legacy here and rides the
# legacy_total==0 poll above. Were it still uncounted, fam_legacy would return 'NA'
# (a stale v1 flow row would then escape BOTH the re-seal job and the D4 gate).
CFLOW_L=$(fam_legacy "connector_oauth_flows.pkce_verifier_sealed")
{ [ "$CFLOW_L" = 0 ] && [ "${CFLOW_L0:-0}" -ge 1 ]; } 2>/dev/null \
  && ok "  after: connector_oauth_flows.pkce_verifier_sealed legacy=0 (drained the $CFLOW_L0 v1 row(s) counted before the job)" \
  || no "  connector_oauth_flows.pkce_verifier_sealed not drained/counted (before=$CFLOW_L0 after=$CFLOW_L; want ≥1 → 0 — 'NA' ⇒ still uncounted)"
stop_server

# ── (c/D4) Retirement gate — legacy key retires cleanly once parity is zero ────
say "(c) Retirement gate — boot WITHOUT the legacy key succeeds at zero parity"
boot "p3-retire-ok" static 0 shared 0 "$MASTER_KEY" \
  && ok "KMS static, FLUIDBOX_CREDENTIAL_KEY ABSENT, zero v1 rows → boots healthy" \
  || no "legacy-retired boot refused despite zero parity: $(tail -20 "$SERVER_LOG")"
stop_server

# ── (c/D4) Retirement gate NEGATIVE — one hand-reverted v1 row refuses boot ────
# Flip ONE resealed family's key_version back to 1 (the bytes stay v2 — the gate
# is a COUNT of the version column, so a hand-reverted version triggers the same
# refusal the gate exists for). seal.rs check_retirement_gates.
say "(c) Retirement gate NEGATIVE — one v1 straggler refuses the legacy-retired boot"
db "update trigger_subscriptions set callback_secret_key_version=1 where callback_secret_sealed is not null" >/dev/null
STRAG=$(db "select count(*) from trigger_subscriptions where callback_secret_key_version=1 and callback_secret_sealed is not null")
[ "${STRAG:-0}" -ge 1 ] && ok "hand-reverted $STRAG trigger_subscriptions row(s) to key_version=1" || no "could not revert a row to v1"
if boot_expect_refusal "p3-retire-refuse" static 0 shared 0 "$MASTER_KEY"; then
  { grep -q "legacy (v1) sealed row(s) remain" "$SERVER_LOG" && grep -q "trigger_subscriptions.callback_secret_sealed" "$SERVER_LOG"; } \
    && ok "legacy-absent boot with a v1 straggler → REFUSED, naming the family" \
    || no "boot refused but the log lacks the family-named gate reason: $(tail -5 "$SERVER_LOG")"
else
  # Forensics on the healthy-boot failure: hung vs healthy, row state, and the
  # unfiltered tail showing how far boot actually got.
  STRAG_AFTER=$(db "select count(*) from trigger_subscriptions where callback_secret_key_version=1 and callback_secret_sealed is not null")
  HCODE=$(curl -s -o /dev/null -w '%{http_code}' "$API/v1/health")
  no "a v1 straggler did NOT refuse the legacy-retired boot (health=$HCODE; straggler rows after boot=$STRAG_AFTER; log tail: $(tail -6 "$SERVER_LOG" | tr '\n' '|'))"
fi
# Restore parity so the tenant-mode boot is clean.
db "update trigger_subscriptions set callback_secret_key_version=2 where callback_secret_sealed is not null" >/dev/null
ok "restored the straggler to key_version=2 (parity zero again)"

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 4 — KMS STATIC, legacy ABSENT (retired), TENANT LLM mode + fake LiteLLM.
# This boot doubles as the retirement-gate POSITIVE (legacy absent, zero parity).
# Section (i): per-tenant virtual keys. Section (j): RLS. Cross-tenant 404.
# ═════════════════════════════════════════════════════════════════════════════
say "(i) Virtual keys — tenant mode boot; per-tenant keys; master confined to /key/generate"
boot "p4" static 0 tenant 0 "$MASTER_KEY" || { no "tenant-mode boot failed: $(tail -20 "$SERVER_LOG")"; exit 1; }
ok "control plane up (KMS static, legacy retired, LLM_KEY_MODE=tenant, fake LiteLLM)"
DEFAULT_TID=$(db "select id from tenants order by created_at asc limit 1")
need "$DEFAULT_TID" "default tenant id did not resolve" && ok "default (deployment) tenant id captured"
# Two orgs → two eager mints at LiteLLM, each with the MASTER-key bearer.
admin_post "/v1/admin/orgs" "{\"slug\":\"org-a\",\"display_name\":\"Org A\"}"
[ "$CODE" = 200 ] && ok "org 'org-a' created (tenant mode → eager virtual-key mint)" || no "org-a → $CODE: $BODY"
admin_post "/v1/admin/orgs" "{\"slug\":\"org-b\",\"display_name\":\"Org B\"}"
[ "$CODE" = 200 ] && ok "org 'org-b' created (tenant mode → eager virtual-key mint)" || no "org-b → $CODE: $BODY"
TID_A=$(db "select id from tenants where slug='org-a'")
TID_B=$(db "select id from tenants where slug='org-b'")
# The fake LiteLLM saw the MASTER key ONLY on /key/generate — and on EVERY
# /key/generate, not merely the first. The fake accepts any Authorization, so a
# `generate[0]` spot-check would stay green while org-b's mint (and every later
# one) presented the wrong credential.
GEN_AUTH=$(llm_all_auth generate "Bearer $MASTER_KEY")
case "$GEN_AUTH" in
  "OK "*) ok "EVERY /key/generate so far authenticated with the MASTER key (${GEN_AUTH#OK } call(s))";;
  NONE)   no "no /key/generate calls recorded — the eager per-tenant mint never happened";;
  *)      no "a /key/generate call used the WRONG credential: '${GEN_AUTH#BAD }'";;
esac
KEY_A=$(llm_state | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(next((g['key'] for g in d['generate'] if g['tenant']=='$TID_A'), ''))" 2>/dev/null)
KEY_B=$(llm_state | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(next((g['key'] for g in d['generate'] if g['tenant']=='$TID_B'), ''))" 2>/dev/null)
{ need "$KEY_A" "org-a virtual key not minted" && need "$KEY_B" "org-b virtual key not minted"; } && \
  { [ "$KEY_A" != "$KEY_B" ] && ok "org-a and org-b minted DIFFERENT virtual keys ($KEY_A ≠ $KEY_B)" || no "the two orgs share a virtual key ($KEY_A)"; }
# Two distinct sealed tenant_llm_keys rows (v2 under each tenant's own DEK).
LLMROWS=$(db "select count(distinct litellm_key_sealed) from tenant_llm_keys where tenant_id in ('$TID_A','$TID_B')")
[ "$LLMROWS" = 2 ] && ok "two DISTINCT sealed tenant_llm_keys rows (per-tenant custody)" || no "distinct sealed llm-key rows = $LLMROWS (want 2)"

# A facade model call carries the VIRTUAL key, never the master. Use a real run in
# the default tenant (lazy-mints the default tenant's key on first use).
say "(i) Facade call carries the virtual key; rotate → new key next call"
create_run "pub-agent"; DRUN="$RUN"
need "$DRUN" "default-tenant run not created ($BODY)" && ok "created a run in the default tenant ($DRUN)"
forge_running "$DRUN" "sess-d-$$" "default" && ok "run forced running + session token forged" || true
MODEL=$(db "select run_spec->>'model' from sessions where id='$DRUN'")
need "$MODEL" "could not read the run's frozen model" && ok "frozen model = $MODEL"
MSG0=$(llm_field "['messages'].__len__()")
facade_call "sess-d-$$" "$MODEL"
[ "$FCODE" = 200 ] && ok "facade /v1/messages → 200 (upstream reached)" || no "facade call → $FCODE: $(printf '%s' "$FBODY" | head -c160)"
[ "$(llm_field "['messages'].__len__()")" -gt "$MSG0" ] && ok "the call reached the fake LiteLLM upstream" || no "no new /v1/messages at the upstream"
DEF_AUTH=$(llm_field "['messages'][-1]['auth']")
case "$DEF_AUTH" in
  "Bearer sk-fbx-"*) ok "the facade presented a VIRTUAL key upstream ($DEF_AUTH), never the master";;
  *) no "facade upstream auth wrong: '$DEF_AUTH'";;
esac
[ "$DEF_AUTH" != "Bearer $MASTER_KEY" ] && ok "the master key NEVER rode a model request" || no "the MASTER key leaked onto /v1/messages!"
# Rotate org-a's key → a facade call FOR org-a carries the NEW key.
OA_SID=$(forge_tenant_session "$TID_A" "$DRUN" "sess-oa-$$")
if need "$OA_SID" "could not forge an org-a session"; then
  facade_call "sess-oa-$$" "$MODEL"
  OA_AUTH1=$(llm_field "['messages'][-1]['auth']")
  [ "$OA_AUTH1" = "Bearer $KEY_A" ] && ok "org-a's facade call presented org-a's virtual key ($KEY_A)" || no "org-a facade key wrong: '$OA_AUTH1' (want Bearer $KEY_A)"
  admin_post "/v1/admin/orgs/org-a/llm-key/rotate" '{}'
  { [ "$CODE" = 200 ] && echo "$BODY" | grep -qi '"rotated": *true'; } && ok "POST /v1/admin/orgs/org-a/llm-key/rotate → {rotated:true}" || no "rotate → $CODE: $BODY"
  KEY_A2=$(llm_state | python3 -c "
import sys,json
d=json.load(sys.stdin)
ks=[g['key'] for g in d['generate'] if g['tenant']=='$TID_A']
print(ks[-1] if ks else '')" 2>/dev/null)
  facade_call "sess-oa-$$" "$MODEL"
  OA_AUTH2=$(llm_field "['messages'][-1]['auth']")
  { [ "$OA_AUTH2" = "Bearer $KEY_A2" ] && [ "$KEY_A2" != "$KEY_A" ]; } \
    && ok "after rotate, org-a's next facade call presents the NEW key ($KEY_A2 ≠ $KEY_A)" \
    || no "rotate did not change the presented key (was $KEY_A, now '$OA_AUTH2', new mint '$KEY_A2')"
fi
# Provisioning-credential sweep over EVERY recorded admin call in this phase —
# the eager org-a/org-b mints, the default tenant's lazy mint, the rotation
# re-mint, and the rotation's best-effort delete of the superseded key. The
# master key is provisioning-only: it must appear on all of them and (asserted
# above + in section (k)) on no model request.
GEN_AUTH=$(llm_all_auth generate "Bearer $MASTER_KEY")
case "$GEN_AUTH" in
  "OK "*) ok "EVERY /key/generate call used the MASTER key (${GEN_AUTH#OK } call(s): eager mints + lazy mint + rotation)";;
  NONE)   no "no /key/generate calls recorded at all — the virtual-key assertions would be vacuous";;
  *)      no "a /key/generate call used the WRONG credential: '${GEN_AUTH#BAD }'";;
esac
DEL_AUTH=$(llm_all_auth delete "Bearer $MASTER_KEY")
case "$DEL_AUTH" in
  "OK "*) ok "EVERY /key/delete call used the MASTER key (${DEL_AUTH#OK } call(s): the rotation's old-key cleanup)";;
  NONE)   no "no /key/delete recorded, yet the rotation above returned {rotated:true} — rotate_tenant_key awaits the superseded key's delete before returning, so org-a's old key is now a live orphan at LiteLLM";;
  *)      no "a /key/delete call used the WRONG credential: '${DEL_AUTH#BAD }'";;
esac

# ── (j) RLS — the runtime role sees only its tenant; GUC bypass; audit is append-only ─
# #32 (j). SET ROLE fluidbox_runtime (NOLOGIN, granted to the CI superuser by
# migration 0018) → the tenant GUC gates visibility; no GUC → zero; the bypass GUC
# → all; UPDATE on auth_audit_log → permission denied (the deferred-grant proof).
say "(j) RLS — runtime role tenant isolation, GUC bypass, append-only audit"
# Ensure both tenants have session rows to distinguish.
OTHER_SID=$(forge_tenant_session "$TID_B" "$DRUN" "sess-rls-b-$$")
CNT_A=$(db "select count(*) from sessions where tenant_id='$TID_A'")
CNT_B=$(db "select count(*) from sessions where tenant_id='$TID_B'")
TOTAL=$(db "select count(*) from sessions")
# With tenant-A GUC, an unfiltered scan sees ONLY tenant A (the buggy-predicate
# negative). SET LOCAL on the dotted custom GUC (unquoted class.name) emits no row,
# so `select count(*)` is the sole output — the RLS policy keys on this GUC.
# db_raw (NOT db): these four assert on what the policy alone allows, so the
# connection must carry no ambient bypass GUC — db() would set one and every
# count would come back as the cross-tenant total.
#
# BOTH sides must be non-empty first. `RLS_A == CNT_A` is a vacuous pass at
# 0 == 0 (and so is `RLS_ALL == TOTAL` on an empty table): the comparison would
# report isolation while proving nothing, and the surviving `!=` guard against
# TOTAL would be the only real content. One loud failure, then skip the four.
if { [ "${CNT_A:-0}" -gt 0 ] && [ "${CNT_B:-0}" -gt 0 ] && [ "${TOTAL:-0}" -gt "${CNT_A:-0}" ]; }; then
  ok "RLS fixture is non-degenerate (A=$CNT_A, B=$CNT_B, total=$TOTAL — both tenants own rows)"
  RLS_A=$(db_raw "set role fluidbox_runtime; begin; set local fluidbox.tenant_id = '$TID_A'; select count(*) from sessions; commit;")
  { [ "$RLS_A" = "$CNT_A" ] && [ "$RLS_A" != "$TOTAL" ]; } \
    && ok "runtime role + tenant-A GUC sees ONLY A's sessions ($RLS_A == A=$CNT_A, ≠ total=$TOTAL)" \
    || no "RLS tenant-A read = $RLS_A (A=$CNT_A total=$TOTAL)"
  # Symmetric: tenant-B GUC sees ONLY B's sessions (isolation, not a fixed subset).
  RLS_B=$(db_raw "set role fluidbox_runtime; begin; set local fluidbox.tenant_id = '$TID_B'; select count(*) from sessions; commit;")
  { [ "$RLS_B" = "$CNT_B" ] && [ "$RLS_B" != "$TOTAL" ]; } \
    && ok "runtime role + tenant-B GUC sees ONLY B's sessions ($RLS_B == B=$CNT_B, ≠ total=$TOTAL)" \
    || no "RLS tenant-B read = $RLS_B (B=$CNT_B total=$TOTAL)"
  # No GUC → RLS denies everything.
  RLS_NONE=$(db_raw "set role fluidbox_runtime; select count(*) from sessions;")
  [ "$RLS_NONE" = 0 ] && ok "runtime role with NO tenant GUC → 0 rows (fail closed)" || no "no-GUC read = $RLS_NONE (want 0)"
  # Bypass GUC → the audited system_worker lens sees all.
  RLS_ALL=$(db_raw "set role fluidbox_runtime; begin; set local fluidbox.bypass = 'system_worker'; select count(*) from sessions; commit;")
  [ "$RLS_ALL" = "$TOTAL" ] && ok "runtime role + bypass GUC → all $RLS_ALL rows (system_worker lens)" || no "bypass read = $RLS_ALL (want total=$TOTAL)"
else
  no "RLS fixture is degenerate (A=$CNT_A B=$CNT_B total=$TOTAL) — the tenant-isolation comparisons would be vacuous; skipping them"
fi
# ── The GLOBAL-row read/write SPLIT (0018 :222-247) ───────────────────────────
# The two MIXED tables (`connector_catalog`, `oauth_client_registrations`) carry
# `tenant_id IS NULL` rows every tenant must READ and no tenant may WRITE. That
# split is the single place in 0018 where SELECT and INSERT/UPDATE/DELETE differ,
# so nothing else in this suite covers it: a `for all` policy (whose USING also
# filters UPDATE/DELETE) would read identically here and quietly make global rows
# mutable by any scoped transaction. Every probe below rides `db_raw` + SET ROLE
# (policies bind the runtime role) and every mutation is rolled back.
for GT in connector_catalog oauth_client_registrations; do
  GLOBALS=$(db "select count(*) from $GT where tenant_id is null")
  if [ "${GLOBALS:-0}" -gt 0 ] 2>/dev/null; then
    # READ: a tenant-scoped transaction sees every global row (shared reference
    # data — this is also why the catalog renders before a scope exists).
    GSEE=$(db_raw "set role fluidbox_runtime; begin; set local fluidbox.tenant_id = '$TID_A'; select count(*) from $GT where tenant_id is null; commit;")
    [ "$GSEE" = "$GLOBALS" ] \
      && ok "  $GT: a tenant-scoped read SEES all $GLOBALS global row(s)" \
      || no "  $GT: scoped read saw $GSEE of $GLOBALS global rows (want all — global rows are shared reference data)"
    # UPDATE: the policy's USING filters the global rows out, so a scoped UPDATE
    # matches ZERO rows (silently — RLS narrows, it does not raise, on U/D).
    GUPD=$(db_raw "set role fluidbox_runtime; begin; set local fluidbox.tenant_id = '$TID_A'; with u as (update $GT set created_at = created_at where tenant_id is null returning 1) select count(*) from u; rollback;")
    [ "$GUPD" = 0 ] \
      && ok "  $GT: a tenant-scoped UPDATE of global rows touches 0 rows" \
      || no "  $GT: a tenant-scoped UPDATE mutated $GUPD global row(s) — the read/write split is broken"
    # DELETE: same filter (rolled back regardless, so a broken policy cannot eat
    # the catalog the rest of this run depends on).
    GDEL=$(db_raw "set role fluidbox_runtime; begin; set local fluidbox.tenant_id = '$TID_A'; with d as (delete from $GT where tenant_id is null returning 1) select count(*) from d; rollback;")
    [ "$GDEL" = 0 ] \
      && ok "  $GT: a tenant-scoped DELETE of global rows removes 0 rows" \
      || no "  $GT: a tenant-scoped DELETE removed $GDEL global row(s) — the read/write split is broken"
    # BYPASS: the audited system_worker lens is the ONE writer of global rows.
    GBYP=$(db_raw "set role fluidbox_runtime; begin; set local fluidbox.bypass = 'system_worker'; with u as (update $GT set created_at = created_at where tenant_id is null returning 1) select count(*) from u; rollback;")
    [ "${GBYP:-0}" -gt 0 ] \
      && ok "  $GT: the system_worker bypass CAN mutate global rows ($GBYP)" \
      || no "  $GT: the bypass could not mutate global rows (got '$GBYP') — deployment writes would fail closed"
  else
    no "  $GT has no global (tenant_id IS NULL) rows — the read/write-split probes would be vacuous"
  fi
done
# INSERT: a scoped transaction may not MINT a global row (WITH CHECK raises, so
# this one surfaces as an error, not a zero row count). Rolled back either way.
#
# BOTH mixed tables are probed. The SELECT/UPDATE/DELETE loop above passes on
# `oauth_client_registrations` no matter what `registration_insert` says, so a
# `tenant_id IS NULL` arm creeping back into that ONE policy — while every other
# policy stayed correct — would leave the whole section green while a tenant-scoped
# transaction could mint a GLOBAL client identity: the row that holds the
# deployment-wide OAuth client_id and its sealed client_secret.
for GI in \
  "connector_catalog|slug, name, tier|'rls-global-probe-$$', 'RLS global probe', 'custom'" \
  "oauth_client_registrations|id, issuer, redirect_uri, source, client_id|gen_random_uuid(), 'https://rls-global-probe-$$.invalid', 'https://rls-global-probe-$$.invalid/cb', 'dcr', 'rls-global-probe'"
do
  GT="${GI%%|*}"; GI_REST="${GI#*|}"; GCOLS="${GI_REST%%|*}"; GVALS="${GI_REST#*|}"
  GINS=$(psql "$DATABASE_URL" -X -q -A -t -c "set role fluidbox_runtime; begin; set local fluidbox.tenant_id = '$TID_A'; insert into $GT ($GCOLS) values ($GVALS); rollback;" 2>&1)
  echo "$GINS" | grep -qi "row-level security" \
    && ok "  $GT: a tenant-scoped INSERT of a GLOBAL row → refused by row-level security" \
    || no "  $GT: a tenant-scoped INSERT minted a global row (or failed for another reason): $GINS"
done
# The runtime role cannot UPDATE the append-only audit log.
AUDIT_ERR=$(psql "$DATABASE_URL" -X -q -c "set role fluidbox_runtime; update auth_audit_log set action = action" 2>&1)
echo "$AUDIT_ERR" | grep -qi "permission denied" && ok "runtime role UPDATE on auth_audit_log → permission denied (append-only)" || no "audit UPDATE not denied: $AUDIT_ERR"
# Cross-tenant API 404: the operator's default-tenant scope cannot read org-B's session.
if need "${OTHER_SID:-}" "no org-B session for the cross-tenant 404 check"; then
  X404=$(curl -s -o /dev/null -w '%{http_code}' -H "$AH" "$API/v1/sessions/$OTHER_SID")
  [ "$X404" = 404 ] && ok "operator (default-tenant scope) GET org-B's session → 404 (tenant-scoped loader)" || no "cross-tenant read → $X404 (want 404)"
fi
stop_server

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 5 — shared LLM mode + REQUIRE_SSO=1. The forbidden hosted posture: the
# facade refuses EVERY model request with a stable 503 code. facade.rs / llm_keys.rs.
# ═════════════════════════════════════════════════════════════════════════════
say "(a/i) SSO + shared → facade refuses every model request (503 tenant_llm_keys_required)"
boot "p5" static 0 shared 1 "$MASTER_KEY" || { no "sso+shared boot failed: $(tail -20 "$SERVER_LOG")"; exit 1; }
ok "control plane up (KMS static, shared LLM, REQUIRE_SSO=1)"
# The /internal facade is session-token authed (not the admin token), so a psql-
# forged running session drives it even under REQUIRE_SSO. Reuse a prior session's
# run_spec (copied into the default tenant).
ANY_SID=$(db "select id from sessions where tenant_id='$DEFAULT_TID' limit 1")
if need "$ANY_SID" "no session to copy for the sso facade probe"; then
  SSO_SID=$(forge_tenant_session "$DEFAULT_TID" "$ANY_SID" "sess-sso-$$")
  SSO_MODEL=$(db "select run_spec->>'model' from sessions where id='$SSO_SID'")
  if need "$SSO_SID" "could not forge the sso facade session"; then
    facade_call "sess-sso-$$" "$SSO_MODEL"
    { [ "$FCODE" = 503 ] && printf '%s' "$FBODY" | grep -q "tenant_llm_keys_required"; } \
      && ok "shared mode + REQUIRE_SSO → facade → 503 with code tenant_llm_keys_required" \
      || no "sso+shared facade → $FCODE: $(printf '%s' "$FBODY" | head -c160)"
  fi
fi
stop_server

# ═════════════════════════════════════════════════════════════════════════════
# (k) Redaction / log hygiene — NO secret material in ANY server log across ALL
# boots: the two deployment keys (legacy + KEK) hex, the LiteLLM master key, minted
# virtual keys, refresh tokens, private-key material, cookie values, and every AS
# state param we captured. #32 (k).
# ═════════════════════════════════════════════════════════════════════════════
say "(k) Log hygiene — no secrets in any server log"
ALL_LOGS=$(cat "$WORK"/server-*.log 2>/dev/null)
# Gather the sensitive values we HOLD.
STATE_PARAMS=$(as_state | python3 -c "
import sys,json
d=json.load(sys.stdin)
vals=set()
for a in d.get('authorize',[]):
    if a.get('state'): vals.add(a['state'])
print('\n'.join(vals))" 2>/dev/null)
REFRESH_TOKS=$(as_state | python3 -c "
import sys,json
d=json.load(sys.stdin)
toks=set(d.get('refresh',[]))
for g in d.get('grants',[]):
    if g.get('minted_refresh'): toks.add(g['minted_refresh'])
print('\n'.join(t for t in toks if t))" 2>/dev/null)
COOKIE_VALS=$(grep -hoiE '__Host-fbx_oauth_flow[[:space:]]+[^[:space:]]+' "$WORK"/jar* 2>/dev/null | awk '{print $NF}' | sort -u)
VKEYS=$(llm_state | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('\n'.join(sorted({g['key'] for g in d.get('generate',[]) if g.get('key')})))" 2>/dev/null)

check_absent() { # label value
  [ -z "$2" ] && return 0
  if printf '%s' "$ALL_LOGS" | grep -Fq "$2"; then
    no "log hygiene: $1 LEAKED into a server log"
  else
    ok "log hygiene: $1 absent from every server log"
  fi
}
check_absent "FLUIDBOX_CREDENTIAL_KEY (legacy key hex)" "$CRED_KEY"
check_absent "FLUIDBOX_KMS_STATIC_KEK (KEK hex)" "$STATIC_KEK"
check_absent "LITELLM_MASTER_KEY" "$MASTER_KEY"
printf '%s' "$ALL_LOGS" | grep -q "BEGIN RSA PRIVATE KEY" && no "log hygiene: a private key (BEGIN RSA PRIVATE KEY) LEAKED" || ok "log hygiene: no 'BEGIN RSA PRIVATE KEY' in any log"
printf '%s' "$ALL_LOGS" | grep -q "CLIENTSECRET" && no "log hygiene: a github-app/idp client secret LEAKED" || ok "log hygiene: no client-secret material in any log"
# Multi-value families: assert each captured value is absent.
LEAK=0
for v in $VKEYS;        do printf '%s' "$ALL_LOGS" | grep -Fq "$v" && LEAK=1; done
[ "$LEAK" = 0 ] && ok "log hygiene: no minted virtual key (sk-fbx-*) in any log" || no "log hygiene: a virtual key LEAKED"
LEAK=0
for v in $REFRESH_TOKS; do printf '%s' "$ALL_LOGS" | grep -Fq "$v" && LEAK=1; done
[ "$LEAK" = 0 ] && ok "log hygiene: no OAuth refresh token in any log" || no "log hygiene: a refresh token LEAKED"
LEAK=0
for v in $STATE_PARAMS; do printf '%s' "$ALL_LOGS" | grep -Fq "$v" && LEAK=1; done
[ "$LEAK" = 0 ] && ok "log hygiene: no OAuth state param value in any log" || no "log hygiene: an OAuth state param LEAKED"
LEAK=0
for v in $COOKIE_VALS;  do printf '%s' "$ALL_LOGS" | grep -Fq "$v" && LEAK=1; done
[ "$LEAK" = 0 ] && ok "log hygiene: no flow-cookie value in any log" || no "log hygiene: a flow-cookie value LEAKED"

# ── Result ───────────────────────────────────────────────────────────────────
say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
