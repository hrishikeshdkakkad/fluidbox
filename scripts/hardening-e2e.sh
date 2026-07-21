#!/usr/bin/env bash
# Phase E acceptance E2E (#33) — broker + network hardening, driven end-to-end
# over real HTTP against python-stdlib fakes (an MCP server, a second MCP server
# used only to be KILLED, and a redirecting server), with NO docker and NO Dex.
# It owns its stack: one control-plane boot, admin-token mode, psql fixtures.
#
# Design: .superpowers/sdd/phase-e-plan.md (E1–E14) and issue #33's acceptance
# bullets. Sections are lettered to map 1:1 with those bullets:
#   (a) SSRF / egress admission + dial + redirect + clone-URL policy   [Task 1]
#   (b) a DENIED brokered call never contacts the upstream            [Task 2/3]
#   (c) per-run MCP session isolation + auth on every request         [Task 2]
#   (d) 2025-11-25 conformance (initialize-first, headers, drift,
#       404-reinit, server→client -32601, SSE, DELETE, SEP-835)       [Task 2]
#   (e) frozen-schema argument enforcement + its GATE ORDER           [Task 3]
#   (f) durable four-state execution claims                           [Task 4]
#   (g) audience negatives   — Task 5  (placeholder at the end)
#   (h) LLM reservations     — Task 7  (placeholder at the end)
#   (i) two-replica          — Task 6  (placeholder at the end)
#   (j) breaker / rate       — Task 8  (placeholder at the end)
#
# House style mirrors scripts/secrets-e2e.sh + scripts/bindings-e2e.sh:
# pass/fail counters, a `db()` psql helper carrying the audited bypass GUC
# (0018 FORCEs RLS on every tenant table, so a GUC-less fixture read returns
# zero rows), fail-fast `need` preconditions, a cleanup trap, and a single
# section-labeled server log.
#
# ASSERTION DISCIPLINE (the Phase D false-green lesson, now a standing rule):
#   * every count assertion carries a `>0` precondition, so an empty or dead
#     fake can never pass one vacuously;
#   * every "exactly N" assertion first proves its recorder file is non-empty;
#   * a section that asserts ZERO upstream traffic carries a POSITIVE CONTROL in
#     the same section proving the recorder DOES record when a call is allowed;
#   * where an assertion could not be made fail-capable in this harness, there
#     is a comment naming what would be required instead — never a fake pass.
#
# HERMETIC + no model spend: runs never launch a sandbox (no runner image in CI,
# so provisioning fails FAST via the dead-registry image ref — exactly what the
# forged-run fixture wants) and every upstream is a local python fake.
# NEVER executed locally — CI on the PR is its proof (`bash -n` + shellcheck are
# the local bar). The CI job (distinct DB `fluidbox_hardening`, mirroring the
# `secrets` job's env matrix) is added separately in .github/workflows/ci.yml.
#
# `set -e` is intentionally OMITTED (matching the siblings): this drives a large
# negative matrix of EXPECTED non-2xx responses; aborting on the first would
# defeat it. Failures are counted; a nonzero `fail` exits 1.
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
# Postgres service. No docker, no Dex: every fake is python stdlib.
if [ -z "${DATABASE_URL:-}" ]; then
  echo "hardening-e2e: DATABASE_URL is required (CI provides the Postgres service)." >&2
  echo "  This script drives the broker, the egress boundary, the schema gate and" >&2
  echo "  the execution-claim table against a real DB; it will not run — and must" >&2
  echo "  never silently skip — without one." >&2
  exit 2
fi
command -v curl    >/dev/null 2>&1 || { echo "hardening-e2e: curl is required." >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "hardening-e2e: python3 is required (fakes + JSON)." >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "hardening-e2e: openssl is required (keys + sha256)." >&2; exit 2; }
command -v git     >/dev/null 2>&1 || { echo "hardening-e2e: git is required (the file:// clone fixture)." >&2; exit 2; }
# psql is REQUIRED, not optional: the acceptance PROVES ledger `source` values,
# execution-claim states and the SEP-835 connection note directly. None of those
# may silently skip, so a missing psql aborts the whole run.
command -v psql    >/dev/null 2>&1 || { echo "hardening-e2e: psql is required (acceptance must be PROVEN, not skipped)." >&2; exit 2; }

# ── Config ───────────────────────────────────────────────────────────────────
API_PORT=8787
API="http://127.0.0.1:$API_PORT"
# Reserved for section (i) (Task 6): the second replica binds here, same DB.
# shellcheck disable=SC2034  # consumed by the section (i) placeholder's boot
API_PORT_B=8788

ADMIN_TOKEN=$(openssl rand -hex 32)
CRED_KEY=$(openssl rand -hex 32)        # FLUIDBOX_CREDENTIAL_KEY (seals connections)
MASTER_KEY="sk-litellm-master-$$"       # LITELLM_MASTER_KEY placeholder (shared mode
                                        # refuses to boot on an EMPTY key; no facade
                                        # traffic in sections (a)-(f)).

# Fake servers (fixed high ports; readiness-probed like the siblings).
MCP_PORT=8971       # the primary brokered MCP upstream (all conformance work)
MCP2_PORT=8972      # a SECOND MCP upstream, killed on purpose in section (f)
REDIR_PORT=8973     # a server that answers 302 (redirect-refusal proof)
LLM_PORT=8974       # reserved: fake LiteLLM for section (h) (Task 7)
MCP_URL="http://127.0.0.1:$MCP_PORT/mcp"
MCP2_URL="http://127.0.0.1:$MCP2_PORT/mcp"
REDIR_URL="http://127.0.0.1:$REDIR_PORT/mcp"
# Where the redirect fake points its Location: a DIFFERENT host:port, on the
# primary MCP fake, at a path nothing else ever touches. If the hardened client
# ever followed a 3xx, that fake's recorder would show a `/followed` request.
FOLLOW_URL="http://127.0.0.1:$MCP_PORT/followed"

# Literal private/metadata targets. These are deliberately NOT servers: the
# control plane must refuse them BEFORE opening a socket, so the assertions never
# depend on a connect timeout. 10.255.255.1 is non-loopback private (blocked even
# under the dev seam); 169.254.169.254 is cloud metadata (blocked unconditionally).
PRIV_MCP="https://10.255.255.1:1/mcp"
PRIV_HTTP_MCP="http://10.255.255.1:1/mcp"
META_URL="https://169.254.169.254/latest/meta-data/"
PRIV_CLONE="https://10.255.255.1/repo.git"

SLUG="hq-fake"        # custom catalog slug (valid [a-z0-9-])
SLUG2="hq-fake-2"     # the killable upstream's catalog slug
PROTO_SNAP="2025-06-18"   # what the fake negotiates at photograph time

WORK=$(mktemp -d)
DATA_DIR="$WORK/data"; mkdir -p "$DATA_DIR"
FAKES="$WORK/fakes";   mkdir -p "$FAKES"
CLONE_ROOT="$WORK/repos"; mkdir -p "$CLONE_ROOT"
CLONE_BASE="file://$CLONE_ROOT"     # FLUIDBOX_GITHUB_CLONE_BASE for this run
SERVER_PID=""
MCP_PID=""; MCP2_PID=""; REDIR_PID=""
SERVER_LOG="$WORK/server.log"
UB="$WORK/ub"                       # scratch body file for the curl helpers
MCP_LOG="$WORK/mcp-requests.jsonl";     : > "$MCP_LOG"
MCP2_LOG="$WORK/mcp2-requests.jsonl";   : > "$MCP2_LOG"
REDIR_LOG="$WORK/redirect-requests.jsonl"; : > "$REDIR_LOG"
MCP_CTL="$WORK/mcp-control.json"
MCP2_CTL="$WORK/mcp2-control.json"
# The bearers the fakes accept. Anything else is a real 401 (a credentialed
# server), so a broker that turned the WRONG credential fails loudly.
TOK_HQ="hq-secret-$$"
TOK_HQ2="hq2-secret-$$"

pass=0; fail=0
ok()  { printf "  \033[1;32m✓\033[0m %s\n" "$1"; pass=$((pass+1)); }
no()  { printf "  \033[1;31m✗\033[0m %s\n" "$1"; fail=$((fail+1)); }
say() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }
# Fail-fast precondition guard (identical semantics to the siblings): when a
# value a section DEPENDS ON is empty, record ONE loud failure and return nonzero
# so the caller SKIPS the dependent steps — keeping one root failure legible
# instead of fanning it into dozens of misleading downstream ones. Never weakens
# a passing assertion: in the healthy path the value is non-empty and every guard
# runs.
need() { # value message
  [ -n "$1" ] && return 0
  no "precondition unmet — $2"
  return 1
}
# The >0 precondition every count assertion is required to carry. Prints the
# failure itself so call sites stay one-liners.
gt0() { # value label
  case "$1" in
    ''|*[!0-9]*) no "precondition unmet — $2 is not a number ('$1')"; return 1;;
  esac
  [ "$1" -gt 0 ] && return 0
  no "precondition unmet — $2 is 0 (an empty/dead recorder cannot prove anything)"
  return 1
}

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }

# psql shortcut. -q suppresses the command tag (else "INSERT 0 1" poisons a
# RETURNING capture); -A -t keep tuples-only/unaligned; -X skips ~/.psqlrc.
# The audited bypass GUC rides INSIDE the helper: migration 0018 FORCEs RLS on
# every tenant table (binding the table OWNER too), so a GUC-less fixture read
# returns zero rows and a fixture INSERT is refused. A session-level SET on a
# custom (dotted) option needs no privilege.
db() { psql "$DATABASE_URL" -X -q -A -t -c "set fluidbox.bypass = 'system_worker'; $1"; }

# ── Cleanup ──────────────────────────────────────────────────────────────────
# shellcheck disable=SC2329  # invoked via the EXIT/INT/TERM trap
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  [ -n "$MCP_PID" ]    && kill "$MCP_PID"    2>/dev/null
  [ -n "$MCP2_PID" ]   && kill "$MCP2_PID"   2>/dev/null
  [ -n "$REDIR_PID" ]  && kill "$REDIR_PID"  2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ═════════════════════════════════════════════════════════════════════════════
# Fakes (python stdlib; ThreadingHTTPServer — reqwest keeps pooled connections
# alive, and a serial HTTPServer would starve curl behind them). Each fake is
# written to its own FILE so it can be launched more than once with different
# ports/recorders (section (f) needs a second MCP upstream it can kill).
# ═════════════════════════════════════════════════════════════════════════════

# ── The Streamable-HTTP MCP fake ──────────────────────────────────────────────
# Records EVERY request as one jsonl line — HTTP method, path, the auth /
# mcp-session-id / mcp-protocol-version headers, the JSON-RPC method, the tool
# name, the offered protocolVersion (on initialize) and the JSON-RPC error code
# (so the server→client `-32601` reply POST is countable). That log is the whole
# basis of sections (b)-(f): it proves what DID and (crucially) what did NOT
# reach the upstream.
#
# Behavior is driven by a CONTROL FILE re-read on EVERY request, so bash can flip
# the negotiated protocol version or the tools/call outcome mid-run without a
# restart:
#   {"proto": "<negotiated version>", "tools_call": "<mode>", "epoch": <int>}
# tools_call modes: ok | is_error | http_500 | rpc_error | insufficient_scope |
#                   expire_once | sse | sse_multiline | sse_server_request | hang
# `expire_once` answers 404 exactly once per `epoch` value (the 404-with-session
# reinit path); bump `epoch` to re-arm it.
cat > "$FAKES/fake_mcp.py" <<'PYEOF'
import http.server, json, os, sys, threading, time

PORT   = int(sys.argv[1])
LOG    = sys.argv[2]
CTL    = sys.argv[3]
ACCEPT = {"Bearer " + t for t in sys.argv[4:]}

LOCK = threading.Lock()
STATE = {"n": 0, "expired_epochs": set()}

TOOLS = [
    # `required` + typed properties: section (e) violates BOTH shapes (a missing
    # required property, and a wrong-typed one).
    {"name": "hq_search", "description": "Search the fake knowledge base",
     "inputSchema": {"type": "object",
                     "properties": {"query": {"type": "string"}},
                     "required": ["query"],
                     "additionalProperties": False}},
    {"name": "hq_count", "description": "Count things",
     "inputSchema": {"type": "object",
                     "properties": {"n": {"type": "integer"}},
                     "required": ["n"],
                     "additionalProperties": False}},
]


def ctl():
    try:
        with open(CTL) as f:
            return json.load(f)
    except Exception:
        return {}


def nxt():
    with LOCK:
        STATE["n"] += 1
        return STATE["n"]


def record(row):
    with LOCK:
        with open(LOG, "a") as f:
            f.write(json.dumps(row) + "\n")
            f.flush()
            os.fsync(f.fileno())


class Mcp(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ── wire helpers ──────────────────────────────────────────────────────
    def _raw(self, code, body, ctype, headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj, headers=None):
        self._raw(code, json.dumps(obj), "application/json", headers)

    def _sse(self, events, headers=None):
        # `events` is a list of already-formatted `data:` line groups.
        body = "".join(e + "\n" for e in events)
        self._raw(200, body, "text/event-stream", headers)

    def _hdrs(self):
        return {
            "auth": self.headers.get("authorization", ""),
            "session": self.headers.get("mcp-session-id", ""),
            "proto_hdr": self.headers.get("mcp-protocol-version", ""),
            "accept": self.headers.get("accept", ""),
        }

    # ── non-POST verbs (the terminal DELETE is an acceptance bullet) ───────
    def do_DELETE(self):
        row = {"http": "DELETE", "path": self.path, "rpc": "", "tool": "",
               "offered": "", "error_code": "", "id": ""}
        row.update(self._hdrs())
        record(row)
        self._json(200, {"ok": True})

    def do_GET(self):
        row = {"http": "GET", "path": self.path, "rpc": "", "tool": "",
               "offered": "", "error_code": "", "id": ""}
        row.update(self._hdrs())
        record(row)
        self._json(405, {"error": "POST JSON-RPC"})

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        try:
            req = json.loads(raw)
        except Exception:
            req = {}
        method = req.get("method", "") or ""
        rid = req.get("id")
        params = req.get("params") or {}
        err = req.get("error") if isinstance(req.get("error"), dict) else {}
        row = {
            "http": "POST", "path": self.path, "rpc": method,
            "tool": params.get("name", "") if method == "tools/call" else "",
            "offered": params.get("protocolVersion", "") if method == "initialize" else "",
            "error_code": str(err.get("code", "")) if err else "",
            "id": "" if rid is None else str(rid),
        }
        row.update(self._hdrs())
        record(row)

        # A server→client REQUEST we sent gets answered by the control plane on
        # this same endpoint: that inbound message is a RESPONSE (no method, an
        # id, an error). Ack it and stop — it is not a request for us to serve.
        if not method and rid is not None:
            return self._json(202, {"ok": True})

        # Credential check FIRST — a rejected credential never reaches a method.
        if row["auth"] not in ACCEPT:
            return self._json(401, {"jsonrpc": "2.0", "id": rid,
                                    "error": {"code": -32001, "message": "unauthorized"}})
        if self.path != "/mcp":
            return self._json(404, {"message": "not found"})

        c = ctl()
        if method == "initialize":
            sid = "%s-sess-%d" % (c.get("session_prefix", "fbx"), nxt())
            return self._json(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": c.get("proto", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-hq", "version": "1.0.0"}}},
                headers={"Mcp-Session-Id": sid})
        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        if method == "tools/list":
            return self._json(200, {"jsonrpc": "2.0", "id": rid,
                                    "result": {"tools": TOOLS}})
        if method == "tools/call":
            return self._tools_call(c, req, rid)
        return self._json(200, {"jsonrpc": "2.0", "id": rid,
                                "error": {"code": -32601, "message": "method not found"}})

    def _tools_call(self, c, req, rid):
        mode = c.get("tools_call", "ok")
        name = (req.get("params") or {}).get("name", "")
        good = {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": "hq result — %s ok" % name}],
            "isError": False}}
        if mode == "http_500":
            return self._raw(500, "upstream exploded", "text/plain")
        if mode == "rpc_error":
            return self._json(200, {"jsonrpc": "2.0", "id": rid,
                                    "error": {"code": -32000, "message": "boom"}})
        if mode == "is_error":
            return self._json(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": "tool said no"}], "isError": True}})
        if mode == "insufficient_scope":
            # SEP-835: a scope challenge the client can never satisfy by
            # re-minting the SAME grant. Terminal for the call.
            return self._json(401, {"error": "forbidden"}, headers={
                "WWW-Authenticate":
                    'Bearer error="insufficient_scope", scope="hq:write hq:admin"'})
        if mode == "expire_once":
            ep = str(c.get("epoch", 0))
            fresh = False
            with LOCK:
                if ep not in STATE["expired_epochs"]:
                    STATE["expired_epochs"].add(ep)
                    fresh = True
            if fresh:
                # 404 on a request that CARRIED a session id ⇒ the client must
                # re-initialize ONCE and replay.
                return self._json(404, {"error": "session not found"})
            return self._json(200, good)
        if mode == "hang":
            time.sleep(int(c.get("hang_secs", 45)))
            return self._json(200, good)
        if mode == "sse":
            return self._sse(["event: message",
                              "data: " + json.dumps(good), ""])
        if mode == "sse_multiline":
            # ONE logical event whose `data:` payload is split across lines; the
            # assembler must join the lines with "\n" before parsing. The split
            # point MUST be a structural boundary (between JSON tokens) — an
            # arbitrary index could land inside a string literal, where the
            # injected newline is a raw control character and the JSON would be
            # invalid for reasons that have nothing to do with the assembler.
            head = '{"jsonrpc": "2.0", "id": %s,' % json.dumps(rid)
            tail = '"result": %s}' % json.dumps(good["result"])
            return self._sse(["event: message",
                              "data: " + head,
                              "data: " + tail, ""])
        if mode == "sse_server_request":
            # A server→client JSON-RPC REQUEST interleaved before our response.
            srv = {"jsonrpc": "2.0", "id": "srv-%d" % nxt(), "method": "roots/list"}
            return self._sse([": a comment line",
                              "event: message",
                              "data: " + json.dumps(srv), "",
                              "event: message",
                              "data: " + json.dumps(good), ""])
        return self._json(200, good)

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Mcp).serve_forever()
PYEOF

# ── The redirecting fake ──────────────────────────────────────────────────────
# `/mcp` answers 302 with a Location on ANOTHER host; `/followed` answers 200.
# Every request is recorded, so "the client refused the 3xx and did NOT follow"
# is provable two ways: this recorder holds EXACTLY one request, and the primary
# MCP fake's recorder holds ZERO `/followed` requests.
cat > "$FAKES/fake_redirect.py" <<'PYEOF'
import http.server, json, os, sys, threading

PORT, LOG, LOCATION = int(sys.argv[1]), sys.argv[2], sys.argv[3]
LOCK = threading.Lock()


def record(row):
    with LOCK:
        with open(LOG, "a") as f:
            f.write(json.dumps(row) + "\n")
            f.flush()
            os.fsync(f.fileno())


class Redir(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self, verb):
        n = int(self.headers.get("content-length") or 0)
        if n:
            self.rfile.read(n)
        record({"http": verb, "path": self.path,
                "auth": self.headers.get("authorization", "")})
        if self.path.startswith("/followed"):
            body = b'{"followed":true}'
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(302)
        self.send_header("Location", LOCATION)
        self.send_header("content-length", "0")
        self.end_headers()

    def do_POST(self):
        self._handle("POST")

    def do_GET(self):
        self._handle("GET")

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Redir).serve_forever()
PYEOF

# ── The recorder query helper ────────────────────────────────────────────────
# One python file so every assertion reads the SAME jsonl the same way. All ops
# take a START index so a section can scope itself to its own window (the
# recorder is append-only and shared across sections).
#   len                              → total rows
#   count      [k=v …]               → rows[START:] matching every k=v
#   first F    [k=v …]               → the first matching row's F ("" if none)
#   distinct F [k=v …]               → space-joined sorted distinct non-empty F
#   all_have F [k=v …]               → "NONE" | "BAD <row-index>" | "OK <n>"
# `k=` (empty value) means "field must be the empty string", which is how the
# initialize request's ABSENT MCP-Protocol-Version header is asserted.
cat > "$FAKES/rec.py" <<'PYEOF'
import json, sys

log, start, op = sys.argv[1], int(sys.argv[2]), sys.argv[3]
rest = sys.argv[4:]

rows = []
try:
    with open(log) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
except FileNotFoundError:
    pass

if op == "len":
    print(len(rows))
    sys.exit(0)

field = ""
if op in ("first", "distinct", "all_have"):
    field, rest = rest[0], rest[1:]
filters = []
for spec in rest:
    k, _, v = spec.partition("=")
    filters.append((k, v))


def match(r):
    return all(str(r.get(k, "")) == v for k, v in filters)


sel = [(i, r) for i, r in enumerate(rows) if i >= start and match(r)]

if op == "count":
    print(len(sel))
elif op == "first":
    print(sel[0][1].get(field, "") if sel else "")
elif op == "distinct":
    vals = sorted({str(r.get(field, "")) for _, r in sel if str(r.get(field, ""))})
    print(" ".join(vals))
elif op == "all_have":
    if not sel:
        print("NONE")
    else:
        bad = [i for i, r in sel if not str(r.get(field, ""))]
        print("BAD %d" % bad[0] if bad else "OK %d" % len(sel))
else:
    print("UNKNOWN_OP")
    sys.exit(2)
PYEOF

rec()   { python3 "$FAKES/rec.py" "$MCP_LOG"   "$@"; }
rec2()  { python3 "$FAKES/rec.py" "$MCP2_LOG"  "$@"; }
recr()  { python3 "$FAKES/rec.py" "$REDIR_LOG" "$@"; }
# The current end of a recorder — every section snapshots this first so its
# assertions are scoped to its OWN window and can never inherit earlier traffic.
mark()  { rec 0 len; }
mark2() { rec2 0 len; }
markr() { recr 0 len; }

# ── Fake lifecycle ───────────────────────────────────────────────────────────
# The control file must exist BEFORE the first request; both fakes tolerate a
# missing one, but writing it up front keeps the negotiated version explicit.
mcp_mode() { # proto tools_call [epoch]
  printf '{"proto":"%s","tools_call":"%s","epoch":%s,"hang_secs":45}\n' \
    "$1" "$2" "${3:-0}" > "$MCP_CTL"
}
mcp2_mode() { # proto tools_call
  printf '{"proto":"%s","tools_call":"%s","epoch":0}\n' "$1" "$2" > "$MCP2_CTL"
}

start_mcp() {
  mcp_mode "$PROTO_SNAP" ok
  python3 "$FAKES/fake_mcp.py" "$MCP_PORT" "$MCP_LOG" "$MCP_CTL" "$TOK_HQ" &
  MCP_PID=$!
  for _ in $(seq 1 40); do
    # A bare POST (no auth) → 401 proves the listener is up AND enforcing.
    curl -s -o /dev/null -X POST "$MCP_URL" 2>/dev/null && {
      ok "fake MCP up on :$MCP_PORT (bearer-checked, recorder at mcp-requests.jsonl)"; return 0; }
    sleep 0.25
  done
  echo "hardening-e2e: fake MCP did not become ready" >&2; exit 1
}

# The SECOND MCP upstream exists to be KILLED and restarted (section (f)'s
# connect-refused → failed_before_send → re-claim proof). Same image, own port,
# own recorder, own control file.
start_mcp2() { # quiet?
  mcp2_mode "$PROTO_SNAP" ok
  python3 "$FAKES/fake_mcp.py" "$MCP2_PORT" "$MCP2_LOG" "$MCP2_CTL" "$TOK_HQ2" &
  MCP2_PID=$!
  for _ in $(seq 1 40); do
    curl -s -o /dev/null -X POST "$MCP2_URL" 2>/dev/null && {
      [ "${1:-}" = quiet ] || ok "fake MCP #2 up on :$MCP2_PORT (the killable upstream)"
      return 0; }
    sleep 0.25
  done
  echo "hardening-e2e: fake MCP #2 did not become ready" >&2; exit 1
}
stop_mcp2() {
  [ -n "$MCP2_PID" ] && kill "$MCP2_PID" 2>/dev/null
  for _ in $(seq 1 40); do
    curl -s -o /dev/null -m 1 -X POST "$MCP2_URL" 2>/dev/null || { MCP2_PID=""; return 0; }
    sleep 0.25
  done
  MCP2_PID=""
  return 1
}

start_redirect() {
  python3 "$FAKES/fake_redirect.py" "$REDIR_PORT" "$REDIR_LOG" "$FOLLOW_URL" &
  REDIR_PID=$!
  for _ in $(seq 1 40); do
    curl -s -o /dev/null "http://127.0.0.1:$REDIR_PORT/ready" 2>/dev/null && {
      ok "fake redirector up on :$REDIR_PORT (302 → $FOLLOW_URL)"; return 0; }
    sleep 0.25
  done
  echo "hardening-e2e: fake redirector did not become ready" >&2; exit 1
}

# ═════════════════════════════════════════════════════════════════════════════
# Server boot. CI passes FLUIDBOX_SERVER_BIN (a prebuilt binary) so the script
# `exec`s it (clean single-process lifecycle); otherwise `cargo run`.
# ═════════════════════════════════════════════════════════════════════════════
_spawn() {
  : > "$SERVER_LOG"
  (
    cd "$ROOT" || exit 1
    export DATABASE_URL="$DATABASE_URL"
    export FLUIDBOX_BIND="127.0.0.1:$API_PORT"
    # LOAD-BEARING: a loopback-http public URL is the ONLY switch that opens the
    # dev-loopback egress seam (egress.rs `dev_loopback`). Without it every fake
    # in this file becomes an unreachable plain-http non-https target and the
    # whole suite fails at the first dial — while the metadata/private-IP
    # negatives below stay blocked regardless, which is exactly the split the
    # SSRF section asserts.
    export FLUIDBOX_PUBLIC_URL="http://127.0.0.1:$API_PORT"
    export FLUIDBOX_ADMIN_TOKEN="$ADMIN_TOKEN"
    export FLUIDBOX_PROVIDER=docker
    export FLUIDBOX_DATA_DIR="$DATA_DIR"
    # Phase D (#32): run the app pool as the NON-superuser role migration 0018
    # creates, so every HTTP request in this suite executes with RLS actually
    # ENFORCED (CI's DB user is the superuser `postgres`, for whom policies are
    # skipped entirely). Migration 0019's claims table carries the same triple,
    # so section (f) exercises it under the runtime role too.
    export FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime
    # A dead-registry image ref makes provisioning fail in milliseconds (no
    # runner image in CI), so the forged-run fixtures settle terminal fast.
    export FLUIDBOX_SANDBOX_IMAGE=localhost:1/fluidbox-absent:ci
    export FLUIDBOX_CODEX_SANDBOX_IMAGE=localhost:1/fluidbox-absent:ci
    # The file:// clone-base seam section (a) asserts the POSITIVE half of.
    export FLUIDBOX_GITHUB_CLONE_BASE="$CLONE_BASE"
    export FLUIDBOX_CREDENTIAL_KEY="$CRED_KEY"
    export FLUIDBOX_REQUIRE_SSO=0
    # LITELLM_MASTER_KEY placeholder — `shared` mode refuses to boot on an EMPTY
    # key. No facade traffic happens in sections (a)-(f); section (h) (Task 7)
    # points LLM_UPSTREAM_URL at a fake on :$LLM_PORT.
    export FLUIDBOX_LLM_KEY_MODE=shared
    export LITELLM_MASTER_KEY="$MASTER_KEY"
    export LLM_UPSTREAM_URL="http://127.0.0.1:$LLM_PORT"
    export RUST_LOG="${RUST_LOG:-warn,fluidbox_server=info}"
    if [ -n "${FLUIDBOX_SERVER_BIN:-}" ] && [ -x "${FLUIDBOX_SERVER_BIN}" ]; then
      exec "$FLUIDBOX_SERVER_BIN"
    fi
    exec cargo run -q -p fluidbox-server
  ) >>"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
}

boot() {
  _spawn
  for _ in $(seq 1 180); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then SERVER_PID=""; return 1; fi
    curl -sf "$API/v1/health" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# ── HTTP helpers ─────────────────────────────────────────────────────────────
AH="authorization: Bearer $ADMIN_TOKEN"
BODY=""; CODE=""
admin_post() { CODE=$(curl -s -o "$UB" -w '%{http_code}' -X POST -H "$AH" -H 'content-type: application/json' -d "$2" "$API$1"); BODY=$(cat "$UB"); }
admin_get()  { CODE=$(curl -s -o "$UB" -w '%{http_code}' -H "$AH" "$API$1"); BODY=$(cat "$UB"); }
# The in-sandbox internal gate: authenticated by the per-session bearer token.
sess_call() { # sid token-plaintext json → prints the tools/call response body
  curl -s -X POST -H "authorization: Bearer $2" -H 'content-type: application/json' -d "$3" "$API/internal/sessions/$1/tools/call"
}
sess_perm() { # sid token-plaintext json → prints the /permission response body
  curl -s -X POST -H "authorization: Bearer $2" -H 'content-type: application/json' -d "$3" "$API/internal/sessions/$1/permission"
}

# ── The forged-run fixture (proven CI-green in bindings-e2e + secrets-e2e) ────
# A run created here NEVER launches a sandbox (dead-registry image), so the
# orchestrator fails provisioning. We wait for the run to SETTLE — terminal AND
# its finalization intent cleared, the race-free quiescent point where no
# background worker writes the row again — then FORCE it to 'running' as a
# documented test fixture so the internal gate accepts work. started_at and
# last_heartbeat_at stay NULL, so no watchdog / wall-clock sweeper reaps it.
# Finally psql-forge a session token exactly how the orchestrator mints one
# (kind 'session', token_sha256 = sha256(plaintext)); the plaintext is never
# echoed. NOTE for Task 5: `api_tokens.audience` defaults to 'all', which every
# audience-guarded route accepts — this forger keeps working unchanged.
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
  db "update sessions set status='running', status_reason='hardening-e2e fixture (run never launched)' where id='$sid'" >/dev/null
  sha=$(printf '%s' "$tok" | openssl dgst -sha256 | awk '{print $NF}')
  tid=$(db "select tenant_id from sessions where id='$sid'")
  db "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, expires_at)
      values (gen_random_uuid(), '$tid', 'session', '$sid', '$sha', now() + interval '2 hours')" >/dev/null
  return 0
}

# Create a run as the operator; sets RUN to the session id (empty on failure).
# $2 REPLACES the default workspace fragment — `workspace` and the legacy `repo`
# are mutually exclusive (sending both is a 400), so the clone-policy runs pass
# their own `"workspace":{…}` instead of appending to the default.
RUN=""
create_run() { # agent [workspace-or-repo-json-fragment]
  local ws=${2:-'"repo":{"kind":"none"}'}
  admin_post "/v1/sessions" "{\"agent\":\"$1\",\"task\":\"hardening-e2e\",$ws}"
  RUN=$(echo "$BODY" | j "['session']['id']")
}
# Create a run + settle + force running + forge its token in one step. Sets RUN.
live_run() { # agent token-plaintext label
  create_run "$1"
  need "$RUN" "$3 run not created ($CODE: $BODY)" || return 1
  forge_running "$RUN" "$2" "$3" || return 1
  return 0
}

wait_terminal() { # sid [deadline_secs] → prints the terminal status
  local deadline=$(( $(date +%s) + ${2:-300} )) st=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    st=$(db "select status from sessions where id='$1'")
    case "$st" in completed|failed|cancelled|budget_exceeded) echo "$st"; return 0;; esac
    sleep 2
  done
  echo "timeout(last=$st)"; return 1
}

# Poll a run's approvals for the first pending id (operator lens).
pending_approval_id() { # sid → prints approval id (empty until one appears)
  local aid=""
  for _ in $(seq 1 60); do
    admin_get "/v1/sessions/$1/approvals"
    aid=$(echo "$BODY" | python3 -c "
import sys,json
rows=[a for a in json.load(sys.stdin).get('approvals',[]) if a.get('status')=='pending']
print(rows[0]['id'] if rows else '')" 2>/dev/null)
    [ -n "$aid" ] && break
    sleep 0.5
  done
  echo "$aid"
}

# The execution-claim row for one (session, tool_call_id) — migration 0019.
claim_state()   { db "select state   from tool_execution_claims where session_id='$1' and tool_call_id='$2'"; }
claim_attempt() { db "select attempt from tool_execution_claims where session_id='$1' and tool_call_id='$2'"; }
# The ledgered gate `source` for one tool.decision (events.payload is the
# internally-tagged EventBody, so `source` sits at the payload top level).
decision_source() { db "select payload->>'source' from events where session_id='$1' and type='tool.decision' and payload->>'tool_call_id'='$2' order by seq desc limit 1"; }

# ═════════════════════════════════════════════════════════════════════════════
say "BOOT — fake MCP (x2) + redirector + control plane"
start_mcp
start_mcp2
start_redirect
boot || { no "control plane did not become healthy: $(tail -30 "$SERVER_LOG")"; exit 1; }
ok "control plane up (dev-loopback egress seam OPEN via FLUIDBOX_PUBLIC_URL=$API)"

# ── SETUP: policies + catalog + connections + agents ─────────────────────────
say "SETUP — policies, catalog entries, connections (photograph @ $PROTO_SNAP), agents"
mk_policy() { # name yaml-body
  local py; py=$(python3 -c "import json,sys;print(json.dumps(sys.stdin.read()))" <<EOF
$2
EOF
)
  admin_post "/v1/policies" "{\"name\":\"$1\",\"yaml\":$py}"
  [ "$CODE" = 200 ] && ok "policy $1 created" || no "policy $1 → $CODE: $BODY"
}
mk_policy hq-allow 'name: hq-allow
defaults:
  tool_action: deny
autonomy:
  permitted: true
  on_approval_rule: deny
tools:
  - match: ["Read", "Glob", "Grep", "LS"]
    action: allow
  - match: ["mcp__*"]
    action: allow'
mk_policy hq-deny 'name: hq-deny
defaults:
  tool_action: deny
autonomy:
  permitted: true
  on_approval_rule: deny
tools:
  - match: ["Read", "Glob", "Grep", "LS"]
    action: allow
  - match: ["mcp__*"]
    action: deny'
mk_policy hq-approve 'name: hq-approve
defaults:
  tool_action: deny
autonomy:
  permitted: true
  on_approval_rule: deny
tools:
  - match: ["mcp__*"]
    action: approve
    approval_ttl_secs: 120'

admin_post "/v1/catalog" \
  "{\"slug\":\"$SLUG\",\"name\":\"HQ Fake\",\"transport\":\"streamable_http\",\"url\":\"$MCP_URL\",\"auth_mode\":\"api_key\",\"auth_hints\":{\"header_name\":\"authorization\",\"scheme\":\"Bearer\"}}"
[ "$CODE" = 200 ] && ok "catalog entry '$SLUG' added (api_key, tier forced custom)" || no "catalog create → $CODE: $BODY"
admin_post "/v1/catalog/$SLUG/connect" "{\"token\":\"$TOK_HQ\",\"display_name\":\"hq\"}"
[ "$CODE" = 200 ] && ok "connected '$SLUG' (photograph froze the tool surface)" || no "connect → $CODE: $BODY"
CONN=$(echo "$BODY" | j "['connection']['id']")
need "$CONN" "no connection id from the catalog connect ($BODY)" || exit 1
SNAP_PROTO=$(db "select protocol_version from connection_tool_snapshots where connection_id='$CONN'")
[ "$SNAP_PROTO" = "$PROTO_SNAP" ] \
  && ok "snapshot recorded the NEGOTIATED protocol_version '$SNAP_PROTO'" \
  || no "snapshot protocol_version='$SNAP_PROTO' (want $PROTO_SNAP)"

admin_post "/v1/catalog" \
  "{\"slug\":\"$SLUG2\",\"name\":\"HQ Fake 2\",\"transport\":\"streamable_http\",\"url\":\"$MCP2_URL\",\"auth_mode\":\"api_key\",\"auth_hints\":{\"header_name\":\"authorization\",\"scheme\":\"Bearer\"}}"
[ "$CODE" = 200 ] && ok "catalog entry '$SLUG2' added (the killable upstream)" || no "catalog #2 create → $CODE: $BODY"
admin_post "/v1/catalog/$SLUG2/connect" "{\"token\":\"$TOK_HQ2\",\"display_name\":\"hq2\"}"
[ "$CODE" = 200 ] && ok "connected '$SLUG2'" || no "connect #2 → $CODE: $BODY"
CONN2=$(echo "$BODY" | j "['connection']['id']")
need "$CONN2" "no connection id for the killable upstream ($BODY)" || exit 1

mk_agent() { # name policy connector-url slug
  admin_post "/v1/agents" \
    "{\"name\":\"$1\",\"policy\":\"$2\",\"connection_requirements\":[{\"slot\":\"hq\",\"connector\":{\"url\":\"$3\",\"slug\":\"$4\"},\"required_tools\":[\"hq_search\"],\"binding_mode\":\"organization\"}]}"
  [ "$CODE" = 200 ] && ok "agent '$1' created (slot hq → $4)" || no "agent $1 → $CODE: $BODY"
}
mk_agent hq-agent      hq-allow   "$MCP_URL"  "$SLUG"
mk_agent hq-deny-agent hq-deny    "$MCP_URL"  "$SLUG"
mk_agent hq-appr-agent hq-approve "$MCP_URL"  "$SLUG"
mk_agent hq2-agent     hq-allow   "$MCP2_URL" "$SLUG2"
# A connection-free agent for the clone-policy runs (no brokered surface needed).
admin_post "/v1/agents" "{\"name\":\"plain-agent\",\"policy\":\"hq-allow\"}"
[ "$CODE" = 200 ] && ok "agent 'plain-agent' created (no connection requirement)" || no "plain-agent → $CODE: $BODY"

# ═════════════════════════════════════════════════════════════════════════════
# (a) SSRF / egress: admission, dial, redirect refusal, clone-URL policy.
#     Acceptance bullet: "SSRF-hardened outbound clients; private/metadata/
#     redirect targets refused at admission AND at dial."
# ═════════════════════════════════════════════════════════════════════════════
say "(a) SSRF/egress — admission (connections, callbacks), dial (broker), redirects, clone URLs"

# (a.1) Connection admission. connections.rs:224 wraps egress::admit_url's message
# as "base_url rejected: <reason>"; the private/metadata reason string is
# egress.rs:130 "refusing an egress target at a private/loopback/link-local
# address"; the plain-http reason is egress.rs:121.
admin_post "/v1/connections" \
  "{\"provider\":\"mcp_http\",\"display_name\":\"meta\",\"base_url\":\"$META_URL\",\"token\":\"x\"}"
{ [ "$CODE" = 400 ] && echo "$BODY" | grep -q "base_url rejected" \
    && echo "$BODY" | grep -q "private/loopback/link-local"; } \
  && ok "connection with a cloud-metadata base_url → 400 'base_url rejected: …private/loopback/link-local…'" \
  || no "metadata base_url admission → $CODE: $BODY"
admin_post "/v1/connections" \
  "{\"provider\":\"mcp_http\",\"display_name\":\"priv\",\"base_url\":\"$PRIV_MCP\",\"token\":\"x\"}"
{ [ "$CODE" = 400 ] && echo "$BODY" | grep -q "private/loopback/link-local"; } \
  && ok "connection with an https private-IP base_url → 400 (host-literal block)" \
  || no "private-IP base_url admission → $CODE: $BODY"
admin_post "/v1/connections" \
  "{\"provider\":\"mcp_http\",\"display_name\":\"privhttp\",\"base_url\":\"$PRIV_HTTP_MCP\",\"token\":\"x\"}"
{ [ "$CODE" = 400 ] && echo "$BODY" | grep -q "plain-http egress target"; } \
  && ok "connection with a NON-loopback plain-http base_url → 400 'refusing a plain-http egress target' (E3)" \
  || no "plain-http base_url admission → $CODE: $BODY"
# POSITIVE CONTROL: the loopback fake's http URL IS admitted under the dev seam —
# without this the three refusals above could all be "everything is rejected".
admin_post "/v1/connections" \
  "{\"provider\":\"mcp_http\",\"display_name\":\"loopback-ok\",\"base_url\":\"$MCP_URL\",\"token\":\"$TOK_HQ\"}"
[ "$CODE" = 200 ] \
  && ok "POSITIVE CONTROL: the loopback plain-http fake IS admitted (dev seam open)" \
  || no "loopback base_url was refused → $CODE: $BODY (the dev seam is closed — every later section will fail)"
# …and retire it immediately: an organization binding resolves a requirement by
# (url, slug), so a SECOND active connection at $MCP_URL would make every later
# section's binding AMBIGUOUS. Revoke through the API, then force the row (the
# API may 409 depending on state) — this control connection must never be
# resolvable again.
CTRL_CONN=$(echo "$BODY" | j "['connection']['id']")
if [ -n "$CTRL_CONN" ]; then
  admin_post "/v1/connections/$CTRL_CONN/revoke" '{}'
  db "update integration_connections set status='revoked', updated_at=now() where id='$CTRL_CONN'" >/dev/null
  [ "$(db "select status from integration_connections where id='$CTRL_CONN'")" = revoked ] \
    && ok "the control connection was revoked (binding resolution stays unambiguous)" \
    || no "the control connection is still resolvable — later bindings will be ambiguous"
fi

# (a.2) Trigger callback admission (triggers.rs:570 — "callback_url rejected: …").
admin_post "/v1/triggers" \
  "{\"agent\":\"plain-agent\",\"name\":\"sub-meta-$$\",\"task_template\":\"noop\",\"callback_url\":\"$META_URL\"}"
{ [ "$CODE" = 400 ] && echo "$BODY" | grep -q "callback_url rejected" \
    && echo "$BODY" | grep -q "private/loopback/link-local"; } \
  && ok "trigger subscription with a metadata callback_url → 400 'callback_url rejected: …'" \
  || no "metadata callback_url admission → $CODE: $BODY"
admin_post "/v1/triggers" \
  "{\"agent\":\"plain-agent\",\"name\":\"sub-priv-$$\",\"task_template\":\"noop\",\"callback_url\":\"$PRIV_MCP\"}"
{ [ "$CODE" = 400 ] && echo "$BODY" | grep -q "callback_url rejected"; } \
  && ok "trigger subscription with a private-IP callback_url → 400" \
  || no "private callback_url admission → $CODE: $BODY"

# (a.3) DIAL-time refusal. `POST /v1/mcp/probe` goes straight into the broker's
# dial funnel (catalog.rs probe → broker::probe_tools → discover_tools →
# ensure_initialized → dial_rpc), whose FIRST statement is
# `egress::admit_url(...)` (broker.rs:624) mapping to CallErr::NeverSent — i.e.
# the refusal happens before any bytes leave. The probe surfaces it verbatim in
# `notes` with reachable=false.
admin_post "/v1/mcp/probe" "{\"url\":\"$META_URL\"}"
{ [ "$CODE" = 200 ] && [ "$(echo "$BODY" | j "['reachable']")" = "False" ] \
    && echo "$BODY" | grep -q "private/loopback/link-local"; } \
  && ok "broker DIAL of a metadata URL → reachable=false, refused before the socket opens" \
  || no "metadata dial → $CODE: $BODY"
admin_post "/v1/mcp/probe" "{\"url\":\"$PRIV_MCP\"}"
{ [ "$CODE" = 200 ] && [ "$(echo "$BODY" | j "['reachable']")" = "False" ] \
    && echo "$BODY" | grep -q "private/loopback/link-local"; } \
  && ok "broker DIAL of a private-IP URL → reachable=false, refused before the socket opens" \
  || no "private dial → $CODE: $BODY"
# POSITIVE CONTROL for the dial path: the live fake IS reachable (it answers 401
# to a credential-free probe, which is still `reachable: true`).
admin_post "/v1/mcp/probe" "{\"url\":\"$MCP_URL\"}"
{ [ "$CODE" = 200 ] && [ "$(echo "$BODY" | j "['reachable']")" = "True" ]; } \
  && ok "POSITIVE CONTROL: the live loopback fake probes reachable=true" \
  || no "live fake probe → $CODE: $BODY"

# (a.4) A 3xx is REFUSED, never followed (build_egress_http uses
# redirect::Policy::none(); dial_rpc's `status.is_redirection()` arm returns
# CallErr::Ambiguous("upstream attempted redirect (refused)") — broker.rs:656-662).
R_MARK=$(markr); F_MARK=$(mark)
admin_post "/v1/mcp/probe" "{\"url\":\"$REDIR_URL\"}"
{ [ "$CODE" = 200 ] && [ "$(echo "$BODY" | j "['reachable']")" = "False" ] \
    && echo "$BODY" | grep -q "upstream attempted redirect (refused)"; } \
  && ok "a redirecting upstream → reachable=false, 'upstream attempted redirect (refused)'" \
  || no "redirect refusal → $CODE: $BODY"
REDIR_HITS=$(recr "$R_MARK" count)
if gt0 "$REDIR_HITS" "the redirector's recorder in this window"; then
  [ "$REDIR_HITS" = 1 ] \
    && ok "the redirector recorded EXACTLY ONE request (the client did not retry it)" \
    || no "redirector recorded $REDIR_HITS requests in the window (want exactly 1)"
fi
FOLLOWED=$(rec "$F_MARK" count path=/followed)
[ "$FOLLOWED" = 0 ] \
  && ok "the redirect TARGET was never contacted (0 requests at $FOLLOW_URL)" \
  || no "the 3xx WAS followed — $FOLLOWED request(s) reached $FOLLOW_URL"

# (a.5) Clone-URL policy (fluidbox-workspace `validate_clone_url`, reached during
# the `initializing` state — before any sandbox launch, so the dead-registry
# image never masks it). The refusal text lands in sessions.status_reason via
# orchestrator::fail.
say "(a) clone-URL policy — private host refused, bad scheme refused, clone-base accepted"
git -C "$CLONE_ROOT" init -q -b main fixture 2>/dev/null || git init -q -b main "$CLONE_ROOT/fixture"
FX="$CLONE_ROOT/fixture"
git -C "$FX" config user.email hardening@fluidbox.dev
git -C "$FX" config user.name fbx-e2e
echo "hello" > "$FX/README.md"
git -C "$FX" add -A
git -C "$FX" commit -qm c1
FX_SHA=$(git -C "$FX" rev-parse HEAD)
need "$FX_SHA" "git fixture repo has no commit" && ok "file:// fixture repo ready under the configured clone base"

create_run plain-agent "\"workspace\":{\"kind\":\"git_repository\",\"clone_url\":\"$PRIV_CLONE\"}"
CL_PRIV="$RUN"
if need "$CL_PRIV" "private-clone run not created ($CODE: $BODY)"; then
  ST=$(wait_terminal "$CL_PRIV" 300)
  SR=$(db "select coalesce(status_reason,'') from sessions where id='$CL_PRIV'")
  { [ "$ST" = failed ] && echo "$SR" | grep -q "refusing a clone URL"; } \
    && ok "https clone URL at a private address → failed during initializing ('refusing a clone URL…')" \
    || no "private clone: status='$ST' reason='$SR'"
fi
create_run plain-agent "\"workspace\":{\"kind\":\"git_repository\",\"clone_url\":\"ssh://git@example.com/x.git\"}"
CL_SSH="$RUN"
if [ -n "$CL_SSH" ]; then
  ST=$(wait_terminal "$CL_SSH" 300)
  SR=$(db "select coalesce(status_reason,'') from sessions where id='$CL_SSH'")
  { [ "$ST" = failed ] && echo "$SR" | grep -q "clone_url must be http(s):// or file://"; } \
    && ok "an ssh:// clone URL → failed with the scheme-allowlist message" \
    || no "ssh clone: status='$ST' reason='$SR'"
else
  # A 400 at admission is an equally valid enforcement point — record it as such
  # rather than silently passing.
  { [ "$CODE" = 400 ] && ok "an ssh:// clone URL → 400 at admission ($BODY)"; } \
    || no "ssh clone was neither created nor rejected → $CODE: $BODY"
fi
create_run plain-agent "\"workspace\":{\"kind\":\"git_repository\",\"clone_url\":\"file://$FX\"}"
CL_OK="$RUN"
if need "$CL_OK" "clone-base run not created ($CODE: $BODY)"; then
  wait_terminal "$CL_OK" 300 >/dev/null
  BC=$(db "select coalesce(base_commit,'') from sessions where id='$CL_OK'")
  SR=$(db "select coalesce(status_reason,'') from sessions where id='$CL_OK'")
  [ "$BC" = "$FX_SHA" ] \
    && ok "a file:// clone UNDER the configured clone base is accepted (base_commit == fixture HEAD)" \
    || no "clone-base file:// was not materialized (base_commit='$BC', want $FX_SHA; reason='$SR')"
fi
# NOT ASSERTED — "a file:// URL OUTSIDE the clone base is refused". Under
# `dev_loopback` (which this whole suite requires, see FLUIDBOX_PUBLIC_URL above)
# `validate_clone_url` allows EVERY file:// URL by design: the clone-base prefix
# is only consulted when the dev seam is closed. An assertion here could not
# fail, so it is deliberately absent. Making it fail-capable needs a SECOND boot
# with a non-loopback https FLUIDBOX_PUBLIC_URL — which simultaneously makes
# every loopback fake in this file unreachable, so it belongs in its own boot
# (a follow-up section), not here. The unit tests in
# crates/fluidbox-workspace/src/lib.rs cover the closed-seam matrix directly.

# ═════════════════════════════════════════════════════════════════════════════
# (b) A DENIED brokered call never contacts the upstream.
#     Acceptance bullet: "a denied tool call never reaches the upstream server."
#     Shape guard: the ZERO assertion is meaningless without proof the recorder
#     WOULD have recorded — so the positive control runs in this same section,
#     against the same fake, in the same recorder window.
# ═════════════════════════════════════════════════════════════════════════════
say "(b) A denied brokered call performs ZERO upstream traffic (with a positive control)"
mcp_mode "$PROTO_SNAP" ok
if live_run hq-deny-agent "sess-b-deny-$$" "b/deny"; then
  B_DENY="$RUN"
  B_MARK=$(mark)
  R=$(sess_call "$B_DENY" "sess-b-deny-$$" '{"tool_call_id":"b1","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  echo "$R" | grep -q '"denied": *true' \
    && ok "policy-denied brokered call → denied:true" \
    || no "expected a policy denial, got: $R"
  [ "$(decision_source "$B_DENY" b1)" = policy ] \
    && ok "the denial is ledgered as tool.decision source='policy'" \
    || no "tool.decision source='$(decision_source "$B_DENY" b1)' (want policy)"
  B_TRAFFIC=$(rec "$B_MARK" count)
  [ "$B_TRAFFIC" = 0 ] \
    && ok "the fake MCP recorded ZERO requests for the denied call" \
    || no "a denied call produced $B_TRAFFIC upstream request(s)"
fi
# POSITIVE CONTROL, same fake + same window semantics: an ALLOWED call DOES
# record. Without this, a fake that had silently died would make the ZERO above
# pass vacuously.
if live_run hq-agent "sess-b-allow-$$" "b/allow"; then
  B_ALLOW="$RUN"
  B_MARK2=$(mark)
  R=$(sess_call "$B_ALLOW" "sess-b-allow-$$" '{"tool_call_id":"b2","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  echo "$R" | grep -q '"ok": *true' \
    && ok "POSITIVE CONTROL: the allowed call executed (ok:true)" \
    || no "positive control failed: $R"
  B_CALLS=$(rec "$B_MARK2" count rpc=tools/call)
  [ "$B_CALLS" = 1 ] \
    && ok "POSITIVE CONTROL: the fake recorded exactly 1 tools/call — the recorder works" \
    || no "positive control recorded $B_CALLS tools/call (want 1 — the ZERO assertion above is only meaningful if this is 1)"
fi
# Trust-tier denial (the other "denied" flavor) is likewise silent upstream. The
# frozen RunSpec's trust_tier is what the gate reads, so the fixture flips BOTH
# the column and the frozen copy — the same fixture section (e) reuses.
if live_run hq-agent "sess-b-ro-$$" "b/readonly"; then
  B_RO="$RUN"
  db "update sessions set trust_tier='read_only', run_spec = jsonb_set(run_spec,'{trust_tier}','\"read_only\"') where id='$B_RO'" >/dev/null
  B_MARK3=$(mark)
  R=$(sess_call "$B_RO" "sess-b-ro-$$" '{"tool_call_id":"b3","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  { echo "$R" | grep -q '"denied": *true' && echo "$R" | grep -q "read-only trust tier"; } \
    && ok "trust-tier (ReadOnly) denial of a brokered call → denied:true" \
    || no "expected a trust-tier denial, got: $R"
  [ "$(decision_source "$B_RO" b3)" = trust_tier ] \
    && ok "the denial is ledgered as tool.decision source='trust_tier'" \
    || no "tool.decision source='$(decision_source "$B_RO" b3)' (want trust_tier)"
  B_RO_TRAFFIC=$(rec "$B_MARK3" count)
  [ "$B_RO_TRAFFIC" = 0 ] \
    && ok "the trust-tier-denied call produced ZERO upstream requests" \
    || no "a trust-tier-denied call produced $B_RO_TRAFFIC upstream request(s)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# (c) Per-run MCP session isolation + authentication on every request.
#     Acceptance bullet: "each run gets its own upstream MCP session; every
#     brokered request is authenticated."
#     Mechanism: the registry key is (run session id, McpPeer::Binding(binding
#     id)) — broker.rs session_entry/McpPeer — so two runs of ONE agent against
#     ONE connection are two distinct upstream sessions.
# ═════════════════════════════════════════════════════════════════════════════
say "(c) Session isolation — two runs, two distinct upstream sessions; auth on every request"
mcp_mode "$PROTO_SNAP" ok
C_OK=1
live_run hq-agent "sess-c1-$$" "c/run-1" || C_OK=0
C_RUN1="$RUN"
C_MARK1=$(mark)
[ "$C_OK" = 1 ] && sess_call "$C_RUN1" "sess-c1-$$" '{"tool_call_id":"c1","tool":"mcp__hq__hq_search","input":{"query":"one"}}' > "$WORK/c1.json"
live_run hq-agent "sess-c2-$$" "c/run-2" || C_OK=0
C_RUN2="$RUN"
C_MARK2=$(mark)
[ "$C_OK" = 1 ] && sess_call "$C_RUN2" "sess-c2-$$" '{"tool_call_id":"c2","tool":"mcp__hq__hq_search","input":{"query":"two"}}' > "$WORK/c2.json"

if [ "$C_OK" = 1 ]; then
  grep -q '"ok": *true' "$WORK/c1.json" && grep -q '"ok": *true' "$WORK/c2.json" \
    && ok "both runs executed their brokered call" \
    || no "a run's brokered call failed: $(cat "$WORK/c1.json" "$WORK/c2.json")"
  # Run 2's window is open-ended (it is the last traffic in this section), but
  # run 1's must be CLOSED at run 2's start — `rec … distinct` only takes a
  # lower bound, so run 1 gets an explicit [start, end) slice. Without it run 1's
  # "distinct sessions" would also contain run 2's and the inequality below
  # could never fail.
  S2=$(rec "$C_MARK2" distinct session rpc=tools/call)
  S1_ONLY=$(python3 - "$MCP_LOG" "$C_MARK1" "$C_MARK2" <<'PYEOF'
import json, sys
log, a, b = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rows = [json.loads(l) for l in open(log) if l.strip()]
vals = sorted({r.get("session", "") for i, r in enumerate(rows)
               if a <= i < b and r.get("rpc") == "tools/call" and r.get("session")})
print(" ".join(vals))
PYEOF
)
  if need "$S1_ONLY" "run 1 sent no tools/call carrying an mcp-session-id" \
     && need "$S2" "run 2 sent no tools/call carrying an mcp-session-id"; then
    N1=$(printf '%s\n' "$S1_ONLY" | wc -w | tr -d ' ')
    N2=$(printf '%s\n' "$S2" | wc -w | tr -d ' ')
    { [ "$N1" = 1 ] && [ "$N2" = 1 ] && [ "$S1_ONLY" != "$S2" ]; } \
      && ok "the two runs used DISTINCT upstream mcp-session-ids ('$S1_ONLY' vs '$S2'), never reusing one" \
      || no "session isolation broken (run1=[$S1_ONLY] n=$N1, run2=[$S2] n=$N2)"
  fi
  # Every POST in BOTH windows carried an Authorization header. Scoped to POSTs
  # deliberately: the terminal session DELETE (broker.rs cleanup_run_sessions)
  # sends mcp-session-id + mcp-protocol-version and NO credential, so a blanket
  # "every request" assertion would encode that as required behavior. The
  # "OK n"/"NONE" shape carries its own >0 precondition.
  AUTHED=$(rec "$C_MARK1" all_have auth http=POST)
  case "$AUTHED" in
    OK\ *) ok "every recorded POST in the isolation window carried Authorization ($AUTHED)";;
    NONE)  no "no POSTs recorded in the isolation window — the auth assertion would be vacuous";;
    *)     no "a POST reached the upstream WITHOUT Authorization ($AUTHED)";;
  esac
  # …and it was the connection's sealed credential, not something from the input.
  BEARERS=$(rec "$C_MARK1" distinct auth http=POST)
  [ "$BEARERS" = "Bearer $TOK_HQ" ] \
    && ok "every POST presented exactly the connection's sealed credential" \
    || no "unexpected credential(s) on the wire: [$BEARERS]"
fi

# ═════════════════════════════════════════════════════════════════════════════
# (d) 2025-11-25 conformance.
#     Acceptance bullet: "the broker meets the 2025-11-25 Streamable-HTTP
#     contract: initialize-first, version negotiation, protocol header, session
#     lifecycle, SSE, and SEP-835 scope challenges."
# ═════════════════════════════════════════════════════════════════════════════
say "(d) 2025-11-25 conformance — initialize-first, offered version, headers, notifications"
mcp_mode "$PROTO_SNAP" ok
if live_run hq-agent "sess-d1-$$" "d/handshake"; then
  D_RUN="$RUN"
  D_MARK=$(mark)
  R=$(sess_call "$D_RUN" "sess-d1-$$" '{"tool_call_id":"d1","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  echo "$R" | grep -q '"ok": *true' && ok "handshake run executed its call" || no "handshake call: $R"
  D_TOTAL=$(rec "$D_MARK" count)
  if gt0 "$D_TOTAL" "the handshake window"; then
    # initialize is the FIRST JSON-RPC method this run ever sends — never a
    # tools/* probe (broker.rs ensure_initialized; stateless-first is gone).
    [ "$(rec "$D_MARK" first rpc http=POST)" = initialize ] \
      && ok "the first JSON-RPC method of the run is 'initialize' (never tools/*)" \
      || no "first method was '$(rec "$D_MARK" first rpc http=POST)' (want initialize)"
    # The OFFERED version is broker.rs OFFERED_PROTOCOL = "2025-11-25".
    [ "$(rec "$D_MARK" first offered rpc=initialize)" = "2025-11-25" ] \
      && ok "the client OFFERED protocolVersion '2025-11-25'" \
      || no "offered version was '$(rec "$D_MARK" first offered rpc=initialize)' (want 2025-11-25)"
    NOTES=$(rec "$D_MARK" count rpc=notifications/initialized)
    [ "$NOTES" = 1 ] \
      && ok "'notifications/initialized' was sent exactly once after initialize (unconditional)" \
      || no "notifications/initialized count = $NOTES (want 1)"
    # MCP-Protocol-Version on EVERY post-initialize request…
    PH=$(rec "$D_MARK" all_have proto_hdr rpc=tools/call)
    case "$PH" in
      OK\ *) ok "every tools/call carried MCP-Protocol-Version ($PH)";;
      NONE)  no "no tools/call recorded — the protocol-header assertion would be vacuous";;
      *)     no "a tools/call went out WITHOUT MCP-Protocol-Version ($PH)";;
    esac
    PHN=$(rec "$D_MARK" all_have proto_hdr rpc=notifications/initialized)
    case "$PHN" in
      OK\ *) ok "notifications/initialized carried MCP-Protocol-Version too ($PHN)";;
      *)     no "notifications/initialized lacked MCP-Protocol-Version ($PHN)";;
    esac
    # …and NOT on initialize itself (nothing is negotiated yet — session_headers
    # only sets it once `sess.negotiated` is non-empty).
    INIT_NOHDR=$(rec "$D_MARK" count rpc=initialize proto_hdr=)
    INIT_N=$(rec "$D_MARK" count rpc=initialize)
    if gt0 "$INIT_N" "initialize requests in the handshake window"; then
      [ "$INIT_NOHDR" = "$INIT_N" ] \
        && ok "initialize itself carried NO MCP-Protocol-Version (nothing negotiated yet)" \
        || no "initialize carried a protocol header ($INIT_NOHDR of $INIT_N were header-free)"
    fi
    PV=$(rec "$D_MARK" distinct proto_hdr rpc=tools/call)
    [ "$PV" = "$PROTO_SNAP" ] \
      && ok "the header value is the NEGOTIATED version '$PROTO_SNAP', not the offered one" \
      || no "MCP-Protocol-Version was [$PV] (want $PROTO_SNAP)"
  fi
fi

say "(d) Version negotiation — unsupported version refused, snapshot drift denied"
# UNSUPPORTED SET (snapshot absent). check_negotiated falls back to
# SUPPORTED_PROTOCOLS membership only when the frozen surface carries NO
# protocol_version — which is exactly a RunSpec frozen before Phase E. The
# fixture reproduces that by DELETING the key from the frozen jsonb, so the
# assertion exercises the legacy-surface arm (broker.rs:907-911).
mcp_mode "2024-11-05" ok
if live_run hq-agent "sess-d2-$$" "d/unsupported"; then
  D_UNS="$RUN"
  db "update sessions set run_spec = run_spec #- '{brokered,0,protocol_version}' where id='$D_UNS'" >/dev/null
  LEFT=$(db "select count(*) from sessions where id='$D_UNS' and run_spec->'brokered'->0 ? 'protocol_version'")
  [ "$LEFT" = 0 ] \
    && ok "fixture: the frozen surface's protocol_version was removed (a pre-Phase-E RunSpec)" \
    || no "fixture failed — protocol_version is still on the frozen surface"
  D_MARK=$(mark)
  R=$(sess_call "$D_UNS" "sess-d2-$$" '{"tool_call_id":"d2","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  { echo "$R" | grep -q "negotiated unsupported protocol version" \
      && echo "$R" | grep -q "2024-11-05"; } \
    && ok "a server negotiating '2024-11-05' fails the call with the unsupported-version error" \
    || no "unsupported-version refusal wrong: $R"
  D_UNS_CALLS=$(rec "$D_MARK" count rpc=tools/call)
  [ "$D_UNS_CALLS" = 0 ] \
    && ok "the version refusal happened at initialize — ZERO tools/call reached the upstream" \
    || no "$D_UNS_CALLS tools/call escaped despite the version refusal"
fi
# SNAPSHOT DRIFT (snapshot present, server moved). The surface froze
# '2025-06-18'; the server now negotiates '2025-11-25' — a supported version, so
# only the exact-match rule catches it. Deny message: broker.rs:903-906, which
# names the operator remedy POST /v1/connections/{id}/tools/refresh.
mcp_mode "2025-11-25" ok
if live_run hq-agent "sess-d3-$$" "d/drift"; then
  D_DRIFT="$RUN"
  D_MARK=$(mark)
  R=$(sess_call "$D_DRIFT" "sess-d3-$$" '{"tool_call_id":"d3","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  { echo "$R" | grep -q "mcp protocol drift" && echo "$R" | grep -q "tools/refresh"; } \
    && ok "protocol DRIFT (frozen $PROTO_SNAP, now 2025-11-25) is denied and names /tools/refresh" \
    || no "drift denial wrong: $R"
  D_DRIFT_CALLS=$(rec "$D_MARK" count rpc=tools/call)
  [ "$D_DRIFT_CALLS" = 0 ] \
    && ok "the drift denial happened at initialize — ZERO tools/call reached the upstream" \
    || no "$D_DRIFT_CALLS tools/call escaped despite the drift denial"
  # The drift verdict is an answer FROM the upstream initialize, so the claim
  # settles Definitive → failed_upstream (internal.rs dispatch_to_completion).
  [ "$(claim_state "$D_DRIFT" d3)" = failed_upstream ] \
    && ok "the drift dispatch settled the execution claim at 'failed_upstream'" \
    || no "drift claim state = '$(claim_state "$D_DRIFT" d3)' (want failed_upstream)"
fi
mcp_mode "$PROTO_SNAP" ok

say "(d) Session lifecycle — 404 reinit-once + replay; server→client request → -32601"
# A 404 on a request that CARRIED a session id ⇒ reinit ONCE and replay ONCE
# (broker.rs managed_call). A FRESH run is required so the window contains the
# run's own first initialize: 2 initializes + 2 tools/call (the 404 + the replay).
mcp_mode "$PROTO_SNAP" expire_once 1
if live_run hq-agent "sess-d4-$$" "d/404"; then
  D_404="$RUN"
  D_MARK=$(mark)
  R=$(sess_call "$D_404" "sess-d4-$$" '{"tool_call_id":"d4","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  echo "$R" | grep -q '"ok": *true' \
    && ok "a 404-with-session was recovered — the replayed call succeeded" \
    || no "404 recovery failed: $R"
  D_INITS=$(rec "$D_MARK" count rpc=initialize)
  D_CALLS=$(rec "$D_MARK" count rpc=tools/call)
  if gt0 "$D_INITS" "initializes in the 404 window"; then
    { [ "$D_INITS" = 2 ] && [ "$D_CALLS" = 2 ]; } \
      && ok "exactly TWO initializes and ONE replay (tools/call x2) — never more" \
      || no "404 reinit shape wrong (initialize=$D_INITS tools/call=$D_CALLS; want 2 and 2)"
  fi
fi
# A server→client JSON-RPC REQUEST arriving in the SSE stream must be answered
# `-32601` (broker.rs reply_method_not_found), not silently dropped. The fake
# records the inbound response POST's error code.
mcp_mode "$PROTO_SNAP" sse_server_request
if live_run hq-agent "sess-d5-$$" "d/serverreq"; then
  D_SRQ="$RUN"
  D_MARK=$(mark)
  R=$(sess_call "$D_SRQ" "sess-d5-$$" '{"tool_call_id":"d5","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  echo "$R" | grep -q '"ok": *true' \
    && ok "an SSE response carrying an interleaved server→client request still resolved the call" \
    || no "sse_server_request call: $R"
  MNF=$(rec "$D_MARK" count error_code=-32601)
  [ "$MNF" = 1 ] \
    && ok "the fake recorded exactly ONE '-32601' response POST (the unsupported server request was answered)" \
    || no "-32601 replies recorded = $MNF (want exactly 1)"
fi
# A multi-line `data:` event must be joined with newlines before parsing
# (mcp_sse.rs SseEventAssembler). Split JSON is the only reason this can fail.
mcp_mode "$PROTO_SNAP" sse_multiline
if live_run hq-agent "sess-d6-$$" "d/sse"; then
  D_SSE="$RUN"
  D_MARK=$(mark)
  R=$(sess_call "$D_SSE" "sess-d6-$$" '{"tool_call_id":"d6","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  { echo "$R" | grep -q '"ok": *true' && echo "$R" | grep -q "hq result"; } \
    && ok "a multi-line SSE 'data:' event parsed correctly (the result reached the runner)" \
    || no "multi-line SSE parse: $R"
  SSE_CALLS=$(rec "$D_MARK" count rpc=tools/call)
  [ "$SSE_CALLS" = 1 ] \
    && ok "the multi-line SSE call was a single upstream request" \
    || no "multi-line SSE produced $SSE_CALLS tools/call (want 1)"
fi
mcp_mode "$PROTO_SNAP" ok

say "(d) Terminal DELETE — a finished run tears its upstream session down"
# broker.rs run_terminal_mcp_cleanup is hooked into the orchestrator's terminal
# reconcile (orchestrator.rs:852). Cancelling a run with a live upstream session
# must produce a DELETE carrying that session's id.
if live_run hq-agent "sess-d7-$$" "d/delete"; then
  D_DEL="$RUN"
  D_MARK=$(mark)
  R=$(sess_call "$D_DEL" "sess-d7-$$" '{"tool_call_id":"d7","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  echo "$R" | grep -q '"ok": *true' && ok "the to-be-cancelled run opened an upstream session" || no "delete-run call: $R"
  UPSTREAM_SID=$(rec "$D_MARK" first session rpc=tools/call)
  admin_post "/v1/sessions/$D_DEL/cancel" '{}'
  DEL_SEEN=0
  for _ in $(seq 1 90); do
    [ "$(rec "$D_MARK" count http=DELETE)" -gt 0 ] && { DEL_SEEN=1; break; }
    sleep 1
  done
  if need "$UPSTREAM_SID" "no upstream mcp-session-id was ever issued to this run"; then
    { [ "$DEL_SEEN" = 1 ] \
        && [ "$(rec "$D_MARK" count http=DELETE session="$UPSTREAM_SID")" -ge 1 ]; } \
      && ok "run terminal → the fake recorded a DELETE for the run's upstream session ($UPSTREAM_SID)" \
      || no "no DELETE recorded for the terminated run's upstream session (seen=$DEL_SEEN)"
  fi
fi

say "(d) SEP-835 — an insufficient_scope challenge is TERMINAL and marks the connection"
# The piece Task 2 deliberately deferred to this suite. broker.rs auth_error →
# CallErr::InsufficientScope → mark_insufficient_scope (broker.rs:1185-1209),
# which writes integration_connections.status='error' + the oauth.error note
# "insufficient_scope: reconnect with more scopes (server asked for: …)". There
# must be NO re-mint retry — exactly ONE tools/call on the wire.
mcp_mode "$PROTO_SNAP" insufficient_scope
if live_run hq-agent "sess-d8-$$" "d/scope"; then
  D_SCOPE="$RUN"
  D_MARK=$(mark)
  R=$(sess_call "$D_SCOPE" "sess-d8-$$" '{"tool_call_id":"d8","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  echo "$R" | grep -q "insufficient scope" \
    && ok "the scope challenge surfaced as 'insufficient scope — reconnect the connection with more scopes'" \
    || no "insufficient_scope response wrong: $R"
  SCOPE_CALLS=$(rec "$D_MARK" count rpc=tools/call)
  [ "$SCOPE_CALLS" = 1 ] \
    && ok "exactly ONE tools/call reached the upstream — no re-mint retry after a scope challenge" \
    || no "tools/call count = $SCOPE_CALLS (want exactly 1; >1 means a forbidden retry)"
  CSTAT=$(db "select status from integration_connections where id='$CONN'")
  CNOTE=$(db "select coalesce(oauth->>'error','') from integration_connections where id='$CONN'")
  [ "$CSTAT" = error ] \
    && ok "the connection landed status='error' (create_run/photograph/broker now fail closed off it)" \
    || no "connection status='$CSTAT' after the scope challenge (want error)"
  { echo "$CNOTE" | grep -q "insufficient_scope: reconnect with more scopes" \
      && echo "$CNOTE" | grep -q "hq:write"; } \
    && ok "the reconnect note records the challenge scope verbatim-but-sanitized ('$CNOTE')" \
    || no "connection note = '$CNOTE' (want the insufficient_scope reconnect note naming the scope)"
  # A NEW run against the errored connection must be refused at creation.
  admin_post "/v1/sessions" "{\"agent\":\"hq-agent\",\"task\":\"t\",\"repo\":{\"kind\":\"none\"}}"
  [ "$CODE" != 200 ] \
    && ok "a new run bound to the errored connection → $CODE (fail closed off status)" \
    || no "a new run against the errored connection was created: $BODY"
  # Restore the connection so the remaining sections can bind it. This is a
  # documented fixture, not a product path (reconnect is the product path).
  db "update integration_connections set status='active', oauth = coalesce(oauth,'{}'::jsonb) - 'error', updated_at=now() where id='$CONN'" >/dev/null
  [ "$(db "select status from integration_connections where id='$CONN'")" = active ] \
    && ok "fixture: the connection was restored to active for the remaining sections" \
    || no "fixture restore failed — sections (e)/(f) will fail at binding"
fi
mcp_mode "$PROTO_SNAP" ok

# ═════════════════════════════════════════════════════════════════════════════
# (e) Frozen-schema argument enforcement.
#     Acceptance bullet: "tool arguments are validated server-side against the
#     frozen inputSchema before dispatch."
#     The gate order is LOAD-BEARING: budget → frozen-set availability →
#     [schema] → trust tier → policy → approvals (internal.rs:356-388).
# ═════════════════════════════════════════════════════════════════════════════
say "(e) Schema enforcement — bad args denied source='schema', zero dispatch; good args pass"
mcp_mode "$PROTO_SNAP" ok
if live_run hq-agent "sess-e-$$" "e/schema"; then
  E_RUN="$RUN"
  # (e.1) A missing REQUIRED property.
  E_MARK=$(mark)
  R=$(sess_call "$E_RUN" "sess-e-$$" '{"tool_call_id":"e1","tool":"mcp__hq__hq_search","input":{}}')
  { echo "$R" | grep -q '"denied": *true' \
      && echo "$R" | grep -q "arguments rejected by frozen schema"; } \
    && ok "args missing a required property → denied 'arguments rejected by frozen schema: …'" \
    || no "missing-required denial wrong: $R"
  [ "$(decision_source "$E_RUN" e1)" = schema ] \
    && ok "the rejection is ledgered as tool.decision source='schema'" \
    || no "tool.decision source='$(decision_source "$E_RUN" e1)' (want schema)"
  E1_CALLS=$(rec "$E_MARK" count rpc=tools/call)
  [ "$E1_CALLS" = 0 ] \
    && ok "the schema-rejected call produced ZERO tools/call upstream" \
    || no "$E1_CALLS tools/call escaped a schema rejection"
  # The bounded message names JSON-pointer PATHS, never argument VALUES.
  E1_REASON=$(db "select coalesce(payload->>'reason','') from events where session_id='$E_RUN' and type='tool.decision' and payload->>'tool_call_id'='e1'")
  [ "${#E1_REASON}" -le 600 ] \
    && ok "the ledgered schema reason is bounded (${#E1_REASON} bytes)" \
    || no "schema reason is unbounded (${#E1_REASON} bytes)"

  # (e.2) A wrong-typed property.
  E_MARK=$(mark)
  R=$(sess_call "$E_RUN" "sess-e-$$" '{"tool_call_id":"e2","tool":"mcp__hq__hq_count","input":{"n":"not-a-number"}}')
  { echo "$R" | grep -q '"denied": *true' \
      && echo "$R" | grep -q "arguments rejected by frozen schema"; } \
    && ok "a wrong-typed argument → denied by the frozen schema" \
    || no "type-violation denial wrong: $R"
  E2_CALLS=$(rec "$E_MARK" count rpc=tools/call)
  [ "$E2_CALLS" = 0 ] \
    && ok "the type-violating call produced ZERO tools/call upstream" \
    || no "$E2_CALLS tools/call escaped a type violation"

  # (e.3) POSITIVE CONTROL: valid arguments pass the same gate and DO dispatch.
  E_MARK=$(mark)
  R=$(sess_call "$E_RUN" "sess-e-$$" '{"tool_call_id":"e3","tool":"mcp__hq__hq_count","input":{"n":7}}')
  echo "$R" | grep -q '"ok": *true' \
    && ok "POSITIVE CONTROL: schema-valid arguments pass and execute" \
    || no "valid arguments were rejected: $R"
  E3_CALLS=$(rec "$E_MARK" count rpc=tools/call)
  [ "$E3_CALLS" = 1 ] \
    && ok "POSITIVE CONTROL: the valid call produced exactly 1 tools/call — the ZEROs above are meaningful" \
    || no "valid call produced $E3_CALLS tools/call (want 1)"

  # (e.4) A BUILT-IN (non-mcp) tool is untouched by schema enforcement — it
  # carries no frozen inputSchema, so schema_gate_decision returns None.
  R=$(sess_perm "$E_RUN" "sess-e-$$" '{"tool_call_id":"e4","tool":"Read","input":{"file_path":"/workspace/x"}}')
  echo "$R" | grep -q '"decision": *"allow"' \
    && ok "a built-in tool (Read) is unaffected by schema enforcement (allowed)" \
    || no "built-in tool decision: $R"
  [ "$(decision_source "$E_RUN" e4)" = policy ] \
    && ok "the built-in's decision came from the POLICY stage, not the schema stage" \
    || no "built-in tool.decision source='$(decision_source "$E_RUN" e4)' (want policy)"
fi

say "(e) Gate ORDER proof — a ReadOnly run with bad args records the SCHEMA denial, not trust_tier"
# The unit tests cannot show this: it needs a run whose trust tier WOULD deny the
# same tool. Because schema runs BEFORE trust tier (internal.rs:356-388 sits
# above the ReadOnly block at :400), the ledgered source must be 'schema'.
# Section (b) already proved the SAME tier + tool + run shape with GOOD args
# records 'trust_tier' — so the two together isolate the ordering.
if live_run hq-agent "sess-e-ro-$$" "e/order"; then
  E_RO="$RUN"
  db "update sessions set trust_tier='read_only', run_spec = jsonb_set(run_spec,'{trust_tier}','\"read_only\"') where id='$E_RO'" >/dev/null
  [ "$(db "select run_spec->>'trust_tier' from sessions where id='$E_RO'")" = read_only ] \
    && ok "fixture: the frozen RunSpec's trust_tier is read_only" \
    || no "fixture failed — the frozen trust_tier is not read_only"
  E_MARK=$(mark)
  R=$(sess_call "$E_RO" "sess-e-ro-$$" '{"tool_call_id":"e5","tool":"mcp__hq__hq_search","input":{}}')
  echo "$R" | grep -q "arguments rejected by frozen schema" \
    && ok "ReadOnly + bad args → the SCHEMA message, not the read-only one" \
    || no "order proof: expected the schema message, got: $R"
  SRC=$(decision_source "$E_RO" e5)
  [ "$SRC" = schema ] \
    && ok "ORDER PROVEN: tool.decision source='schema' (schema runs BEFORE the trust-tier floor)" \
    || no "ORDER BROKEN: tool.decision source='$SRC' (want schema; 'trust_tier' means the insertion moved)"
  E5_CALLS=$(rec "$E_MARK" count rpc=tools/call)
  [ "$E5_CALLS" = 0 ] && ok "the order-proof call reached the upstream ZERO times" \
    || no "$E5_CALLS tools/call escaped the order-proof denial"
fi

# ═════════════════════════════════════════════════════════════════════════════
# (f) Durable four-state execution claims (migration 0019).
#     Acceptance bullet: "one upstream dispatch per intent; ambiguous outcomes
#     are never silently retried; a cancelled run never dispatches."
# ═════════════════════════════════════════════════════════════════════════════
say "(f) Execution claims — duplicate intent dispatches ONCE and both callers adopt one result"
mcp_mode "$PROTO_SNAP" ok
if live_run hq-agent "sess-f1-$$" "f/duplicate"; then
  F_DUP="$RUN"
  # Warm the upstream session first, so the two concurrent requests race on the
  # CLAIM (the thing under test) and not on the handshake.
  sess_call "$F_DUP" "sess-f1-$$" '{"tool_call_id":"f0","tool":"mcp__hq__hq_search","input":{"query":"warm"}}' >/dev/null
  F_MARK=$(mark)
  ( sess_call "$F_DUP" "sess-f1-$$" '{"tool_call_id":"f1","tool":"mcp__hq__hq_search","input":{"query":"dup"}}' > "$WORK/f1a" 2>/dev/null ) & P1=$!
  ( sess_call "$F_DUP" "sess-f1-$$" '{"tool_call_id":"f1","tool":"mcp__hq__hq_search","input":{"query":"dup"}}' > "$WORK/f1b" 2>/dev/null ) & P2=$!
  wait "$P1"; wait "$P2"
  F1_CALLS=$(rec "$F_MARK" count rpc=tools/call)
  F1_TOTAL=$(rec "$F_MARK" count)
  if gt0 "$F1_TOTAL" "the duplicate-intent window"; then
    [ "$F1_CALLS" = 1 ] \
      && ok "two concurrent /tools/call for ONE intent produced EXACTLY ONE upstream tools/call" \
      || no "duplicate intent produced $F1_CALLS upstream tools/call (want exactly 1)"
  fi
  { grep -q '"ok": *true' "$WORK/f1a" && grep -q '"ok": *true' "$WORK/f1b"; } \
    && ok "BOTH callers got a successful result (the loser ADOPTED the winner's outcome)" \
    || no "a duplicate caller did not succeed: $(cat "$WORK/f1a" "$WORK/f1b")"
  [ "$(cat "$WORK/f1a")" = "$(cat "$WORK/f1b")" ] \
    && ok "the two responses are byte-identical (the duplicate-return contract)" \
    || no "duplicate responses differ:\n$(cat "$WORK/f1a")\n$(cat "$WORK/f1b")"
  [ "$(claim_state "$F_DUP" f1)" = succeeded ] \
    && ok "the claim row settled at 'succeeded'" \
    || no "claim state = '$(claim_state "$F_DUP" f1)' (want succeeded)"
  CLAIM_ROWS=$(db "select count(*) from tool_execution_claims where session_id='$F_DUP' and tool_call_id='f1'")
  [ "$CLAIM_ROWS" = 1 ] \
    && ok "exactly ONE claim row exists for the duplicated intent (the unique key held)" \
    || no "claim rows for one intent = $CLAIM_ROWS (want 1)"
fi

say "(f) A definitive upstream error settles 'failed_upstream' — never 'ambiguous'"
mcp_mode "$PROTO_SNAP" http_500
if live_run hq-agent "sess-f2-$$" "f/500"; then
  F_500="$RUN"
  F_MARK=$(mark)
  R=$(sess_call "$F_500" "sess-f2-$$" '{"tool_call_id":"f2","tool":"mcp__hq__hq_search","input":{"query":"boom"}}')
  F2_CALLS=$(rec "$F_MARK" count rpc=tools/call)
  if gt0 "$F2_CALLS" "tools/call in the 500 window"; then
    ok "the 500-returning upstream was actually contacted ($F2_CALLS tools/call)"
  fi
  ST=$(claim_state "$F_500" f2)
  { [ "$ST" = failed_upstream ] && [ "$ST" != ambiguous ]; } \
    && ok "an HTTP 500 settled the claim at 'failed_upstream' (a definitive answer, not ambiguity)" \
    || no "claim state after a 500 = '$ST' (want failed_upstream; 'ambiguous' is the bug this asserts against)"
  echo "$R" | grep -qi "500" \
    && ok "the runner-facing error names the upstream status" \
    || no "500 response did not surface the status: $R"
fi
# A JSON-RPC error object is likewise DEFINITIVE.
mcp_mode "$PROTO_SNAP" rpc_error
if live_run hq-agent "sess-f2b-$$" "f/rpcerr"; then
  F_RPC="$RUN"
  F_MARK=$(mark)
  sess_call "$F_RPC" "sess-f2b-$$" '{"tool_call_id":"f2b","tool":"mcp__hq__hq_search","input":{"query":"boom"}}' >/dev/null
  F2B_CALLS=$(rec "$F_MARK" count rpc=tools/call)
  if gt0 "$F2B_CALLS" "tools/call in the JSON-RPC-error window"; then
    [ "$(claim_state "$F_RPC" f2b)" = failed_upstream ] \
      && ok "a JSON-RPC error object also settles 'failed_upstream'" \
      || no "claim state after a JSON-RPC error = '$(claim_state "$F_RPC" f2b)' (want failed_upstream)"
  fi
fi
mcp_mode "$PROTO_SNAP" ok

say "(f) A connect-refused destination settles 'failed_before_send' and IS re-claimable"
# The second fake exists exactly for this: kill it, and the dial fails at the
# CONNECT phase (reqwest `is_connect()` — broker.rs:644-646) which is POSITIVE
# proof no bytes were written ⇒ DispatchOutcome::NeverSent ⇒ 'failed_before_send',
# the ONLY re-claimable state. Restart it and the SAME intent re-dispatches.
if live_run hq2-agent "sess-f3-$$" "f/connect"; then
  F_CONN="$RUN"
  stop_mcp2 && ok "the second upstream was stopped (its port now refuses connections)" \
            || no "the second upstream did not stop — the connect-refused assertion cannot be trusted"
  R=$(sess_call "$F_CONN" "sess-f3-$$" '{"tool_call_id":"f3","tool":"mcp__hq__hq_search","input":{"query":"gone"}}')
  ST=$(claim_state "$F_CONN" f3)
  [ "$ST" = failed_before_send ] \
    && ok "a refused connection settled the claim at 'failed_before_send' (provably never sent)" \
    || no "claim state after a refused connect = '$ST' (want failed_before_send)"
  echo "$R" | grep -q '"ok": *false' \
    && ok "the runner got a retryable error for the never-sent dispatch" \
    || no "never-sent response was not an error: $R"
  # Now bring it back and RETRY the identical intent: only failed_before_send is
  # re-claimable, so this must produce a real upstream request and settle.
  start_mcp2 quiet
  F_MARK2=$(mark2)
  R=$(sess_call "$F_CONN" "sess-f3-$$" '{"tool_call_id":"f3","tool":"mcp__hq__hq_search","input":{"query":"gone"}}')
  F3_CALLS=$(rec2 "$F_MARK2" count rpc=tools/call)
  [ "$F3_CALLS" = 1 ] \
    && ok "the retry WAS re-dispatched — the restarted upstream recorded exactly 1 tools/call" \
    || no "retry produced $F3_CALLS upstream tools/call (want 1 — failed_before_send must be re-claimable)"
  echo "$R" | grep -q '"ok": *true' \
    && ok "the re-claimed dispatch succeeded" \
    || no "re-claimed dispatch: $R"
  [ "$(claim_state "$F_CONN" f3)" = succeeded ] \
    && ok "the SAME claim row now reads 'succeeded'" \
    || no "claim state after re-claim = '$(claim_state "$F_CONN" f3)' (want succeeded)"
  [ "$(claim_attempt "$F_CONN" f3)" = 2 ] \
    && ok "attempt was bumped to 2 (the re-claim reused the row, never inserted a second)" \
    || no "claim attempt = '$(claim_attempt "$F_CONN" f3)' (want 2)"
fi

say "(f) An 'ambiguous' claim is NEVER re-dispatched"
# Invariant 15. Forcing the state directly is the sanctioned fixture (the plan
# offers "flip claim_expires_at into the past and let the sweeper run, or write
# the state directly"); writing it removes all timing dependence. The intent's
# verdict row stays 'auto_allowed', so the GATE allows the retry and the refusal
# can only come from the claim — which is precisely what is under test.
if live_run hq-agent "sess-f4-$$" "f/ambiguous"; then
  F_AMB="$RUN"
  R=$(sess_call "$F_AMB" "sess-f4-$$" '{"tool_call_id":"f4","tool":"mcp__hq__hq_search","input":{"query":"amb"}}')
  echo "$R" | grep -q '"ok": *true' && ok "the ambiguity fixture's first call succeeded normally" || no "f4 first call: $R"
  db "update tool_execution_claims set state='ambiguous', result_content=null, error_message='hardening-e2e fixture' where session_id='$F_AMB' and tool_call_id='f4'" >/dev/null
  [ "$(claim_state "$F_AMB" f4)" = ambiguous ] \
    && ok "fixture: the claim row was forced to 'ambiguous'" \
    || no "fixture failed — claim state is '$(claim_state "$F_AMB" f4)'"
  F_MARK=$(mark)
  R=$(sess_call "$F_AMB" "sess-f4-$$" '{"tool_call_id":"f4","tool":"mcp__hq__hq_search","input":{"query":"amb"}}')
  echo "$R" | grep -q "outcome ambiguous — not retried" \
    && ok "a repeat of an ambiguous intent is REFUSED ('brokered call outcome ambiguous — not retried')" \
    || no "ambiguous repeat response: $R"
  F4_CALLS=$(rec "$F_MARK" count rpc=tools/call)
  [ "$F4_CALLS" = 0 ] \
    && ok "the ambiguous repeat reached the upstream ZERO times (never re-dispatched)" \
    || no "$F4_CALLS tools/call escaped an ambiguous claim"
  [ "$(claim_state "$F_AMB" f4)" = ambiguous ] \
    && ok "the claim row is still 'ambiguous' (the refusal did not mutate it)" \
    || no "claim state changed to '$(claim_state "$F_AMB" f4)' after the refusal"
fi

say "(f) Cancel DURING an approval wait — approving afterwards dispatches NOTHING"
# The other half of Gap 11: the approval said "allow" minutes ago, but the run is
# gone. Two fences exist and either is a pass — the post-wait terminality recheck
# in decide_tool_call (internal.rs:676 "session terminal during approval wait")
# and the claim's in-transaction non-terminal condition (internal.rs:1045
# "session is terminal"). The ZERO-dispatch assertion is the load-bearing one and
# is asserted separately so a message-shape change cannot mask it.
if live_run hq-appr-agent "sess-f5-$$" "f/cancel"; then
  F_CAN="$RUN"
  F_MARK=$(mark)
  ( sess_call "$F_CAN" "sess-f5-$$" '{"tool_call_id":"f5","tool":"mcp__hq__hq_search","input":{"query":"pending"}}' > "$WORK/f5" 2>/dev/null ) & P3=$!
  AID=$(pending_approval_id "$F_CAN")
  if need "$AID" "no approval became pending (the approve-policy agent did not pause)"; then
    admin_post "/v1/sessions/$F_CAN/cancel" '{}'
    { [ "$CODE" = 200 ] || [ "$CODE" = 202 ] || [ "$CODE" = 409 ]; } \
      && ok "the run was cancelled while the brokered call sat in the approval wait ($CODE)" \
      || no "cancel → $CODE: $BODY"
    # Bounded well inside the policy's 120 s approval TTL: if this poll ran long
    # enough for the waiter to time out, the verdict would be a timeout-deny and
    # the cancel-during-wait path would never be exercised at all.
    for _ in $(seq 1 40); do
      case "$(db "select status from sessions where id='$F_CAN'")" in
        cancelled|failed|completed|budget_exceeded) break;;
      esac
      sleep 1
    done
    admin_post "/v1/approvals/$AID/decision" '{"decision":"approved_once"}'
    [ "$CODE" = 200 ] && ok "the pending approval was APPROVED after the cancel" \
      || no "approve-after-cancel → $CODE: $BODY (the waiter now falls back to its 120s TTL)"
  fi
  wait "$P3"
  R=$(cat "$WORK/f5")
  F5_CALLS=$(rec "$F_MARK" count rpc=tools/call)
  [ "$F5_CALLS" = 0 ] \
    && ok "ZERO tools/call reached the upstream for the approved-but-cancelled intent" \
    || no "$F5_CALLS tools/call dispatched for a cancelled run (the Gap-11 bug)"
  echo "$R" | grep -qE "session terminal during approval wait|session is terminal|session is not active" \
    && ok "the response names the terminal session as the reason" \
    || no "cancel-during-approval response: $R"
  CST=$(claim_state "$F_CAN" f5)
  [ -z "$CST" ] \
    && ok "no execution claim was ever taken for the cancelled intent" \
    || no "a claim row exists in state '$CST' for a cancelled run's intent"
fi

# ═════════════════════════════════════════════════════════════════════════════
# LATER TASKS APPEND BELOW. Each placeholder owns its acceptance bullet; the
# harness above (fakes, recorders, boot, forgers, psql helpers) is shared —
# extend it rather than duplicating. Nothing about unshipped behavior is
# asserted here: an empty section is honest, a guessed one is not.
# ═════════════════════════════════════════════════════════════════════════════

# SECTION (g) audience negatives — Task 5 (audience-scoped sandbox credentials,
# migration 0020). Append here: psql-forge one `api_tokens` row per audience
# (`llm`/`tool`/`control`/`workspace`) for a live run, then assert per-route
# 403s (control token on /permission, llm on /result, tool on the facade,
# workspace ONLY on /workspace) and that a legacy `audience='all'` row still
# passes everywhere. `forge_running` above already writes an audience-defaulted
# row, which is the legacy case.

# SECTION (h) reservations — Task 7 (durable request-keyed LLM budget
# reservations, migration 0022). Append here: start a fake LiteLLM on
# :$LLM_PORT (LLM_UPSTREAM_URL already points there), give a run a budget for
# fewer than N requests, fire N in parallel through the facade, and assert that
# exactly the budget's worth pass and that recorded usage + conservative
# sweeper conversions never exceed budget + one reservation.

# SECTION (i) two-replica — Task 6 (approval single-emission, lease/epoch
# fencing, delivery claims). Append here: boot a SECOND server against the SAME
# DB on :$API_PORT_B (the `_spawn` helper needs a port parameter for that), then
# assert exactly ONE `approval.decided` event per decision, one POST per
# delivery at a signed-webhook sink, and that a stale-epoch mutation is refused.

# SECTION (j) breaker/rate — Task 8 (outbound rate limits + per-connection
# circuit breakers). Append here: use the fake's `http_500` / `hang` control
# modes to drive consecutive transport failures until the breaker opens (the
# refusal is a pre-write proof ⇒ claim state `failed_before_send`), then prove
# the half-open probe closes it. Timing-sensitive: prefer counting the fake's
# recorder over sleeping on wall-clock windows.

# ── Result ───────────────────────────────────────────────────────────────────
say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
