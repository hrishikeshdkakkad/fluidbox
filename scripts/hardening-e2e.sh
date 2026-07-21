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
#   (g) per-route audience negatives (the route→audience mapping)     [Task 5]
#   (h) LLM reservations     — Task 7  (placeholder at the end)
#   (i) two-replica          — Task 6  (placeholder at the end)
#   (j) outbound rate limits + per-connection circuit breakers        [Task 8]
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

# Per-boot egress-governor overrides, consumed by `_spawn`. EMPTY ⇒ leave the
# server's own defaults (governor.rs DEFAULT_*). The governor is IN-MEMORY and
# PER-REPLICA and its limits are resolved once at boot
# (`GovernorLimits::from_config`) — there is deliberately no runtime knob — so
# section (j) sets these and RESTARTS rather than mutating a live process.
GOV_TENANT=""; GOV_CONN=""; GOV_HOST=""; GOV_THRESHOLD=""; GOV_OPEN_SECS=""

_spawn() {
  printf '\n===== control plane (re)start =====\n' >> "$SERVER_LOG"
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
    # Section (j)'s governor knobs. Unset here on the FIRST boot, so sections
    # (a)-(g) run against the shipped defaults (tenant 120 / connection 60 /
    # host 120 per minute, breaker 5 → 60 s) and cannot be throttled by them.
    [ -n "$GOV_TENANT" ]    && export FLUIDBOX_EGRESS_RATE_TENANT_PER_MIN="$GOV_TENANT"
    [ -n "$GOV_CONN" ]      && export FLUIDBOX_EGRESS_RATE_CONNECTION_PER_MIN="$GOV_CONN"
    [ -n "$GOV_HOST" ]      && export FLUIDBOX_EGRESS_RATE_HOST_PER_MIN="$GOV_HOST"
    [ -n "$GOV_THRESHOLD" ] && export FLUIDBOX_EGRESS_BREAKER_THRESHOLD="$GOV_THRESHOLD"
    [ -n "$GOV_OPEN_SECS" ] && export FLUIDBOX_EGRESS_BREAKER_OPEN_SECS="$GOV_OPEN_SECS"
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

# Stop the control plane and boot it again on the SAME port + DB, picking up any
# GOV_* knobs set since. Used ONLY by section (j) (the governor's limits are
# boot-resolved). Safe for the fixtures already in the DB: the forged runs carry
# NULL started_at/last_heartbeat_at (no watchdog or wall-clock sweeper touches
# them) and never provisioned a sandbox (so the boot orphan sweep, which walks the
# PROVIDER's live sandboxes, sees nothing of theirs) — and section (j) forges its
# own runs after the restart regardless.
restart_server() { # label → 0 if the new process is healthy
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  SERVER_PID=""
  # Wait for the LISTENER to go away, not just the pid: under `cargo run` the pid
  # is cargo and the kill may not reach the server, in which case the rebind would
  # fail. CI sets FLUIDBOX_SERVER_BIN (the subshell `exec`s the binary, so the
  # signal lands on the server itself). A port that never frees is a LOUD failure,
  # never a silent skip.
  for _ in $(seq 1 60); do
    curl -sf "$API/v1/health" >/dev/null 2>&1 || break
    sleep 0.5
  done
  if curl -sf "$API/v1/health" >/dev/null 2>&1; then
    no "$1: the previous control plane still holds :$API_PORT (set FLUIDBOX_SERVER_BIN so the kill reaches the server, not cargo)"
    return 1
  fi
  boot || { no "$1: the control plane did not come back up: $(tail -30 "$SERVER_LOG")"; return 1; }
  ok "$1"
  return 0
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
# echoed. `api_tokens.audience` is left to its migration-0020 DEFAULT 'all',
# which every audience-guarded route accepts (in-flight compat) — so this forger
# keeps working unchanged AND doubles as section (g)'s LEGACY token.
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

# ── Audience-scoped token forgers (section (g), migration 0020) ──────────────
# The FOUR scoped audiences. `all` is deliberately NOT in this list: it is the
# column DEFAULT the forger above already produces, and section (g) treats it as
# the legacy in-flight case rather than as one of the scoped audiences.
AUDIENCES="llm tool control workspace"
# The exact 403 body the guards emit (auth.rs `require_audience` /
# internal.rs::result / facade.rs → `ApiError::Forbidden("wrong_audience")`,
# rendered by error.rs as `Json(json!({"error": msg}))`). Asserted VERBATIM, not
# by status: images/runner-lib/contract.mjs keys its fatal abort off this exact
# BODY code (`parsed.error === "wrong_audience"`), so a body-shape change would
# silently restore the "every tool call looks like a deny" bug.
WRONG_AUD='{"error":"wrong_audience"}'

# Forge ONE session token with an EXPLICIT audience — the same row shape the
# orchestrator mints (kind 'session', token_sha256 = sha256(plaintext)) plus the
# 0020 column. `revoked` (any non-empty value) stamps revoked_at, which only
# `/result`'s idempotent terminal ack still resolves.
forge_audience_token() { # sid audience token-plaintext [revoked]
  local sid=$1 aud=$2 tok=$3 rev=${4:-} sha tid rcol="null"
  [ -n "$rev" ] && rcol="now()"
  sha=$(printf '%s' "$tok" | openssl dgst -sha256 | awk '{print $NF}')
  tid=$(db "select tenant_id from sessions where id='$sid'")
  need "$tid" "no tenant for session $sid — cannot forge the '$aud' token" || return 1
  db "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, audience, expires_at, revoked_at)
      values (gen_random_uuid(), '$tid', 'session', '$sid', '$sha', '$aud', now() + interval '2 hours', $rcol)" >/dev/null
  [ "$(db "select audience from api_tokens where token_sha256='$sha'")" = "$aud" ]
}
# One token per scoped audience for a run, named "<prefix>-<audience>". The
# run's own `live_run` token is "<prefix>-all" — the legacy row — so a single
# prefix names the whole five-token set.
forge_audience_set() { # sid prefix
  local sid=$1 pfx=$2 a rc=0
  for a in $AUDIENCES; do
    forge_audience_token "$sid" "$a" "$pfx-$a" || rc=1
  done
  [ "$rc" = 0 ] \
    && ok "forged one api_tokens row per audience for '$pfx' (llm/tool/control/workspace) + the legacy 'all' from live_run" \
    || no "audience token forge failed for '$pfx' — every assertion using it would be meaningless"
  return $rc
}

# One internal-plane request as a given token. Sets CODE + BODY like admin_*.
aud_curl() { # method path token [json-body]
  local m=$1 p=$2 t=$3 b=${4:-}
  [ -n "$b" ] || b='{}'
  if [ "$m" = GET ]; then
    CODE=$(curl -s -o "$UB" -w '%{http_code}' -H "authorization: Bearer $t" "$API$p")
  else
    CODE=$(curl -s -o "$UB" -w '%{http_code}' -X "$m" -H "authorization: Bearer $t" \
      -H 'content-type: application/json' -d "$b" "$API$p")
  fi
  BODY=$(cat "$UB")
}
wrong_aud_body() { case "$1" in *wrong_audience*) return 0;; esac; return 1; }

# Running tally of the init container's blast radius, accumulated BY the matrix
# (never by a second pass — the bodies differ per route, and an invalid body is
# rejected by the Json extractor BEFORE the handler's audience guard, which would
# read as a false "refused"). WS_TRIED is the >0 precondition.
WS_TRIED=0; WS_LEAK=0; WS_OWN_OK=0

# ONE route × EVERY audience. The route's own audience must be ACCEPTED (any
# non-403 that is not a wrong_audience body — the route's own downstream 200/400/
# 404/502 is irrelevant to the mapping), every OTHER scoped audience must be
# refused 403 with the body code VERBATIM, and the legacy 'all' must pass.
# "non-403 = accepted" is precise, not loose: `wrong_audience` is the ONLY
# ApiError::Forbidden anywhere on the internal plane (internal.rs + facade.rs
# carry no other), so a 403 on these routes can mean nothing else.
# Self-checking: a broken forge shows up as 401s on the three negatives, so the
# "accepted" arms can never pass vacuously.
aud_matrix() { # label required-audience token-prefix method path [json-body]
  local label=$1 want=$2 pfx=$3 m=$4 p=$5 b=${6:-} a
  for a in $AUDIENCES all; do
    aud_curl "$m" "$p" "$pfx-$a" "$b"
    if [ "$a" = "$want" ]; then
      { [ "$CODE" != 403 ] && ! wrong_aud_body "$BODY"; } \
        && ok "$label ← '$a' (the route's OWN audience): accepted ($CODE)" \
        || no "$label ← '$a' (the route's OWN audience) was REFUSED → $CODE: $BODY"
      [ "$a" = workspace ] && WS_OWN_OK=1
    elif [ "$a" = all ]; then
      { [ "$CODE" != 403 ] && ! wrong_aud_body "$BODY"; } \
        && ok "$label ← legacy 'all': accepted ($CODE) — in-flight sessions keep working" \
        || no "$label ← legacy 'all' was REFUSED → $CODE: $BODY (breaks every run spanning the deploy)"
    else
      { [ "$CODE" = 403 ] && [ "$BODY" = "$WRONG_AUD" ]; } \
        && ok "$label ← '$a': 403 $WRONG_AUD" \
        || no "$label ← '$a': $CODE '$BODY' (want 403 $WRONG_AUD)"
      if [ "$a" = workspace ]; then
        WS_TRIED=$((WS_TRIED+1))
        [ "$CODE" = 403 ] || WS_LEAK=$((WS_LEAK+1))
      fi
    fi
  done
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

# Terminal AND its finalization intent cleared — the same quiescent point
# `forge_running` waits for, and a STRICTLY STRONGER anchor than wait_terminal:
# `delete_finalization` is the terminal reconcile's LAST step, so once the intent
# is gone everything that reconcile drives (token revoke, delivery enqueue, the
# spawned MCP teardown, reap, workspace/archive cleanup) has been issued.
wait_settled() { # sid [deadline_secs] → prints the terminal status
  local deadline=$(( $(date +%s) + ${2:-300} )) st="" fin=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    st=$(db "select status from sessions where id='$1'")
    fin=$(db "select count(*) from session_finalizations where session_id='$1'")
    case "$st" in
      completed|failed|cancelled|budget_exceeded) [ "$fin" = 0 ] && { echo "$st"; return 0; };;
    esac
    sleep 1
  done
  echo "timeout(last=$st,finalizations=$fin)"; return 1
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
  # only because this window CONTAINS only POSTs (neither isolation run is
  # cancelled here, so no teardown DELETE lands in it) — NOT because the DELETE
  # is credential-free. Since 2dbe42b the terminal session DELETE carries the
  # same re-resolved authorization a live call does, and section (d)'s
  # "Terminal DELETE" blocks assert exactly that. The "OK n"/"NONE" shape carries
  # its own >0 precondition.
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
  CALL_AUTH=$(rec "$D_MARK" first auth rpc=tools/call)
  if need "$UPSTREAM_SID" "no upstream mcp-session-id was ever issued to this run"; then
    { [ "$DEL_SEEN" = 1 ] \
        && [ "$(rec "$D_MARK" count http=DELETE session="$UPSTREAM_SID")" -ge 1 ]; } \
      && ok "run terminal → the fake recorded a DELETE for the run's upstream session ($UPSTREAM_SID)" \
      || no "no DELETE recorded for the terminated run's upstream session (seen=$DEL_SEEN)"
    # 2dbe42b: the teardown DELETE is AUTHORIZED — it carries the same
    # authorization header a live call carries, re-resolved at teardown through
    # `terminal_peer_auth` → recheck_binding → brokered_auth_for_conn (never
    # cached on the registry entry — invariant 9). Before that fix the DELETE went
    # out bare and a conforming upstream 401'd it, leaking the session upstream.
    DEL_AUTH=$(rec "$D_MARK" first auth http=DELETE session="$UPSTREAM_SID")
    if need "$CALL_AUTH" "the run's tools/call recorded no authorization header (nothing to compare the DELETE against)"; then
      [ "$DEL_AUTH" = "$CALL_AUTH" ] \
        && ok "the teardown DELETE carried the SAME authorization as the run's tools/call ('$DEL_AUTH')" \
        || no "teardown DELETE authorization='$DEL_AUTH' but the run's tools/call carried '$CALL_AUTH'"
      [ "$DEL_AUTH" = "Bearer $TOK_HQ" ] \
        && ok "…and it is the connection's sealed credential verbatim, not a stale or empty header" \
        || no "teardown DELETE presented '$DEL_AUTH' (want 'Bearer \$TOK_HQ')"
    fi
  fi
fi

say "(d) Terminal DELETE — a REVOKED connection sends NO credential, and no DELETE at all"
# The fail-closed half of the same fix: at teardown the credential is re-resolved
# LIVE, so a connection revoked between a run's last call and its terminalization
# resolves to nothing and the DELETE is SKIPPED entirely — an unauthorized DELETE
# would just 401, and a revoked connection is precisely where a credential must
# not go. Both halves are asserted (the absence AND that the run still
# terminalized), so an absent DELETE can never be confused with a wedged run.
#
# Everything here runs against the SECOND fake so the primary's recorder windows
# stay untouched, and the ORDER is load-bearing: the positive control (B) runs
# BEFORE the zero (A) is asserted and its DELETE is polled for, so by the time the
# zero is read the terminal-cleanup path has provably completed at least once on
# this replica — the zero cannot be "the DELETE simply has not happened yet".
mcp2_mode "$PROTO_SNAP" ok
D_REV_MARK=""; D_REV_SID=""
if live_run hq2-agent "sess-d9-$$" "d/delete-revoked"; then
  D_REV="$RUN"
  D_REV_MARK=$(mark2)
  R=$(sess_call "$D_REV" "sess-d9-$$" '{"tool_call_id":"d9","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  echo "$R" | grep -q '"ok": *true' \
    && ok "the to-be-revoked run opened an upstream session on the second fake" \
    || no "delete-revoked run's call: $R"
  D_REV_SID=$(rec2 "$D_REV_MARK" first session rpc=tools/call)
  # Revoked by direct status write, not the API: `/revoke` is exercised in (a),
  # and a plain status flip leaves authorization_generation untouched so the
  # restore below returns the connection to EXACTLY its prior state for (f).
  db "update integration_connections set status='revoked', updated_at=now() where id='$CONN2'" >/dev/null
  [ "$(db "select status from integration_connections where id='$CONN2'")" = revoked ] \
    && ok "fixture: the connection was revoked while its run's upstream session was still live" \
    || no "fixture failed — the connection is not revoked, so the skip cannot be attributed"
  admin_post "/v1/sessions/$D_REV/cancel" '{}'
  # `wait_settled`, not `wait_terminal`: the teardown is spawned by the terminal
  # reconcile and the reconcile only clears the finalization intent as its LAST
  # step, so waiting for the QUIESCENT point puts a full reap + workspace/archive
  # cleanup between the teardown's spawn and the restore below. (Honest residual:
  # the teardown is fire-and-forget with no DB trace, so this is an ordering
  # ANCHOR, not a barrier — three local DB reads racing a provider round trip.
  # A hard barrier would need the cleanup to leave an observable mark, which is
  # a product change, not a test change.)
  D_REV_ST=$(wait_settled "$D_REV" 300)
  case "$D_REV_ST" in
    cancelled|failed|completed|budget_exceeded)
      ok "the run still TERMINALIZED ('$D_REV_ST') and its terminal reconcile ran to completion — a skipped DELETE never wedges teardown";;
    *)
      no "the run did not reach a quiescent terminal state after the cancel ($D_REV_ST)";;
  esac
  db "update integration_connections set status='active', oauth = coalesce(oauth,'{}'::jsonb) - 'error', updated_at=now() where id='$CONN2'" >/dev/null
  [ "$(db "select status from integration_connections where id='$CONN2'")" = active ] \
    && ok "fixture: the second connection was restored to active (the control below and section (f) bind it)" \
    || no "fixture restore failed — the positive control and section (f) will fail at binding"
fi
# B) POSITIVE CONTROL on the SAME recorder, same verb: with the connection active,
# the teardown DELETE arrives AND carries the connection's sealed credential.
if live_run hq2-agent "sess-d10-$$" "d/delete-authed"; then
  D_AUTHED="$RUN"
  D_A_MARK=$(mark2)
  R=$(sess_call "$D_AUTHED" "sess-d10-$$" '{"tool_call_id":"d10","tool":"mcp__hq__hq_search","input":{"query":"x"}}')
  echo "$R" | grep -q '"ok": *true' \
    && ok "POSITIVE CONTROL: the control run opened an upstream session" \
    || no "delete-authed run's call: $R"
  D_A_SID=$(rec2 "$D_A_MARK" first session rpc=tools/call)
  D_A_CALL_AUTH=$(rec2 "$D_A_MARK" first auth rpc=tools/call)
  admin_post "/v1/sessions/$D_AUTHED/cancel" '{}'
  D_A_SEEN=0
  for _ in $(seq 1 90); do
    [ "$(rec2 "$D_A_MARK" count http=DELETE)" -gt 0 ] && { D_A_SEEN=1; break; }
    sleep 1
  done
  if need "$D_A_SID" "the control run was issued no upstream mcp-session-id" \
     && need "$D_A_CALL_AUTH" "the control run's tools/call recorded no authorization header"; then
    D_A_DEL_AUTH=$(rec2 "$D_A_MARK" first auth http=DELETE session="$D_A_SID")
    { [ "$D_A_SEEN" = 1 ] && [ "$D_A_DEL_AUTH" = "$D_A_CALL_AUTH" ]; } \
      && ok "POSITIVE CONTROL: the DELETE landed on the second fake carrying the SAME authorization as the run's tools/call ('$D_A_CALL_AUTH')" \
      || no "control DELETE seen=$D_A_SEEN authorization='$D_A_DEL_AUTH' (want '$D_A_CALL_AUTH')"
    [ "$D_A_DEL_AUTH" = "Bearer $TOK_HQ2" ] \
      && ok "…and it is the second connection's sealed credential verbatim" \
      || no "control DELETE presented '$D_A_DEL_AUTH' (want 'Bearer \$TOK_HQ2')"
  fi
fi
# …and only NOW the ZERO, with the recorder demonstrably recording DELETEs.
if [ -n "$D_REV_MARK" ]; then
  if need "$D_REV_SID" "the revoked run never opened an upstream session — the ZERO assertion would be vacuous"; then
    D_REV_DELS=$(rec2 "$D_REV_MARK" count http=DELETE session="$D_REV_SID")
    [ "$D_REV_DELS" = 0 ] \
      && ok "the REVOKED connection's run produced ZERO upstream DELETEs for its session ($D_REV_SID) — fail-closed, no credential leaves for a revoked connection" \
      || no "$D_REV_DELS DELETE(s) went out for a run whose connection was revoked"
  fi
fi
# NOT ASSERTED — "the registry entry was EVICTED". `drain_run_sessions` evicts
# under the map lock before any I/O, but the registry is a per-replica in-memory
# map with no read surface (no admin route, no gauge), so from outside the process
# the only observable would be a second teardown re-DELETEing the same session —
# which the terminal reconcile never re-drives. Making it fail-capable needs an
# introspection seam, not a cleverer curl. What actually matters operationally IS
# asserted: the run terminalizes even when the DELETE is skipped.
#
# NOT ASSERTED — "an OAuth access token that expired mid-run is RE-MINTED for the
# DELETE rather than sent stale". Every connection in this suite is a STATIC
# api_key connection; proving a re-mint needs a fake authorization server (RFC 9728
# PRM + RFC 8414 metadata + a rotating token endpoint), which this file
# deliberately does not carry — connector OAuth has its own coverage. The weaker
# proxy available here (assert only that SOME authorization rides the DELETE)
# would pass just as happily with a stale token, so it is omitted rather than
# faked. The re-resolution PATH is exercised above: `terminal_peer_auth` runs
# recheck_binding → brokered_auth_for_conn, the same resolution a live call makes,
# and that is exactly where an expired OAuth token is re-minted.

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
# SECTIONS (g) AND (j) FOLLOW; (h) AND (i) ARE STILL PLACEHOLDERS — their
# behavior (durable LLM reservations, multi-replica coordination) has not landed,
# and an empty section is honest where a guessed one is not. Each placeholder
# owns its acceptance bullet; the harness above (fakes, recorders, boot, forgers,
# psql helpers) is shared — extend it rather than duplicating. Section (j) runs
# LAST because it REBOOTS the control plane with low egress ceilings.
# ═════════════════════════════════════════════════════════════════════════════

# ═════════════════════════════════════════════════════════════════════════════
# (g) Per-route audience negatives (Gap 10, invariant 19; migration 0020).
#     Acceptance bullet: "a leaked LLM or tool-intent credential can never reach
#     a runner-control route."
#
#     THIS SECTION IS THE SOLE PROOF OF THE ROUTE→AUDIENCE MAPPING, and it is
#     deliberately EXHAUSTIVE rather than a sample. auth.rs says so itself
#     (auth.rs:357-365): the audience constants remove a typo class and nothing
#     more — wiring `events` to `AUD_TOOL` compiles clean and passes every Rust
#     unit test, because `audience_matrix_allow_deny_and_legacy_all` tests the
#     PREDICATE, never the wiring. So every route in the internal Router
#     (main.rs:467-482) appears below, each crossed with every audience:
#
#       route                                    required audience   enforced at
#       /internal/sessions/{id}/permission       tool                internal.rs:714
#       /internal/sessions/{id}/tools/call       tool                internal.rs:770
#       /internal/sessions/{id}/events           control             internal.rs:1525
#       /internal/sessions/{id}/heartbeat        control             internal.rs:1608
#       /internal/sessions/{id}/result           control             internal.rs:1659
#       /internal/sessions/{id}/workspace  (GET) workspace           internal.rs:1562
#       /internal/token/renew                    control             internal.rs:1753
#       /internal/llm/{*rest}                    llm                 facade.rs:338
#       /internal/llm-usage                      (none — see below)  callback.rs:22
#
#     `/llm-usage` is the ONE deliberately-unguarded route: it is LiteLLM's
#     callback and authenticates on the deployment's shared LiteLLM secret, not
#     on a session token at all. The meaningful negative there is that a session
#     token — ANY audience — does not authenticate it, with the shared secret as
#     the positive control.
# ═════════════════════════════════════════════════════════════════════════════
say "(g) Audience negatives — every internal route × every audience"
mcp_mode "$PROTO_SNAP" ok
G_PFX="sess-g-$$"
if live_run hq-agent "$G_PFX-all" "g/audiences" && forge_audience_set "$RUN" "$G_PFX"; then
  G_MAIN="$RUN"
  G_SESS="/internal/sessions/$G_MAIN"

  aud_matrix "POST /internal/sessions/{id}/permission" tool "$G_PFX" \
    POST "$G_SESS/permission" \
    '{"tool_call_id":"gperm","tool":"Read","input":{"file_path":"/workspace/x"}}'

  # tools/call additionally proves the guard runs BEFORE the broker: the three
  # wrong-audience attempts must contact the upstream zero times, and the one
  # accepted attempt is this window's own positive control (exactly 1 tools/call,
  # which is both the >0 precondition and the ceiling).
  G_MARK=$(mark)
  aud_matrix "POST /internal/sessions/{id}/tools/call" tool "$G_PFX" \
    POST "$G_SESS/tools/call" \
    '{"tool_call_id":"gcall","tool":"mcp__hq__hq_search","input":{"query":"g"}}'
  G_CALLS=$(rec "$G_MARK" count rpc=tools/call)
  [ "$G_CALLS" = 1 ] \
    && ok "across the whole tools/call audience matrix the upstream saw EXACTLY ONE tools/call — the wrong-audience attempts never reached the broker" \
    || no "the tools/call matrix produced $G_CALLS upstream tools/call (want exactly 1: only the 'tool' token dispatches)"

  aud_matrix "POST /internal/sessions/{id}/events" control "$G_PFX" \
    POST "$G_SESS/events" '{"actor":"agent","body":{"type":"unknown"}}'
  aud_matrix "POST /internal/sessions/{id}/heartbeat" control "$G_PFX" \
    POST "$G_SESS/heartbeat" '{}'
  aud_matrix "POST /internal/token/renew" control "$G_PFX" \
    POST "/internal/token/renew" '{"ttl_secs":600}'
  # The init container's ONLY credential. A 404 here is the archive being absent
  # (these runs never provisioned) — the mapping question is only ever 403-or-not.
  aud_matrix "GET  /internal/sessions/{id}/workspace" workspace "$G_PFX" \
    GET "$G_SESS/workspace"
  # Model egress. Nothing listens on :$LLM_PORT in this boot, so the accepted
  # arm fails at the upstream dial — again, not a 403, which is the whole claim.
  aud_matrix "POST /internal/llm/{*rest}" llm "$G_PFX" \
    POST "/internal/llm/v1/messages" \
    '{"model":"claude-haiku-4-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}'

  # The init container's blast radius, as ONE verdict over the matrix above: the
  # workspace token opened /workspace and was refused by every other guarded
  # route it was offered to. Stated separately because "the archive credential
  # cannot do anything else" is the property the split exists for.
  if gt0 "$WS_TRIED" "guarded routes the workspace token was offered to"; then
    { [ "$WS_LEAK" = 0 ] && [ "$WS_OWN_OK" = 1 ]; } \
      && ok "the workspace token reaches ONLY /workspace ($WS_TRIED sibling routes refused it; the archive route accepted it)" \
      || no "workspace-token containment broken: $WS_LEAK of $WS_TRIED sibling routes accepted it (own-route accepted=$WS_OWN_OK)"
  fi
fi

say "(g) /internal/llm-usage — the deliberately-unguarded route rejects session tokens"
# Not a session-token route at all: `litellm_usage` (callback.rs:22-29) accepts a
# bearer that CONTAINS the deployment's LiteLLM key and otherwise answers
# `{"ignored":"unauthenticated"}` without writing anything. The negative that
# matters is that no audience of session token authenticates it.
if [ -n "${G_MAIN:-}" ]; then
  G_USAGE_BAD=0
  for G_A in $AUDIENCES all; do
    aud_curl POST "/internal/llm-usage" "$G_PFX-$G_A" '{"id":"g-usage","spend":0}'
    echo "$BODY" | grep -q '"ignored"' || G_USAGE_BAD=$((G_USAGE_BAD+1))
  done
  [ "$G_USAGE_BAD" = 0 ] \
    && ok "no session token (llm/tool/control/workspace/all) authenticates /internal/llm-usage — all 5 answered 'ignored: unauthenticated'" \
    || no "$G_USAGE_BAD session token(s) were ACCEPTED by /internal/llm-usage (it must key on the LiteLLM shared secret only)"
  # POSITIVE CONTROL: the shared secret DOES authenticate it — without this the
  # five refusals above could just be a route that ignores everything.
  aud_curl POST "/internal/llm-usage" "$MASTER_KEY" '{"id":"g-usage-ok","spend":0}'
  { echo "$BODY" | grep -q '"ok"' && ! echo "$BODY" | grep -q '"ignored"'; } \
    && ok "POSITIVE CONTROL: the LiteLLM shared secret IS accepted there (ok:true) — the refusals above are real" \
    || no "the LiteLLM shared secret was not accepted at /internal/llm-usage → $CODE: $BODY"
fi

say "(g) /result ordering — a revoked CONTROL token still ACKs; a wrong audience never does"
# /result is the one route with token LENIENCY (internal.rs:1644-1660): it
# resolves through `session_for_token_incl_revoked` so a runner whose token was
# revoked by the terminal transition can still ack idempotently. The audience
# check sits on the RESOLVED row ABOVE that leniency, and that ORDER is the
# assertion: a revoked CONTROL token acks, while an llm/tool token — revoked or
# live — is refused before ever reaching the ack. If the check moved below the
# terminal-ack branch, the revoked LLM token would get a 200 "already terminal".
if live_run hq-agent "sess-gv-$$-all" "g/result-leniency" && forge_audience_set "$RUN" "sess-gv-$$"; then
  G_REV="$RUN"
  admin_post "/v1/sessions/$G_REV/cancel" '{}'
  G_REV_ST=$(wait_terminal "$G_REV" 300)
  case "$G_REV_ST" in completed|failed|cancelled|budget_exceeded)
    ok "the leniency fixture's run is terminal ('$G_REV_ST') — the state the ack exists for";;
  *) no "the leniency fixture's run did not terminalize (status='$G_REV_ST')";; esac
  # The terminal transition revokes EVERY session token (revoke_session_tokens),
  # which is exactly the state under test — assert it rather than assume it.
  # Polled, not read once: the revoke happens INSIDE the terminal reconcile, a
  # step after the status write `wait_terminal` returns on.
  G_LIVE_TOKS=""
  for _ in $(seq 1 60); do
    G_LIVE_TOKS=$(db "select count(*) from api_tokens where session_id='$G_REV' and kind='session' and revoked_at is null")
    [ "$G_LIVE_TOKS" = 0 ] && break
    sleep 1
  done
  [ "$G_LIVE_TOKS" = 0 ] \
    && ok "terminalization revoked all of that run's session tokens (the leniency precondition holds)" \
    || no "$G_LIVE_TOKS token(s) survived terminalization — the 'revoked token' halves below would not be testing revocation"
  aud_curl POST "/internal/sessions/$G_REV/result" "sess-gv-$$-control" '{"outcome":"completed","summary":"g"}'
  { [ "$CODE" = 200 ] && echo "$BODY" | grep -q '"ok"'; } \
    && ok "a REVOKED 'control' token still ACKs /result on a terminal run ($BODY) — the idempotent ack the runner retries into" \
    || no "revoked control token on /result → $CODE: $BODY (want a 200 ack)"
  aud_curl POST "/internal/sessions/$G_REV/result" "sess-gv-$$-llm" '{"outcome":"completed","summary":"g"}'
  { [ "$CODE" = 403 ] && [ "$BODY" = "$WRONG_AUD" ]; } \
    && ok "a REVOKED 'llm' token on the SAME terminal run → 403 $WRONG_AUD (refused ABOVE the leniency, never acked)" \
    || no "revoked llm token on /result → $CODE: $BODY (want 403 $WRONG_AUD — a 200 ack means the audience check sank below the leniency)"
  aud_curl POST "/internal/sessions/$G_REV/result" "sess-gv-$$-tool" '{"outcome":"completed","summary":"g"}'
  { [ "$CODE" = 403 ] && [ "$BODY" = "$WRONG_AUD" ]; } \
    && ok "…and a REVOKED 'tool' token likewise → 403 $WRONG_AUD" \
    || no "revoked tool token on /result → $CODE: $BODY (want 403 $WRONG_AUD)"
fi
# A LIVE (unrevoked) llm/tool token is refused the same way — the other half of
# "revoked-or-live". Uses the still-running g/audiences run, whose tokens are live.
if [ -n "${G_MAIN:-}" ]; then
  aud_curl POST "/internal/sessions/$G_MAIN/result" "$G_PFX-llm" '{"outcome":"completed","summary":"g"}'
  { [ "$CODE" = 403 ] && [ "$BODY" = "$WRONG_AUD" ]; } \
    && ok "a LIVE 'llm' token on a NON-terminal run's /result → 403 $WRONG_AUD (model egress can never terminalize a run)" \
    || no "live llm token on /result → $CODE: $BODY (want 403 $WRONG_AUD)"
  aud_curl POST "/internal/sessions/$G_MAIN/result" "$G_PFX-tool" '{"outcome":"completed","summary":"g"}'
  { [ "$CODE" = 403 ] && [ "$BODY" = "$WRONG_AUD" ]; } \
    && ok "a LIVE 'tool' token on the same route → 403 $WRONG_AUD" \
    || no "live tool token on /result → $CODE: $BODY (want 403 $WRONG_AUD)"
  # A /result that got through persists a finalization INTENT before ACKing
  # (internal.rs `finalize_reported`), so zero intents is the observable proof
  # that neither refused post drove the run one step toward terminal.
  [ "$(db "select count(*) from session_finalizations where session_id='$G_MAIN'")" = 0 ] \
    && ok "…and neither refused /result post left a finalization intent behind (the run was never driven toward terminal)" \
    || no "a wrong-audience /result post persisted a finalization intent"
fi
# The /result AUDIENCE MATRIX itself runs LAST and on its OWN run, because its
# accepted arms (control, then legacy 'all') genuinely finalize the session.
if live_run hq-agent "sess-gr-$$-all" "g/result-matrix" && forge_audience_set "$RUN" "sess-gr-$$"; then
  aud_matrix "POST /internal/sessions/{id}/result" control "sess-gr-$$" \
    POST "/internal/sessions/$RUN/result" '{"outcome":"completed","summary":"g"}'
fi

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

# ═════════════════════════════════════════════════════════════════════════════
# (j) Outbound rate limits + per-connection circuit breakers (Task 8, E14).
#     Acceptance bullet: "outbound dials are rate-limited per tenant/connection/
#     host and a repeatedly-failing upstream is circuit-broken."
#
#     The governor is IN-MEMORY, PER-REPLICA and BOOT-RESOLVED (governor.rs
#     `GovernorLimits::from_config`) — there is no runtime knob by design — so
#     this section RESTARTS the control plane with low ceilings. It runs LAST for
#     that reason: everything above keeps the shipped defaults.
#
#     Knob layout, and why each value:
#       TENANT_PER_MIN=0, HOST_PER_MIN=0 — DISABLED. Both are proven disabled
#         (a zero-capacity bucket would refuse the very first dial with
#         "scope tenant"), and disabling HOST is also a NECESSITY here: host_key
#         drops the port (broker.rs `host_key`), so BOTH fakes share the single
#         bucket "127.0.0.1" and an enabled host ceiling would couple the two
#         independent sub-tests below.
#       CONNECTION_PER_MIN=12 — the only bucket left binding, and per connection,
#         so the rate sub-test (on the FIRST connection) and the breaker
#         sub-tests (on the SECOND) cannot spend each other's budget.
#       BREAKER_THRESHOLD=3, OPEN_SECS=60 — three consecutive transport failures
#         open it; 60 s is long enough that no assertion here races the
#         half-open promotion.
# ═════════════════════════════════════════════════════════════════════════════
say "(j) Rate limits + circuit breakers"
GOV_TENANT=0; GOV_CONN=12; GOV_HOST=0; GOV_THRESHOLD=3; GOV_OPEN_SECS=60
if restart_server "control plane rebooted with tenant=0 host=0 connection=12/min, breaker 3 → 60s"; then

  # (j.1) `0` MEANS DISABLED, per dimension — never "refuse everything"
  # (GovernorLimits::from_config's contract). With TWO dimensions at 0, a
  # zero-capacity reading would refuse this very first dial with "scope tenant".
  mcp_mode "$PROTO_SNAP" ok
  if live_run hq-agent "sess-j1-$$" "j/zero-disabled"; then
    J_ZERO="$RUN"
    J_MARK=$(mark)
    R=$(sess_call "$J_ZERO" "sess-j1-$$" '{"tool_call_id":"j1","tool":"mcp__hq__hq_search","input":{"query":"z"}}')
    { echo "$R" | grep -q '"ok": *true' && ! echo "$R" | grep -q "outbound rate limit reached"; } \
      && ok "0 = DISABLED: with the tenant AND host ceilings at 0 the dial is ADMITTED (a zero-capacity bucket would have refused it 'scope tenant')" \
      || no "a ceiling of 0 refused a dial — 0 must mean disabled, not 'refuse everything': $R"
    J1_CALLS=$(rec "$J_MARK" count rpc=tools/call)
    [ "$J1_CALLS" = 1 ] \
      && ok "…and it really reached the upstream (exactly 1 tools/call)" \
      || no "the admitted dial produced $J1_CALLS tools/call (want 1)"
  fi

  # (j.2) THE BOUNDARY THAT MATTERS: an `isError` tool result is NOT a transport
  # failure. broker.rs `breaker_signal` maps every `Ok(_)` — isError or not — to
  # Outcome::Ok, because an upstream that answers is demonstrably healthy. Four
  # consecutive isErrors is MORE than the threshold of 3, so if that rule were
  # inverted the fourth call (and the healthy one after it) would be refused
  # "circuit breaker open" instead of executing.
  mcp2_mode "$PROTO_SNAP" is_error
  if live_run hq2-agent "sess-j2-$$" "j/iserror-not-a-failure"; then
    J_IE="$RUN"
    J_MARK2=$(mark2)
    J_IE_BAD=0
    for J_N in 1 2 3 4; do
      R=$(sess_call "$J_IE" "sess-j2-$$" "{\"tool_call_id\":\"j2-$J_N\",\"tool\":\"mcp__hq__hq_search\",\"input\":{\"query\":\"e\"}}")
      { echo "$R" | grep -q '"ok": *true' && echo "$R" | grep -q '"is_error": *true'; } \
        || J_IE_BAD=$((J_IE_BAD+1))
    done
    J2_CALLS=$(rec2 "$J_MARK2" count rpc=tools/call)
    if gt0 "$J2_CALLS" "tools/call recorded in the isError window"; then
      { [ "$J_IE_BAD" = 0 ] && [ "$J2_CALLS" = 4 ]; } \
        && ok "FOUR consecutive isError results (> the threshold of 3) ALL dispatched — a healthy upstream rejecting a call is not a transport failure" \
        || no "isError handling wrong: $J_IE_BAD malformed response(s), $J2_CALLS tools/call reached the upstream (want 0 and 4)"
    fi
    # …and the healthy call after them still flows: the breaker never opened.
    mcp2_mode "$PROTO_SNAP" ok
    J_MARK2B=$(mark2)
    R=$(sess_call "$J_IE" "sess-j2-$$" '{"tool_call_id":"j2-ok","tool":"mcp__hq__hq_search","input":{"query":"ok"}}')
    { echo "$R" | grep -q '"ok": *true' && ! echo "$R" | grep -q "circuit breaker open"; } \
      && ok "the call AFTER four isErrors succeeded — the breaker is still CLOSED" \
      || no "the post-isError call was refused (the breaker opened on definitive tool errors): $R"
    [ "$(rec2 "$J_MARK2B" count rpc=tools/call)" = 1 ] \
      && ok "…and it was really dispatched (1 tools/call)" \
      || no "the post-isError call did not reach the upstream"
  fi

  # (j.3) TRANSPORT failures DO open it. HTTP 5xx ⇒ CallErr::UpstreamUnavailable
  # ⇒ Outcome::TransportFailure (broker.rs `breaker_signal`); three consecutive
  # ones hit the threshold, and the NEXT dial must be refused with the fake's
  # request count FROZEN — the refusal happens in `governor_gate`, before the
  # per-peer session mutex and before any bytes leave.
  mcp2_mode "$PROTO_SNAP" http_500
  if live_run hq2-agent "sess-j3-$$" "j/breaker"; then
    J_BR="$RUN"
    J_MARK3=$(mark2)
    for J_N in 1 2 3; do
      sess_call "$J_BR" "sess-j3-$$" "{\"tool_call_id\":\"j3-$J_N\",\"tool\":\"mcp__hq__hq_search\",\"input\":{\"query\":\"boom\"}}" >/dev/null
    done
    J3_FAILS=$(rec2 "$J_MARK3" count rpc=tools/call)
    if gt0 "$J3_FAILS" "tools/call recorded while driving the breaker's failures"; then
      [ "$J3_FAILS" = 3 ] \
        && ok "three consecutive HTTP 500s reached the upstream (the breaker's only input, and its threshold)" \
        || no "the failure window recorded $J3_FAILS tools/call (want exactly 3)"
      J_MARK3B=$(mark2)
      R=$(sess_call "$J_BR" "sess-j3-$$" '{"tool_call_id":"j3-open","tool":"mcp__hq__hq_search","input":{"query":"after"}}')
      J3_FROZEN=$(rec2 "$J_MARK3B" count)
      [ "$J3_FROZEN" = 0 ] \
        && ok "the post-threshold call reached the upstream ZERO times — the fake's request count is FROZEN (it recorded $J3_FAILS a moment earlier, so it was demonstrably still recording)" \
        || no "$J3_FROZEN request(s) reached the upstream after the breaker should have opened"
      echo "$R" | grep -q "upstream circuit breaker open after repeated transport failures" \
        && ok "the refusal is the breaker's own message ('upstream circuit breaker open after repeated transport failures …')" \
        || no "breaker refusal text wrong: $R"
      echo "$R" | grep -q "(scope breaker" \
        && ok "…naming scope 'breaker' (not a rate scope — the two are distinguishable by the runner)" \
        || no "the breaker refusal did not name scope 'breaker': $R"
      echo "$R" | grep -qE "retry after [0-9]+s" \
        && ok "…and carrying a retry-after hint" \
        || no "the breaker refusal carried no 'retry after Ns' hint: $R"
      { echo "$R" | grep -q "upstream sha256:" && ! echo "$R" | grep -q "127.0.0.1"; } \
        && ok "the upstream appears ONLY as a sha256: digest — the raw host never reaches the runner" \
        || no "the refusal leaked the raw upstream host (or dropped the digest): $R"
      [ "$(claim_state "$J_BR" j3-open)" = failed_before_send ] \
        && ok "the breaker refusal settled the claim at 'failed_before_send' — pre-write proof, so the intent stays RE-CLAIMABLE (section (f) proves that state re-dispatches)" \
        || no "claim state after a breaker refusal = '$(claim_state "$J_BR" j3-open)' (want failed_before_send)"
    fi
  fi

  # (j.4) Breaker state does not LEAK across connections. The breaker key is
  # (connection, host) — strictly finer than per-connection — so with the second
  # connection's breaker open, the first connection's dials to the SAME host
  # (127.0.0.1, one shared host bucket, which is why HOST is disabled here) are
  # untouched.
  mcp_mode "$PROTO_SNAP" ok
  if live_run hq-agent "sess-j4-$$" "j/no-leak"; then
    J_NL="$RUN"
    J_MARK4=$(mark)
    R=$(sess_call "$J_NL" "sess-j4-$$" '{"tool_call_id":"j4","tool":"mcp__hq__hq_search","input":{"query":"other"}}')
    { echo "$R" | grep -q '"ok": *true' && ! echo "$R" | grep -q "circuit breaker open"; } \
      && ok "with the SECOND connection's breaker open, a dial on the FIRST connection still succeeds — breaker state is per (connection, host)" \
      || no "an open breaker leaked onto another connection: $R"
    [ "$(rec "$J_MARK4" count rpc=tools/call)" = 1 ] \
      && ok "…and it really dispatched (1 tools/call on the first fake)" \
      || no "the cross-connection dial did not reach its upstream"
  fi

  # (j.5) The per-connection RATE bucket. Drives dials until the bucket runs dry
  # (capacity 12, refilling one token per 5 s — the loop's 30-call ceiling is far
  # more than a fast local fake needs to outrun the refill, and stopping at the
  # FIRST refusal keeps this independent of exactly where it lands).
  if live_run hq-agent "sess-j5-$$" "j/rate"; then
    J_RATE="$RUN"
    J_THROTTLED=""; J_PASSED=0; J_RESP=""
    for J_N in $(seq 1 30); do
      R=$(sess_call "$J_RATE" "sess-j5-$$" "{\"tool_call_id\":\"j5-$J_N\",\"tool\":\"mcp__hq__hq_search\",\"input\":{\"query\":\"r\"}}")
      if echo "$R" | grep -q "outbound rate limit reached"; then
        J_THROTTLED="j5-$J_N"; J_RESP="$R"; break
      fi
      echo "$R" | grep -q '"ok": *true' && J_PASSED=$((J_PASSED+1))
    done
    if gt0 "$J_PASSED" "dials ADMITTED before the connection bucket ran dry"; then
      [ -n "$J_THROTTLED" ] \
        && ok "the per-connection bucket ran dry after $J_PASSED admitted dials — '$J_THROTTLED' was refused" \
        || no "30 consecutive dials, none refused: the 12/min connection ceiling never bound"
    fi
    if [ -n "$J_THROTTLED" ]; then
      echo "$J_RESP" | grep -q "outbound rate limit reached (scope connection" \
        && ok "the refusal is the rate limiter's own message naming scope 'connection'" \
        || no "rate-limit refusal text/scope wrong: $J_RESP"
      echo "$J_RESP" | grep -qE "retry after [0-9]+s" \
        && ok "…and carries the 'retry after Ns' hint a client can act on" \
        || no "the rate-limit refusal carried no retry-after hint: $J_RESP"
      { echo "$J_RESP" | grep -q "upstream sha256:" && ! echo "$J_RESP" | grep -q "127.0.0.1"; } \
        && ok "…with the upstream as a sha256: digest only" \
        || no "the rate-limit refusal leaked the raw upstream host: $J_RESP"
      echo "$J_RESP" | grep -qE "scope (tenant|host)" \
        && no "a refusal named scope tenant/host, which are set to 0 (DISABLED) — 0 is being read as zero capacity" \
        || ok "no refusal ever named the DISABLED tenant/host scopes across $J_PASSED+ dials — the '0 = disabled' contract holds under load"
      [ "$(claim_state "$J_RATE" "$J_THROTTLED")" = failed_before_send ] \
        && ok "the throttled intent's claim row reads 'failed_before_send' — RE-CLAIMABLE, which is what makes acting on 'retry after Ns' safe" \
        || no "claim state for the throttled intent = '$(claim_state "$J_RATE" "$J_THROTTLED")' (want failed_before_send)"
    fi
  fi
  # NOT ASSERTED — "the half-open probe CLOSES the breaker". Closing needs the
  # full 60 s open window to elapse (the window is boot-resolved with the same
  # ceilings, and OPEN_SECS is clamped in seconds), so proving it live means
  # either a >60 s sleep in CI or a third boot whose only purpose is a 1-second
  # window — and a 1 s window races every assertion around it. The state machine
  # (Open → HalfOpen on the first dial past the window, single-probe
  # exclusivity, probe-success ⇒ Closed{0}, probe-failure ⇒ a FRESH window) is
  # driven exhaustively against an injected clock in governor.rs's own tests,
  # which is the right place for a pure-timing property. What only an e2e can
  # show — that a real refusal never touches the socket, carries the digest, and
  # leaves a re-claimable claim — is asserted above.
fi

# ── Result ───────────────────────────────────────────────────────────────────
say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
