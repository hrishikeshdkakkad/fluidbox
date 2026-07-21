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
#   (h) durable per-run LLM budget reservations (Gap 14)              [Task 7]
#   (i) two-replica coordination (Gap 13)                             [Task 6]
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
#   * NO ASSERTION MAY PASS ON AN ABSENT ANSWER. Concretely, three rules the
#     whole-branch review added after finding assertions that passed without
#     exercising anything:
#       - a `db()` read that FAILED is not an empty result: psql runs with
#         ON_ERROR_STOP, returns `<psql-error>`, and the run fails at RESULT;
#       - an emptiness/length assertion (`-z`, `= ""`, `${#x} -le N`) carries a
#         FLOOR proving the query returned a row at all (a companion count);
#       - `CODE=000` (curl never connected) is a hard failure, and an "accepted"
#         HTTP arm names the set of codes it accepts instead of saying "not 403";
#   * where an assertion could not be made fail-capable in this harness, there
#     is a comment naming what would be required instead — never a fake pass.
#     Grep `NOT ASSERTED` for the full set; the two added by the whole-branch
#     review are DNS REBINDING (section (a)) and cross-USER session isolation
#     (section (c)), the two acceptance clauses this suite structurally cannot
#     reach — an IP-literal harness has no rebinding, and a single-tenant
#     REQUIRE_SSO=0 boot has no user boundary.
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
# Section (i) (Task 6): the SECOND replica, same DB, its own two ports.
#
# TWO ports per replica, not one: main.rs binds a public listener (`FLUIDBOX_BIND`)
# AND a sandbox-facing internal listener (`FLUIDBOX_INTERNAL_BIND`, main.rs:527-528),
# whose Docker-provider default is 127.0.0.1:8788 (config.rs:267-273). The first
# replica therefore ALREADY holds 8788, so a second replica bound there would die
# at `bind()` before serving a byte — which is why the ports below are 8790/8791
# and not the 8788 this file's placeholder originally reserved. The public bind
# serves /internal too (the comment at main.rs:519), so every request in section
# (i) still goes to the public port; the internal bind only has to be FREE.
API_PORT_B=8790
API_PORT_B_INT=8791
API_B="http://127.0.0.1:$API_PORT_B"

ADMIN_TOKEN=$(openssl rand -hex 32)
CRED_KEY=$(openssl rand -hex 32)        # FLUIDBOX_CREDENTIAL_KEY (seals connections)
MASTER_KEY="sk-litellm-master-$$"       # LITELLM_MASTER_KEY placeholder (shared mode
                                        # refuses to boot on an EMPTY key; no facade
                                        # traffic in sections (a)-(f)).

# Fake servers (fixed high ports; readiness-probed like the siblings).
MCP_PORT=8971       # the primary brokered MCP upstream (all conformance work)
MCP2_PORT=8972      # a SECOND MCP upstream, killed on purpose in section (f)
REDIR_PORT=8973     # a server that answers 302 (redirect-refusal proof)
LLM_PORT=8974       # the fake LiteLLM (data plane + /key/* admin plane) — section (h)
SINK_PORT=8975      # the signed-callback receiver both replicas POST to — section (i)
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
SERVER_PID=""; SERVER_B_PID=""
MCP_PID=""; MCP2_PID=""; REDIR_PID=""; LLM_PID=""; SINK_PID=""
SERVER_LOG="$WORK/server.log"
SERVER_B_LOG="$WORK/server-b.log"   # replica B's own log (section (i))
UB="$WORK/ub"                       # scratch body file for the curl helpers
MCP_LOG="$WORK/mcp-requests.jsonl";     : > "$MCP_LOG"
MCP2_LOG="$WORK/mcp2-requests.jsonl";   : > "$MCP2_LOG"
REDIR_LOG="$WORK/redirect-requests.jsonl"; : > "$REDIR_LOG"
LLM_LOG="$WORK/llm-requests.jsonl";     : > "$LLM_LOG"
SINK_LOG="$WORK/sink-deliveries.jsonl"; : > "$SINK_LOG"
MCP_CTL="$WORK/mcp-control.json"
MCP2_CTL="$WORK/mcp2-control.json"
LLM_CTL="$WORK/llm-control.json"
# The EXACT 401 body the fake LiteLLM answers with in section (h)'s release test,
# defined ONCE here and passed to the fake as argv — so "forwarded verbatim" is a
# byte comparison against a single source of truth, not two hand-copied literals.
# The shape is deliberate: facade.rs:834-835 names `{"error":{"message":"OpenAI API
# key not found","type":"auth_error"}}` as PROVIDER-originated and therefore NOT a
# virtual-key rejection, so `virtual_key_rejected` is false and the facade takes the
# R5 exit — forward verbatim, release the reservation, never re-provision.
LLM_401_BODY='{"error":{"message":"OpenAI API key not found","type":"auth_error"}}'
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
#
# `-v ON_ERROR_STOP=1` is LOAD-BEARING, not hygiene. Without it psql exits 0 on a
# failed statement, so a broken query printed to stderr and returned "" — and an
# EMPTY string silently satisfies every `-z`, `= ""` and `${#x} -le N` assertion
# in this file. A psql failure is now three things at once:
#   1. a loud stderr line (visible in the CI log next to the section it broke),
#   2. the value `<psql-error>` on stdout — which no assertion here expects, so
#      every downstream comparison FAILS instead of passing on emptiness,
#   3. a line in $DB_ERR_LOG, asserted to be empty in the RESULT section — so a
#      failure inside a `db … >/dev/null` fixture write (whose value nothing
#      reads) is still COUNTED. The counter itself cannot live here: db() is
#      almost always called inside `$( )`, and a subshell's `fail=$((fail+1))`
#      never reaches the parent.
# db() is never called from a background subshell (the only `&` blocks in this
# file run sess_call/perm_at/curl), so one shared stderr file is safe and keeps
# stdout free of NOTICE/WARNING text.
DB_ERR='<psql-error>'
DB_ERR_LOG="$WORK/psql-errors.log";  : > "$DB_ERR_LOG"
DB_ERR_FILE="$WORK/.psql-stderr";    : > "$DB_ERR_FILE"
db() {
  local out rc
  out=$(psql "$DATABASE_URL" -X -q -A -t -v ON_ERROR_STOP=1 \
        -c "set fluidbox.bypass = 'system_worker'; $1" 2>"$DB_ERR_FILE")
  rc=$?
  if [ "$rc" -ne 0 ]; then
    printf '%s :: exit %s :: %s\n' "$1" "$rc" "$(tr '\n' ' ' < "$DB_ERR_FILE")" >> "$DB_ERR_LOG"
    printf "  \033[1;31m✗\033[0m psql FAILED (exit %s): %s\n      %s\n" \
      "$rc" "$1" "$(tr '\n' ' ' < "$DB_ERR_FILE")" >&2
    printf '%s\n' "$DB_ERR"
    return "$rc"
  fi
  printf '%s\n' "$out"
}

# ── Cleanup ──────────────────────────────────────────────────────────────────
# Where a FAILED CI run's forensics are copied to (see below). Fixed, inside the
# checkout, because actions/upload-artifact needs a path known when the workflow
# YAML is written and $WORK is a random mktemp dir.
CI_ARTIFACTS="$ROOT/hardening-e2e-artifacts"
# shellcheck disable=SC2329  # invoked via the EXIT/INT/TERM trap
cleanup() {
  local rc=$?
  # CI FORENSICS. $WORK holds the ONLY copy of the control-plane logs and every
  # recorder JSONL, and the `rm -rf` below destroys them — which left a CI-only
  # failure with nothing to debug but the pass/fail lines. So: when the run
  # FAILED (nonzero exit, or any counted failure) and we are in CI, copy those
  # files out first. Copy-out rather than "skip the rm" so the artifact path is
  # static, and only on failure so a green run leaves nothing behind.
  if [ -n "${CI:-}" ] && { [ "$rc" -ne 0 ] || [ "${fail:-0}" -gt 0 ]; }; then
    mkdir -p "$CI_ARTIFACTS"
    cp -p "$SERVER_LOG" "$SERVER_B_LOG" "$MCP_LOG" "$MCP2_LOG" "$REDIR_LOG" \
          "$LLM_LOG" "$SINK_LOG" "$DB_ERR_LOG" "$CI_ARTIFACTS/" 2>/dev/null
    echo "hardening-e2e: run failed (exit $rc, $fail failed assertions) — preserved server logs + recorder JSONLs in $CI_ARTIFACTS" >&2
  fi
  [ -n "$SERVER_PID" ]   && kill "$SERVER_PID"   2>/dev/null
  [ -n "$SERVER_B_PID" ] && kill "$SERVER_B_PID" 2>/dev/null
  [ -n "$MCP_PID" ]    && kill "$MCP_PID"    2>/dev/null
  [ -n "$MCP2_PID" ]   && kill "$MCP2_PID"   2>/dev/null
  [ -n "$REDIR_PID" ]  && kill "$REDIR_PID"  2>/dev/null
  [ -n "$LLM_PID" ]    && kill "$LLM_PID"    2>/dev/null
  [ -n "$SINK_PID" ]   && kill "$SINK_PID"   2>/dev/null
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

# ── The fake LiteLLM (section (h)) ───────────────────────────────────────────
# ONE process serving BOTH planes the facade talks to:
#   * the DATA plane `/v1/messages` (the Anthropic dialect this suite's runs use —
#     facade.rs `resolve_suffix`), and
#   * the ADMIN plane `/key/generate` + `/key/delete`, which `FLUIDBOX_LLM_KEY_MODE=
#     tenant` mints against (llm_keys.rs:419-420, :488-489).
# Every request is recorded as one jsonl line carrying the AUTHORIZATION it was
# presented — which is how section (h) proves the master key is confined to the
# admin plane in tenant mode (the D7 invariant) without ever printing a key.
#
# Behavior is BODY-DRIVEN, so one server serves every case with no restart and no
# control-file race: `metadata.fbx_hold_ms` holds the response open (the ceiling and
# concurrency tests need overlapping in-flight requests), `metadata.fbx_usage`
# selects the response shape, and `metadata.fbx_reply` selects the status. `metadata`
# is a first-class Anthropic request field and the facade forwards the re-serialized
# body verbatim for this dialect (facade.rs:643 — only the OpenAI dialect is
# rewritten), so the knobs arrive intact.
#   fbx_usage: normal   → 200 JSON WITH a usage object      (reconcile ⇒ charged)
#              none     → 200 JSON with NO usage object     (R11 retain)
#              sse      → 200 SSE carrying message_start/message_delta usage
#              sse_none → 200 SSE with NO usage event at all (R13 retain + marker)
#   fbx_reply: unauthorized → the argv-supplied 401 body, verbatim
# The ONE control-file knob is `keygen`, because a mint failure cannot be driven
# from a request body the server writes itself.
cat > "$FAKES/fake_llm.py" <<'PYEOF'
import http.server, json, os, sys, threading, time

PORT, LOG, CTL, UNAUTH = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]

LOCK = threading.Lock()
STATE = {"minted": 0}


def ctl():
    try:
        with open(CTL) as f:
            return json.load(f)
    except Exception:
        return {}


def record(row):
    with LOCK:
        with open(LOG, "a") as f:
            f.write(json.dumps(row) + "\n")
            f.flush()
            os.fsync(f.fileno())


SSE_WITH_USAGE = (
    "event: message\n"
    'data: {"type":"message_start","message":{"usage":'
    '{"input_tokens":11,"output_tokens":0}}}\n\n'
    "event: message\n"
    'data: {"type":"message_delta","usage":{"output_tokens":7}}\n\n'
)
# No message_start and no message_delta ⇒ AnthropicAccumulator.seen stays false ⇒
# Meter::any() is false ⇒ facade.rs R13 (retain + the "usage unparsed" marker).
SSE_NO_USAGE = (
    "event: message\n"
    'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}\n\n'
    "event: message\n"
    'data: {"type":"message_stop"}\n\n'
)


class Llm(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _raw(self, code, body, ctype):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._raw(code, json.dumps(obj), "application/json")

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        try:
            req = json.loads(raw)
        except Exception:
            req = {}
        meta = req.get("metadata") if isinstance(req.get("metadata"), dict) else {}
        try:
            hold = int(meta.get("fbx_hold_ms", 0) or 0)
        except Exception:
            hold = 0
        usage = str(meta.get("fbx_usage", "normal"))
        reply = str(meta.get("fbx_reply", "ok"))
        record({
            "path": self.path.split("?")[0],
            "auth": self.headers.get("authorization", ""),
            "xapikey": self.headers.get("x-api-key", ""),
            "hold": str(hold),
            "usage": usage,
            "reply": reply,
            "model": str(req.get("model", "")),
        })
        if self.path.startswith("/key/generate"):
            if ctl().get("keygen", "ok") != "ok":
                # 5xx (not 4xx): llm_keys.rs treats a client error as "nothing was
                # created" and a 5xx as AMBIGUOUS, keeping the mint guard armed —
                # which is the path that also exercises /key/delete below.
                return self._json(503, {"error": "harness disabled /key/generate"})
            with LOCK:
                STATE["minted"] += 1
                minted = "sk-fbx-tenant-%d" % STATE["minted"]
            return self._json(200, {"key": minted})
        if self.path.startswith("/key/delete"):
            return self._json(200, {"deleted": True})
        if not self.path.startswith("/v1/messages"):
            return self._json(404, {"error": "unknown path"})
        if hold > 0:
            time.sleep(hold / 1000.0)
        if reply == "unauthorized":
            return self._raw(401, UNAUTH, "application/json")
        if usage in ("sse", "sse_none"):
            body = SSE_WITH_USAGE if usage == "sse" else SSE_NO_USAGE
            return self._raw(200, body, "text/event-stream")
        out = {
            "id": "msg_fake", "type": "message", "role": "assistant",
            "model": req.get("model", ""), "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "ok"}],
        }
        if usage != "none":
            out["usage"] = {"input_tokens": 11, "output_tokens": 7}
        return self._json(200, out)

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Llm).serve_forever()
PYEOF

# ── The signed-callback receiver (section (i)) ───────────────────────────────
# The "external service" both replicas' delivery workers POST to. Records ONE line
# per POST carrying `x-fluidbox-delivery` (deliveries.rs:485) — the id receivers
# dedup on — so "exactly one POST per delivery with two live workers" is a count
# over distinct ids, not a guess.
#
# HOLD_MS is load-bearing, not padding: `attempt` processes a claimed batch
# SEQUENTIALLY, so holding each POST open keeps the claim visible in
# `result_deliveries.claimed_by` long enough for the psql sampler to observe it
# (the claim is CLEARED by mark_delivery_attempt on completion — db_lib.rs
# `claimed_by = null` — so a fast sink erases the only evidence of who claimed).
# It also guarantees the second claim round: the per-tick limit is 10
# (deliveries.rs:132), so a 14-row burst leaves 4 rows for whichever worker ticks
# next, and the first claimant is busy 10*HOLD_MS — longer than the other's 3 s
# tick. Kept far under DELIVERY_TIMEOUT (10 s) so every attempt still succeeds.
cat > "$FAKES/fake_sink.py" <<'PYEOF'
import http.server, json, os, sys, threading, time

PORT, LOG, HOLD_MS = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
LOCK = threading.Lock()


def record(row):
    with LOCK:
        with open(LOG, "a") as f:
            f.write(json.dumps(row) + "\n")
            f.flush()
            os.fsync(f.fileno())


class Sink(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        if n:
            self.rfile.read(n)
        record({
            "delivery": self.headers.get("x-fluidbox-delivery", ""),
            "event": self.headers.get("x-fluidbox-event", ""),
            "signed": "yes" if self.headers.get("x-fluidbox-signature") else "no",
        })
        if HOLD_MS > 0:
            time.sleep(HOLD_MS / 1000.0)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        body = b'{"ready":true}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Sink).serve_forever()
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
recl()  { python3 "$FAKES/rec.py" "$LLM_LOG"   "$@"; }
recs()  { python3 "$FAKES/rec.py" "$SINK_LOG"  "$@"; }
# The current end of a recorder — every section snapshots this first so its
# assertions are scoped to its OWN window and can never inherit earlier traffic.
mark()  { rec 0 len; }
mark2() { rec2 0 len; }
markr() { recr 0 len; }
markl() { recl 0 len; }
marks() { recs 0 len; }

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

# The fake LiteLLM's ONE control-file knob (mint failures cannot ride a request
# body — see the fake's header).
llm_keygen() { # ok|fail
  printf '{"keygen":"%s"}\n' "$1" > "$LLM_CTL"
}
start_llm() {
  llm_keygen ok
  python3 "$FAKES/fake_llm.py" "$LLM_PORT" "$LLM_LOG" "$LLM_CTL" "$LLM_401_BODY" &
  LLM_PID=$!
  for _ in $(seq 1 40); do
    # A POST to an unknown path answers 404 — enough to prove the listener is up,
    # and it records a line the sections below never read (their windows start
    # after their own mark).
    curl -s -o /dev/null -X POST "http://127.0.0.1:$LLM_PORT/_ready" 2>/dev/null && {
      ok "fake LiteLLM up on :$LLM_PORT (data plane + /key/* admin plane, auth recorded)"
      return 0; }
    sleep 0.25
  done
  echo "hardening-e2e: fake LiteLLM did not become ready" >&2; exit 1
}

# How long the callback sink holds each POST open (see the fake's header — this is
# what keeps `result_deliveries.claimed_by` observable and what forces the second
# claim round).
SINK_HOLD_MS=500
start_sink() {
  python3 "$FAKES/fake_sink.py" "$SINK_PORT" "$SINK_LOG" "$SINK_HOLD_MS" &
  SINK_PID=$!
  for _ in $(seq 1 40); do
    curl -s -o /dev/null "http://127.0.0.1:$SINK_PORT/ready" 2>/dev/null && {
      ok "callback sink up on :$SINK_PORT (holds each POST ${SINK_HOLD_MS}ms, records x-fluidbox-delivery)"
      return 0; }
    sleep 0.25
  done
  echo "hardening-e2e: callback sink did not become ready" >&2; exit 1
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

# Per-boot LLM knobs, consumed by `_spawn` (section (h) sets and RESTARTS — both
# are boot-resolved: `Config::from_env` parses the key mode, and the reservation
# ceiling is a process-lifetime `OnceLock` (facade.rs:207-226)).
LLM_KEY_MODE=shared     # shared | tenant
LLM_MAX_RES=""          # empty ⇒ the shipped default (32)

# `_spawn` sets this; callers assign it to whichever replica handle they own.
SPAWN_PID=""

_spawn() { # [public-port] [internal-port] [logfile] → sets SPAWN_PID
  # Parameterized for section (i): a SECOND replica needs its own public AND
  # internal binds (main.rs:527-528) and its own log. Every pre-existing call site
  # passes nothing and gets exactly the previous behavior.
  local port=${1:-$API_PORT} iport=${2:-} log=${3:-$SERVER_LOG}
  printf '\n===== control plane (re)start =====\n' >> "$log"
  (
    cd "$ROOT" || exit 1
    export DATABASE_URL="$DATABASE_URL"
    export FLUIDBOX_BIND="127.0.0.1:$port"
    [ -n "$iport" ] && export FLUIDBOX_INTERNAL_BIND="127.0.0.1:$iport"
    # LOAD-BEARING: a loopback-http public URL is the ONLY switch that opens the
    # dev-loopback egress seam (egress.rs `dev_loopback`). Without it every fake
    # in this file becomes an unreachable plain-http non-https target and the
    # whole suite fails at the first dial — while the metadata/private-IP
    # negatives below stay blocked regardless, which is exactly the split the
    # SSRF section asserts.
    export FLUIDBOX_PUBLIC_URL="http://127.0.0.1:$port"
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
    # key. No facade traffic happens in sections (a)-(f); section (h) points
    # LLM_UPSTREAM_URL at the fake on :$LLM_PORT and flips the key mode.
    export FLUIDBOX_LLM_KEY_MODE="$LLM_KEY_MODE"
    export LITELLM_MASTER_KEY="$MASTER_KEY"
    export LLM_UPSTREAM_URL="http://127.0.0.1:$LLM_PORT"
    # Section (h.3)'s concurrency ceiling. Unset on every other boot, so the rest
    # of the suite runs against the shipped default (32) and cannot be refused by
    # it. `FLUIDBOX_LLM_ADMIN_URL` is deliberately left unset: it defaults to
    # LLM_UPSTREAM_URL (config.rs:257), so the fake serves both planes on one port
    # and "which plane got which credential" is answerable from one recorder.
    [ -n "$LLM_MAX_RES" ] && export FLUIDBOX_LLM_MAX_CONCURRENT_RESERVATIONS="$LLM_MAX_RES"
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
  ) >>"$log" 2>&1 &
  SPAWN_PID=$!
}

boot() {
  _spawn
  SERVER_PID=$SPAWN_PID
  for _ in $(seq 1 180); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then SERVER_PID=""; return 1; fi
    curl -sf "$API/v1/health" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# ── The SECOND replica (section (i)) ─────────────────────────────────────────
# Same binary, same DATABASE_URL, same runtime role, distinct ports and log.
# Booted only in section (i) and stopped at its end, so section (j) — whose
# governor is in-memory and PER-REPLICA — still runs against exactly one process.
#
# Boot ORDER is load-bearing: replica A is healthy (and has therefore already run
# every migration) long before this is called, so B's own migrate pass is a no-op
# and the two can never race the migration lock. The shared FLUIDBOX_DATA_DIR is
# deliberate (it models the shared volume a real two-replica deployment has), and
# B's boot is safe for the forged fixtures already in the DB for exactly the reason
# `restart_server` documents: they carry NULL started_at/last_heartbeat_at and
# never provisioned a sandbox, so no watchdog, wall-clock sweeper or orphan reap
# on B has anything of theirs to act on.
boot_replica_b() {
  _spawn "$API_PORT_B" "$API_PORT_B_INT" "$SERVER_B_LOG"
  SERVER_B_PID=$SPAWN_PID
  for _ in $(seq 1 180); do
    if ! kill -0 "$SERVER_B_PID" 2>/dev/null; then SERVER_B_PID=""; return 1; fi
    curl -sf "$API_B/v1/health" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
stop_replica_b() {
  [ -n "$SERVER_B_PID" ] && kill "$SERVER_B_PID" 2>/dev/null
  SERVER_B_PID=""
  for _ in $(seq 1 60); do
    curl -sf "$API_B/v1/health" >/dev/null 2>&1 || return 0
    sleep 0.5
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
# TWO rules every CODE/BODY helper below obeys, both learned from a false green:
#
#  1. TRUNCATE $UB FIRST. It is ONE shared file and curl does not truncate `-o`
#     when the connection never opens — so a dead control plane answers
#     `CODE=000` while $UB still holds the PREVIOUS request's body. Any assertion
#     shaped "not a 403" / "not the wrong-audience body" then passes against a
#     corpse, reading a stale success as this request's answer.
#  2. `CODE=000` IS A FAILURE, everywhere. curl reports 000 when it never got a
#     status line at all (connection refused, DNS failure, timeout). That is not
#     "the route accepted us", it is "there was no route" — and this suite reboots
#     the server four times, so a boot that silently died must never read as a
#     pass. Counted here rather than at the call sites: these helpers run in the
#     MAIN shell (they set globals), so `no` reaches the real counter.
http_dead() { # code label → 0 (having recorded ONE failure) when nothing answered
  [ "$1" = 000 ] || return 1
  no "$2: the request never completed (curl code 000 — connection refused / no status line). A dead control plane is never a passing outcome."
  return 0
}
admin_post() {
  : > "$UB"
  CODE=$(curl -s -o "$UB" -w '%{http_code}' -X POST -H "$AH" -H 'content-type: application/json' -d "$2" "$API$1")
  BODY=$(cat "$UB")
  http_dead "$CODE" "POST $1" && return 1
  return 0
}
admin_get()  {
  : > "$UB"
  CODE=$(curl -s -o "$UB" -w '%{http_code}' -H "$AH" "$API$1")
  BODY=$(cat "$UB")
  http_dead "$CODE" "GET $1" && return 1
  return 0
}
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
  : > "$UB"
  if [ "$m" = GET ]; then
    CODE=$(curl -s -o "$UB" -w '%{http_code}' -H "authorization: Bearer $t" "$API$p")
  else
    CODE=$(curl -s -o "$UB" -w '%{http_code}' -X "$m" -H "authorization: Bearer $t" \
      -H 'content-type: application/json' -d "$b" "$API$p")
  fi
  BODY=$(cat "$UB")
  http_dead "$CODE" "$m $p" && return 1
  return 0
}
wrong_aud_body() { case "$1" in *wrong_audience*) return 0;; esac; return 1; }
# The ACCEPTED set for an audience matrix arm, stated POSITIVELY. The old shape
# was `[ "$CODE" != 403 ]`, which passes on 000 (no connection) and on 401 (the
# token never resolved — a broken forge), i.e. exactly the two ways this matrix
# can go blind. Acceptance means "THIS handler answered": a status it produces
# itself. The exact 2xx cannot be pinned per route without coupling the mapping
# proof to unrelated downstream state — the workspace archive is absent (404),
# nothing listens on the LLM port in this boot (5xx), and /tools/call may deny
# (200) or reject a body (400/422) — which is why the set is a list rather than
# `= 200`. 000, 401 and 403 are the three codes it deliberately excludes.
AUD_ACCEPT_SET="200 201 202 204 400 404 409 422 429 500 502 503 504"
aud_accepted() { case " $AUD_ACCEPT_SET " in *" $1 "*) return 0;; esac; return 1; }

# Running tally of the init container's blast radius, accumulated BY the matrix
# (never by a second pass — the bodies differ per route, and an invalid body is
# rejected by the Json extractor BEFORE the handler's audience guard, which would
# read as a false "refused"). WS_TRIED is the >0 precondition.
WS_TRIED=0; WS_LEAK=0; WS_OWN_OK=0

# ONE route × EVERY audience. The route's own audience must be ACCEPTED — the
# handler's OWN answer, positively (`aud_accepted`, above), with no
# wrong_audience body — every OTHER scoped audience must be refused 403 with the
# body code VERBATIM, and the legacy 'all' must pass. Acceptance is a positive
# membership test rather than "not 403" because `wrong_audience` being the ONLY
# ApiError::Forbidden on the internal plane (internal.rs + facade.rs carry no
# other) makes 403 sufficient for the NEGATIVE arms but not necessary for the
# positive ones: a 000 (dead server) and a 401 (a forge that produced no usable
# token) are both "not 403" and neither is acceptance.
# Self-checking twice over: a broken forge shows up as 401s on the three
# negatives AND fails the accepted arms, so no arm can pass vacuously.
aud_matrix() { # label required-audience token-prefix method path [json-body]
  local label=$1 want=$2 pfx=$3 m=$4 p=$5 b=${6:-} a
  for a in $AUDIENCES all; do
    aud_curl "$m" "$p" "$pfx-$a" "$b"
    if [ "$a" = "$want" ]; then
      # WS_OWN_OK is set INSIDE the passing branch: outside it (its original
      # position) it recorded only that the workspace arm was TRIED, which made
      # the `WS_OWN_OK = 1` conjunct in the containment verdict below unfalsifiable
      # — the "the archive route accepted it" half was never actually asserted.
      if aud_accepted "$CODE" && ! wrong_aud_body "$BODY"; then
        ok "$label ← '$a' (the route's OWN audience): accepted ($CODE)"
        [ "$a" = workspace ] && WS_OWN_OK=1
      else
        no "$label ← '$a' (the route's OWN audience) was NOT accepted → $CODE: $BODY (want one of: $AUD_ACCEPT_SET)"
      fi
    elif [ "$a" = all ]; then
      { aud_accepted "$CODE" && ! wrong_aud_body "$BODY"; } \
        && ok "$label ← legacy 'all': accepted ($CODE) — in-flight sessions keep working" \
        || no "$label ← legacy 'all' was NOT accepted → $CODE: $BODY (want one of: $AUD_ACCEPT_SET; breaks every run spanning the deploy)"
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
# POSITIVE CONTROL for the ZERO below — the in-section control this file's
# assertion discipline mandates. The redirect TARGET lives on the PRIMARY fake
# ($FOLLOW_URL is $MCP_PORT/followed), so the zero is only meaningful if that
# fake's recorder was alive and appending in THIS window. One probe of the same
# fake must land at path=/mcp; the zero filters on path=/followed, so the control
# can never inflate it.
admin_post "/v1/mcp/probe" "{\"url\":\"$MCP_URL\"}"
F_CTL=$(rec "$F_MARK" count path=/mcp)
gt0 "$F_CTL" "requests recorded on the redirect-target fake in this window" \
  && ok "POSITIVE CONTROL: the redirect-target fake recorded $F_CTL request(s) at /mcp in this same window — its recorder is live"
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
#
# NOT ASSERTED — DNS REBINDING, the remaining half of acceptance bullet (a).
# Every SSRF target in this section is an IP LITERAL ($PRIV_MCP, $META_URL,
# $PRIV_CLONE), which exercises `admit_url`'s host-literal short-circuit
# (egress.rs) and nothing else. A rebinding attack does not use a literal: it
# uses a NAME that resolves to a public address when the URL is admitted and to a
# private one when the socket is opened. The product's answer to that is a
# different mechanism than anything asserted here — `admit_url` deliberately does
# NOT resolve (resolving would only add a TOCTOU window), and the enforcement is
# `SsrfDnsResolver`, a reqwest `dns::Resolve` that re-filters EVERY resolved
# address at CONNECT time and errors when the filtered set is empty, so a
# rebound name never opens a connection.
# Making this fail-capable in an e2e needs a CONTROLLABLE DNS SERVER: a resolver
# that answers A=<public> for the first lookup of one name and A=<private> for
# the second, plus the control plane's process resolver pointed at it (a
# /etc/resolv.conf or a resolver-override the server does not expose). This
# harness is python-stdlib fakes on loopback with no root and no resolver seam,
# so there is no honest assertion to write — a name that resolves to 127.0.0.1
# would be refused by the SAME literal/CIDR filter already asserted above, and
# would prove nothing about rebinding while LOOKING like it did. What IS covered:
# `filter_public_addrs` (the exact function SsrfDnsResolver applies to resolved
# addresses) is driven over public/private/loopback/metadata addresses by
# `dns_filter_range_logic` in crates/fluidbox-server/src/egress.rs's own tests.

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
# NOT ASSERTED — "session IDs never cross USER boundaries", the second half of
# acceptance bullet (c). What is proven above is per-RUN isolation: two runs of
# ONE agent against ONE connection get two distinct upstream mcp-session-ids,
# because the registry key is (run session id, McpPeer::Binding(binding id)).
# That is the whole of the isolation this boot CAN show. This suite runs
# FLUIDBOX_REQUIRE_SSO=0 with a single tenant and drives everything with the
# admin token, so every run here belongs to the SAME principal — there is no user
# boundary in this process for a session id to cross, and an assertion phrased as
# one would be comparing two runs of one user and calling it a cross-user proof.
# Making it fail-capable needs a SECOND tenant and a second USER: two orgs, an
# activated IdP config per org, a member in each, and a run per member whose
# upstream sessions are then compared. That is the SSO fixture — REQUIRE_SSO=1
# plus an OIDC provider and cookie/PAT principals — which simultaneously confines
# the admin token to /v1/admin/* and would break every forge, catalog Connect and
# aud_matrix call in this file (the same reason (h)'s `tenant_llm_keys_required`
# is disclosed rather than asserted). scripts/identity-e2e.sh is the suite that
# already owns that fixture; the tenant-scoping floor underneath it — every
# tenant-owned loader carrying a TenantScope, and RLS FORCEd on the session
# tables — is asserted there and in the fluidbox-db tests, not here.

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
  # The floor this fixture needs: `run_spec->'brokered'->0 ? 'protocol_version'`
  # is NULL — hence not-true, hence count 0 — when there is no brokered surface at
  # ALL. So the zero alone cannot tell "the key was removed" from "this run froze
  # no brokered surface, and the unsupported-version arm below is testing nothing".
  # Prove the surface EXISTS first, then that the key is gone from it.
  SURF=$(db "select coalesce(jsonb_array_length(run_spec->'brokered'),0) from sessions where id='$D_UNS'")
  LEFT=$(db "select count(*) from sessions where id='$D_UNS' and run_spec->'brokered'->0 ? 'protocol_version'")
  if gt0 "$SURF" "frozen brokered surfaces on the unsupported-version run"; then
    [ "$LEFT" = 0 ] \
      && ok "fixture: the frozen surface exists ($SURF) and its protocol_version was removed (a pre-Phase-E RunSpec)" \
      || no "fixture failed — protocol_version is still on the frozen surface"
  fi
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
  # Stated as a POSITIVE refusal set, not `!= 200`: the binding refusal is an
  # ApiError::BadRequest raised by bindings.rs (either "connection '…' is error —
  # reconnect it" on an explicit slot, or the no-satisfying-connection arm), so
  # the answer must be a 4xx the HANDLER produced. `!= 200` also accepted 000 —
  # a control plane that had died would have "proven" fail-closed behaviour.
  admin_post "/v1/sessions" "{\"agent\":\"hq-agent\",\"task\":\"t\",\"repo\":{\"kind\":\"none\"}}"
  case "$CODE" in
    400|409|422)
      { [ -n "$BODY" ] && ok "a new run bound to the errored connection → $CODE (fail closed off status): $BODY"; } \
        || no "the run was refused with $CODE but an EMPTY body — no refusal reason was rendered";;
    *)
      no "a new run against the errored connection → $CODE: $BODY (want a 400/409/422 refusal; 2xx = it was created, 000 = nothing answered)";;
  esac
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
  # The bounded message names JSON-pointer PATHS, never argument VALUES. The
  # bound needs a FLOOR at both ends or it is not an assertion: zero bytes
  # satisfies `-le 600`, so an absent event row — or a psql that failed — used to
  # "prove" boundedness. The floor is the companion row count (the ledger row must
  # EXIST) plus a non-empty reason, and the reason must still name the schema
  # rejection rather than being any old short string.
  E1_ROWS=$(db "select count(*) from events where session_id='$E_RUN' and type='tool.decision' and payload->>'tool_call_id'='e1'")
  E1_REASON=$(db "select coalesce(payload->>'reason','') from events where session_id='$E_RUN' and type='tool.decision' and payload->>'tool_call_id'='e1'")
  if gt0 "$E1_ROWS" "tool.decision ledger rows for the schema-rejected intent"; then
    { [ "${#E1_REASON}" -ge 1 ] && [ "${#E1_REASON}" -le 600 ] \
        && echo "$E1_REASON" | grep -q "frozen schema"; } \
      && ok "the ledgered schema reason is present, names the frozen schema, and is bounded (${#E1_REASON} bytes, 1..600)" \
      || no "schema reason is out of bounds or not a schema reason (${#E1_REASON} bytes): '$E1_REASON'"
  fi

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
  # POSITIVE CONTROL for that ZERO, in the SAME recorder window. It cannot be run
  # on $E_RO itself (every call from a ReadOnly run is denied — with good args by
  # the tier, with bad args by the schema), so it is a fresh full-trust run whose
  # valid call MUST appear in the window the zero was read from. Read after the
  # zero, exactly like (h.3a)/(h.3b)'s deferred control: the zero covered
  # [E_MARK, now) and this re-read proves the recorder was appending in it.
  if live_run hq-agent "sess-e-ro-ctl-$$" "e/order-control"; then
    R=$(sess_call "$RUN" "sess-e-ro-ctl-$$" '{"tool_call_id":"e5c","tool":"mcp__hq__hq_count","input":{"n":3}}')
    echo "$R" | grep -q '"ok": *true' \
      && ok "POSITIVE CONTROL: a full-trust run's valid call executed in the same window" \
      || no "the order-proof's positive control call failed: $R"
    E5_CTL=$(rec "$E_MARK" count rpc=tools/call)
    gt0 "$E5_CTL" "tools/call recorded in the order-proof window once a real dispatch happened" \
      && ok "POSITIVE CONTROL: that same window now holds $E5_CTL tools/call — the ZERO above was a real absence, not a dead fake"
  fi
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
  # `[ "$ST" != ambiguous ]` used to ride along as a second conjunct here. It was
  # tautological — the preceding `= failed_upstream` already excludes every other
  # state, `ambiguous` included — so it asserted nothing and only made the check
  # look stronger than it was. The single equality IS the assertion; the failure
  # message keeps naming 'ambiguous' as the regression this guards.
  ST=$(claim_state "$F_500" f2)
  [ "$ST" = failed_upstream ] \
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
  # POSITIVE CONTROL for that ZERO, on the SAME run and in the SAME window: a
  # DIFFERENT intent (f4c) on this very session dispatches normally. That makes
  # the zero attributable to the AMBIGUOUS CLAIM specifically — not to a dead
  # fake, a dead recorder, or a run that had stopped dispatching anything.
  R=$(sess_call "$F_AMB" "sess-f4-$$" '{"tool_call_id":"f4c","tool":"mcp__hq__hq_search","input":{"query":"ctl"}}')
  echo "$R" | grep -q '"ok": *true' \
    && ok "POSITIVE CONTROL: a fresh intent on the SAME run still dispatches (only the ambiguous one is frozen)" \
    || no "the ambiguous section's positive control call failed: $R"
  F4_CTL=$(rec "$F_MARK" count rpc=tools/call)
  gt0 "$F4_CTL" "tools/call recorded in the ambiguous window once a fresh intent ran" \
    && ok "POSITIVE CONTROL: that same window now holds $F4_CTL tools/call — the ZERO above was a real absence"
fi

say "(f) Cancel DURING an approval wait — approving afterwards dispatches NOTHING"
# The other half of Gap 11: the approval said "allow" minutes ago, but the run is
# gone. Two fences exist and either is a pass, and there are exactly THREE strings
# in the shipped source between them (verified against internal.rs, #33):
#   1. "session stopped accepting work during the approval wait" — the post-wait
#      terminality recheck's LEDGER reason (EventBody::ToolDecision,
#      source="session_terminal"). It is NOT the response body: that arm returns
#      GateDecision::terminal_deny(), which /tools/call renders as (3).
#   2. "session is not active" — TERMINAL_MESSAGE, the RESPONSE for both the
#      handler-top terminal guard and fence 1 (deliberately indistinguishable to
#      a runner).
#   3. "session is terminal" — ClaimOutcome::SessionTerminal, the claim's
#      in-transaction non-terminal condition.
# The alternation below carries only the two RESPONSE shapes, (2) and (3). A
# fourth string, "session terminal during approval wait", used to lead it and
# exists NOWHERE in the source — a branch that can never match hides which shape
# actually shipped, so it is gone.
# TO WHOEVER UNIFIES THESE GUARDS: this is the assertion that tracks them. If
# ClaimOutcome::SessionTerminal is folded onto TERMINAL_MESSAGE, string (3) goes
# dead and must be DROPPED from the alternation for exactly the reason the fourth
# one was — every alternative here has to be a real, greppable string, or the
# check quietly stops naming which fence fired.
# The ZERO-dispatch assertion is the load-bearing one and is asserted separately
# so a message-shape change cannot mask it.
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
  echo "$R" | grep -qE "session is terminal|session is not active" \
    && ok "the response names the terminal session as the reason" \
    || no "cancel-during-approval response: $R"
  # The "no claim row" assertion needs a FLOOR, or a psql that answered nothing
  # would satisfy `-z` and read as "nothing was claimed". Two companions, both in
  # this window: the run's own claim count must be a real 0, and the SAME table
  # read through the SAME helper must be returning rows for the runs that DID
  # claim (section (f) has been filling it since the duplicate-intent test).
  F5_CLAIMS=$(db "select count(*) from tool_execution_claims where session_id='$F_CAN'")
  F5_CLAIM_CTL=$(db "select count(*) from tool_execution_claims where state='succeeded'")
  CST=$(claim_state "$F_CAN" f5)
  if gt0 "$F5_CLAIM_CTL" "claim rows readable in this window (the table, the bypass GUC and psql all work)"; then
    { [ "$F5_CLAIMS" = 0 ] && [ -z "$CST" ]; } \
      && ok "no execution claim was ever taken for the cancelled intent (0 rows for the run, and $F5_CLAIM_CTL succeeded rows prove the read works)" \
      || no "claim rows for the cancelled run = '$F5_CLAIMS', f5 state = '$CST' (want 0 and empty)"
  fi
  # POSITIVE CONTROL for the ZERO above, in the SAME recorder window — F_MARK was
  # re-marked at the top of this block, so nothing else proved the fake or its
  # recorder survived the cancel + approval poll (~40 s of sleeps). A fresh run's
  # allowed call must now appear in that window. Read AFTER the zero, so it can
  # never inflate it.
  if live_run hq-agent "sess-f5c-$$" "f/cancel-control"; then
    R=$(sess_call "$RUN" "sess-f5c-$$" '{"tool_call_id":"f5c","tool":"mcp__hq__hq_count","input":{"n":5}}')
    echo "$R" | grep -q '"ok": *true' \
      && ok "POSITIVE CONTROL: a live run's call executed after the cancel test" \
      || no "the cancel section's positive control call failed: $R"
    F5_CTL=$(rec "$F_MARK" count rpc=tools/call)
    gt0 "$F5_CTL" "tools/call recorded in the cancel window once a live run dispatched" \
      && ok "POSITIVE CONTROL: that same window now holds $F5_CTL tools/call — the ZERO above was a real absence, not a fake that died during the cancel poll"
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# ORDER OF THE REMAINING SECTIONS, and why it is not arbitrary:
#   (g) audiences   — no boot change; runs on the original process.
#   (h) reservations— its last sub-test REBOOTS with FLUIDBOX_LLM_KEY_MODE=tenant
#                     and a reservation ceiling of 2 (both boot-resolved), then
#                     hands the knobs back.
#   (i) two-replica — boots a SECOND process and stops it again at the end, so
#                     everything after it is single-replica once more.
#   (j) governor    — REBOOTS with low egress ceilings; runs LAST because those
#                     ceilings would throttle every section above it.
# The harness (fakes, recorders, boot/forge helpers, psql shims) is shared — a new
# section extends it rather than duplicating it.
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

# ═════════════════════════════════════════════════════════════════════════════
# (h) Durable request-keyed LLM budget reservations (Task 7, E13; Gap 14;
#     migration 0022).
#     Acceptance bullet: "concurrent model requests can no longer all pass one
#     budget check; a per-request reservation binds them against the run's
#     frozen budget."
#
#     THE RACE, precisely (0022's header): the facade CHECKED accumulated usage
#     before forwarding and RECORDED usage only after completion, so N concurrent
#     requests all read the same remaining budget and all passed it. The fix books
#     a CONSERVATIVE maximum BEFORE forwarding — atomically, behind a short
#     `sessions FOR UPDATE` plus one guard CTE (db_lib.rs `reserve_llm_budget`) —
#     and reconciles it against authoritative usage afterwards.
#
#     DEVIATION 1, THE SOLE-CLAIMANT RULE (db_lib.rs:5291-5302): the budget arms
#     are SKIPPED when ZERO other reservations are live (`a.n = 0` in the guard).
#     Gap 14 is a CONCURRENCY race; the terminal "this run is out of budget"
#     verdict deliberately stays with the pre-existing accumulated check. Every
#     assertion below is therefore about the CONCURRENT case — and (h.1c) asserts
#     the carve-out itself, so a refusal here can never be confused with "the
#     budget was simply too small to make any request at all".
#
#     SIZING (written down so a future edit can re-derive it):
#       reserved = declared max output + ceil(body_len / BYTES_PER_INPUT_TOKEN)
#       [facade.rs `conservative_reservation`], and BYTES_PER_INPUT_TOKEN is 1 —
#       #33 review 1 moved it off the 4-byte AVERAGE, which was not an upper bound
#       at all (dense or adversarial text tokenizes far denser, so two requests
#       could each reserve a quarter of what they spent and both be admitted).
#       Byte-level BPE has all 256 bytes in its vocabulary and only ever merges,
#       so N bytes can never bill more than N input tokens: 1:1 is a bound no
#       input can beat.
#       The burst declares `max_tokens: 1000` in a 189-byte body (measured — the
#       facade re-serializes it to the same 189 bytes), so ONE request books
#       1000 + 189 = 1189 tokens. The run's frozen `max_tokens` budget is
#       forced to 1500, which sits between one reservation and two:
#         * one request alone  → admitted (sole claimant; the arms are skipped);
#         * a second WHILE the first is live → 0 used + 1189 active + 1189 this
#           = 2378 > 1500 ⇒ BudgetExceeded.
#       Both margins are wide (1189 vs 1500, 2378 vs 1500) so neither verdict can
#       flip on a model-name length change or a few bytes of body drift. Note the
#       first margin is the tighter of the two now: a body that grew past 311
#       bytes would make the SOLE claimant's reservation exceed 1500, which the
#       carve-out still admits — (h.1c) asserts exactly that, so the section stays
#       readable either way.
#
#       WHAT THE ESTIMATE IS COMPARED AGAINST (#33 review 1): the assertions in
#       (h.1) only prove admission SERIALIZES around the estimate — they never ask
#       whether the estimate actually bounds the spend. (h.2a) closes that: it
#       compares the settled reservation to the AUTHORITATIVE `usage_entries` row
#       the facade wrote for the same request id, and requires reserved ≥ actual.
#       That is the property "conservative" means, and it is the one that fails if
#       the ratio ever drifts back toward an average. `fbx_hold_ms` holds the winner
#       upstream for 3 s — far longer than the burst takes to arrive — so the
#       losers provably contend with a LIVE reservation rather than a settled one.
#       Nothing here can be swept out from under the assertions: the reservation
#       TTL is 1800 s (facade.rs:189) and the expiry sweep only touches expired
#       rows, so a RETAINED reservation stays `reserved` for the whole suite.
# ═════════════════════════════════════════════════════════════════════════════
#     SCOPE — SINGLE REPLICA (#33 review 7, stated so nobody reads more into it).
#     Every request in (h) is fired at $API, i.e. replica A; replica B is not
#     booted until (i). What (h) therefore proves is that CONCURRENT ADMISSION is
#     serialized in the DATABASE — `reserve_llm_budget`'s `sessions FOR UPDATE`
#     plus its guard CTE — which is where the property lives and the only place it
#     could live, since the reservation table is the shared state. It does NOT
#     exercise two facade PROCESSES contending, and it is not evidence about
#     process-local caching in the facade (there is none on this path: the
#     admission decision is one round trip and holds no in-process state between
#     requests). A cross-replica version would assert the same SQL through a
#     second client; it is omitted, not silently covered.
say "(h) LLM budget reservations — fake LiteLLM up"
start_llm

# One facade request, foreground; sets CODE + BODY like the admin_* helpers —
# including the shared-body-file truncation and the 000 hard failure (this
# section reboots the control plane, so "the facade answered 000" must never read
# as "the facade did not 403 us").
llm_post() { # token json
  : > "$UB"
  CODE=$(curl -s -o "$UB" -w '%{http_code}' -X POST \
    -H "authorization: Bearer $1" -H 'content-type: application/json' \
    -d "$2" "$API/internal/llm/v1/messages")
  BODY=$(cat "$UB")
  http_dead "$CODE" "POST /internal/llm/v1/messages" && return 1
  return 0
}
# The request body. `metadata` is a first-class Anthropic field and this dialect's
# body is forwarded re-serialized but otherwise untouched (facade.rs:643), so the
# fake reads these knobs straight off the wire.
llm_body() { # model max_tokens hold_ms usage [reply]
  printf '{"model":"%s","max_tokens":%s,"messages":[{"role":"user","content":"hardening-e2e reservation probe"}],"metadata":{"fbx_hold_ms":%s,"fbx_usage":"%s","fbx_reply":"%s"}}' \
    "$1" "$2" "$3" "$4" "${5:-ok}"
}
# Fire one facade request in the BACKGROUND: status code → "<tag>.code", body →
# "<tag>.body", pid appended to the pidfile. Pids ride a file (never `wait` with
# no argument) because the fakes are also background children of this shell and
# would never exit.
llm_fire() { # pidfile tag token json
  (
    # Per-tag body file, truncated first for the same reason $UB is: curl leaves
    # `-o` untouched when the connection never opens, and these files are read
    # back by tag after the wait. A 000 here needs no `no` of its own — it is a
    # background subshell (the counter would be lost), and the caller's outcome
    # classifier already routes an unrecognised code to its "other" bucket, which
    # fails its assertion.
    : > "$2.body"
    c=$(curl -s -o "$2.body" -w '%{http_code}' -X POST \
      -H "authorization: Bearer $3" -H 'content-type: application/json' \
      -d "$4" "$API/internal/llm/v1/messages")
    printf '%s' "$c" > "$2.code"
  ) &
  echo $! >> "$1"
}
llm_wait() { # pidfile
  local p
  while read -r p; do wait "$p"; done < "$1"
}
res_count() { db "select count(*) from llm_reservations where session_id='$1' and state='$2'"; }
usage_rows() { db "select count(*) from usage_entries where session_id='$1'"; }

say "(h.1) Concurrency — one budget, N parallel requests, exactly one booking fits"
# Pre-initialized because `set -u` is on and (h.2)/(h.3) read H_MODEL: a failed
# fixture must skip its dependants loudly, never abort the whole suite on an
# unbound expansion.
H_OK=0; H1=""; H_MODEL=""; H_HARNESS=""
if live_run hq-agent "sess-h1-$$" "h/reservations"; then H_OK=1; H1="$RUN"; fi
if [ "$H_OK" = 1 ]; then
  # The facade is the LLM audience (Task 5), so this section drives it with a
  # PURPOSE-BUILT llm token rather than the run's legacy 'all' one — the same
  # credential a real sandbox's fake ANTHROPIC_API_KEY now carries.
  forge_audience_token "$H1" llm "sess-h1-$$-llm" \
    && ok "forged an 'llm'-audience session token for the facade" \
    || { no "could not forge the llm-audience token — section (h) cannot run"; H_OK=0; }
  H_MODEL=$(db "select run_spec->>'model' from sessions where id='$H1'")
  H_HARNESS=$(db "select run_spec->>'harness' from sessions where id='$H1'")
  need "$H_MODEL" "the frozen RunSpec carries no model — the facade's model pin would reject every body" || H_OK=0
  # The body shapes below (max_tokens, usage envelope, SSE event types) are the
  # ANTHROPIC dialect's, which facade.rs `dialect_for` selects from the frozen
  # harness. Assert it rather than assume it.
  [ "$H_HARNESS" = claude-agent-sdk ] \
    && ok "the run's frozen harness is 'claude-agent-sdk' ⇒ the Anthropic dialect (the bodies below)" \
    || { no "frozen harness is '$H_HARNESS' (want claude-agent-sdk; the dialect-shaped bodies would not apply)"; H_OK=0; }
fi
if [ "$H_OK" = 1 ]; then
  db "update sessions set run_spec = jsonb_set(jsonb_set(run_spec,'{budgets,max_tokens}','1500'),'{budgets,max_cost_usd}','null') where id='$H1'" >/dev/null
  H_BUDGET=$(db "select run_spec->'budgets'->>'max_tokens' from sessions where id='$H1'")
  [ "$H_BUDGET" = 1500 ] \
    && ok "fixture: the frozen token budget is 1500 — between ONE conservative reservation (1189) and TWO (2378)" \
    || no "fixture failed — frozen max_tokens is '$H_BUDGET' (want 1500); the sizing above no longer holds"

  H_MARK=$(markl)
  : > "$WORK/h1.pids"
  for H_N in 1 2 3 4 5; do
    llm_fire "$WORK/h1.pids" "$WORK/h1-$H_N" "sess-h1-$$-llm" \
      "$(llm_body "$H_MODEL" 1000 3000 normal)"
  done
  llm_wait "$WORK/h1.pids"

  H_PASS=0; H_429=0; H_OTHER=0; H_SHAPED=0
  for H_N in 1 2 3 4 5; do
    H_C=$(cat "$WORK/h1-$H_N.code" 2>/dev/null)
    H_B=$(cat "$WORK/h1-$H_N.body" 2>/dev/null)
    case "$H_C" in
      2*)  H_PASS=$((H_PASS+1));;
      429) H_429=$((H_429+1))
           # The DIALECT-shaped machine slot, not a substring match: Anthropic
           # puts the code in `error.type` with the envelope `type:"error"`
           # (facade.rs `reservation_refusal`), which is what the runner SDK
           # parses. A 429 whose body lost that shape is a regression.
           { [ "$(echo "$H_B" | j "['error']['type']")" = llm_budget_reservation_exceeded ] \
               && [ "$(echo "$H_B" | j "['type']")" = error ]; } && H_SHAPED=$((H_SHAPED+1));;
      *)   H_OTHER=$((H_OTHER+1));;
    esac
  done
  if gt0 "$H_429" "429 reservation refusals in the burst"; then
    [ "$H_429" = "$H_SHAPED" ] \
      && ok "every one of the $H_429 refusals is a 429 whose Anthropic-shaped body carries error.type='llm_budget_reservation_exceeded'" \
      || no "$H_SHAPED of $H_429 refusals carried the dialect-shaped machine code (the runner SDK keys on error.type)"
  fi
  [ "$H_OTHER" = 0 ] \
    && ok "no burst request failed for an unrelated reason (0 responses outside 2xx/429)" \
    || no "$H_OTHER burst request(s) answered neither 2xx nor 429 — the counts below would be meaningless"
  # The sizing check, stated separately from the acceptance above so a future
  # numbers change fails HERE (loudly, with the arithmetic in the message) rather
  # than quietly weakening the concurrency claim.
  [ "$H_PASS" = 1 ] \
    && ok "exactly ONE of 5 concurrent requests was admitted — the other 4 contended with a LIVE reservation (1189 booked vs a 1500 budget)" \
    || no "$H_PASS of 5 concurrent requests were admitted (want exactly 1; re-derive the sizing comment above — reserved=1189, budget=1500)"

  # THE GAP-14 LEDGER ASSERTION: recorded usage can never exceed what was
  # admitted. `usage_entries` rows are written ONLY by a reconcile (authoritative)
  # or the expiry sweep (conservative), both keyed on the request id, so this
  # counts spend events against admissions.
  H_USAGE=$(usage_rows "$H1")
  if gt0 "$H_PASS" "requests ADMITTED by the reservation gate"; then
    [ "$H_USAGE" -le "$H_PASS" ] \
      && ok "recorded usage rows ($H_USAGE) never exceed the admitted requests ($H_PASS)" \
      || no "$H_USAGE usage rows for $H_PASS admitted requests — a refused request spent budget"
  fi
  # …and the positive control for that ≤: usage recording WORKS in this window,
  # so "≤" is not passing because nothing was ever recorded.
  gt0 "$H_USAGE" "usage rows recorded for the admitted request(s)" \
    && ok "POSITIVE CONTROL: the admitted request(s) DID record usage ($H_USAGE row(s)) — the ≤ above is not vacuous"
  # A refusal books NOTHING: the insert is inside the same guarded CTE, so a
  # refused request leaves no row at all (not even a 'released' one).
  H_ROWS=$(db "select count(*) from llm_reservations where session_id='$H1'")
  [ "$H_ROWS" = "$H_PASS" ] \
    && ok "exactly $H_ROWS reservation row(s) exist for $H_PASS admitted request(s) — a refused request books nothing (the guard and the insert are one statement)" \
    || no "llm_reservations rows = $H_ROWS for $H_PASS admitted request(s) (want equal)"
  [ "$(res_count "$H1" reserved)" = 0 ] \
    && ok "no reservation is left 'reserved' once the burst settled (each admitted request reconciled)" \
    || no "$(res_count "$H1" reserved) reservation(s) still 'reserved' after the burst settled"

  # Shared mode presents the DEPLOYMENT key on every model request (the explicit
  # D7 behavior). Asserted here so section (h.3)'s tenant-mode assertion has a
  # baseline it visibly differs from.
  H_AUTH=$(recl "$H_MARK" distinct auth path=/v1/messages)
  [ "$H_AUTH" = "Bearer $MASTER_KEY" ] \
    && ok "shared mode: every model request presented the deployment key, and only that" \
    || no "shared-mode upstream authorization was [$H_AUTH] (want exactly the deployment key)"

  say "(h.1c) The sole-claimant carve-out — one request ALONE, same tiny budget, is ADMITTED"
  # Deviation 1, asserted directly. Without it, the refusals above would be
  # indistinguishable from "this budget is too small to ever make a request", and
  # a run whose per-request estimate exceeds its remaining budget would livelock.
  llm_post "sess-h1-$$-llm" "$(llm_body "$H_MODEL" 1000 0 normal)"
  { [ "$CODE" = 200 ] && ! echo "$BODY" | grep -q llm_budget_reservation_exceeded; } \
    && ok "a lone request against the SAME 1500-token budget is admitted (200) — the refusals above were about CONCURRENCY, not about the budget being unreachable" \
    || no "the sole claimant was refused → $CODE: $BODY (the carve-out at db_lib.rs:5291-5302 is gone; runs whose estimate exceeds their remaining budget would livelock)"
fi

say "(h.2) Retention — a stream that reports NO usage keeps its reservation (never assume zero)"
# design :1122 / facade.rs R13: "we could not parse usage" is NOT proof of zero
# spend, so the booking is RETAINED for the expiry sweep to convert into a
# conservative charge — and a `usage unparsed` marker lands on the timeline. The
# WITH-usage control runs FIRST, on the same run and the same recorders, so the
# "stays reserved" verdict cannot be "the SSE path never charges anything".
if [ "$H_OK" = 1 ] && live_run hq-agent "sess-h2-$$" "h/retention"; then
  H2="$RUN"
  forge_audience_token "$H2" llm "sess-h2-$$-llm" >/dev/null
  db "update sessions set run_spec = jsonb_set(jsonb_set(run_spec,'{budgets,max_tokens}','null'),'{budgets,max_cost_usd}','null') where id='$H2'" >/dev/null
  # A) POSITIVE CONTROL — an SSE response that DOES carry usage events charges.
  llm_post "sess-h2-$$-llm" "$(llm_body "$H_MODEL" 64 0 sse)"
  [ "$CODE" = 200 ] \
    && ok "POSITIVE CONTROL: the usage-carrying SSE response was forwarded (200)" \
    || no "usage-carrying SSE request → $CODE: $BODY"
  H2_CHARGED=0
  for _ in $(seq 1 40); do
    [ "$(res_count "$H2" charged)" -ge 1 ] && { H2_CHARGED=1; break; }
    sleep 0.5
  done
  [ "$H2_CHARGED" = 1 ] \
    && ok "POSITIVE CONTROL: its reservation reconciled to 'charged' — the SSE drain CAN settle a booking" \
    || no "the usage-carrying SSE reservation never reached 'charged' (states: $(db "select coalesce(string_agg(state,','),'none') from llm_reservations where session_id='$H2'"))"
  # (h.2a) IS THE ESTIMATE ACTUALLY CONSERVATIVE? (#33 review 1.) Everything in
  # (h.1) proves admission serializes AROUND the reservation; nothing there
  # compares it to what the request went on to spend, so a ratio that
  # under-counts would keep every assertion green while the hard budget
  # overspends. This is that comparison, against the authoritative source: the
  # facade keys the `usage_entries` row on the SAME id as the reservation
  # (migration 0022 — the id is minted before the insert precisely so the two
  # join), so `reserved_tokens` vs the summed usage columns is a direct
  # bound check on the estimate. Fails the moment the ratio drifts back toward an
  # average, which is what shipped and what review 1 caught.
  H2_CMP=$(db "select r.reserved_tokens::text || ' ' ||
                      (u.input_tokens+u.output_tokens+u.cache_read_tokens+u.cache_write_tokens)::text
               from llm_reservations r
               join usage_entries u on u.external_id = r.id::text
               where r.session_id='$H2' and r.state='charged' limit 1")
  H2_RES=${H2_CMP%% *}; H2_ACT=${H2_CMP##* }
  if need "$H2_CMP" "no charged reservation joined to an authoritative usage row (the bound check below cannot run)"; then
    { [ -n "$H2_RES" ] && [ -n "$H2_ACT" ] && [ "$H2_RES" -ge "$H2_ACT" ]; } \
      && ok "the reservation BOUNDED the spend: $H2_RES tokens booked vs $H2_ACT actually billed for the same request id — conservative, as design :1117 requires" \
      || no "the reservation booked $H2_RES tokens but authoritative usage for that request id was $H2_ACT — the estimate is an average, not a maximum, and the hard budget is overspendable"
  fi
  # B) The retention case — same run, same route, only the usage events removed.
  llm_post "sess-h2-$$-llm" "$(llm_body "$H_MODEL" 64 0 sse_none)"
  [ "$CODE" = 200 ] \
    && ok "the usage-free SSE response was forwarded to the caller unchanged (200)" \
    || no "usage-free SSE request → $CODE: $BODY"
  H2_MARKER=0
  for _ in $(seq 1 40); do
    [ "$(db "select count(*) from events where session_id='$H2' and type='agent.message' and payload->>'text'='model stream completed (usage unparsed)'")" -ge 1 ] \
      && { H2_MARKER=1; break; }
    sleep 0.5
  done
  [ "$H2_MARKER" = 1 ] \
    && ok "the timeline carries the 'model stream completed (usage unparsed)' marker — a call happened and was recorded as unmetered" \
    || no "no 'usage unparsed' marker on the timeline (the drain's zero-usage branch did not run)"
  H2_RESERVED=$(res_count "$H2" reserved)
  H2_RELEASED=$(res_count "$H2" released)
  { [ "$H2_RESERVED" = 1 ] && [ "$H2_RELEASED" = 0 ]; } \
    && ok "the unmetered request's booking is STILL 'reserved' (0 released) — never assume zero; the expiry sweep will charge it conservatively" \
    || no "unmetered booking states: reserved=$H2_RESERVED released=$H2_RELEASED (want 1 and 0 — a release here silently under-charges)"
fi

say "(h.3) Ceiling + release — tenant key mode, FLUIDBOX_LLM_MAX_CONCURRENT_RESERVATIONS=2"
# Both knobs are BOOT-resolved (the key mode in `Config::from_env`; the ceiling in
# a process-lifetime OnceLock at facade.rs:207-226), so this restarts rather than
# mutating a live process — the same discipline section (j) uses for the governor.
# Tenant mode is exercised here because the RELEASE path this section asserts (R1
# and R5) is reached through it, and because it is the only posture where "the
# master key never rides a model request" is observable.
LLM_KEY_MODE=tenant; LLM_MAX_RES=2
if [ "$H_OK" = 1 ] \
   && restart_server "control plane rebooted with FLUIDBOX_LLM_KEY_MODE=tenant, reservation ceiling 2"; then

  # (h.3a) A tenant key that cannot be provisioned ⇒ the pre-existing 503 code,
  # and the booking is RELEASED (R1 — nothing was sent). Run FIRST, before any
  # successful mint: `ensure_tenant_key` caches in memory AND seals the key in the
  # DB, so once a mint succeeds this path is unreachable for the rest of the run.
  llm_keygen fail
  H3_MARK=$(markl)
  if live_run hq-agent "sess-h3a-$$" "h/key-unavailable"; then
    H3A="$RUN"
    forge_audience_token "$H3A" llm "sess-h3a-$$-llm" >/dev/null
    llm_post "sess-h3a-$$-llm" "$(llm_body "$H_MODEL" 64 0 normal)"
    { [ "$CODE" = 503 ] \
        && [ "$(echo "$BODY" | j "['error']['type']")" = tenant_llm_key_unavailable ]; } \
      && ok "an unmintable tenant key still answers 503 'tenant_llm_key_unavailable' (the secrets-e2e code, unchanged by the reservation work)" \
      || no "unmintable tenant key → $CODE: $BODY (want 503 tenant_llm_key_unavailable)"
    H3A_REL=$(res_count "$H3A" released)
    H3A_RES=$(res_count "$H3A" reserved)
    { [ "$H3A_REL" = 1 ] && [ "$H3A_RES" = 0 ]; } \
      && ok "…and its booking was RELEASED (R1: the refusal is upstream of the dial, so non-dispatch is PROVEN)" \
      || no "key-unavailable booking states: released=$H3A_REL reserved=$H3A_RES (want 1 and 0)"
    # ZERO model-plane traffic for that request. Read from H3_MARK now, and read
    # the SAME window again after (h.3b) succeeds — the second read is this zero's
    # positive control (the recorder demonstrably records /v1/messages in it).
    H3A_MSGS=$(recl "$H3_MARK" count path=/v1/messages)
    [ "$H3A_MSGS" = 0 ] \
      && ok "the 503 reached the upstream ZERO times (the model plane was never dialed)" \
      || no "$H3A_MSGS model request(s) went upstream despite the key refusal"
  fi

  # (h.3b) THE CEILING. Budgets are NULLed so ONLY the concurrency ceiling can
  # bind (the outcome mapping checks `under_ceiling` first, but with no budget the
  # verdict is unambiguous). Three parallel requests against a ceiling of 2: the
  # first two book, the third finds `a.n = 2` and `2 < 2` false.
  llm_keygen ok
  if live_run hq-agent "sess-h3b-$$" "h/ceiling"; then
    H3B="$RUN"
    forge_audience_token "$H3B" llm "sess-h3b-$$-llm" >/dev/null
    db "update sessions set run_spec = jsonb_set(jsonb_set(run_spec,'{budgets,max_tokens}','null'),'{budgets,max_cost_usd}','null') where id='$H3B'" >/dev/null
    # `->>'max_tokens'` returns the empty string for JSON null, for a missing key,
    # for a missing `budgets` object AND for a missing ROW — so `= ""` alone would
    # pass even if this session did not exist. Floor: the row must exist and the
    # key must be PRESENT, and only then is its value asserted to be JSON null
    # (via `<null>`, which coalesce can produce from nothing else here).
    H3B_KEYS=$(db "select count(*) from sessions where id='$H3B' and run_spec->'budgets' ? 'max_tokens'")
    H3B_BUDGET=$(db "select coalesce(run_spec->'budgets'->>'max_tokens','<null>') from sessions where id='$H3B'")
    if gt0 "$H3B_KEYS" "the ceiling run's row + its frozen budgets.max_tokens key"; then
      [ "$H3B_BUDGET" = "<null>" ] \
        && ok "fixture: this run has NO token budget (budgets.max_tokens is present and JSON null) — only the concurrency ceiling can refuse" \
        || no "fixture failed — the ceiling run still carries a token budget ('$H3B_BUDGET')"
    fi
    : > "$WORK/h3b.pids"
    for H_N in 1 2 3; do
      llm_fire "$WORK/h3b.pids" "$WORK/h3b-$H_N" "sess-h3b-$$-llm" \
        "$(llm_body "$H_MODEL" 64 4000 normal)"
    done
    llm_wait "$WORK/h3b.pids"
    H3B_PASS=0; H3B_CEIL=0; H3B_OTHER=0
    for H_N in 1 2 3; do
      H_C=$(cat "$WORK/h3b-$H_N.code" 2>/dev/null)
      H_B=$(cat "$WORK/h3b-$H_N.body" 2>/dev/null)
      case "$H_C" in
        2*)  H3B_PASS=$((H3B_PASS+1));;
        429) [ "$(echo "$H_B" | j "['error']['type']")" = llm_reservation_ceiling_exceeded ] \
               && H3B_CEIL=$((H3B_CEIL+1)) || H3B_OTHER=$((H3B_OTHER+1));;
        *)   H3B_OTHER=$((H3B_OTHER+1));;
      esac
    done
    if gt0 "$H3B_PASS" "requests admitted under the ceiling of 2"; then
      { [ "$H3B_CEIL" = 1 ] && [ "$H3B_PASS" = 2 ] && [ "$H3B_OTHER" = 0 ]; } \
        && ok "3 overlapping requests against a ceiling of 2 → exactly ONE 'llm_reservation_ceiling_exceeded' (2 admitted, 0 other outcomes)" \
        || no "ceiling outcome: admitted=$H3B_PASS ceiling-refused=$H3B_CEIL other=$H3B_OTHER (want 2 / 1 / 0)"
    fi
    # Tenant mode's custody claim, from the recorder: the MODEL plane presented
    # the minted virtual key, and the master key appeared ONLY on the admin plane.
    H3_AUTH=$(recl "$H3_MARK" distinct auth path=/v1/messages)
    H3_MINT=$(recl "$H3_MARK" first auth path=/key/generate)
    { [ -n "$H3_AUTH" ] && [ "$H3_AUTH" != "Bearer $MASTER_KEY" ]; } \
      && ok "tenant mode: the model plane presented a per-tenant virtual key, never the deployment master key" \
      || no "tenant-mode model-plane authorization was [$H3_AUTH] — the master key must not ride a model request"
    [ "$H3_MINT" = "Bearer $MASTER_KEY" ] \
      && ok "…and the master key appears ONLY on the /key/generate admin plane (the D7 confinement)" \
      || no "/key/generate presented [$H3_MINT] (want the deployment master key)"
    # The deferred positive control for (h.3a)'s ZERO: the SAME window now holds
    # model-plane requests, so that zero was a real absence, not a dead recorder.
    H3_MSGS_NOW=$(recl "$H3_MARK" count path=/v1/messages)
    gt0 "$H3_MSGS_NOW" "model-plane requests recorded in the window (h.3a) read as zero" \
      && ok "POSITIVE CONTROL: that same recorder window now holds $H3_MSGS_NOW model request(s) — (h.3a)'s ZERO was a real absence"
  fi

  # (h.3c) RELEASE on a proven non-execution. A 401 is the facade's own proof that
  # the request never executed upstream (the basis of its exactly-once replay), so
  # the booking is released — and the rejection is forwarded VERBATIM, never
  # re-shaped and never re-provisioned into (this body is the provider-originated
  # shape facade.rs:834-835 excludes from `virtual_key_rejected`). Its OWN run, so
  # "the reservation" is unambiguous: exactly one row exists.
  if live_run hq-agent "sess-h3c-$$" "h/401-release"; then
    H3C="$RUN"
    forge_audience_token "$H3C" llm "sess-h3c-$$-llm" >/dev/null
    llm_post "sess-h3c-$$-llm" "$(llm_body "$H_MODEL" 64 0 normal unauthorized)"
    { [ "$CODE" = 401 ] && [ "$BODY" = "$LLM_401_BODY" ]; } \
      && ok "the upstream 401 was forwarded VERBATIM (status and bytes identical to what the upstream sent)" \
      || no "401 forwarding → $CODE: $BODY (want 401 and exactly '$LLM_401_BODY')"
    H3C_ROWS=$(db "select count(*) from llm_reservations where session_id='$H3C'")
    if gt0 "$H3C_ROWS" "reservation rows booked by the 401 request"; then
      H3C_STATE=$(db "select state from llm_reservations where session_id='$H3C'")
      [ "$H3C_STATE" = released ] \
        && ok "its reservation is 'released', NOT 'charged' — a 401 is proof of non-execution, so the budget is given back" \
        || no "the 401 request's reservation is '$H3C_STATE' (want released; 'charged' would bill a request that never ran)"
    fi
    [ "$(usage_rows "$H3C")" = 0 ] \
      && ok "…and nothing was recorded as usage for it" \
      || no "the 401 request recorded usage ($(usage_rows "$H3C") row(s))"
  fi

  # NOT ASSERTED — the OTHER pre-existing 503, `tenant_llm_keys_required`. It
  # fires only under FLUIDBOX_REQUIRE_SSO=1 + shared mode (llm_keys.rs
  # `KeySource::RefuseSsoShared`), and REQUIRE_SSO=1 confines the admin token to
  # /v1/admin/* — which would break every fixture, forge and assertion in this
  # file. Proving it needs a boot whose whole identity posture differs, which is
  # exactly what scripts/secrets-e2e.sh already owns; asserting a weaker proxy
  # here would add no signal. The half this suite CAN reach —
  # `tenant_llm_key_unavailable` — is asserted in (h.3a), including that the
  # reservation work did not change its status or its code.
fi
# Hand the knobs back UNCONDITIONALLY — including on the path where (h) was
# skipped entirely — so section (i) boots its replica, and section (j) reboots
# this one, on the shipped defaults. Replica A itself stays on whatever boot it
# last got until (j) restarts it; section (i) drives no facade traffic at all.
LLM_KEY_MODE=shared; LLM_MAX_RES=""

# ═════════════════════════════════════════════════════════════════════════════
# (i) Two-replica coordination (Task 6, E12; Gap 13; migration 0021).
#     Acceptance bullet: "two replicas on one database: a decided approval emits
#     exactly ONE pair of ledger rows and releases every waiter; each delivery is
#     POSTed once; a driver without the lease cannot mutate a session."
#
#     THE FIXTURE: two processes, distinct public+internal ports, ONE database,
#     ONE runtime role, one shared callback sink. Nothing is mocked — the second
#     replica is the same binary with the same env, so every worker it runs (the
#     delivery claim loop, the finalize driver, approval expiry, the
#     `fluidbox_approvals` LISTEN relay) is genuinely live and genuinely racing
#     the first. Replica B is stopped at the END of this section so section (j),
#     whose governor is in-memory and per-replica, still measures one process.
#
#     WHY IT IS A REAL TEST AND NOT A RESTATEMENT: before Task 6 every awakened
#     waiter ledgered its own `approval.decided` + `tool.decision`, so N
#     re-attached waiters produced N pairs; and the delivery poll took no claim, so
#     both replicas POSTed the same row. Both are now single-winner in the DB —
#     the decision CAS carries the events inside its transaction, and the delivery
#     poll claims `for update skip locked`. The assertions below are exactly those
#     two counts, plus the notify hop that makes the first one fast, plus the lease
#     that makes the driver single-writer.
# ═════════════════════════════════════════════════════════════════════════════
say "(i) Two-replica coordination — callback sink + replica B"
start_sink

# One /permission call against a NAMED replica — the base URL is the only thing
# that differs from `sess_perm`, and naming the replica is what makes a failure
# message say WHICH process misbehaved.
perm_at() { # base sid token json
  curl -s -X POST -H "authorization: Bearer $3" -H 'content-type: application/json' \
    -d "$4" "$1/internal/sessions/$2/permission"
}
perm_body() { # tool_call_id
  printf '{"tool_call_id":"%s","tool":"mcp__hq__hq_search","input":{"query":"i"}}' "$1"
}
# Count rows on the OPERATOR-VISIBLE timeline (GET /v1/sessions/{id}/events),
# optionally narrowed by one payload field. Deliberately the API and not psql: the
# single-emission property is a claim about what an operator (and the SSE stream
# built on the same `events_after` query) sees.
ev_count() { # sid type [payload-key] [payload-value]
  admin_get "/v1/sessions/$1/events?limit=1000"
  echo "$BODY" | python3 -c "
import sys, json
t, k, v = sys.argv[1], sys.argv[2], sys.argv[3]
n = 0
for r in json.load(sys.stdin).get('events', []):
    if r.get('type') != t:
        continue
    if k and str((r.get('payload') or {}).get(k, '')) != v:
        continue
    n += 1
print(n)
" "$2" "${3:-}" "${4:-}" 2>/dev/null
}
now_ms() { python3 -c 'import time;print(int(time.time()*1000))'; }

I_OK=0
if boot_replica_b; then
  I_OK=1
  ok "replica B healthy on :$API_PORT_B (public) / :$API_PORT_B_INT (internal), same DB + runtime role"
else
  no "replica B did not become healthy — every assertion in section (i) is skipped: $(tail -30 "$SERVER_B_LOG")"
fi

if [ "$I_OK" = 1 ]; then
  # Prove the second process is a REAL peer before asserting anything about it:
  # it serves the same tenant's data from the same database.
  # `j` interpolates its argument as a SUFFIX of `d`, so the length is spelled as
  # a method call rather than `len(...)` (which would evaluate to `dlen(...)`).
  admin_get "/v1/agents"
  I_AGENTS_A=$(echo "$BODY" | j "['agents'].__len__()")
  I_AGENTS_B=$(curl -s -H "$AH" "$API_B/v1/agents" | j "['agents'].__len__()")
  { [ -n "$I_AGENTS_B" ] && [ "$I_AGENTS_A" = "$I_AGENTS_B" ]; } \
    && ok "both replicas serve the SAME database (identical agent count: $I_AGENTS_A)" \
    || no "replica A lists $I_AGENTS_A agents, replica B lists '$I_AGENTS_B' — they are not on one DB, so nothing below tests coordination"
fi

say "(i.1) Single emission — one decided approval, TWO blocked waiters, ONE pair of ledger rows"
mcp_mode "$PROTO_SNAP" ok
if [ "$I_OK" = 1 ] && live_run hq-appr-agent "sess-i1-$$" "i/single-emission"; then
  I1="$RUN"
  ( perm_at "$API"   "$I1" "sess-i1-$$" "$(perm_body i1)" > "$WORK/i1-a" 2>/dev/null ) & I1PA=$!
  ( perm_at "$API_B" "$I1" "sess-i1-$$" "$(perm_body i1)" > "$WORK/i1-b" 2>/dev/null ) & I1PB=$!
  I1_AID=$(pending_approval_id "$I1")
  if need "$I1_AID" "no approval became pending — neither replica paused, so there is nothing to decide"; then
    # PRECONDITION, not decoration: both callers must still be BLOCKED when the
    # decision lands. A waiter that had already returned would make "exactly one
    # pair" trivially true (one waiter, one pair) and prove nothing.
    { kill -0 "$I1PA" 2>/dev/null && kill -0 "$I1PB" 2>/dev/null; } \
      && ok "both replicas' /permission calls are still blocked on the one approval row" \
      || no "a waiter returned before the decision (replica A: $(kill -0 "$I1PA" 2>/dev/null && echo blocked || echo returned); replica B: $(kill -0 "$I1PB" 2>/dev/null && echo blocked || echo returned)) — the two-waiter race is not being exercised"
    admin_post "/v1/approvals/$I1_AID/decision" '{"decision":"approved_once"}'
    [ "$CODE" = 200 ] \
      && ok "the approval was decided ONCE, on replica A" \
      || no "decision on replica A → $CODE: $BODY"
  fi
  wait "$I1PA"; wait "$I1PB"
  I1_A=$(cat "$WORK/i1-a" 2>/dev/null); I1_B=$(cat "$WORK/i1-b" 2>/dev/null)
  echo "$I1_A" | grep -q '"decision": *"allow"' \
    && ok "replica A's waiter returned allow" \
    || no "replica A's waiter did not allow: $I1_A"
  echo "$I1_B" | grep -q '"decision": *"allow"' \
    && ok "replica B's waiter returned allow (the decision crossed processes)" \
    || no "replica B's waiter did not allow: $I1_B"
  # THE LOAD-BEARING COUNTS. Both rows are written INSIDE the decision CAS
  # (`decide_approval_tx` + `approval_decision_events`), so the number of waiters
  # cannot multiply them.
  I1_DECIDED=$(ev_count "$I1" approval.decided approval_id "$I1_AID")
  I1_TOOLDEC=$(ev_count "$I1" tool.decision tool_call_id i1)
  [ "$I1_DECIDED" = 1 ] \
    && ok "exactly ONE 'approval.decided' on the timeline for that approval (two waiters, one row)" \
    || no "approval.decided rows for approval $I1_AID = $I1_DECIDED (want exactly 1; >1 is the pre-Task-6 per-waiter emission)"
  [ "$I1_TOOLDEC" = 1 ] \
    && ok "exactly ONE 'tool.decision' for that intent (two waiters, one row)" \
    || no "tool.decision rows for tool_call_id 'i1' = $I1_TOOLDEC (want exactly 1; >1 means waiters are emitting again)"

  # POSITIVE CONTROL, same run + same reader + same window: a SECOND decision on
  # this session DOES add a second pair. Without it, "exactly 1" would also be the
  # reading of a timeline that stopped recording.
  ( perm_at "$API" "$I1" "sess-i1-$$" "$(perm_body i1b)" > "$WORK/i1-c" 2>/dev/null ) & I1PC=$!
  I1_AID2=$(pending_approval_id "$I1")
  if need "$I1_AID2" "the control approval never became pending"; then
    admin_post "/v1/approvals/$I1_AID2/decision" '{"decision":"approved_once"}'
  fi
  wait "$I1PC"
  I1_TOTAL=$(ev_count "$I1" approval.decided)
  I1_TOOLTOTAL=$(ev_count "$I1" tool.decision tool_call_id i1b)
  if gt0 "$I1_TOOLTOTAL" "tool.decision rows for the control intent"; then
    { [ "$I1_TOTAL" = 2 ] && [ "$I1_TOOLTOTAL" = 1 ]; } \
      && ok "POSITIVE CONTROL: a second decision on the same run added exactly one more pair (2 approval.decided total) — the recorder is live, so the ONEs above are real" \
      || no "control decision: approval.decided total=$I1_TOTAL, tool.decision for 'i1b'=$I1_TOOLTOTAL (want 2 and 1)"
  fi
fi

say "(i.2) The NOTIFY relay — a decision on replica A releases a waiter on replica B in well under its poll floor"
# The waiter's fallback is a ≤2 s poll anchored at the moment it read the row as
# pending (internal.rs:742, `tick = until_expiry.min(Duration::from_secs(2))`).
# The measurement below is deliberately arranged so a MISSED notify cannot look
# fast: `pending_approval_id` polls at 0.5 s granularity and we then sleep another
# 0.5 s, so the decision lands 0.5-1.0 s after the waiter's anchor — meaning a
# poll-driven wake could not arrive sooner than ~1.0 s after the decision. A
# NOTIFY-driven wake is one LISTEN hop plus one indexed approval read.
#
# THRESHOLD: 400 ms. That is comfortably above the notify path (a broadcast wake,
# one primary-key read and the HTTP response, tens of ms even on a loaded runner)
# and comfortably below the ~1.0 s floor computed above, so the two outcomes are
# not confusable and no statistics are needed. The elapsed time is measured from
# BEFORE the decision request is sent, so it over-counts by that request's own
# latency — the conservative direction for a "must be small" assertion. Two
# samples, both required to pass.
I2_THRESHOLD_MS=400
if [ "$I_OK" = 1 ] && live_run hq-appr-agent "sess-i2-$$" "i/notify"; then
  I2="$RUN"
  for I2_K in 1 2; do
    ( R=$(perm_at "$API_B" "$I2" "sess-i2-$$" "$(perm_body "i2-$I2_K")" 2>/dev/null)
      printf '%s\n%s\n' "$(now_ms)" "$R" > "$WORK/i2-$I2_K" ) & I2P=$!
    I2_AID=$(pending_approval_id "$I2")
    if need "$I2_AID" "sample $I2_K: no approval became pending on replica B"; then
      # Give replica B's handler time to enter its wait loop before the decision
      # lands. `kill -0` proves ONLY that the curl process has not exited, i.e.
      # that B has not answered yet — it is NOT evidence that B is inside the
      # wait loop (#33 review 6; the earlier wording claimed it was). See the
      # NOT-ASSERTED note under this block for exactly what that leaves open.
      sleep 0.5
      kill -0 "$I2P" 2>/dev/null \
        && ok "sample $I2_K: replica B has not answered yet (the request is still outstanding), so the measurement below has something to measure" \
        || no "sample $I2_K: replica B's waiter returned before the decision — the latency below would measure nothing"
      I2_T0=$(now_ms)
      admin_post "/v1/approvals/$I2_AID/decision" '{"decision":"approved_once"}'
      [ "$CODE" = 200 ] || no "sample $I2_K: decision on replica A → $CODE: $BODY"
    else
      I2_T0=$(now_ms)
    fi
    wait "$I2P"
    I2_T1=$(head -1 "$WORK/i2-$I2_K" 2>/dev/null)
    I2_RESP=$(tail -n +2 "$WORK/i2-$I2_K" 2>/dev/null)
    if need "$I2_T1" "sample $I2_K: replica B's waiter recorded no completion timestamp"; then
      I2_MS=$(( I2_T1 - I2_T0 ))
      echo "$I2_RESP" | grep -q '"decision": *"allow"' \
        && ok "sample $I2_K: replica B's waiter returned allow" \
        || no "sample $I2_K: replica B's waiter returned '$I2_RESP' (want allow)"
      { [ "$I2_MS" -ge 0 ] && [ "$I2_MS" -le "$I2_THRESHOLD_MS" ]; } \
        && ok "sample $I2_K: replica B released ${I2_MS}ms after the decision on replica A — far under the ~1000ms a poll-driven wake could have managed" \
        || no "sample $I2_K: replica B released ${I2_MS}ms after the decision (want ≤${I2_THRESHOLD_MS}ms; ~1000ms+ means the pg_notify relay did not cross and it fell back to the ≤2s poll)"
    fi
  done
fi
# NOT ASSERTED — "the wake was caused BY the notification" (#33 review 6, and the
# honest reading of what (i.2) delivers). The measurement is sound about LATENCY:
# a poll-driven wake is anchored at the waiter's first read of the pending row and
# ticks at ≤2 s, so ≤400 ms is inconsistent with the poll path. What is NOT proven
# is that the waiter had ALREADY performed that first read when the decision
# landed. The pending row becomes visible to the fixture at INSERT time, which
# precedes the handler entering its wait loop; if replica B were descheduled
# across that gap for longer than the 0.5 s sleep, its first read would find the
# row already decided and return fast with no LISTEN/NOTIFY involved — green, for
# the wrong reason. Nothing observable from outside distinguishes the two: the
# handler exposes no "I am waiting" signal, and adding one is a server change
# (`internal.rs`), not a script change. Two independent samples must BOTH be fast,
# so a false green needs the stall to recur, but that is a probability argument,
# not a proof. Treat (i.2) as "cross-replica release is fast enough to rule out
# the poll floor", not as "the NOTIFY fired". The relay itself — that the decision
# transaction emits on `fluidbox_approvals` — is asserted in `fluidbox-db`'s own
# tests, where it is a property of the statement rather than of a race.

say "(i.3) Delivery claims — both workers live, ONE POST per delivery"
I3_N=14
I3_SUB=""; I3_TOK=""
if [ "$I_OK" = 1 ]; then
  admin_post "/v1/triggers" \
    "{\"agent\":\"plain-agent\",\"name\":\"i3-sub-$$\",\"task_template\":\"hardening-e2e delivery\",\"autonomous\":true,\"callback_url\":\"http://127.0.0.1:$SINK_PORT/cb\"}"
  I3_SUB=$(echo "$BODY" | j "['subscription']['id']")
  I3_TOK=$(echo "$BODY" | j "['token']")
  { [ "$CODE" = 200 ] && [ -n "$I3_SUB" ] && [ -n "$I3_TOK" ]; } \
    && ok "subscription created with a loopback signed-callback destination" \
    || no "subscription create → $CODE: $BODY"
fi
if [ -n "$I3_SUB" ] && [ -n "$I3_TOK" ]; then
  I3_MARK=$(marks)
  # Invocations ALTERNATE between the replicas, so both processes are proven to
  # serve the trigger API too — and the deliveries they enqueue are indistinguish-
  # able afterwards, which is the point (any worker may claim any row).
  I3_INVOKED=0
  for I3_K in $(seq 1 $I3_N); do
    if [ $(( I3_K % 2 )) -eq 0 ]; then I3_BASE="$API_B"; else I3_BASE="$API"; fi
    I3_SID=$(curl -s -X POST -H "authorization: Bearer $I3_TOK" -H 'content-type: application/json' \
      -d '{}' "$I3_BASE/v1/triggers/$I3_SUB/invoke" | j "['session_id']")
    [ -n "$I3_SID" ] && I3_INVOKED=$((I3_INVOKED+1))
  done
  if gt0 "$I3_INVOKED" "trigger invocations that created a run"; then
    [ "$I3_INVOKED" = "$I3_N" ] \
      && ok "$I3_INVOKED runs invoked (alternating replicas — both serve the trigger API)" \
      || no "only $I3_INVOKED of $I3_N invocations created a run"
  fi
  # Wait for every run to terminalize AND for its delivery row to be POSTed.
  I3_DELIVERED=0
  I3_DEADLINE=$(( $(date +%s) + 420 ))
  while [ "$(date +%s)" -lt "$I3_DEADLINE" ]; do
    I3_DELIVERED=$(db "select count(*) from result_deliveries where subscription_id='$I3_SUB' and status='delivered'")
    [ "$I3_DELIVERED" = "$I3_INVOKED" ] && break
    sleep 2
  done
  I3_ROWS=$(db "select count(*) from result_deliveries where subscription_id='$I3_SUB'")
  if gt0 "$I3_ROWS" "delivery rows enqueued for the subscription"; then
    { [ "$I3_ROWS" = "$I3_INVOKED" ] && [ "$I3_DELIVERED" = "$I3_INVOKED" ]; } \
      && ok "all $I3_ROWS deliveries reached status='delivered' (one row per run, exactly-once by the terminal-entry funnel)" \
      || no "delivery rows=$I3_ROWS delivered=$I3_DELIVERED for $I3_INVOKED runs — the counts below would be misleading"
  fi
  # THE LOAD-BEARING COUNT: with two claim loops racing, the sink saw each
  # delivery exactly once. Before the claim this was two POSTs per row.
  I3_POSTS=$(recs "$I3_MARK" count)
  # Snapshotted BEFORE the replay below, because this recorder window is
  # open-ended: read afterwards it would also contain the replay's rows and the
  # subset check at the end of this section would be vacuously true.
  I3_IDS1_SET=$(recs "$I3_MARK" distinct delivery)
  I3_IDS=$(echo "$I3_IDS1_SET" | wc -w | tr -d ' ')
  if gt0 "$I3_POSTS" "POSTs recorded by the callback sink"; then
    { [ "$I3_POSTS" = "$I3_DELIVERED" ] && [ "$I3_IDS" = "$I3_DELIVERED" ]; } \
      && ok "the sink recorded $I3_POSTS POSTs carrying $I3_IDS DISTINCT x-fluidbox-delivery ids for $I3_DELIVERED deliveries — exactly one POST each, with both workers live" \
      || no "sink POSTs=$I3_POSTS distinct ids=$I3_IDS for $I3_DELIVERED deliveries (want all three equal; POSTs>ids means two replicas attempted one row)"
  fi
  I3_SIGNED=$(recs "$I3_MARK" all_have signed)
  case "$I3_SIGNED" in
    OK\ *) ok "every POST carried an x-fluidbox-signature ($I3_SIGNED)";;
    NONE)  no "no POSTs recorded — the signature assertion would be vacuous";;
    *)     no "a callback went out UNSIGNED ($I3_SIGNED)";;
  esac

  # ── Did BOTH workers actually claim, or was one idle? ────────────────────
  # `mark_delivery_attempt` CLEARS `claimed_by` on completion (db_lib.rs
  # `claimed_by = null`), so the only way to see who claimed is to sample WHILE
  # rows are in flight. The burst below makes that deterministic rather than
  # lucky: all $I3_N rows are reset to due at once, the per-tick claim limit is 10
  # (deliveries.rs:132), and the first claimant then spends 10 × ${SINK_HOLD_MS}ms
  # working through its batch sequentially — longer than the other worker's 3 s
  # tick, so the remaining rows are necessarily claimed by the OTHER replica.
  # The replay is deliberate: the same delivery id arrives at the sink twice,
  # which is precisely the at-least-once contract receivers dedup on, so this
  # window asserts nothing about POST counts.
  I3_MARK2=$(marks)
  db "update result_deliveries set status='pending', attempts=0, next_attempt_at=now(),
      claimed_by=null, claimed_until=null, delivered_at=null
      where subscription_id='$I3_SUB'" >/dev/null
  I3_PENDING=$(db "select count(*) from result_deliveries where subscription_id='$I3_SUB' and status='pending'")
  [ "$I3_PENDING" = "$I3_ROWS" ] \
    && ok "fixture: all $I3_PENDING deliveries were reset to due AT ONCE (a burst larger than one tick's claim limit of 10)" \
    || no "fixture failed — only $I3_PENDING of $I3_ROWS rows are pending; the two-round claim argument does not hold"
  I3_SEEN=""
  I3_OBS_DEADLINE=$(( $(date +%s) + 120 ))
  while [ "$(date +%s)" -lt "$I3_OBS_DEADLINE" ]; do
    I3_NOW=$(db "select coalesce(string_agg(distinct claimed_by::text, ' '), '') from result_deliveries where subscription_id='$I3_SUB' and claimed_by is not null")
    for I3_ONE in $I3_NOW; do
      case " $I3_SEEN " in
        *" $I3_ONE "*) ;;
        *) I3_SEEN="$I3_SEEN $I3_ONE";;
      esac
    done
    I3_DISTINCT=$(echo "$I3_SEEN" | wc -w | tr -d ' ')
    [ "$I3_DISTINCT" -ge 2 ] && break
    [ "$(db "select count(*) from result_deliveries where subscription_id='$I3_SUB' and status='pending'")" = 0 ] && break
    sleep 0.3
  done
  I3_DISTINCT=$(echo "$I3_SEEN" | wc -w | tr -d ' ')
  if gt0 "$I3_DISTINCT" "distinct claim owners observed while deliveries were in flight"; then
    [ "$I3_DISTINCT" = 2 ] \
      && ok "TWO distinct replica ids were observed holding delivery claims — the second worker is genuinely doing work, not idle while the first drains everything" \
      || no "only $I3_DISTINCT distinct claim owner(s) observed across a $I3_ROWS-row burst (want 2 — with a per-tick limit of 10 the second round MUST fall to the other replica unless its worker is dead)"
  fi
  # The replay window's own shape: the SAME ids arriving again. Asserted as a real
  # SUBSET test against the pre-replay snapshot, not as a count comparison — a
  # re-attempt must reuse the delivery row's id, which is exactly what makes
  # at-least-once safe for a receiver that dedups on `x-fluidbox-delivery`.
  I3_POSTS2=$(recs "$I3_MARK2" count)
  I3_IDS2_SET=$(recs "$I3_MARK2" distinct delivery)
  I3_IDS2=$(echo "$I3_IDS2_SET" | wc -w | tr -d ' ')
  I3_NEWIDS=0
  for I3_ONE in $I3_IDS2_SET; do
    case " $I3_IDS1_SET " in
      *" $I3_ONE "*) ;;
      *) I3_NEWIDS=$((I3_NEWIDS+1));;
    esac
  done
  if gt0 "$I3_IDS2" "distinct delivery ids seen during the forced replay"; then
    [ "$I3_NEWIDS" = 0 ] \
      && ok "every one of the $I3_IDS2 replayed ids (across $I3_POSTS2 POSTs) is one the sink had ALREADY seen — a re-attempt reuses the delivery id, which is what receivers dedup on" \
      || no "$I3_NEWIDS of $I3_IDS2 replayed deliveries carried an id the sink had never seen (a re-attempt must never mint a new x-fluidbox-delivery)"
  fi
fi

say "(i.4) Lease + epoch fencing — a foreign lease stops the fenced driver, and expiring it hands over"
# The fence's operational meaning, driven end to end. A session whose lease is held
# by a THIRD (dead) replica may not be mutated by either live driver: both call
# `hold_lease` first (orchestrator.rs:593) and, getting None, RELEASE the
# finalization claim and return. The request-side wind-down is deliberately
# unfenced (orchestrator.rs:458-464 — a lease held elsewhere must never swallow a
# user's cancel), so the run still enters `cancelling` and then stops there.
#
# Forcing the epoch directly (the plan's psql fixture) would prove less than this:
# a manual bump is picked up by the SAME owner on its next renew (the epoch moves
# only on an owner CHANGE), so it self-heals and no assertion could fail. A
# FOREIGN owner with a live lease is the state the fence actually exists for, and
# it is observable in both directions.
if [ "$I_OK" = 1 ] && live_run plain-agent "sess-i4-$$" "i/lease"; then
  I4="$RUN"
  I4_FOREIGN=$(db "select gen_random_uuid()")
  need "$I4_FOREIGN" "could not mint a foreign replica id" || I4_FOREIGN=""
  if [ -n "$I4_FOREIGN" ]; then
    db "update sessions set orchestrator_owner_id='$I4_FOREIGN',
        orchestrator_lease_until = now() + interval '150 seconds' where id='$I4'" >/dev/null
    I4_EPOCH0=$(db "select orchestrator_epoch from sessions where id='$I4'")
    [ "$(db "select orchestrator_owner_id from sessions where id='$I4'")" = "$I4_FOREIGN" ] \
      && ok "fixture: a THIRD replica id holds an unexpired driver lease (epoch $I4_EPOCH0)" \
      || no "fixture failed — the foreign lease was not installed, so nothing below is fenced"

    admin_post "/v1/sessions/$I4/cancel" '{}'
    { [ "$CODE" = 200 ] || [ "$CODE" = 202 ]; } \
      && ok "the cancel was ACCEPTED by replica A despite the foreign lease (the request path is unfenced by design)" \
      || no "cancel → $CODE: $BODY"
    I4_WIND=""
    for _ in $(seq 1 30); do
      I4_WIND=$(db "select status from sessions where id='$I4'")
      case "$I4_WIND" in cancelling|finalizing|completed|failed|cancelled|budget_exceeded) break;; esac
      sleep 0.5
    done
    [ "$I4_WIND" = cancelling ] \
      && ok "the run entered 'cancelling' (the intent materialized) but got no further" \
      || no "the run's status after the cancel is '$I4_WIND' (want cancelling; a terminal status means the fence did not hold)"

    # THE ea11853 ASSERTION, and it is fail-capable in exactly the right way:
    # a fenced driver RELEASES the finalization claim on its way out, so the next
    # replica's 20 s finalize worker can claim again and `attempts` keeps rising.
    # If the claim were left stamped, `claim_finalization`'s predicate would refuse
    # for the full 420 s stale window and this counter would be FROZEN.
    # `coalesce((select …), 0)` rather than `coalesce(attempts, 0)`: the latter
    # returns ZERO ROWS (an empty string here) if the intent is gone, which would
    # break the arithmetic comparison instead of failing the assertion cleanly.
    I4_ATT0=$(db "select coalesce((select attempts from session_finalizations where session_id='$I4'), 0)")
    sleep 25
    I4_ATT1=$(db "select coalesce((select attempts from session_finalizations where session_id='$I4'), 0)")
    I4_STATUS=$(db "select status from sessions where id='$I4'")
    if gt0 "$I4_ATT1" "finalization drive attempts recorded while the lease was foreign"; then
      [ "$I4_ATT1" -gt "$I4_ATT0" ] \
        && ok "drivers KEPT trying and kept being turned away ($I4_ATT0 → $I4_ATT1 attempts across 25s > the 20s worker tick) — the fenced driver releases its claim instead of squatting it" \
        || no "finalization attempts froze at $I4_ATT1 across 25s — either no driver retried, or a fenced driver left the claim stamped (the 420s squat ea11853 fixes)"
    fi
    [ "$I4_STATUS" = cancelling ] \
      && ok "…and the run is STILL 'cancelling' — no replica mutated a session whose lease it does not hold" \
      || no "the run reached '$I4_STATUS' while a foreign replica held the lease (the epoch fence let a mutation through)"

    # Expire the lease: the next worker tick may now steal it, and a steal — unlike
    # a renew — MUST bump the epoch.
    db "update sessions set orchestrator_lease_until = now() - interval '60 seconds' where id='$I4'" >/dev/null
    I4_FINAL=$(wait_terminal "$I4" 180)
    case "$I4_FINAL" in
      completed|failed|cancelled|budget_exceeded)
        ok "with the lease expired, a live replica took over and drove the run to '$I4_FINAL'";;
      *)
        no "the run never terminalized after the lease expired (status=$I4_FINAL) — takeover is broken";;
    esac
    I4_OWNER=$(db "select orchestrator_owner_id from sessions where id='$I4'")
    I4_EPOCH1=$(db "select orchestrator_epoch from sessions where id='$I4'")
    { [ -n "$I4_OWNER" ] && [ "$I4_OWNER" != "$I4_FOREIGN" ]; } \
      && ok "the lease now belongs to a LIVE replica, not the dead one that held it" \
      || no "orchestrator_owner_id is '$I4_OWNER' after takeover (want a live replica's id, never the foreign one)"
    # `>` rather than `= epoch0 + 1`: a takeover bumps by exactly one, but a second
    # lapse-and-steal (the other replica picking the session up after a 30 s lease
    # TTL on a slow runner) is EQUALLY correct behavior, so pinning the exact value
    # would make this flaky without making it stronger. What must hold — and what
    # a renew would violate — is that the owner change moved it at all.
    { [ -n "$I4_EPOCH1" ] && [ "$I4_EPOCH1" -gt "$I4_EPOCH0" ]; } \
      && ok "the fencing epoch advanced on the owner change ($I4_EPOCH0 → $I4_EPOCH1) — the token the dead driver still carries no longer matches the session (what a mutation carrying it does is NOT asserted here; see the disclosure below)" \
      || no "orchestrator_epoch is '$I4_EPOCH1' after a takeover from epoch $I4_EPOCH0 (a steal MUST bump it; only a renew keeps it)"
  fi
fi

# NOT ASSERTED — STALE-EPOCH FENCING ITSELF. Read this before quoting (i.4) as
# coverage of the fence (#33 review 5, which found the section's old success text
# claiming more than its assertions deliver).
#
# What (i.4) actually drives: a lease held by a THIRD replica makes BOTH live
# drivers fail `hold_lease` and stop — before either ever acquires an epoch. So no
# driver in this section ever HOLDS an epoch across a takeover, and no fenced
# mutation carrying a stale token is ever attempted, let alone observed to be
# refused. Deleting the `expected_epoch` predicate from the process-level wiring
# would leave every assertion above GREEN. What (i.4) does prove, and it is worth
# having, is the lease's operational behavior end to end: a foreign holder stops
# both drivers, a fenced-out driver RELEASES its finalization claim instead of
# squatting it (the attempts counter keeps rising), the session does not advance
# while the foreign lease is live, and expiring it produces a real takeover whose
# owner change bumps the epoch.
#
# Why the missing half is not driven here: it needs a driver to keep running with
# a known-stale token PAST a takeover, i.e. an injected pause between the lease
# read and the fenced mutation. That is a server-side seam, not something the
# script can arrange. The pure-CAS property — "an UPDATE carrying epoch N matches
# zero rows once the session is at N+1" — is driven directly against the database
# in `fluidbox-db`'s own lease/fence tests (the epoch-fence and steal-matrix
# cases), and the process-level wiring (that the driver PASSES the epoch it proved
# into every lifecycle mutation, and re-proves it adjacent to the slow ones) is
# held by source-level guards in `orchestrator.rs`'s own test module, each of
# which was confirmed to fail when its statement is removed.
#
# NOT ASSERTED, and NOT TRUE AS SOMETIMES STATED — "every provider side effect
# carries an epoch" (#33 review 8). It does not, deliberately.
# `finish_terminal_cleanup` runs OUTSIDE the fence: a driver that loses the
# terminal transition still performs cleanup once it observes the session
# terminal, because cleanup is the retry ticket and stranding it whenever the
# winner died mid-way would leak sandboxes. The epoch gates the TRANSITION. What
# bounds the unfenced part instead is the finalization claim (one cleanup runs at
# a time), idempotence throughout (token revocation is an UPDATE, delivery enqueue
# is deduped), and UID-preconditioned provider deletes. `orchestrator.rs` says the
# same thing at the call site; anywhere the property is written down it must be
# scoped to the transition, not to side effects.
#
# NOT ASSERTED — MCP session affinity across replicas. The broker's session
# registry is per-replica in-memory, so a run whose calls land on two replicas
# opens two upstream MCP sessions. That is a KNOWN, disclosed residual (Phase F),
# not a regression this suite can catch: asserting it today would encode the
# limitation as if it were the contract.

if [ "$I_OK" = 1 ]; then
  stop_replica_b \
    && ok "replica B stopped — section (j) measures a single process, as its per-replica governor requires" \
    || no "replica B is still holding :$API_PORT_B; section (j)'s per-replica governor assertions may be diluted"
fi

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
# EVERY psql statement this run issued had to succeed. db() cannot count its own
# failures (it runs inside `$( )`, and a subshell's counter increment is lost),
# so it appends to $DB_ERR_LOG and the tally is asserted HERE — once, for the
# whole file. This is what stops a broken fixture write, or a psql that lost the
# server, from turning into an assertion that "passed" on an empty string.
DB_ERRS=$(wc -l < "$DB_ERR_LOG" | tr -d ' ')
[ "$DB_ERRS" = 0 ] \
  && ok "every psql statement in this run succeeded — no assertion above read a swallowed error" \
  || no "$DB_ERRS psql statement(s) FAILED; every assertion reading one is VOID:
$(cat "$DB_ERR_LOG")"

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
