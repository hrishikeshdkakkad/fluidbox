#!/usr/bin/env bash
# Phase F acceptance E2E (#34) — scale, reliability and rollout.
#
# SCAFFOLDING ONLY, DELIBERATELY. The properties this suite will assert (design
# :1597-1613: 60/150/300 concurrent sandboxes, 1,500 saved connections, OAuth
# refresh storms, revocation during active runs, upstream 401/404/429/5xx, slow
# approvals, broker restart mid-session, the cross-replica reservation race,
# database failover, tenant-isolation fuzz) are still being built. Everything
# below the helper block is therefore ONE real section plus a list of the
# sections still to come — and NOT a set of placeholder assertions.
#
# That choice is the direct lesson of Phase E: its dominant defect class was
# eleven assertions that passed while testing nothing. A stub assertion is worse
# than an absent one, because an absent section is visibly missing while a stub
# reports green. If you are adding a section here, read the ASSERTION DISCIPLINE
# contract below first — it is the same contract scripts/hardening-e2e.sh:27-48
# states, and it is binding.
#
# ASSERTION DISCIPLINE (inherited verbatim from hardening-e2e.sh; a standing rule):
#   * every count assertion carries a `>0` precondition, so an empty or dead
#     fixture can never pass one vacuously;
#   * every "exactly N" assertion first proves its recorder is non-empty;
#   * a section that asserts ZERO of something carries a POSITIVE CONTROL in the
#     same section proving the recorder DOES record when the thing happens;
#   * NO ASSERTION MAY PASS ON AN ABSENT ANSWER:
#       - a `db()` read that FAILED is not an empty result: psql runs with
#         ON_ERROR_STOP, returns `<psql-error>`, and the run fails at RESULT;
#       - an emptiness assertion (`-z`, `= ""`) carries a FLOOR proving the query
#         returned a row at all;
#       - `CODE=000` (curl never connected) is a hard failure, and an "accepted"
#         HTTP arm names the set of codes it accepts instead of saying "not 403";
#   * where an assertion cannot be made fail-capable here, a `NOT ASSERTED`
#     comment names what would be required instead — never a fake pass.
#
# HERMETIC + no model spend: runs never launch a sandbox (no runner image in CI,
# and the template run's workspace is an absent local path, which fails during
# `initializing` before the provider is ever asked). No upstream is contacted.
#
# NEVER executed locally — CI on the PR is its proof (`bash -n` + shellcheck are
# the local bar).
#
# `set -e` is intentionally OMITTED (matching the siblings): this drives negative
# matrices of EXPECTED non-2xx responses; aborting on the first would defeat it.
# Failures are counted; a nonzero `fail` exits 1.
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
# Postgres service.
if [ -z "${DATABASE_URL:-}" ]; then
  echo "scale-e2e: DATABASE_URL is required (CI provides the Postgres service)." >&2
  echo "  This script forges session fixtures, drives the internal gate over real" >&2
  echo "  HTTP and reads the ledger back; it will not run — and must never" >&2
  echo "  silently skip — without one." >&2
  exit 2
fi
command -v curl    >/dev/null 2>&1 || { echo "scale-e2e: curl is required." >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "scale-e2e: python3 is required (JSON + uuids)." >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "scale-e2e: openssl is required (tokens + sha256)." >&2; exit 2; }
# psql is REQUIRED, not optional: the fixture forge and every ledger assertion go
# through it. None of those may silently skip, so a missing psql aborts the run.
command -v psql    >/dev/null 2>&1 || { echo "scale-e2e: psql is required (acceptance must be PROVEN, not skipped)." >&2; exit 2; }

# ── Config ───────────────────────────────────────────────────────────────────
# PORTS. scripts/hardening-e2e.sh owns 8787/8788 (replica A) and 8790/8791
# (replica B). This suite deliberately picks a DIFFERENT block so both can run on
# one developer machine at the same time without a bind() race; in CI they are
# separate jobs on separate runners, so the choice costs nothing there.
#
# TWO ports per replica, not one: main.rs binds a public listener
# (`FLUIDBOX_BIND`) AND a sandbox-facing internal listener
# (`FLUIDBOX_INTERNAL_BIND`, whose Docker-provider default is 127.0.0.1:8788).
# The public bind serves /internal too, so every request below goes to the public
# port; the internal bind only has to be FREE.
API_PORT=8795
API_PORT_INT=8796
API="http://127.0.0.1:$API_PORT"
# The SECOND replica (for the cross-replica sections still to come).
API_PORT_B=8797
API_PORT_B_INT=8798
API_B="http://127.0.0.1:$API_PORT_B"

ADMIN_TOKEN=$(openssl rand -hex 32)
CRED_KEY=$(openssl rand -hex 32)        # FLUIDBOX_CREDENTIAL_KEY
MASTER_KEY="sk-litellm-master-$$"       # `shared` LLM key mode refuses an EMPTY key

# A tag unique per run. Every forged row and every token plaintext carries it, so
# a leftover fixture from an earlier run can never satisfy an assertion here.
TAG="sc$$$(date +%s)"

# How many sessions section (a) forges. Small enough to be cheap in CI, large
# enough that the requests genuinely overlap. The 60/150/300 design bullets are
# for the loadgen harness driving a dedicated environment, not for a CI job that
# shares a runner with eleven other jobs.
FORGE_N=24

WORK=$(mktemp -d)
DATA_DIR="$WORK/data";   mkdir -p "$DATA_DIR"
RESP="$WORK/responses";  mkdir -p "$RESP"
SERVER_PID=""; SERVER_B_PID=""
SERVER_LOG="$WORK/server.log"
SERVER_B_LOG="$WORK/server-b.log"
UB="$WORK/ub"                       # scratch body file for the curl helpers

pass=0; fail=0
ok()  { printf "  \033[1;32m✓\033[0m %s\n" "$1"; pass=$((pass+1)); }
no()  { printf "  \033[1;31m✗\033[0m %s\n" "$1"; fail=$((fail+1)); }
say() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }

# Fail-fast precondition guard: when a value a section DEPENDS ON is empty,
# record ONE loud failure and return nonzero so the caller SKIPS the dependent
# steps — keeping one root failure legible instead of fanning it into dozens of
# misleading downstream ones. Never weakens a passing assertion.
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
# EMPTY string silently satisfies every `-z` and `= ""` assertion. A psql failure
# is now three things at once:
#   1. a loud stderr line (visible in the CI log next to the section it broke),
#   2. the value `<psql-error>` on stdout — which no assertion expects, so every
#      downstream comparison FAILS instead of passing on emptiness,
#   3. a line in $DB_ERR_LOG, asserted empty in RESULT — so a failure inside a
#      `db … >/dev/null` fixture write (whose value nothing reads) is still
#      COUNTED. The counter cannot live here: db() is almost always called inside
#      `$( )`, and a subshell's `fail=$((fail+1))` never reaches the parent.
# db() must NEVER be called from a background subshell (one shared stderr file);
# the only `&` block in this file runs curl.
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
# Where a FAILED CI run's forensics are copied to. Fixed, inside the checkout,
# because actions/upload-artifact needs a path known when the workflow YAML is
# written and $WORK is a random mktemp dir.
CI_ARTIFACTS="$ROOT/scale-e2e-artifacts"
# shellcheck disable=SC2329  # invoked via the EXIT/INT/TERM trap
cleanup() {
  local rc=$?
  # CI FORENSICS. $WORK holds the ONLY copy of the control-plane logs and the
  # per-request recorders, and the `rm -rf` below destroys them — which would
  # leave a CI-only failure with nothing to debug but the pass/fail lines. So:
  # when the run FAILED (nonzero exit, or any counted failure) and we are in CI,
  # copy those files out first. Copy-out rather than "skip the rm" so the
  # artifact path is static, and only on failure so a green run leaves nothing.
  if [ -n "${CI:-}" ] && { [ "$rc" -ne 0 ] || [ "${fail:-0}" -gt 0 ]; }; then
    mkdir -p "$CI_ARTIFACTS"
    cp -p "$SERVER_LOG" "$SERVER_B_LOG" "$DB_ERR_LOG" "$CI_ARTIFACTS/" 2>/dev/null
    cp -pR "$RESP" "$CI_ARTIFACTS/responses" 2>/dev/null
    echo "scale-e2e: run failed (exit $rc, $fail failed assertions) — preserved server logs + per-request recorders in $CI_ARTIFACTS" >&2
  fi
  [ -n "$SERVER_PID" ]   && kill "$SERVER_PID"   2>/dev/null
  [ -n "$SERVER_B_PID" ] && kill "$SERVER_B_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ── Boot ─────────────────────────────────────────────────────────────────────
# `_spawn` sets this; callers assign it to whichever replica handle they own.
SPAWN_PID=""

_spawn() { # [public-port] [internal-port] [logfile] → sets SPAWN_PID
  local port=${1:-$API_PORT} iport=${2:-$API_PORT_INT} log=${3:-$SERVER_LOG}
  printf '\n===== control plane (re)start =====\n' >> "$log"
  (
    cd "$ROOT" || exit 1
    export DATABASE_URL="$DATABASE_URL"
    export FLUIDBOX_BIND="127.0.0.1:$port"
    export FLUIDBOX_INTERNAL_BIND="127.0.0.1:$iport"
    # LOAD-BEARING: a loopback-http public URL is the ONLY switch that opens the
    # dev-loopback egress seam (egress.rs `dev_loopback`). Sections that point
    # the control plane at a local fake upstream need it; the metadata/private-IP
    # negatives stay blocked regardless.
    export FLUIDBOX_PUBLIC_URL="http://127.0.0.1:$port"
    export FLUIDBOX_ADMIN_TOKEN="$ADMIN_TOKEN"
    export FLUIDBOX_PROVIDER=docker
    export FLUIDBOX_DATA_DIR="$DATA_DIR"
    # Phase D (#32): run the app pool as the NON-superuser role migration 0018
    # creates, so every HTTP request executes with RLS actually ENFORCED (CI's DB
    # user is the superuser `postgres`, for whom policies are skipped entirely).
    export FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime
    # A dead-registry image ref makes PROVISIONING fail in milliseconds (there is
    # no runner image in CI). Necessary but NOT sufficient for a fast fixture —
    # see `create_run`'s workspace default for the other half.
    export FLUIDBOX_SANDBOX_IMAGE=localhost:1/fluidbox-absent:ci
    export FLUIDBOX_CODEX_SANDBOX_IMAGE=localhost:1/fluidbox-absent:ci
    export FLUIDBOX_CREDENTIAL_KEY="$CRED_KEY"
    export FLUIDBOX_REQUIRE_SSO=0
    export FLUIDBOX_LLM_KEY_MODE=shared
    export LITELLM_MASTER_KEY="$MASTER_KEY"
    export RUST_LOG="${RUST_LOG:-warn,fluidbox_server=info}"
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

# ── The SECOND replica ───────────────────────────────────────────────────────
# Same binary, same DATABASE_URL, same runtime role, distinct ports and log.
# Boot ORDER is load-bearing: replica A is healthy (and has therefore already run
# every migration) long before this is called, so B's own migrate pass is a no-op
# and the two can never race the migration lock. The shared FLUIDBOX_DATA_DIR is
# deliberate (it models the shared volume a real two-replica deployment has), and
# B's boot is safe for forged fixtures already in the DB: they carry NULL
# started_at/last_heartbeat_at and never provisioned a sandbox, so no watchdog,
# wall-clock sweeper or orphan reap on B has anything of theirs to act on.
#
# Unused by the one section below; present because the cross-replica sections
# still to come (reservation race, approval fan-out, delivery claims) need it and
# the boot discipline above is the part that is easy to get wrong later.
# shellcheck disable=SC2317,SC2329  # called by sections still to be written
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
# shellcheck disable=SC2317,SC2329  # called by sections still to be written
stop_replica_b() {
  [ -n "$SERVER_B_PID" ] && kill "$SERVER_B_PID" 2>/dev/null
  SERVER_B_PID=""
  for _ in $(seq 1 60); do
    curl -sf "$API_B/v1/health" >/dev/null 2>&1 || return 0
    sleep 0.5
  done
  return 1
}

# ── HTTP helpers ─────────────────────────────────────────────────────────────
AH="authorization: Bearer $ADMIN_TOKEN"
CODE=""; BODY=""

# curl code 000 means the request never completed — no status line at all. That
# is never a passing outcome, and it is the single easiest way for a matrix to go
# blind, so it is checked at the helper rather than at each call site.
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
# shellcheck disable=SC2317,SC2329  # called by sections still to be written
admin_get() {
  : > "$UB"
  CODE=$(curl -s -o "$UB" -w '%{http_code}' -H "$AH" "$API$1")
  BODY=$(cat "$UB")
  http_dead "$CODE" "GET $1" && return 1
  return 0
}

# ── The FAST session forge ───────────────────────────────────────────────────
# The bash twin of crates/fluidbox-loadgen/src/seed.rs, and the reason this suite
# can reach a three-digit session count at all.
#
# WHY NOT the hardening suite's `forge_running`: that creates EVERY run through
# the public API and waits for provisioning to fail and the finalizer to quiesce.
# At one run per fixture that is fine; at N it is not (see hardening-e2e.sh's
# `create_run` comment — the wrong workspace choice costs ~140 s PER RUN).
#
# THE RECIPE: create ONE run properly through POST /v1/sessions so the RunSpec is
# GENUINE — frozen policy snapshot, real budgets — then clone that row N times
# and mint the four audience-scoped tokens per clone. Two statements, any N.
#
# What the clones inherit is every column that governs a gate decision
# (`run_spec`, `budgets`, `autonomy`, `trust_tier`, `agent_revision_id`,
# `tenant_id`), copied VERBATIM. What they deliberately do NOT inherit is the
# lifecycle: `status` is forced to 'running' and `started_at`/`last_heartbeat_at`
# stay NULL, so the heartbeat watchdog and the wall-clock budget sweeper have
# nothing of theirs to reap — the same property `forge_running` relies on. No
# clone ever had a sandbox handle, so the boot orphan reap has nothing to do.
#
# Token plaintexts are DERIVED, not stored: `fbx_sess_sc_<TAG>_<ord>_<audience>`
# with `ord` 1-based from `with ordinality`, so bash reconstructs any token from
# its index. The `fbx_sess_` prefix is not cosmetic — event.rs's Redactor scrubs
# it, so a forged token that leaked into a ledger payload is redacted exactly
# like a real one. `sha256()` and `convert_to()` are core Postgres (11+).
FORGED_IDS=""
forge_fast() { # template-sid count label → sets FORGED_IDS (newline separated)
  local tpl=$1 n=$2 label=$3 arr cnt tokcnt
  need "$tpl" "$label: no template session id" || return 1
  cnt=$(db "select count(*) from sessions where id='$tpl'")
  [ "$cnt" = 1 ] || { no "$label: template session row missing (count=$cnt)"; return 1; }

  FORGED_IDS=$(python3 -c "import uuid;print('\n'.join(str(uuid.uuid4()) for _ in range($n)))")
  need "$FORGED_IDS" "$label: could not generate $n uuids" || return 1
  # A Postgres array literal: '{"uuid","uuid",…}'.
  arr=$(printf '%s\n' "$FORGED_IDS" | paste -sd, - )

  db "insert into sessions (id, tenant_id, agent_id, agent_revision_id, status, status_reason,
                            autonomy, trust_tier, task, repo_source, run_spec, budgets)
      select x.id, t.tenant_id, t.agent_id, t.agent_revision_id, 'running',
             'scale-e2e fixture ($TAG); cloned from $tpl — never provisioned a sandbox',
             t.autonomy, t.trust_tier, t.task, t.repo_source, t.run_spec, t.budgets
        from unnest('{$arr}'::uuid[]) as x(id)
        cross join (select tenant_id, agent_id, agent_revision_id, autonomy, trust_tier,
                           task, repo_source, run_spec, budgets
                      from sessions where id='$tpl') as t" >/dev/null

  db "insert into api_tokens (id, tenant_id, kind, session_id, token_sha256, audience, expires_at)
      select gen_random_uuid(), t.tenant_id, 'session', x.id,
             encode(sha256(convert_to('fbx_sess_sc_${TAG}_'||x.ord||'_'||a.aud, 'UTF8')), 'hex'),
             a.aud, now() + interval '2 hours'
        from unnest('{$arr}'::uuid[]) with ordinality as x(id, ord)
        cross join (values ('llm'),('tool'),('control'),('workspace')) as a(aud)
        cross join (select tenant_id from sessions where id='$tpl') as t" >/dev/null

  cnt=$(db "select count(*) from sessions where id = any('{$arr}'::uuid[]) and status='running'")
  tokcnt=$(db "select count(*) from api_tokens where session_id = any('{$arr}'::uuid[]) and kind='session'")
  gt0 "$cnt" "$label: forged session rows" || return 1
  [ "$cnt" = "$n" ] \
    && ok "$label: forged $cnt sessions in 'running' from template $tpl (2 statements, no sandbox)" \
    || { no "$label: forged $cnt sessions, wanted $n"; return 1; }
  [ "$tokcnt" = "$((n * 4))" ] \
    && ok "$label: minted $tokcnt audience-scoped tokens (llm/tool/control/workspace × $n)" \
    || { no "$label: minted $tokcnt tokens, wanted $((n * 4))"; return 1; }
  return 0
}

# The array literal for the ids forged most recently — every ledger read below
# scopes itself to exactly this run's rows.
forged_array() { printf '%s\n' "$FORGED_IDS" | paste -sd, - ; }

# ── Run creation (public API — the RunSpec must be genuine) ──────────────────
# The default workspace names a local_copy path that does not exist, and that is
# a RUNTIME BUDGET decision, not an accident: an absent source fails in
# `materialize_local`'s `!source.exists()` guard DURING `initializing`, before any
# base commit, sandbox handle or `started_at`. `expected_diff` is false, the first
# drive terminalizes, and the run quiesces in ~1 s — whereas a scratch workspace
# materializes, fails at the provider, and then pays the finalizer's 120 s
# provision-settle grace. It also means NO SANDBOX IS EVER REQUESTED.
RUN=""
create_run() { # agent
  admin_post "/v1/sessions" \
    "{\"agent\":\"$1\",\"task\":\"scale-e2e\",\"workspace\":{\"kind\":\"local_copy\",\"path\":\"/nonexistent-fluidbox-scale-fixture\"}}"
  RUN=$(echo "$BODY" | j "['session']['id']")
}

# Terminal AND its finalization intent cleared — the quiescent point at which no
# background worker will write the row again. `delete_finalization` is the
# terminal reconcile's LAST step, so once the intent is gone everything that
# reconcile drives has been issued.
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

# ═════════════════════════════════════════════════════════════════════════════
say "BOOT — control plane"
boot || { no "control plane did not become healthy: $(tail -30 "$SERVER_LOG")"; exit 1; }
ok "control plane up on $API (RLS enforced as fluidbox_runtime)"

# ── SETUP: policy + agent + the ONE template run ─────────────────────────────
say "SETUP — policy, agent, template run"
POLICY_YAML=$(python3 -c "import json,sys;print(json.dumps(sys.stdin.read()))" <<EOF
name: scale-allow-$TAG
defaults:
  tool_action: deny
autonomy:
  permitted: true
  on_approval_rule: deny
tools:
  - match: ["Read", "Glob", "Grep", "LS"]
    action: allow
EOF
)
admin_post "/v1/policies" "{\"name\":\"scale-allow-$TAG\",\"yaml\":$POLICY_YAML}"
[ "$CODE" = 200 ] && ok "policy scale-allow-$TAG created" || no "policy → $CODE: $BODY"

admin_post "/v1/agents" "{\"name\":\"scale-agent-$TAG\",\"policy\":\"scale-allow-$TAG\"}"
[ "$CODE" = 200 ] && ok "agent scale-agent-$TAG created" || no "agent → $CODE: $BODY"

create_run "scale-agent-$TAG"
need "$RUN" "template run not created ($CODE: $BODY)" || exit 1
TPL_STATUS=$(wait_settled "$RUN" 300)
case "$TPL_STATUS" in
  completed|failed|cancelled|budget_exceeded)
    ok "template run $RUN settled ('$TPL_STATUS') — its RunSpec is frozen and stable";;
  *) no "template run never settled ($TPL_STATUS)"; exit 1;;
esac

# ═════════════════════════════════════════════════════════════════════════════
# (a) The fast fixture forge, and the gate answering every one of N concurrent
#     sessions exactly once.
#
#     This is the ONE section this scaffolding ships with, chosen as the cheapest
#     property that is (i) genuinely true of the system today and (ii) genuinely
#     fail-capable: a broken forge makes every request a 401, a broken gate
#     leaves the ledger short, and either one fails here. It is also the
#     precondition every later section depends on — if the forge is wrong, every
#     scale assertion built on it would be meaningless.
# ═════════════════════════════════════════════════════════════════════════════
say "(a) fast fixture forge + one gate decision per concurrent session"

if forge_fast "$RUN" "$FORGE_N" "(a)"; then
  ARR=$(forged_array)

  # Every audience is present exactly once per session. Without this the four
  # tokens could all have been minted with the same audience and the `tool`
  # bearer below would still work — the matrix would be blind to a forge that
  # silently produced one audience four times.
  AUD_KINDS=$(db "select count(distinct audience) from api_tokens where session_id = any('{$ARR}'::uuid[])")
  gt0 "$AUD_KINDS" "(a) distinct audiences minted" && {
    [ "$AUD_KINDS" = 4 ] \
      && ok "(a) all four audiences are present (llm/tool/control/workspace), not one repeated" \
      || no "(a) $AUD_KINDS distinct audiences minted, wanted 4"
  }

  # ── fire N concurrent gate calls, one per session, with its OWN tool token ──
  # Backgrounded curl only — db() is never called from a subshell (it shares one
  # stderr file, and a subshell's fail counter would be lost).
  IDX=0
  BURST_PIDS=""
  while IFS= read -r SID; do
    [ -n "$SID" ] || continue
    IDX=$((IDX + 1))
    (
      # --max-time is load-bearing, not hygiene. `wait` below blocks on EVERY
      # backgrounded curl, so ONE request the gate never answers hangs the whole
      # job until the CI job timeout — which reads in the checks list as
      # "cancelled", indistinguishable from a human cancel, and in the log from a
      # deadlock. A load harness must bound every remote-driven request: a gate
      # decision is sub-second, so 30 s is pure headroom, and a request that
      # blows it writes curl's `000` — which the DEAD assertion below already
      # treats as a hard failure. The bound converts an uninformative timeout
      # into a precise "N requests never completed" verdict.
      curl -s --max-time 30 --connect-timeout 10 -o "$RESP/$IDX.body" -w '%{http_code}' \
        -X POST -H "authorization: Bearer fbx_sess_sc_${TAG}_${IDX}_tool" \
        -H 'content-type: application/json' \
        -d "{\"tool_call_id\":\"$TAG-a-$IDX\",\"tool\":\"Read\",\"input\":{\"file_path\":\"/workspace/README.md\"}}" \
        "$API/internal/sessions/$SID/permission" > "$RESP/$IDX.code"
    ) &
    BURST_PIDS="$BURST_PIDS $!"
  done <<< "$FORGED_IDS"
  # `wait $BURST_PIDS`, NEVER a bare `wait`. This section runs with the control
  # plane ALIVE in the background (boot() started it with `&`), and a bare `wait`
  # waits for EVERY background job — including that server, which never exits. The
  # first cut used a bare `wait`, and the job hung to the 45-min CI timeout with
  # every curl already returned: --max-time on the curls could not save it,
  # because the process `wait` was blocked on was the server, not a request.
  # shellcheck disable=SC2086
  wait $BURST_PIDS

  # The recorder must be non-empty BEFORE any "exactly N" claim is made of it.
  RESP_FILES=$(find "$RESP" -name '*.code' | wc -l | tr -d ' ')
  if gt0 "$RESP_FILES" "(a) per-request recorder files"; then
    [ "$RESP_FILES" = "$FORGE_N" ] \
      && ok "(a) all $FORGE_N concurrent gate requests produced a recorder file" \
      || no "(a) $RESP_FILES recorder files for $FORGE_N requests — some request vanished"

    # 000 = the request never completed. Counted separately from any status,
    # because a dead control plane must never read as a passing outcome.
    DEAD=$(grep -lx 000 "$RESP"/*.code 2>/dev/null | wc -l | tr -d ' ')
    [ "$DEAD" = 0 ] \
      && ok "(a) no request came back 000 — the control plane answered every one under concurrency" \
      || no "(a) $DEAD of $FORGE_N requests never completed (curl 000): the deployment stopped accepting"

    # The gate answers 200 for BOTH verdicts, so the STATUS proves the handler
    # ran and the BODY proves which way it went. The policy allows `Read`, so
    # every verdict must be `allow`; a deny here would mean the clone did not
    # inherit the template's frozen policy snapshot.
    OK200=$(grep -lx 200 "$RESP"/*.code 2>/dev/null | wc -l | tr -d ' ')
    if gt0 "$OK200" "(a) requests answered 200"; then
      [ "$OK200" = "$FORGE_N" ] \
        && ok "(a) every one of $FORGE_N requests was answered 200 by the gate handler itself" \
        || no "(a) only $OK200 of $FORGE_N requests reached the gate handler (the rest were 401/403/5xx — see $RESP)"
    fi
    ALLOWED=$(grep -l '"decision":"allow"' "$RESP"/*.body 2>/dev/null | wc -l | tr -d ' ')
    if gt0 "$ALLOWED" "(a) allow verdicts"; then
      [ "$ALLOWED" = "$FORGE_N" ] \
        && ok "(a) all $FORGE_N verdicts were 'allow' — every clone inherited the template's frozen policy snapshot" \
        || no "(a) $ALLOWED of $FORGE_N verdicts were 'allow'; the clones' frozen policy does not match the template's"
    fi
  fi

  # ── the ledger is the authority, not the response ──────────────────────────
  REQ_EVENTS=$(db "select count(*) from events where session_id = any('{$ARR}'::uuid[]) and type='tool.requested'")
  if gt0 "$REQ_EVENTS" "(a) tool.requested ledger rows"; then
    [ "$REQ_EVENTS" = "$FORGE_N" ] \
      && ok "(a) the ledger holds exactly $REQ_EVENTS tool.requested rows — one per request, none duplicated under concurrency" \
      || no "(a) $REQ_EVENTS tool.requested rows for $FORGE_N requests"
  fi
  REQ_SESSIONS=$(db "select count(distinct session_id) from events where session_id = any('{$ARR}'::uuid[]) and type='tool.requested'")
  if gt0 "$REQ_SESSIONS" "(a) sessions with a tool.requested row"; then
    [ "$REQ_SESSIONS" = "$FORGE_N" ] \
      && ok "(a) …spread across all $REQ_SESSIONS sessions — every forged session was genuinely reachable, not one session $FORGE_N times" \
      || no "(a) only $REQ_SESSIONS of $FORGE_N sessions recorded a request"
  fi
  # `append_event` assigns a gapless per-session seq under a row lock. ONE gate
  # call appends TWO events — `tool.requested` then `tool.decision` — so with one
  # request per session the max seq must be <=2. A HIGHER value means a second
  # request was counted against this session, i.e. traffic crossed sessions.
  # (Do NOT "correct" this bound to =1: that is the stale-comment trap this line
  # used to set — the code has always been right, the old comment was not.)
  MAXSEQ=$(db "select coalesce(max(seq), 0) from events where session_id = any('{$ARR}'::uuid[])")
  gt0 "$MAXSEQ" "(a) max per-session event seq" && {
    [ "$MAXSEQ" -le 2 ] \
      && ok "(a) the per-session event seq never exceeded $MAXSEQ — no session absorbed another's traffic" \
      || no "(a) a session reached seq $MAXSEQ with one request each: requests crossed sessions"
  }

  # ── POSITIVE CONTROL for the authentication ────────────────────────────────
  # Everything above would also pass if the internal gate accepted ANY bearer.
  # This proves it does not: the same request with an unminted token is refused,
  # and leaves no ledger row behind.
  CTRL_SID=$(printf '%s\n' "$FORGED_IDS" | head -1)
  if need "$CTRL_SID" "(a) no forged session for the auth positive control"; then
    : > "$UB"
    CTRL_CODE=$(curl -s -o "$UB" -w '%{http_code}' -X POST \
      -H "authorization: Bearer fbx_sess_sc_${TAG}_never_minted_tool" \
      -H 'content-type: application/json' \
      -d "{\"tool_call_id\":\"$TAG-ctrl\",\"tool\":\"Read\",\"input\":{\"file_path\":\"/workspace/README.md\"}}" \
      "$API/internal/sessions/$CTRL_SID/permission")
    if ! http_dead "$CTRL_CODE" "(a) auth positive control"; then
      [ "$CTRL_CODE" = 401 ] \
        && ok "(a) POSITIVE CONTROL: an unminted bearer is refused 401 — the $FORGE_N successes above were genuinely authenticated" \
        || no "(a) an unminted bearer got $CTRL_CODE (want 401): the internal gate is not checking the token, and every assertion above is VOID"
    fi
    CTRL_EVENTS=$(db "select count(*) from events where session_id = any('{$ARR}'::uuid[]) and payload->'data'->>'tool_call_id'='$TAG-ctrl'")
    # `-eq 0` is safe here BECAUSE the companion count above proved the same
    # query shape returns rows for a real tool_call_id (REQ_EVENTS > 0).
    [ "$CTRL_EVENTS" = 0 ] \
      && ok "(a) …and the refused request appended NO ledger row" \
      || no "(a) the refused request left $CTRL_EVENTS ledger row(s): a rejected bearer reached the ledger"
  fi

  # NOT ASSERTED — the 60/150/300 design bullets themselves, and every latency
  # property. A shared CI runner hosts the control plane, Postgres and the client
  # in one container with no resource isolation, so a p99 measured here would be
  # a number about GitHub's scheduler. That measurement belongs to
  # `fluidbox-loadgen` against a dedicated environment; what CI can prove — and
  # does prove above — is CORRECTNESS under concurrency: every session reachable,
  # every decision recorded exactly once, no cross-session bleed.
fi

# ═════════════════════════════════════════════════════════════════════════════
# SECTIONS STILL TO COME. Listed, not stubbed: a placeholder assertion would
# report green while proving nothing, which is the defect class this suite was
# written to avoid. Each line names the design bullet and the fixture it needs.
#
#   (b) 1,500 saved connections — needs a local fake MCP upstream (python stdlib,
#       mirroring hardening-e2e.sh's `fake_mcp.py`) so each create can photograph
#       a tool surface; asserts snapshot parity and list latency at size.
#   (c) upstream 401/404/429/5xx — same fake, driven through the broker with the
#       four-state `tool_execution_claims` histogram read back per arm
#       (definitive upstream response ⇒ failed_upstream and TERMINAL; only a
#       proven non-send ⇒ failed_before_send and re-claimable).
#   (d) slow approvals — an `approve` policy plus N parked handlers, decided
#       after a delay; asserts one `approval.decided` per approval (the Gap 13
#       CAS) and that waiters emit nothing.
#   (e) connection revocation during active runs — revoke mid-flight; asserts the
#       post-revocation calls deny with ledger `source='binding'`, fail-closed.
#   (f) broker restart during active sessions — kill replica A mid-dispatch via
#       `_spawn`/`boot`; asserts an `ambiguous` claim is never re-dispatched and
#       that a `failed_before_send` one is re-claimable.
#   (g) the cross-replica reservation race — `boot_replica_b`, then parallel
#       facade calls for ONE session against both replicas; asserts the summed
#       `usage_entries` never exceed the frozen budget by more than one request.
#   (h) OAuth refresh storms — needs a fake authorization server AND a way to
#       reach `auth_kind='oauth'` connections without a browser (the
#       `__Host-fbx_oauth_flow` cookie is claimed inside the single-use
#       predicate); the flow forge is the open design question.
#   (i) database failover — needs a database this suite can fail over. Out of
#       reach for a CI Postgres service container; likely a manual runbook
#       exercise rather than a CI section.
#   (j) tenant-isolation fuzz — needs FLUIDBOX_REQUIRE_SSO=1 and two orgs, under
#       which the admin token is confined to /v1/admin/*. The existing coverage
#       is scripts/identity-e2e.sh plus the RLS negatives; extending THOSE is
#       likely better than duplicating the identity fixture here.
# ═════════════════════════════════════════════════════════════════════════════

# ── Result ───────────────────────────────────────────────────────────────────
# EVERY psql statement this run issued had to succeed. db() cannot count its own
# failures (it runs inside `$( )`, and a subshell's counter increment is lost), so
# it appends to $DB_ERR_LOG and the tally is asserted HERE — once, for the whole
# file. This is what stops a broken fixture write, or a psql that lost the server,
# from turning into an assertion that "passed" on an empty string.
DB_ERRS=$(wc -l < "$DB_ERR_LOG" | tr -d ' ')
[ "$DB_ERRS" = 0 ] \
  && ok "every psql statement in this run succeeded — no assertion above read a swallowed error" \
  || no "$DB_ERRS psql statement(s) FAILED; every assertion reading one is VOID:
$(cat "$DB_ERR_LOG")"

say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
