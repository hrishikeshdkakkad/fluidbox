#!/usr/bin/env bash
# THE gate proof: a tool call the control plane denied does not execute.
#
# This is the acceptance test the permission-gate bypass got past. It is worth
# understanding why the suites that existed could not catch it:
#
#   * `governance-e2e.sh` kills the real runner and drives /permission itself, so
#     it validates the SERVER and structurally cannot validate the HARNESS.
#   * `e2e-tool-gate.sh` phase 1 does drive a live agent — and self-skips without
#     model credits, which is exactly the state the repository was in when the
#     bypass shipped.
#   * the gate unit tests assert the hook's SHAPE against the runner source. Real,
#     useful, and unable to prove the SDK ever invokes it.
#
# What was missing was a way to run the REAL runner image and the REAL Claude
# Code CLI through the REAL hook → callback → /permission path with no model. That
# is this script: the model upstream is a mock that returns a canned `tool_use`,
# and the control plane is a mock whose verdict each scenario chooses. It yields
# two witnesses that cannot be faked:
#
#   1. a REAL filesystem side effect in the bind-mounted /workspace, visible from
#      the host; and
#   2. for read-only-classified commands (which leave no filesystem trace — and
#      which are precisely the class that bypassed the gate), the digest of a
#      NONCE MINTED SECONDS EARLIER arriving back in the tool_result on turn 2.
#
# Deterministic, repeatable, $0, and able to hold a verdict open to test ordering.
# It needs docker and python3. It needs no API key.
#
#   scripts/gate-proof.sh                 # the whole matrix
#   GATEPROOF_IMAGE=... scripts/gate-proof.sh
#   GP_KEEP=1 scripts/gate-proof.sh       # keep the per-scenario workspaces
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${GATEPROOF_IMAGE:-fluidbox-sandbox-runner:dev}"
PORT="${GATEPROOF_PORT:-18799}"
EVIDENCE="${GATEPROOF_EVIDENCE:-$ROOT/gate-proof-evidence}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/gateproof.XXXXXXXX")"

GREEN=$'\033[1;32m'; RED=$'\033[1;31m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
pass=0; fail=0
ok()  { printf "  ${GREEN}✓${RESET} %s\n" "$1"; pass=$((pass+1)); }
no()  { printf "  ${RED}✗ %s${RESET}\n" "$1"; shift; for l in "$@"; do printf "      %s\n" "$l"; done; fail=$((fail+1)); }
note(){ printf "    ${DIM}%s${RESET}\n" "$1"; }

cleanup() {
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null
  docker rm -f $(docker ps -aq --filter "label=fluidbox.gateproof=1" 2>/dev/null) >/dev/null 2>&1
  if [ -z "${GP_KEEP:-}" ]; then rm -rf "$WORK"; else printf "\n  workspaces kept at %s\n" "$WORK"; fi
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "gate-proof: docker is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "gate-proof: python3 is required" >&2; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
  echo "gate-proof: image $IMAGE not found." >&2
  echo "  build it: docker build -t $IMAGE -f images/sandbox-runner/Dockerfile images" >&2
  exit 1
}
mkdir -p "$EVIDENCE"

printf "\n%s== the gate proof — no API key, no model spend ==%s\n" "$BOLD" "$RESET"
printf "  image: %s\n  mock:  http://host.docker.internal:%s\n" "$IMAGE" "$PORT"

# PREFLIGHT: prove the container can write the bind-mounted workspace at all.
#
# This is not defensive padding. Every "denied" assertion in this script is an
# ABSENCE — no file appeared, no digest came back — and an absence has two
# explanations: the gate held, or the harness never could have produced the
# effect. A read-only bind mount, a uid mismatch, or a missing host-gateway
# route all yield a clean sweep of green negatives and a completely false
# conclusion. The positive controls (C, D) catch it too; this catches it FIRST,
# with a message that names the cause.
probe_dir="$WORK/_preflight"; mkdir -p "$probe_dir"; chmod 0777 "$probe_dir"
if docker run --rm --label fluidbox.gateproof=1 -v "$probe_dir:/workspace" \
     --entrypoint sh "$IMAGE" -c 'printf preflight > /workspace/w' >/dev/null 2>&1 \
   && [ -f "$probe_dir/w" ]; then
  ok "preflight: the container can write the bind-mounted workspace"
else
  no "preflight: the container CANNOT write the bind-mounted workspace" \
     "Every negative result below would be meaningless — an absent side effect" \
     "would prove nothing about the gate. Fix the mount, then re-run." \
     "(uid in image is 10001; host dir must be writable by it)"
  printf "\n  %sRESULT: aborted before any scenario ran%s\n\n" "$BOLD" "$RESET"
  exit 1
fi
if docker run --rm --label fluidbox.gateproof=1 \
     --add-host host.docker.internal:host-gateway --entrypoint sh "$IMAGE" \
     -c "command -v getent >/dev/null && getent hosts host.docker.internal >/dev/null" >/dev/null 2>&1; then
  ok "preflight: host.docker.internal resolves inside the sandbox"
else
  note "host.docker.internal did not resolve via getent (non-fatal; the runs below will show it)"
fi

# run_scenario <name> <mode> <hold_secs> <command-template> [timeout_secs]
#   The template may contain @NONCE@ and @WS@.
# Sets: SC_DIR, SC_LOG, SC_NONCE, SC_RC, SC_TIMED_OUT
#
# The wait is BOUNDED because one of the fail-closed behaviours under test is
# unbounded on purpose: on a 5xx from /permission, `requestPermission` retries
# FOREVER rather than assuming a verdict. That is the correct posture — a broken
# control plane must block the tool, not release it — and it means the container
# never exits. So the scenario runs detached and gets killed at the deadline, and
# "still retrying when we killed it, having executed nothing" IS the pass.
run_scenario() {
  local name="$1" mode="$2" hold="$3" tmpl="$4" limit="${5:-90}"
  SC_DIR="$WORK/$name"; SC_LOG="$WORK/$name.jsonl"
  mkdir -p "$SC_DIR/workspace"
  # The runner image runs as uid 10001; this dir is created by the invoking user.
  # Without this the container cannot write and EVERY mutating probe "produces no
  # side effect" — which reads exactly like a gate that held. The parent is a
  # 0700 mktemp dir, so this widens nothing reachable by another user.
  chmod 0777 "$SC_DIR/workspace"
  SC_NONCE="fbxgp-$(openssl rand -hex 10 2>/dev/null || python3 -c 'import secrets;print(secrets.token_hex(10))')"
  local cmd="${tmpl//@NONCE@/$SC_NONCE}"
  cmd="${cmd//@WS@//workspace}"

  GP_MODE="$mode" GP_COMMAND="$cmd" GP_HOLD_SECS="$hold" GP_PORT="$PORT" GP_LOG="$SC_LOG" \
    python3 "$ROOT/scripts/gate-proof/mock.py" >"$WORK/$name.mock.log" 2>&1 &
  MOCK_PID=$!
  for _ in $(seq 1 50); do
    curl -fsS -m 1 "http://127.0.0.1:$PORT/ping" >/dev/null 2>&1 && break
    sleep 0.1
  done

  # The REAL image, the REAL entrypoint (which performs the production
  # unlinked-fd credential hand-off because FLUIDBOX_SESSION_TOKEN is present),
  # the REAL index.mjs, the REAL pinned Claude Code CLI.
  local cname="gp-${name}-$$"
  docker rm -f "$cname" >/dev/null 2>&1
  docker run -d --name "$cname" \
    --label fluidbox.gateproof=1 \
    --add-host host.docker.internal:host-gateway \
    -v "$SC_DIR/workspace:/workspace" \
    -e FLUIDBOX_CONTROL_URL="http://host.docker.internal:$PORT" \
    -e FLUIDBOX_SESSION_ID="019fgp00-0000-7000-8000-00000000000$((RANDOM % 10))" \
    -e FLUIDBOX_SESSION_TOKEN="fbx_sess_gateproof_control" \
    -e FLUIDBOX_TOOL_TOKEN="fbx_sess_gateproof_tool" \
    -e FLUIDBOX_LLM_TOKEN="fbx_sess_gateproof_llm" \
    -e FLUIDBOX_TASK="Run the probe command exactly once." \
    -e FLUIDBOX_WORKSPACE="/workspace" \
    -e FLUIDBOX_MODEL="claude-haiku-4-5" \
    -e FLUIDBOX_AUTONOMY="supervised" \
    -e FLUIDBOX_MAX_TURNS="3" \
    -e ANTHROPIC_BASE_URL="http://host.docker.internal:$PORT" \
    -e ANTHROPIC_API_KEY="fbx_sess_gateproof_llm" \
    -e DISABLE_TELEMETRY=1 \
    -e DISABLE_ERROR_REPORTING=1 \
    -e DISABLE_AUTOUPDATER=1 \
    -e CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    "$IMAGE" >/dev/null 2>&1

  local waited=0
  SC_TIMED_OUT=0
  while [ "$waited" -lt "$limit" ]; do
    [ "$(docker inspect -f '{{.State.Running}}' "$cname" 2>/dev/null)" = "true" ] || break
    sleep 1; waited=$((waited + 1))
  done
  if [ "$(docker inspect -f '{{.State.Running}}' "$cname" 2>/dev/null)" = "true" ]; then
    SC_TIMED_OUT=1
    docker kill "$cname" >/dev/null 2>&1
  fi
  SC_RC=$(docker inspect -f '{{.State.ExitCode}}' "$cname" 2>/dev/null || echo -1)
  docker logs "$cname" >"$WORK/$name.runner.log" 2>&1
  docker rm -f "$cname" >/dev/null 2>&1

  kill "$MOCK_PID" 2>/dev/null; MOCK_PID=""
  cp "$SC_LOG" "$EVIDENCE/$name.jsonl" 2>/dev/null || true
  cp "$WORK/$name.runner.log" "$EVIDENCE/$name.runner.log" 2>/dev/null || true
}

# ── reading a side effect back, on every platform ──────────────────────────
#
# The image runs as uid 10001 and the CLI's Bash tool writes with umask 077, so
# a side-effect file lands 0600 owned by 10001. Whether the HOST can then read
# it depends on the engine:
#
#   * colima / Docker Desktop — lima's virtiofs remaps ownership to the invoking
#     user, so a host-side `grep` on a 0600 file just works. This is why the
#     defect below was invisible for the whole of this candidate's validation.
#   * native Linux (CI) — no remapping. The file really is owned by 10001 and
#     the runner (uid 1001) gets EACCES.
#
# The failure that produced was maximally misleading: the POSITIVE CONTROL
# reported "the allowed command produced no side effect" — declaring every
# negative result in the run uninterpretable — when the command had in fact
# produced exactly the side effect it was supposed to, and only the harness
# could not read it. An environment problem wearing the costume of a result,
# which is the pattern this whole suite exists to avoid.
#
# So evidence is read back THROUGH a container as root. Same answer on every
# engine, and it never depends on how the host's uid happens to line up.
ws_exists() { # scenario_workspace, filename
  docker run --rm --label fluidbox.gateproof=1 --user 0:0 -v "$1:/ws:ro" \
    --entrypoint sh "$IMAGE" -c "[ -f \"/ws/$2\" ]" >/dev/null 2>&1
}
ws_read() { # scenario_workspace, filename -> contents on stdout, empty if absent
  docker run --rm --label fluidbox.gateproof=1 --user 0:0 -v "$1:/ws:ro" \
    --entrypoint sh "$IMAGE" -c "cat \"/ws/$2\" 2>/dev/null" 2>/dev/null
}

# ── helpers that read the recorded evidence ────────────────────────────────
# `grep -c` prints 0 AND exits non-zero when there are no matches, so the old
# `|| echo 0` fired too and this returned the two-line string "0\n0" — making
# every caller's `[ "$(permission_calls)" -ge 1 ]` a syntax error
# (`[: 0\n0: integer expected`). It failed CLOSED, so no result was ever wrong,
# but the assertion messages printed a mangled count and scenario F's attempt
# arithmetic rested on it. `|| true` keeps grep's own single `0`.
# It must ALWAYS print exactly one integer: `grep -c` on a MISSING file prints
# nothing at all (the error goes to /dev/null), which would leave the comparison
# just as broken as before, with an empty operand instead of two.
permission_calls() {
  local n
  n=$(grep -c '"kind": "permission"' "$SC_LOG" 2>/dev/null || true)
  printf '%s' "${n:-0}"
}
digest_of() { printf '%s' "$1" | shasum -a 256 2>/dev/null | cut -d' ' -f1 || printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
# Did the command's OUTPUT come back to the model? (turn-2 tool_result)
executed_by_digest() { grep -q "$1" "$SC_LOG" 2>/dev/null; }

# ═══════════════════════════════════════════════════════════════════════════
printf "\n%s A — deny everything, READ-ONLY-classified probe (the class that bypassed)%s\n" "$BOLD" "$RESET"
run_scenario A deny 0 "printf '@NONCE@' | sha256sum"
A_DIGEST=$(digest_of "$SC_NONCE")
if [ "$(permission_calls)" -ge 1 ]; then
  ok "the gate WAS consulted ($(permission_calls) call(s)) — this is the fix"
else
  no "the gate was NEVER consulted — the bypass is back" \
     "This is the P0. A read-only-classified Bash command reached execution" \
     "without /permission being called. Evidence: $EVIDENCE/A.jsonl"
fi
if executed_by_digest "$A_DIGEST"; then
  no "the DENIED command executed anyway" \
     "digest $A_DIGEST of a nonce minted seconds ago came back in the tool_result" \
     "so the command really ran despite a deny verdict"
else
  ok "the denied command did NOT execute (its digest is absent from every turn)"
fi

printf "\n%s B — deny everything, MUTATING probe (host-visible side effect)%s\n" "$BOLD" "$RESET"
run_scenario B deny 0 "printf '@NONCE@' > @WS@/SIDE_EFFECT.txt"
# Checked through a container, not with a host stat: this assertion's failure
# mode is a FALSE PASS. A file the host cannot see for permission reasons would
# read as "the gate held".
if ws_exists "$SC_DIR/workspace" SIDE_EFFECT.txt; then
  no "the denied command wrote a file" "$(ws_read "$SC_DIR/workspace" SIDE_EFFECT.txt)"
else
  ok "no side effect in the bind-mounted workspace"
fi
[ "$(permission_calls)" -ge 1 ] && ok "the gate was consulted for the mutating probe" \
  || no "the gate was not consulted for the mutating probe"

printf "\n%s C — allow, MUTATING probe (POSITIVE CONTROL)%s\n" "$BOLD" "$RESET"
note "Without this, B proves nothing: an inert harness also produces no side effect."
run_scenario C allow 0 "printf '@NONCE@' > @WS@/SIDE_EFFECT.txt"
C_CONTENT=$(ws_read "$SC_DIR/workspace" SIDE_EFFECT.txt)
if printf '%s' "$C_CONTENT" | grep -q "$SC_NONCE"; then
  ok "the allowed command DID execute — the harness can produce the side effect"
elif ws_exists "$SC_DIR/workspace" SIDE_EFFECT.txt; then
  # Distinguished deliberately: "wrote the wrong bytes" and "wrote nothing" are
  # different faults, and conflating them is what made the CI failure read as a
  # security result.
  no "POSITIVE CONTROL FAILED — the allowed command wrote a file with unexpected content" \
     "expected the nonce $SC_NONCE, got: $(printf '%s' "$C_CONTENT" | head -c 120)" \
     "Runner log: $EVIDENCE/C.runner.log"
else
  no "POSITIVE CONTROL FAILED — the allowed command produced no side effect" \
     "Every negative result in this run is therefore uninterpretable." \
     "Runner log: $EVIDENCE/C.runner.log"
fi

printf "\n%s D — allow, READ-ONLY probe (POSITIVE CONTROL for the digest witness)%s\n" "$BOLD" "$RESET"
run_scenario D allow 0 "printf '@NONCE@' | sha256sum"
D_DIGEST=$(digest_of "$SC_NONCE")
if executed_by_digest "$D_DIGEST"; then
  ok "the allowed read-only command executed and its digest came back"
else
  no "POSITIVE CONTROL FAILED — an allowed read-only command produced no digest" \
     "The digest witness used in A is therefore not measuring anything." \
     "Runner log: $EVIDENCE/D.runner.log"
fi

printf "\n%s E — approval PRECEDES execution (verdict held open 6s)%s\n" "$BOLD" "$RESET"
run_scenario E allow 6 "printf '@NONCE@' > @WS@/SIDE_EFFECT.txt"
if ws_exists "$SC_DIR/workspace" SIDE_EFFECT.txt; then
  REQ=$(grep '"kind": "permission"' "$SC_LOG" | head -1 | python3 -c 'import sys,json;print(json.loads(sys.stdin.readline())["t_ms"])' 2>/dev/null || echo 0)
  ANS=$(grep '"kind": "permission_answered"' "$SC_LOG" | head -1 | python3 -c 'import sys,json;print(json.loads(sys.stdin.readline())["t_ms"])' 2>/dev/null || echo 0)
  WROTE=$(python3 -c "import os,sys;print(int(os.path.getmtime(sys.argv[1])*1000))" "$SC_DIR/workspace/SIDE_EFFECT.txt")
  note "requested ${REQ} · answered ${ANS} (+$((ANS-REQ))ms held) · written ${WROTE} (+$((WROTE-ANS))ms after the verdict)"
  if [ "$WROTE" -ge "$ANS" ]; then
    ok "the side effect appeared only AFTER the verdict — nothing ran while pending"
  else
    no "the side effect predates the verdict by $((ANS-WROTE))ms — execution raced the gate"
  fi
else
  no "E produced no side effect at all (expected one: mode=allow)"
fi

printf "\n%s F — the gate fails CLOSED on every broken answer%s\n" "$BOLD" "$RESET"
note "No path may become an allow. A control plane that is DOWN must block the tool"
note "indefinitely rather than release it, so 'still retrying at the deadline' is a pass."
# http500 retries forever by design, so it gets a short deadline and is expected
# to be killed still trying. The rest resolve promptly.
for spec in "http500:25" "unauth401:60" "wrongaud403:60" "nonjson:60" "emptyjson:60"; do
  m="${spec%%:*}"; lim="${spec##*:}"
  run_scenario "F-$m" "$m" 0 "printf '@NONCE@' > @WS@/SIDE_EFFECT.txt" "$lim"
  attempts=$(permission_calls)
  if ws_exists "$SC_DIR/workspace" SIDE_EFFECT.txt; then
    no "$m ALLOWED execution" "a broken control-plane answer must never become an allow"
  elif [ "$m" = "http500" ]; then
    if [ "$SC_TIMED_OUT" = "1" ] && [ "$attempts" -ge 2 ]; then
      ok "$m → blocked indefinitely, still retrying after ${lim}s ($attempts attempts), never executed"
    else
      no "$m did not block indefinitely" \
         "timed_out=$SC_TIMED_OUT attempts=$attempts exit=$SC_RC" \
         "A 5xx must make the runner keep asking, not give up and proceed."
    fi
  else
    ok "$m → no execution (runner exit $SC_RC, $attempts attempt(s), timed_out=$SC_TIMED_OUT)"
  fi
done

printf "\n%s──────────────────────────────────────────────────────%s\n" "$BOLD" "$RESET"
printf "  evidence: %s\n" "$EVIDENCE"
printf "  %sRESULT: %d passed, %d failed%s\n\n" "$BOLD" "$pass" "$fail" "$RESET"
[ "$fail" -eq 0 ] || exit 1
