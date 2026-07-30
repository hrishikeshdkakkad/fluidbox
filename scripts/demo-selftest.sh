#!/usr/bin/env bash
# Static self-checks for scripts/demo.sh — the properties whose violation makes
# `just demo` fail on a FRESH CLONE, which is the one environment the demo exists
# to serve and the hardest one to keep in a test loop.
#
# Every check here is a real defect that shipped:
#
#   1. `BIN=$(server_bin)` captured the "first run: compiling…" line, because
#      warn/ok/die all print to STDOUT. The launcher then exec'd a multi-line
#      string. It failed ONLY on the from-source path — the path every new user
#      takes — and was invisible to the validation drills because they all set
#      FLUIDBOX_DEMO_SERVER_BIN, whose early return prints nothing.
#   2. The success-shaped receipt on a failed run (exit 0, "every tool call
#      crossed the server-side gate: 0 decisions").
#   3. The preflight validating the docker CLI's context while the server uses
#      bollard's DOCKER_HOST.
#
# No docker, no database, no network. Seconds.
#
#   scripts/demo-selftest.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
D=scripts/demo.sh

pass=0; fail=0
ok()  { printf '  ok        %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  FAIL      %s\n' "$1"; shift; for l in "$@"; do printf '            %s\n' "$l"; done; fail=$((fail + 1)); }

[ -f "$D" ] || { echo "missing $D" >&2; exit 1; }

bash -n "$D" && ok "demo.sh parses" || bad "demo.sh does not parse"

# Match against a COMMENT-STRIPPED copy, not the file.
#
# The first version of this script grepped the file and reported three failures
# on a correct demo.sh — because demo.sh now carries comments that quote each
# defect in order to explain it ("It used to `echo` the path and be called as
# BIN=$(server_bin)…"). A static checker that cannot tell code from a description
# of the bug it hunts is worse than none: it cries wolf on exactly the codebase
# that fixed the problem, and the natural response is to delete the check.
#
# Only whole-line comments are removed, so no line of code is ever hidden.
S=$(mktemp "${TMPDIR:-/tmp}/demo-selftest.XXXXXX")
trap 'rm -f "$S"' EXIT
grep -vE '^[[:space:]]*#' "$D" >"$S"

# ── 1. no command substitution may capture a function that prints diagnostics ──
if grep -nE '=\$\(\s*(server_bin|resolve_server_bin)' "$S" >/dev/null; then
  bad "the server binary path is captured from stdout" \
      "$(grep -nE '=\$\(\s*(server_bin|resolve_server_bin)' "$S")" \
      "warn/ok/die print to stdout, so the capture also swallows their text and" \
      "the launcher execs a multi-line string. Use the SERVER_BIN global."
else
  ok "the server binary path is not captured from stdout"
fi

if grep -qE '^\s*SERVER_BIN="' "$S" && grep -q '"\$SERVER_BIN"' "$S"; then
  ok "the launcher uses the SERVER_BIN global"
else
  bad "SERVER_BIN is not set-and-used" "expected a SERVER_BIN assignment and a \"\$SERVER_BIN\" launch"
fi

# The general form of defect 1: any `X=$(fn)` where fn is defined in this script
# and its body calls a printer. Catches the next one, not just this one.
printers='(^|[^[:alnum:]_])(ok|warn|say|die|note)[[:space:]]'
captured=$(grep -oE '\$\(\s*[a-z_][a-z0-9_]*\s*\)' "$S" | tr -d '$(): ' | sort -u)
offenders=""
for fn in $captured; do
  grep -qE "^${fn}\(\)" "$S" || continue        # not a local function
  body=$(awk "/^${fn}\\(\\) \\{/,/^\\}/" "$S")
  printf '%s' "$body" | grep -qE "$printers" && offenders="$offenders $fn"
done
if [ -n "$offenders" ]; then
  bad "captured function(s) print user-facing text:$offenders" \
      "their output lands in the variable instead of the terminal"
else
  ok "no captured function prints user-facing text"
fi

# ── 2. a failed run must not look like a success ─────────────────────────────
if grep -qE '\[ \$RUN_STATUS -le 3 \]' "$S"; then
  bad "a non-completed terminal state is treated as success" \
      "\`[ \$RUN_STATUS -le 3 ]\` accepts the watcher's deliberate 3"
else
  ok "a non-completed terminal state is not treated as success"
fi
grep -q 'RUN_OUTCOME' "$S" && ok "the terminal state is carried back for the failure banner" \
  || bad "no RUN_OUTCOME handling — the demo cannot report which state it ended in"
if grep -q 'every tool call crossed the server-side gate' "$S"; then
  bad "the receipt asserts the guarantee instead of reporting the measurement" \
      "on a failed run this prints '...gate: 0 decisions', which refutes itself"
else
  ok "the security receipt reports the measurement, not the guarantee"
fi

# ── 3. preflight and the server must resolve the same docker daemon ──────────
# Definition AND call. Testing only for the name is the same trap that let the
# gate suite stay green while the tripwire's only call site was deleted: a
# function's own declaration satisfies a presence check.
endpoint_defs=$(grep -cE '^resolve_docker_endpoint\(\)' "$S")
endpoint_uses=$(grep -cE '^[[:space:]]+resolve_docker_endpoint([[:space:]]|$)' "$S")
if [ "$endpoint_defs" -eq 1 ] && [ "$endpoint_uses" -ge 1 ] && grep -q 'export DOCKER_HOST=' "$S"; then
  ok "the docker endpoint is resolved once, called from preflight, and exported"
else
  bad "the docker endpoint resolution is defined but not called (defs=$endpoint_defs calls=$endpoint_uses)" \
      "the preflight would validate the CLI's context while the server uses bollard's DOCKER_HOST," \
      "which is how a run fails with 'No such image' after a green preflight"
fi

printf '\n%s: %d passed, %d failed\n' "$(basename "$0")" "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
