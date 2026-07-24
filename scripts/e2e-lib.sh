#!/usr/bin/env bash
# Shared helpers for the fluidbox e2e suites. Source, don't execute:
#   source "$(dirname "$0")/e2e-lib.sh"
# Provides: ROOT, API, load_env, require_cmd, ok/no/say counters, j (JSON
# field extractor), port_in_use, wait_health, start_server, stop_server.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API=${FLUIDBOX_API_URL:-http://127.0.0.1:8787}
SERVER_PID=""
# XXXXXX must be the trailing characters (macOS mktemp requirement).
SERVER_LOG="${SERVER_LOG:-$(mktemp "${TMPDIR:-/tmp}/fbx-e2e-server.log.XXXXXX")}"

pass=0; fail=0
ok()  { printf "  \033[1;32m✓\033[0m %s\n" "$1"; pass=$((pass+1)); }
no()  { printf "  \033[1;31m✗\033[0m %s\n" "$1"; fail=$((fail+1)); }
say() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }

load_env() {
  [ -f "$ROOT/.env" ] || { echo "missing $ROOT/.env — copy .env.example and fill it in"; exit 1; }
  set -a; source "$ROOT/.env"; set +a
  # The acceptance fixtures are loopback-http BY CONSTRUCTION (fake AS, fake
  # GitHub API, plain-http callbacks, file:// clones), and the Phase-E egress
  # seams key on a loopback FLUIDBOX_PUBLIC_URL — a hosted/ngrok URL in .env
  # (real webhook work) turns the dev seam OFF and 400s every http fixture.
  # Pin the suite's posture regardless of what .env carries; CI runs loopback
  # and this makes local runs match it.
  export FLUIDBOX_PUBLIC_URL="http://127.0.0.1:8787"
}

require_cmd() {
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || { echo "missing required command: $c"; exit 1; }
  done
}

# Health lives under the public /v1 nest.
port_in_use() { curl -fsS -m 2 "$API/v1/health" >/dev/null 2>&1; }

wait_health() { # [tries × 0.5s]
  for _ in $(seq 1 "${1:-120}"); do
    curl -fsS -m 2 "$API/v1/health" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

# Start a control plane we own. cwd = repo root (the boot seeder reads
# ./policies); bind 0.0.0.0 so sandboxes reach us via host.docker.internal.
# `exec` makes the subshell PID the server PID.
start_server() {
  ( cd "$ROOT" && exec env FLUIDBOX_BIND=0.0.0.0:8787 \
      ./target/debug/fluidbox-server >>"$SERVER_LOG" 2>&1 ) &
  SERVER_PID=$!
  if ! wait_health 120; then
    echo "server failed to become healthy; last log lines:"
    tail -20 "$SERVER_LOG"
    return 1
  fi
}

stop_server() {
  [ -n "$SERVER_PID" ] || return 0
  kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  SERVER_PID=""
  for _ in $(seq 1 20); do port_in_use || return 0; sleep 0.5; done
  return 0
}
