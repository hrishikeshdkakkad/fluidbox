#!/usr/bin/env bash
# fluidbox codex-runner entrypoint. Runs as ROOT to lock the codex config +
# execpolicy rules beyond the reach of the agent, then drops to the
# unprivileged runner uid to actually run. The agent never gets a writable
# config or rules; codex's writable runtime state lives OUTSIDE CODEX_HOME.
set -euo pipefail

CODEX_HOME="${CODEX_HOME:-/opt/fluidbox-codex/home}"
STATE_DIR="/opt/fluidbox-codex/state"

# ── Immutable layer (root-owned, read-only): config + rules + skills ──
# Materialized FRESH each boot; the agent (runner uid) cannot modify OR delete
# these (the parent dir is root-owned, so no dir-write to unlink files).
install -d -m 0755 "$CODEX_HOME" "$CODEX_HOME/rules"
cp /opt/fluidbox-codex/config.toml "$CODEX_HOME/config.toml"
cp /opt/fluidbox-codex/rules/default.rules "$CODEX_HOME/rules/default.rules"
# Pre-create the one-time markers so codex never needs to WRITE them into the
# read-only home (it only reads them if present).
: > "$CODEX_HOME/installation_id"
: > "$CODEX_HOME/.personality_migration"
# Materialize bundled system skills read-only if the binary ships them.
install -d -m 0555 "$CODEX_HOME/skills" "$CODEX_HOME/skills/.system" 2>/dev/null || true
chown -R root:root "$CODEX_HOME"
find "$CODEX_HOME" -type d -exec chmod 0555 {} +
find "$CODEX_HOME" -type f -exec chmod 0444 {} +

# ── Writable state (runner-owned): sqlite + logs + tmp/arg0 ──
# codex writes state_/logs_/goals_/memories_ sqlite here (+ WAL/SHM) and uses
# tmp/arg0 for executable path aliases — none of which may touch the immutable
# config/rules. Kept OUTSIDE CODEX_HOME entirely (sqlite_home/log_dir config).
install -d -o runner -g runner -m 0755 "$STATE_DIR" "$STATE_DIR/log"
install -d -o runner -g runner -m 0755 "$CODEX_HOME/tmp" "$CODEX_HOME/tmp/arg0"
# A clean, empty home for the runner (caches) that carries NO codex config.
install -d -o runner -g runner -m 0755 /home/runner

# Drop privileges and exec the supervisor as the runner uid. gosu re-execs (no
# extra process, no TTY games), so PID-1 semantics stay clean for the child
# monitor.
exec gosu runner:runner node /opt/fluidbox-codex/index.mjs
