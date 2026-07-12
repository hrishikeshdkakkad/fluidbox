#!/usr/bin/env bash
# fluidbox codex-runner entrypoint. Runs as ROOT to lock the codex config
# down beyond the reach of the agent, then drops to the unprivileged runner
# uid to actually run. The agent never gets a writable config, and /workspace
# is never a config-discovery root.
set -euo pipefail

CODEX_HOME="${CODEX_HOME:-/opt/fluidbox-codex/home}"

# Materialize config.toml FRESH each boot as root, then make it read-only and
# root-owned so the agent (runner uid) cannot amend it at run time. The
# security-critical settings are ALSO re-asserted as `-c` CLI overrides by the
# supervisor (defense in depth against a tampered file).
install -d -m 0755 "$CODEX_HOME" "$CODEX_HOME/rules"
cp /opt/fluidbox-codex/config.toml "$CODEX_HOME/config.toml"
# The execpolicy rules that force EVERY exec through the fluidbox gate.
cp /opt/fluidbox-codex/rules/default.rules "$CODEX_HOME/rules/default.rules"
chown -R root:root "$CODEX_HOME"
chmod -R a-w "$CODEX_HOME"
chmod 0555 "$CODEX_HOME" "$CODEX_HOME/rules"
chmod 0444 "$CODEX_HOME/config.toml" "$CODEX_HOME/rules/default.rules"

# The agent's HOME must not be a config-discovery root either. Give the runner
# a clean, empty home it owns (for caches) that carries no codex config.
install -d -o runner -g runner -m 0755 /home/runner

# Drop privileges and exec the supervisor as the runner uid. gosu re-execs (no
# extra process, no TTY games), so PID 1 semantics stay clean for the child
# monitor.
exec gosu runner:runner node /opt/fluidbox-codex/index.mjs
