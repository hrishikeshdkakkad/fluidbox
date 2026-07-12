# fluidbox codex runner — the OpenAI Codex app-server harness as a sandbox
# payload. Second harness; EXACT behavioral parity with the Claude runner via
# the shared runner contract. Ships no secrets; identity + wiring arrive via
# env at run time. The codex binary is pinned (@openai/codex@0.144.1).
#
# The provider runs EVERY sandbox with `cap_drop=ALL` + `no-new-privileges`
# (harness-neutral hardening). That makes runtime privilege transitions
# impossible — no chown to another uid (CAP_CHOWN), no gosu/setuid drop
# (CAP_SETUID/SETGID). So, exactly like the claude image, ALL privileged setup
# happens at BUILD time and the container runs as an unprivileged `USER` with
# nothing to escalate. Config immutability is preserved by baking the config +
# rules root-owned READ-ONLY (the runner uid can neither modify nor delete
# them); the writable runtime state is runner-owned. Containers are always
# fresh from this image, so "baked at build" == "fresh each boot".
#
# BUILD CONTEXT = images/ (shared with the claude runner). Build with:
#   docker build -t <img> -f images/codex-runner/Dockerfile images
FROM node:24-bookworm-slim

# Coding toolchain. (No gosu: there is no runtime privilege drop — see above.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ripgrep curl ca-certificates python3 python3-pip python3-venv \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/fluidbox-codex
# Pin the codex binary (bin/codex.js + the platform-specific binary via
# optional deps) and the MCP SDK (broker-shim / sandbox-gate-shim).
COPY codex-runner/runner/package.json ./package.json
RUN npm install --omit=dev && npm cache clean --force

COPY codex-runner/runner/index.mjs ./index.mjs
COPY codex-runner/config.toml ./config.toml
COPY codex-runner/rules ./rules
# The shared runner contract lib + shims.
COPY runner-lib ./lib

# Structurally null-route codex's phone-home hosts (update check / telemetry /
# direct-OpenAI). Model traffic rides the fluidbox FACADE (host.docker.internal),
# never api.openai.com — with the custom [model_providers] + requires_openai_auth
# =false, codex has no reason to reach these, and the workspace is pre-fetched
# so the sandbox never needs github/npm either. Black-holing them is
# belt-and-suspenders with the egress-free hardened network mode; in HostDev
# it is the guard. The e2e network census asserts no unexpected egress.
RUN printf '%s\n' \
      '0.0.0.0 api.openai.com' \
      '0.0.0.0 chatgpt.com' \
      '0.0.0.0 auth.openai.com' \
    >> /etc/hosts || true

# All codex state (config, sessions, logs) lives here — relocated off $HOME so
# /workspace and the runner's home are never config-discovery roots.
ENV CODEX_HOME=/opt/fluidbox-codex/home
# The pinned codex binary is installed by npm into node_modules/.bin.
ENV PATH="/opt/fluidbox-codex/node_modules/.bin:${PATH}"

# The unprivileged run identity. useradd -m gives it a runner-owned /home/runner.
RUN useradd -m -u 10001 runner \
    && mkdir -p /workspace \
    && chown -R runner:runner /workspace

# ── Config immutability + writable state, all at BUILD time ──────────────────
# The ONLY governance-critical files are config.toml (approval_policy /
# sandbox_mode / model provider) and rules/default.rules (the execpolicy that
# forces every exec through the gate). Those are root-owned READ-ONLY inside a
# root-owned 0555 CODEX_HOME: the runner uid can neither overwrite them (0444)
# nor unlink+replace them (writing/unlinking a file needs write on the DIR, and
# CODEX_HOME/rules are 0555 root-owned).
#
# Codex ALSO writes non-critical state into CODEX_HOME at startup — it
# materializes its bundled system skills into skills/.system and (re)writes the
# installation markers. Those are created runner-owned so codex boots; they are
# NOT governance-critical (a skill still executes only via the gate). The
# writable sqlite (sqlite_home) + logs (log_dir) live OUTSIDE CODEX_HOME
# (config.toml relocates them), runner-owned.
RUN set -eux; \
    install -d -m 0555 "$CODEX_HOME" "$CODEX_HOME/rules"; \
    cp /opt/fluidbox-codex/config.toml "$CODEX_HOME/config.toml"; \
    cp /opt/fluidbox-codex/rules/default.rules "$CODEX_HOME/rules/default.rules"; \
    chown root:root "$CODEX_HOME" "$CODEX_HOME/config.toml" \
        "$CODEX_HOME/rules" "$CODEX_HOME/rules/default.rules"; \
    chmod 0555 "$CODEX_HOME" "$CODEX_HOME/rules"; \
    chmod 0444 "$CODEX_HOME/config.toml" "$CODEX_HOME/rules/default.rules"; \
    install -o runner -g runner -m 0644 /dev/null "$CODEX_HOME/installation_id"; \
    install -o runner -g runner -m 0644 /dev/null "$CODEX_HOME/.personality_migration"; \
    install -d -o runner -g runner -m 0755 \
        "$CODEX_HOME/skills" "$CODEX_HOME/tmp" "$CODEX_HOME/tmp/arg0" \
        /opt/fluidbox-codex/state /opt/fluidbox-codex/state/log

USER runner
WORKDIR /workspace
ENTRYPOINT ["node", "/opt/fluidbox-codex/index.mjs"]
