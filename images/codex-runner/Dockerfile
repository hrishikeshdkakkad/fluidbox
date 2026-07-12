# fluidbox codex runner — the OpenAI Codex app-server harness as a sandbox
# payload. Second harness; EXACT behavioral parity with the Claude runner via
# the shared runner contract. Ships no secrets; identity + wiring arrive via
# env at run time. The codex binary is pinned (@openai/codex@0.144.1).
#
# BUILD CONTEXT = images/ (shared with the claude runner). Build with:
#   docker build -t <img> -f images/codex-runner/Dockerfile images
FROM node:24-bookworm-slim

# Coding toolchain + gosu (clean privilege drop in the entrypoint).
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ripgrep curl ca-certificates python3 python3-pip python3-venv \
        build-essential gosu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/fluidbox-codex
# Pin the codex binary (bin/codex.js + the platform-specific binary via
# optional deps) and the MCP SDK (broker-shim / sandbox-gate-shim).
COPY codex-runner/runner/package.json ./package.json
RUN npm install --omit=dev && npm cache clean --force

COPY codex-runner/runner/index.mjs ./index.mjs
COPY codex-runner/config.toml ./config.toml
COPY codex-runner/rules ./rules
COPY codex-runner/entrypoint.sh ./entrypoint.sh
# The shared runner contract lib + shims.
COPY runner-lib ./lib
RUN chmod 0555 ./entrypoint.sh

# The unprivileged run identity. The entrypoint runs as ROOT (to lock the
# config), then gosu-drops to this uid. /workspace is bind-mounted rw.
RUN useradd -m -u 10001 runner \
    && mkdir -p /workspace \
    && chown -R runner:runner /workspace

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

WORKDIR /workspace
ENTRYPOINT ["/opt/fluidbox-codex/entrypoint.sh"]
