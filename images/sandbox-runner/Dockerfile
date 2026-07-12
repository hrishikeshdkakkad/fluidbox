# fluidbox sandbox runner — the Claude Agent SDK harness as a sandbox payload.
# The image ships no secrets; identity + wiring arrive via env at run time.
#
# BUILD CONTEXT = images/ (shared with the codex runner), so this Dockerfile
# reaches both sandbox-runner/ and the shared runner-lib/. Build with:
#   docker build -t <img> -f images/sandbox-runner/Dockerfile images
FROM node:24-bookworm-slim

# Toolchain the agent needs to actually do coding work.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ripgrep curl ca-certificates python3 python3-pip python3-venv \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/fluidbox-runner
COPY sandbox-runner/runner/package.json ./package.json
RUN npm install --omit=dev && npm cache clean --force

COPY sandbox-runner/runner/index.mjs ./index.mjs
COPY sandbox-runner/runner/servers ./servers
# The shared runner contract lib + shims (broker-shim, sandbox-gate-shim).
COPY runner-lib ./lib

# Non-root. /workspace is bind-mounted rw by the provider.
RUN useradd -m -u 10001 runner \
    && mkdir -p /workspace \
    && chown -R runner:runner /opt/fluidbox-runner /workspace
USER runner

WORKDIR /workspace
ENTRYPOINT ["node", "/opt/fluidbox-runner/index.mjs"]
