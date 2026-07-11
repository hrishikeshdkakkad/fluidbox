# fluidbox sandbox runner — the Claude Agent SDK harness as a sandbox payload.
# The image ships no secrets; identity + wiring arrive via env at run time.
FROM node:24-bookworm-slim

# Toolchain the agent needs to actually do coding work.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ripgrep curl ca-certificates python3 python3-pip python3-venv \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/fluidbox-runner
COPY runner/package.json ./package.json
RUN npm install --omit=dev && npm cache clean --force

COPY runner/index.mjs ./index.mjs
COPY runner/broker-shim.mjs ./broker-shim.mjs
COPY runner/servers ./servers

# Non-root. /workspace is bind-mounted rw by the provider.
RUN useradd -m -u 10001 runner \
    && mkdir -p /workspace \
    && chown -R runner:runner /opt/fluidbox-runner /workspace
USER runner

WORKDIR /workspace
ENTRYPOINT ["node", "/opt/fluidbox-runner/index.mjs"]
