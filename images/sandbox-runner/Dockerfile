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

# Non-root. /workspace is bind-mounted rw by the provider. The mode on
# entrypoint.sh is asserted here rather than inherited from the build context,
# so a lost exec bit in a checkout can never make the image unstartable.
RUN useradd -m -u 10001 runner \
    && mkdir -p /workspace \
    && chmod 0755 /opt/fluidbox-runner/lib/entrypoint.sh \
    && chown -R runner:runner /opt/fluidbox-runner /workspace
USER runner

WORKDIR /workspace
# NOT `node index.mjs` directly: entrypoint.sh moves the runner-control token
# out of the environment and hands it over on an unlinked-file fd, then `exec`s
# this exact command — so node is still pid 1 (signals reach it unchanged) but
# its execve-fixed /proc/<pid>/environ never contains the credential. See
# images/runner-lib/entrypoint.sh, including what it does NOT close (ptrace).
ENTRYPOINT ["/opt/fluidbox-runner/lib/entrypoint.sh", "node", "/opt/fluidbox-runner/index.mjs"]
