# fluidbox replay runner — deterministic, model-free demo harness.
# Replays a baked transcript through the real runner contract; used by
# `just demo`. Ships no secrets; identity + wiring arrive via env at run time.
#
# BUILD CONTEXT = images/ (shared with the other runners):
#   docker build -t <img> -f images/replay-runner/Dockerfile images
FROM node:24-bookworm-slim

# bash ships with bookworm; git is for transcripts that inspect the workspace
# repo (policy-allowed read-only git commands).
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The driver is dependency-free: it uses only node built-ins plus the shared
# contract client. No npm install on purpose.
WORKDIR /opt/fluidbox-replay
COPY replay-runner/runner/index.mjs ./index.mjs
COPY replay-runner/runner/steps.mjs ./steps.mjs
COPY replay-runner/runner/transcript.json ./transcript.json
# The shared runner contract lib, at the same path the sandbox runner bakes —
# the driver's default import path matches, and entrypoint.sh is shared too.
COPY runner-lib /opt/fluidbox-runner/lib

RUN useradd -m -u 10001 runner \
    && mkdir -p /workspace \
    && chmod 0755 /opt/fluidbox-runner/lib/entrypoint.sh \
    && chown -R runner:runner /opt/fluidbox-replay /opt/fluidbox-runner /workspace
USER runner

WORKDIR /workspace
# Same token-handoff entrypoint as the sandbox runner: the runner-control
# credential arrives on an unlinked fd, never in /proc/<pid>/environ.
ENTRYPOINT ["/opt/fluidbox-runner/lib/entrypoint.sh", "node", "/opt/fluidbox-replay/index.mjs"]
