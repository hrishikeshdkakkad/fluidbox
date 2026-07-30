# fluidbox qwen runner — the Qwen Code harness as a sandbox payload. Third
# harness; EXACT behavioral parity with the Claude and Codex runners via the
# shared runner contract. Ships no secrets; identity + wiring arrive via env
# at run time. The CLI + SDK are pinned exactly (@qwen-code/qwen-code@0.21.1,
# @qwen-code/sdk@0.1.8) — Qwen ships weekly minors, and every governance fact
# in docs/research/2026-07-30-qwen-code-sdk-protocol.md was verified against
# these pins (the version-bump checklist lives there).
#
# The provider runs EVERY sandbox with `cap_drop=ALL` + `no-new-privileges`
# (harness-neutral hardening), so ALL privileged setup happens at BUILD time
# and the container runs as an unprivileged `USER` with nothing to escalate —
# the same discipline both sibling images ship (the codex bring-up proved any
# runtime chown/gosu dies at the first syscall).
#
# BUILD CONTEXT = images/ (shared with the other runners). Build with:
#   docker build -t <img> -f images/qwen-runner/Dockerfile images
FROM node:24-bookworm-slim

# Coding toolchain the agent needs to do real work (parity with siblings).
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ripgrep curl ca-certificates python3 python3-pip python3-venv \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/fluidbox-qwen
# Pin the SDK (spawns + drives the CLI over stream-json), the CLI itself
# (the supervisor points pathToQwenExecutable at THIS install, never the
# SDK's bundled copy), and the MCP SDK (broker shim).
COPY qwen-runner/runner/package.json ./package.json
RUN npm install --omit=dev && npm cache clean --force

COPY qwen-runner/runner/index.mjs ./runner/index.mjs
COPY qwen-runner/runner/canonicalize.mjs ./runner/canonicalize.mjs
COPY qwen-runner/settings.json ./settings.json
# The shared runner contract lib + shims.
COPY runner-lib ./lib

# Structurally null-route qwen's own provider/phone-home hosts. Model traffic
# rides the fluidbox FACADE (OPENAI_BASE_URL → host.docker.internal), never
# DashScope or qwen.ai — with auth.selectedType=openai + the env-injected
# base URL, the CLI has no reason to reach these; telemetry is disabled in
# settings. Black-holing them is belt-and-suspenders with the egress-free
# hardened network mode; in HostDev it is the guard.
RUN printf '%s\n' \
      '0.0.0.0 dashscope.aliyuncs.com' \
      '0.0.0.0 dashscope-intl.aliyuncs.com' \
      '0.0.0.0 chat.qwen.ai' \
      '0.0.0.0 portal.qwen.ai' \
      '0.0.0.0 api.openai.com' \
    >> /etc/hosts || true

# The ONE governance-critical file is settings.json (approval mode, the
# permissions.ask interception rules, the tool lockdown, auth type, telemetry
# off). System scope OUTRANKS workspace/user scopes for scalars and the
# permissions arrays union-merge, so a repo-committed .qwen/settings.json can
# only ADD restrictions — but the file itself must be immutable: root-owned
# 0444 inside root-owned 0555 directories (the runner uid can neither
# overwrite nor unlink+replace it).
ENV QWEN_CODE_SYSTEM_SETTINGS_PATH=/opt/fluidbox-qwen/settings.json

# The unprivileged run identity. useradd -m gives it a writable /home/runner —
# the qwen CLI writes runtime state under $HOME/.qwen at boot (installation_id,
# projects/, skills/, tmp/, usage/ — enumerated in the research doc §6; the
# codex bring-up's BLOCKER #3 lesson is why this is deliberate, not an
# accident). None of it is governance-critical: permissions live in the
# system-scope file above, which user scope cannot relax.
RUN useradd -m -u 10001 runner \
    && mkdir -p /workspace \
    && chown -R runner:runner /workspace \
    && chown root:root /opt/fluidbox-qwen /opt/fluidbox-qwen/runner /opt/fluidbox-qwen/settings.json \
    && chmod 0555 /opt/fluidbox-qwen /opt/fluidbox-qwen/runner \
    && chmod 0444 /opt/fluidbox-qwen/settings.json \
    && chmod 0755 /opt/fluidbox-qwen/lib/entrypoint.sh

USER runner
WORKDIR /workspace
# NOT `node runner/index.mjs` directly: entrypoint.sh moves the runner-control
# token out of the environment and hands it over on an unlinked-file fd, then
# `exec`s this exact command — node stays pid 1 but its execve-fixed
# /proc/<pid>/environ never contains the credential. Root-owned like the rest
# of /opt/fluidbox-qwen, so the runner uid cannot rewrite its own entrypoint.
ENTRYPOINT ["/opt/fluidbox-qwen/lib/entrypoint.sh", "node", "/opt/fluidbox-qwen/runner/index.mjs"]
