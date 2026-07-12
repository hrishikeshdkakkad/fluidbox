// fluidbox runner contract — the HTTP client every harness image shares.
//
// A harness is a runner image that implements this contract over HTTP against
// the control plane's internal gateway. This module is that contract, so the
// Claude Agent SDK runner and the Codex supervisor differ only in how they
// drive their agent loop — the governance wiring (permission gate, events,
// heartbeat, token renewal, result) is identical and lives here ONCE.
//
// Endpoints (all under /internal/sessions/{id}):
//   POST /permission   — the gate; blocks in supervised mode, instant in autonomous
//   POST /events       — narrative timeline (advisory; the server owns decisions/usage)
//   POST /heartbeat    — liveness (every 10s, independent of any approval wait)
//   POST /result       — terminal outcome (from the final agent message)
// and POST /internal/token/renew — long-run token renewal.
//
// Model calls leave via the per-harness facade base URL using the session
// token as a fake provider key; the real key lives only in the gateway.

import crypto from "node:crypto";

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function requireEnv(k) {
  const v = process.env[k];
  if (!v) {
    console.error(`fluidbox-runner: missing required env ${k}`);
    process.exit(2);
  }
  return v;
}

// Absolute path of the shims inside every runner image (both Dockerfiles copy
// runner-lib/ here). Passed to the harness's MCP wiring.
export const RUNNER_LIB_DIR = "/opt/fluidbox-runner/lib";
export const BROKER_SHIM = `${RUNNER_LIB_DIR}/broker-shim.mjs`;
export const SANDBOX_GATE_SHIM = `${RUNNER_LIB_DIR}/sandbox-gate-shim.mjs`;

/// Parse the shared FLUIDBOX_* env into one object. CAPABILITIES is the
/// FROZEN manifest (the control plane already stripped broker internals — no
/// upstream URLs or credentials reach this process).
export function loadRunnerEnv() {
  const CONTROL = requireEnv("FLUIDBOX_CONTROL_URL");
  const SESSION = requireEnv("FLUIDBOX_SESSION_ID");
  const TOKEN = requireEnv("FLUIDBOX_SESSION_TOKEN");
  const TASK = requireEnv("FLUIDBOX_TASK");
  const capabilities = (() => {
    const raw = process.env.FLUIDBOX_CAPABILITIES;
    if (!raw) return { servers: [] };
    try {
      const parsed = JSON.parse(raw);
      return { servers: Array.isArray(parsed?.servers) ? parsed.servers : [] };
    } catch (e) {
      console.error("fluidbox-runner: bad FLUIDBOX_CAPABILITIES (ignoring):", e.message);
      return { servers: [] };
    }
  })();
  return {
    CONTROL,
    SESSION,
    TOKEN,
    TASK,
    AUTONOMY: process.env.FLUIDBOX_AUTONOMY || "supervised",
    MODEL: process.env.FLUIDBOX_MODEL || "",
    WORKSPACE: process.env.FLUIDBOX_WORKSPACE || "/workspace",
    SYSTEM_PROMPT: process.env.FLUIDBOX_SYSTEM_PROMPT || undefined,
    MAX_TURNS: parseInt(process.env.FLUIDBOX_MAX_TURNS || "60", 10),
    CAPABILITIES: capabilities,
    // Brokered aliases: canUseTool (claude) / the codex supervisor wave these
    // through — the broker endpoint re-runs the identical gate server-side.
    BROKERED: new Set(
      capabilities.servers.filter((s) => s.class === "brokered").map((s) => s.name),
    ),
  };
}

// `mcp__<server>__<tool>` → server alias (aliases carry no underscores, so
// the first `__` after the prefix splits unambiguously).
export function mcpServerOf(toolName) {
  if (typeof toolName !== "string" || !toolName.startsWith("mcp__")) return null;
  const rest = toolName.slice(5);
  const i = rest.indexOf("__");
  return i > 0 ? rest.slice(0, i) : null;
}

// One-line summary of a canonical tool input, for the timeline/approval card.
export function summarizeInput(tool, input) {
  if (!input || typeof input !== "object") return tool;
  if (typeof input.command === "string") return input.command.slice(0, 200);
  if (typeof input.file_path === "string") return input.file_path;
  if (Array.isArray(input.edits) && typeof input.edits[0]?.file_path === "string") {
    return input.edits.map((e) => e.file_path).join(", ").slice(0, 200);
  }
  if (typeof input.path === "string") return input.path;
  if (typeof input.pattern === "string") return `pattern: ${input.pattern}`;
  return tool;
}

/// The runner contract client. Bind it to the loaded env; each harness calls
/// the same methods.
export class RunnerClient {
  constructor(env) {
    this.env = env;
    this.heartbeatTimer = null;
    this.renewTimer = null;
    // TTL-aware renewal: the server mints ~3h tokens and caps each renew at
    // ~3h, so renew every 90 min — comfortably ahead of expiry even across a
    // long supervised approval wait, and a no-op (renewed:false) once the
    // session goes terminal (the server revokes tokens then).
    this.renewIntervalMs = 90 * 60 * 1000;
  }

  sessionBase() {
    return `${this.env.CONTROL.replace(/\/$/, "")}/internal/sessions/${this.env.SESSION}`;
  }

  async #post(url, body, { retries = 0, timeoutMs = 30000 } = {}) {
    for (let attempt = 0; ; attempt++) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const res = await fetch(url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${this.env.TOKEN}`,
          },
          body: JSON.stringify(body),
          signal: ctrl.signal,
        });
        clearTimeout(timer);
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          throw new Error(`${url} → HTTP ${res.status}: ${text}`);
        }
        return res.status === 204 ? null : await res.json().catch(() => null);
      } catch (e) {
        clearTimeout(timer);
        if (attempt >= retries) throw e;
        await sleep(Math.min(2000 * (attempt + 1), 8000));
      }
    }
  }

  async emit(actor, body) {
    try {
      await this.#post(`${this.sessionBase()}/events`, { actor, body }, { retries: 3 });
    } catch (e) {
      console.error("fluidbox-runner: emit failed (continuing):", e.message);
    }
  }

  /// The permission gate. Blocks until the control plane answers (supervised
  /// may hold it minutes; autonomous is instant). The client timeout exceeds
  /// the server's 10-min approval TTL, and we retry FOREVER on transient
  /// errors reusing the SAME tool_call_id — the server dedupes, so a socket
  /// drop never risks a double-decision or a hung tool. input_digest is left
  /// empty; the SERVER computes the authoritative digest (Phase 6).
  async requestPermission(toolName, input, toolCallId) {
    const body = { tool_call_id: toolCallId, tool: toolName, input };
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.#post(`${this.sessionBase()}/permission`, body, {
          timeoutMs: 12 * 60 * 1000,
        });
      } catch (e) {
        console.error(`fluidbox-runner: permission attempt ${attempt} failed:`, e.message);
        await sleep(Math.min(2000 * (attempt + 1), 10000));
      }
    }
  }

  startHeartbeat() {
    this.heartbeatTimer = setInterval(() => {
      this.#post(`${this.sessionBase()}/heartbeat`, {}, { retries: 1 }).catch(() => {});
    }, 10000);
    this.heartbeatTimer.unref?.();
  }

  /// Renew the session token ahead of expiry so a long autonomous run never
  /// loses its facade/gateway access mid-flight. Independent of the heartbeat
  /// and never coupled to an approval wait. Stops on its own once the server
  /// reports the token can no longer be renewed (terminal session).
  startTokenRenew() {
    const url = `${this.env.CONTROL.replace(/\/$/, "")}/internal/token/renew`;
    this.renewTimer = setInterval(async () => {
      try {
        const res = await this.#post(url, { ttl_secs: 3 * 3600 }, { retries: 2 });
        if (res && res.renewed === false) {
          // Terminal or revoked — nothing left to renew.
          this.stopTokenRenew();
        }
      } catch (e) {
        console.error("fluidbox-runner: token renew failed (will retry):", e.message);
      }
    }, this.renewIntervalMs);
    this.renewTimer.unref?.();
  }

  stopTokenRenew() {
    if (this.renewTimer) {
      clearInterval(this.renewTimer);
      this.renewTimer = null;
    }
  }

  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  async postResult(outcome, summary) {
    await this.#post(
      `${this.sessionBase()}/result`,
      { outcome, summary: (summary || "").slice(0, 4000) },
      { retries: 5 },
    );
  }
}

/// Env a brokered server's broker-shim needs. Shared by every harness — the
/// broker path is identical for claude and codex (control-plane gate +
/// execute; the shim holds only the session token).
export function brokerShimEnv(env, srv) {
  return {
    ...process.env,
    FLUIDBOX_BROKER_SERVER: srv.name,
    FLUIDBOX_BROKER_TOOLS: JSON.stringify(srv.tools || []),
  };
}

/// Env a sandbox server's gate-shim needs (codex path — the shim gates each
/// call via /permission before spawning the real stdio subprocess). Claude
/// runs sandbox servers directly and gates them through canUseTool instead.
export function gateShimEnv(env, srv) {
  return {
    ...process.env,
    FLUIDBOX_GATE_SERVER: srv.name,
    FLUIDBOX_GATE_COMMAND: srv.command,
    FLUIDBOX_GATE_ARGS: JSON.stringify(srv.args || []),
    FLUIDBOX_GATE_TOOLS: JSON.stringify(srv.tools || []),
  };
}

export { crypto };
