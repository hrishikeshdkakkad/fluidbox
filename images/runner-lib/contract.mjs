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
import { fileURLToPath } from "node:url";

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function requireEnv(k) {
  const v = process.env[k];
  if (!v) {
    console.error(`fluidbox-runner: missing required env ${k}`);
    process.exit(2);
  }
  return v;
}

// ─── Audience mismatch: a FATAL misconfiguration, never a verdict ──────────
//
// Gap 10 gave every internal route a required audience, and the control plane
// refuses a wrong-audience credential with `403 {"error":"wrong_audience"}`.
// That refusal must NOT be collapsed into the ordinary 401/403 "the session is
// over" handling, which answers `deny` and lets the agent keep going: a runner
// image whose token wiring disagrees with the control plane's route guards
// would then have EVERY tool call denied while model spend proceeds normally,
// and the run would finish with a plausible summary that is simply wrong.
// Wrong-and-expensive-and-looks-right is the worst failure shape we have, so
// this class aborts the process instead.
export const EXIT_AUDIENCE_MISMATCH = 3;

/// True iff an HTTP refusal is the control plane's audience guard. Keyed off
/// the BODY code (`{"error":"wrong_audience"}`) rather than the status, because
/// 403 alone is also how a terminal session refuses. Robust to a non-JSON body
/// (a proxy error page, an empty body): JSON is tried first, then a plain
/// substring — that code word appears in no other refusal we emit.
export function isWrongAudienceRefusal(status, bodyText) {
  if (status !== 401 && status !== 403) return false;
  if (typeof bodyText !== "string" || bodyText.length === 0) return false;
  try {
    const parsed = JSON.parse(bodyText);
    if (parsed && typeof parsed === "object" && parsed.error === "wrong_audience") return true;
  } catch {
    // Not JSON — fall through to the substring check.
  }
  return bodyText.includes("wrong_audience");
}

/// The one-line operator diagnostic. Names the likely cause, because in
/// practice there is only one: the runner image and the control plane were not
/// deployed together (images ship IN this repo and are versioned with the
/// server — a PINNED pre-split image on a post-split server is the reachable
/// shape, since `runner_image` is a per-revision API field that carries forward
/// across revisions).
export function audienceMismatchDiagnostic(where) {
  return (
    `fluidbox-runner: FATAL — the control plane refused this credential at ${where} with ` +
    `'wrong_audience'; this runner image predates (or disagrees with) the audience-scoped ` +
    `credential split, and the runner image and control plane MUST be deployed together. ` +
    `Aborting the run: continuing would deny every tool call while model spend proceeds, ` +
    `producing a wrong result that looks right.`
  );
}

// Shim paths, derived from THIS module's own location — so they resolve
// correctly no matter where each image installs the lib (the claude image at
// /opt/fluidbox-runner/lib, the codex image at /opt/fluidbox-codex/lib).
export const RUNNER_LIB_DIR = fileURLToPath(new URL(".", import.meta.url)).replace(/\/$/, "");
export const BROKER_SHIM = fileURLToPath(new URL("./broker-shim.mjs", import.meta.url));
export const SANDBOX_GATE_SHIM = fileURLToPath(new URL("./sandbox-gate-shim.mjs", import.meta.url));

/// Parse the shared FLUIDBOX_* env into one object. CAPABILITIES is the
/// FROZEN manifest (the control plane already stripped broker internals — no
/// upstream URLs or credentials reach this process).
///
/// AUDIENCE-SCOPED CREDENTIALS (Gap 10). The control plane now mints one token
/// per audience and the routes enforce which is accepted:
///   TOKEN      (FLUIDBOX_SESSION_TOKEN) — runner-control: events, heartbeat,
///              result, token renew. The harness DELETES this var from
///              process.env before spawning the agent, so it lives only here.
///   TOOL_TOKEN (FLUIDBOX_TOOL_TOKEN)    — tool intent: /permission, /tools/call.
///   LLM_TOKEN  (FLUIDBOX_LLM_TOKEN)     — model egress at the facade (codex;
///              claude's SDK reads ANTHROPIC_API_KEY directly).
/// Both scoped vars fall back to TOKEN so a NEW image still runs against an OLD
/// server, where the single legacy token carries audience 'all' and every route
/// accepts it. (The reverse — an OLD image on a NEW server — is unsupported and
/// fails closed at the tool gate; see harness.rs.)
export function loadRunnerEnv() {
  const CONTROL = requireEnv("FLUIDBOX_CONTROL_URL");
  const SESSION = requireEnv("FLUIDBOX_SESSION_ID");
  const TOKEN = requireEnv("FLUIDBOX_SESSION_TOKEN");
  const TOOL_TOKEN = process.env.FLUIDBOX_TOOL_TOKEN || TOKEN;
  const LLM_TOKEN = process.env.FLUIDBOX_LLM_TOKEN || TOKEN;
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
    TOOL_TOKEN,
    LLM_TOKEN,
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
    // Renewal cadence: the server mints ~3h tokens and caps each renew at 3h,
    // so a 45-min success cadence keeps ≥2 full failed cycles of runway; a
    // transient failure reschedules in 2 min (well before any deadline), not
    // a full interval later.
    this.renewOkMs = 45 * 60 * 1000;
    this.renewRetryMs = 2 * 60 * 1000;
    // Quiesce (the sole additive runner-contract field): the heartbeat
    // response carries {"action":"quiesce"} once the control plane cancels the
    // run. We invoke the harness-registered abort callback ONCE, which stops
    // the agent and exits WITHOUT posting /result (the cancel finalizer owns
    // the outcome). Registered via onQuiesce(); harness-specific, one place.
    this.quiesceCb = null;
    this.quiesced = false;
    // Latch for the fatal audience-mismatch abort below: the FIRST detection
    // owns the exit, every later caller just parks.
    this.audienceAborting = false;
  }

  /// Abort the run on a `wrong_audience` refusal (Gap 10). Never returns: it
  /// logs the diagnostic, best-effort records it on the run's timeline, and
  /// exits non-zero so nothing downstream mistakes a misconfiguration for a
  /// governance verdict. Deliberately does NOT post /result — a runner whose
  /// credential wiring the control plane just rejected has not earned the right
  /// to write a terminal outcome; the heartbeat watchdog terminalizes the
  /// exited run, exactly as it does for any runner crash.
  async #abortAudienceMismatch(where) {
    if (this.audienceAborting) {
      // Never resolves: concurrent callers must not continue, and the first
      // detection's process.exit is moments away.
      return new Promise(() => {});
    }
    this.audienceAborting = true;
    const diag = audienceMismatchDiagnostic(where);
    console.error(diag);
    // RAW fetch, never #post — #post is what detected this, and re-entering it
    // would recurse. Hard 5s cap; a failure here changes nothing. In the
    // pinned-old-image shape the single legacy token IS the runner-control
    // credential, so /events accepts it and the diagnostic reaches the run
    // timeline rather than only the container log.
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 5000);
      try {
        await fetch(`${this.sessionBase()}/events`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${this.env.TOKEN}`,
          },
          body: JSON.stringify({
            actor: "harness",
            body: { type: "agent.message", data: { role: "system", text: diag } },
          }),
          signal: ctrl.signal,
        });
      } finally {
        clearTimeout(timer);
      }
    } catch (e) {
      console.error(
        "fluidbox-runner: could not record the audience-mismatch diagnostic:",
        e?.message || e,
      );
    }
    process.exit(EXIT_AUDIENCE_MISMATCH);
  }

  /// Register the harness abort callback fired when the control plane asks the
  /// run to quiesce (cancellation). Called at most once. The callback should
  /// stop the agent loop and let the process exit 0 without posting /result.
  /// A quiesce that arrived BEFORE registration (heartbeats start first in
  /// some harnesses) is replayed here — never swallowed.
  onQuiesce(cb) {
    this.quiesceCb = cb;
    if (this.quiesced && cb) {
      console.error("fluidbox-runner: replaying quiesce received before handler registration");
      try {
        cb();
      } catch (e) {
        console.error("fluidbox-runner: quiesce callback threw:", e?.message || e);
      }
    }
  }

  #maybeQuiesce(res) {
    if (this.quiesced || !res || res.action !== "quiesce") return;
    // Latching without a handler would swallow the cancel permanently: the
    // next heartbeat re-delivers, and onQuiesce replays if we latch later.
    this.quiesced = true;
    console.error("fluidbox-runner: control plane requested quiesce — stopping agent");
    if (!this.quiesceCb) {
      console.error("fluidbox-runner: quiesce before handler registration; will replay on registration");
      return;
    }
    try {
      this.quiesceCb?.();
    } catch (e) {
      console.error("fluidbox-runner: quiesce callback threw:", e?.message || e);
    }
  }

  sessionBase() {
    return `${this.env.CONTROL.replace(/\/$/, "")}/internal/sessions/${this.env.SESSION}`;
  }

  // `token` selects the AUDIENCE this call authenticates with (Gap 10). It
  // defaults to the runner-control credential, which is what events, heartbeat,
  // result and token-renew need; the tool gate passes TOOL_TOKEN explicitly.
  async #post(url, body, { retries = 0, timeoutMs = 30000, token = this.env.TOKEN } = {}) {
    for (let attempt = 0; ; attempt++) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const res = await fetch(url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${token}`,
          },
          body: JSON.stringify(body),
          signal: ctrl.signal,
        });
        clearTimeout(timer);
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          const err = new Error(`${url} → HTTP ${res.status}: ${text}`);
          err.status = res.status;
          err.body = text;
          // Checked HERE, once, so EVERY route (permission, events, heartbeat,
          // result, renew) gets the fatal treatment rather than each caller's
          // local 4xx policy. Never returns.
          if (isWrongAudienceRefusal(res.status, text)) {
            await this.#abortAudienceMismatch(url);
          }
          throw err;
        }
        return res.status === 204 ? null : await res.json().catch(() => null);
      } catch (e) {
        clearTimeout(timer);
        // Retry only TRANSIENT failures: a network error (no status), a
        // request-timeout / too-early / rate-limit, or a 5xx. A hard 4xx
        // (400/401/403/404) will never heal on retry — surface it at once so
        // callers (e.g. the renew loop) can act on the status immediately.
        const s = e.status;
        const retryable =
          s === undefined || s === 408 || s === 425 || s === 429 || (s >= 500 && s < 600);
        if (!retryable || attempt >= retries) throw e;
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
        // The gate is the TOOL-INTENT audience — never the control credential.
        return await this.#post(`${this.sessionBase()}/permission`, body, {
          timeoutMs: 12 * 60 * 1000,
          token: this.env.TOOL_TOKEN,
        });
      } catch (e) {
        // A terminal 401/403 means the session is gone (token revoked on the
        // terminal transition) — retrying forever would hang the runner. Treat
        // it as a hard DENY and stop. A `wrong_audience` 403 NEVER reaches here:
        // #post aborts the process on that body code, precisely so a credential
        // misconfiguration is not laundered into a governance verdict.
        if (e.status === 401 || e.status === 403) {
          console.error("fluidbox-runner: permission rejected (session terminal) — deny");
          return { decision: "deny", message: "session is not active" };
        }
        console.error(`fluidbox-runner: permission attempt ${attempt} failed:`, e.message);
        await sleep(Math.min(2000 * (attempt + 1), 10000));
      }
    }
  }

  startHeartbeat() {
    this.heartbeatTimer = setInterval(() => {
      this.#post(`${this.sessionBase()}/heartbeat`, {}, { retries: 1 })
        .then((res) => this.#maybeQuiesce(res))
        .catch(() => {});
    }, 10000);
    this.heartbeatTimer.unref?.();
  }

  /// Renew the session token ahead of expiry so a long autonomous run never
  /// loses its facade/gateway access mid-flight. A SELF-RESCHEDULING loop
  /// (not a fixed interval): an immediate startup renew removes mint-to-launch
  /// skew, a success reschedules at the 45-min cadence, a transient failure
  /// reschedules in 2 min (well before the deadline), and a terminal (400) or
  /// revoked/unauthorized (401/403) response stops it PERMANENTLY — the run
  /// is over. Independent of the heartbeat and never coupled to an approval
  /// wait; the timer is unref'd so it never keeps the process alive.
  startTokenRenew() {
    const url = `${this.env.CONTROL.replace(/\/$/, "")}/internal/token/renew`;
    const schedule = (ms) => {
      this.renewTimer = setTimeout(tick, ms);
      this.renewTimer.unref?.();
    };
    const tick = async () => {
      try {
        const res = await this.#post(url, { ttl_secs: 3 * 3600 }, { retries: 1 });
        if (res && res.renewed === false) {
          this.stopTokenRenew(); // revoked in a race — nothing left to renew
          return;
        }
        schedule(this.renewOkMs);
      } catch (e) {
        if (e.status === 400 || e.status === 401 || e.status === 403) {
          // Terminal session or revoked token — the run is over. Stop.
          this.stopTokenRenew();
          return;
        }
        console.error("fluidbox-runner: token renew failed (retrying soon):", e.message);
        schedule(this.renewRetryMs);
      }
    };
    schedule(0); // immediate startup renew
  }

  stopTokenRenew() {
    if (this.renewTimer) {
      clearTimeout(this.renewTimer);
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
    // The server makes /result idempotent to the terminal-transition token
    // revoke (a revoked token whose session is already terminal is ACKed
    // 200), so a lost-response retry never needs a runner-side 401 hack.
    await this.#post(
      `${this.sessionBase()}/result`,
      { outcome, summary: (summary || "").slice(0, 4000) },
      { retries: 5 },
    );
  }
}

/// Env a brokered server's broker-shim needs. Shared by every harness — the
/// broker path is identical for claude and codex (control-plane gate +
/// execute). The shim calls /tools/call, so it receives the TOOL-INTENT token
/// EXPLICITLY: `process.env` no longer carries the control credential (the
/// harness deleted it before any spawn), and the shim must never hold one.
export function brokerShimEnv(env, srv) {
  return {
    ...process.env,
    FLUIDBOX_TOOL_TOKEN: env.TOOL_TOKEN,
    FLUIDBOX_BROKER_SERVER: srv.name,
    FLUIDBOX_BROKER_TOOLS: JSON.stringify(srv.tools || []),
  };
}

/// Env a sandbox server's gate-shim needs (codex path — the shim gates each
/// call via /permission before spawning the real stdio subprocess). Claude
/// runs sandbox servers directly and gates them through canUseTool instead.
/// Like the broker shim it preflights a TOOL-INTENT route, so it gets that
/// token explicitly and never the runner-control one.
export function gateShimEnv(env, srv) {
  return {
    ...process.env,
    FLUIDBOX_TOOL_TOKEN: env.TOOL_TOKEN,
    FLUIDBOX_GATE_SERVER: srv.name,
    FLUIDBOX_GATE_COMMAND: srv.command,
    FLUIDBOX_GATE_ARGS: JSON.stringify(srv.args || []),
    FLUIDBOX_GATE_TOOLS: JSON.stringify(srv.tools || []),
  };
}

export { crypto };
