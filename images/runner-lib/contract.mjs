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
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { log } from "./log.mjs";

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function requireEnv(k) {
  const v = process.env[k];
  if (!v) {
    log.error("missing required env", { env_var: k });
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

// ─── Off-environment credential hand-off (Phase F) ─────────────────────────
//
// The runner-control credential no longer reaches the runner in its
// environment. `lib/entrypoint.sh` writes it to a 0600 file, opens it as a file
// descriptor, unlinks the file, unsets the variable and `exec`s the runner —
// so execve() gives the runner an environ region that never held the token and
// /proc/<pid>/environ has nothing for a same-uid agent child to read. This end
// of the contract reads that descriptor (named by the env var below, which is
// NOT a secret: it names a channel rather than being one) and CLOSES it before
// the harness spawns anything.
//
// Read the "what this does NOT close" note in entrypoint.sh: ptrace(2) of the
// runner by a same-uid child still reaches the token in live memory, and no
// container hardening we ship blocks it.
export const TOKEN_FD_ENV = "FLUIDBOX_SESSION_TOKEN_FD";

// A hand-off that was ATTEMPTED and FAILED is fatal, exactly like an audience
// mismatch and for the same reason: the alternatives are running credential-less
// (every /events, /heartbeat and /result silently rejected while model spend
// proceeds) or falling back to an environment variable the entrypoint already
// unset. Both are the wrong-and-expensive-and-looks-right shape. Abort instead.
export const EXIT_TOKEN_HANDOFF = 4;

// A session token is ~50 bytes. The cap exists so a mis-pointed descriptor
// (someone else's fd, a socket) can never be read into unbounded memory.
const HANDOFF_MAX_BYTES = 4096;

/// The one-line operator diagnostic for a failed hand-off. Unlike the audience
/// mismatch this is NOT mirrored to the run timeline — /events needs the very
/// credential that just failed to arrive, so the container log is the only
/// place it can go.
export function tokenHandoffDiagnostic(reason) {
  return (
    `fluidbox-runner: FATAL — the runner-control credential hand-off failed (${reason}). ` +
    `${TOKEN_FD_ENV} was set, so the entrypoint already removed the token from this ` +
    `process's environment and there is nothing to fall back to. Aborting the run: ` +
    `continuing would fail every /events, /heartbeat and /result call while model spend ` +
    `proceeds, producing a wrong result that looks right.`
  );
}

/// Read the runner-control credential from the hand-off descriptor and close it.
/// Returns `{ok:true, token}` or `{ok:false, reason}` — the caller decides the
/// exit, so this stays unit-testable. Closing is unconditional and immediate:
/// the descriptor must not survive to be inherited by anything the harness
/// spawns, and the file behind it is already unlinked so nothing can re-open it.
export function readControlTokenFromFd(fdSpec, { fsMod = fs } = {}) {
  const fd = Number(fdSpec);
  if (!Number.isInteger(fd) || fd < 3) {
    return { ok: false, reason: `${TOKEN_FD_ENV}='${fdSpec}' is not a usable descriptor number` };
  }
  const buf = Buffer.alloc(HANDOFF_MAX_BYTES);
  let len = 0;
  try {
    for (;;) {
      const n = fsMod.readSync(fd, buf, len, buf.length - len, null);
      if (n === 0) break; // EOF
      len += n;
      if (len >= buf.length) {
        return { ok: false, reason: `fd ${fd} carried more than ${HANDOFF_MAX_BYTES} bytes` };
      }
    }
  } catch (e) {
    return { ok: false, reason: `reading fd ${fd} failed: ${e?.code || e?.message || e}` };
  } finally {
    try {
      fsMod.closeSync(fd);
    } catch {
      // Already closed / never valid — the read result above is what matters.
    }
  }
  const token = buf.toString("utf8", 0, len).trim();
  if (!token) return { ok: false, reason: `fd ${fd} carried no credential (0 usable bytes)` };
  return { ok: true, token };
}

/// Resolve the runner-control credential. Prefers the off-environment hand-off
/// and NEVER falls back to the environment once it has been attempted.
///
/// COMPATIBILITY PATH: with `FLUIDBOX_SESSION_TOKEN_FD` absent — someone ran
/// `node index.mjs` directly, or an old manifest/provider bypassed the image
/// ENTRYPOINT — the token is read from the environment exactly as it always
/// was. That path RE-OPENS the /proc/<pid>/environ residual in full: the token
/// sits in this process's execve-fixed environ region for its whole life, where
/// any same-uid agent child can read it. It exists so a bypassed entrypoint
/// degrades to Phase E behaviour instead of failing the run; it is NOT the
/// supported configuration, and both shipped images route through the
/// entrypoint.
export function resolveControlToken() {
  const fdSpec = process.env[TOKEN_FD_ENV];
  if (fdSpec === undefined || fdSpec === "") {
    return requireEnv("FLUIDBOX_SESSION_TOKEN");
  }
  const res = readControlTokenFromFd(fdSpec);
  if (!res.ok) {
    log.error(tokenHandoffDiagnostic(res.reason), { reason: res.reason });
    process.exit(EXIT_TOKEN_HANDOFF);
  }
  return res.token;
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
///   TOKEN      (the hand-off fd, else FLUIDBOX_SESSION_TOKEN) — runner-control:
///              events, heartbeat, result, token renew. Phase F moved this one
///              OFF the environment entirely (see resolveControlToken above);
///              the harness still DELETES the legacy var, which is what the
///              compatibility path and the spawned environment need.
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
  const TOKEN = resolveControlToken();
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
      log.warn("FLUIDBOX_CAPABILITIES is unparseable; ignoring it", { error: e.message });
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
      log.info("replaying a quiesce that arrived before handler registration");
      try {
        cb();
      } catch (e) {
        log.error("quiesce callback threw", { error: e?.message || e });
      }
    }
  }

  #maybeQuiesce(res) {
    if (this.quiesced || !res || res.action !== "quiesce") return;
    // Latching without a handler would swallow the cancel permanently: the
    // next heartbeat re-delivers, and onQuiesce replays if we latch later.
    this.quiesced = true;
    log.info("control plane requested quiesce — stopping the agent");
    if (!this.quiesceCb) {
      log.info("quiesce arrived before handler registration; it will replay on registration");
      return;
    }
    try {
      this.quiesceCb?.();
    } catch (e) {
      log.error("quiesce callback threw", { error: e?.message || e });
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
      log.warn("posting a timeline event failed; continuing", { error: e.message });
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
          log.info("permission request rejected: the session is terminal — denying");
          return { decision: "deny", message: "session is not active" };
        }
        log.warn("permission request failed", { attempt, error: e.message, retrying: true });
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
        log.warn("token renew failed", { error: e.message, retrying: true });
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

// ─── Why the gate is a HOOK, not the permission callback ───────────────────
//
// `canUseTool` is NOT an interception point. The Agent SDK does not call it
// per tool call; it translates the callback into `--permission-prompt-tool
// stdio` on the Claude Code CLI it spawns, and the CLI consults that prompt
// tool ONLY for calls it decides to ASK about. Anything the CLI approves on
// its own first — its read-only / safe-command classification, an
// `allowedTools` entry, an allow rule from a settings file, a permissionMode
// that auto-accepts — executes with the callback never running at all.
//
// Measured on @anthropic-ai/claude-agent-sdk 0.3.205 in the shipped image: an
// ordinary coding workload (list files, read one, grep, `wc -l`) produced FOUR
// tool calls and ZERO canUseTool invocations, and `printf '<nonce>' |
// sha256sum` executed and returned the digest of a nonce minted seconds
// earlier while the gate was never consulted. The SDK states the rule itself:
// "Bare allowedTools entries auto-approve the whole tool before the callback
// is consulted... To gate every tool call, use a PreToolUse hook instead."
//
// A PreToolUse hook fires for EVERY tool call, underneath that short-circuit.
// So the hook is what makes the gate mandatory. It deliberately does NO I/O:
// it answers `ask`, which forces the call onto the canUseTool path, and the
// blocking /permission round trip still happens THERE. Keeping the blocking on
// the callback is the point — a supervised approval can hold for minutes,
// `requestPermission` already owns the 12-minute timeout and forever-retry
// semantics for exactly that, and a hook that never awaits anything cannot
// time out, throw, or become a new way to lose a decision.
export const GATE_ASK_REASON =
  "fluidbox governs this run: every tool call needs a control-plane decision";

/// The PreToolUse hook return that forces a call onto the gate. Pure and
/// synchronous by construction — see the note above for why that matters.
export function forceGateDecision() {
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "ask",
      permissionDecisionReason: GATE_ASK_REASON,
    },
  };
}

// A tool that executed without a fluidbox decision is a governance failure,
// not a verdict — the same class as EXIT_AUDIENCE_MISMATCH and treated the
// same way. It means the harness lost mediation (an SDK/CLI that stopped
// firing the hook, a tool class routed around it), and the honest response is
// to stop the run loudly rather than finish a run whose audit trail claims
// decisions it never made.
export const EXIT_UNGOVERNED_TOOL = 5;

export function ungovernedToolDiagnostic(tool, toolCallId) {
  return (
    `fluidbox-runner: FATAL — the tool '${tool}' (call ${toolCallId}) produced a result but ` +
    `NEVER received a fluidbox decision. The permission gate was bypassed, which means this ` +
    `runner image can no longer mediate tool calls for this agent SDK. Aborting the run: ` +
    `continuing would execute ungoverned tools while the ledger showed a clean timeline.`
  );
}

/// Tripwire bookkeeping for the gate.
///
/// The hook above PREVENTS the bypass; this detects one anyway. It pairs the
/// `tool_use` blocks the harness observes on the message stream with the calls
/// the gate actually decided, and reports any call that produced a RESULT
/// without one. That ordering is what makes it sound: the SDK emits the
/// assistant `tool_use`, then the hook/callback run, then the `tool_result`
/// arrives — so by result time a governed call is always already decided.
///
/// Deliberately conservative: it only trips on a call it watched being
/// emitted, so a tool_result the harness never saw the request for (a nested
/// subagent transcript, a future message shape) is ignored rather than
/// failing a legitimate run. That is a knowingly incomplete detector — it is
/// a backstop for regression, not the guarantee. The guarantee is the hook.
export class GateWitness {
  constructor() {
    this.emittedTools = new Map(); // tool_call_id -> tool name
    this.decidedCalls = new Set(); // tool_call_ids the gate answered
  }

  /// A `tool_use` block seen on the message stream.
  sawToolUse(toolCallId, tool) {
    if (typeof toolCallId === "string" && toolCallId) {
      this.emittedTools.set(toolCallId, tool);
    }
  }

  /// The gate produced a decision for this call (allow, deny, or a brokered
  /// wave-through — all three are decisions, made in exactly one place).
  sawDecision(toolCallId) {
    if (typeof toolCallId === "string" && toolCallId) {
      this.decidedCalls.add(toolCallId);
    }
  }

  /// The tool name when this result belongs to an observed-but-undecided
  /// call, else null.
  ungovernedResult(toolCallId) {
    if (typeof toolCallId !== "string" || !toolCallId) return null;
    if (this.decidedCalls.has(toolCallId)) return null;
    return this.emittedTools.get(toolCallId) ?? null;
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
