// fluidbox runner logging — the sandbox half of the observability schema.
//
// # Why the runner logs in the same shape as the control plane
//
// A run's story spans two processes: the control plane decides, the runner
// executes. When something goes wrong the interesting question is almost always
// about the SEAM — "the gate allowed it, so why did the tool not run", "the
// runner says the token was refused, what did the server think". Answering that
// means putting both halves in one query, and that only works if they agree on
// the record shape and, crucially, on `session_id`.
//
// So this emits the same flat JSON envelope `fluidbox-obs` does (`ts`, `level`,
// `target`, `msg`, `service`, plus fields), with `session_id` bound once at
// construction. A collector that indexes control-plane logs indexes these with
// no extra configuration, and `session_id` joins them.
//
// # Why redaction matters MORE here, not less
//
// This process holds every credential the sandbox is given — and one of them,
// the LLM-audience session token, is literally the value of `ANTHROPIC_API_KEY`.
// A stack trace, an HTTP error, or a careless `console.error(err)` on a fetch
// failure can put it on stderr, which the container runtime collects and ships
// wherever the deployment's logs go. Every value written here is scrubbed by
// shape and by field name, the same two mechanisms the Rust side uses.
//
// # Where it writes
//
// stderr, always. The sandbox's stdout belongs to the agent, and interleaving
// runner diagnostics with agent output would corrupt both. This is also what
// the `console.error` calls this module replaces already did.

/// Value patterns, mirroring `fluidbox-obs::redact`. Independent restatements on
/// purpose — a change to one should FAIL the other's tests rather than silently
/// travel with it — with the fluidbox session prefix first because it is the one
/// this process is most likely to leak.
const PATTERNS = [
  [/fbx_(sess|trig|web|pat)_[A-Za-z0-9_-]{8,}/g, "‹redacted›"],
  [/sk-ant-[A-Za-z0-9_-]{8,}/g, "‹redacted›"],
  [/sk-proj-[A-Za-z0-9_-]{16,}/g, "‹redacted›"],
  [/sk-[A-Za-z0-9]{20,}/g, "‹redacted›"],
  [/gh[pousr]_[A-Za-z0-9]{20,}/g, "‹redacted›"],
  [/github_pat_[A-Za-z0-9_]{20,}/g, "‹redacted›"],
  [/AKIA[0-9A-Z]{16}/g, "‹redacted›"],
  [/xox[baprs]-[A-Za-z0-9-]{10,}/g, "‹redacted›"],
  [/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "‹redacted›"],
  [/(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{16,}=*/gi, "‹redacted›"],
  [/([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s:/@]+):[^@\s/]+@/g, "$1:‹redacted›@"],
  [/([?&#])(code|state|token|access_token|id_token|refresh_token|client_secret)=[^&\s"'>]+/gi,
   "$1$2=‹redacted›"],
];

/// Field names whose value is never written, whatever it looks like. The half
/// that catches a secret with no recognisable shape — which is what a session
/// token looks like once its prefix is stripped, and what every random
/// passphrase looks like always.
const DENY = [
  "authorization", "cookie", "password", "secret", "token", "credential",
  "api_key", "apikey", "bearer", "key", "signature", "verifier",
];
const DENY_SUFFIX = ["_token", "_secret", "_key", "_password", "_credential", "_signature"];
/// Structural join keys that merely LOOK sensitive. Without these the runner's
/// most useful diagnostics — which audience a refused token carried, which
/// tool call an id belongs to — would be blanked.
const ALLOW = ["token_id", "token_audience", "required_audience", "key_version", "has_token"];

export function isSensitiveField(name) {
  if (ALLOW.includes(name)) return false;
  if (DENY.includes(name)) return true;
  return DENY_SUFFIX.some((s) => name.endsWith(s));
}

export function scrub(text) {
  let out = String(text);
  for (const [re, rep] of PATTERNS) out = out.replace(re, rep);
  return out;
}

/// Longest rendered value for one field. Generous for a real diagnostic, small
/// enough that a stack trace or a dumped response body cannot become the whole
/// log volume of a run.
const MAX_FIELD = 4096;

/// Walk a structure, replacing the value of any sensitively-named key at any
/// depth. Depth- and breadth-bounded: this runs on values a failing HTTP client
/// handed us, so a cyclic or pathologically large object must cost a truncated
/// log line rather than the runner's stack.
const MAX_DEPTH = 8;
const MAX_KEYS = 200;

function blankSensitiveKeys(value, depth = 0, seen = new WeakSet()) {
  if (value === null || typeof value !== "object") return value;
  if (depth >= MAX_DEPTH) return "[depth-capped]";
  if (seen.has(value)) return "[circular]";
  seen.add(value);
  if (Array.isArray(value)) {
    return value.slice(0, MAX_KEYS).map((v) => blankSensitiveKeys(v, depth + 1, seen));
  }
  const out = {};
  let n = 0;
  for (const [k, v] of Object.entries(value)) {
    if (n++ >= MAX_KEYS) {
      out["…"] = "[key-capped]";
      break;
    }
    out[k] = isSensitiveField(k.toLowerCase()) ? "‹redacted›" : blankSensitiveKeys(v, depth + 1, seen);
  }
  return out;
}

function renderValue(name, value) {
  if (isSensitiveField(name)) return "‹redacted›";
  if (value === null || value === undefined) return null;
  if (typeof value === "number" || typeof value === "boolean") return value;
  let s;
  if (value instanceof Error) {
    // The message and the stack, not the whole object: an Error's own
    // enumerable properties routinely carry the request that failed, headers
    // included.
    s = value.stack || value.message || String(value);
  } else if (typeof value === "object") {
    try {
      // Blank sensitive keys RECURSIVELY before serialising. Checking only the
      // top-level field name is not enough and the difference is exactly the
      // realistic case: a fetch failure logged as
      // `{ response: { headers: { authorization: "…" } } }` puts the credential
      // two levels down, where a name check never looks and — if the value has
      // no recognisable shape, which a stripped session token does not — no
      // pattern catches it either.
      s = JSON.stringify(blankSensitiveKeys(value));
    } catch {
      s = "[unserialisable]";
    }
  } else {
    s = String(value);
  }
  s = scrub(s);
  if (s.length > MAX_FIELD) s = `${s.slice(0, MAX_FIELD)}…(+${s.length - MAX_FIELD} chars truncated)`;
  return s;
}

const LEVELS = { trace: 10, debug: 20, info: 30, warn: 40, error: 50 };

/// The envelope keys this module writes. A field with one of these names is
/// emitted with a trailing underscore rather than shadowing the envelope —
/// the same rule the Rust formatter applies.
const RESERVED = new Set(["ts", "level", "target", "msg", "service", "session_id"]);

// Escape one value for the human-readable single-line format. JSON's string
// escaping covers quotes, backslashes, LF/CR/TAB, and ESC; DEL/C1 controls are
// escaped explicitly because JSON permits some of them literally while a
// terminal may still interpret them.
function textFragment(value) {
  const quoted = JSON.stringify(String(value));
  const inner = quoted ? quoted.slice(1, -1) : "";
  return inner.replace(/[\u007f-\u009f]/g, (ch) =>
    `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function textToken(value) {
  const raw = String(value);
  const escaped = textFragment(raw);
  return raw.length === 0 || /[\s\u0000-\u001f\u007f-\u009f"\\]/u.test(raw)
    ? `"${escaped}"`
    : escaped;
}

export function createLogger({
  target = "runner",
  service = "fluidbox-runner",
  sessionId = process.env.FLUIDBOX_SESSION_ID,
  level = process.env.FLUIDBOX_LOG_LEVEL,
  format = process.env.FLUIDBOX_LOG_FORMAT,
  write = (line) => process.stderr.write(line),
} = {}) {
  // An unrecognised level must not silence the runner: fall back to `info`
  // rather than to nothing. A logging misconfiguration should cost detail, not
  // the whole diagnostic surface.
  const threshold = LEVELS[String(level || "").toLowerCase()] ?? LEVELS.info;
  // JSON unless a human explicitly asked for text. The sandbox's stderr is
  // collected by a container runtime, not read by a person, so the default
  // matches where it actually goes.
  const asJson = String(format || "json").toLowerCase() !== "text";

  function emit(lvl, msg, fields) {
    if (LEVELS[lvl] < threshold) return;
    const rec = {
      ts: new Date().toISOString(),
      level: lvl,
      target,
      msg: scrub(String(msg)),
      service,
    };
    if (sessionId) rec.session_id = sessionId;
    for (const [k, v] of Object.entries(fields || {})) {
      const rendered = renderValue(k, v);
      if (rendered === null) continue;
      rec[RESERVED.has(k) ? `${k}_` : k] = rendered;
    }
    if (asJson) {
      write(`${JSON.stringify(rec)}\n`);
      return;
    }
    const extra = Object.entries(rec)
      .filter(([k]) => !["ts", "level", "target", "msg", "service"].includes(k))
      .map(([k, v]) => `${textToken(k)}=${typeof v === "string" ? textToken(v) : String(v)}`)
      .join(" ");
    write(
      `${rec.ts} ${lvl.padStart(5)} service=${textToken(rec.service)} ${textToken(rec.target)}: ` +
        `${textFragment(rec.msg)}${extra ? ` ${extra}` : ""}\n`,
    );
  }

  const api = {};
  for (const lvl of Object.keys(LEVELS)) {
    api[lvl] = (msg, fields) => emit(lvl, msg, fields);
  }
  /// A child logger with a narrower target and extra bound fields — used by the
  /// shims, which run as separate processes and should be distinguishable.
  api.child = (childTarget, bound = {}) =>
    createLogger({
      target: childTarget,
      service,
      sessionId,
      level,
      format,
      write: (line) => {
        if (!Object.keys(bound).length) return write(line);
        try {
          const rec = JSON.parse(line);
          for (const [k, v] of Object.entries(bound)) rec[k] = renderValue(k, v);
          return write(`${JSON.stringify(rec)}\n`);
        } catch {
          return write(line);
        }
      },
    });
  return api;
}

/// The process-wide logger. Created eagerly because every module that imports
/// this one wants it at import time, and its construction reads env only.
export const log = createLogger();
