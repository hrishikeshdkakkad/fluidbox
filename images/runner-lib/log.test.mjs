// Tests for the runner's structured logging.
//
// The property that matters most here is NEGATIVE: this process holds every
// credential the sandbox is given — and one of them, the LLM-audience session
// token, IS the value of `ANTHROPIC_API_KEY` — so the question is not "does it
// log" but "can a credential get out". A container runtime collects this
// process's stderr and ships it wherever the deployment's logs go, so a leak
// here travels further than one in the control plane.
//
// Zero dependencies, node's built-in runner. From the repo root:
//     node --test images/runner-lib/

import { test } from "node:test";
import assert from "node:assert/strict";
import { createLogger, scrub, isSensitiveField } from "./log.mjs";

/// Capture what the logger writes.
function capture(opts = {}) {
  const lines = [];
  const log = createLogger({
    sessionId: "018f2c3d-0000-7000-8000-000000000001",
    level: "trace",
    write: (l) => lines.push(l),
    ...opts,
  });
  return { log, lines, json: () => lines.map((l) => JSON.parse(l)) };
}

/// One realistic credential from each family the sandbox can be holding or can
/// see in an upstream error.
//
// Each entry is `[realistic rendering, the substring that must NOT survive]`.
// The second element matters because several rules deliberately PRESERVE
// context — a connection string keeps its host, an OAuth callback keeps the
// parameter name — so "the whole value disappeared" is the wrong assertion and
// would force the redactor to be blunter than it should be.
const SECRETS = {
  "session token (also the fake ANTHROPIC_API_KEY)": [`fbx_sess_${"a".repeat(32)}`, "a".repeat(32)],
  "tool token": [`fbx_sess_${"b".repeat(32)}`, "b".repeat(32)],
  "anthropic key": [`sk-ant-api03-${"c".repeat(40)}`, "c".repeat(40)],
  "openai key": [`sk-${"d".repeat(32)}`, "d".repeat(32)],
  "github pat": [`ghp_${"e".repeat(36)}`, "e".repeat(36)],
  "aws key id": ["AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"],
  jwt: [`eyJ${"f".repeat(20)}.eyJ${"g".repeat(20)}.${"h".repeat(30)}`, "h".repeat(30)],
  "bearer header": [`Authorization: Bearer ${"i".repeat(40)}`, "i".repeat(40)],
  "connection string": ["postgres://user:s3cr3tp4ss@db.internal/fbx", "s3cr3tp4ss"],
  "oauth callback": ["https://as.example/cb?code=abc123def456ghi&state=xyz", "abc123def456ghi"],
};

test("no credential family reaches stderr, by any route", () => {
  for (const [family, [secret, mustGo]] of Object.entries(SECRETS)) {
    const { log, lines } = capture();
    // Every shape a real callsite takes.
    log.info(`upstream said: ${secret}`);
    log.warn("call failed", { detail: secret });
    log.error("threw", { error: new Error(`boom ${secret}`) });
    // Two levels down inside an object — the realistic case, and the one a
    // top-level field-name check never reaches.
    log.debug("nested", { response: { headers: { authorization: secret } } });
    log.info("named", { client_secret: secret });
    const out = lines.join("");
    assert.ok(!out.includes(mustGo), `${family}: reached stderr\n  wanted gone: ${mustGo}\n  got: ${out}`);
  }
});

test("a sensitively-named field is blanked whatever its shape", () => {
  const { log, json } = capture();
  // None of these match any pattern — that is the point. A session token with
  // its prefix stripped, and a random passphrase, are just entropy.
  log.info("connected", {
    password: "correct-horse-battery-staple",
    api_key: "9f2c4a7e11b3d8650fa2c9e4b7d1a038",
    token_audience: "llm",
  });
  const r = json()[0];
  assert.equal(r.password, "‹redacted›");
  assert.equal(r.api_key, "‹redacted›");
  // …and the structural key beside it survives, or the runner's most useful
  // diagnostic (which audience a refused token carried) is destroyed too.
  assert.equal(r.token_audience, "llm");
});

test("records carry the session id, so both halves of a run join", () => {
  const { log, json } = capture();
  log.info("hello");
  const r = json()[0];
  assert.equal(r.session_id, "018f2c3d-0000-7000-8000-000000000001");
  assert.equal(r.service, "fluidbox-runner");
  assert.equal(r.level, "info");
  assert.equal(r.msg, "hello");
  assert.ok(r.ts.endsWith("Z"), "UTC ISO-8601");
});

test("every record is independently parsable JSON, one per line", () => {
  const { log, lines } = capture();
  log.info("a");
  log.warn("b", { n: 1 });
  assert.equal(lines.length, 2);
  for (const l of lines) {
    assert.ok(l.endsWith("\n"), "one record per line");
    JSON.parse(l); // throws on malformed
  }
});

test("a value containing a quote cannot inject a sibling key", () => {
  const { log, json } = capture();
  log.info('msg', { detail: '","injected":"yes' });
  const r = json()[0];
  assert.equal(r.injected, undefined);
  assert.equal(r.detail, '","injected":"yes');
});

test("the level filter suppresses below the threshold but never everything", () => {
  const { log, lines } = capture({ level: "warn" });
  log.debug("quiet");
  log.info("also quiet");
  log.warn("loud");
  log.error("louder");
  assert.equal(lines.length, 2);
  // An UNRECOGNISED level must fall back to info rather than silencing the
  // runner: a logging misconfiguration should cost detail, not the diagnostic
  // surface.
  const { log: l2, lines: out2 } = capture({ level: "verbose-please" });
  l2.info("still logged");
  l2.debug("below info");
  assert.equal(out2.length, 1);
});

test("oversized values are capped and the record still parses", () => {
  const { log, json } = capture();
  log.info("huge", { blob: "x".repeat(100_000) });
  const r = json()[0]; // throws if unparsable
  assert.ok(r.blob.length < 5000, `capped, got ${r.blob.length}`);
  assert.match(r.blob, /truncated/);
});

test("a field named like an envelope key is renamed, not dropped", () => {
  const { log, json } = capture();
  log.info("real", { level: "critical", msg: "shadow" });
  const r = json()[0];
  assert.equal(r.level, "info", "the envelope wins");
  assert.equal(r.msg, "real");
  assert.equal(r.level_, "critical", "and the field is preserved");
  assert.equal(r.msg_, "shadow");
});

test("an Error logs its stack, not its enumerable properties", () => {
  const { log, json } = capture();
  const e = new Error("upstream refused");
  // Fetch errors routinely carry the failing request, headers included.
  e.request = { headers: { authorization: `Bearer ${"z".repeat(40)}` } };
  log.error("failed", { error: e });
  const r = json()[0];
  assert.match(r.error, /upstream refused/);
  assert.ok(!r.error.includes("z".repeat(40)), "the attached request did not ride along");
});

test("text format carries the same data and the same redaction", () => {
  const { log, lines } = capture({ format: "text" });
  log.warn("push rejected", { detail: `ghp_${"q".repeat(36)}`, tool: "Bash" });
  const line = lines[0];
  assert.ok(!line.includes("q".repeat(36)), line);
  assert.match(line, /tool=Bash/);
  assert.match(line, /push rejected/);
});

test("the pattern and field rules classify the way the Rust side does", () => {
  // Field POSITION.
  for (const f of ["authorization", "cookie", "client_secret", "refresh_token", "api_key"]) {
    assert.ok(isSensitiveField(f), f);
  }
  for (const f of ["token_id", "token_audience", "session_id", "tool", "verdict"]) {
    assert.ok(!isSensitiveField(f), f);
  }
  // Value SHAPE — and the context around it survives, or people turn redaction off.
  const out = scrub("callback https://as.example/cb?code=abc123def456ghi failed");
  assert.match(out, /as\.example/);
  assert.match(out, /code=/);
  assert.match(out, /failed/);
  assert.ok(!out.includes("abc123def456ghi"));
});

test("a shapeless credential nested inside an object is blanked by key", () => {
  const { log, lines } = capture();
  // No pattern matches this — it is just entropy, which is exactly what a
  // stripped session token and a random passphrase look like. Only the
  // recursive key check can catch it.
  const shapeless = "9f2c4a7e11b3d8650fa2c9e4b7d1a038";
  log.error("fetch failed", {
    response: { status: 401, headers: { authorization: shapeless }, url: "https://x/y" },
  });
  const out = lines.join("");
  assert.ok(!out.includes(shapeless), `nested shapeless secret leaked: ${out}`);
  // …and the diagnostic around it survives, or logging the response is pointless.
  assert.match(out, /401/);
  assert.match(out, /https:\/\/x\/y/);
});

test("a cyclic or enormous object costs a truncated line, not the runner", () => {
  const { log, json } = capture();
  const cyclic = { name: "outer" };
  cyclic.self = cyclic;
  log.info("cyclic", { obj: cyclic });
  assert.match(json()[0].obj, /circular/);

  const deep = {};
  let cur = deep;
  for (let i = 0; i < 50; i++) {
    cur.next = {};
    cur = cur.next;
  }
  const { log: l2, json: j2 } = capture();
  l2.info("deep", { obj: deep });
  assert.match(j2()[0].obj, /depth-capped/);
});
