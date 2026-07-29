// Driver integration: spawn the real driver (index.mjs) as a child process
// against a stub control plane, with the REAL runner-lib contract client.
// Asserts the runner contract: one /permission per tool step with stable ids,
// real execution only on allow, deny-tolerant narration, exactly one /result.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const DRIVER = join(HERE, "..", "index.mjs");
const CONTRACT = join(HERE, "..", "..", "..", "runner-lib", "contract.mjs");

function fixtureWorkspace() {
  const dir = mkdtempSync(join(tmpdir(), "fbx-replay-drv-"));
  writeFileSync(
    join(dir, "app.js"),
    'function greet(name) {\n  return "Hello, name!";\n}\nmodule.exports = { greet };\n',
  );
  writeFileSync(
    join(dir, "test.js"),
    'const { greet } = require("./app.js");\n' +
      'const got = greet("Ada");\n' +
      'if (got !== "Hello, Ada!") {\n' +
      '  console.error(`FAIL greet("Ada") -> ${JSON.stringify(got)} (expected "Hello, Ada!")`);\n' +
      "  process.exit(1);\n" +
      "}\n" +
      'console.log("PASS 1/1 greet returns a personal greeting");\n',
  );
  writeFileSync(join(dir, "run_tests.sh"), "#!/usr/bin/env bash\nexec node test.js\n");
  writeFileSync(
    join(dir, "deploy.sh"),
    '#!/usr/bin/env bash\nline="[deploy] $(date -u +%FT%TZ) released demo build to demo-target"\n' +
      'echo "$line" >> deploy.log\necho "$line"\n',
  );
  chmodSync(join(dir, "run_tests.sh"), 0o755);
  chmodSync(join(dir, "deploy.sh"), 0o755);
  return dir;
}

// A scripted control plane: allow everything except commands matching /curl/.
function stubControlPlane(record) {
  return createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : {};
      const reply = (obj) => {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(obj));
      };
      if (req.url.endsWith("/permission")) {
        record.permissions.push(body);
        if (/\bcurl\b/.test(body.input?.command || "")) {
          return reply({ decision: "deny", message: "network calls are denied by the demo policy" });
        }
        return reply({ decision: "allow" });
      }
      if (req.url.endsWith("/events")) {
        record.events.push(body);
        return reply({ seq: record.events.length });
      }
      if (req.url.endsWith("/heartbeat")) return reply({ ok: true, action: null });
      if (req.url.endsWith("/result")) {
        record.results.push(body);
        return reply({ ok: true });
      }
      if (req.url.endsWith("/token/renew")) return reply({ renewed: true, ttl_secs: 10800 });
      res.statusCode = 404;
      reply({ error: "unexpected route " + req.url });
    });
  });
}

test("driver replays the transcript through the gate and posts one result", async () => {
  const record = { permissions: [], events: [], results: [] };
  const server = stubControlPlane(record);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;

  const workspace = fixtureWorkspace();
  const transcript = join(mkdtempSync(join(tmpdir(), "fbx-replay-tr-")), "transcript.json");
  writeFileSync(
    transcript,
    JSON.stringify([
      { say: "Replay of a recorded run — no model calls. Running the test suite first." },
      { tool: "Bash", input: { command: "./run_tests.sh" } },
      { say: "greet() returns the literal string. Fixing app.js." },
      {
        tool: "Edit",
        input: {
          file_path: "/workspace/app.js",
          old_string: '"Hello, name!"',
          new_string: '"Hello, " + name + "!"',
        },
      },
      { tool: "Bash", input: { command: "./run_tests.sh" } },
      {
        tool: "Bash",
        input: { command: "curl -s https://status.demo.internal/health" },
        on_deny_say: "Outbound network calls are denied by policy here — moving on.",
      },
      { tool: "Bash", input: { command: "./deploy.sh" } },
      { say: "Done: test fixed and verified." },
    ]),
  );

  const child = spawn(process.execPath, [DRIVER], {
    env: {
      ...process.env,
      FLUIDBOX_CONTROL_URL: `http://127.0.0.1:${port}`,
      FLUIDBOX_SESSION_ID: "sess-test",
      FLUIDBOX_SESSION_TOKEN: "fbx_sess_control",
      FLUIDBOX_TOOL_TOKEN: "fbx_sess_tool",
      FLUIDBOX_TASK: "fix the failing test [deterministic replay]",
      FLUIDBOX_AUTONOMY: "supervised",
      FLUIDBOX_WORKSPACE: workspace,
      REPLAY_TRANSCRIPT: transcript,
      FLUIDBOX_RUNNER_LIB: CONTRACT,
      FLUIDBOX_REPLAY_DELAY_MS: "0",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (c) => (stderr += c));
  const [code] = await once(child, "exit");
  server.close();

  assert.equal(code, 0, `driver exit ${code}; stderr:\n${stderr}`);

  // One permission per tool step, stable ids, in order.
  assert.deepEqual(
    record.permissions.map((p) => p.tool_call_id),
    ["rp_001", "rp_002", "rp_003", "rp_004", "rp_005"],
  );
  assert.deepEqual(
    record.permissions.map((p) => p.tool),
    ["Bash", "Edit", "Bash", "Bash", "Bash"],
  );

  // Allowed steps executed for real: the edit landed, deploy.log written.
  assert.match(readFileSync(join(workspace, "app.js"), "utf8"), /"Hello, " \+ name \+ "!"/);
  assert.equal(existsSync(join(workspace, "deploy.log")), true);

  // Denied curl was NOT executed but narrated via on_deny_say.
  const texts = record.events
    .filter((e) => e.body?.type === "agent.message")
    .map((e) => e.body.data.text)
    .join("\n");
  assert.match(texts, /no model calls/i);
  assert.match(texts, /denied by policy here — moving on/);
  assert.match(texts, /exit 1/); // first test run failed…
  assert.match(texts, /PASS 1\/1/); // …second passed

  // Exactly one completed result, with honest tallies.
  assert.equal(record.results.length, 1);
  assert.equal(record.results[0].outcome, "completed");
  assert.match(record.results[0].summary, /4 executed/);
  assert.match(record.results[0].summary, /1 denied/);
});

test("driver keeps going when the gated deploy is denied (deny-path ending)", async () => {
  const record = { permissions: [], events: [], results: [] };
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : {};
      const reply = (obj) => {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(obj));
      };
      if (req.url.endsWith("/permission")) {
        record.permissions.push(body);
        if ((body.input?.command || "").includes("deploy.sh")) {
          return reply({ decision: "deny", message: "denied by operator" });
        }
        return reply({ decision: "allow" });
      }
      if (req.url.endsWith("/events")) {
        record.events.push(body);
        return reply({ seq: record.events.length });
      }
      if (req.url.endsWith("/heartbeat")) return reply({ ok: true, action: null });
      if (req.url.endsWith("/result")) {
        record.results.push(body);
        return reply({ ok: true });
      }
      if (req.url.endsWith("/token/renew")) return reply({ renewed: true, ttl_secs: 10800 });
      res.statusCode = 404;
      reply({});
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;

  const workspace = fixtureWorkspace();
  const transcript = join(mkdtempSync(join(tmpdir(), "fbx-replay-tr-")), "transcript.json");
  writeFileSync(
    transcript,
    JSON.stringify([
      {
        tool: "Bash",
        input: { command: "./deploy.sh" },
        on_deny_say: "Deploy withheld by the operator — nothing was released.",
      },
      { say: "Wrapping up." },
    ]),
  );

  const child = spawn(process.execPath, [DRIVER], {
    env: {
      ...process.env,
      FLUIDBOX_CONTROL_URL: `http://127.0.0.1:${port}`,
      FLUIDBOX_SESSION_ID: "sess-deny",
      FLUIDBOX_SESSION_TOKEN: "fbx_sess_control",
      FLUIDBOX_TOOL_TOKEN: "fbx_sess_tool",
      FLUIDBOX_TASK: "deny path [deterministic replay]",
      FLUIDBOX_WORKSPACE: workspace,
      REPLAY_TRANSCRIPT: transcript,
      FLUIDBOX_RUNNER_LIB: CONTRACT,
      FLUIDBOX_REPLAY_DELAY_MS: "0",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (c) => (stderr += c));
  const [code] = await once(child, "exit");
  server.close();

  assert.equal(code, 0, `driver exit ${code}; stderr:\n${stderr}`);
  assert.equal(existsSync(join(workspace, "deploy.log")), false, "denied deploy must not run");
  const texts = record.events
    .filter((e) => e.body?.type === "agent.message")
    .map((e) => e.body.data.text)
    .join("\n");
  assert.match(texts, /Deploy withheld by the operator/);
  assert.equal(record.results.length, 1);
  assert.equal(record.results[0].outcome, "completed");
  assert.match(record.results[0].summary, /deploy withheld|denied/i);
});
