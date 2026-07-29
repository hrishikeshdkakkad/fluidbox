// executeStep: the replay driver's real-execution core. Bash runs in the
// workspace; Write/Edit are confined to it. No fluidbox wiring here — pure.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { executeStep } from "../steps.mjs";

function ws() {
  return mkdtempSync(join(tmpdir(), "fbx-replay-ws-"));
}

test("Bash runs in the workspace cwd and captures output + exit code", async () => {
  const dir = ws();
  writeFileSync(join(dir, "hello.txt"), "hi\n");
  const okRes = await executeStep({ tool: "Bash", input: { command: "cat hello.txt" } }, dir);
  assert.equal(okRes.ok, true);
  assert.match(okRes.output, /hi/);

  const failRes = await executeStep({ tool: "Bash", input: { command: "exit 3" } }, dir);
  assert.equal(failRes.ok, false);
  assert.equal(failRes.exit_code, 3);
});

test("Bash times out runaway commands", async () => {
  const dir = ws();
  const res = await executeStep(
    { tool: "Bash", input: { command: "sleep 30" }, timeout_ms: 300 },
    dir,
  );
  assert.equal(res.ok, false);
  assert.match(res.output, /timed out/i);
});

test("Write creates a file inside the workspace (canonical /workspace path)", async () => {
  const dir = ws();
  const res = await executeStep(
    { tool: "Write", input: { file_path: "/workspace/notes/a.txt", content: "x\n" } },
    dir,
  );
  assert.equal(res.ok, true);
  assert.equal(readFileSync(join(dir, "notes/a.txt"), "utf8"), "x\n");
});

test("Write refuses paths escaping the workspace", async () => {
  const dir = ws();
  for (const p of ["/etc/passwd", "../outside.txt", "/workspace/../escape.txt"]) {
    const res = await executeStep({ tool: "Write", input: { file_path: p, content: "no" } }, dir);
    assert.equal(res.ok, false, `expected refusal for ${p}`);
    assert.match(res.output, /outside the workspace/);
  }
  assert.equal(existsSync(join(dir, "..", "escape.txt")), false);
});

test("Edit replaces a unique old_string; fails closed on missing or ambiguous", async () => {
  const dir = ws();
  writeFileSync(join(dir, "app.js"), 'return "Hello, name!";\n');

  const applied = await executeStep(
    {
      tool: "Edit",
      input: {
        file_path: "/workspace/app.js",
        old_string: '"Hello, name!"',
        new_string: '"Hello, " + name + "!"',
      },
    },
    dir,
  );
  assert.equal(applied.ok, true);
  assert.equal(readFileSync(join(dir, "app.js"), "utf8"), 'return "Hello, " + name + "!";\n');

  const missing = await executeStep(
    {
      tool: "Edit",
      input: { file_path: "/workspace/app.js", old_string: "nope", new_string: "x" },
    },
    dir,
  );
  assert.equal(missing.ok, false);
  assert.match(missing.output, /not found/);

  writeFileSync(join(dir, "dup.js"), "aa aa\n");
  const dup = await executeStep(
    { tool: "Edit", input: { file_path: "/workspace/dup.js", old_string: "aa", new_string: "b" } },
    dir,
  );
  assert.equal(dup.ok, false);
  assert.match(dup.output, /not unique/);
});

test("unknown tool fails closed", async () => {
  const res = await executeStep({ tool: "Teleport", input: {} }, ws());
  assert.equal(res.ok, false);
  assert.match(res.output, /unsupported tool/);
});
