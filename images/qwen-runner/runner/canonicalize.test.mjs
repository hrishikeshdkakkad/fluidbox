// node --test unit fixtures for the qwen canonicalizer (no deps, no SDK —
// runs on the host: `node --test images/qwen-runner/runner/`).
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { canonicalize, canonicalizeCommand, cwdInWorkspace } from "./canonicalize.mjs";

const ws = fs.mkdtempSync(path.join(os.tmpdir(), "qwen-canon-ws-"));
fs.mkdirSync(path.join(ws, "sub"));

test("shell command passes through and wrapped spellings unwrap", () => {
  assert.equal(canonicalizeCommand("git status"), "git status");
  assert.equal(canonicalizeCommand('bash -lc "git status"'), "git status");
  assert.equal(canonicalizeCommand("/bin/sh -c 'ls -la'"), "ls -la");
  assert.equal(canonicalizeCommand("zsh -c \"echo hi\""), "echo hi");
  // Not a wrapper — a command that merely STARTS with sh-ish text stays whole.
  assert.equal(canonicalizeCommand("shellcheck run.sh"), "shellcheck run.sh");
});

test("run_shell_command canonicalizes to Bash{command} with cwd containment", () => {
  const ok = canonicalize("run_shell_command", { command: "git status", directory: ws }, ws);
  assert.equal(ok.tool, "Bash");
  assert.deepEqual(ok.input, { command: "git status", cwd: ws });
  // Subdirectory is inside.
  const sub = canonicalize("run_shell_command", { command: "ls", directory: path.join(ws, "sub") }, ws);
  assert.equal(sub.tool, "Bash");
  // Outside / nonexistent / relative → deny, never gate.
  for (const dir of ["/etc", path.join(ws, "missing"), "relative/dir"]) {
    const d = canonicalize("run_shell_command", { command: "ls", directory: dir }, ws);
    assert.ok(d.deny, `directory '${dir}' must be refused`);
  }
  // Empty/missing command → deny fail-closed (never a blind-approvable Bash{}).
  assert.ok(canonicalize("run_shell_command", {}, ws).deny);
  assert.ok(canonicalize("run_shell_command", { command: "" }, ws).deny);
  assert.ok(canonicalize("run_shell_command", { command: 42 }, ws).deny);
});

test("cwdInWorkspace resolves symlinks and refuses escapes", () => {
  const escape = path.join(ws, "escape");
  fs.symlinkSync("/etc", escape);
  assert.equal(cwdInWorkspace(escape, ws), false, "symlink escaping the workspace must fail");
  assert.equal(cwdInWorkspace(path.join(ws, "sub"), ws), true);
  assert.equal(cwdInWorkspace(ws, ws), true);
  // A sibling whose name merely PREFIXES the workspace path must not pass.
  const sibling = ws + "-sibling";
  fs.mkdirSync(sibling, { recursive: true });
  assert.equal(cwdInWorkspace(sibling, ws), false);
});

test("file tools map to canonical names with identical field names", () => {
  const read = canonicalize("read_file", { file_path: "/w/a.txt", offset: 3 }, ws);
  assert.equal(read.tool, "Read");
  assert.deepEqual(read.input, { file_path: "/w/a.txt" });
  const write = canonicalize("write_file", { file_path: "/w/a.txt", content: "x" }, ws);
  assert.equal(write.tool, "Write");
  const edit = canonicalize(
    "edit",
    { file_path: "/w/a.txt", old_string: "a", new_string: "b", replace_all: true },
    ws,
  );
  assert.equal(edit.tool, "Edit");
  assert.deepEqual(edit.input, {
    file_path: "/w/a.txt",
    old_string: "a",
    new_string: "b",
    replace_all: true,
  });
  const nb = canonicalize("notebook_edit", { notebook_path: "/w/n.ipynb", cell_id: "c1" }, ws);
  assert.equal(nb.tool, "NotebookEdit");
  assert.equal(canonicalize("grep_search", { pattern: "foo", path: "/w" }, ws).tool, "Grep");
  assert.equal(canonicalize("glob", { pattern: "**/*.rs" }, ws).tool, "Glob");
  assert.equal(canonicalize("list_directory", { path: "/w" }, ws).tool, "LS");
  assert.equal(canonicalize("todo_write", { todos: [] }, ws).tool, "TodoWrite");
  // Missing required fields → deny fail-closed.
  assert.ok(canonicalize("read_file", {}, ws).deny);
  assert.ok(canonicalize("write_file", { file_path: "/w/a" }, ws).deny);
  assert.ok(canonicalize("edit", { file_path: "/w/a", old_string: "x" }, ws).deny);
  assert.ok(canonicalize("grep_search", {}, ws).deny);
  assert.ok(canonicalize("list_directory", {}, ws).deny);
});

test("unknown tool names deny — census drift never reaches the gate natively", () => {
  for (const name of ["save_memory", "web_fetch", "computer_use__click", "mystery_tool"]) {
    const d = canonicalize(name, { anything: 1 }, ws);
    assert.ok(d.deny, `'${name}' must be refused`);
  }
});

test("mapBack folds gate rewrites onto the original input, nothing else", () => {
  const shell = canonicalize(
    "run_shell_command",
    { command: "rm -rf build", is_background: false, timeout: 5 },
    ws,
  );
  const back = shell.mapBack({ command: "rm -rf build/tmp", injected: "nope" });
  assert.deepEqual(back, { command: "rm -rf build/tmp", is_background: false, timeout: 5 });
  // A malformed updated_input falls back to the original input untouched.
  assert.deepEqual(shell.mapBack(null), { command: "rm -rf build", is_background: false, timeout: 5 });
  assert.deepEqual(shell.mapBack({ command: 7 }), {
    command: "rm -rf build",
    is_background: false,
    timeout: 5,
  });
  const edit = canonicalize("edit", { file_path: "/w/a", old_string: "x", new_string: "y" }, ws);
  const eb = edit.mapBack({ file_path: "/w/b", old_string: "x", new_string: "z", extra: true });
  assert.deepEqual(eb, { file_path: "/w/b", old_string: "x", new_string: "z" });
});
