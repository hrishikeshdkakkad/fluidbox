// Tests for the off-environment runner-control credential hand-off (Phase F).
//
// The property under test is not "the code runs" — it is that the process the
// entrypoint `exec`s CANNOT be asked for the runner-control token through its
// environment, while still RECEIVING that token through the intended channel.
// So every assertion here is made from INSIDE the exec'd process, against its
// own environment (and, on Linux, its own /proc/self/environ, which is the
// exact surface a same-uid agent child would read).
//
// Zero dependencies, node's built-in runner. From the repo root:
//     node --test images/runner-lib/
//
// PLATFORM. Everything runs on macOS and Linux; the four assertions that need
// procfs (/proc/self/environ, and the `(deleted)`/mode readback through
// /proc/self/fd/3) are guarded by an explicit linux check and skipped
// elsewhere. CI is Linux, so CI gets the full set.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const LIB_DIR = fileURLToPath(new URL(".", import.meta.url)).replace(/\/$/, "");
const ENTRYPOINT = path.join(LIB_DIR, "entrypoint.sh");
const CONTRACT = path.join(LIB_DIR, "contract.mjs");
const IS_LINUX = process.platform === "linux";

const TOKEN = "fbx_sess_HANDOFFCANARY0123456789abcdef";

// A `node` STUB that records everything the exec'd process can see about its
// own credentials. Deliberately not real node: this proves the property at the
// execve boundary, independent of anything our JS does afterwards.
const STUB_NODE = `#!/bin/sh
set -u
printf '%s' "$*" > "$FBX_TEST_OUT/argv"
env > "$FBX_TEST_OUT/env"
if [ -r /proc/self/environ ]; then
	tr '\\0' '\\n' < /proc/self/environ > "$FBX_TEST_OUT/proc_environ"
fi
if [ -n "\${FLUIDBOX_SESSION_TOKEN_FD:-}" ]; then
	cat <&3 > "$FBX_TEST_OUT/fd3"
	if [ -e /proc/self/fd/3 ]; then
		readlink /proc/self/fd/3 > "$FBX_TEST_OUT/fd3_link" 2>/dev/null || true
		stat -L -c '%a' /proc/self/fd/3 > "$FBX_TEST_OUT/fd3_mode" 2>/dev/null || true
	fi
fi
exit 0
`;

/// One hermetic sandbox per case: its own PATH entry, its own TMPDIR and HOME
/// (so the hand-off file can only land somewhere we can inspect), its own
/// output dir.
function makeCase(t, { stub = STUB_NODE } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "fbx-entrypoint-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  const out = path.join(root, "out");
  const tmp = path.join(root, "tmp");
  const home = path.join(root, "home");
  for (const d of [bin, out, tmp, home]) fs.mkdirSync(d);
  fs.writeFileSync(path.join(bin, "node"), stub, { mode: 0o755 });
  return { root, bin, out, tmp, home };
}

function runEntrypoint(c, { env = {}, args = ["node", "/opt/fluidbox/index.mjs"] } = {}) {
  return spawnSync(ENTRYPOINT, args, {
    encoding: "utf8",
    env: {
      PATH: `${c.bin}:${process.env.PATH}`,
      TMPDIR: c.tmp,
      HOME: c.home,
      FBX_TEST_OUT: c.out,
      ...env,
    },
  });
}

const readOut = (c, name) => {
  const p = path.join(c.out, name);
  return fs.existsSync(p) ? fs.readFileSync(p, "utf8") : null;
};

// ── The core guarantee ────────────────────────────────────────────────────

test("the exec'd process's environment never contains the runner-control token", (t) => {
  const c = makeCase(t);
  const r = runEntrypoint(c, {
    env: { FLUIDBOX_SESSION_TOKEN: TOKEN, FLUIDBOX_SESSION_ID: "sess-1" },
  });
  assert.equal(r.status, 0, `entrypoint failed: ${r.stderr}`);

  const envDump = readOut(c, "env");
  assert.ok(envDump, "the stub never ran — the entrypoint did not exec the command");

  // THE assertion. Not "the variable is absent" but "the value is nowhere in
  // the environment", so renaming the variable cannot launder a leak.
  assert.ok(
    !envDump.includes(TOKEN),
    `the runner-control token survived into the exec'd environment:\n${envDump}`,
  );
  assert.ok(
    !/^FLUIDBOX_SESSION_TOKEN=/m.test(envDump),
    `FLUIDBOX_SESSION_TOKEN is still set in the exec'd environment:\n${envDump}`,
  );

  // …and the runner was still told where to find its credential.
  assert.match(envDump, /^FLUIDBOX_SESSION_TOKEN_FD=3$/m);
  // Unrelated wiring is passed through untouched.
  assert.match(envDump, /^FLUIDBOX_SESSION_ID=sess-1$/m);
  // The command and its arguments survive the wrapper verbatim.
  assert.equal(readOut(c, "argv"), "/opt/fluidbox/index.mjs");

  // The intended channel actually delivered.
  assert.equal(readOut(c, "fd3"), TOKEN);

  // Nothing was left behind on disk for a later reader.
  assert.deepEqual(fs.readdirSync(c.tmp), [], "a hand-off file was left in TMPDIR");
  assert.deepEqual(fs.readdirSync(c.home), [], "a hand-off file was left in HOME");
});

test("/proc/self/environ — the surface an agent child actually reads — is clean", { skip: !IS_LINUX && "linux only" }, (t) => {
  const c = makeCase(t);
  const r = runEntrypoint(c, { env: { FLUIDBOX_SESSION_TOKEN: TOKEN } });
  assert.equal(r.status, 0, `entrypoint failed: ${r.stderr}`);

  const procEnviron = readOut(c, "proc_environ");
  assert.ok(procEnviron, "/proc/self/environ was unreadable on a linux host");
  assert.ok(
    !procEnviron.includes(TOKEN),
    `the token is readable at /proc/<pid>/environ:\n${procEnviron}`,
  );
  assert.match(procEnviron, /^FLUIDBOX_SESSION_TOKEN_FD=3$/m);
});

test("the hand-off file is unlinked and mode 0600 while the descriptor is open", { skip: !IS_LINUX && "linux only" }, (t) => {
  const c = makeCase(t);
  const r = runEntrypoint(c, { env: { FLUIDBOX_SESSION_TOKEN: TOKEN } });
  assert.equal(r.status, 0, `entrypoint failed: ${r.stderr}`);

  // procfs reports a deleted-but-open file's path with a " (deleted)" suffix —
  // direct proof that the bytes are reachable by no path by the time the runner
  // (and therefore any agent child) exists.
  assert.match(readOut(c, "fd3_link") || "", /\(deleted\)\s*$/);
  assert.equal((readOut(c, "fd3_mode") || "").trim(), "600");
});

// ── The runner end of the contract ────────────────────────────────────────

/// A probe that boots the REAL contract module the way a runner does and
/// reports what it got. `node` on PATH is the real interpreter here.
function probeCase(t, probeSource) {
  const c = makeCase(t, { stub: "" });
  fs.rmSync(path.join(c.bin, "node"));
  fs.symlinkSync(process.execPath, path.join(c.bin, "node"));
  const probe = path.join(c.root, "probe.mjs");
  fs.writeFileSync(probe, probeSource);
  return { c, probe };
}

const LOAD_PROBE = `
import { loadRunnerEnv } from ${JSON.stringify(CONTRACT)};
import fs from "node:fs";
const env = loadRunnerEnv();
let fd3Open = true;
try { fs.fstatSync(3); } catch { fd3Open = false; }
process.stdout.write(JSON.stringify({
  token: env.TOKEN,
  toolToken: env.TOOL_TOKEN,
  envVar: process.env.FLUIDBOX_SESSION_TOKEN ?? null,
  fd3Open,
}));
`;

const RUNNER_ENV = {
  FLUIDBOX_CONTROL_URL: "http://control.invalid",
  FLUIDBOX_SESSION_ID: "sess-1",
  FLUIDBOX_TASK: "do the thing",
};

test("the runner reads its credential from the hand-off descriptor and closes it", (t) => {
  const { c, probe } = probeCase(t, LOAD_PROBE);
  const r = runEntrypoint(c, {
    env: { ...RUNNER_ENV, FLUIDBOX_SESSION_TOKEN: TOKEN },
    args: ["node", probe],
  });
  assert.equal(r.status, 0, `probe failed (${r.status}): ${r.stderr}`);
  const got = JSON.parse(r.stdout);
  assert.equal(got.token, TOKEN, "loadRunnerEnv did not recover the token");
  assert.equal(got.envVar, null, "the token was still readable from process.env");
  // Closed BEFORE the harness can spawn anything, so no child can inherit it.
  assert.equal(got.fd3Open, false, "the hand-off descriptor was left open");
  // The scoped-token fallback still works off the recovered credential.
  assert.equal(got.toolToken, TOKEN);
});

test("compatibility path: with no hand-off, the environment still works", (t) => {
  const { c, probe } = probeCase(t, LOAD_PROBE);
  // Bypasses the entrypoint entirely — `node index.mjs`, an old manifest.
  const r = spawnSync(process.execPath, [probe], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, ...RUNNER_ENV, FLUIDBOX_SESSION_TOKEN: TOKEN },
  });
  assert.equal(r.status, 0, `probe failed (${r.status}): ${r.stderr}`);
  const got = JSON.parse(r.stdout);
  assert.equal(got.token, TOKEN);
  // …and this is exactly why that path re-opens the residual: the token is in
  // the environment for the life of the process. Asserted so the compatibility
  // path's cost stays visible rather than implied.
  assert.equal(got.envVar, TOKEN);
});

// ── Fail closed and loudly ────────────────────────────────────────────────

test("a broken hand-off aborts with EXIT_TOKEN_HANDOFF, never a silent fallback", (t) => {
  const { c, probe } = probeCase(t, LOAD_PROBE);
  for (const [label, fd] of [
    // An OUT-OF-RANGE descriptor, not merely an unopened one. "fd 9 is closed"
    // reads like a fact but is a platform assumption: a parent can leak
    // descriptors above 2 into a child, and CI proved it — on the GitHub Linux
    // runner this case died by SIGNAL (spawnSync status `null`) instead of
    // exiting 4, while it exited 4 on macOS. A descriptor above the process
    // limit is EBADF by definition everywhere, so the case tests the guard
    // rather than the environment.
    ["an out-of-range descriptor", "1000000"],
    ["a descriptor number that cannot be ours", "0"],
    ["a non-numeric value", "three"],
  ]) {
    const r = spawnSync(process.execPath, [probe], {
      encoding: "utf8",
      env: {
        PATH: process.env.PATH,
        ...RUNNER_ENV,
        FLUIDBOX_SESSION_TOKEN_FD: fd,
        // Present on purpose: the hand-off having been ATTEMPTED must beat any
        // environment value, or a bad fd would silently reinstate the residual.
        FLUIDBOX_SESSION_TOKEN: TOKEN,
      },
    });
    // `signal` first: a `status` of null means the child was KILLED, which the
    // bare status assertion reports only as "null !== 4" — a message that sent
    // the first CI failure here on a long detour.
    assert.equal(r.signal, null, `${label}: killed by ${r.signal}, stderr: ${r.stderr}`);
    assert.equal(r.status, 4, `${label}: expected EXIT_TOKEN_HANDOFF (4), got ${r.status} ${r.stdout}`);
    assert.match(r.stderr, /FATAL — the runner-control credential hand-off failed/, label);
    assert.ok(!r.stdout.includes(TOKEN), `${label}: fell back to the environment`);
  }
});

test("the entrypoint refuses to exec anything when it has no command", (t) => {
  const c = makeCase(t);
  const r = runEntrypoint(c, { env: { FLUIDBOX_SESSION_TOKEN: TOKEN }, args: [] });
  assert.equal(r.status, 4);
  assert.match(r.stderr, /no runner command was given to exec/);
});

test("with no token in the environment the entrypoint is a transparent wrapper", (t) => {
  const c = makeCase(t);
  const r = runEntrypoint(c, { env: { FLUIDBOX_SESSION_ID: "sess-1" } });
  assert.equal(r.status, 0, `entrypoint failed: ${r.stderr}`);
  const envDump = readOut(c, "env");
  assert.ok(envDump, "the entrypoint did not exec the command");
  // No descriptor is advertised, so the runner takes the environment path and
  // its own requireEnv() owns the missing-token diagnostic.
  assert.ok(!/^FLUIDBOX_SESSION_TOKEN_FD=/m.test(envDump), envDump);
  assert.deepEqual(fs.readdirSync(c.tmp), []);
});
