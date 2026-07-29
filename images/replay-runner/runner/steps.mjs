// Real execution for replayed tool steps, confined to the run's workspace.
// Pure with respect to fluidbox wiring: no tokens, no control-plane calls.
import { execFile } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, normalize, relative, resolve, sep } from "node:path";

const OUTPUT_CAP = 16 * 1024;

// Canonical inputs carry container-absolute paths (/workspace/…); tests and
// local runs rebase them onto whatever directory stands in for the workspace.
function containedPath(filePath, workspaceDir) {
  const base = resolve(workspaceDir);
  const target = filePath.startsWith("/workspace")
    ? join(base, filePath.slice("/workspace".length))
    : resolve(base, filePath);
  const norm = normalize(target);
  if (norm !== base && !norm.startsWith(base + sep)) {
    return { err: `refusing path outside the workspace: ${filePath}` };
  }
  return { path: norm, rel: relative(base, norm) || "." };
}

function runBash(command, cwd, timeoutMs) {
  return new Promise((resolveP) => {
    execFile(
      "bash",
      ["-c", command],
      { cwd, timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, env: process.env },
      (error, stdout, stderr) => {
        const output = ((stdout || "") + (stderr || "")).slice(0, OUTPUT_CAP);
        if (error && error.killed) {
          resolveP({ ok: false, exit_code: null, output: `${output}\n[timed out after ${timeoutMs}ms]`.trim() });
        } else if (error) {
          resolveP({ ok: false, exit_code: typeof error.code === "number" ? error.code : 1, output });
        } else {
          resolveP({ ok: true, exit_code: 0, output });
        }
      },
    );
  });
}

/// Execute one transcript step against the workspace. Never throws: every
/// outcome is {ok, output, exit_code?} so the driver can narrate it.
export async function executeStep(step, workspaceDir) {
  const input = step.input || {};
  switch (step.tool) {
    case "Bash": {
      if (typeof input.command !== "string" || !input.command.trim()) {
        return { ok: false, output: "Bash step without a command" };
      }
      return runBash(input.command, workspaceDir, step.timeout_ms || 60_000);
    }
    case "Write": {
      const loc = containedPath(String(input.file_path || ""), workspaceDir);
      if (loc.err) return { ok: false, output: loc.err };
      mkdirSync(dirname(loc.path), { recursive: true });
      writeFileSync(loc.path, String(input.content ?? ""));
      return { ok: true, output: `wrote ${loc.rel}` };
    }
    case "Edit": {
      const loc = containedPath(String(input.file_path || ""), workspaceDir);
      if (loc.err) return { ok: false, output: loc.err };
      let text;
      try {
        text = readFileSync(loc.path, "utf8");
      } catch {
        return { ok: false, output: `cannot read ${loc.rel}` };
      }
      const { old_string: oldStr, new_string: newStr } = input;
      if (typeof oldStr !== "string" || typeof newStr !== "string") {
        return { ok: false, output: "Edit step needs old_string and new_string" };
      }
      const first = text.indexOf(oldStr);
      if (first === -1) return { ok: false, output: `old_string not found in ${loc.rel}` };
      if (text.indexOf(oldStr, first + 1) !== -1) {
        return { ok: false, output: `old_string not unique in ${loc.rel}` };
      }
      writeFileSync(loc.path, text.slice(0, first) + newStr + text.slice(first + oldStr.length));
      return { ok: true, output: `edited ${loc.rel}` };
    }
    default:
      return { ok: false, output: `unsupported tool ${step.tool}` };
  }
}
