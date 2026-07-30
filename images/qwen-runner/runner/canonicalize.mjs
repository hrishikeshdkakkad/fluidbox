// Qwen tool-call canonicalization — the load-bearing supervisor obligation.
//
// Names/shapes crossing /permission MUST be the canonical fluidbox vocabulary
// (fluidbox-core/src/tools.rs); canonicalization is runner-side by contract.
// Qwen Code 0.21.x converged on Claude-Code-style parameter names (file_path,
// old_string/new_string, pattern/path, notebook_path — verified against the
// pinned bundle, docs/research/2026-07-30-qwen-code-sdk-protocol.md §3), so
// most mappings are a rename plus fail-closed required-field checks. The two
// rules that carry real weight:
//
//   * UNKNOWN TOOL NAME → DENY. A qwen tool this map doesn't know must never
//     reach the gate under its native name (that would fork the policy
//     vocabulary) nor slip through ungated (post-hoc ledgering is never a
//     releasable mode). The settings lockdown unregisters everything outside
//     this map; the deny is the drift backstop for a version bump that grows
//     the census.
//   * MISSING REQUIRED FIELDS → DENY. Never gate an empty shape — a
//     supervised human could blind-approve `Bash{}` (the codex empty-edits
//     lesson, Phase 6 review H1).
//
// `run_shell_command.directory` is the exec cwd: a `cat x` verdict is not
// equivalent if it runs outside the workspace, so the supervisor enforces
// realpath containment itself (mirroring the codex supervisor's
// cwdInWorkspace) rather than trusting the CLI's own workspace boundary.

import fs from "node:fs";

// Unwrap ONE layer of `sh -c` / `bash -lc` / `zsh -c` wrapping (with or
// without an absolute path). Qwen executes `command` via `bash -c` itself so
// the model normally sends the bare script, but a wrapped spelling would
// match no policy allow-prefix and over-escalate (or over-deny under
// ReadOnly) — the same fail-safe unwrap the codex supervisor ships. The
// metachar screen in policy applies to the UNWRAPPED script.
const SHELL_WRAP = /^(?:\/usr\/bin\/|\/bin\/|\/usr\/local\/bin\/)?(?:ba|z)?sh\s+-l?c\s+([\s\S]+)$/;

export function canonicalizeCommand(commandStr) {
  const m = SHELL_WRAP.exec(commandStr.trim());
  if (!m) return commandStr.trim();
  let inner = m[1].trim();
  // Strip ONE symmetric quote layer if present.
  if (
    inner.length >= 2 &&
    ((inner.startsWith('"') && inner.endsWith('"')) ||
      (inner.startsWith("'") && inner.endsWith("'")))
  ) {
    inner = inner.slice(1, -1);
  }
  return inner;
}

// Resolve-and-contain: the directory must EXIST and realpath-resolve to the
// workspace or below. No lexical fallback — a nonexistent path under a
// symlink must not be accepted lexically (codex review MINOR, kept here).
export function cwdInWorkspace(dir, workspace) {
  let resolved;
  try {
    resolved = fs.realpathSync(dir);
  } catch {
    return false;
  }
  const ws = fs.realpathSync(workspace);
  return resolved === ws || resolved.startsWith(ws + "/");
}

const deny = (message) => ({ deny: message });

const str = (v) => (typeof v === "string" && v.length > 0 ? v : null);

/// Map one qwen tool call to its canonical gate shape.
/// Returns `{ tool, input, mapBack(updatedInput) }` on success or
/// `{ deny: reason }` — the caller answers the SDK without gating.
/// `mapBack` folds a gate-rewritten canonical input back onto the ORIGINAL
/// qwen input (field names coincide, so this is a guarded merge of exactly
/// the fields we sent — gate-added extras never leak into the CLI).
export function canonicalize(toolName, input, workspace) {
  const inp = input && typeof input === "object" ? input : {};
  // Guarded merge helper: copy only `fields` back from the gate's updated
  // input, keeping everything else the CLI sent (offsets, flags, …).
  const passThrough = (tool, fields, extra = {}) => {
    const canonical = { ...extra };
    for (const f of fields) {
      if (inp[f] !== undefined) canonical[f] = inp[f];
    }
    return {
      tool,
      input: canonical,
      mapBack: (updated) => {
        if (!updated || typeof updated !== "object") return input;
        const merged = { ...inp };
        for (const f of fields) {
          if (updated[f] !== undefined) merged[f] = updated[f];
        }
        return merged;
      },
    };
  };

  switch (toolName) {
    case "run_shell_command": {
      const raw = str(inp.command);
      if (!raw) return deny("run_shell_command without a command string — refused fail-closed");
      const command = canonicalizeCommand(raw);
      if (!command) return deny("run_shell_command unwrapped to an empty command — refused");
      const canonical = { command };
      if (inp.directory !== undefined) {
        const dir = str(inp.directory);
        if (!dir || !cwdInWorkspace(dir, workspace)) {
          return deny(
            `run_shell_command directory '${inp.directory}' is outside the workspace (or does not exist) — refused`,
          );
        }
        canonical.cwd = dir; // additive context for the ledger; policy ignores unknown fields
      }
      return {
        tool: "Bash",
        input: canonical,
        mapBack: (updated) => {
          if (!updated || typeof updated !== "object" || typeof updated.command !== "string") {
            return input;
          }
          return { ...inp, command: updated.command };
        },
      };
    }
    case "read_file": {
      if (!str(inp.file_path)) return deny("read_file without file_path — refused fail-closed");
      return passThrough("Read", ["file_path"]);
    }
    case "write_file": {
      if (!str(inp.file_path) || typeof inp.content !== "string") {
        return deny("write_file without file_path/content — refused fail-closed");
      }
      return passThrough("Write", ["file_path", "content"]);
    }
    case "edit": {
      if (!str(inp.file_path) || typeof inp.old_string !== "string" || typeof inp.new_string !== "string") {
        return deny("edit without file_path/old_string/new_string — refused fail-closed");
      }
      return passThrough("Edit", ["file_path", "old_string", "new_string", "replace_all"]);
    }
    case "notebook_edit": {
      if (!str(inp.notebook_path)) return deny("notebook_edit without notebook_path — refused fail-closed");
      return passThrough("NotebookEdit", [
        "notebook_path",
        "cell_id",
        "new_source",
        "cell_type",
        "edit_mode",
      ]);
    }
    case "grep_search": {
      if (!str(inp.pattern)) return deny("grep_search without pattern — refused fail-closed");
      return passThrough("Grep", ["pattern", "path", "glob"]);
    }
    case "glob": {
      if (!str(inp.pattern)) return deny("glob without pattern — refused fail-closed");
      return passThrough("Glob", ["pattern", "path"]);
    }
    case "list_directory": {
      if (!str(inp.path)) return deny("list_directory without path — refused fail-closed");
      return passThrough("LS", ["path"]);
    }
    case "todo_write":
      return passThrough("TodoWrite", ["todos"]);
    default:
      // mcp__* never reaches here (the supervisor routes those first); every
      // other name is a census drift — deny, never forward a native name.
      return deny(
        `tool '${toolName}' has no canonical mapping — refused fail-closed (census drift?)`,
      );
  }
}
