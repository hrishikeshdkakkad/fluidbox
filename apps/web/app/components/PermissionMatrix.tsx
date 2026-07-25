"use client";

// The resolved permission matrix. Every verdict here was decided by the policy
// engine in the control plane and sent over the wire — for a saved policy via
// GET /policies/{name}, for an in-progress draft via POST /policies/preview.
// This component chooses how to SHOW a verdict, never what the verdict is.
//
// Editing is the DRAFT flow (design §4.4): clicking an action edits/creates an
// exact-name HEAD rule in the client-side draft; nothing is written until
// Publish. Conditional rows (paths/shell) stay display-only here — the rules
// editor is where constraints are edited, because a flat action cannot express
// "allow in /workspace · never .env · ask elsewhere".

import { MatrixRow, PolicyAction, RuleConstraints, ToolRule } from "../lib/api";

/** The policy engine's vocabulary, in the product's words. "approve" means the
 *  run pauses and waits for a human, so it reads as "Ask". Exported so every
 *  governance surface says the same word for the same verdict. */
export const VERB: Record<PolicyAction, string> = {
  allow: "Allow",
  approve: "Ask",
  deny: "Deny",
};
const ACTIONS: PolicyAction[] = ["allow", "approve", "deny"];

const GROUP_LABEL: Record<string, string> = {
  files: "Files",
  search: "Search",
  shell: "Shell",
  web: "Web",
  meta: "Agent",
};

/**
 * A conditional rule stated as a sentence.
 *
 * The fallback clause ("otherwise ask") comes from the server's
 * `paths_on_no_match` / `shell_on_no_match`. It is deliberately NOT hardcoded:
 * the browser must never re-derive a verdict the policy engine already decided.
 */
function describe(c: RuleConstraints, action: PolicyAction): string {
  const verb = VERB[action].toLowerCase();
  const parts: string[] = [];

  if (c.paths_allow.length) parts.push(`${verb} in ${c.paths_allow.join(", ")}`);
  if (c.paths_deny.length) parts.push(`never ${c.paths_deny.join(", ")}`);
  if (c.shell_allow_prefixes.length) {
    parts.push(`${verb} for ${c.shell_allow_prefixes.length} known-safe commands`);
  }
  if (c.shell_deny_regex.length) {
    parts.push(
      `${c.shell_deny_regex.length} blocked pattern${c.shell_deny_regex.length === 1 ? "" : "s"}`
    );
  }

  const onNoMatch = c.paths_on_no_match ?? c.shell_on_no_match;
  if (onNoMatch) parts.push(`otherwise ${VERB[onNoMatch].toLowerCase()}`);

  const sentence = parts.join(" · ");
  return sentence.charAt(0).toUpperCase() + sentence.slice(1);
}

/** The full constraint lists, for the hover title — the sentence summarises
 *  long shell lists as counts, but the detail stays inspectable. */
function detail(c: RuleConstraints): string {
  const lines: string[] = [];
  if (c.paths_allow.length) lines.push(`Allowed paths:\n  ${c.paths_allow.join("\n  ")}`);
  if (c.paths_deny.length) lines.push(`Denied paths:\n  ${c.paths_deny.join("\n  ")}`);
  if (c.shell_allow_prefixes.length) {
    lines.push(`Allowed command prefixes:\n  ${c.shell_allow_prefixes.join("\n  ")}`);
  }
  if (c.shell_deny_regex.length) {
    lines.push(`Blocked command patterns:\n  ${c.shell_deny_regex.join("\n  ")}`);
  }
  return lines.join("\n\n");
}

/** `mcp__cloudflare__d1_database_create` → `d1_database_create`; the server
 *  name is already the group heading, so it is not repeated on every row. */
function toolLabel(row: MatrixRow): string {
  const prefix = `mcp__${row.server}__`;
  return row.server && row.tool.startsWith(prefix) ? row.tool.slice(prefix.length) : row.tool;
}

/** Is the rule that decided this row a MATRIX-authored head rule for exactly
 *  this tool — one exact matcher, no constraints, no per-rule overrides? Such
 *  a rule is safe to remove from the matrix (the tool falls back to whatever
 *  the rules below say). This inspects the DRAFT'S STRUCTURE the user is
 *  editing — it re-derives no verdict. */
export function isExactHeadRule(rule: ToolRule | undefined, tool: string): boolean {
  return (
    !!rule &&
    rule.match.length === 1 &&
    rule.match[0] === tool &&
    !rule.paths &&
    !rule.shell &&
    !rule.on_autonomous &&
    rule.approval_ttl_secs == null &&
    rule.approval_scope == null
  );
}

type Group = { key: string; label: string; mcp: boolean; rows: MatrixRow[] };

/** `group` keys canonical tools; for `mcp__*` rows `group` is null and the
 *  server name is the grouping key instead. Server order is preserved. */
function groupRows(rows: MatrixRow[]): Group[] {
  const order: string[] = [];
  const byKey = new Map<string, MatrixRow[]>();
  for (const row of rows) {
    const key = row.group ?? row.server ?? "other";
    if (!byKey.has(key)) {
      byKey.set(key, []);
      order.push(key);
    }
    byKey.get(key)!.push(row);
  }
  return order.map((key) => {
    const groupRows = byKey.get(key)!;
    const mcp = groupRows[0].group === null;
    return { key, label: GROUP_LABEL[key] ?? key, mcp, rows: groupRows };
  });
}

export function PermissionMatrix({
  rows,
  tools,
  onSet,
  onClear,
}: {
  rows: MatrixRow[];
  /** The DRAFT's rule list — used only to recognise matrix-authored exact
   *  head rules (structure, not verdicts). */
  tools: ToolRule[];
  /** Set this tool's action in the draft (edit/create an exact head rule). */
  onSet: (tool: string, action: PolicyAction) => void;
  /** Remove this tool's matrix-authored head rule from the draft. */
  onClear: (tool: string) => void;
}) {
  return (
    <>
      {groupRows(rows).map((group) => (
        <section key={group.key} className="matrix-group">
          <div className="sectitle">
            {group.label}
            {group.mcp && <span className="chip">MCP server</span>}
          </div>
          <div className="matrix">
            {group.rows.map((row) => (
              <Row key={row.tool} row={row} tools={tools} onSet={onSet} onClear={onClear} />
            ))}
          </div>
        </section>
      ))}
    </>
  );
}

function Row({
  row,
  tools,
  onSet,
  onClear,
}: {
  row: MatrixRow;
  tools: ToolRule[];
  onSet: (tool: string, action: PolicyAction) => void;
  onClear: (tool: string) => void;
}) {
  const status = row.status;
  // A conditional rule's verdict depends on the path touched or the command
  // run, so no single action can express it — its home is the rules editor.
  const configurable = status.status !== "conditional";
  const winningRule =
    status.status !== "default" && status.rule != null ? tools[status.rule] : undefined;
  const matrixAuthored = isExactHeadRule(winningRule, row.tool);

  return (
    <div className="matrix-row">
      <span className="matrix-tool mono" title={row.tool}>
        {toolLabel(row)}
      </span>

      <div className="matrix-verdict">
        {status.status === "conditional" ? (
          <span className="matrix-conditional" title={detail(status.constraints)}>
            {describe(status.constraints, status.action)}
          </span>
        ) : (
          // Three mutually exclusive options, so: a real radio group. Native
          // radios are what make the control honest to a screen reader —
          // exclusivity, "1 of 3", and arrow-key navigation are the browser's,
          // not ours. Choosing what is already in force writes nothing (the
          // draft only changes when the action actually differs).
          <fieldset className="seg">
            <legend className="sr-only">Permission for {row.tool}</legend>
            {ACTIONS.map((action) => (
              <label key={action} className={status.action === action ? "on" : ""}>
                <input
                  type="radio"
                  name={`perm-${row.tool}`}
                  value={action}
                  checked={status.action === action}
                  disabled={!configurable}
                  onChange={() => {
                    if (status.action !== action) onSet(row.tool, action);
                  }}
                />
                {VERB[action]}
              </label>
            ))}
          </fieldset>
        )}
      </div>

      <div className="matrix-tail">
        {matrixAuthored ? (
          <button
            type="button"
            className="text-action"
            onClick={() => onClear(row.tool)}
            title="Remove this per-tool rule from the draft — the tool falls back to the rules below"
          >
            Per-tool rule · remove
          </button>
        ) : status.status === "default" ? (
          <span className="faint">policy default</span>
        ) : status.status === "conditional" ? (
          <span className="faint">edit in Rules</span>
        ) : null}
      </div>
    </div>
  );
}
