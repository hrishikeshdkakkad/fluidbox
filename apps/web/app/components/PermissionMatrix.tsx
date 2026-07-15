"use client";

// The resolved permission matrix. Every verdict here was decided by the policy
// engine in the control plane and sent over the wire — this component chooses
// how to SHOW a verdict, never what the verdict is.

import { MatrixRow, PolicyAction, RuleConstraints } from "../lib/api";

/** The policy engine's vocabulary, in the product's words. "approve" means the
 *  run pauses and waits for a human, so it reads as "Ask". */
const VERB: Record<PolicyAction, string> = {
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
  busy,
  onSet,
  onClear,
}: {
  rows: MatrixRow[];
  /** Tool with a request in flight; its controls are disabled meanwhile. */
  busy: string | null;
  onSet: (tool: string, action: PolicyAction) => void;
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
              <Row
                key={row.tool}
                row={row}
                busy={busy === row.tool}
                onSet={onSet}
                onClear={onClear}
              />
            ))}
          </div>
        </section>
      ))}
    </>
  );
}

function Row({
  row,
  busy,
  onSet,
  onClear,
}: {
  row: MatrixRow;
  busy: boolean;
  onSet: (tool: string, action: PolicyAction) => void;
  onClear: (tool: string) => void;
}) {
  const status = row.status;

  // A conditional rule's verdict depends on the path touched or the command
  // run, so no single action can express it. Offering a three-way control here
  // would let one click flatten the rule and drop `paths.deny: **/.env`. The
  // server refuses such an override with a 400; the UI must not offer what the
  // server will refuse. `overridable` is the same answer from the same source.
  const configurable = status.status !== "conditional" && row.overridable;

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
        ) : configurable ? (
          // Three mutually exclusive options, so: a real radio group. Native
          // radios are what make the control honest to a screen reader —
          // exclusivity, "1 of 3", and arrow-key navigation are the browser's,
          // not ours. The <legend> names the group and is hidden visually only;
          // `.seg` keeps the look, with each <label> as one option.
          <fieldset className="seg" disabled={busy}>
            <legend className="sr-only">Permission for {row.tool}</legend>
            {ACTIONS.map((action) => (
              <label key={action} className={status.action === action ? "on" : ""}>
                <input
                  type="radio"
                  name={`perm-${row.tool}`}
                  value={action}
                  checked={status.action === action}
                  // Choosing what is already in force must not write anything:
                  // a PUT here would mint an override with an identical action,
                  // bumping the policy version and flipping this row's tail
                  // from "policy default" to "Overridden" — a global change the
                  // click never asked for. `status.action` is the server's
                  // resolved verdict, so this compares, it never re-derives.
                  // (An overridden row re-selecting its own action is likewise
                  // a no-op; the tail's "clear" button is what reverts it.)
                  // A radio fires no change event when re-picked, so this is
                  // belt-and-braces — the invariant should not rest on that.
                  onChange={() => {
                    if (status.action !== action) onSet(row.tool, action);
                  }}
                />
                {VERB[action]}
              </label>
            ))}
          </fieldset>
        ) : (
          <span className="matrix-fixed">{VERB[status.action]}</span>
        )}
      </div>

      <div className="matrix-tail">
        {status.status === "overridden" ? (
          <button
            type="button"
            className="text-action"
            disabled={busy}
            onClick={() => onClear(row.tool)}
            title={`Clear this override — restores ${VERB[status.underlying.action]}`}
          >
            Overridden · clear
          </button>
        ) : status.status === "default" ? (
          <span className="faint">policy default</span>
        ) : null}
      </div>
    </div>
  );
}
