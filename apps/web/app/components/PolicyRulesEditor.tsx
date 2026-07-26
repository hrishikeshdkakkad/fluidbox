"use client";

// The ordered rule list — the expert half of the authoring surface (design
// §4.4). First match wins, so ORDER is part of the meaning: rules move up and
// down, and the matrix's per-tool decisions surface here as exact-name head
// rules. Everything edits the client-side draft; the server's preview resolves
// what these rules MEAN (the matrix, the autonomy summary), and Publish is
// where validation and persistence happen.

import { useRef, useState } from "react";
import { ArrowDown, ArrowUp, Plus, Trash2 } from "lucide-react";
import { ApprovalScope, PolicyAction, ToolRule } from "../lib/api";
import { VERB } from "./PermissionMatrix";

const ACTIONS: PolicyAction[] = ["allow", "approve", "deny"];

/** One glob/regex/prefix per line. Newline-separated deliberately: commas are
 *  legal characters inside a deny_regex. */
function LinesField({
  label,
  hint,
  values,
  placeholder,
  onChange,
}: {
  label: string;
  hint?: string;
  values: string[];
  placeholder?: string;
  onChange: (next: string[]) => void;
}) {
  return (
    <label className="field">
      <span className="lab">
        {label} {hint ? <span className="optional-label">{hint}</span> : null}
      </span>
      <textarea
        className="inp mono"
        style={{ minHeight: 54 }}
        value={values.join("\n")}
        placeholder={placeholder}
        spellCheck={false}
        onChange={(e) =>
          onChange(
            e.target.value
              .split("\n")
              .map((line) => line.trim())
              .filter(Boolean)
          )
        }
      />
    </label>
  );
}

function MatchChips({
  rule,
  index,
  knownTools,
  onChange,
}: {
  rule: ToolRule;
  index: number;
  knownTools: string[];
  onChange: (next: string[]) => void;
}) {
  const [pending, setPending] = useState("");
  const commit = () => {
    const value = pending.trim();
    if (!value || rule.match.includes(value)) return;
    onChange([...rule.match, value]);
    setPending("");
  };
  return (
    <div className="field">
      <span className="lab">Matches tools</span>
      <div className="chips" style={{ alignItems: "center", gap: 6 }}>
        {rule.match.map((m) => (
          <span key={m} className="chip">
            <span className="mono">{m}</span>
            <button
              type="button"
              className="text-action"
              aria-label={`Remove matcher ${m}`}
              style={{ marginLeft: 6 }}
              onClick={() => onChange(rule.match.filter((x) => x !== m))}
            >
              ×
            </button>
          </span>
        ))}
        <input
          className="inp mono"
          style={{ width: 220 }}
          list={`rule-tools-${index}`}
          value={pending}
          placeholder="Read · Bash · mcp__github__*"
          onChange={(e) => setPending(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              commit();
            }
          }}
          // Committing on blur is deliberate: silently DISCARDING typed text
          // when the user tabs away or clicks Publish is the worse failure —
          // a stray chip is visible and removable, a lost matcher is neither.
          // A partial name is inert anyway: matching is exact unless the
          // matcher ends in `*`, so `Ba` matches nothing called `Bash`.
          onBlur={commit}
        />
        <button
          type="button"
          className="btn sm"
          disabled={!pending.trim() || rule.match.includes(pending.trim())}
          onClick={commit}
        >
          Add
        </button>
        <datalist id={`rule-tools-${index}`}>
          {knownTools.map((t) => (
            <option key={t} value={t} />
          ))}
        </datalist>
      </div>
      <span className="field-hint">
        Exact names or a trailing <span className="mono">*</span> wildcard. First matching rule
        wins, top to bottom.
      </span>
    </div>
  );
}

function RuleCard({
  rule,
  index,
  count,
  knownTools,
  onChange,
  onMove,
  onRemove,
}: {
  rule: ToolRule;
  index: number;
  count: number;
  knownTools: string[];
  onChange: (next: ToolRule) => void;
  onMove: (delta: -1 | 1) => void;
  onRemove: () => void;
}) {
  const set = (patch: Partial<ToolRule>) => onChange({ ...rule, ...patch });
  const paths = rule.paths ?? null;
  const shell = rule.shell ?? null;

  return (
    <div className="panel pad" style={{ marginBottom: 10 }}>
      <div className="spread" style={{ alignItems: "center" }}>
        <div className="chips" style={{ alignItems: "center" }}>
          <span className="chip">
            rule <b>{index + 1}</b>
          </span>
          {paths && <span className="chip">paths</span>}
          {shell && <span className="chip">shell</span>}
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <button
            type="button"
            className="btn sm"
            aria-label="Move rule up"
            disabled={index === 0}
            onClick={() => onMove(-1)}
          >
            <ArrowUp size={13} />
          </button>
          <button
            type="button"
            className="btn sm"
            aria-label="Move rule down"
            disabled={index === count - 1}
            onClick={() => onMove(1)}
          >
            <ArrowDown size={13} />
          </button>
          <button type="button" className="btn sm danger" aria-label="Delete rule" onClick={onRemove}>
            <Trash2 size={13} />
          </button>
        </div>
      </div>

      <MatchChips rule={rule} index={index} knownTools={knownTools} onChange={(m) => set({ match: m })} />
      {rule.match.length === 0 && (
        <p className="err" style={{ marginTop: -4 }} role="status">
          This rule matches nothing yet — add at least one tool name before publishing.
        </p>
      )}

      <div className="agent-creator-grid">
        <label className="field">
          <span className="lab">Action</span>
          <select
            className="inp"
            value={rule.action}
            onChange={(e) => set({ action: e.target.value as PolicyAction })}
          >
            {ACTIONS.map((a) => (
              <option key={a} value={a}>
                {VERB[a]}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span className="lab">
            Risk note <span className="optional-label">shown on denials/approvals</span>
          </span>
          <input
            className="inp"
            value={rule.risk ?? ""}
            placeholder="network egress from sandbox"
            onChange={(e) => set({ risk: e.target.value || null })}
          />
        </label>
      </div>

      <details className="advanced-config" open={!!paths}>
        <summary>Path constraints {paths ? "· active" : ""}</summary>
        <div className="advanced-config-body">
          {paths ? (
            <>
              <LinesField
                label="Allowed path globs"
                hint="outside → asks a human"
                values={paths.allow}
                placeholder={"/workspace/**"}
                onChange={(allow) => set({ paths: { ...paths, allow } })}
              />
              <LinesField
                label="Denied path globs"
                hint="deny always wins"
                values={paths.deny}
                placeholder={"**/.env"}
                onChange={(deny) => set({ paths: { ...paths, deny } })}
              />
              {paths.allow.length > 0 && (
                <p className="helper">
                  A path outside the allowed globs asks a human — the engine hardcodes that
                  escalation.
                </p>
              )}
              <button type="button" className="btn sm" onClick={() => set({ paths: null })}>
                Remove path constraints
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn sm"
              onClick={() => set({ paths: { allow: [], deny: [] } })}
            >
              Add path constraints
            </button>
          )}
        </div>
      </details>

      <details className="advanced-config" open={!!shell}>
        <summary>Shell constraints {shell ? "· active" : ""}</summary>
        <div className="advanced-config-body">
          {shell ? (
            <>
              <LinesField
                label="Allowed command prefixes"
                hint="token-boundary matched"
                values={shell.allow_prefixes}
                placeholder={"git status"}
                onChange={(allow_prefixes) => set({ shell: { ...shell, allow_prefixes } })}
              />
              <LinesField
                label="Denied command patterns (regex)"
                hint="checked first, always deny"
                values={shell.deny_regex}
                placeholder={"\\bcurl\\b"}
                onChange={(deny_regex) => set({ shell: { ...shell, deny_regex } })}
              />
              <label className="field">
                <span className="lab">Anything else</span>
                <select
                  className="inp"
                  value={shell.on_no_match}
                  onChange={(e) =>
                    set({ shell: { ...shell, on_no_match: e.target.value as PolicyAction } })
                  }
                >
                  {ACTIONS.map((a) => (
                    <option key={a} value={a}>
                      {VERB[a]}
                    </option>
                  ))}
                </select>
              </label>
              <button type="button" className="btn sm" onClick={() => set({ shell: null })}>
                Remove shell constraints
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn sm"
              onClick={() =>
                set({ shell: { allow_prefixes: [], deny_regex: [], on_no_match: "approve" } })
              }
            >
              Add shell constraints
            </button>
          )}
        </div>
      </details>

      <details className="advanced-config">
        <summary>Advanced · autonomy & approval overrides</summary>
        <div className="advanced-config-body">
          <label className="field">
            <span className="lab">When autonomous and this rule would ask</span>
            <select
              className="inp"
              value={rule.on_autonomous ?? ""}
              onChange={(e) =>
                set({ on_autonomous: (e.target.value || null) as "allow" | "deny" | null })
              }
            >
              <option value="">Policy default</option>
              <option value="deny">Deny</option>
              <option value="allow">Allow</option>
            </select>
          </label>
          <label className="field">
            <span className="lab">
              Approval expires after (seconds) <span className="optional-label">optional</span>
            </span>
            <input
              className="inp mono"
              type="number"
              min={1}
              value={rule.approval_ttl_secs ?? ""}
              placeholder="policy default"
              onChange={(e) => {
                const raw = e.target.value.trim();
                set({ approval_ttl_secs: raw === "" ? null : Math.max(1, Number(raw) || 1) });
              }}
            />
          </label>
          <label className="field">
            <span className="lab">Approval scope</span>
            <select
              className="inp"
              value={rule.approval_scope ?? ""}
              onChange={(e) =>
                set({ approval_scope: (e.target.value || null) as ApprovalScope | null })
              }
            >
              <option value="">Policy default</option>
              <option value="once">Once per call</option>
              <option value="session">Once per session scope</option>
            </select>
          </label>
        </div>
      </details>
    </div>
  );
}

export function PolicyRulesEditor({
  rules,
  knownTools,
  onChange,
}: {
  rules: ToolRule[];
  /** Typeahead corpus: the canonical vocabulary ∪ this policy's mcp__* roster
   *  — exactly the names the matrix is drawn from. */
  knownTools: string[];
  onChange: (next: ToolRule[]) => void;
}) {
  // Stable per-CARD identity. A `ToolRule` carries no id (the strict publish
  // parser refuses unknown fields, so one cannot ride in the document), and
  // the array index is NOT identity: reorder or delete a rule and React would
  // hand the next rule the previous one's card — carrying that card's own
  // state, the half-typed matcher and the open/closed <details>, onto a
  // different rule. So the editor keeps a parallel id list and moves it in
  // lockstep with every mutation it performs.
  const idSeq = useRef(0);
  const ids = useRef<string[]>([]);
  if (ids.current.length !== rules.length) {
    // The list changed from OUTSIDE this editor and the LENGTH moved with it —
    // a matrix click prepending a head rule is the live case. Old ids cannot be
    // mapped onto new positions without knowing what happened, so re-key.
    // (Length now matches, so a StrictMode double render does not re-key
    // again.)
    //
    // This length check is NOT the whole story, and must not be mistaken for
    // it: a SAME-LENGTH external replacement — a revert landing while the
    // editor is open — keeps every id, which would carry a card's uncommitted
    // matcher text onto a different rule. That case is handled a level up, by
    // the page remounting this component on `formEpoch` whenever it replaces
    // the draft from outside the editors. Do not delete that key.
    ids.current = rules.map(() => `rule-${idSeq.current++}`);
  }

  const replace = (index: number, next: ToolRule) =>
    onChange(rules.map((r, i) => (i === index ? next : r)));
  const move = (index: number, delta: -1 | 1) => {
    const target = index + delta;
    if (target < 0 || target >= rules.length) return;
    const next = [...rules];
    [next[index], next[target]] = [next[target], next[index]];
    [ids.current[index], ids.current[target]] = [ids.current[target], ids.current[index]];
    onChange(next);
  };
  const remove = (index: number) => {
    ids.current = ids.current.filter((_, i) => i !== index);
    onChange(rules.filter((_, i) => i !== index));
  };
  const add = () => {
    ids.current = [...ids.current, `rule-${idSeq.current++}`];
    onChange([...rules, { match: [], action: "approve" }]);
  };

  return (
    <>
      {rules.length === 0 ? (
        <div className="empty">
          <div>No rules — every tool resolves to the policy default.</div>
        </div>
      ) : (
        rules.map((rule, index) => (
          <RuleCard
            key={ids.current[index]}
            rule={rule}
            index={index}
            count={rules.length}
            knownTools={knownTools}
            onChange={(next) => replace(index, next)}
            onMove={(delta) => move(index, delta)}
            onRemove={() => remove(index)}
          />
        ))
      )}
      <button type="button" className="btn" onClick={add}>
        <Plus size={13} /> Add rule
      </button>
    </>
  );
}
