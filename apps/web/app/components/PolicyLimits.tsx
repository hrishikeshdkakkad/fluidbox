"use client";

// Budgets · Approvals · Autonomy · Network · Defaults — the flat knobs of a
// policy (design §4.4). The permissions matrix answers what an agent may do;
// this answers what a run may SPEND doing it, how long a human has to answer,
// what happens when nobody is watching, and whether the sandbox may reach the
// network.
//
// Editing writes STRUCTURE into the client-side draft; nothing persists until
// Publish, and every resolved consequence (the autonomy summary, the matrix)
// is re-fetched from the server's preview. This file chooses words and units
// for a number, never the number.

import {
  ApprovalScope,
  Budgets,
  EgressMode,
  PolicyAction,
  PolicyContent,
} from "../lib/api";
import { VERB } from "./PermissionMatrix";

/** A cap the policy did not set. `spec::Budgets` is four `Option`s, so an unset
 *  cap arrives as `null` — no ceiling of that kind, which is not zero. */
const NO_CAP = "No limit";

const SCOPE: Record<ApprovalScope, string> = {
  once: "Once per call",
  session: "Once per session scope",
};

const EGRESS: Record<EgressMode, string> = {
  none: "None",
  "proxy-only": "Proxy only",
  allowlist: "Allowlist",
};

function num(n: number): string {
  return n.toLocaleString("en-US");
}

/** 1800 → "30 min". Units only; the seconds are the server's. */
function duration(secs: number): string {
  if (secs < 60) return `${num(secs)} sec`;
  const scaled = secs < 3600 ? secs / 60 : secs / 3600;
  return `${num(Math.round(scaled * 10) / 10)} ${secs < 3600 ? "min" : "hr"}`;
}

/** A nullable numeric cap: empty = no ceiling of that kind. */
function CapField({
  label,
  hint,
  value,
  onChange,
}: {
  label: string;
  hint?: string;
  value: number | null;
  onChange: (next: number | null) => void;
}) {
  return (
    <label className="field">
      <span className="lab">
        {label} {hint ? <span className="optional-label">{hint}</span> : null}
      </span>
      <input
        className="inp mono"
        type="number"
        min={0}
        step="any"
        value={value ?? ""}
        placeholder={NO_CAP}
        onChange={(e) => {
          const raw = e.target.value.trim();
          onChange(raw === "" ? null : Number(raw));
        }}
      />
    </label>
  );
}

/** The flat forms, editing the draft in place. */
export function PolicyLimits({
  content,
  onChange,
}: {
  content: PolicyContent;
  onChange: (next: PolicyContent) => void;
}) {
  const set = (patch: Partial<PolicyContent>) => onChange({ ...content, ...patch });
  const { budgets, approvals, autonomy, egress, defaults } = content;

  return (
    <>
      <div className="sectitle" style={{ marginTop: 0 }}>
        Default verdict
      </div>
      <p className="helper" style={{ marginBottom: 4 }}>
        When no rule matches a tool. Fail-safe is Ask — a human decides the unknown.
      </p>
      <label className="field">
        <span className="lab">Unmatched tools</span>
        <select
          className="inp"
          value={defaults.tool_action}
          onChange={(e) =>
            set({ defaults: { tool_action: e.target.value as PolicyAction } })
          }
        >
          {(["allow", "approve", "deny"] as PolicyAction[]).map((a) => (
            <option key={a} value={a}>
              {VERB[a]}
            </option>
          ))}
        </select>
      </label>

      <div className="sectitle">What a run may spend</div>
      <p className="helper" style={{ marginBottom: 4 }}>
        A ceiling, not an allowance: an agent and each run may tighten these, never widen them.
        Empty means no ceiling of that kind.
      </p>
      <div className="agent-creator-grid">
        <CapField
          label="Wall clock (seconds)"
          hint={budgets.max_wall_clock_secs != null ? duration(budgets.max_wall_clock_secs) : undefined}
          value={budgets.max_wall_clock_secs}
          onChange={(v) => set({ budgets: { ...budgets, max_wall_clock_secs: v } })}
        />
        <CapField
          label="Tokens"
          value={budgets.max_tokens}
          onChange={(v) => set({ budgets: { ...budgets, max_tokens: v } })}
        />
        <CapField
          label="Cost (USD)"
          value={budgets.max_cost_usd}
          onChange={(v) => set({ budgets: { ...budgets, max_cost_usd: v } })}
        />
        <CapField
          label="Tool calls"
          value={budgets.max_tool_calls}
          onChange={(v) => set({ budgets: { ...budgets, max_tool_calls: v } })}
        />
      </div>

      <div className="sectitle">Approvals</div>
      <div className="agent-creator-grid">
        <label className="field">
          <span className="lab">
            Request expires after (seconds){" "}
            <span className="optional-label">{duration(approvals.default_ttl_secs)}</span>
          </span>
          <input
            className="inp mono"
            type="number"
            min={1}
            value={approvals.default_ttl_secs}
            onChange={(e) =>
              set({
                approvals: {
                  ...approvals,
                  default_ttl_secs: Math.max(1, Number(e.target.value) || 1),
                },
              })
            }
          />
        </label>
        <label className="field">
          <span className="lab">One decision reaches</span>
          <select
            className="inp"
            value={approvals.scope}
            onChange={(e) =>
              set({ approvals: { ...approvals, scope: e.target.value as ApprovalScope } })
            }
          >
            {(Object.keys(SCOPE) as ApprovalScope[]).map((s) => (
              <option key={s} value={s}>
                {SCOPE[s]}
              </option>
            ))}
          </select>
        </label>
      </div>
      <p className="helper">If nobody answers in time: {VERB[approvals.timeout_action]}.</p>

      <div className="sectitle">Unattended runs</div>
      <label className="check">
        <input
          type="checkbox"
          checked={autonomy.permitted}
          onChange={(e) => set({ autonomy: { ...autonomy, permitted: e.target.checked } })}
        />
        Permit autonomous runs of this policy
      </label>
      <label className="field">
        <span className="lab">When an action would ask a human</span>
        <select
          className="inp"
          value={autonomy.on_approval_rule}
          onChange={(e) =>
            set({
              autonomy: {
                ...autonomy,
                on_approval_rule: e.target.value as "allow" | "deny",
              },
            })
          }
          disabled={!autonomy.permitted}
        >
          <option value="deny">Deny it (human absence narrows)</option>
          <option value="allow">Allow it</option>
        </select>
      </label>

      <div className="sectitle">Network</div>
      <label className="field">
        <span className="lab">Egress</span>
        <select
          className="inp"
          value={egress.mode}
          onChange={(e) => set({ egress: { mode: e.target.value as EgressMode } })}
        >
          {(Object.keys(EGRESS) as EgressMode[]).map((m) => (
            <option key={m} value={m}>
              {EGRESS[m]}
            </option>
          ))}
        </select>
      </label>
    </>
  );
}
