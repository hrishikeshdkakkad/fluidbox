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

import { useState } from "react";
import {
  ApprovalScope,
  EgressMode,
  NetworkGrantMode,
  NetworkPolicy,
  PolicyAction,
  PolicyContent,
  TargetRule,
} from "../lib/api";
import { coerceCap, coerceTtlSecs } from "../lib/policy-caps";
import { MODE_HINT, MODE_LABEL, MODE_ORDER, networkOf } from "../lib/network";
import { VERB } from "./PermissionMatrix";
import { TargetRuleEditor } from "./TargetRuleEditor";

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

/** A nullable numeric cap: an EMPTY field means no ceiling of that kind.
 *
 *  `integer` marks the caps that are `u64` server-side (seconds, tokens, tool
 *  calls) as opposed to the `f64` cost.
 *
 *  This is a TEXT input holding its own raw string, and both of those are
 *  load-bearing. `<input type="number">` reports `value === ""` for any
 *  intermediate state the browser cannot parse — `-`, `1e`, `1.` — which is
 *  indistinguishable from a cleared field. Deriving the draft from it turned
 *  every such keystroke into `null`, i.e. NO CEILING: a silent WIDENING, the
 *  one direction an edit must never take by accident. Holding the raw text
 *  locally makes "" mean exactly what the person typed.
 *
 *  What a given string MEANS is `lib/policy-caps.ts::coerceCap`, which is
 *  where that rule is stated and tested. */
function CapField({
  label,
  hint,
  value,
  integer = false,
  onChange,
}: {
  label: string;
  hint?: string;
  value: number | null;
  integer?: boolean;
  onChange: (next: number | null) => void;
}) {
  const [raw, setRaw] = useState(value == null ? "" : String(value));
  const edit = (next: string) => {
    setRaw(next);
    const out = coerceCap(next, integer);
    if (out.kind === "clear") onChange(null);
    else if (out.kind === "set") onChange(out.value);
  };
  return (
    <label className="field">
      <span className="lab">
        {label} {hint ? <span className="optional-label">{hint}</span> : null}
      </span>
      <input
        className="inp mono"
        type="text"
        inputMode={integer ? "numeric" : "decimal"}
        value={raw}
        placeholder={NO_CAP}
        spellCheck={false}
        onChange={(e) => edit(e.target.value)}
      />
    </label>
  );
}

/** The approval TTL. Not a `CapField`: it is NOT nullable — every approval has
 *  an expiry — so an empty field has no meaning to send, and the same raw-text
 *  handling applies for the same reason (a `type="number"` intermediate state
 *  used to collapse to `Number("") || 1`, i.e. one second). The rule is
 *  `lib/policy-caps.ts::coerceTtlSecs`. */
function TtlField({ value, onChange }: { value: number; onChange: (next: number) => void }) {
  const [raw, setRaw] = useState(String(value));
  return (
    <label className="field">
      <span className="lab">
        Request expires after (seconds) <span className="optional-label">{duration(value)}</span>
      </span>
      <input
        className="inp mono"
        type="text"
        inputMode="numeric"
        value={raw}
        spellCheck={false}
        onChange={(e) => {
          setRaw(e.target.value);
          const out = coerceTtlSecs(e.target.value);
          if (out.kind === "set") onChange(out.value);
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
          integer
          hint={budgets.max_wall_clock_secs != null ? duration(budgets.max_wall_clock_secs) : undefined}
          value={budgets.max_wall_clock_secs}
          onChange={(v) => set({ budgets: { ...budgets, max_wall_clock_secs: v } })}
        />
        <CapField
          label="Tokens"
          integer
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
          integer
          value={budgets.max_tool_calls}
          onChange={(v) => set({ budgets: { ...budgets, max_tool_calls: v } })}
        />
      </div>

      <div className="sectitle">Approvals</div>
      <div className="agent-creator-grid">
        <TtlField
          value={approvals.default_ttl_secs}
          onChange={(default_ttl_secs) => set({ approvals: { ...approvals, default_ttl_secs } })}
        />
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

      {(() => {
        const net = networkOf(content);
        const setNet = (patch: Partial<NetworkPolicy>) =>
          set({ network: { ...net, ...patch } });
        return (
          <>
            <div className="sectitle">Where a sandbox may reach</div>
            <p className="helper" style={{ marginBottom: 4 }}>
              The ceiling for every run on this policy. An agent may ask for less, never more.
            </p>

            <label className="field">
              <span className="lab">Ceiling</span>
              <select
                className="inp"
                value={net.max_mode}
                onChange={(e) => {
                  const max_mode = e.target.value as NetworkGrantMode;
                  // A public request must carry NO targets; clearing here keeps the
                  // ceiling and the catalog from disagreeing on screen.
                  setNet(max_mode === "public" ? { max_mode, allow: [] } : { max_mode });
                }}
              >
                {MODE_ORDER.map((m) => (
                  <option key={m} value={m}>
                    {MODE_LABEL[m]}
                  </option>
                ))}
              </select>
            </label>
            <p className="helper">{MODE_HINT[net.max_mode]}</p>

            {net.max_mode === "public" && (
              <p className="helper warn">
                Public grants reach anything the deployment&rsquo;s deny wall does not forbid.
                On a deployment fronted by a CDN, that wall cannot enumerate every address of
                your own public API, so a run could in principle reach it. Sandbox tokens are
                scoped to the internal plane and the load balancer refuses unsigned origin
                traffic, so the exposure is limited to unauthenticated endpoints — but prefer
                Approved targets where you can name them.
              </p>
            )}

            {net.max_mode === "approved" && (
              <>
                <div className="sectitle">Allowed targets</div>
                <TargetRuleEditor
                  value={net.allow}
                  onChange={(allow: TargetRule[]) => setNet({ allow })}
                />
              </>
            )}

            {net.max_mode !== "offline" && (
              <>
                <label className="field">
                  <span className="lab">Require a human to authorize each run</span>
                  <input
                    type="checkbox"
                    checked={net.require_approval}
                    onChange={(e) => setNet({ require_approval: e.target.checked })}
                  />
                </label>
                <p className="helper">
                  The run parks in <code>awaiting_authorization</code> and appears in the
                  timeline for approval before it gets any egress.
                </p>

                <label className="field">
                  <span className="lab">Max grant lifetime (seconds)</span>
                  <input
                    className="inp"
                    type="number"
                    value={net.max_grant_secs ?? ""}
                    placeholder="default"
                    onChange={(e) =>
                      setNet({ max_grant_secs: e.target.value === "" ? null : Number(e.target.value) })
                    }
                  />
                </label>
              </>
            )}
          </>
        );
      })()}

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
