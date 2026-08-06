"use client";

// The egress a revision DECLARES, authored in one place.
//
// This shape is edited from two screens — Agents › Add revision, and the run
// composer's new-agent path — which held byte-similar copies of the same
// select, the same target editor and the same helper text. They had already
// drifted, and the rule about which modes carry targets lived in both onChange
// handlers. One editor, one rule.
//
// What LEAVES the browser is `lib/network.ts::requestForWire`, not this: the
// caller applies it at submit. Targets typed under `approved` therefore SURVIVE
// a toggle to offline or public (nothing is destroyed while you decide) while
// the payload still carries only what the mode is allowed to carry.

import { NetworkGrantMode, NetworkRequest } from "../lib/api";
import { MODE_LABEL, MODE_ORDER } from "../lib/network";
import { TargetRuleEditor } from "./TargetRuleEditor";

export function NetworkRequestEditor({
  value,
  onChange,
  disabled = false,
}: {
  value: NetworkRequest;
  onChange: (next: NetworkRequest) => void;
  disabled?: boolean;
}) {
  const keptTargets = value.mode !== "approved" ? value.targets.length : 0;
  return (
    <>
      <label className="field">
        <span className="lab">Mode</span>
        <select
          className="inp"
          disabled={disabled}
          value={value.mode}
          onChange={(e) => onChange({ ...value, mode: e.target.value as NetworkGrantMode })}
        >
          {MODE_ORDER.map((m) => (
            <option key={m} value={m}>
              {MODE_LABEL[m]}
            </option>
          ))}
        </select>
      </label>

      {value.mode === "approved" && (
        <TargetRuleEditor
          value={value.targets}
          disabled={disabled}
          onChange={(targets) => onChange({ ...value, targets })}
        />
      )}

      {value.mode === "public" && (
        <p className="helper">
          A public declaration carries no targets: it reaches everything the deployment&rsquo;s deny
          wall permits, and core refuses the pairing outright because listing targets beside
          &ldquo;everything&rdquo; reads as a narrowing the datapath would not apply.
        </p>
      )}

      {keptTargets > 0 && (
        // Say so rather than leaving it as hidden state: the targets are held
        // for a switch back, and are NOT part of what this declaration grants.
        <p className="helper">
          {keptTargets} target{keptTargets === 1 ? "" : "s"} kept for if you switch back to{" "}
          {MODE_LABEL.approved} — a {MODE_LABEL[value.mode].toLowerCase()} declaration sends none.
        </p>
      )}
    </>
  );
}
