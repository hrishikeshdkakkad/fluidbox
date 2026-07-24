"use client";

import { useId } from "react";
import { AuthMe, OwnerChoice, ownerOptions } from "../lib/api";

/**
 * Who should own a new connection: the organization (shared) or the signed-in
 * member (personal). Presentation only — it renders exactly the options the
 * principal may pick (from `ownerOptions`, which mirrors the server's
 * `resolve_owner` gate) and the caller always SENDS the choice explicitly. The
 * control plane re-enforces authority regardless of what this offers.
 *
 * `allowPersonal={false}` for github_app custody (organization-only). When only
 * one owner is possible (e.g. the operator, or a member on org-only custody) it
 * collapses to a static line rather than a pointless single radio.
 */
export function OwnerPicker({
  me,
  value,
  onChange,
  allowPersonal = true,
}: {
  me: AuthMe | null;
  value: OwnerChoice;
  onChange: (v: OwnerChoice) => void;
  allowPersonal?: boolean;
}) {
  const groupName = useId();
  const opts = ownerOptions(me, allowPersonal);
  const choices: { value: OwnerChoice; label: string; hint: string }[] = [];
  if (opts.canOrganization)
    choices.push({
      value: "organization",
      label: "Organization",
      hint: "visible to every member",
    });
  if (opts.canPersonal)
    choices.push({ value: "personal", label: "Personal", hint: "only you can see or use it" });

  if (choices.length <= 1) {
    const only = choices[0];
    return (
      <div className="field">
        <span className="lab">Owner</span>
        <span className="helper">
          {only ? `${only.label} — ${only.hint}.` : "Organization — visible to every member."}
        </span>
      </div>
    );
  }

  return (
    <div className="field">
      <span className="lab">Owner</span>
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        {choices.map((c) => (
          <label key={c.value} className="check">
            <input
              type="radio"
              name={groupName}
              checked={value === c.value}
              onChange={() => onChange(c.value)}
            />
            {c.label}
            <span className="faint" style={{ marginLeft: 4 }}>
              — {c.hint}
            </span>
          </label>
        ))}
      </div>
    </div>
  );
}
