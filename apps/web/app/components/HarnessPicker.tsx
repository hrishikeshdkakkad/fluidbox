"use client";

// Which agent brain runs inside the sandbox. Harnesses implement the same
// runner contract (canUseTool → /permission, events, heartbeats, /result),
// so governance is identical across them — only the brain changes. Offer
// exactly what the control plane can run today; announced ones render as
// disabled cards so the extension point is visible.

import { Check } from "lucide-react";

export const HARNESSES = [
  {
    id: "claude-agent-sdk",
    name: "Claude Agent SDK",
    hint: "Claude Code in the sandbox — live timeline, gated tools, approvals.",
    available: true,
  },
  {
    id: "codex",
    name: "Codex",
    hint: "OpenAI Codex on the same governed runner contract.",
    available: true,
  },
];

export function HarnessPicker({
  value,
  onChange,
}: {
  value: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="opt-grid">
      {HARNESSES.map((h) => (
        <button
          key={h.id}
          type="button"
          disabled={!h.available}
          className={`opt ${value === h.id ? "on" : ""} ${h.available ? "" : "off"}`}
          onClick={() => h.available && onChange(h.id)}
          title={h.available ? undefined : "Not available yet"}
        >
          <span className="t">
            {h.name}
            {value === h.id ? <Check /> : !h.available ? <span className="badge">soon</span> : null}
          </span>
          <div className="id">{h.id}</div>
          <div className="d">{h.hint}</div>
        </button>
      ))}
    </div>
  );
}
