"use client";

// Which agent brain runs inside the sandbox. Harnesses implement the same
// runner contract (canUseTool → /permission, events, heartbeats, /result),
// so governance is identical across them — only the brain changes. The list
// (and each harness's models) comes from the control plane via GET /harnesses
// — the server is the single source of truth. Announced-but-unavailable
// harnesses render as disabled cards so the extension point stays visible.

import { HarnessInfo } from "../lib/api";

export function HarnessPicker({
  harnesses,
  value,
  onChange,
}: {
  harnesses: HarnessInfo[];
  value: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="opt-grid">
      {harnesses.map((h) => (
        <button
          key={h.id}
          type="button"
          disabled={!h.available}
          className={`opt ${value === h.id ? "on" : ""} ${h.available ? "" : "off"}`}
          onClick={() => h.available && onChange(h.id)}
          title={h.available ? undefined : "Not available yet"}
        >
          <span className="t">
            {h.display_name}
            {value === h.id ? (
              <span className="selected-label">Selected</span>
            ) : !h.available ? (
              <span className="badge">soon</span>
            ) : null}
          </span>
          <div className="id">{h.id}</div>
          <div className="d">{h.hint}</div>
        </button>
      ))}
    </div>
  );
}
