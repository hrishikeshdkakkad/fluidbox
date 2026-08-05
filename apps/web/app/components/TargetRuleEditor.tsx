"use client";

// One row editor for TargetRule[], shared by the policy ceiling and the agent
// declaration — both edit the identical shape. Structure only: whether a
// target is REACHABLE is resolved server-side.

import { FqdnPattern, L4Protocol, TargetRule } from "../lib/api";
import { describeTarget } from "../lib/network";

export const EMPTY_TARGET: TargetRule = {
  kind: "dns",
  pattern: { kind: "wildcard", suffix: "" },
  ports: [{ from: 443, to: 443 }],
  protocol: "tcp",
};

function patternValue(p: FqdnPattern): string {
  return p.kind === "exact" ? p.name : p.suffix;
}

export function TargetRuleEditor({
  value,
  onChange,
  disabled = false,
}: {
  value: TargetRule[];
  onChange: (next: TargetRule[]) => void;
  disabled?: boolean;
}) {
  const patch = (i: number, next: TargetRule) =>
    onChange(value.map((t, n) => (n === i ? next : t)));
  const remove = (i: number) => onChange(value.filter((_, n) => n !== i));

  return (
    <div>
      {value.length === 0 && (
        <p className="helper">
          No targets. An <code>approved</code> ceiling with no targets grants nothing —
          which is what makes it inert until you add one.
        </p>
      )}

      {value.map((t, i) => {
        // This editor authors a single port range; a rule that arrived via the
        // API with several ranges is shown read-only so an edit cannot silently
        // discard the extra ranges (it would rewrite `ports` to just ports[0]).
        const multiRange = t.ports.length > 1;
        return (
        <div className="agent-creator-grid" key={i}>
          <label className="field">
            <span className="lab">Match</span>
            <select
              className="inp"
              disabled={disabled}
              value={t.kind === "cidr" ? "cidr" : t.pattern.kind}
              onChange={(e) => {
                const k = e.target.value;
                if (k === "cidr") patch(i, { kind: "cidr", cidr: "", ports: t.ports, protocol: t.protocol });
                else if (k === "exact")
                  patch(i, { kind: "dns", pattern: { kind: "exact", name: "" }, ports: t.ports, protocol: t.protocol });
                else
                  patch(i, { kind: "dns", pattern: { kind: "wildcard", suffix: "" }, ports: t.ports, protocol: t.protocol });
              }}
            >
              <option value="wildcard">Subdomains of…</option>
              <option value="exact">Exactly…</option>
              <option value="cidr">IP range (CIDR)</option>
            </select>
          </label>

          <label className="field">
            <span className="lab">{t.kind === "cidr" ? "CIDR" : "Host"}</span>
            <input
              className="inp mono"
              disabled={disabled}
              placeholder={t.kind === "cidr" ? "10.0.0.0/8" : "nvidia.com"}
              value={t.kind === "cidr" ? t.cidr : patternValue(t.pattern)}
              onChange={(e) => {
                const v = e.target.value.trim();
                if (t.kind === "cidr") patch(i, { ...t, cidr: v });
                else if (t.pattern.kind === "exact")
                  patch(i, { ...t, pattern: { kind: "exact", name: v } });
                else patch(i, { ...t, pattern: { kind: "wildcard", suffix: v } });
              }}
            />
          </label>

          <label className="field">
            <span className="lab">Protocol</span>
            <select
              className="inp"
              disabled={disabled}
              value={t.protocol}
              onChange={(e) => patch(i, { ...t, protocol: e.target.value as L4Protocol })}
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </label>

          <label className="field">
            <span className="lab">Ports (from)</span>
            <input
              className="inp"
              type="number"
              disabled={disabled || multiRange}
              value={t.ports[0]?.from ?? 443}
              onChange={(e) => {
                const from = Number(e.target.value);
                patch(i, { ...t, ports: [{ from, to: Math.max(from, t.ports[0]?.to ?? from) }] });
              }}
            />
          </label>

          <label className="field">
            <span className="lab">Ports (to)</span>
            <input
              className="inp"
              type="number"
              disabled={disabled || multiRange}
              value={t.ports[0]?.to ?? 443}
              onChange={(e) =>
                patch(i, { ...t, ports: [{ from: t.ports[0]?.from ?? 443, to: Number(e.target.value) }] })
              }
            />
          </label>

          {multiRange && (
            <p className="helper">Multiple port ranges — shown read-only; edit via the API.</p>
          )}

          <button type="button" className="btn ghost" disabled={disabled} onClick={() => remove(i)}>
            Remove
          </button>

          <p className="helper mono">{describeTarget(t)}</p>

          {t.kind === "dns" && t.pattern.kind === "wildcard" && (
            <p className="helper">
              A wildcard is <strong>one label</strong>: this matches{" "}
              <code>api.{t.pattern.suffix || "example.com"}</code> but NOT the bare{" "}
              <code>{t.pattern.suffix || "example.com"}</code> and NOT{" "}
              <code>a.b.{t.pattern.suffix || "example.com"}</code>. Add the apex as its own
              target if the agent needs it.
            </p>
          )}
        </div>
        );
      })}

      <button
        type="button"
        className="btn"
        disabled={disabled}
        onClick={() => onChange([...value, structuredClone(EMPTY_TARGET)])}
      >
        Add target
      </button>
    </div>
  );
}
