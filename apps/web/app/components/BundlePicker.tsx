"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, BundleRef, CapabilityBundle } from "../lib/api";

/** Multi-select over the capability-bundle registry, rendered as pin cards.
 *  Selection is EXPLICIT pins (name@version — §17 #7 made visible): a bundle
 *  already pinned keeps its version unless deliberately changed; newly
 *  checked names default to the latest version. Nothing floats. */
export function BundlePicker({
  pins,
  onChange,
  refreshKey = 0,
  onAddServer,
}: {
  pins: BundleRef[];
  onChange: (pins: BundleRef[]) => void;
  refreshKey?: number;
  onAddServer?: () => void;
}) {
  const [registry, setRegistry] = useState<CapabilityBundle[]>([]);
  useEffect(() => {
    apiGet<{ bundles: CapabilityBundle[] }>("/capabilities")
      .then((r) => setRegistry(r.bundles))
      .catch(() => {
        /* offline handled by sidebar */
      });
  }, [refreshKey]);

  // The list is (name, version desc) ordered — group to versions per name.
  const byName = new Map<string, CapabilityBundle[]>();
  for (const b of registry) {
    const l = byName.get(b.name) || [];
    l.push(b);
    byName.set(b.name, l);
  }
  const names = [...byName.keys()];
  const pinOf = (name: string) => pins.find((p) => p.name === name);

  const toggle = (name: string) => {
    const cur = pinOf(name);
    if (cur) {
      onChange(pins.filter((p) => p.name !== name));
    } else {
      const latest = byName.get(name)![0];
      onChange([...pins, { id: latest.id, name, version: latest.version }]);
    }
  };
  const setVersion = (name: string, version: number) => {
    const row = byName.get(name)!.find((b) => b.version === version);
    if (!row) return;
    onChange(pins.map((p) => (p.name === name ? { id: row.id, name, version } : p)));
  };

  if (names.length === 0) {
    return (
      <div className="field">
        <span className="lab">Capability bundles</span>
        <span className="helper">
          None registered yet. Connect an MCP server to photograph its tools into a versioned bundle.
        </span>
        {onAddServer ? (
          <button className="btn" type="button" onClick={onAddServer}>Connect an MCP server</button>
        ) : (
          <Link href="/capabilities" className="btn">Open capabilities</Link>
        )}
      </div>
    );
  }
  return (
    <div className="field">
      <div className="bundle-picker-head">
        <span className="lab">Capability bundles — exact version pins</span>
        {onAddServer && (
          <button className="btn ghost sm" type="button" onClick={onAddServer}>Connect new MCP</button>
        )}
      </div>
      <div style={{ display: "grid", gap: 6, maxHeight: 340, overflowY: "auto", paddingRight: 2 }}>
        {names.map((name) => {
          const versions = byName.get(name)!;
          const latest = versions[0];
          const pin = pinOf(name);
          const shown = pin
            ? (versions.find((v) => v.version === pin.version) ?? latest)
            : latest;
          return (
            <label key={name} className={`cap-row ${pin ? "on" : ""}`}>
              <input type="checkbox" checked={!!pin} onChange={() => toggle(name)} />
              <span className="nm">{name}</span>
              {pin ? (
                <select
                  className="inp"
                  value={pin.version}
                  onClick={(e) => e.stopPropagation()}
                  onChange={(e) => setVersion(name, Number(e.target.value))}
                >
                  {versions.map((v) => (
                    <option key={v.version} value={v.version}>
                      @{v.version}
                      {v.version === latest.version ? " (latest)" : ""}
                    </option>
                  ))}
                </select>
              ) : (
                <span className="faint" style={{ fontSize: 11.5 }}>
                  latest @{latest.version}
                </span>
              )}
              <span className="meta">
                {shown.tool_count} tool{shown.tool_count === 1 ? "" : "s"}
                {[...new Set(shown.classes)].map((c) => (
                  <span key={c} className={`badge ${c === "brokered" ? "brand" : ""}`}>
                    {c}
                  </span>
                ))}
              </span>
            </label>
          );
        })}
      </div>
    </div>
  );
}
