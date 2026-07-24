"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGetCached, BundleRef, CapabilityBundle } from "../lib/api";

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
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [retryKey, setRetryKey] = useState(0);
  useEffect(() => {
    let active = true;
    const timer = window.setTimeout(() => {
      setLoading(true);
      setLoadError("");
      apiGetCached<{ bundles: CapabilityBundle[] }>("/capabilities", {
        maxAgeMs: 30_000,
        force: refreshKey > 0 || retryKey > 0,
      })
        .then((r) => {
          if (active) setRegistry(r.bundles);
        })
        .catch((error) => {
          if (active) setLoadError(`Tool bundles could not be loaded. ${String(error)}`);
        })
        .finally(() => {
          if (active) setLoading(false);
        });
    }, 0);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [refreshKey, retryKey]);

  // The list is (name, version desc) ordered — group to versions per name.
  const byName = new Map<string, CapabilityBundle[]>();
  for (const b of registry) {
    const l = byName.get(b.name) || [];
    l.push(b);
    byName.set(b.name, l);
  }
  const names = [...byName.keys()];
  const pinOf = (name: string) => pins.find((p) => p.name === name);

  // A zero-tool bundle contributes nothing to a run, so attaching one is
  // always a mistake. They are almost always test residue: fluidbox-db's
  // tests mint `pmt-bundle-<uuid>` against REAL Neon (see CLAUDE.md), so a
  // dev database accumulates them. The cure is `just db-clean`; this is a
  // guard. A pinned bundle stays visible even at zero tools — hiding
  // something already attached would strand it.
  const hasTools = (name: string) => (byName.get(name)![0].tool_count ?? 0) > 0;

  // Phase C cutover: brokered servers no longer ride capability bundles — they
  // are connection requirements resolved into run_resource_bindings, and
  // `run_service::create_run` REFUSES any revision that still pins a brokered
  // bundle. Offering one here builds a revision that can never run, and
  // revisions are immutable, so the only escape is appending another one.
  // Hide them from selection; keep an already-pinned one visible and flagged so
  // a legacy revision is fixable rather than silently broken.
  const isBrokered = (name: string) =>
    (byName.get(name)![0].classes ?? []).includes("brokered");

  const attachable = (name: string) => (hasTools(name) && !isBrokered(name)) || !!pinOf(name);
  const shownNames = names.filter(attachable);
  const blockedPins = shownNames.filter((name) => isBrokered(name) && !!pinOf(name));
  const hiddenBrokered = names.filter((name) => isBrokered(name) && !pinOf(name)).length;
  const hiddenEmpty = names.filter(
    (name) => !hasTools(name) && !isBrokered(name) && !pinOf(name)
  ).length;

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

  if (loading && names.length === 0) {
    return (
      <div className="field">
        <span className="lab">Sandbox tool bundles</span>
        <span className="helper">Loading registered bundles…</span>
      </div>
    );
  }

  if (loadError && names.length === 0) {
    return (
      <div className="field">
        <span className="lab">Sandbox tool bundles</span>
        <div className="err" role="alert">{loadError}</div>
        <button className="btn" type="button" onClick={() => setRetryKey((current) => current + 1)}>
          Retry bundles
        </button>
      </div>
    );
  }

  if (names.length === 0) {
    return (
      <div className="field">
        <span className="lab">Sandbox tool bundles</span>
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
        <span className="lab">Sandbox tool bundles — exact version pins</span>
        {onAddServer && (
          <button className="btn ghost sm" type="button" onClick={onAddServer}>Connect new MCP</button>
        )}
      </div>
      {loadError && (
        <div className="err" role="alert">
          {loadError} Showing the last successful list.{" "}
          <button className="btn sm" type="button" onClick={() => setRetryKey((current) => current + 1)}>
            Retry
          </button>
        </div>
      )}
      <div className="opt-list">
        {shownNames.map((name) => {
          const versions = byName.get(name)!;
          const latest = versions[0];
          const pin = pinOf(name);
          const shown = pin
            ? (versions.find((v) => v.version === pin.version) ?? latest)
            : latest;
          const blocked = isBrokered(name) && !!pin;
          return (
            <label key={name} className={`cap-row ${pin ? "on" : ""} ${blocked ? "blocked" : ""}`}>
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
      {blockedPins.length > 0 && (
        <p className="err" style={{ margin: "8px 0 0" }}>
          {blockedPins.join(", ")} {blockedPins.length === 1 ? "is a brokered bundle" : "are brokered bundles"} and
          can no longer run. Uncheck {blockedPins.length === 1 ? "it" : "them"} and declare the server as a
          connection requirement instead — otherwise every run of this agent is refused.
        </p>
      )}
      {(hiddenEmpty > 0 || hiddenBrokered > 0) && (
        <p className="helper" style={{ margin: "6px 0 0" }}>
          {[
            hiddenEmpty > 0 ? `${hiddenEmpty} with no tools to attach` : null,
            hiddenBrokered > 0
              ? `${hiddenBrokered} brokered — connect those under Integrations and declare them as connection requirements`
              : null,
          ]
            .filter(Boolean)
            .join(" · ")}
        </p>
      )}
    </div>
  );
}
