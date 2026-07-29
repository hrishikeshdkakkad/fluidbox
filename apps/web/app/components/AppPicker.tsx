"use client";

// ONE app-store grid for everything an agent can use.
//
// The backend stores two different objects — in-sandbox tool bundles (pins,
// §17 #7) and brokered connection requirements (Phase C) — because they have
// different custody and security models. That split is the system's anatomy,
// not the user's mental model: a person composing an agent thinks "let it use
// Notion". So this picker shows one grid of app cards and routes each toggle
// to the right object internally:
//
//   · catalog entry with a photographed in-image bundle (auth "none")  → pin
//   · catalog entry with a dialable URL (Notion, Linear, …)            → requirement
//   · registry bundle with no catalog entry (BYO wizard results)       → pin
//   · legacy requirement rows with no catalog slug                     → visible + removable
//
// The full-control editors (BundlePicker / RequirementsEditor) still exist on
// the agent edit page; this is the composer's simple surface.

import { useEffect, useState } from "react";
import {
  apiGetCached,
  BindingMode,
  BundleRef,
  CapabilityBundle,
  CatalogEntry,
  ConnectionRequirement,
  ConnectionToolSnapshot,
  fetchConnectionTools,
} from "../lib/api";
import { ConnectorCard, ConnectorMark, connectorConnected } from "./ConnectorCard";
import { useAuthMe } from "../lib/useAuthMe";

export function AppPicker({
  pins,
  requirements,
  onPinsChange,
  onRequirementsChange,
  onAddServer,
  refreshKey = 0,
}: {
  pins: BundleRef[];
  requirements: ConnectionRequirement[];
  onPinsChange: (pins: BundleRef[]) => void;
  onRequirementsChange: (reqs: ConnectionRequirement[]) => void;
  onAddServer?: () => void;
  refreshKey?: number;
}) {
  const me = useAuthMe();
  const [catalog, setCatalog] = useState<CatalogEntry[]>([]);
  const [bundles, setBundles] = useState<CapabilityBundle[]>([]);
  const [addingSlug, setAddingSlug] = useState<string | null>(null);
  const [addErr, setAddErr] = useState("");
  const [snapCache, setSnapCache] = useState<Record<string, ConnectionToolSnapshot>>({});
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [retryKey, setRetryKey] = useState(0);

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.allSettled([
      apiGetCached<{ connectors: CatalogEntry[] }>("/catalog", {
        maxAgeMs: 5 * 60_000,
        force: refreshKey > 0 || retryKey > 0,
      }),
      apiGetCached<{ bundles: CapabilityBundle[] }>("/capabilities", {
        maxAgeMs: 30_000,
        force: refreshKey > 0 || retryKey > 0,
      }),
    ]).then(([cat, cap]) => {
      if (!active) return;
      if (cat.status === "fulfilled") setCatalog(cat.value.connectors);
      if (cap.status === "fulfilled") setBundles(cap.value.bundles);
      setLoadError(cat.status === "rejected" && cap.status === "rejected");
      setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [refreshKey, retryKey]);

  // ── routing predicates ────────────────────────────────────────────────
  const pinned = (name: string) => pins.some((p) => p.name === name);
  const required = (slug: string) => requirements.some((r) => r.connector.slug === slug);

  const togglePinByBundle = (b: { id: string; name: string; version: number }) => {
    if (pinned(b.name)) onPinsChange(pins.filter((p) => p.name !== b.name));
    else onPinsChange([...pins, { id: b.id, name: b.name, version: b.version }]);
  };

  const toggleRequirement = async (entry: CatalogEntry) => {
    if (required(entry.slug)) {
      onRequirementsChange(requirements.filter((r) => r.connector.slug !== entry.slug));
      return;
    }
    if (!entry.url || !entry.connection) return;
    // `required_tools` is not a filter — it IS the frozen tool surface a run
    // gets (bindings.rs: "EXACTLY the required subset"), and the server
    // refuses an empty list as dead config. So adding an app means declaring
    // its photographed tool list, the same thing the BYO wizard does. That is
    // also why an unconnected app cannot be added from here: no snapshot, no
    // tool names to declare — its card routes to the Store instead.
    setAddErr("");
    setAddingSlug(entry.slug);
    try {
      const snap = snapCache[entry.slug] ?? (await fetchConnectionTools(entry.connection.id));
      setSnapCache((prev) => ({ ...prev, [entry.slug]: snap }));
      const tools = snap.tools.map((t) => t.name);
      if (tools.length === 0) {
        setAddErr(
          `${entry.name}'s tool list is empty — refresh its tools under MCP, then try again.`
        );
        return;
      }
      onRequirementsChange([
        ...requirements,
        {
          // The slot is just a stable name the run binds against; the slug is
          // the obvious one and stays out of the user's way entirely.
          slot: entry.slug,
          connector: { url: entry.url, slug: entry.slug },
          required_tools: tools,
          // "The person running it" needs a signed-in user identity to resolve
          // (bindings.rs refuses it otherwise). In admin mode there is none —
          // the operator has no user_id — so the working default there is the
          // organisation's account. SSO deployments default to personal.
          binding_mode: me?.user_id ? "invoking_user" : "organization",
        },
      ]);
    } catch {
      setAddErr(`${entry.name}'s tools could not be loaded. Try again in a moment.`);
    } finally {
      setAddingSlug(null);
    }
  };

  const setBindingMode = (slot: string, mode: BindingMode) =>
    onRequirementsChange(
      requirements.map((r) => (r.slot === slot ? { ...r, binding_mode: mode } : r))
    );

  const removeRequirementRow = (slot: string) =>
    onRequirementsChange(requirements.filter((r) => r.slot !== slot));

  // ── card inventory ────────────────────────────────────────────────────
  // Catalog entries split by how attaching works. `rest_action` reference
  // cards (connectable === false, no bundle) are not usable and are skipped.
  const bundleEntries = catalog.filter((e) => e.auth_mode === "none" && e.bundle);
  const reqEntries = catalog.filter((e) => !!e.url && e.connectable !== false);

  // Registry bundles with no catalog card: BYO results and friends. Mirrors
  // BundlePicker's guard — zero-tool and legacy brokered-class bundles hide
  // unless already pinned (an attached one must stay visible to be removable).
  const catalogBundleNames = new Set(catalog.map((e) => e.bundle?.name).filter(Boolean));
  const latestByName = new Map<string, CapabilityBundle>();
  for (const b of bundles) if (!latestByName.has(b.name)) latestByName.set(b.name, b);
  const looseBundles = [...latestByName.values()].filter(
    (b) =>
      !catalogBundleNames.has(b.name) &&
      (((b.tool_count ?? 0) > 0 && !(b.classes ?? []).includes("brokered")) || pinned(b.name))
  );

  // Requirement rows this grid cannot express as a catalog card (custom URLs,
  // drafts from older flows): keep them visible and removable.
  const knownSlugs = new Set(reqEntries.map((e) => e.slug));
  const looseReqs = requirements.filter(
    (r) => !r.connector.slug || !knownSlugs.has(r.connector.slug)
  );

  // Ready-to-use first — the things a user can act on with zero extra steps.
  const orderedReqEntries = [
    ...reqEntries.filter((e) => connectorConnected(e)),
    ...reqEntries.filter((e) => !connectorConnected(e)),
  ];

  if (loading && catalog.length === 0 && bundles.length === 0) {
    return (
      <div className="field">
        <span className="lab">Apps &amp; tools</span>
        <span className="helper">Loading apps…</span>
      </div>
    );
  }

  if (loadError && catalog.length === 0 && bundles.length === 0) {
    return (
      <div className="field">
        <span className="lab">Apps &amp; tools</span>
        <div className="err" role="alert">The app list could not be loaded.</div>
        <button className="btn" type="button" onClick={() => setRetryKey((k) => k + 1)}>
          Try again
        </button>
      </div>
    );
  }

  const added = pins.length + requirements.length;

  return (
    <div className="field">
      <div className="bundle-picker-head">
        <span className="lab">Apps &amp; tools</span>
        {added > 0 && (
          <span className="helper" style={{ margin: 0 }}>
            {added} added
          </span>
        )}
      </div>
      {addErr && (
        <div className="err" role="alert">
          {addErr}
        </div>
      )}
      <div className="connector-grid app-picker-grid">
        {bundleEntries.map((entry) => {
          const on = pinned(entry.bundle!.name);
          return (
            <div className="app-card-wrap" key={`b-${entry.slug}`}>
              <ConnectorCard
                entry={entry}
                selected={on}
                onClick={() => togglePinByBundle(entry.bundle!)}
                meta="Ready to use"
                action={
                  on ? <span className="state ok">✓ Added</span> : <span className="state">Add</span>
                }
              />
            </div>
          );
        })}

        {orderedReqEntries.map((entry) => {
          const on = required(entry.slug);
          const ready = connectorConnected(entry);
          const req = requirements.find((r) => r.connector.slug === entry.slug);
          return (
            <div className={`app-card-wrap${on ? " has-sub" : ""}`} key={`r-${entry.slug}`}>
              <ConnectorCard
                entry={entry}
                selected={on}
                onClick={() => {
                  // Removing is always allowed; adding needs a connection
                  // (its snapshot supplies the tool names) — an unconnected
                  // card routes to the Store's Connect flow instead.
                  if (on || ready) void toggleRequirement(entry);
                  else window.open("/capabilities", "_blank", "noreferrer");
                }}
                meta={
                  ready ? (
                    <span className="mcp-state-ok">Ready to use</span>
                  ) : (
                    <span className="mcp-state-warn">Connect it first — takes about a minute</span>
                  )
                }
                action={
                  on ? (
                    <span className="state ok">✓ Added</span>
                  ) : addingSlug === entry.slug ? (
                    <span className="state">Adding…</span>
                  ) : ready ? (
                    <span className="state">Add</span>
                  ) : (
                    <span className="state">Set up ↗</span>
                  )
                }
              />
              {on && req && (
                <div className="app-card-sub">
                  <span>Uses the account of</span>
                  <select
                    className="inp"
                    value={req.binding_mode}
                    onChange={(e) => setBindingMode(req.slot, e.target.value as BindingMode)}
                    aria-label={`Whose ${entry.name} account`}
                  >
                    <option value="invoking_user">the person running it</option>
                    <option value="organization">the organisation</option>
                  </select>
                  {!ready && (
                    <span className="app-card-sub-warn">
                      Won&apos;t start until set up —{" "}
                      <a className="link" href="/capabilities" target="_blank" rel="noreferrer">
                        set it up ↗
                      </a>
                    </span>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {looseBundles.map((b) => {
          const on = pinned(b.name);
          const stale = (b.classes ?? []).includes("brokered");
          return (
            <div className="app-card-wrap" key={`lb-${b.name}`}>
              <button
                className={`connector-card${on ? " selected" : ""}`}
                type="button"
                onClick={() => togglePinByBundle(b)}
                aria-pressed={on}
              >
                <ConnectorMark
                  entry={{ slug: b.name, name: b.name } as unknown as CatalogEntry}
                />
                <span className="connector-card-copy">
                  <span className="connector-card-title">
                    <span className="nm">{b.name}</span>
                  </span>
                  <span className="desc">{b.description || "A tool server you added."}</span>
                  <span className="connector-card-meta">
                    {stale ? (
                      <span className="mcp-state-warn">Outdated — remove it</span>
                    ) : (
                      `${b.tool_count} tool${b.tool_count === 1 ? "" : "s"} · ready to use`
                    )}
                  </span>
                </span>
                <span className="connector-card-action">
                  {on ? <span className="state ok">✓ Added</span> : <span className="state">Add</span>}
                </span>
              </button>
            </div>
          );
        })}

        {looseReqs.map((r) => (
          <div className="app-card-wrap has-sub" key={`lr-${r.slot}`}>
            <button
              className="connector-card selected"
              type="button"
              onClick={() => removeRequirementRow(r.slot)}
              aria-pressed
            >
              <span className="connector-mark connector-mark-custom" aria-hidden="true">
                <span>{(r.connector.slug || r.slot || "C").slice(0, 1).toUpperCase()}</span>
              </span>
              <span className="connector-card-copy">
                <span className="connector-card-title">
                  <span className="nm">{r.connector.slug || r.slot || "Custom server"}</span>
                </span>
                <span className="desc">{r.connector.url || "No address set"}</span>
                <span className="connector-card-meta">Added by hand</span>
              </span>
              <span className="connector-card-action">
                <span className="state ok">✓ Added</span>
              </span>
            </button>
            <div className="app-card-sub">
              <span>Uses the account of</span>
              <select
                className="inp"
                value={r.binding_mode}
                onChange={(e) => setBindingMode(r.slot, e.target.value as BindingMode)}
                aria-label="Whose account"
              >
                <option value="invoking_user">the person running it</option>
                <option value="organization">the organisation</option>
              </select>
            </div>
          </div>
        ))}

        {onAddServer && (
          <div className="app-card-wrap">
            <button className="connector-card" type="button" onClick={onAddServer}>
              <span className="connector-mark connector-mark-custom" aria-hidden="true">
                <span>+</span>
              </span>
              <span className="connector-card-copy">
                <span className="connector-card-title">
                  <span className="nm">Add your own</span>
                </span>
                <span className="desc">Have a server address? Connect it and it appears here.</span>
                <span className="connector-card-meta">Takes about a minute</span>
              </span>
              <span className="connector-card-action">
                <span className="state">Add →</span>
              </span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
