"use client";

// The agent-revision editor for brokered connection requirements (Phase C,
// design :349-389). An agent declares WHAT it needs per slot — a connector
// (from the catalog or a custom URL), the required tools, and a binding mode
// (whose credential) — never a concrete connection. Presentation only: it emits
// the `connection_requirements` array; the server validates and resolves it.
//
// Mirrors BundlePicker's shape (registry fetch → rows → typed refs out); the
// tool field offers names from an accessible matching connection's snapshot when
// one exists, and free text otherwise.

import { useEffect, useRef, useState } from "react";
import {
  apiGetCached,
  BindingMode,
  CatalogEntry,
  Connection,
  ConnectionRequirement,
  ConnectionToolSnapshot,
  connectionMatchesConnector,
  fetchConnectionTools,
} from "../lib/api";
import { ConnectorCard, connectorAttention, connectorConnected } from "./ConnectorCard";

interface Row {
  key: string;
  slot: string;
  connectorUrl: string;
  connectorSlug: string | null;
  custom: boolean;
  tools: string[];
  toolDraft: string;
  bindingMode: BindingMode;
  /** UI-only: show the connector card grid for this row. A new row opens in
   *  the picker; a seeded row shows its chosen connector until "Change". */
  picking: boolean;
}

let keySeq = 0;
const newKey = () => `req-${keySeq++}`;

const CUSTOM = "__custom__";

function seedRows(value: ConnectionRequirement[]): Row[] {
  return value.map((r) => ({
    key: newKey(),
    slot: r.slot,
    connectorUrl: r.connector.url,
    connectorSlug: r.connector.slug ?? null,
    custom: !r.connector.slug,
    tools: [...r.required_tools],
    toolDraft: "",
    bindingMode: r.binding_mode,
    picking: false,
  }));
}

/** Internal rows → the wire array. Drops a fully-blank row (added but never
 *  filled) so it can't fail submit; partially-filled rows are sent as-is and
 *  the server's 422 (rendered verbatim) guides the fix. */
function toRequirements(rows: Row[]): ConnectionRequirement[] {
  return rows
    .filter((r) => r.slot.trim() || r.connectorUrl.trim() || r.tools.length > 0)
    .map((r) => ({
      slot: r.slot.trim(),
      connector: r.connectorSlug
        ? { url: r.connectorUrl.trim(), slug: r.connectorSlug }
        : { url: r.connectorUrl.trim() },
      required_tools: r.tools,
      binding_mode: r.bindingMode,
    }));
}

export function RequirementsEditor({
  value,
  onChange,
}: {
  value: ConnectionRequirement[];
  onChange: (reqs: ConnectionRequirement[]) => void;
}) {
  const [rows, setRows] = useState<Row[]>(() => seedRows(value));
  const [catalog, setCatalog] = useState<CatalogEntry[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [snapshots, setSnapshots] = useState<Record<string, ConnectionToolSnapshot | null>>({});
  const [lookupError, setLookupError] = useState(false);
  const fetching = useRef<Set<string>>(new Set());

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setRows((current) =>
        JSON.stringify(toRequirements(current)) === JSON.stringify(value)
          ? current
          : seedRows(value)
      );
    }, 0);
    return () => window.clearTimeout(timer);
  }, [value]);

  useEffect(() => {
    let active = true;
    Promise.allSettled([
      apiGetCached<{ connectors: CatalogEntry[] }>("/catalog", { maxAgeMs: 5 * 60_000 }),
      apiGetCached<{ connections: Connection[] }>("/connections", { maxAgeMs: 10_000 }),
    ]).then(([catalogResult, connectionResult]) => {
      if (!active) return;
      if (catalogResult.status === "fulfilled") {
        setCatalog(catalogResult.value.connectors.filter((entry) => !!entry.url));
      }
      if (connectionResult.status === "fulfilled") {
        setConnections(connectionResult.value.connections);
      }
      setLookupError(
        catalogResult.status === "rejected" || connectionResult.status === "rejected"
      );
    });
    return () => {
      active = false;
    };
  }, []);

  const update = (next: Row[]) => {
    setRows(next);
    onChange(toRequirements(next));
  };
  const patch = (key: string, fields: Partial<Row>) =>
    update(rows.map((r) => (r.key === key ? { ...r, ...fields } : r)));

  const matchConn = (url: string): Connection | undefined =>
    url.trim() ? connections.find((c) => connectionMatchesConnector(c, url)) : undefined;

  // Photograph-backed tool suggestions: fetch the snapshot for any matched
  // connection once, so the tool field can offer real tool names.
  useEffect(() => {
    for (const row of rows) {
      const conn = matchConn(row.connectorUrl);
      if (conn && !(conn.id in snapshots) && !fetching.current.has(conn.id)) {
        fetching.current.add(conn.id);
        fetchConnectionTools(conn.id)
          .then((s) => setSnapshots((prev) => ({ ...prev, [conn.id]: s })))
          .catch(() => setSnapshots((prev) => ({ ...prev, [conn.id]: null })));
      }
    }
    // rows/connections drive which snapshots are needed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, connections]);

  const addRow = () =>
    update([
      ...rows,
      {
        key: newKey(),
        slot: "",
        connectorUrl: "",
        connectorSlug: null,
        custom: true,
        tools: [],
        toolDraft: "",
        bindingMode: "invoking_user",
        picking: true,
      },
    ]);
  const removeRow = (key: string) => update(rows.filter((r) => r.key !== key));

  const pickConnector = (row: Row, choice: CatalogEntry | typeof CUSTOM) => {
    if (choice === CUSTOM) {
      patch(row.key, { custom: true, connectorSlug: null, connectorUrl: "", picking: false });
      return;
    }
    if (!choice.url) return;
    patch(row.key, {
      custom: false,
      connectorSlug: choice.slug,
      connectorUrl: choice.url,
      picking: false,
      // A slot is just a stable name the RunSpec binds against. Defaulting it
      // to the connector's slug means the common case needs no typing at all;
      // it stays editable for an agent that needs two slots on one connector.
      slot: row.slot.trim() || choice.slug,
    });
  };

  /** Catalog entries usable AS a brokered requirement: a requirement is a URL
   *  the control plane dials, so an entry without one (stdio / in-image) can
   *  never satisfy a slot. Reference-only cards can never be connected either. */
  const pickable = catalog.filter((e) => !!e.url && e.connectable !== false);
  const ready = pickable.filter((e) => connectorConnected(e));
  const needsConnecting = pickable.filter((e) => !connectorConnected(e));

  const addTool = (row: Row, raw: string) => {
    const parts = raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (parts.length === 0) {
      patch(row.key, { toolDraft: "" });
      return;
    }
    const tools = [...row.tools];
    for (const p of parts) if (!tools.includes(p)) tools.push(p);
    patch(row.key, { tools, toolDraft: "" });
  };
  const removeTool = (row: Row, tool: string) =>
    patch(row.key, { tools: row.tools.filter((t) => t !== tool) });

  const suggestionsFor = (row: Row): string[] => {
    const conn = matchConn(row.connectorUrl);
    const snap = conn ? snapshots[conn.id] : null;
    if (!snap) return [];
    return snap.tools.map((t) => t.name).filter((n) => !row.tools.includes(n));
  };

  return (
    <div className="field">
      <div className="bundle-picker-head">
        <span className="lab">Apps this agent can use</span>
        <button className="btn ghost sm" type="button" onClick={addRow}>
          Add an app
        </button>
      </div>
      {lookupError && (
        <span className="helper" role="status">
          The app list is unavailable right now. You can still type an address and tool names by hand.
        </span>
      )}
      {rows.length === 0 ? (
        <span className="helper">
          None yet. Pick the apps this agent should be able to use — Notion, GitHub, Linear
          and more. You choose whose account it uses when it runs.
        </span>
      ) : (
        <div className="opt-list">
          {rows.map((row) => {
            const suggestions = suggestionsFor(row);
            const selectedEntry = row.connectorSlug
              ? catalog.find((e) => e.slug === row.connectorSlug)
              : undefined;
            return (
              <div
                key={row.key}
                style={{
                  display: "grid",
                  gap: 8,
                  padding: "10px 0",
                  borderBottom: "1px solid var(--border)",
                }}
              >
                {/*
                  CATALOGUE FIRST, FORM SECOND. The old row led with a bare
                  `slot` text box — jargon before you had chosen anything. You
                  now pick a connector from the same cards as the MCP Store,
                  and the mechanical fields appear underneath once that choice
                  is made.

                  The split into "Ready to use" / "Needs connecting" is the
                  load-bearing part: requirement satisfaction is
                  ALL-or-fail-closed at run start, so a connector nobody has
                  connected yields an agent that creates fine and can never
                  run. Sorting by connection state makes that legible at a
                  glance instead of one label per card.
                */}
                {row.picking ? (
                  <div className="mcp-catalogue">
                    {ready.length > 0 && (
                      <>
                        <div className="mcp-catalogue-head">
                          <span className="mcp-catalogue-title">Ready to use</span>
                          <span className="mcp-catalogue-count">{ready.length}</span>
                        </div>
                        <div className="connector-grid">
                          {ready.map((entry) => (
                            <ConnectorCard
                              key={entry.slug}
                              entry={entry}
                              selected={row.connectorSlug === entry.slug}
                              onClick={() => pickConnector(row, entry)}
                              action={<span className="state ok">● Connected</span>}
                            />
                          ))}
                        </div>
                      </>
                    )}

                    {needsConnecting.length > 0 && (
                      <>
                        <div className="mcp-catalogue-head">
                          <span className="mcp-catalogue-title">Needs connecting</span>
                          <span className="mcp-catalogue-count">{needsConnecting.length}</span>
                          <a
                            className="link mcp-catalogue-link"
                            href="/capabilities"
                            target="_blank"
                            rel="noreferrer"
                          >
                            Set one up ↗
                          </a>
                        </div>
                        <p className="mcp-catalogue-note">
                          You can pick these now, but the agent will not be able to start until
                          the app is set up with an account.
                        </p>
                        <div className="connector-grid">
                          {needsConnecting.map((entry) => (
                            <ConnectorCard
                              key={entry.slug}
                              entry={entry}
                              selected={row.connectorSlug === entry.slug}
                              onClick={() => pickConnector(row, entry)}
                              action={
                                connectorAttention(entry) ? (
                                  <span className="state err">{connectorAttention(entry)}</span>
                                ) : (
                                  <span className="state mcp-state-muted">Not connected</span>
                                )
                              }
                            />
                          ))}
                        </div>
                      </>
                    )}

                    <div className="mcp-catalogue-head">
                      <span className="mcp-catalogue-title">Something else</span>
                    </div>
                    <div className="connector-grid">
                      <button
                        className={`connector-card${row.custom && !row.connectorSlug ? " selected" : ""}`}
                        type="button"
                        onClick={() => pickConnector(row, CUSTOM)}
                      >
                        <span className="connector-mark connector-mark-custom" aria-hidden="true">
                          <span>+</span>
                        </span>
                        <span className="connector-card-copy">
                          <span className="connector-card-title">
                            <span className="nm">Custom URL</span>
                          </span>
                          <span className="desc">
                            An app that is not in the list above.
                          </span>
                          <span className="connector-card-meta">Streamable HTTP</span>
                        </span>
                        <span className="connector-card-action">
                          <span className="state">Enter URL</span>
                        </span>
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    {selectedEntry && (
                      <ConnectorCard
                        entry={selectedEntry}
                        selected
                        onClick={() => patch(row.key, { picking: true })}
                        action={<span className="state">Change</span>}
                        meta={
                          connectorConnected(selectedEntry) ? (
                            <span className="mcp-state-ok">● Ready to use</span>
                          ) : (
                            <span className="mcp-state-warn">
                              Not set up yet —{" "}
                              <a
                                className="link"
                                href="/capabilities"
                                target="_blank"
                                rel="noreferrer"
                              >
                                set it up
                              </a>{" "}
                              or this agent will not start
                            </span>
                          )
                        }
                      />
                    )}
                    {row.custom && (
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <input
                          className="inp mono"
                          placeholder="https://mcp.example.com/mcp"
                          value={row.connectorUrl}
                          onChange={(e) => patch(row.key, { connectorUrl: e.target.value })}
                          aria-label="Connector URL"
                        />
                        <button
                          className="btn ghost sm"
                          type="button"
                          onClick={() => patch(row.key, { picking: true })}
                        >
                          Browse apps
                        </button>
                      </div>
                    )}
                    {/* The mechanical fields: secondary to the choice above. */}
                    <div className="mcp-req-detail">
                      <label className="mcp-req-field">
                        <span className="mcp-req-lab">Label</span>
                        <input
                          className="inp mono"
                          placeholder="e.g. notion"
                          value={row.slot}
                          onChange={(e) => patch(row.key, { slot: e.target.value })}
                          aria-label="Label"
                        />
                      </label>
                      <label className="mcp-req-field">
                        <span className="mcp-req-lab">Whose account</span>
                        <select
                          className="inp"
                          value={row.bindingMode}
                          onChange={(e) =>
                            patch(row.key, { bindingMode: e.target.value as BindingMode })
                          }
                          aria-label="Whose account"
                        >
                          <option value="invoking_user">The person running it</option>
                          <option value="organization">The organisation</option>
                        </select>
                      </label>
                      <button
                        className="btn ghost sm danger"
                        type="button"
                        onClick={() => removeRow(row.key)}
                        aria-label="Remove requirement"
                      >
                        Remove
                      </button>
                    </div>
                  </>
                )}
                <div>
                  <div className="chips" style={{ marginBottom: 4 }}>
                    {row.tools.map((t) => (
                      <span key={t} className="chip">
                        {t}
                        <button
                          type="button"
                          className="chip-x"
                          onClick={() => removeTool(row, t)}
                          aria-label={`Remove ${t}`}
                          style={{
                            marginLeft: 4,
                            background: "none",
                            border: 0,
                            color: "inherit",
                            cursor: "pointer",
                          }}
                        >
                          ×
                        </button>
                      </span>
                    ))}
                    {row.tools.length === 0 && (
                      <span className="faint" style={{ fontSize: 11.5 }}>
                        all tools allowed
                      </span>
                    )}
                  </div>
                  <input
                    className="inp mono"
                    placeholder="tool name, press Enter"
                    value={row.toolDraft}
                    onChange={(e) => patch(row.key, { toolDraft: e.target.value })}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === ",") {
                        e.preventDefault();
                        addTool(row, row.toolDraft);
                      }
                    }}
                    onBlur={() => row.toolDraft.trim() && addTool(row, row.toolDraft)}
                    aria-label="Add required tool"
                  />
                  {suggestions.length > 0 && (
                    <div className="chips" style={{ marginTop: 6 }}>
                      <span className="faint" style={{ fontSize: 11 }}>
                        from snapshot:
                      </span>
                      {suggestions.slice(0, 12).map((s) => (
                        <button
                          key={s}
                          type="button"
                          className="chip"
                          onClick={() => addTool(row, s)}
                          style={{ cursor: "pointer" }}
                        >
                          + {s}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
