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

interface Row {
  key: string;
  slot: string;
  connectorUrl: string;
  connectorSlug: string | null;
  custom: boolean;
  tools: string[];
  toolDraft: string;
  bindingMode: BindingMode;
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
      },
    ]);
  const removeRow = (key: string) => update(rows.filter((r) => r.key !== key));

  const pickConnector = (row: Row, selectValue: string) => {
    if (selectValue === CUSTOM) {
      patch(row.key, { custom: true, connectorSlug: null });
      return;
    }
    const entry = catalog.find((e) => e.slug === selectValue);
    if (!entry || !entry.url) return;
    patch(row.key, { custom: false, connectorSlug: entry.slug, connectorUrl: entry.url });
  };

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
        <span className="lab">Connection requirements — brokered tools</span>
        <button className="btn ghost sm" type="button" onClick={addRow}>
          Add requirement
        </button>
      </div>
      {lookupError && (
        <span className="helper" role="status">
          Connector suggestions are unavailable. Existing values and custom URL/tool entry still work.
        </span>
      )}
      {rows.length === 0 ? (
        <span className="helper">
          None. Declare a brokered MCP server the agent must be bound to at run time — a
          connection is chosen per run (yours or the organization&apos;s), never frozen here.
        </span>
      ) : (
        <div className="opt-list">
          {rows.map((row) => {
            const suggestions = suggestionsFor(row);
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
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <input
                    className="inp mono"
                    style={{ maxWidth: 160 }}
                    placeholder="slot (e.g. issues)"
                    value={row.slot}
                    onChange={(e) => patch(row.key, { slot: e.target.value })}
                    aria-label="Requirement slot"
                  />
                  <select
                    className="inp"
                    value={row.custom ? CUSTOM : (row.connectorSlug ?? CUSTOM)}
                    onChange={(e) => pickConnector(row, e.target.value)}
                    aria-label="Connector"
                  >
                    <option value={CUSTOM}>Custom URL…</option>
                    {catalog.map((e) => (
                      <option key={e.slug} value={e.slug}>
                        {e.name}
                      </option>
                    ))}
                  </select>
                  <select
                    className="inp"
                    style={{ maxWidth: 150 }}
                    value={row.bindingMode}
                    onChange={(e) =>
                      patch(row.key, { bindingMode: e.target.value as BindingMode })
                    }
                    aria-label="Binding mode"
                  >
                    <option value="invoking_user">Invoking user</option>
                    <option value="organization">Organization</option>
                  </select>
                  <button
                    className="btn ghost sm danger"
                    type="button"
                    onClick={() => removeRow(row.key)}
                    aria-label="Remove requirement"
                  >
                    Remove
                  </button>
                </div>
                {row.custom && (
                  <input
                    className="inp mono"
                    placeholder="https://mcp.example.com/mcp"
                    value={row.connectorUrl}
                    onChange={(e) => patch(row.key, { connectorUrl: e.target.value })}
                    aria-label="Connector URL"
                  />
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
                        no required tools yet
                      </span>
                    )}
                  </div>
                  <input
                    className="inp mono"
                    placeholder="required tool, press Enter or comma"
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
