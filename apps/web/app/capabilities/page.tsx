"use client";

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, CapabilityBundle } from "../lib/api";
import { PageHead } from "../components/bits";

const EXAMPLE = `[
  {
    "class": "sandbox",
    "name": "ws",
    "command": "node",
    "args": ["/opt/fluidbox-runner/servers/workspace-info.mjs"],
    "tools": [
      { "name": "workspace_file_count", "description": "Count files in the workspace",
        "input_schema": { "type": "object", "properties": {} } },
      { "name": "workspace_grep_count", "description": "Count lines containing a pattern",
        "input_schema": { "type": "object", "properties": { "pattern": { "type": "string" } },
                          "required": ["pattern"] } }
    ]
  },
  {
    "class": "brokered",
    "name": "kb",
    "url": "https://mcp.example.com/mcp",
    "connection_id": "<mcp_http connection id, omit if the server needs no credential>"
  }
]`;

export default function Capabilities() {
  const [bundles, setBundles] = useState<CapabilityBundle[]>([]);
  const [showNew, setShowNew] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await apiGet<{ bundles: CapabilityBundle[] }>("/capabilities");
      setBundles(r.bundles);
    } catch {
      /* offline handled by rail */
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <>
      <PageHead
        eyebrow="registry"
        title="Capabilities"
        sub="Versioned bundles of MCP servers agents may attach. Registration photographs each server's tool schemas (brokered: discovered; sandbox: declared) — runs freeze that snapshot, and the permission gate judges every call. Attach ≠ allow."
        right={
          <button className="btn primary" onClick={() => setShowNew(true)}>
            + Register bundle
          </button>
        }
      />

      <div className="panel">
        {bundles.length === 0 ? (
          <div className="empty">
            no capability bundles — register one, then attach it on an agent revision
          </div>
        ) : (
          <div className="rows">
            {bundles.map((b) => (
              <div
                key={b.id}
                className="row"
                style={{ gridTemplateColumns: "220px 1fr auto", alignItems: "center" }}
              >
                <span className="mono" style={{ color: "var(--accent)" }}>
                  {b.name}@{b.version}
                </span>
                <span className="task">
                  {b.description || "—"}
                  <span className="mut" style={{ marginLeft: 8, fontSize: 12 }}>
                    {b.server_count} server{b.server_count === 1 ? "" : "s"} · {b.tool_count} tool
                    {b.tool_count === 1 ? "" : "s"}
                  </span>
                  <span
                    className="mut mono"
                    style={{ display: "block", fontSize: 11, marginTop: 2 }}
                  >
                    {b.definition_digest.slice(0, 24)}…
                  </span>
                </span>
                <span className="chips">
                  {[...new Set(b.classes)].map((c) => (
                    <span
                      key={c}
                      className={`autopill ${c === "sandbox" ? "supervised" : "autonomous"}`}
                    >
                      {c}
                    </span>
                  ))}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {showNew && (
        <NewBundle
          onClose={() => setShowNew(false)}
          onCreated={() => {
            setShowNew(false);
            load();
          }}
        />
      )}
    </>
  );
}

function NewBundle({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [servers, setServers] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async () => {
    setErr("");
    if (!name.trim()) {
      setErr("name is required");
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(servers);
    } catch (e) {
      setErr(`servers is not valid JSON: ${String(e)}`);
      return;
    }
    setBusy(true);
    try {
      await apiPost("/capabilities", {
        name: name.trim(),
        description: description.trim() || null,
        servers: parsed,
      });
      onCreated();
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  return (
    <div className="overlay" onClick={onClose}>
      <div className="panel modal" onClick={(e) => e.stopPropagation()}>
        <div className="mh">
          <div>
            <div className="eyebrow" style={{ margin: 0 }}>
              register bundle version
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 15, marginTop: 4 }}>
              append-only, like agent revisions
            </div>
          </div>
          <button className="btn ghost sm" onClick={onClose}>
            esc
          </button>
        </div>
        <div className="mb">
          <p className="mut" style={{ fontSize: 12.5, marginTop: 0 }}>
            Registering an existing name appends the next version; pinned attachments keep the old
            one (§17 #7). Brokered servers are contacted NOW to photograph their tools — declare
            tools only for sandbox servers. Credentials come from mcp_http connections; they are
            never stored here and never enter a sandbox.
          </p>
          <label className="field">
            <span className="lab">Name</span>
            <input
              className="inp mono"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="kb-tools"
            />
          </label>
          <label className="field">
            <span className="lab">Description (optional)</span>
            <input
              className="inp"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </label>
          <label className="field">
            <span className="lab">Servers (JSON array)</span>
            <textarea
              className="inp mono"
              style={{ minHeight: 180, fontSize: 11.5 }}
              value={servers}
              onChange={(e) => setServers(e.target.value)}
              placeholder={EXAMPLE}
            />
          </label>
          {err && <div className="err">{err}</div>}
          <div className="spread" style={{ marginTop: 16 }}>
            <span className="mut" style={{ fontSize: 12 }}>
              brokered servers are discovered &amp; validated before storage
            </span>
            <button className="btn primary" onClick={submit} disabled={busy}>
              {busy ? "photographing…" : "Register"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
