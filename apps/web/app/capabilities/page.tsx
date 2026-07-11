"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  apiGet,
  apiPost,
  CapabilityBundle,
  CatalogConnectResult,
  CatalogEntry,
  Connection,
} from "../lib/api";
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
  const [catalog, setCatalog] = useState<CatalogEntry[]>([]);
  const [showNew, setShowNew] = useState(false);
  const [connecting, setConnecting] = useState<CatalogEntry | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await apiGet<{ bundles: CapabilityBundle[] }>("/capabilities");
      setBundles(r.bundles);
    } catch {
      /* offline handled by rail */
    }
    try {
      const c = await apiGet<{ connectors: CatalogEntry[] }>("/catalog");
      setCatalog(c.connectors);
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

      {catalog.length > 0 && (
        <div className="panel" style={{ marginBottom: 16 }}>
          <div className="eyebrow" style={{ marginTop: 0 }}>
            add from catalog
          </div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(230px, 1fr))",
              gap: 10,
            }}
          >
            {catalog.map((e) => (
              <button
                key={e.slug}
                onClick={() => setConnecting(e)}
                style={{
                  textAlign: "left",
                  background: "transparent",
                  border: "1px solid var(--line)",
                  borderRadius: 8,
                  padding: "10px 12px",
                  cursor: "pointer",
                  color: "inherit",
                  font: "inherit",
                }}
              >
                <div className="spread" style={{ alignItems: "baseline" }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 14 }}>
                    {e.icon ? `${e.icon} ` : ""}
                    {e.name}
                  </span>
                  <span
                    className={`autopill ${e.tier === "verified" ? "supervised" : "autonomous"}`}
                  >
                    {e.tier}
                  </span>
                </div>
                <div className="mut" style={{ fontSize: 11.5, marginTop: 4, minHeight: 30 }}>
                  {e.description || ""}
                </div>
                <div className="mut mono" style={{ fontSize: 10.5, marginTop: 6 }}>
                  {e.auth_mode === "none"
                    ? "no credential"
                    : e.auth_mode === "api_key"
                      ? "api key"
                      : "oauth"}
                  {e.categories.length > 0 ? ` · ${e.categories.join(", ")}` : ""}
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

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
      {connecting && (
        <ConnectCatalog
          entry={connecting}
          onClose={() => {
            setConnecting(null);
            load();
          }}
        />
      )}
    </>
  );
}

function ConnectCatalog({ entry, onClose }: { entry: CatalogEntry; onClose: () => void }) {
  const [token, setToken] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState("");
  const [waiting, setWaiting] = useState(false);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    return () => {
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, []);

  const submit = async () => {
    setErr("");
    if (entry.auth_mode === "api_key" && !token.trim()) {
      setErr(
        entry.auth_hints.composite
          ? `paste the credential as ${entry.auth_hints.composite}`
          : "a token is required"
      );
      return;
    }
    setBusy(true);
    try {
      const r = await apiPost<CatalogConnectResult>(`/catalog/${entry.slug}/connect`, {
        token: token.trim() || null,
        display_name: displayName.trim() || null,
        client_id: clientId.trim() || null,
        client_secret: clientSecret.trim() || null,
      });
      if (entry.auth_mode !== "oauth") {
        setDone(
          r.bundle
            ? `bundle ${r.bundle.name}@${r.bundle.version} registered — attach it on an agent revision`
            : "connected"
        );
        setBusy(false);
        return;
      }
      // OAuth: hand the browser to the authorization server, then watch the
      // connection flip active (the callback photographs the bundle).
      const connId = r.connection?.id;
      if (r.authorize_url) window.open(r.authorize_url, "_blank", "noopener");
      setWaiting(true);
      setBusy(false);
      pollTimer.current = setInterval(async () => {
        try {
          const list = await apiGet<{ connections: Connection[] }>("/connections");
          const c = list.connections.find((x) => x.id === connId);
          if (c?.status === "active") {
            if (pollTimer.current) clearInterval(pollTimer.current);
            setWaiting(false);
            setDone("connected — the bundle was registered with the fresh credential");
          }
        } catch {
          /* keep polling */
        }
      }, 2000);
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
              connect from catalog · {entry.tier}
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 15, marginTop: 4 }}>
              {entry.icon ? `${entry.icon} ` : ""}
              {entry.name}
            </div>
          </div>
          <button className="btn ghost sm" onClick={onClose}>
            esc
          </button>
        </div>
        <div className="mb">
          <p className="mut" style={{ fontSize: 12.5, marginTop: 0 }}>
            {entry.description}
            {entry.egress.length > 0 && (
              <span className="mono" style={{ display: "block", fontSize: 11, marginTop: 4 }}>
                egress: {entry.egress.join(", ")}
              </span>
            )}
          </p>
          {entry.tool_hints.length > 0 && (
            <p className="mut" style={{ fontSize: 11.5 }}>
              Suggested policy seeds (untrusted hints — your policy stays the judge):{" "}
              {entry.tool_hints.map((h) => `${h.pattern} → ${h.action}`).join(" · ")}
            </p>
          )}
          {done ? (
            <>
              <div className="empty" style={{ padding: "18px 0" }}>
                ✓ {done}
              </div>
              <div className="spread">
                <span />
                <button className="btn primary" onClick={onClose}>
                  Done
                </button>
              </div>
            </>
          ) : waiting ? (
            <div className="empty" style={{ padding: "18px 0" }}>
              waiting for authorization in the opened tab…
            </div>
          ) : (
            <>
              {entry.auth_mode === "api_key" && (
                <label className="field">
                  <span className="lab">
                    {entry.auth_hints.composite
                      ? `Credential (${entry.auth_hints.composite})`
                      : "API key"}
                    {entry.auth_hints.key_url ? ` — from ${entry.auth_hints.key_url}` : ""}
                  </span>
                  <input
                    className="inp mono"
                    type="password"
                    placeholder={entry.auth_hints.placeholder || ""}
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                  />
                </label>
              )}
              {entry.auth_mode === "oauth" && (
                <>
                  <p className="mut" style={{ fontSize: 12.5 }}>
                    Connecting opens the provider&apos;s consent page once. fluidbox then
                    custodies a rotating refresh token (sealed at rest) and mints short-lived
                    access tokens at call time — nothing ever enters a sandbox.
                  </p>
                  <label className="field">
                    <span className="lab">Pre-registered client id (optional)</span>
                    <input
                      className="inp mono"
                      value={clientId}
                      onChange={(e) => setClientId(e.target.value)}
                      placeholder="leave empty to use CIMD/DCR"
                    />
                  </label>
                  <label className="field">
                    <span className="lab">Client secret (optional, confidential clients)</span>
                    <input
                      className="inp mono"
                      type="password"
                      value={clientSecret}
                      onChange={(e) => setClientSecret(e.target.value)}
                    />
                  </label>
                </>
              )}
              <label className="field">
                <span className="lab">Display name (optional)</span>
                <input
                  className="inp"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                />
              </label>
              {err && <div className="err">{err}</div>}
              <div className="spread" style={{ marginTop: 16 }}>
                <span className="mut" style={{ fontSize: 12 }}>
                  {entry.auth_mode === "none"
                    ? "registers the bundle immediately (photograph now)"
                    : entry.auth_mode === "api_key"
                      ? "the key is sealed at rest and proven by the photograph"
                      : "you will be redirected to authorize once"}
                </span>
                <button className="btn primary" onClick={submit} disabled={busy}>
                  {busy ? "connecting…" : "Connect"}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
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
