"use client";

// Capabilities = tools agents can CALL during a run (design §8.3): sandbox
// stdio servers baked into the runner image, and brokered MCP servers the
// control plane calls with sealed credentials. Distinct from Integrations
// (platforms agents work ON — repos, events, publishing).

import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Check,
  ChevronDown,
  ChevronRight,
  KeyRound,
  Package,
  Plus,
  Puzzle,
  Search,
  ShieldCheck,
} from "lucide-react";
import {
  apiGet,
  apiPost,
  BundleDetail,
  CapabilityBundle,
  CatalogConnectResult,
  CatalogEntry,
  Connection,
} from "../lib/api";
import { LoadingRows, ModalShell, PageHead } from "../components/bits";
import { AddServerWizard } from "./AddServerWizard";

type Tab = "store" | "bundles" | "connections";

export default function CapabilitiesPage() {
  return (
    <Suspense fallback={null}>
      <Capabilities />
    </Suspense>
  );
}

function Capabilities() {
  const router = useRouter();
  const params = useSearchParams();
  const tab = ((params.get("tab") as Tab) || "store") as Tab;
  const setTab = (t: Tab) =>
    router.replace(t === "store" ? "/capabilities" : `/capabilities?tab=${t}`);

  const [catalog, setCatalog] = useState<CatalogEntry[]>([]);
  const [bundles, setBundles] = useState<CapabilityBundle[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [connecting, setConnecting] = useState<CatalogEntry | null>(null);
  const [showBundle, setShowBundle] = useState(false);
  const [showWizard, setShowWizard] = useState(false);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    const results = await Promise.allSettled([
      apiGet<{ connectors: CatalogEntry[] }>("/catalog"),
      apiGet<{ bundles: CapabilityBundle[] }>("/capabilities"),
      apiGet<{ connections: Connection[] }>("/connections"),
    ]);
    if (results[0].status === "fulfilled") setCatalog(results[0].value.connectors);
    if (results[1].status === "fulfilled") setBundles(results[1].value.bundles);
    if (results[2].status === "fulfilled") setConnections(results[2].value.connections);
    setLoading(false);
  }, []);

  useEffect(() => {
    const first = window.setTimeout(() => void load(), 0);
    // Returning from an OAuth consent tab should show the new state.
    window.addEventListener("focus", load);
    return () => {
      clearTimeout(first);
      window.removeEventListener("focus", load);
    };
  }, [load]);

  const act = async (fn: () => Promise<void>) => {
    setErr("");
    try {
      await fn();
      load();
    } catch (e) {
      setErr(String(e));
    }
  };

  const revoke = (id: string) => act(async () => void (await apiPost(`/connections/${id}/revoke`, {})));
  // Popup blockers void the gesture across an await — open synchronously.
  const reconnectOauth = (id: string) => {
    const tabRef = window.open("", "_blank");
    act(async () => {
      try {
        const r = await apiPost<{ authorize_url: string }>(`/connections/${id}/oauth/start`, {});
        if (tabRef) tabRef.location.href = r.authorize_url;
        else window.location.href = r.authorize_url;
      } catch (e) {
        tabRef?.close();
        throw e;
      }
    });
  };

  // Tool-server credentials only — git platform connections live on the
  // Integrations page.
  const toolConnections = connections.filter(
    (c) => c.provider === "mcp_http" && c.status !== "revoked"
  );

  return (
    <>
      <PageHead
        title="Capabilities"
        sub="Tools your agents can call during a run. Connect a service once — every call still passes the permission gate. Attach ≠ allow."
      />

      <div className="tabs">
        <button className={`tab ${tab === "store" ? "active" : ""}`} onClick={() => setTab("store")}>
          Store
        </button>
        <button className={`tab ${tab === "bundles" ? "active" : ""}`} onClick={() => setTab("bundles")}>
          Bundles
          <span className="n">{bundles.length}</span>
        </button>
        <button
          className={`tab ${tab === "connections" ? "active" : ""}`}
          onClick={() => setTab("connections")}
        >
          Connections
          <span className="n">{toolConnections.length}</span>
        </button>
      </div>

      {err && <div className="err" style={{ marginBottom: 10 }}>{err}</div>}

      {loading ? (
        <div className="panel"><LoadingRows /></div>
      ) : tab === "store" ? (
        <Store catalog={catalog} onOpen={setConnecting} onAddOwn={() => setShowWizard(true)} />
      ) : tab === "bundles" ? (
        <BundlesTab bundles={bundles} onRegister={() => setShowBundle(true)} />
      ) : (
        <ToolConnections
          connections={toolConnections}
          onRevoke={revoke}
          onReconnect={reconnectOauth}
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
      {showBundle && (
        <NewBundle
          onClose={() => setShowBundle(false)}
          onCreated={() => {
            setShowBundle(false);
            load();
          }}
        />
      )}
      {showWizard && (
        <AddServerWizard
          onClose={() => {
            setShowWizard(false);
            load();
          }}
        />
      )}
    </>
  );
}

/* ─── Store ──────────────────────────────────────────────────────────── */

function Store({
  catalog,
  onOpen,
  onAddOwn,
}: {
  catalog: CatalogEntry[];
  onOpen: (e: CatalogEntry) => void;
  onAddOwn: () => void;
}) {
  const [q, setQ] = useState("");
  const [cat, setCat] = useState<string | null>(null);

  const categories = [...new Set(catalog.flatMap((e) => e.categories))].sort();
  const shown = catalog.filter((e) => {
    if (cat && !e.categories.includes(cat)) return false;
    if (!q.trim()) return true;
    const hay = `${e.name} ${e.slug} ${e.description || ""} ${e.categories.join(" ")}`.toLowerCase();
    return hay.includes(q.trim().toLowerCase());
  });

  return (
    <>
      <div className="storebar">
        <div className="search">
          <Search />
          <input
            className="inp"
            placeholder="Search tools…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        {categories.length > 0 && (
          <div className="chipset">
            <button className={`fchip ${cat === null ? "on" : ""}`} onClick={() => setCat(null)}>
              All
            </button>
            {categories.map((c) => (
              <button
                key={c}
                className={`fchip ${cat === c ? "on" : ""}`}
                onClick={() => setCat(cat === c ? null : c)}
              >
                {c}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="store-grid">
        <AddOwnCard onClick={onAddOwn} />
        {shown.map((e) => (
          <StoreCard key={e.slug} entry={e} onOpen={() => onOpen(e)} />
        ))}
      </div>
      {shown.length === 0 && catalog.length > 0 && (
        <p className="helper" style={{ marginTop: 10 }}>No connectors match.</p>
      )}

      <p className="helper" style={{ marginTop: 14 }}>
        These are tools agents use <i>inside</i> a run. To run agents <i>on</i> a repository —
        clone a branch, react to pull requests, publish reviews — connect GitHub under{" "}
        <Link href="/integrations" className="link">
          Integrations
        </Link>
        .
      </p>
    </>
  );
}

function StoreCard({ entry, onOpen }: { entry: CatalogEntry; onOpen: () => void }) {
  const connected =
    entry.connection?.status === "active" || (entry.auth_mode === "none" && !!entry.bundle);
  const attention = !!entry.connection && entry.connection.status !== "active" && !connected;

  return (
    <button className="store-card" onClick={onOpen}>
      <div className="top">
        <span className="store-icon">{entry.icon || <Puzzle />}</span>
        <div style={{ minWidth: 0 }}>
          <div className="nm">{entry.name}</div>
          <div style={{ marginTop: 2 }}>
            {entry.tier === "verified" ? (
              <span className="badge brand">
                <ShieldCheck size={11} /> verified
              </span>
            ) : (
              <span className="badge">{entry.tier}</span>
            )}
          </div>
        </div>
      </div>
      <div className="desc">{entry.description || ""}</div>
      <div className="foot">
        <span>
          {entry.auth_mode === "none"
            ? "No credential"
            : entry.auth_mode === "api_key"
              ? "API key"
              : "OAuth"}
          {entry.bundle ? ` · v${entry.bundle.version}` : ""}
        </span>
        {connected ? (
          <span className="state ok">
            <Check /> Connected
          </span>
        ) : attention ? (
          <span className="state err">{entry.connection!.status}</span>
        ) : (
          <span className="state" style={{ color: "var(--ink)" }}>
            Connect
          </span>
        )}
      </div>
    </button>
  );
}

function AddOwnCard({ onClick }: { onClick: () => void }) {
  return (
    <button className="store-card" onClick={onClick} style={{ borderStyle: "dashed" }}>
      <div className="top">
        <span className="store-icon">
          <Plus />
        </span>
        <div style={{ minWidth: 0 }}>
          <div className="nm">Add your own server</div>
          <div style={{ marginTop: 2 }}>
            <span className="badge">bring your own MCP</span>
          </div>
        </div>
      </div>
      <div className="desc">
        Paste a URL — we detect the auth, preview the tools, and register it in one step.
      </div>
      <div className="foot">
        <span>Remote (HTTP) MCP</span>
        <span className="state" style={{ color: "var(--ink)" }}>
          Add
        </span>
      </div>
    </button>
  );
}

/* ─── Bundles ────────────────────────────────────────────────────────── */

// One bundle row, click to expand and lazily fetch its photographed tools
// (GET /capabilities/{id}) — the list endpoint stays light (counts only).
function BundleRow({ b }: { b: CapabilityBundle }) {
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState<BundleDetail | null>(null);
  const [loading, setLoading] = useState(false);

  const toggle = async () => {
    const next = !open;
    setOpen(next);
    if (next && !detail) {
      setLoading(true);
      try {
        setDetail(await apiGet<BundleDetail>(`/capabilities/${b.id}`));
      } catch {
        /* leave detail null; the row still shows counts */
      }
      setLoading(false);
    }
  };

  return (
    <>
      <div
        className="row"
        style={{ gridTemplateColumns: "200px 1fr 130px 110px", cursor: "pointer" }}
        onClick={toggle}
      >
        <span className="mono" style={{ fontSize: 12, color: "var(--accent)", display: "flex", alignItems: "center", gap: 4 }}>
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          {b.name}@{b.version}
        </span>
        <span className="task">
          {b.description || "—"}
          <span className="faint mono" style={{ display: "block", fontSize: 11, marginTop: 2 }}>
            {b.definition_digest.slice(0, 24)}…
          </span>
        </span>
        <span className="meta">
          {b.server_count} server{b.server_count === 1 ? "" : "s"} · {b.tool_count} tool
          {b.tool_count === 1 ? "" : "s"}
        </span>
        <span className="chips">
          {[...new Set(b.classes)].map((c) => (
            <span key={c} className={`badge ${c === "brokered" ? "brand" : ""}`}>
              {c}
            </span>
          ))}
        </span>
      </div>
      {open && (
        <div style={{ padding: "4px 12px 12px 22px" }}>
          {loading ? (
            <span className="faint" style={{ fontSize: 12 }}>Loading tools…</span>
          ) : detail && detail.servers.length > 0 ? (
            detail.servers.map((s) => (
              <div key={s.name} style={{ marginBottom: 8 }}>
                <span className="mono" style={{ fontSize: 12 }}>
                  {s.name}{" "}
                  <span className={`badge ${s.class === "brokered" ? "brand" : ""}`}>{s.class}</span>
                </span>
                {s.tools.length === 0 ? (
                  <div className="faint" style={{ fontSize: 12, marginTop: 2 }}>No tools.</div>
                ) : (
                  s.tools.map((t) => (
                    <div key={t.name} style={{ fontSize: 12, marginTop: 2 }}>
                      <span className="mono" style={{ color: "var(--accent)" }}>{t.name}</span>
                      {t.description ? <span className="faint"> — {t.description}</span> : null}
                    </div>
                  ))
                )}
              </div>
            ))
          ) : (
            <span className="faint" style={{ fontSize: 12 }}>No tool details.</span>
          )}
        </div>
      )}
    </>
  );
}

function BundlesTab({
  bundles,
  onRegister,
}: {
  bundles: CapabilityBundle[];
  onRegister: () => void;
}) {
  return (
    <>
      <div className="spread" style={{ marginBottom: 12 }}>
        <span className="helper" style={{ maxWidth: 620 }}>
          Bundles are versioned snapshots of a server&apos;s tools, photographed at
          registration. Runs freeze the exact pinned version — and attaching a bundle never
          bypasses the permission gate.
        </span>
        <button className="btn" onClick={onRegister}>
          <Plus /> Register bundle
        </button>
      </div>
      <div className="panel">
        {bundles.length === 0 ? (
          <div className="empty">
            <Package />
            <div>No bundles yet — connecting from the Store registers one automatically.</div>
          </div>
        ) : (
          <div className="rows">
            <div className="thead" style={{ gridTemplateColumns: "200px 1fr 130px 110px" }}>
              <span>Bundle</span>
              <span>Description</span>
              <span>Contents</span>
              <span>Classes</span>
            </div>
            {bundles.map((b) => (
              <BundleRow key={b.id} b={b} />
            ))}
          </div>
        )}
      </div>
    </>
  );
}

/* ─── Tool-server connections (mcp_http credentials) ─────────────────── */

function ToolConnections({
  connections,
  onRevoke,
  onReconnect,
}: {
  connections: Connection[];
  onRevoke: (id: string) => void;
  onReconnect: (id: string) => void;
}) {
  return (
    <>
      <div className="panel">
        {connections.length === 0 ? (
          <div className="empty">
            <KeyRound />
            <div>No tool credentials yet — connect something from the Store.</div>
          </div>
        ) : (
          <div className="rows">
            {connections.map((c) => (
              <div
                key={c.id}
                className="row"
                style={{ gridTemplateColumns: "1fr auto auto", alignItems: "center" }}
              >
                <span className="task">
                  {c.display_name}
                  <span className="chips" style={{ display: "inline-flex", marginLeft: 8, verticalAlign: "middle" }}>
                    {c.auth_kind === "oauth" ? (
                      <span className="chip">
                        oauth{c.oauth?.client_id_source ? ` · ${c.oauth.client_id_source}` : ""}
                      </span>
                    ) : (
                      <span className="chip">api key</span>
                    )}
                    {c.metadata?.header_name && <span className="chip">header {c.metadata.header_name}</span>}
                  </span>
                  {c.oauth?.scopes && c.oauth.scopes.length > 0 && (
                    <span className="faint" style={{ marginLeft: 8, fontSize: 12 }}>
                      scopes: {c.oauth.scopes.join(", ")}
                    </span>
                  )}
                  {c.metadata?.base_url && (
                    <span className="faint mono" style={{ display: "block", fontSize: 11.5, marginTop: 2 }}>
                      {c.metadata.base_url}
                    </span>
                  )}
                  {c.status === "error" && c.oauth?.error && (
                    <span className="err" style={{ display: "block", fontSize: 11.5, marginTop: 2 }}>
                      {c.oauth.error}
                    </span>
                  )}
                </span>
                {c.status === "active" ? (
                  <span className="badge ok">active</span>
                ) : c.status === "pending" ? (
                  <span className="badge warn">pending</span>
                ) : (
                  <span className="badge err">{c.status}</span>
                )}
                <span style={{ display: "flex", gap: 6 }}>
                  {c.status === "active" ? (
                    <button className="btn ghost sm danger" onClick={() => onRevoke(c.id)}>
                      Revoke
                    </button>
                  ) : c.auth_kind === "oauth" ? (
                    <button className="btn ghost sm" onClick={() => onReconnect(c.id)}>
                      Reconnect
                    </button>
                  ) : null}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
      <p className="helper" style={{ marginTop: 10 }}>
        Credentials for brokered tool servers. The control plane holds them sealed and makes
        the calls itself — a credential never enters a sandbox. Tokens are audience-bound to
        the server&apos;s base URL.
      </p>
    </>
  );
}

/* ─── Connect-from-catalog modal ─────────────────────────────────────── */

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

  const conn = entry.connection;
  const isConnected = conn?.status === "active" || (entry.auth_mode === "none" && !!entry.bundle);
  const needsReattention = !!conn && conn.status !== "active" && !isConnected;

  const watchUntilActive = (connId?: string) => {
    setWaiting(true);
    pollTimer.current = setInterval(async () => {
      try {
        const list = await apiGet<{ connections: Connection[] }>("/connections");
        const c = list.connections.find((x) => x.id === connId);
        if (c?.status === "active") {
          if (pollTimer.current) clearInterval(pollTimer.current);
          setWaiting(false);
          setDone("Connected — the bundle was registered with the fresh credential.");
        }
      } catch {
        /* keep polling */
      }
    }, 2000);
  };

  const disconnect = async () => {
    if (!conn) return;
    setErr("");
    setBusy(true);
    try {
      await apiPost(`/connections/${conn.id}/revoke`, {});
      setDone("Disconnected — the credential is revoked. Connect again any time.");
      setBusy(false);
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  const reconnect = async () => {
    if (!conn) return;
    setErr("");
    setBusy(true);
    try {
      const r = await apiPost<{ authorize_url: string }>(`/connections/${conn.id}/oauth/start`, {});
      window.open(r.authorize_url, "_blank", "noopener");
      setBusy(false);
      watchUntilActive(conn.id);
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  const submit = async () => {
    setErr("");
    if (entry.auth_mode === "api_key" && !token.trim()) {
      setErr(
        entry.auth_hints.composite
          ? `Paste the credential as ${entry.auth_hints.composite}.`
          : "A token is required."
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
            ? `Bundle ${r.bundle.name}@${r.bundle.version} registered — attach it on an agent revision.`
            : "Connected."
        );
        setBusy(false);
        return;
      }
      // OAuth: hand the browser to the authorization server, then watch the
      // connection flip active (the callback photographs the bundle).
      if (r.authorize_url) window.open(r.authorize_url, "_blank", "noopener");
      setBusy(false);
      watchUntilActive(r.connection?.id);
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  return (
    <ModalShell
      title={`${entry.icon ? `${entry.icon} ` : ""}${entry.name}`}
      sub={entry.tier === "verified" ? "Verified connector" : `${entry.tier} connector`}
      onClose={onClose}
    >
      <p className="note" style={{ marginTop: 0 }}>
        {entry.description}
        {entry.egress.length > 0 && (
          <span className="faint mono" style={{ display: "block", fontSize: 11, marginTop: 4 }}>
            egress: {entry.egress.join(", ")}
          </span>
        )}
      </p>
      {entry.tool_hints.length > 0 && (
        <p className="helper">
          Suggested policy seeds (hints only — your policy stays the judge):{" "}
          {entry.tool_hints.map((h) => `${h.pattern} → ${h.action}`).join(" · ")}
        </p>
      )}
      {done ? (
        <>
          <div className="empty" style={{ padding: "18px 0" }}>
            <Check />
            <div>{done}</div>
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
          Waiting for authorization in the opened tab…
        </div>
      ) : isConnected ? (
        <>
          <div className="empty" style={{ padding: "18px 0" }}>
            <Check />
            <div>
              Connected
              {entry.bundle
                ? ` — bundle ${entry.bundle.name}@${entry.bundle.version} is registered and attachable.`
                : " — no bundle registered yet (use Register bundle with this connection)."}
            </div>
          </div>
          {err && <div className="err">{err}</div>}
          <div className="spread" style={{ marginTop: 16 }}>
            <span className="helper">
              {entry.auth_mode === "none"
                ? "Registering again appends the next bundle version."
                : "Disconnecting revokes the credential; frozen runs keep their snapshots."}
            </span>
            {entry.auth_mode === "none" ? (
              <button className="btn primary" onClick={submit} disabled={busy}>
                Register again
              </button>
            ) : (
              <button className="btn ghost sm danger" onClick={disconnect} disabled={busy}>
                Disconnect
              </button>
            )}
          </div>
        </>
      ) : needsReattention && conn ? (
        <>
          <div className="empty" style={{ padding: "18px 0" }}>
            Connection is {conn.status}
            {conn.status === "error"
              ? " — the credential needs re-consent."
              : " — authorization was never completed."}
          </div>
          {err && <div className="err">{err}</div>}
          <div className="spread" style={{ marginTop: 16 }}>
            <button className="btn ghost sm danger" onClick={disconnect} disabled={busy}>
              Disconnect
            </button>
            {conn.auth_kind === "oauth" ? (
              <button className="btn primary" onClick={reconnect} disabled={busy}>
                Reconnect
              </button>
            ) : (
              <span />
            )}
          </div>
        </>
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
              <p className="helper">
                Connecting opens the provider&apos;s consent page once. fluidbox then custodies a
                rotating refresh token (sealed at rest) and mints short-lived access tokens at
                call time — nothing ever enters a sandbox.
              </p>
              <label className="field">
                <span className="lab">Pre-registered client id (optional)</span>
                <input
                  className="inp mono"
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                  placeholder="Leave empty to use CIMD/DCR"
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
            <input className="inp" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          </label>
          {err && <div className="err">{err}</div>}
          <div className="spread" style={{ marginTop: 16 }}>
            <span className="helper">
              {entry.auth_mode === "none"
                ? "Registers the bundle immediately."
                : entry.auth_mode === "api_key"
                  ? "The key is sealed at rest and proven by registration."
                  : "You will be redirected to authorize once."}
            </span>
            <button className="btn primary" onClick={submit} disabled={busy}>
              {busy ? "Connecting…" : "Connect"}
            </button>
          </div>
        </>
      )}
    </ModalShell>
  );
}

/* ─── Register custom bundle ─────────────────────────────────────────── */

const BUNDLE_EXAMPLE = `[
  {
    "class": "sandbox",
    "name": "ws",
    "command": "node",
    "args": ["/opt/fluidbox-runner/servers/workspace-info.mjs"],
    "tools": [
      { "name": "workspace_file_count", "description": "Count files in the workspace",
        "input_schema": { "type": "object", "properties": {} } }
    ]
  },
  {
    "class": "brokered",
    "name": "kb",
    "url": "https://mcp.example.com/mcp",
    "connection_id": "<mcp_http connection id, omit if the server needs no credential>"
  }
]`;

function NewBundle({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [servers, setServers] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async () => {
    setErr("");
    if (!name.trim()) {
      setErr("A name is required.");
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(servers);
    } catch (e) {
      setErr(`Servers is not valid JSON: ${String(e)}`);
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
    <ModalShell
      title="Register bundle version"
      sub="Append-only, like agent revisions — registering an existing name appends the next version."
      onClose={onClose}
    >
      <p className="helper" style={{ marginTop: 0 }}>
        Brokered servers are contacted now to photograph their tools — declare tools only for
        sandbox servers. Credentials come from mcp_http connections; they are never stored here
        and never enter a sandbox.
      </p>
      <label className="field">
        <span className="lab">Name</span>
        <input className="inp mono" value={name} onChange={(e) => setName(e.target.value)} placeholder="kb-tools" />
      </label>
      <label className="field">
        <span className="lab">Description (optional)</span>
        <input className="inp" value={description} onChange={(e) => setDescription(e.target.value)} />
      </label>
      <label className="field">
        <span className="lab">Servers (JSON array)</span>
        <textarea
          className="inp mono"
          style={{ minHeight: 180, fontSize: 11.5 }}
          value={servers}
          onChange={(e) => setServers(e.target.value)}
          placeholder={BUNDLE_EXAMPLE}
        />
      </label>
      {err && <div className="err">{err}</div>}
      <div className="spread" style={{ marginTop: 16 }}>
        <span className="helper">Brokered servers are discovered &amp; validated before storage.</span>
        <button className="btn primary" onClick={submit} disabled={busy}>
          {busy ? "Photographing…" : "Register"}
        </button>
      </div>
    </ModalShell>
  );
}
