"use client";

// Capabilities = tools agents can CALL during a run (design §8.3): sandbox
// stdio servers baked into the runner image, and brokered MCP servers the
// control plane calls with sealed credentials. Distinct from Integrations
// (platforms agents work ON — repos, events, publishing).

import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  ChevronDown,
  ChevronRight,
  Search,
} from "lucide-react";
import {
  apiGet,
  apiPost,
  AuthMe,
  BundleDetail,
  BundleServer,
  CapabilityBundle,
  CatalogConnectResult,
  CatalogEntry,
  Connection,
  ConnectionToolSnapshot,
  fetchConnectionTools,
  isToolConnection,
  OwnerChoice,
  ownerOptions,
  refreshConnectionTools,
} from "../lib/api";
import { useAuthMe } from "../lib/useAuthMe";
import { GitHubMark, LoadingRows, ModalShell, OwnerTag, PageHead, timeAgo } from "../components/bits";
import { OwnerPicker } from "../components/OwnerPicker";
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
  const me = useAuthMe();
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
  const [toolsFor, setToolsFor] = useState<Connection | null>(null);
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
        const r = await apiPost<{ go_url: string }>(`/connections/${id}/oauth/start`, {});
        if (tabRef) tabRef.location.href = r.go_url;
        else window.location.href = r.go_url;
      } catch (e) {
        tabRef?.close();
        throw e;
      }
    });
  };

  const toolConnections = connections.filter((c) => isToolConnection(c) && c.status !== "revoked");

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
          meUserId={me?.user_id}
          onRevoke={revoke}
          onReconnect={reconnectOauth}
          onShowTools={setToolsFor}
        />
      )}

      {connecting && (
        <ConnectCatalog
          entry={connecting}
          me={me}
          // The catalog projection carries only {id,status,auth_kind}; the full
          // row (ownership, name, created_at) comes from the connections list
          // the page already holds.
          fullConnection={connections.find((c) => c.id === connecting.connection?.id) ?? null}
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
          me={me}
          onClose={() => {
            setShowWizard(false);
            load();
          }}
        />
      )}
      {toolsFor && (
        <ConnectionToolsPanel connection={toolsFor} onClose={() => setToolsFor(null)} />
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

  const categories = [...new Set(catalog.flatMap((e) => e.categories.map(canonicalCategory)))].sort();
  const shown = catalog.filter((e) => {
    if (cat && !e.categories.map(canonicalCategory).includes(cat)) return false;
    if (!q.trim()) return true;
    const hay = `${e.name} ${e.slug} ${e.description || ""} ${e.categories.join(" ")}`.toLowerCase();
    return hay.includes(q.trim().toLowerCase());
  });
  const grouped = shown.reduce<Map<string, CatalogEntry[]>>((groups, entry) => {
    const category = canonicalCategory(entry.categories[0] || "custom");
    const entries = groups.get(category) || [];
    entries.push(entry);
    groups.set(category, entries);
    return groups;
  }, new Map());

  return (
    <>
      <div className="connector-toolbar">
        <div className="storebar">
          <div className="search">
            <Search />
            <input
              className="inp"
              placeholder="Search connectors…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <button className="btn primary connector-add" type="button" onClick={onAddOwn}>
            New Connector
          </button>
        </div>
        {categories.length > 0 && (
          <div className="chipset connector-filters" aria-label="Connector categories">
            <button className={`fchip ${cat === null ? "on" : ""}`} onClick={() => setCat(null)}>
              All
            </button>
            {categories.map((c) => (
              <button
                key={c}
                className={`fchip ${cat === c ? "on" : ""}`}
                onClick={() => setCat(cat === c ? null : c)}
              >
                {formatCategory(c)}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="connector-groups">
        {[...grouped.entries()].map(([category, entries]) => (
          <section className="connector-group" key={category}>
            <div className="connector-group-head">
              <h2>{formatCategory(category)}</h2>
              <span>{entries.length}</span>
            </div>
            <div className="connector-grid">
              {entries.map((entry) => (
                <StoreCard key={entry.slug} entry={entry} onOpen={() => onOpen(entry)} />
              ))}
            </div>
          </section>
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
  // Imported `rest_action` cards are reference-only: browsable, but Connect is
  // refused until the REST action executor lands (bulk-import plan D3).
  const referenceOnly = entry.connectable === false;

  return (
    <button className="connector-card" type="button" onClick={onOpen}>
      <ConnectorMark entry={entry} />
      <span className="connector-card-copy">
        <span className="connector-card-title">
          <span className="nm">{entry.name}</span>
          {entry.tier !== "verified" && <span className="badge">{entry.tier}</span>}
        </span>
        <span className="desc">{entry.description || "Connect this service as a governed run capability."}</span>
        <span className="connector-card-meta">
          {entry.auth_mode === "none"
            ? "No credential"
            : entry.auth_mode === "api_key"
              ? "API key"
              : "OAuth"}
          {entry.bundle ? ` · v${entry.bundle.version}` : ""}
        </span>
      </span>
      <span className="connector-card-action">
        {connected ? (
          <span className="state ok">Connected</span>
        ) : attention ? (
          <span className="state err">{entry.connection!.status}</span>
        ) : referenceOnly ? (
          <span className="state" style={{ color: "var(--muted)" }}>
            Reference only
          </span>
        ) : (
          <span className="state">Connect</span>
        )}
      </span>
    </button>
  );
}

function ConnectorMark({ entry }: { entry: CatalogEntry }) {
  const tone = [
    "atlassian",
    "github",
    "linear",
    "notion",
    "sentry",
    "stripe",
    "workspace",
  ].includes(entry.slug) ? entry.slug : "custom";
  const initials = entry.name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0])
    .join("")
    .toUpperCase();

  return (
    <span className={`connector-mark connector-mark-${tone}`} aria-hidden="true">
      {entry.slug === "github" ? <GitHubMark size={21} /> : <span>{initials || "C"}</span>}
    </span>
  );
}

function formatCategory(category: string) {
  const names: Record<string, string> = {
    "project-mgmt": "Project management",
    dev: "Developer",
    docs: "Knowledge",
    payments: "Finance",
    observability: "Operations",
    workspace: "Workspace",
    custom: "Custom",
  };
  return names[category] || category.replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function canonicalCategory(category: string) {
  const aliases: Record<string, string> = {
    dev: "developer",
    vcs: "developer",
    docs: "knowledge",
    payments: "finance",
    observability: "operations",
  };
  return aliases[category] || category;
}

/* ─── Bundles ────────────────────────────────────────────────────────── */

// The photographed tool list of a bundle, grouped by server. Shared by the
// Bundles tab and the connector modal so the two renderings never drift.
function ServerTools({ servers }: { servers: BundleServer[] }) {
  return (
    <>
      {servers.map((s) => (
        <div key={s.name} className="tool-group">
          <div className="tool-group-head">
            <span>{s.name}</span>
            <span className={`badge ${s.class === "brokered" ? "brand" : ""}`}>{s.class}</span>
            <span className="tool-group-count">{s.tools.length}</span>
          </div>
          {s.tools.length === 0 ? (
            <div className="tool-empty">No tools.</div>
          ) : (
            s.tools.map((t) => (
              <div key={t.name} className="tool-row">
                <span className="tool-name">{t.name}</span>
                {t.description ? <span className="tool-desc">{t.description}</span> : null}
              </div>
            ))
          )}
        </div>
      ))}
    </>
  );
}

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
            <div className="tool-list">
              <div className="tool-loading">Loading tools…</div>
            </div>
          ) : detail && detail.servers.length > 0 ? (
            <div className="tool-list">
              <ServerTools servers={detail.servers} />
            </div>
          ) : (
            <div className="tool-list">
              <div className="tool-empty">No tool details.</div>
            </div>
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
          Register bundle
        </button>
      </div>
      <div className="panel">
        {bundles.length === 0 ? (
          <div className="empty">
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
  meUserId,
  onRevoke,
  onReconnect,
  onShowTools,
}: {
  connections: Connection[];
  meUserId?: string | null;
  onRevoke: (id: string) => void;
  onReconnect: (id: string) => void;
  onShowTools: (c: Connection) => void;
}) {
  return (
    <>
      <div className="panel">
        {connections.length === 0 ? (
          <div className="empty">
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
                    <OwnerTag connection={c} meUserId={meUserId} />
                    {c.auth_kind === "oauth" ? (
                      <span className="chip">
                        oauth{c.oauth?.client_id_source ? ` · ${c.oauth.client_id_source}` : ""}
                      </span>
                    ) : c.auth_kind === "none" ? (
                      <span className="chip">no auth</span>
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
                  <button className="btn ghost sm" onClick={() => onShowTools(c)}>
                    Tools
                  </button>
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

/* ─── Connection tool snapshot panel ─────────────────────────────────── */

// The append-only photograph of a brokered connection's tools/list
// (GET /connections/{id}/tools). Refresh re-photographs into a new version; a
// 4xx body is actionable (e.g. reauthorization guidance) and is shown verbatim.
function ConnectionToolsPanel({
  connection,
  onClose,
}: {
  connection: Connection;
  onClose: () => void;
}) {
  const [snapshot, setSnapshot] = useState<ConnectionToolSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    setErr("");
    try {
      setSnapshot(await fetchConnectionTools(connection.id));
    } catch (e) {
      setErr(String(e));
    } finally {
      setLoading(false);
    }
  }, [connection.id]);

  useEffect(() => {
    // Defer the first fetch out of the effect body (repo convention, survey D
    // §9) so the synchronous setState inside load() doesn't cascade-render.
    const t = window.setTimeout(() => void load(), 0);
    return () => clearTimeout(t);
  }, [load]);

  const refresh = async () => {
    setErr("");
    setRefreshing(true);
    try {
      setSnapshot(await refreshConnectionTools(connection.id));
    } catch (e) {
      // 4xx bodies (generation refresh / reauthorization guidance) are designed
      // to be actionable — surface them verbatim.
      setErr(String(e));
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <ModalShell
      title={`${connection.display_name} · tools`}
      sub="The connection's latest photographed tool surface. The permission gate still judges every call."
      onClose={onClose}
    >
      {loading ? (
        <div className="tool-list">
          <div className="tool-loading">Loading tools…</div>
        </div>
      ) : snapshot ? (
        <>
          <div className="chips" style={{ marginBottom: 10 }}>
            <span className="chip">
              version <b>{snapshot.version}</b>
            </span>
            <span className="chip">
              protocol <b>{snapshot.protocol_version}</b>
            </span>
            <span className="chip">
              generation <b>{snapshot.authorization_generation}</b>
            </span>
            <span className="chip">
              photographed <b>{timeAgo(snapshot.discovered_at)}</b>
            </span>
          </div>
          <div className="field">
            <span className="lab">Tools ({snapshot.tools.length})</span>
            {snapshot.tools.length === 0 ? (
              <div className="tool-empty">No tools in this snapshot.</div>
            ) : (
              <div className="rows" style={{ marginTop: 6 }}>
                {snapshot.tools.map((t) => (
                  <div
                    key={t.name}
                    className="row"
                    style={{ gridTemplateColumns: "minmax(120px, 40%) 1fr", padding: "6px 10px" }}
                  >
                    <span className="mono" style={{ fontSize: 12, color: "var(--accent)" }}>
                      {t.name}
                    </span>
                    <span className="faint" style={{ fontSize: 12 }}>
                      {t.description || "—"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
          <p className="faint mono" style={{ fontSize: 11, marginTop: 6 }}>
            digest {snapshot.tools_digest.slice(0, 24)}…
          </p>
        </>
      ) : (
        <div className="empty" style={{ padding: "18px 0" }}>
          <div>No tool snapshot yet — refresh to photograph.</div>
        </div>
      )}
      {err && <div className="err">{err}</div>}
      <div className="spread" style={{ marginTop: 16 }}>
        <span className="helper">Re-photographing appends a new snapshot version.</span>
        <button className="btn primary" onClick={refresh} disabled={refreshing}>
          {refreshing ? "Refreshing…" : "Refresh tools"}
        </button>
      </div>
    </ModalShell>
  );
}

/* ─── Connect-from-catalog modal ─────────────────────────────────────── */

function ConnectCatalog({
  entry,
  me,
  fullConnection,
  onClose,
}: {
  entry: CatalogEntry;
  me: AuthMe | null;
  fullConnection: Connection | null;
  onClose: () => void;
}) {
  const [token, setToken] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [ownerChoice, setOwnerChoice] = useState<OwnerChoice | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState("");
  const [waiting, setWaiting] = useState(false);
  const [toolDetail, setToolDetail] = useState<BundleDetail | null>(null);
  const [toolsErr, setToolsErr] = useState(false);
  const [snapshot, setSnapshot] = useState<ConnectionToolSnapshot | null>(null);
  const [snapshotErr, setSnapshotErr] = useState(false);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  // Catalog connections are mcp_http — personal is allowed for any member.
  const owner = ownerChoice ?? ownerOptions(me, true).default;

  const conn = entry.connection;
  const connId = conn?.id;
  const isConnected = conn?.status === "active" || (entry.auth_mode === "none" && !!entry.bundle);
  const needsReattention = !!conn && conn.status !== "active" && !isConnected;
  const bundleId = entry.bundle?.id;
  const toolsLoading = isConnected && !!bundleId && !toolDetail && !toolsErr;

  useEffect(() => {
    return () => {
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, []);

  // A connected bundle already holds its photographed tool schemas — fetch them
  // once and render them in the modal so the tools are visible here, not only in
  // the Bundles tab (design 2026-07-14). Pure presentation: no logic, just the API.
  useEffect(() => {
    if (!isConnected || !bundleId) return;
    let cancelled = false;
    apiGet<BundleDetail>(`/capabilities/${bundleId}`)
      .then((d) => {
        if (!cancelled) setToolDetail(d);
      })
      .catch(() => {
        if (!cancelled) setToolsErr(true);
      });
    return () => {
      cancelled = true;
    };
  }, [isConnected, bundleId]);

  // A brokered (remote) connection never registers a bundle — Phase C moved its
  // tool surface to a per-connection snapshot. Read that instead, so the tools
  // are visible here and not only behind the Connections tab's Tools panel.
  useEffect(() => {
    if (!isConnected || !connId || bundleId) return;
    let cancelled = false;
    fetchConnectionTools(connId)
      .then((s) => {
        if (!cancelled) setSnapshot(s);
      })
      .catch(() => {
        if (!cancelled) setSnapshotErr(true);
      });
    return () => {
      cancelled = true;
    };
  }, [isConnected, connId, bundleId]);
  // Imported `rest_action` cards are reference-only until the REST action
  // executor lands — Connect is refused server-side, so don't offer it here.
  const referenceOnly = entry.connectable === false;

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
      const r = await apiPost<{ go_url: string }>(`/connections/${conn.id}/oauth/start`, {});
      window.open(r.go_url, "_blank", "noopener");
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
        owner,
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
      // OAuth: hand the browser to the go endpoint (it binds the per-flow cookie,
      // then redirects to the authorization server), then watch the connection
      // flip active (the callback photographs the bundle).
      if (r.go_url) window.open(r.go_url, "_blank", "noopener");
      setBusy(false);
      watchUntilActive(r.connection?.id);
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  return (
    <ModalShell
      title={entry.name}
      sub={entry.tier === "verified" ? "Verified connector" : `${entry.tier} connector`}
      onClose={onClose}
    >
      <p className="connector-lead">{entry.description}</p>
      {(entry.egress.length > 0 || entry.tool_hints.length > 0) && (
        <div className="connector-meta">
          {entry.egress.length > 0 && (
            <div className="meta-row">
              <span className="meta-label">Egress</span>
              <div className="egress-list">
                {entry.egress.map((h) => (
                  <span key={h} className="egress-chip">
                    {h}
                  </span>
                ))}
              </div>
            </div>
          )}
          {entry.tool_hints.length > 0 && (
            <div className="meta-row">
              <span className="meta-label">Policy hints — your policy decides</span>
              <div className="hint-list">
                {entry.tool_hints.map((h) => (
                  <div key={h.pattern} className="hint-row">
                    <span className="hint-pattern">{h.pattern}</span>
                    <span className="hint-arrow">→</span>
                    <span className={`hint-action ${h.action}`}>{h.action}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
      {done ? (
        <>
          <div className="empty" style={{ padding: "18px 0" }}>
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
          <div className="connector-status">
            <span className="status-dot" />
            <span>Connected</span>
            {fullConnection && <OwnerTag connection={fullConnection} meUserId={me?.user_id} />}
            {entry.bundle ? (
              <span className="bundle-chip">
                {entry.bundle.name}@{entry.bundle.version}
              </span>
            ) : snapshot ? (
              <span className="bundle-chip">
                v{snapshot.version} · {snapshot.protocol_version}
              </span>
            ) : snapshotErr ? (
              <span className="faint" style={{ fontSize: 12, fontWeight: 400 }}>
                tool snapshot unavailable
              </span>
            ) : (
              <span className="faint" style={{ fontSize: 12, fontWeight: 400 }}>
                reading tool snapshot…
              </span>
            )}
          </div>
          {(fullConnection || snapshot) && (
            <p className="faint" style={{ fontSize: 12, marginTop: 6 }}>
              {fullConnection && `${fullConnection.display_name} · connected ${timeAgo(fullConnection.created_at)}`}
              {snapshot &&
                `${fullConnection ? " · " : ""}photographed ${timeAgo(snapshot.discovered_at)} · generation ${snapshot.authorization_generation}`}
            </p>
          )}
          {!entry.bundle && snapshot && (
            <div className="tool-section">
              <div className="tool-section-head">
                <h4>Tools</h4>
                <span className="tool-count">{snapshot.tools.length} agents can call</span>
              </div>
              {snapshot.tools.length === 0 ? (
                <div className="tool-list">
                  <div className="tool-empty">No tools in this snapshot.</div>
                </div>
              ) : (
                <div className="rows" style={{ marginTop: 6 }}>
                  {snapshot.tools.map((t) => (
                    <div
                      key={t.name}
                      className="row"
                      style={{ gridTemplateColumns: "minmax(120px, 40%) 1fr", padding: "6px 10px" }}
                    >
                      <span className="mono" style={{ fontSize: 12, color: "var(--accent)" }}>
                        {t.name}
                      </span>
                      <span className="faint" style={{ fontSize: 12 }}>
                        {t.description || "—"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
          {entry.bundle && (
            <div className="tool-section">
              <div className="tool-section-head">
                <h4>Tools</h4>
                {toolDetail && (
                  <span className="tool-count">
                    {toolDetail.servers.reduce((n, s) => n + s.tools.length, 0)} agents can call
                  </span>
                )}
              </div>
              {toolsLoading ? (
                <div className="tool-list">
                  <div className="tool-loading">Loading tools…</div>
                </div>
              ) : toolsErr ? (
                <div className="tool-list">
                  <div className="tool-empty">Couldn&apos;t load tools.</div>
                </div>
              ) : toolDetail && toolDetail.servers.length > 0 ? (
                <div className="tool-list">
                  <ServerTools servers={toolDetail.servers} />
                </div>
              ) : (
                <div className="tool-list">
                  <div className="tool-empty">No tools.</div>
                </div>
              )}
            </div>
          )}
          {err && <div className="err">{err}</div>}
          <div className="spread" style={{ marginTop: 18 }}>
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
      ) : referenceOnly ? (
        <>
          <div className="empty" style={{ padding: "18px 0" }}>
            <div>
              Reference only — this connector was imported for discovery. It has no hosted MCP
              endpoint fluidbox can attach yet, so there&apos;s nothing to connect today.
            </div>
          </div>
          <div className="spread" style={{ marginTop: 16 }}>
            <span className="helper">
              Imported, untrusted reference data ({entry.tier}). Its tool hints are display-only —
              your policy stays the judge.
            </span>
            <button className="btn ghost" onClick={onClose}>
              Close
            </button>
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
          <OwnerPicker me={me} value={owner} onChange={setOwnerChoice} />
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
        Bundles now carry <strong>sandbox</strong> (in-image stdio) servers only — declare their
        tools inline, as above.
      </p>
      <p className="helper" style={{ marginTop: 0 }}>
        For a brokered (remote) MCP server, connect it under{" "}
        <Link href="/capabilities">Integrations</Link> instead — its tools are photographed into a
        per-connection snapshot, and an agent names it through a connection requirement.
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
        <span className="helper">Sandbox servers are validated before storage.</span>
        <button className="btn primary" onClick={submit} disabled={busy}>
          {busy ? "Registering…" : "Register"}
        </button>
      </div>
    </ModalShell>
  );
}
