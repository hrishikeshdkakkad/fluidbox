"use client";

import { useCallback, useEffect, useState } from "react";
import {
  apiGet,
  apiPost,
  appIngressPath,
  Connection,
  GithubAppRegistration,
  ingressPath,
} from "../lib/api";
import { PageHead } from "../components/bits";

export default function Connections() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [registrations, setRegistrations] = useState<GithubAppRegistration[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [org, setOrg] = useState("");
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");

  const load = useCallback(async () => {
    try {
      const [c, r] = await Promise.all([
        apiGet<{ connections: Connection[] }>("/connections"),
        apiGet<{ registrations: GithubAppRegistration[] }>("/github/app"),
      ]);
      setConnections(c.connections);
      setRegistrations(r.registrations);
    } catch {
      /* offline handled by rail */
    }
  }, []);

  useEffect(() => {
    load();
    // Returning from the GitHub tab should show the new state without a
    // manual refresh.
    window.addEventListener("focus", load);
    return () => window.removeEventListener("focus", load);
  }, [load]);

  const act = async (fn: () => Promise<void>) => {
    setErr("");
    setNote("");
    try {
      await fn();
      load();
    } catch (e) {
      setErr(String(e));
    }
  };

  // Browsers void the click gesture across an await (popup blockers eat a
  // late window.open) — open the tab synchronously, then point it at the
  // URL the API returns.
  const openVia = (getUrl: () => Promise<string>) => {
    const tab = window.open("", "_blank");
    act(async () => {
      try {
        const url = await getUrl();
        if (tab) tab.location.href = url;
        else window.location.href = url;
      } catch (e) {
        tab?.close();
        throw e;
      }
    });
  };

  // The manifest dance: the server mints a one-time flow; the browser tab
  // we open is what gets bound to it (cookie), then continues to GitHub.
  const setupApp = () =>
    openVia(async () => {
      const r = await apiPost<{ go_url: string }>("/github/app/manifest/start", {
        organization: org.trim() || null,
      });
      return r.go_url;
    });

  const connectGithub = (regId: string) =>
    openVia(async () => {
      const r = await apiPost<{ go_url: string }>(`/github/app/${regId}/install/start`, {});
      return r.go_url;
    });

  const syncReg = (regId: string) =>
    act(async () => {
      const r = await apiPost<{ synced: unknown[]; conflicts: unknown[] }>(
        `/github/app/${regId}/sync`,
        {}
      );
      setNote(`sync: ${r.synced.length} installation(s) reconciled, ${r.conflicts.length} conflict(s)`);
    });

  const revokeReg = (regId: string) =>
    act(async () => {
      await apiPost(`/github/app/${regId}/revoke`, {});
    });

  const revoke = (id: string) => act(async () => void (await apiPost(`/connections/${id}/revoke`, {})));

  // pending (webhook-discovered) → activate; revoked/suspended/error
  // registration-backed rows → revive. One explicit admin act either way.
  const approve = (id: string) => act(async () => void (await apiPost(`/connections/${id}/approve`, {})));

  // Restart the OAuth dance on the SAME connection (pending rows finish it,
  // errored rows revive after invalid_grant — nothing is recreated).
  const reconnectOauth = (id: string) =>
    openVia(async () => {
      const r = await apiPost<{ authorize_url: string }>(`/connections/${id}/oauth/start`, {});
      return r.authorize_url;
    });

  const activeRegs = registrations.filter((r) => r.status === "active");

  return (
    <>
      <PageHead
        eyebrow="integrations"
        title="Connections"
        sub="Authorized relationships with external services. A connection sets the maximum authority fluidbox can exercise — agents only ever use a narrower slice, and credentials never enter a sandbox."
        right={
          <button className="btn ghost" onClick={() => setShowAdvanced(true)}>
            advanced
          </button>
        }
      />

      {err && <div className="err">{err}</div>}
      {note && (
        <div className="mut" style={{ fontSize: 12.5, marginBottom: 8 }}>
          {note}
        </div>
      )}

      {/* ── GitHub App: the seamless path ─────────────────────────────── */}
      <div className="panel" style={{ marginBottom: 16 }}>
        {registrations.length === 0 ? (
          <div style={{ padding: 4 }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, marginBottom: 6 }}>
              Connect GitHub
            </div>
            <p className="mut" style={{ fontSize: 12.5, marginTop: 0, maxWidth: 640 }}>
              One click creates a private GitHub App with exactly the permissions fluidbox needs
              (contents: read, pull requests: write, checks: write) and its webhook pre-wired —
              nothing to paste. The app installs on the account that owns it; leave the
              organization blank to create it on your personal account.
            </p>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <input
                className="inp mono"
                style={{ maxWidth: 220 }}
                placeholder="organization (optional)"
                value={org}
                onChange={(e) => setOrg(e.target.value)}
              />
              <button className="btn primary" onClick={setupApp}>
                Set up GitHub App
              </button>
            </div>
          </div>
        ) : (
          <div className="rows">
            {registrations.map((r) => (
              <div
                key={r.id}
                className="row"
                style={{ gridTemplateColumns: "90px 1fr auto auto", alignItems: "center" }}
              >
                <span className="mono" style={{ color: "var(--accent)" }}>
                  github app
                </span>
                <span className="task">
                  {r.html_url ? (
                    <a href={r.html_url} target="_blank" rel="noreferrer">
                      {r.name ?? r.slug ?? "pending app"}
                    </a>
                  ) : (
                    (r.name ?? "pending app")
                  )}
                  {r.owner_login && (
                    <span className="mut" style={{ marginLeft: 8, fontSize: 12 }}>
                      @{r.owner_login}
                    </span>
                  )}
                  {r.status === "active" && (
                    <span
                      className="mut mono"
                      style={{ display: "block", fontSize: 11.5, marginTop: 2 }}
                    >
                      webhook → {appIngressPath(r)}
                      {!r.has_webhook_secret && " · events disabled (no webhook secret — recreate the app)"}
                    </span>
                  )}
                  <span className="mut" style={{ display: "block", fontSize: 11.5, marginTop: 2 }}>
                    webhook delivery needs a publicly reachable FLUIDBOX_PUBLIC_URL; everything
                    else works locally
                  </span>
                </span>
                <span className={`autopill ${r.status === "active" ? "supervised" : "autonomous"}`}>
                  {r.status}
                </span>
                <span style={{ display: "flex", gap: 6 }}>
                  {r.status === "active" && (
                    <>
                      <button className="btn primary sm" onClick={() => connectGithub(r.id)}>
                        Connect GitHub
                      </button>
                      <button className="btn ghost sm" onClick={() => syncReg(r.id)}>
                        sync &amp; activate installs
                      </button>
                    </>
                  )}
                  {r.status !== "revoked" && (
                    <button className="btn ghost sm" onClick={() => revokeReg(r.id)}>
                      revoke
                    </button>
                  )}
                </span>
              </div>
            ))}
            <div className="row" style={{ gridTemplateColumns: "1fr auto", alignItems: "center" }}>
              <span className="mut" style={{ fontSize: 12 }}>
                need another account or organization? private apps install only on their owner —
                create one app per owner
              </span>
              <span style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <input
                  className="inp mono"
                  style={{ maxWidth: 180, fontSize: 12 }}
                  placeholder="organization (optional)"
                  value={org}
                  onChange={(e) => setOrg(e.target.value)}
                />
                <button className="btn ghost sm" onClick={setupApp}>
                  + new app
                </button>
              </span>
            </div>
          </div>
        )}
      </div>

      {/* ── Connections ───────────────────────────────────────────────── */}
      <div className="panel">
        {connections.length === 0 ? (
          <div className="empty">
            no connections — set up the GitHub App above, then Connect GitHub to pick repositories
          </div>
        ) : (
          <div className="rows">
            {connections.map((c) => (
              <div
                key={c.id}
                className="row"
                style={{ gridTemplateColumns: "90px 1fr auto auto", alignItems: "center" }}
              >
                <span className="mono" style={{ color: "var(--accent)" }}>
                  {c.provider}
                </span>
                <span className="task">
                  {c.display_name}
                  {c.metadata?.login && c.metadata.login !== c.display_name
                    ? ` (@${c.metadata.login})`
                    : ""}
                  {c.registration_id && (
                    <span className="mut mono" style={{ marginLeft: 8, fontSize: 11.5 }}>
                      via app
                    </span>
                  )}
                  {c.auth_kind === "oauth" && (
                    <span className="mut mono" style={{ marginLeft: 8, fontSize: 11.5 }}>
                      oauth{c.oauth?.client_id_source ? ` (${c.oauth.client_id_source})` : ""}
                    </span>
                  )}
                  {c.metadata?.header_name && (
                    <span className="mut mono" style={{ marginLeft: 8, fontSize: 11.5 }}>
                      header: {c.metadata.header_name}
                    </span>
                  )}
                  {c.granted_scopes?.length > 0 && (
                    <span className="mut" style={{ marginLeft: 8, fontSize: 12 }}>
                      scopes: {c.granted_scopes.join(", ")}
                    </span>
                  )}
                  {ingressPath(c) && (
                    <span
                      className="mut mono"
                      style={{ display: "block", fontSize: 11.5, marginTop: 2 }}
                    >
                      webhook → {ingressPath(c)}
                      {c.metadata?.installation_id
                        ? ` · installation ${c.metadata.installation_id}`
                        : ""}
                    </span>
                  )}
                  {c.registration_id && c.metadata?.installation_id && (
                    <span
                      className="mut mono"
                      style={{ display: "block", fontSize: 11.5, marginTop: 2 }}
                    >
                      installation {c.metadata.installation_id} · events via the app webhook
                    </span>
                  )}
                  {c.status === "error" && c.oauth?.error && (
                    <span className="err" style={{ display: "block", fontSize: 11.5, marginTop: 2 }}>
                      {c.oauth.error}
                    </span>
                  )}
                </span>
                <span className={`autopill ${c.status === "active" ? "supervised" : "autonomous"}`}>
                  {c.status}
                </span>
                <span style={{ display: "flex", gap: 6 }}>
                  {c.registration_id && c.status === "pending" && (
                    <button className="btn primary sm" onClick={() => approve(c.id)}>
                      approve
                    </button>
                  )}
                  {c.registration_id && ["revoked", "suspended", "error"].includes(c.status) && (
                    <button className="btn ghost sm" onClick={() => approve(c.id)}>
                      reconnect
                    </button>
                  )}
                  {c.status === "active" ? (
                    <button className="btn ghost sm" onClick={() => revoke(c.id)}>
                      revoke
                    </button>
                  ) : c.auth_kind === "oauth" && c.status !== "revoked" ? (
                    <button className="btn ghost sm" onClick={() => reconnectOauth(c.id)}>
                      reconnect
                    </button>
                  ) : null}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {showAdvanced && (
        <NewConnection
          onClose={() => setShowAdvanced(false)}
          onCreated={() => {
            setShowAdvanced(false);
            load();
          }}
        />
      )}
    </>
  );
}

/** Manual credential entry — the fallback path. The seamless GitHub App
 *  flow above replaces this for the common case. */
function NewConnection({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [flavor, setFlavor] = useState<"github" | "github_app">("github");
  const [token, setToken] = useState("");
  const [appId, setAppId] = useState("");
  const [installationId, setInstallationId] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [webhookSecret, setWebhookSecret] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async () => {
    setErr("");
    if (flavor === "github" && !token.trim()) {
      setErr("token is required");
      return;
    }
    if (
      flavor === "github_app" &&
      (!appId.trim() || !installationId.trim() || !privateKey.trim() || !webhookSecret.trim())
    ) {
      setErr("app id, installation id, private key, and webhook secret are all required");
      return;
    }
    setBusy(true);
    try {
      await apiPost(
        "/connections",
        flavor === "github"
          ? {
              provider: "github",
              token: token.trim(),
              display_name: displayName.trim() || null,
            }
          : {
              provider: "github_app",
              app_id: appId.trim(),
              installation_id: installationId.trim(),
              private_key: privateKey,
              webhook_secret: webhookSecret.trim(),
              display_name: displayName.trim() || null,
            }
      );
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
              advanced — manual credentials
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 15, marginTop: 4 }}>
              GitHub
            </div>
          </div>
          <button className="btn ghost sm" onClick={onClose}>
            esc
          </button>
        </div>
        <div className="mb">
          <p className="mut" style={{ fontSize: 12.5, marginTop: 0 }}>
            Prefer <b>Set up GitHub App</b> on the Connections page — it creates and custodies
            everything below automatically. Use this form only for a pre-existing app or a plain
            personal access token.
          </p>
          <label className="field">
            <span className="lab">Connection flavor</span>
            <select
              className="inp"
              value={flavor}
              onChange={(e) => setFlavor(e.target.value as "github" | "github_app")}
            >
              <option value="github">personal access token — fetch repositories only</option>
              <option value="github_app">
                GitHub App installation — receives PR events, publishes reviews
              </option>
            </select>
          </label>
          {flavor === "github" ? (
            <>
              <p className="mut" style={{ fontSize: 12.5, marginTop: 0 }}>
                Paste a fine-grained personal access token scoped to the repositories agents may
                work in (Contents: read is enough for checkouts). It is validated against GitHub,
                sealed at rest, and only ever used by the control plane — never by a sandbox.
              </p>
              <label className="field">
                <span className="lab">Personal access token</span>
                <input
                  className="inp mono"
                  type="password"
                  placeholder="github_pat_…"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                />
              </label>
            </>
          ) : (
            <>
              <p className="mut" style={{ fontSize: 12.5, marginTop: 0 }}>
                Paste the identity of an app you registered yourself. The private key and webhook
                secret are validated, sealed at rest, and never leave the control plane. After
                connecting, point the App&apos;s webhook at the ingress URL shown on the
                connection row.
              </p>
              <label className="field">
                <span className="lab">App ID</span>
                <input
                  className="inp mono"
                  value={appId}
                  onChange={(e) => setAppId(e.target.value)}
                  placeholder="1234567"
                />
              </label>
              <label className="field">
                <span className="lab">Installation ID</span>
                <input
                  className="inp mono"
                  value={installationId}
                  onChange={(e) => setInstallationId(e.target.value)}
                  placeholder="87654321"
                />
              </label>
              <label className="field">
                <span className="lab">Private key (PEM, downloaded from the App settings)</span>
                <textarea
                  className="inp mono"
                  rows={4}
                  value={privateKey}
                  onChange={(e) => setPrivateKey(e.target.value)}
                  placeholder="-----BEGIN RSA PRIVATE KEY-----"
                />
              </label>
              <label className="field">
                <span className="lab">Webhook secret (the one set on the App&apos;s webhook)</span>
                <input
                  className="inp mono"
                  type="password"
                  value={webhookSecret}
                  onChange={(e) => setWebhookSecret(e.target.value)}
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
              credentials are verified before they are stored
            </span>
            <button className="btn primary" onClick={submit} disabled={busy}>
              {busy ? "verifying…" : "Connect"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
