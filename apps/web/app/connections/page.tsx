"use client";

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, Connection, ingressPath } from "../lib/api";
import { PageHead } from "../components/bits";

export default function Connections() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [showNew, setShowNew] = useState(false);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await apiGet<{ connections: Connection[] }>("/connections");
      setConnections(r.connections);
    } catch {
      /* offline handled by rail */
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const revoke = async (id: string) => {
    setErr("");
    try {
      await apiPost(`/connections/${id}/revoke`, {});
      load();
    } catch (e) {
      setErr(String(e));
    }
  };

  return (
    <>
      <PageHead
        eyebrow="integrations"
        title="Connections"
        sub="Authorized relationships with external services. A connection sets the maximum authority fluidbox can exercise — agents only ever use a narrower slice, and credentials never enter a sandbox."
        right={
          <button className="btn primary" onClick={() => setShowNew(true)}>
            + Connect
          </button>
        }
      />

      {err && <div className="err">{err}</div>}

      <div className="panel">
        {connections.length === 0 ? (
          <div className="empty">no connections — connect GitHub to select repositories on agents</div>
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
                </span>
                <span className={`autopill ${c.status === "active" ? "supervised" : "autonomous"}`}>
                  {c.status}
                </span>
                {c.status === "active" ? (
                  <button className="btn ghost sm" onClick={() => revoke(c.id)}>
                    revoke
                  </button>
                ) : (
                  <span />
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {showNew && (
        <NewConnection
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
              connect service
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
                Create a GitHub App in your org (permissions: Contents read, Pull requests write,
                Checks write; subscribe to Pull request events), install it on the repositories,
                then paste its identity here. The private key and webhook secret are validated,
                sealed at rest, and never leave the control plane. After connecting, point the
                App&apos;s webhook at the ingress URL shown on the connection row.
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
