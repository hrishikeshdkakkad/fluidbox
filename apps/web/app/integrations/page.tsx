"use client";

// Integrations = platforms agents work ON: git hosting that powers workspace
// checkouts (repo/branch/commit), pull-request event triggers, and result
// publishing. Distinct from Capabilities (MCP tools agents call in a run).

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  apiGet,
  apiPost,
  appIngressPath,
  Connection,
  GithubAppRegistration,
  ingressPath,
  isGitConnection,
} from "../lib/api";
import { openVia } from "../lib/github-flows";
import { GitHubMark, ModalShell, PageHead } from "../components/bits";

export default function Integrations() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [registrations, setRegistrations] = useState<GithubAppRegistration[]>([]);
  const [showManual, setShowManual] = useState(false);
  const [org, setOrg] = useState("");
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");

  const load = useCallback(async () => {
    const results = await Promise.allSettled([
      apiGet<{ connections: Connection[] }>("/connections"),
      apiGet<{ registrations: GithubAppRegistration[] }>("/github/app"),
    ]);
    if (results[0].status === "fulfilled") setConnections(results[0].value.connections);
    if (results[1].status === "fulfilled") setRegistrations(results[1].value.registrations);
  }, []);

  useEffect(() => {
    const first = window.setTimeout(() => void load(), 0);
    // Returning from the GitHub tab should show the new state without a
    // manual refresh.
    window.addEventListener("focus", load);
    return () => {
      clearTimeout(first);
      window.removeEventListener("focus", load);
    };
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

  // The manifest dance: the server mints a one-time flow; the browser tab we
  // open is what gets bound to it (cookie), then continues to GitHub.
  // act() invokes its fn synchronously, so openVia's window.open stays inside
  // the click gesture — a late window.open gets eaten by popup blockers.
  const setupApp = () =>
    act(() =>
      openVia(async () => {
        const r = await apiPost<{ go_url: string }>("/github/app/manifest/start", {
          organization: org.trim() || null,
        });
        return r.go_url;
      })
    );

  const connectGithub = (regId: string) =>
    act(() =>
      openVia(async () => {
        const r = await apiPost<{ go_url: string }>(`/github/app/${regId}/install/start`, {});
        return r.go_url;
      })
    );

  const syncReg = (regId: string) =>
    act(async () => {
      const r = await apiPost<{ synced: unknown[]; conflicts: unknown[] }>(
        `/github/app/${regId}/sync`,
        {}
      );
      setNote(`Synced ${r.synced.length} installation(s), ${r.conflicts.length} conflict(s).`);
    });

  const revokeReg = (regId: string) => act(async () => void (await apiPost(`/github/app/${regId}/revoke`, {})));
  const revoke = (id: string) => act(async () => void (await apiPost(`/connections/${id}/revoke`, {})));
  // pending (webhook-discovered) → activate; revoked/suspended/error
  // registration-backed rows → revive. One explicit admin act either way.
  const approve = (id: string) => act(async () => void (await apiPost(`/connections/${id}/approve`, {})));

  // Revoked rows are history, not workspace (the DB keeps them).
  const visibleRegs = registrations.filter((r) => r.status !== "revoked");
  const activeRegs = visibleRegs.filter((r) => r.status === "active");
  const gitConnections = connections.filter((c) => isGitConnection(c) && c.status !== "revoked");

  return (
    <>
      <PageHead
        title="Integrations"
        sub="Platforms your agents work on. A connection powers workspace checkouts (repo, branch, commit), pull-request triggers, and publishing results back."
      />

      {err && <div className="err" style={{ marginBottom: 10 }}>{err}</div>}
      {note && <div className="note" style={{ marginBottom: 10 }}>{note}</div>}

      {/* ── GitHub App: the seamless path ─────────────────────────────── */}
      {visibleRegs.length === 0 ? (
        <div className="feature-card">
          <div className="fi">
            <GitHubMark size={22} />
          </div>
          <div className="ft">
            <div className="nm">GitHub</div>
            <div className="desc">
              One click creates a private GitHub App with exactly the permissions fluidbox
              needs (contents: read, pull requests: write, checks: write) — nothing to paste.
              It installs on the account that owns it; leave the organization blank for your
              personal account.
            </div>
          </div>
          <div className="fa">
            <input
              className="inp mono"
              style={{ maxWidth: 200 }}
              placeholder="Organization (optional)"
              value={org}
              onChange={(e) => setOrg(e.target.value)}
            />
            <button className="btn primary" onClick={setupApp}>
              Set up GitHub App
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="sectitle" style={{ marginTop: 0 }}>
            GitHub Apps
          </div>
          <div className="panel" style={{ marginBottom: 8 }}>
            <div className="rows">
              {visibleRegs.map((r) => (
                <div
                  key={r.id}
                  className="row"
                  style={{ gridTemplateColumns: "36px 1fr auto auto", alignItems: "center" }}
                >
                  <span className="store-icon" style={{ width: 28, height: 28, borderRadius: 7 }}>
                    <GitHubMark size={14} />
                  </span>
                  <span className="task">
                    {r.html_url ? (
                      <a href={r.html_url} target="_blank" rel="noreferrer" className="link">
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
                      <span className="faint mono" style={{ display: "block", fontSize: 11.5, marginTop: 2 }}>
                        webhook → {appIngressPath(r)}
                        {!r.has_webhook_secret && " · events disabled (no webhook secret — recreate the app)"}
                      </span>
                    )}
                  </span>
                  {r.status === "active" ? (
                    <span className="badge ok">
                      active
                    </span>
                  ) : (
                    <span className="badge warn">{r.status}</span>
                  )}
                  <span style={{ display: "flex", gap: 6 }}>
                    {r.status === "active" && (
                      <>
                        <button className="btn sm" onClick={() => connectGithub(r.id)}>
                          Add repositories
                        </button>
                        <button className="btn ghost sm" onClick={() => syncReg(r.id)}>
                          Sync installs
                        </button>
                      </>
                    )}
                    <button className="btn ghost sm danger" onClick={() => revokeReg(r.id)}>
                      Revoke
                    </button>
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div className="spread" style={{ marginBottom: 20 }}>
            <span className="helper">
              Private apps install only on the account that owns them — create one app per
              account or organization. Webhook delivery needs a public FLUIDBOX_PUBLIC_URL.
            </span>
            <span style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
              <input
                className="inp mono"
                style={{ maxWidth: 180, fontSize: 12 }}
                placeholder="Organization (optional)"
                value={org}
                onChange={(e) => setOrg(e.target.value)}
              />
              <button className="btn sm" onClick={setupApp}>
                New app
              </button>
            </span>
          </div>
        </>
      )}

      {/* ── Git connections ───────────────────────────────────────────── */}
      <div className="sectitle">Connections</div>
      <div className="panel">
        {gitConnections.length === 0 ? (
          <div className="empty">
            <GitHubMark size={22} />
            <div style={{ marginTop: 8 }}>
              No connections yet
              {activeRegs.length > 0
                ? " — use Add repositories above to install the app somewhere."
                : " — set up the GitHub App to get started."}
            </div>
          </div>
        ) : (
          <div className="rows">
            {gitConnections.map((c) => (
              <div
                key={c.id}
                className="row"
                style={{ gridTemplateColumns: "90px 1fr auto auto", alignItems: "center" }}
              >
                <span className="mono" style={{ fontSize: 12, color: "var(--accent)" }}>
                  {c.provider}
                </span>
                <span className="task">
                  {c.display_name}
                  {c.metadata?.login && c.metadata.login !== c.display_name ? ` (@${c.metadata.login})` : ""}
                  {c.registration_id && (
                    <span className="chip" style={{ marginLeft: 8 }}>
                      via app
                    </span>
                  )}
                  {c.granted_scopes?.length > 0 && (
                    <span className="faint" style={{ marginLeft: 8, fontSize: 12 }}>
                      scopes: {c.granted_scopes.join(", ")}
                    </span>
                  )}
                  {(ingressPath(c) || (c.registration_id && c.metadata?.installation_id)) && (
                    <span className="faint mono" style={{ display: "block", fontSize: 11.5, marginTop: 2 }}>
                      {ingressPath(c)
                        ? `webhook → ${ingressPath(c)}${c.metadata?.installation_id ? ` · installation ${c.metadata.installation_id}` : ""}`
                        : `installation ${c.metadata!.installation_id} · events via the app webhook`}
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
                  {c.registration_id && c.status === "pending" && (
                    <button className="btn sm" onClick={() => approve(c.id)}>
                      Approve
                    </button>
                  )}
                  {c.registration_id && ["suspended", "error"].includes(c.status) && (
                    <button className="btn ghost sm" onClick={() => approve(c.id)}>
                      Reconnect
                    </button>
                  )}
                  {c.status === "active" && (
                    <button className="btn ghost sm danger" onClick={() => revoke(c.id)}>
                      Revoke
                    </button>
                  )}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="spread" style={{ marginTop: 10 }}>
        <span className="helper">
          A connection is the widest authority fluidbox may exercise — runs use a narrower
          slice, and the credential never enters a sandbox. To give agents GitHub{" "}
          <i>tools</i> inside a run (issues, PRs via MCP), install GitHub from the{" "}
          <Link href="/capabilities" className="link">
            Capabilities store
          </Link>
          .
        </span>
        <button className="btn ghost sm" onClick={() => setShowManual(true)}>
          Add manually
        </button>
      </div>

      {showManual && (
        <NewConnection
          onClose={() => setShowManual(false)}
          onCreated={() => {
            setShowManual(false);
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
      setErr("A token is required.");
      return;
    }
    if (
      flavor === "github_app" &&
      (!appId.trim() || !installationId.trim() || !privateKey.trim() || !webhookSecret.trim())
    ) {
      setErr("App id, installation id, private key, and webhook secret are all required.");
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
    <ModalShell
      title="Add GitHub credentials manually"
      sub="Advanced fallback — Set up GitHub App above creates and custodies all of this automatically."
      onClose={onClose}
    >
      <label className="field">
        <span className="lab">Connection flavor</span>
        <select
          className="inp"
          value={flavor}
          onChange={(e) => setFlavor(e.target.value as "github" | "github_app")}
        >
          <option value="github">Personal access token — fetch repositories only</option>
          <option value="github_app">GitHub App installation — receives PR events, publishes reviews</option>
        </select>
      </label>
      {flavor === "github" ? (
        <>
          <p className="helper" style={{ marginTop: 0 }}>
            Paste a fine-grained personal access token scoped to the repositories agents may work
            in (Contents: read is enough for checkouts). It is validated against GitHub, sealed at
            rest, and only ever used by the control plane — never by a sandbox.
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
          <p className="helper" style={{ marginTop: 0 }}>
            Paste the identity of an app you registered yourself. The private key and webhook
            secret are validated, sealed at rest, and never leave the control plane. After
            connecting, point the app&apos;s webhook at the ingress URL shown on the connection.
          </p>
          <label className="field">
            <span className="lab">App ID</span>
            <input className="inp mono" value={appId} onChange={(e) => setAppId(e.target.value)} placeholder="1234567" />
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
            <span className="lab">Private key (PEM, downloaded from the app settings)</span>
            <textarea
              className="inp mono"
              rows={4}
              value={privateKey}
              onChange={(e) => setPrivateKey(e.target.value)}
              placeholder="-----BEGIN RSA PRIVATE KEY-----"
            />
          </label>
          <label className="field">
            <span className="lab">Webhook secret (the one set on the app&apos;s webhook)</span>
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
        <input className="inp" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
      </label>
      {err && <div className="err">{err}</div>}
      <div className="spread" style={{ marginTop: 16 }}>
        <span className="helper">Credentials are verified before they are stored.</span>
        <button className="btn primary" onClick={submit} disabled={busy}>
          {busy ? "Verifying…" : "Connect"}
        </button>
      </div>
    </ModalShell>
  );
}
