"use client";

// Bring your own MCP server, the easy way: paste a URL → we probe it (no
// commitment) to detect the auth mode and preview the tools → you supply a
// credential or sign in → we photograph the tools and register a custom
// catalog entry + bundle in one call. Rides the same seams as the built-in
// catalog (POST /mcp/probe, POST /mcp/servers); a BYO server becomes an
// ordinary custom Store card afterward.

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Check, Puzzle, Wand2 } from "lucide-react";
import {
  apiGet,
  apiPost,
  AddServerResult,
  BundleServer,
  Connection,
  ProbeResult,
  ToolPreview,
} from "../lib/api";
import { ModalShell } from "../components/bits";

type Step = "url" | "detected" | "done";
type AuthChoice = "none" | "api_key" | "oauth";

function hostFrom(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function ToolList({ tools }: { tools: ToolPreview[] }) {
  if (tools.length === 0) return null;
  return (
    <div className="rows" style={{ marginTop: 8 }}>
      {tools.slice(0, 30).map((t) => (
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
      {tools.length > 30 && (
        <div className="faint" style={{ fontSize: 12, padding: "4px 10px" }}>
          …and {tools.length - 30} more
        </div>
      )}
    </div>
  );
}

export function AddServerWizard({ onClose }: { onClose: () => void }) {
  const [step, setStep] = useState<Step>("url");
  const [url, setUrl] = useState("");
  const [probing, setProbing] = useState(false);
  const [probe, setProbe] = useState<ProbeResult | null>(null);
  const [authMode, setAuthMode] = useState<AuthChoice>("none");

  const [name, setName] = useState("");
  const [token, setToken] = useState("");
  const [headerName, setHeaderName] = useState("");
  const [scheme, setScheme] = useState("Bearer");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");

  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [waiting, setWaiting] = useState(false);
  const [doneMsg, setDoneMsg] = useState("");
  const [doneTools, setDoneTools] = useState<ToolPreview[]>([]);
  const [doneBundle, setDoneBundle] = useState<{ name: string; version: number } | null>(null);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    return () => {
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, []);

  const detect = async () => {
    setErr("");
    if (!url.trim()) {
      setErr("Paste the MCP server's URL.");
      return;
    }
    setProbing(true);
    try {
      const r = await apiPost<ProbeResult>("/mcp/probe", { url: url.trim() });
      setProbe(r);
      setAuthMode(r.auth_mode);
      if (r.auth_hints.scheme) setScheme(r.auth_hints.scheme);
      if (r.auth_hints.header_name) setHeaderName(r.auth_hints.header_name);
      if (!name.trim()) setName(hostFrom(url) || "mcp-server");
      setStep("detected");
      setProbing(false);
    } catch (e) {
      setErr(String(e));
      setProbing(false);
    }
  };

  const flattenTools = (servers: BundleServer[] | undefined): ToolPreview[] =>
    (servers ?? []).flatMap((s) => s.tools);

  const stopPolling = () => {
    if (pollTimer.current) clearInterval(pollTimer.current);
    setWaiting(false);
  };

  // Watch the connection until the OAuth callback flips it active. A failed
  // dance sets status='error' (invalid_grant etc.), so we stop and surface it
  // rather than spin forever; and we cap the wait so an abandoned tab doesn't
  // leave the wizard hanging. Without a connection id there's nothing to poll.
  const watchUntilActive = (connId?: string) => {
    if (!connId) {
      setErr("The server didn't return a connection to track — try again.");
      return;
    }
    setWaiting(true);
    let waited = 0;
    const MAX_WAIT = 300; // seconds
    pollTimer.current = setInterval(async () => {
      waited += 2;
      try {
        const list = await apiGet<{ connections: Connection[] }>("/connections");
        const c = list.connections.find((x) => x.id === connId);
        if (c?.status === "active") {
          stopPolling();
          setDoneMsg("Connected — the bundle was registered with the fresh credential.");
          setStep("done");
        } else if (c?.status === "error") {
          stopPolling();
          setErr("Authorization didn't complete — the sign-in was refused. You can try again.");
        } else if (waited >= MAX_WAIT) {
          stopPolling();
          setErr("Timed out waiting for authorization. Finish the sign-in in the opened tab, then retry.");
        }
      } catch {
        /* transient list failure — keep polling until MAX_WAIT */
      }
    }, 2000);
  };

  const add = async () => {
    setErr("");
    if (!name.trim()) {
      setErr("Give this server a name.");
      return;
    }
    if (authMode === "api_key" && !token.trim()) {
      setErr("An API key is required. Choose OAuth instead if this server uses sign-in.");
      return;
    }
    setBusy(true);
    try {
      const r = await apiPost<AddServerResult>("/mcp/servers", {
        url: url.trim(),
        name: name.trim(),
        auth_mode: authMode,
        token: token.trim() || null,
        header_name: authMode === "api_key" && headerName.trim() ? headerName.trim() : null,
        scheme: authMode === "api_key" ? scheme : null,
        client_id: clientId.trim() || null,
        client_secret: clientSecret.trim() || null,
      });
      if (authMode !== "oauth") {
        setDoneTools(flattenTools(r.servers));
        setDoneBundle(r.bundle ?? null);
        setDoneMsg(
          r.bundle
            ? `Registered ${r.bundle.name}@${r.bundle.version} — attach it on an agent.`
            : "Connected."
        );
        setBusy(false);
        setStep("done");
        return;
      }
      // OAuth: hand the browser to the AS, then watch the connection go active
      // (the callback photographs the bundle).
      if (r.authorize_url) window.open(r.authorize_url, "_blank", "noopener");
      setBusy(false);
      watchUntilActive(r.connection?.id);
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  const recommendation =
    authMode === "none"
      ? "No credential needed — this server is open."
      : authMode === "oauth"
        ? "This server uses OAuth — you'll sign in once and we custody a rotating token, sealed."
        : "This server needs an API key — it's sealed at rest and proven by registration.";

  return (
    <ModalShell
      title="Add your own MCP server"
      sub="Paste a URL — we detect the auth, preview the tools, and register it."
      onClose={onClose}
    >
      {step === "url" && (
        <>
          <label className="field">
            <span className="lab">MCP server URL (streamable HTTP)</span>
            <input
              className="inp mono"
              placeholder="https://mcp.example.com/mcp"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              autoFocus
            />
          </label>
          <p className="helper" style={{ marginTop: 0 }}>
            We contact the server once (no credential, nothing stored) to detect whether it
            needs no auth, an API key, or OAuth — and to preview its tools.
          </p>
          {err && <div className="err">{err}</div>}
          <div className="spread" style={{ marginTop: 16 }}>
            <span className="helper">Only remote (HTTP) MCP servers here.</span>
            <button className="btn primary" onClick={detect} disabled={probing}>
              <Wand2 /> {probing ? "Detecting…" : "Detect"}
            </button>
          </div>
        </>
      )}

      {step === "detected" && probe && (
        <>
          <div className="note" style={{ marginTop: 0 }}>
            {recommendation}
            {!probe.reachable && (
              <span className="err" style={{ display: "block", fontSize: 12, marginTop: 4 }}>
                Couldn&apos;t reach the server anonymously — you can still try connecting with a
                credential.
              </span>
            )}
            {probe.notes.length > 0 && (
              <span className="faint" style={{ display: "block", fontSize: 11.5, marginTop: 4 }}>
                {probe.notes.join(" ")}
              </span>
            )}
          </div>

          {probe.oauth_available && probe.static_possible && (
            <div className="chipset" style={{ marginBottom: 10 }}>
              <button
                className={`fchip ${authMode === "oauth" ? "on" : ""}`}
                onClick={() => setAuthMode("oauth")}
              >
                Use OAuth
              </button>
              <button
                className={`fchip ${authMode === "api_key" ? "on" : ""}`}
                onClick={() => setAuthMode("api_key")}
              >
                Use an API key
              </button>
            </div>
          )}

          <label className="field">
            <span className="lab">Name</span>
            <input className="inp mono" value={name} onChange={(e) => setName(e.target.value)} />
          </label>

          {authMode === "none" && probe.tools_preview.length > 0 && (
            <div className="field">
              <span className="lab">Discovered tools ({probe.tools_preview.length})</span>
              <ToolList tools={probe.tools_preview} />
            </div>
          )}

          {authMode === "api_key" && (
            <>
              <label className="field">
                <span className="lab">API key</span>
                <input
                  className="inp mono"
                  type="password"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="paste the server's token"
                />
              </label>
              <div className="spread" style={{ gap: 10 }}>
                <label className="field" style={{ flex: 1 }}>
                  <span className="lab">Header (optional)</span>
                  <input
                    className="inp mono"
                    value={headerName}
                    onChange={(e) => setHeaderName(e.target.value)}
                    placeholder="authorization"
                  />
                </label>
                <label className="field" style={{ flex: 1 }}>
                  <span className="lab">Scheme</span>
                  <select className="inp" value={scheme} onChange={(e) => setScheme(e.target.value)}>
                    <option value="Bearer">Bearer</option>
                    <option value="Basic">Basic (email:token)</option>
                    <option value="">bare token</option>
                  </select>
                </label>
              </div>
            </>
          )}

          {authMode === "oauth" && (
            <>
              <p className="helper">
                Connecting opens the provider&apos;s consent page once. fluidbox then custodies a
                rotating refresh token (sealed) and mints short-lived access tokens at call time —
                nothing ever enters a sandbox.
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

          {err && <div className="err">{err}</div>}
          {waiting ? (
            <div className="empty" style={{ padding: "18px 0" }}>
              Waiting for authorization in the opened tab…
            </div>
          ) : (
            <div className="spread" style={{ marginTop: 16 }}>
              <button className="btn ghost sm" onClick={() => setStep("url")}>
                Back
              </button>
              <button className="btn primary" onClick={add} disabled={busy}>
                {busy ? "Connecting…" : authMode === "oauth" ? "Sign in & add" : "Add server"}
              </button>
            </div>
          )}
        </>
      )}

      {step === "done" && (
        <>
          <div className="empty" style={{ padding: "18px 0" }}>
            <Check />
            <div>{doneMsg}</div>
          </div>
          {doneTools.length > 0 && (
            <div className="field">
              <span className="lab">
                <Puzzle size={12} style={{ verticalAlign: "middle", marginRight: 4 }} />
                Photographed tools ({doneTools.length})
              </span>
              <ToolList tools={doneTools} />
            </div>
          )}
          <div className="spread" style={{ marginTop: 16 }}>
            <Link href="/agents/new" className="btn ghost sm">
              Attach on an agent →
            </Link>
            <button className="btn primary" onClick={onClose}>
              Done
            </button>
          </div>
          {doneBundle && (
            <p className="helper" style={{ marginTop: 8 }}>
              Pick <span className="mono">{doneBundle.name}</span> under Capabilities when composing
              the agent.
            </p>
          )}
        </>
      )}
    </ModalShell>
  );
}
