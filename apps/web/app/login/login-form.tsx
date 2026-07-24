"use client";

import { useState } from "react";

/**
 * Neutral organization-entry form for hosted (sso) deployments. It never
 * enumerates organizations — it just routes the browser to the org's IdP via
 * the control plane's login-start endpoint.
 *
 * The submit is a plain top-level navigation (NOT a fetch): the browser
 * natively follows the 302 chain to the IdP and stores the __Host-fbx_login_*
 * cookie the proxy hands back from the control plane. All authorization lives
 * in the Rust control plane; this form decides nothing.
 *
 * Rendered only in sso mode — the /login server boundary (page.tsx) redirects
 * to "/" in admin mode before this ever loads.
 *
 * `redirectTo` is the already-sanitized local path to land on after the IdP
 * round-trip (page.tsx clamps it; the control plane re-validates). It rides the
 * login flow as `redirect_to`, so a deep link survives the whole dance.
 */
export default function LoginForm({ redirectTo = "/" }: { redirectTo?: string }) {
  const [org, setOrg] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const slug = org.trim();
    if (!slug) return;
    setBusy(true);
    // Same-origin proxy URL. The proxy (sso mode) forwards the control plane's
    // 302 + Set-Cookie back to the browser, which stores the login cookie and
    // follows the redirect to the identity provider.
    window.location.assign(
      `/api/fluidbox/auth/login/${encodeURIComponent(slug)}/start?redirect_to=${encodeURIComponent(redirectTo)}`
    );
  };

  return (
    <div style={{ minHeight: "70vh", display: "grid", placeItems: "center", padding: "48px 16px" }}>
      <form className="panel pad" style={{ width: "100%", maxWidth: 380 }} onSubmit={submit}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 18 }}>
          <span className="wordmark">fluidbox</span>
          <span className="product-label">control plane</span>
        </div>

        <h1 className="title" style={{ fontSize: 20, margin: 0 }}>
          Sign in
        </h1>
        <div className="sub" style={{ marginTop: 4, marginBottom: 20 }}>
          Enter your organization to continue to your identity provider.
        </div>

        <label className="field" style={{ display: "block" }}>
          <span className="lab">Organization</span>
          <input
            className="inp"
            style={{ width: "100%", marginTop: 6 }}
            name="org"
            value={org}
            onChange={(e) => setOrg(e.target.value)}
            placeholder="acme"
            autoFocus
            autoComplete="organization"
            autoCapitalize="none"
            spellCheck={false}
          />
        </label>

        <button
          type="submit"
          className="btn primary"
          style={{ width: "100%", marginTop: 20 }}
          disabled={busy || org.trim() === ""}
        >
          {busy ? "Redirecting…" : "Continue"}
        </button>
      </form>
    </div>
  );
}
