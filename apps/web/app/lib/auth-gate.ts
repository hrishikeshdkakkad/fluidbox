// Server-side navigation gate for the dashboard (the decisions behind
// proxy.ts). Extracted into a plain, side-effect-free module — the same
// pattern as proxy-auth.ts — so the auth-adjacent routing logic carries unit
// tests while the framework adapter stays a few trivial lines.
//
// This gate is a UX boundary, NOT an authorization boundary: it checks cookie
// PRESENCE only. The control plane validates every session on every API call;
// an expired or forged cookie sails past this gate and is then bounced by the
// api.ts 401 handler. What the gate buys is the correct first paint — an
// anonymous browser in sso mode never renders the app shell, and /login in
// admin mode never renders a form that has no backend.
//
// 2026-07-30 public-site split: the dashboard lives under /app/*; everything
// else on this origin (marketing pages, /docs, /changelog…) is public by
// construction, so the gate's question is no longer "which routes are public"
// but "is this an /app navigation without a session". The WorkOS web-tier
// gate (lib/web-auth.ts) composes with — never replaces — these decisions.

/** The browser session cookie (sso mode). Must match the proxy allowlist's
 *  exact-name entry in proxy-auth.ts and the control plane's cookie name. */
export const SESSION_COOKIE = "__Host-fbx_web";

/** The application home — where "into the app" means after the /app move. */
export const APP_HOME = "/app";

/** Clamp a login-return path to a same-origin absolute path. Anything else —
 *  protocol-relative (`//`), backslash variants browsers normalize to slashes,
 *  absolute URLs, schemes — falls back to the app home. A pre-filter only: the
 *  control plane's `validate_redirect_to` re-validates server-side
 *  (dot-segments, encoded escapes, control chars) before any redirect is
 *  issued. */
export function sanitizeNext(raw: string | null | undefined): string {
  if (!raw) return APP_HOME;
  if (!raw.startsWith("/")) return APP_HOME;
  if (raw.startsWith("//") || raw.startsWith("/\\")) return APP_HOME;
  return raw;
}

/** Is this navigation inside the authenticated application area? Exact-prefix
 *  with the slash guard so `/apple` never gates. */
export function isAppPath(pathname: string): boolean {
  return pathname === "/app" || pathname.startsWith("/app/");
}

export type GateDecision =
  | { kind: "pass" }
  | { kind: "to-login"; next: string }
  | { kind: "to-app" };

/** Where a page navigation should go, given the deployment mode and whether
 *  the browser carries a fluidbox session cookie.
 *
 *    both  — /api/* is never redirected: those are fetches, and every API
 *            route authenticates each call itself (a redirect would break the
 *            401 handling in api.ts and stream consumers).
 *    admin — /login redirects into the app (there is no login UI; the operator
 *            authenticates via the server-injected admin token). Everything
 *            else passes — including /app, which in admin mode is open by
 *            design unless the WorkOS web-tier gate is enabled.
 *    sso   — a sessionless browser navigating anywhere under /app is sent to
 *            /login with the intended path in `next` (restored after the IdP
 *            round-trip). Marketing and docs routes pass: public by
 *            construction. /login itself always passes: the page is
 *            session-aware (it validates a present cookie against
 *            /v1/auth/me and redirects), and gating it here on mere cookie
 *            presence would loop an expired session between /app and /login
 *            forever. */
export function gateDecision(input: {
  mode: "admin" | "sso";
  pathname: string;
  search: string;
  hasSession: boolean;
}): GateDecision {
  const { mode, pathname, search, hasSession } = input;
  if (pathname.startsWith("/api/")) return { kind: "pass" };
  if (mode === "admin") {
    return pathname === "/login" ? { kind: "to-app" } : { kind: "pass" };
  }
  if (pathname === "/login") return { kind: "pass" };
  if (isAppPath(pathname) && !hasSession) {
    return { kind: "to-login", next: `${pathname}${search}` };
  }
  return { kind: "pass" };
}
