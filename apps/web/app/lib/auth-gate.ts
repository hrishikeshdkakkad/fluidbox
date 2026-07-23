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

/** The browser session cookie (sso mode). Must match the proxy allowlist's
 *  exact-name entry in proxy-auth.ts and the control plane's cookie name. */
export const SESSION_COOKIE = "__Host-fbx_web";

/** Clamp a login-return path to a same-origin absolute path. Anything else —
 *  protocol-relative (`//`), backslash variants browsers normalize to slashes,
 *  absolute URLs, schemes — falls back to "/". A pre-filter only: the control
 *  plane's `validate_redirect_to` re-validates server-side (dot-segments,
 *  encoded escapes, control chars) before any redirect is issued. */
export function sanitizeNext(raw: string | null | undefined): string {
  if (!raw) return "/";
  if (!raw.startsWith("/")) return "/";
  if (raw.startsWith("//") || raw.startsWith("/\\")) return "/";
  return raw;
}

export type GateDecision =
  | { kind: "pass" }
  | { kind: "to-login"; next: string }
  | { kind: "to-app" };

/** Where a page navigation should go, given the deployment mode and whether
 *  the browser carries a session cookie.
 *
 *    admin — /login redirects into the app (there is no login UI; the operator
 *            authenticates via the server-injected admin token). Everything
 *            else passes.
 *    sso   — a sessionless browser is sent to /login with the intended path in
 *            `next` (restored after the IdP round-trip). /login itself always
 *            passes: the page is session-aware (it validates a present cookie
 *            against /v1/auth/me and redirects), and gating it here on mere
 *            cookie presence would loop an expired session between / and
 *            /login forever. */
export function gateDecision(input: {
  mode: "admin" | "sso";
  pathname: string;
  search: string;
  hasSession: boolean;
}): GateDecision {
  const { mode, pathname, search, hasSession } = input;
  if (mode === "admin") {
    return pathname === "/login" ? { kind: "to-app" } : { kind: "pass" };
  }
  if (pathname === "/login") return { kind: "pass" };
  if (!hasSession) return { kind: "to-login", next: `${pathname}${search}` };
  return { kind: "pass" };
}
