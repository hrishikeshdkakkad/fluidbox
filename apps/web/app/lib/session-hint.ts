// A pre-paint hint that the browser holds a session — so the PUBLIC pages can
// show "Dashboard" instead of "Sign in" without giving up static rendering.
//
// The problem: /docs, /pricing and the rest are statically generated, and the
// real session cookie (__Host-fbx_web) is HttpOnly, so neither the server
// render nor client JS can see it. Reading it server-side would make every
// marketing page dynamic — losing static generation on the one surface where
// SEO and TTFB matter most. Fetching /auth/me on the client would flash
// "Sign in" and then swap, which is the opposite of seamless.
//
// So proxy.ts — which already runs on every navigation and already reads the
// session cookie — mirrors its PRESENCE into a plain boolean cookie, and the
// script below stamps `data-session` on <html> before first paint. The header
// renders both variants and CSS shows the matching one. Same mechanism as
// THEME_INIT_SCRIPT in ./theme.
//
// SECURITY: this cookie is a UI hint and NEVER a credential. It carries no
// identity, grants nothing, and no authorization path reads it. Every
// authorization decision stays in the control plane behind the HttpOnly
// session cookie. Forging it changes only which button a stranger sees: /app
// still redirects to /login and the API still answers 401.

export const SESSION_HINT_COOKIE = "fbx_ui";

export type SessionHint = "in" | "out";

/** Only an exact "1" counts. Anything else — absent, empty, stale, hostile —
 *  reads as signed out, so the failure mode is "offered a Sign in link". */
export function hintFromCookieValue(raw: string | undefined): SessionHint {
  return raw === "1" ? "in" : "out";
}

/**
 * The Set-Cookie value proxy.ts emits. Not HttpOnly on purpose: the pre-paint
 * script has to read it. Lax so it survives ordinary top-level navigation from
 * an external link without riding cross-site subrequests.
 */
export function hintSetCookie(hasSession: boolean): string {
  const base = `${SESSION_HINT_COOKIE}=`;
  const attrs = "Path=/; SameSite=Lax";
  return hasSession
    ? `${base}1; ${attrs}; Max-Age=${60 * 60 * 24 * 400}`
    : `${base}; ${attrs}; Max-Age=0`;
}

/**
 * Runs in <head> before first paint. Mirrors ./theme's THEME_INIT_SCRIPT:
 * self-contained, no imports, and wrapped in try/catch because a throw here
 * would blank the page.
 *
 * The regex anchors the cookie name to a boundary so `other_fbx_ui=1` cannot
 * masquerade as `fbx_ui=1`.
 */
export const SESSION_HINT_INIT_SCRIPT = `(()=>{try{const n=${JSON.stringify(
  SESSION_HINT_COOKIE
)};const m=new RegExp("(?:^|; *)"+n+"=([^;]*)").exec(document.cookie||"");document.documentElement.dataset.session=m&&m[1]==="1"?"in":"out"}catch{}})()`;
