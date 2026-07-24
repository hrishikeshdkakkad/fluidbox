// Security-boundary helpers for the same-origin control-plane proxy
// (app/api/fluidbox/[...path]/route.ts). Extracted into a plain, side-effect-free
// module so the two decisions that gate operator authority carry unit tests:
//
//   - webMode: which credential mode this deployment runs in (admin token vs
//     cookie passthrough), chosen ONLY by FLUIDBOX_WEB_MODE, never per request.
//   - the cookie allowlist: exactly which browser cookies may ride to the
//     control plane in sso mode. Nothing outside the allowlist is forwarded.
//
// route.ts imports these; behavior is byte-for-byte what it had inline.

/** The deployment credential mode, chosen ONLY by FLUIDBOX_WEB_MODE.
 *
 *  ONLY an absent variable (undefined) stays "admin" — the documented local
 *  default. "admin" and "sso" select their modes. ANY OTHER value THROWS,
 *  INCLUDING a SET-but-empty string (""): an explicitly blank env var is a
 *  misconfiguration, not the local default, so it fails loudly like a hosted
 *  typo ("SSO", "prod", "ssoo") rather than silently degrading to the
 *  admin-token shell (which would leak operator authority into a multi-user
 *  deployment). route.ts resolves this at module scope, so a bad value takes
 *  the whole proxy down instead of quietly serving admin. */
export function webMode(env: string | undefined): "admin" | "sso" {
  if (env === undefined) return "admin";
  if (env === "admin" || env === "sso") return env;
  throw new Error(
    `FLUIDBOX_WEB_MODE must be "admin" or "sso" (got ${JSON.stringify(env)})`
  );
}

/** Cookies the browser may forward to the control plane in sso mode.
 *  `__Host-fbx_web` matches EXACTLY (the session cookie); the login and switch
 *  families match by their trailing-underscore prefix. A lookalike like
 *  `__Host-fbx_webx` or a prefix-less `__Host-fbx_login` is NOT allowed. */
export function isAllowedCookie(name: string): boolean {
  return (
    name === "__Host-fbx_web" ||
    name.startsWith("__Host-fbx_login_") ||
    name.startsWith("__Host-fbx_switch_")
  );
}

/** Parse a request's raw Cookie header, keep only allowlisted cookies, and
 *  rejoin them. Returns null when there is no Cookie header or nothing survives
 *  the filter, so the caller omits the header entirely rather than forwarding an
 *  empty one (never the raw header). */
export function allowedCookieHeader(req: Request): string | null {
  const raw = req.headers.get("cookie");
  if (!raw) return null;
  const kept = raw
    .split(";")
    .map((pair) => pair.trim())
    .filter((pair) => {
      const eq = pair.indexOf("=");
      const name = eq === -1 ? pair : pair.slice(0, eq);
      return isAllowedCookie(name);
    });
  return kept.length > 0 ? kept.join("; ") : null;
}
