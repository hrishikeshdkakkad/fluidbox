// Same-origin proxy to the fluidbox control plane.
//
// The credential behavior is STATIC deployment configuration, chosen by
// FLUIDBOX_WEB_MODE — never inferred per request:
//
//   admin (default, unset) — local/dev, no IdPs. The operator's admin token is
//     injected server-side and never reaches the browser. This path is
//     unchanged from the single-tenant dashboard.
//   sso — hosted/multi-user. There is NO admin token in this environment; the
//     proxy is cookie-passthrough only. It forwards the fluidbox session
//     cookies (allowlist), the CSRF header, and the browser's Origin, and
//     propagates every Set-Cookie the control plane returns back to the browser
//     (each one separately). A missing/invalid cookie fails as 401 — never as
//     operator authority, so a hosted deployment cannot leak operator power.
//
// Both modes stream SSE through untouched.

const API = process.env.FLUIDBOX_API_URL || "http://127.0.0.1:8787";
const MODE = process.env.FLUIDBOX_WEB_MODE === "sso" ? "sso" : "admin";

// Read the operator token ONLY in admin mode. In sso mode this value is never
// dereferenced, so operator authority is absent from the request path even if
// the variable happens to be set in the environment.
const ADMIN_TOKEN =
  MODE === "admin" ? process.env.FLUIDBOX_ADMIN_TOKEN || "" : "";

export const dynamic = "force-dynamic";

/** Cookies the browser may forward to the control plane in sso mode. The raw
 *  Cookie header is parsed and filtered — nothing outside this allowlist rides
 *  along (never the raw header). */
function isAllowedCookie(name: string): boolean {
  return (
    name === "__Host-fbx_web" ||
    name.startsWith("__Host-fbx_login_") ||
    name.startsWith("__Host-fbx_switch_")
  );
}

function allowedCookieHeader(req: Request): string | null {
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

async function forward(req: Request, path: string[]) {
  const url = new URL(req.url);
  const target = `${API}/v1/${path.join("/")}${url.search}`;

  const headers: Record<string, string> = {};
  const ct = req.headers.get("content-type");
  if (ct) headers["content-type"] = ct;
  const lastEventId = req.headers.get("last-event-id");
  if (lastEventId) headers["last-event-id"] = lastEventId;
  const accept = req.headers.get("accept");
  if (accept) headers["accept"] = accept;

  if (MODE === "sso") {
    // Cookie passthrough only — no operator authority in this environment.
    const cookie = allowedCookieHeader(req);
    if (cookie) headers["cookie"] = cookie;
    const csrf = req.headers.get("x-fluidbox-csrf");
    if (csrf) headers["x-fluidbox-csrf"] = csrf;
    // Pass the Origin through as received (the control plane enforces
    // same-origin for cookie-authenticated writes).
    const origin = req.headers.get("origin");
    if (origin) headers["origin"] = origin;
  } else {
    headers["authorization"] = `Bearer ${ADMIN_TOKEN}`;
  }

  const init: RequestInit = { method: req.method, headers };
  if (MODE === "sso") {
    // Login/callback/switch legs return 302s carrying Set-Cookie. Do NOT let
    // the server-side fetch follow them — hand the 302 (and its cookie) back to
    // the browser so it stores the cookie and follows the redirect natively.
    init.redirect = "manual";
  }
  if (req.method !== "GET" && req.method !== "HEAD") {
    init.body = await req.text();
  }

  const upstream = await fetch(target, init);

  // Stream SSE through untouched (both modes).
  const upstreamCt = upstream.headers.get("content-type") || "";
  if (upstreamCt.includes("event-stream")) {
    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        "content-type": "text/event-stream",
        "cache-control": "no-cache, no-transform",
        connection: "keep-alive",
      },
    });
  }

  const body = await upstream.text();

  if (MODE === "admin") {
    // Unchanged single-tenant behavior.
    return new Response(body, {
      status: upstream.status,
      headers: { "content-type": upstreamCt || "application/json" },
    });
  }

  // sso: propagate status, content-type, any redirect Location, and EVERY
  // Set-Cookie header separately (getSetCookie preserves them individually,
  // and append keeps them distinct on the outgoing Response).
  const out = new Headers();
  out.set("content-type", upstreamCt || "application/json");
  const location = upstream.headers.get("location");
  if (location) out.set("location", location);
  for (const cookie of upstream.headers.getSetCookie()) {
    out.append("set-cookie", cookie);
  }
  return new Response(body, { status: upstream.status, headers: out });
}

type Ctx = { params: Promise<{ path: string[] }> };

export async function GET(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function POST(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function PUT(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function PATCH(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function DELETE(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
