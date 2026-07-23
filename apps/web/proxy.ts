import { NextResponse, type NextRequest } from "next/server";
import { gateDecision, SESSION_COOKIE } from "./app/lib/auth-gate";
import { webMode } from "./app/lib/proxy-auth";

// Server-side navigation gate (Next 16 renamed `middleware` to `proxy`). All
// decisions live in app/lib/auth-gate.ts where they are unit-tested; this file
// only adapts them to the request/response types.
//
// Resolved at module scope like the API proxy route: the mode is static
// deployment configuration, and an invalid FLUIDBOX_WEB_MODE takes the app
// down loudly instead of silently serving the admin shell.
const MODE = webMode(process.env.FLUIDBOX_WEB_MODE);

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const decision = gateDecision({
    mode: MODE,
    pathname,
    search,
    hasSession: request.cookies.has(SESSION_COOKIE),
  });
  if (decision.kind === "to-app") {
    return NextResponse.redirect(new URL("/", request.url));
  }
  if (decision.kind === "to-login") {
    const url = new URL("/login", request.url);
    if (decision.next !== "/") url.searchParams.set("next", decision.next);
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  // Page navigations only. Excluded on purpose:
  //   api  — the control-plane proxy (/api/fluidbox/*) authenticates every call
  //          itself; redirecting a fetch to /login would break the 401 handler.
  //   v1   — the sso-mode rewrite surface (next.config.ts): the OIDC callback
  //          rides /v1/auth/callback on THIS origin, before any session exists.
  //   _next/static, _next/image, favicon.ico — assets.
  matcher: ["/((?!api|v1|_next/static|_next/image|favicon.ico).*)"],
};
