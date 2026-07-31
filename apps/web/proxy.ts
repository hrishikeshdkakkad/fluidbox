import { NextResponse, type NextRequest } from "next/server";
import { gateDecision, APP_HOME, SESSION_COOKIE } from "./app/lib/auth-gate";
import { webMode } from "./app/lib/proxy-auth";
import {
  assertAuthModeCompatible,
  requireWorkosEnv,
  webAuthMode,
  workosGate,
} from "./app/lib/web-auth";

// Server-side navigation gate (Next 16 renamed `middleware` to `proxy`). All
// decisions live in app/lib/auth-gate.ts and app/lib/web-auth.ts where they
// are unit-tested; this file only adapts them to the request/response types.
//
// Resolved at module scope like the API proxy route: both modes are static
// deployment configuration, and an invalid or incomplete combination takes
// the app down loudly at cold start instead of silently serving an
// unprotected /app (or the admin shell in a hosted deployment).
const MODE = webMode(process.env.FLUIDBOX_WEB_MODE);
const AUTH = webAuthMode(process.env.FLUIDBOX_WEB_AUTH);
assertAuthModeCompatible(MODE, AUTH);
const WORKOS = AUTH === "workos" ? requireWorkosEnv(process.env) : null;

export async function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const decision = gateDecision({
    mode: MODE,
    pathname,
    search,
    hasSession: request.cookies.has(SESSION_COOKIE),
  });
  if (decision.kind === "to-app") {
    return NextResponse.redirect(new URL(APP_HOME, request.url));
  }
  if (decision.kind === "to-login") {
    const url = new URL("/login", request.url);
    if (decision.next !== APP_HOME) url.searchParams.set("next", decision.next);
    return NextResponse.redirect(url);
  }

  if (!WORKOS) return NextResponse.next();

  // WorkOS web tier (FLUIDBOX_WEB_AUTH=workos). Imported lazily so `none`
  // deployments never load the SDK (which reads its env at module load).
  // The redirect URI is passed explicitly from a runtime env read — the
  // SDK's own NEXT_PUBLIC_ lookup is inlined at build time, which would pin
  // a Docker image built without the variable (deploy/web.Dockerfile note).
  const { authkit, handleAuthkitProxy } = await import("@workos-inc/authkit-nextjs");
  const { session, headers, authorizationUrl } = await authkit(request, {
    redirectUri: WORKOS.redirectUri,
  });
  if (workosGate({ pathname, hasUser: !!session.user }) === "redirect-to-sign-in") {
    if (!authorizationUrl) {
      // Fail closed: an /app navigation that needs authentication but has no
      // authorization URL (SDK misbehavior, upstream outage) must never fall
      // through to the app shell.
      return new NextResponse("authentication unavailable", { status: 503 });
    }
    return handleAuthkitProxy(request, headers, { redirect: authorizationUrl });
  }
  // Session-refresh cookies (and the headers withAuth() consumes in server
  // components / route handlers) ride every response, public pages included.
  return handleAuthkitProxy(request, headers);
}

export const config = {
  // Runs on page navigations AND /api/fluidbox (the control-plane proxy):
  // gateDecision passes every /api/* path untouched — fetches are never
  // redirected — but routing them through here is what lets the WorkOS
  // web-tier gate stamp its session headers so the API route can validate
  // the session server-side on every call. Excluded on purpose:
  //   v1   — the sso-mode rewrite surface (next.config.ts): the OIDC callback
  //          rides /v1/auth/callback on THIS origin, before any session exists.
  //   _next/static, _next/image, favicon.ico — assets.
  matcher: ["/((?!v1|_next/static|_next/image|favicon.ico).*)"],
};
