import { NextResponse, type NextRequest } from "next/server";
import { gateDecision, APP_HOME, SESSION_COOKIE } from "./app/lib/auth-gate";
import { webMode } from "./app/lib/proxy-auth";
import { hintSetCookie } from "./app/lib/session-hint";
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
  const hasSession = request.cookies.has(SESSION_COOKIE);

  // The public pages are statically generated, so they cannot ask the server
  // who you are. This stamps a NON-CREDENTIAL boolean (see lib/session-hint)
  // that a pre-paint script reads, which is what lets the marketing header
  // show "Dashboard" instead of "Sign in" with no flash and without making
  // every marketing page dynamic. Applied to whichever response we return.
  const stamp = <T extends NextResponse>(response: T, signedIn: boolean): T => {
    // append, not set: the WorkOS path already attaches its own Set-Cookie
    // headers to this response and they must all survive.
    response.headers.append("set-cookie", hintSetCookie(signedIn));
    return response;
  };

  const decision = gateDecision({ mode: MODE, pathname, search, hasSession });
  if (decision.kind === "to-app") {
    return stamp(NextResponse.redirect(new URL(APP_HOME, request.url)), hasSession);
  }
  if (decision.kind === "to-login") {
    const url = new URL("/login", request.url);
    if (decision.next !== APP_HOME) url.searchParams.set("next", decision.next);
    // Reaching /login means the session did not satisfy the gate, so clear the
    // hint too — otherwise a lapsed session leaves the public header still
    // claiming you are signed in.
    return stamp(NextResponse.redirect(url), false);
  }

  if (!WORKOS) return stamp(NextResponse.next(), hasSession);

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
    return stamp(handleAuthkitProxy(request, headers, { redirect: authorizationUrl }), false);
  }
  // Session-refresh cookies (and the headers withAuth() consumes in server
  // components / route handlers) ride every response, public pages included.
  // In workos mode the live AuthKit user is the truth for the hint, not the
  // fluidbox session cookie.
  return stamp(handleAuthkitProxy(request, headers), !!session.user);
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
