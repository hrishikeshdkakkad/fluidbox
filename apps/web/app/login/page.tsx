import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { sanitizeNext, SESSION_COOKIE } from "../lib/auth-gate";
import { webMode } from "../lib/proxy-auth";
import LoginForm from "./login-form";

// Evaluate per request (not at build): the mode is read from the runtime env,
// exactly like the proxy route, so a build produced in one mode never bakes a
// stale redirect for a deployment configured in the other.
export const dynamic = "force-dynamic";

// A pre-auth surface: never indexed (robots.txt disallows it too).
export const metadata = {
  title: "Sign in",
  robots: { index: false, follow: false },
};

const API = process.env.FLUIDBOX_API_URL || "http://127.0.0.1:8787";

/** Is the browser's session cookie a LIVE session? Asked of the control plane
 *  (the only authority), forwarding exactly the one session cookie. Errors and
 *  timeouts answer false: the form still renders, and submitting it surfaces
 *  whatever is actually wrong — never a redirect loop into a dead app. */
async function sessionIsLive(cookieValue: string): Promise<boolean> {
  try {
    const res = await fetch(`${API}/v1/auth/me`, {
      headers: { cookie: `${SESSION_COOKIE}=${cookieValue}` },
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Server boundary for /login. In admin (single-tenant / local) mode there is NO
 * login UI — the operator authenticates with the admin token — so /login
 * redirects to /app server-side, before any client code loads (proxy.ts answers
 * first for full navigations; this guard remains for anything the matcher
 * misses). In sso mode the page is session-aware: a browser that already holds
 * a live session is sent back into the app (to `?next=` when present — the
 * deep link the 401 bounce or the navigation gate recorded), and only a
 * sessionless browser sees the neutral org-entry form. The mode is deployment
 * config (FLUIDBOX_WEB_MODE), read here in a server component; the form itself
 * stays a client component.
 */
export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string; error?: string }>;
}) {
  if (webMode(process.env.FLUIDBOX_WEB_MODE) === "admin") {
    redirect("/app");
  }
  const params = await searchParams;
  const next = sanitizeNext(params.next);
  const session = (await cookies()).get(SESSION_COOKIE)?.value;
  if (session && (await sessionIsLive(session))) {
    redirect(next);
  }
  // The control plane redirects its neutral refusal here (login.rs
  // `neutral_unavailable`). The parameter is untrusted, so it is NARROWED to a
  // known token rather than passed through — the form renders fixed copy for
  // that token and nothing at all for anything else. Never render the raw
  // value: it is attacker-controlled text on a pre-auth page.
  const error = params.error === "unavailable" ? "unavailable" : null;
  return <LoginForm redirectTo={next} error={error} />;
}
