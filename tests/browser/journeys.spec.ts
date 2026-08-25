import { test, expect, type Page } from "@playwright/test";

const API = process.env.API_URL ?? "https://api.platform.fluidzero.ai";
const ORG = process.env.ORG_SLUG ?? "fluidzero";
const EMAIL = process.env.TEST_EMAIL ?? "";
const PASSWORD = process.env.TEST_PASSWORD ?? "";
const HAS_CREDS = Boolean(EMAIL && PASSWORD);

// ─── Public surface ────────────────────────────────────────────────────────

test.describe("public site", () => {
  test("marketing page renders", async ({ page }) => {
    const res = await page.goto("/");
    expect(res?.status(), "the marketing page must answer 200").toBe(200);
    // A real render, not a framework error page. Next.js serves its error
    // boundary with a 200, so status alone proves nothing.
    await expect(page.locator("body")).not.toContainText("Application error");
    await expect(page).toHaveTitle(/.+/);
  });

  test("served over HTTPS with HSTS", async ({ page }) => {
    const res = await page.goto("/");
    expect(page.url()).toMatch(/^https:/);
    const hsts = res?.headers()["strict-transport-security"];
    expect(hsts, "HSTS must be set on an origin that issues session cookies").toBeTruthy();
  });

  test("docs are reachable", async ({ page }) => {
    const res = await page.goto("/docs");
    expect(res?.status()).toBeLessThan(400);
  });
});

// ─── Negative auth, in a real browser ──────────────────────────────────────

test.describe("negative authentication", () => {
  test("/app is not reachable without a session", async ({ page }) => {
    await page.goto("/app");
    // Either we land on the login page or we are still challenged for one.
    // What must NOT happen is the dashboard shell rendering.
    await page.waitForLoadState("networkidle");
    const url = page.url();
    const onLogin = /\/login|\/sign-in|auth0\.com|\/callback/.test(url);
    expect(onLogin, `expected a login redirect, got ${url}`).toBeTruthy();
  });

  test("the API refuses an anonymous caller", async ({ request }) => {
    const res = await request.get(`${API}/v1/sessions`, { failOnStatusCode: false });
    expect([401, 403]).toContain(res.status());
  });

  test("the API refuses a forged bearer token", async ({ request }) => {
    const res = await request.get(`${API}/v1/sessions`, {
      headers: { Authorization: "Bearer fbx_pat_not-a-real-token" },
      failOnStatusCode: false,
    });
    expect([401, 403]).toContain(res.status());
  });

  test("health is public and does not leak configuration", async ({ request }) => {
    const res = await request.get(`${API}/v1/health`, { failOnStatusCode: false });
    expect(res.status()).toBe(200);
    const body = (await res.text()).toLowerCase();
    for (const leak of ["postgres://", "password", "secret", "bearer", "sk-"]) {
      expect(body, `health must not contain ${leak}`).not.toContain(leak);
    }
  });
});

// ─── The rewrite that makes __Host- cookies possible ───────────────────────

test.describe("dashboard origin proxies the control plane", () => {
  test("/v1/health answers on the DASHBOARD origin", async ({ page }) => {
    // This is the load-bearing property of the whole topology: the OIDC
    // callback must land on the same origin as the dashboard, because __Host-
    // cookies are host-locked and the control plane refuses cookie-
    // authenticated writes whose Origin is not an exact match. Driven through
    // a real browser deliberately - it is also what proves Vercel's Attack
    // Challenge Mode does not block the path.
    const res = await page.goto("/v1/health");
    expect(res?.status(), "the /v1 rewrite must reach the control plane").toBe(200);
    await expect(page.locator("body")).toContainText(/ok|healthy|status/i);
  });
});

// ─── Authenticated journey ─────────────────────────────────────────────────

async function signIn(page: Page) {
  await page.goto(`/login?org=${ORG}`);
  await page.waitForLoadState("networkidle");

  const slug = page.locator('input[name="org"], input[name="slug"], #org, #slug').first();
  if (await slug.isVisible().catch(() => false)) {
    await slug.fill(ORG);
    await page.locator('button[type="submit"], input[type="submit"]').first().click();
  }
  await page.waitForURL(/auth0\.com|\/authorize/, { timeout: 30_000 });

  await page.locator('input[name="username"], input[name="email"], input[type="email"]').first().fill(EMAIL);
  await page.locator('input[name="password"], input[type="password"]').first().fill(PASSWORD);
  await page.locator('button[type="submit"]').first().click();

  // Consent screen, first login only.
  const accept = page.locator('button[value="accept"], #allow');
  if (await accept.isVisible({ timeout: 5_000 }).catch(() => false)) await accept.click();

  await page.waitForURL(/\/app/, { timeout: 45_000 });
}

test.describe("authenticated journey", () => {
  test.skip(!HAS_CREDS, "TEST_EMAIL / TEST_PASSWORD not set");

  test("Auth0 login lands on the dashboard", async ({ page }) => {
    await signIn(page);
    expect(page.url()).toContain("/app");
    await expect(page.locator("body")).not.toContainText("Application error");
  });

  test("the session cookie carries the attributes the model depends on", async ({ page, context }) => {
    await signIn(page);
    const cookies = await context.cookies();
    const session = cookies.find((c) => c.name.startsWith("__Host-fbx_web"));
    expect(session, "a __Host-fbx_web session cookie must be set").toBeTruthy();
    // __Host- is DEFINED as Secure + Path=/ + no Domain. A conforming browser
    // silently DISCARDS one that breaks the rule, so getting these wrong looks
    // like "login did nothing" rather than like a cookie error.
    expect(session!.secure, "__Host- requires Secure").toBe(true);
    expect(session!.path, "__Host- requires Path=/").toBe("/");
    expect(session!.httpOnly, "a session cookie must be HttpOnly").toBe(true);
    expect(session!.domain.replace(/^\./, "")).toBe(new URL(page.url()).hostname);
  });

  test("an authenticated API call succeeds through the proxy", async ({ page }) => {
    await signIn(page);
    // Report the BODY on failure. A bare status tells you the call failed but
    // not whether it was the cookie, the CSRF header, or authorization - and
    // those have completely different fixes.
    const res = await page.evaluate(async () => {
      // /api/fluidbox/sessions, NOT /api/fluidbox/v1/sessions. The proxy
      // route prepends /v1 itself (`${API}/v1/${path.join("/")}`), so
      // including it here produces /v1/v1/sessions and a bare 404 with an
      // empty body - which looks like an auth problem and is not one.
      const r = await fetch("/api/fluidbox/sessions", {
        credentials: "include",
        headers: { "x-fluidbox-csrf": "1" },
      });
      return { status: r.status, body: (await r.text()).slice(0, 200) };
    });
    expect(res.status, `proxied API call returned ${res.status}: ${res.body}`).toBeLessThan(400);
  });

  test("logout clears the session and re-protects /app", async ({ page, context }) => {
    await signIn(page);

    // POST, not a navigation. /v1/auth/logout is a POST route guarded by the
    // CSRF header - a GET gets 405 and the session survives, which reads as
    // "logout is broken" when the request was simply the wrong shape.
    const status = await page.evaluate(async () => {
      // Exactly what the dashboard does (app/lib/api.ts): POST through the
      // proxy with the CSRF header.
      const r = await fetch("/api/fluidbox/auth/logout", {
        method: "POST",
        credentials: "include",
        headers: { "x-fluidbox-csrf": "1" },
      });
      return r.status;
    });
    expect(status, "POST /v1/auth/logout must be accepted").toBeLessThan(400);

    // Require the cookie to be GONE, not merely empty. `?? ""` would pass for a
    // cookie that is still present with an empty value - and the navigation
    // gate uses cookies.has(), which is TRUE for exactly that case, so the weak
    // form would report a pass on a session that still gates as signed-in.
    const after = (await context.cookies()).find((c) => c.name === "__Host-fbx_web");
    expect(after, `the session cookie must be removed, got ${JSON.stringify(after)}`).toBeUndefined();

    // CACHE-BUST the navigation. We are already ON /app, and Chromium will
    // happily satisfy `goto` for the same URL from its cache without issuing a
    // request - so the server-side gate never runs and the page appears
    // unprotected when it is not. A unique query string forces a real trip.
    //
    // The gate also redirects mid-navigation, which Chromium reports as
    // ERR_ABORTED on the original goto; that is the redirect working.
    const bust = `/app?_=${process.hrtime.bigint()}`;
    await page.goto(bust, { waitUntil: "domcontentloaded" }).catch(() => {});
    await page.waitForLoadState("domcontentloaded").catch(() => {});
    expect(
      /\/login|\/sign-in|auth0\.com/.test(page.url()),
      `/app must be protected again, landed on ${page.url()}`
    ).toBeTruthy();
  });
});
