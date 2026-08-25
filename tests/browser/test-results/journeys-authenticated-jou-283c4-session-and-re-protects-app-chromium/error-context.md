# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: journeys.spec.ts >> authenticated journey >> logout clears the session and re-protects /app
- Location: journeys.spec.ts:152:7

# Error details

```
Error: page.evaluate: Execution context was destroyed, most likely because of a navigation
```

# Page snapshot

```yaml
- generic [ref=f3e1]:
  - generic [ref=f3e4]:
    - generic [ref=f3e5]:
      - generic [ref=f3e6]: fluidbox
      - generic [ref=f3e7]: control plane
    - heading "Sign in" [level=1] [ref=f3e8]
    - generic [ref=f3e9]: Enter your organization to continue to your identity provider.
    - generic [ref=f3e10]:
      - generic [ref=f3e11]: Organization
      - textbox "Organization" [active] [ref=f3e12]:
        - /placeholder: acme
    - button "Continue" [disabled] [ref=f3e13]
  - alert [ref=f3e14]
```

# Test source

```ts
  95  |     await page.locator('button[type="submit"], input[type="submit"]').first().click();
  96  |   }
  97  |   await page.waitForURL(/auth0\.com|\/authorize/, { timeout: 30_000 });
  98  | 
  99  |   await page.locator('input[name="username"], input[name="email"], input[type="email"]').first().fill(EMAIL);
  100 |   await page.locator('input[name="password"], input[type="password"]').first().fill(PASSWORD);
  101 |   await page.locator('button[type="submit"]').first().click();
  102 | 
  103 |   // Consent screen, first login only.
  104 |   const accept = page.locator('button[value="accept"], #allow');
  105 |   if (await accept.isVisible({ timeout: 5_000 }).catch(() => false)) await accept.click();
  106 | 
  107 |   await page.waitForURL(/\/app/, { timeout: 45_000 });
  108 | }
  109 | 
  110 | test.describe("authenticated journey", () => {
  111 |   test.skip(!HAS_CREDS, "TEST_EMAIL / TEST_PASSWORD not set");
  112 | 
  113 |   test("Auth0 login lands on the dashboard", async ({ page }) => {
  114 |     await signIn(page);
  115 |     expect(page.url()).toContain("/app");
  116 |     await expect(page.locator("body")).not.toContainText("Application error");
  117 |   });
  118 | 
  119 |   test("the session cookie carries the attributes the model depends on", async ({ page, context }) => {
  120 |     await signIn(page);
  121 |     const cookies = await context.cookies();
  122 |     const session = cookies.find((c) => c.name.startsWith("__Host-fbx_web"));
  123 |     expect(session, "a __Host-fbx_web session cookie must be set").toBeTruthy();
  124 |     // __Host- is DEFINED as Secure + Path=/ + no Domain. A conforming browser
  125 |     // silently DISCARDS one that breaks the rule, so getting these wrong looks
  126 |     // like "login did nothing" rather than like a cookie error.
  127 |     expect(session!.secure, "__Host- requires Secure").toBe(true);
  128 |     expect(session!.path, "__Host- requires Path=/").toBe("/");
  129 |     expect(session!.httpOnly, "a session cookie must be HttpOnly").toBe(true);
  130 |     expect(session!.domain.replace(/^\./, "")).toBe(new URL(page.url()).hostname);
  131 |   });
  132 | 
  133 |   test("an authenticated API call succeeds through the proxy", async ({ page }) => {
  134 |     await signIn(page);
  135 |     // Report the BODY on failure. A bare status tells you the call failed but
  136 |     // not whether it was the cookie, the CSRF header, or authorization - and
  137 |     // those have completely different fixes.
  138 |     const res = await page.evaluate(async () => {
  139 |       // /api/fluidbox/sessions, NOT /api/fluidbox/v1/sessions. The proxy
  140 |       // route prepends /v1 itself (`${API}/v1/${path.join("/")}`), so
  141 |       // including it here produces /v1/v1/sessions and a bare 404 with an
  142 |       // empty body - which looks like an auth problem and is not one.
  143 |       const r = await fetch("/api/fluidbox/sessions", {
  144 |         credentials: "include",
  145 |         headers: { "x-fluidbox-csrf": "1" },
  146 |       });
  147 |       return { status: r.status, body: (await r.text()).slice(0, 200) };
  148 |     });
  149 |     expect(res.status, `proxied API call returned ${res.status}: ${res.body}`).toBeLessThan(400);
  150 |   });
  151 | 
  152 |   test("logout clears the session and re-protects /app", async ({ page, context }) => {
  153 |     await signIn(page);
  154 | 
  155 |     // POST, not a navigation. /v1/auth/logout is a POST route guarded by the
  156 |     // CSRF header - a GET gets 405 and the session survives, which reads as
  157 |     // "logout is broken" when the request was simply the wrong shape.
  158 |     const status = await page.evaluate(async () => {
  159 |       // Exactly what the dashboard does (app/lib/api.ts): POST through the
  160 |       // proxy with the CSRF header.
  161 |       const r = await fetch("/api/fluidbox/auth/logout", {
  162 |         method: "POST",
  163 |         credentials: "include",
  164 |         headers: { "x-fluidbox-csrf": "1" },
  165 |       });
  166 |       return r.status;
  167 |     });
  168 |     expect(status, "POST /v1/auth/logout must be accepted").toBeLessThan(400);
  169 | 
  170 |     // POLL for the cookie's removal rather than reading once. Chromium applies
  171 |     // a Set-Cookie from a fetch() asynchronously, so a single immediate read
  172 |     // races it - which is exactly how this test flaked (failed, passed on
  173 |     // retry). A flaky gate is worse than a missing one: it either blocks good
  174 |     // deploys or teaches people to re-run until green.
  175 |     //
  176 |     // Require the cookie to be GONE, not merely empty: the navigation gate uses
  177 |     // cookies.has(), which is TRUE for a present-but-empty cookie, so an
  178 |     // "is it blank" assertion would pass a session that still gates as
  179 |     // signed-in.
  180 |     await expect
  181 |       .poll(
  182 |         async () => (await context.cookies()).some((c) => c.name === "__Host-fbx_web"),
  183 |         { timeout: 15_000, message: "the session cookie must be removed by logout" }
  184 |       )
  185 |       .toBe(false);
  186 | 
  187 |     // Assert the SERVER's decision, not the browser's final URL.
  188 |     //
  189 |     // Navigating and reading page.url() was flaky for reasons that have nothing
  190 |     // to do with the gate: Chromium can satisfy a goto to the URL it is already
  191 |     // on from cache, and the app's client-side router rewrites /app?_=N back to
  192 |     // /app - so the observed URL says little about what the server decided. The
  193 |     // security property is "does the server redirect an unauthenticated /app to
  194 |     // login", and a manual-redirect fetch answers exactly that, deterministically.
> 195 |     const gate = await page.evaluate(async () => {
      |                             ^ Error: page.evaluate: Execution context was destroyed, most likely because of a navigation
  196 |       const r = await fetch(`/app?_=${Date.now()}`, {
  197 |         credentials: "include",
  198 |         redirect: "manual",
  199 |         headers: { "cache-control": "no-cache" },
  200 |       });
  201 |       // A `manual` redirect surfaces as an opaqueredirect response, whose status
  202 |       // is 0 by design - the browser refuses to expose cross-origin redirect
  203 |       // details. `type` is what distinguishes it from a real 200.
  204 |       return { type: r.type, status: r.status };
  205 |     });
  206 |     expect(
  207 |       gate.type === "opaqueredirect" || (gate.status >= 300 && gate.status < 400),
  208 |       `/app must be REDIRECTED for a logged-out session, got type=${gate.type} status=${gate.status}`
  209 |     ).toBeTruthy();
  210 |   });
  211 | });
  212 | 
```