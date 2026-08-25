import { defineConfig, devices } from "@playwright/test";

// Browser journeys against the DEPLOYED system, not a dev server. These tests
// exist to prove things a curl cannot: that a real browser can complete the
// Auth0 round trip, that the session cookie it receives has the attributes the
// security model depends on, and that Vercel's Attack Challenge Mode (which
// 429s every non-JS client) does not break the login flow.
//
//   BASE_URL      dashboard origin       default https://platform.fluidzero.ai
//   API_URL       control-plane origin   default https://api.platform.fluidzero.ai
//   ORG_SLUG      org to sign in to      default fluidzero
//   TEST_EMAIL / TEST_PASSWORD  an Auth0 user in that org. When absent, the
//                 authenticated journeys SKIP rather than fail - a missing test
//                 credential is not a broken deployment, and a suite that fails
//                 for the wrong reason trains people to ignore it.

export default defineConfig({
  testDir: ".",
  // Serial. These share one deployment; a parallel login storm against a real
  // IdP is a good way to get rate-limited and learn nothing.
  workers: 1,
  fullyParallel: false,
  timeout: 90_000,
  expect: { timeout: 20_000 },
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]],
  use: {
    baseURL: process.env.BASE_URL ?? "https://platform.fluidzero.ai",
    // Evidence for the runs that matter: the failures.
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    ignoreHTTPSErrors: false, // a bad certificate is a REAL failure here
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
