import { describe, expect, it } from "vitest";
import {
  APP_HOME,
  gateDecision,
  isAppPath,
  sanitizeNext,
  SESSION_COOKIE,
} from "./auth-gate";

// The server-side navigation gate (proxy.ts is the thin adapter; this module
// carries the decisions). Mirrors the proxy-auth.ts pattern: pure, unit-tested
// security-adjacent logic, framework wiring kept trivial.

describe("sanitizeNext", () => {
  it("accepts plain local paths (with query and fragment)", () => {
    for (const ok of ["/app", "/app/agents", "/app/sessions/123?tab=events", "/a/b#frag"]) {
      expect(sanitizeNext(ok)).toBe(ok);
    }
  });

  it("falls back to the app home for every escape class", () => {
    for (const bad of [
      null,
      undefined,
      "",
      "//evil.example", // protocol-relative
      "/\\evil.example", // backslash variant browsers normalize to //
      "http://evil.example",
      "https://evil.example",
      "javascript:alert(1)",
      "relative/path",
      "\\/\\/evil",
    ]) {
      expect(sanitizeNext(bad)).toBe(APP_HOME);
    }
  });
});

describe("isAppPath", () => {
  it("matches /app and everything under it", () => {
    for (const p of ["/app", "/app/agents", "/app/sessions/x?y", "/app/"]) {
      expect(isAppPath(p.split("?")[0])).toBe(true);
    }
  });

  it("never matches lookalikes or public routes", () => {
    for (const p of ["/apple", "/application", "/", "/docs", "/docs/app", "/login"]) {
      expect(isAppPath(p)).toBe(false);
    }
  });
});

describe("gateDecision — both modes", () => {
  it("never redirects API fetches (each route authenticates itself)", () => {
    for (const mode of ["admin", "sso"] as const) {
      expect(
        gateDecision({
          mode,
          pathname: "/api/fluidbox/approvals",
          search: "",
          hasSession: false,
        })
      ).toEqual({ kind: "pass" });
    }
  });
});

describe("gateDecision — admin mode", () => {
  it("redirects /login into the app (no login UI in admin mode)", () => {
    expect(
      gateDecision({ mode: "admin", pathname: "/login", search: "", hasSession: false })
    ).toEqual({ kind: "to-app" });
  });

  it("passes every other route untouched — public and app alike", () => {
    for (const pathname of ["/", "/docs", "/app", "/app/agents", "/app/sessions/x"]) {
      expect(
        gateDecision({ mode: "admin", pathname, search: "", hasSession: false })
      ).toEqual({ kind: "pass" });
    }
  });
});

describe("gateDecision — sso mode", () => {
  it("sends a sessionless /app navigation to /login, carrying the intended path", () => {
    expect(
      gateDecision({
        mode: "sso",
        pathname: "/app/sessions/abc",
        search: "?tab=events",
        hasSession: false,
      })
    ).toEqual({ kind: "to-login", next: "/app/sessions/abc?tab=events" });
  });

  it("gates the app home itself", () => {
    expect(
      gateDecision({ mode: "sso", pathname: "/app", search: "", hasSession: false })
    ).toEqual({ kind: "to-login", next: "/app" });
  });

  it("passes when a session cookie is present (presence only — the control plane validates)", () => {
    expect(
      gateDecision({ mode: "sso", pathname: "/app/agents", search: "", hasSession: true })
    ).toEqual({ kind: "pass" });
  });

  it("never gates /login itself (the page is session-aware; avoids redirect loops)", () => {
    for (const hasSession of [true, false]) {
      expect(
        gateDecision({ mode: "sso", pathname: "/login", search: "", hasSession })
      ).toEqual({ kind: "pass" });
    }
  });

  it("passes every public route without a session (marketing + docs are public by construction)", () => {
    for (const pathname of [
      "/",
      "/product",
      "/open-source",
      "/security",
      "/changelog",
      "/pricing",
      "/docs",
      "/docs/getting-started",
      "/docs/api/reference",
    ]) {
      expect(
        gateDecision({ mode: "sso", pathname, search: "", hasSession: false })
      ).toEqual({ kind: "pass" });
    }
  });

  it("does not let the /app prefix leak onto sibling routes", () => {
    // "/apple" or a lookalike must never gate — the prefix check needs the slash.
    expect(
      gateDecision({ mode: "sso", pathname: "/apple", search: "", hasSession: false })
    ).toEqual({ kind: "pass" });
  });
});

describe("SESSION_COOKIE", () => {
  it("names the browser session cookie exactly (allowlist twin in proxy-auth.ts)", () => {
    expect(SESSION_COOKIE).toBe("__Host-fbx_web");
  });
});
