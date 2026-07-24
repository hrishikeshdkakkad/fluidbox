import { describe, expect, it } from "vitest";
import { gateDecision, sanitizeNext, SESSION_COOKIE } from "./auth-gate";

// The server-side navigation gate (proxy.ts is the thin adapter; this module
// carries the decisions). Mirrors the proxy-auth.ts pattern: pure, unit-tested
// security-adjacent logic, framework wiring kept trivial.

describe("sanitizeNext", () => {
  it("accepts plain local paths (with query and fragment)", () => {
    for (const ok of ["/", "/agents", "/sessions/123?tab=events", "/a/b#frag"]) {
      expect(sanitizeNext(ok)).toBe(ok);
    }
  });

  it("falls back to / for every escape class", () => {
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
      expect(sanitizeNext(bad)).toBe("/");
    }
  });
});

describe("gateDecision — admin mode", () => {
  it("redirects /login into the app (no login UI in admin mode)", () => {
    expect(
      gateDecision({ mode: "admin", pathname: "/login", search: "", hasSession: false })
    ).toEqual({ kind: "to-app" });
  });

  it("passes every other route untouched", () => {
    for (const pathname of ["/", "/agents", "/sessions/x"]) {
      expect(
        gateDecision({ mode: "admin", pathname, search: "", hasSession: false })
      ).toEqual({ kind: "pass" });
    }
  });
});

describe("gateDecision — sso mode", () => {
  it("sends a sessionless browser to /login, carrying the intended path", () => {
    expect(
      gateDecision({
        mode: "sso",
        pathname: "/sessions/abc",
        search: "?tab=events",
        hasSession: false,
      })
    ).toEqual({ kind: "to-login", next: "/sessions/abc?tab=events" });
  });

  it("omits the next param for the root path (nothing to restore)", () => {
    expect(
      gateDecision({ mode: "sso", pathname: "/", search: "", hasSession: false })
    ).toEqual({ kind: "to-login", next: "/" });
  });

  it("passes when a session cookie is present (presence only — the control plane validates)", () => {
    expect(
      gateDecision({ mode: "sso", pathname: "/agents", search: "", hasSession: true })
    ).toEqual({ kind: "pass" });
  });

  it("never gates /login itself (the page is session-aware; avoids redirect loops)", () => {
    for (const hasSession of [true, false]) {
      expect(
        gateDecision({ mode: "sso", pathname: "/login", search: "", hasSession })
      ).toEqual({ kind: "pass" });
    }
  });
});

describe("SESSION_COOKIE", () => {
  it("names the browser session cookie exactly (allowlist twin in proxy-auth.ts)", () => {
    expect(SESSION_COOKIE).toBe("__Host-fbx_web");
  });
});
