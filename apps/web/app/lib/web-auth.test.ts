import { describe, expect, it } from "vitest";
import {
  assertAuthModeCompatible,
  requireWorkosEnv,
  webAuthMode,
  WORKOS_ENV_KEYS,
  workosGate,
} from "./web-auth";

const COMPLETE_ENV = {
  WORKOS_API_KEY: "sk_test_x",
  WORKOS_CLIENT_ID: "client_x",
  WORKOS_COOKIE_PASSWORD: "a".repeat(32),
  NEXT_PUBLIC_WORKOS_REDIRECT_URI: "http://localhost:3000/callback",
};

describe("webAuthMode", () => {
  it("defaults to none only when the variable is ABSENT", () => {
    expect(webAuthMode(undefined)).toBe("none");
  });

  it("accepts the two documented values", () => {
    expect(webAuthMode("none")).toBe("none");
    expect(webAuthMode("workos")).toBe("workos");
  });

  it("throws on anything else, including a set-but-empty string", () => {
    for (const bad of ["", "WORKOS", "work-os", "1", "true", "sso"]) {
      expect(() => webAuthMode(bad)).toThrow(/FLUIDBOX_WEB_AUTH/);
    }
  });
});

describe("assertAuthModeCompatible", () => {
  it("allows admin+none, admin+workos, sso+none", () => {
    expect(() => assertAuthModeCompatible("admin", "none")).not.toThrow();
    expect(() => assertAuthModeCompatible("admin", "workos")).not.toThrow();
    expect(() => assertAuthModeCompatible("sso", "none")).not.toThrow();
  });

  it("refuses sso+workos (two session systems on one origin)", () => {
    expect(() => assertAuthModeCompatible("sso", "workos")).toThrow(
      /mutually exclusive/
    );
  });
});

describe("requireWorkosEnv", () => {
  it("returns only the non-secret subset on a complete environment", () => {
    expect(requireWorkosEnv(COMPLETE_ENV)).toEqual({
      clientId: "client_x",
      redirectUri: "http://localhost:3000/callback",
    });
  });

  it("names every missing variable (and never a value)", () => {
    expect(() => requireWorkosEnv({})).toThrow(
      new RegExp(WORKOS_ENV_KEYS.join(".*"))
    );
  });

  it("treats a set-but-empty variable as missing", () => {
    expect(() => requireWorkosEnv({ ...COMPLETE_ENV, WORKOS_API_KEY: "" })).toThrow(
      /WORKOS_API_KEY/
    );
  });

  it("rejects a short cookie password", () => {
    expect(() =>
      requireWorkosEnv({ ...COMPLETE_ENV, WORKOS_COOKIE_PASSWORD: "short" })
    ).toThrow(/32 characters/);
  });
});

describe("workosGate", () => {
  it("demands a user for /app and everything under it", () => {
    for (const pathname of ["/app", "/app/agents", "/app/sessions/x"]) {
      expect(workosGate({ pathname, hasUser: false })).toBe("redirect-to-sign-in");
      expect(workosGate({ pathname, hasUser: true })).toBe("pass");
    }
  });

  it("passes public routes with or without a user", () => {
    for (const pathname of ["/", "/docs", "/docs/getting-started", "/pricing", "/login"]) {
      expect(workosGate({ pathname, hasUser: false })).toBe("pass");
      expect(workosGate({ pathname, hasUser: true })).toBe("pass");
    }
  });

  it("never redirects an API fetch — the route answers 401 itself", () => {
    expect(workosGate({ pathname: "/api/fluidbox/approvals", hasUser: false })).toBe(
      "pass"
    );
  });

  it("does not gate /app lookalikes", () => {
    expect(workosGate({ pathname: "/apple", hasUser: false })).toBe("pass");
  });
});
