import { describe, expect, it } from "vitest";
import { allowedCookieHeader, isAllowedCookie, webMode } from "./proxy-auth";

// Build a Request carrying (or not) a Cookie header. undici's global Request is
// available under vitest's node environment.
const withCookie = (cookie: string | null): Request =>
  new Request("https://fbx.example/api/fluidbox/x", {
    headers: cookie === null ? {} : { cookie },
  });

describe("isAllowedCookie", () => {
  it("keeps exactly the session cookie and the login/switch families", () => {
    expect(isAllowedCookie("__Host-fbx_web")).toBe(true);
    expect(isAllowedCookie("__Host-fbx_login_abc123")).toBe(true);
    expect(isAllowedCookie("__Host-fbx_switch_9f")).toBe(true);
  });

  it("drops lookalikes and everything else", () => {
    // Extra char after the exact session-cookie name — not the session cookie.
    expect(isAllowedCookie("__Host-fbx_webx")).toBe(false);
    // The login family requires the trailing underscore; the bare stem is not it.
    expect(isAllowedCookie("__Host-fbx_login")).toBe(false);
    expect(isAllowedCookie("__Host-fbx_switch")).toBe(false);
    expect(isAllowedCookie("session")).toBe(false);
    expect(isAllowedCookie("__Host-fbx_websession")).toBe(false);
    expect(isAllowedCookie("anything")).toBe(false);
  });
});

describe("allowedCookieHeader", () => {
  it("filters to the allowlist and rejoins the survivors", () => {
    const req = withCookie(
      "__Host-fbx_web=a; __Host-fbx_login_x=b; __Host-fbx_switch_y=c; " +
        "__Host-fbx_webx=d; __Host-fbx_login=e; session=f; foo=g"
    );
    expect(allowedCookieHeader(req)).toBe(
      "__Host-fbx_web=a; __Host-fbx_login_x=b; __Host-fbx_switch_y=c"
    );
  });

  it("returns null when there is no Cookie header", () => {
    expect(allowedCookieHeader(withCookie(null))).toBeNull();
  });

  it("returns null when nothing survives the filter", () => {
    expect(allowedCookieHeader(withCookie("session=x; foo=y"))).toBeNull();
  });
});

describe("webMode", () => {
  it("selects sso only for the exact string", () => {
    expect(webMode("sso")).toBe("sso");
  });

  it("stays admin for unset/absent (the documented local default)", () => {
    expect(webMode(undefined)).toBe("admin");
    expect(webMode("")).toBe("admin");
    expect(webMode("admin")).toBe("admin");
  });

  it("THROWS on any other value — a hosted typo must never become admin", () => {
    expect(() => webMode("SSO")).toThrow();
    expect(() => webMode("typo")).toThrow();
    expect(() => webMode("anything-else")).toThrow();
  });
});
