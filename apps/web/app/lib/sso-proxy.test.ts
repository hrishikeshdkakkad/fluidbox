import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Route-level test of the sso proxy's forward logic (app/api/fluidbox/[...path]/
// route.ts). The security-critical guarantees, exercised against a stubbed fetch:
//
//   (a) NO Authorization header rides upstream, even though FLUIDBOX_ADMIN_TOKEN
//       is deliberately SET in the environment — sso mode must never leak the
//       operator credential.
//   (b) The Cookie header is filtered to the allowlist before forwarding.
//   (c) Every upstream Set-Cookie header is propagated separately.
//   (d) x-fluidbox-csrf and Origin are forwarded.
//
// route.ts reads FLUIDBOX_WEB_MODE / FLUIDBOX_ADMIN_TOKEN at MODULE scope, so the
// env must be set BEFORE a fresh import — vi.resetModules() drops the cache and
// the dynamic import re-evaluates the module against the just-set env. (This is
// the pattern that worked; a plain top-of-file import would bake stale env.)

const ROUTE_PATH = "../api/fluidbox/[...path]/route";

let captured: { url?: string; headers?: Record<string, string>; method?: string };

function stubUpstream(): void {
  const headers = new Headers();
  headers.set("content-type", "application/json");
  headers.append("set-cookie", "__Host-fbx_web=sess; Path=/; HttpOnly; Secure");
  headers.append("set-cookie", "__Host-fbx_switch_9f=pend; Path=/; HttpOnly; Secure");
  const upstream = new Response('{"ok":true}', { status: 200, headers });
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string | URL, init?: RequestInit) => {
      captured = {
        url: String(url),
        headers: (init?.headers ?? {}) as Record<string, string>,
        method: init?.method,
      };
      return Promise.resolve(upstream);
    })
  );
}

async function loadRoute() {
  vi.resetModules();
  process.env.FLUIDBOX_WEB_MODE = "sso";
  process.env.FLUIDBOX_ADMIN_TOKEN = "operator-token-must-not-leak";
  return import(ROUTE_PATH);
}

beforeEach(() => {
  captured = {};
  stubUpstream();
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.FLUIDBOX_WEB_MODE;
  delete process.env.FLUIDBOX_ADMIN_TOKEN;
});

describe("sso proxy forward", () => {
  it("forwards cookies/csrf/origin with NO bearer, propagating every Set-Cookie", async () => {
    const route = await loadRoute();
    const req = new Request(
      "https://fbx.example/api/fluidbox/auth/login/acme/start?redirect_to=%2F",
      {
        method: "POST",
        headers: {
          cookie: "__Host-fbx_web=a; evil=b; __Host-fbx_switch_x=c; foo=d",
          "x-fluidbox-csrf": "1",
          origin: "https://fbx.example",
          "content-type": "application/json",
        },
        body: "{}",
      }
    );
    const ctx = {
      params: Promise.resolve({ path: ["auth", "login", "acme", "start"] }),
    };
    const res = await route.POST(req, ctx);

    // (a) No operator bearer upstream despite FLUIDBOX_ADMIN_TOKEN being set.
    expect(captured.headers?.authorization).toBeUndefined();
    // (b) Cookie filtered to the allowlist (evil/foo dropped).
    expect(captured.headers?.cookie).toBe(
      "__Host-fbx_web=a; __Host-fbx_switch_x=c"
    );
    // (d) CSRF header + Origin forwarded verbatim.
    expect(captured.headers?.["x-fluidbox-csrf"]).toBe("1");
    expect(captured.headers?.origin).toBe("https://fbx.example");

    // (c) Both upstream Set-Cookie headers propagated, each preserved distinctly.
    const setCookies = res.headers.getSetCookie();
    expect(setCookies).toHaveLength(2);
    expect(setCookies).toContain(
      "__Host-fbx_web=sess; Path=/; HttpOnly; Secure"
    );
    expect(setCookies).toContain(
      "__Host-fbx_switch_9f=pend; Path=/; HttpOnly; Secure"
    );
  });
});
