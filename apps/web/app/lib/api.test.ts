import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  apiGet,
  apiGetCached,
  apiPost,
  AuthMe,
  Connection,
  connectionMatchesConnector,
  invalidateApiCache,
  isGitConnection,
  isToolConnection,
  ownerBadge,
  ownerOptions,
} from "./api";

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

beforeEach(() => {
  invalidateApiCache();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("private control-plane read cache", () => {
  it("coalesces simultaneous GETs for the same projection", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ agents: ["one"] }));
    vi.stubGlobal("fetch", fetchMock);

    const [first, second] = await Promise.all([
      apiGet<{ agents: string[] }>("/agents"),
      apiGet<{ agents: string[] }>("/agents"),
    ]);

    expect(first).toEqual({ agents: ["one"] });
    expect(second).toEqual(first);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("reuses a fresh per-tab value and supports an explicit refresh", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ version: 1 }))
      .mockResolvedValueOnce(jsonResponse({ version: 2 }));
    vi.stubGlobal("fetch", fetchMock);

    expect(await apiGetCached("/catalog", { maxAgeMs: 60_000 })).toEqual({ version: 1 });
    expect(await apiGetCached("/catalog", { maxAgeMs: 60_000 })).toEqual({ version: 1 });
    expect(await apiGetCached("/catalog", { maxAgeMs: 60_000, force: true })).toEqual({
      version: 2,
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("invalidates read projections after a successful write", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ agents: ["before"] }))
      .mockResolvedValueOnce(jsonResponse({ ok: true }))
      .mockResolvedValueOnce(jsonResponse({ agents: ["after"] }));
    vi.stubGlobal("fetch", fetchMock);

    await apiGetCached("/agents", { maxAgeMs: 60_000 });
    await apiPost("/agents", { name: "reviewer" });
    expect(await apiGetCached("/agents", { maxAgeMs: 60_000 })).toEqual({
      agents: ["after"],
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("does not let a read started before a write repopulate stale cache", async () => {
    let resolveOldRead: ((response: Response) => void) | undefined;
    const oldReadResponse = new Promise<Response>((resolve) => {
      resolveOldRead = resolve;
    });
    const fetchMock = vi
      .fn()
      .mockReturnValueOnce(oldReadResponse)
      .mockResolvedValueOnce(jsonResponse({ ok: true }))
      .mockResolvedValueOnce(jsonResponse({ agents: ["after"] }));
    vi.stubGlobal("fetch", fetchMock);

    const oldRead = apiGetCached<{ agents: string[] }>("/agents", { maxAgeMs: 60_000 });
    await apiPost("/agents", { name: "reviewer" });
    const freshRead = await apiGetCached<{ agents: string[] }>("/agents", {
      maxAgeMs: 60_000,
    });
    resolveOldRead?.(jsonResponse({ agents: ["before"] }));

    expect(await oldRead).toEqual({ agents: ["before"] });
    expect(freshRead).toEqual({ agents: ["after"] });
    expect(await apiGetCached("/agents", { maxAgeMs: 60_000 })).toEqual({
      agents: ["after"],
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("does not cache a failed read and releases its in-flight slot", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ error: "temporary" }, 503))
      .mockResolvedValueOnce(jsonResponse({ ready: true }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiGetCached("/health", { maxAgeMs: 60_000 })).rejects.toThrow("503");
    await expect(apiGetCached("/health", { maxAgeMs: 60_000 })).resolves.toEqual({
      ready: true,
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

// Only `provider` is read by the predicates; the rest of Connection is noise.
const conn = (provider: string): Connection => ({ provider }) as Connection;

describe("connection provider classification", () => {
  it("routes both github providers to the git surface", () => {
    expect(isGitConnection(conn("github"))).toBe(true);
    expect(isGitConnection(conn("github_app"))).toBe(true);
    expect(isToolConnection(conn("github"))).toBe(false);
    expect(isToolConnection(conn("github_app"))).toBe(false);
  });

  it("routes mcp_http to the tool surface, never the git one", () => {
    expect(isToolConnection(conn("mcp_http"))).toBe(true);
    // The reported bug: `mcp_http · Cloudflare` was offered as a source for a
    // git checkout. The broker calls that server; it has no repositories.
    expect(isGitConnection(conn("mcp_http"))).toBe(false);
  });

  it("keeps an unclassified provider out of BOTH surfaces", () => {
    // Phase 7 lands `slack` on the server before this client knows the word.
    // The old `provider !== "mcp_http"` form would have admitted it straight
    // into the repo picker. An allowlist fails safe instead.
    expect(isGitConnection(conn("slack"))).toBe(false);
    expect(isToolConnection(conn("slack"))).toBe(false);
  });
});

// ─── Phase C: connection ownership ──────────────────────────────────────────

const owned = (owner_type: "organization" | "user", owner_user_id?: string): Connection =>
  ({ provider: "mcp_http", owner_type, owner_user_id: owner_user_id ?? null }) as Connection;

describe("ownerBadge", () => {
  it("labels an organization connection without a 'yours' marker", () => {
    expect(ownerBadge(owned("organization"), "u1")).toEqual({ label: "Organization", yours: false });
  });

  it("marks a personal connection 'yours' only when the owner matches the viewer", () => {
    expect(ownerBadge(owned("user", "u1"), "u1")).toEqual({ label: "Personal", yours: true });
    expect(ownerBadge(owned("user", "u2"), "u1")).toEqual({ label: "Personal", yours: false });
    // Admin mode / operator: no user id → Personal without "yours".
    expect(ownerBadge(owned("user", "u2"), undefined)).toEqual({ label: "Personal", yours: false });
  });

  it("renders nothing for a pre-Phase-C row that carries no ownership", () => {
    expect(ownerBadge(conn("mcp_http"))).toBeNull();
  });
});

describe("ownerOptions (mirrors the server resolve_owner gate)", () => {
  const me = (roles: string[], user_id = "u1"): AuthMe => ({ user_id, roles, auth_kind: "browser" });

  it("gives an admin/owner both options, defaulting to organization", () => {
    expect(ownerOptions(me(["admin"]))).toEqual({
      canOrganization: true,
      canPersonal: true,
      default: "organization",
    });
  });

  it("gives a plain member personal-only, defaulting to personal", () => {
    expect(ownerOptions(me(["member"]))).toEqual({
      canOrganization: false,
      canPersonal: true,
      default: "personal",
    });
  });

  it("gives the operator organization-only (no personal identity)", () => {
    expect(ownerOptions({ operator: true })).toEqual({
      canOrganization: true,
      canPersonal: false,
      default: "organization",
    });
  });

  it("falls back to organization-only when identity is unknown", () => {
    expect(ownerOptions(null)).toEqual({
      canOrganization: true,
      canPersonal: false,
      default: "organization",
    });
  });

  it("hides personal for organization-only custody (github_app)", () => {
    // A member who could normally pick personal cannot for github_app.
    expect(ownerOptions(me(["member"]), false)).toEqual({
      canOrganization: false,
      canPersonal: false,
      default: "organization",
    });
  });
});

describe("connectionMatchesConnector", () => {
  const withMeta = (meta: Record<string, string>): Connection =>
    ({ provider: "mcp_http", metadata: meta }) as Connection;

  it("matches on endpoint_url ignoring trailing slash and case", () => {
    const c = withMeta({ endpoint_url: "https://MCP.example.com/mcp/" });
    expect(connectionMatchesConnector(c, "https://mcp.example.com/mcp")).toBe(true);
  });

  it("matches a connector under an audience base_url", () => {
    const c = withMeta({ base_url: "https://mcp.example.com" });
    expect(connectionMatchesConnector(c, "https://mcp.example.com/mcp")).toBe(true);
  });

  it("does not match a different host", () => {
    const c = withMeta({ endpoint_url: "https://other.example.com/mcp" });
    expect(connectionMatchesConnector(c, "https://mcp.example.com/mcp")).toBe(false);
  });

  it("does not match when the connection has no endpoint metadata", () => {
    expect(connectionMatchesConnector(withMeta({}), "https://mcp.example.com/mcp")).toBe(false);
  });
});
