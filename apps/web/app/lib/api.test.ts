import { describe, expect, it } from "vitest";
import {
  AuthMe,
  Connection,
  connectionMatchesConnector,
  isGitConnection,
  isToolConnection,
  ownerBadge,
  ownerOptions,
} from "./api";

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
