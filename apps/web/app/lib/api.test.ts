import { describe, expect, it } from "vitest";
import { Connection, isGitConnection, isToolConnection } from "./api";

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
