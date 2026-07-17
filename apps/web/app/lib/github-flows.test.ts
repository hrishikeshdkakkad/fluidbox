import { describe, expect, it } from "vitest";
import { Connection, GithubAppRegistration } from "./api";
import { nextGithubAction, pickNewConnection } from "./github-flows";

const reg = (id: string, status: string): GithubAppRegistration =>
  ({ id, status }) as GithubAppRegistration;

const conn = (
  id: string,
  provider: string,
  status: string,
  registration_id: string | null = null
): Connection => ({ id, provider, status, registration_id }) as Connection;

describe("nextGithubAction", () => {
  it("offers to create an App when no registration is active", () => {
    expect(nextGithubAction([], [])).toEqual({ kind: "create" });
    // A pending registration is not usable custody yet.
    expect(nextGithubAction([reg("r1", "pending")], [])).toEqual({ kind: "create" });
    expect(nextGithubAction([reg("r1", "revoked")], [])).toEqual({ kind: "create" });
  });

  it("offers to install when the App exists but is not installed", () => {
    expect(nextGithubAction([reg("r1", "active")], [])).toEqual({ kind: "install", regId: "r1" });
  });

  it("offers more repositories once an installation is live", () => {
    const conns = [conn("c1", "github_app", "active", "r1")];
    expect(nextGithubAction([reg("r1", "active")], conns)).toEqual({
      kind: "add_repos",
      regId: "r1",
    });
  });

  it("ignores a revoked connection when deciding install vs add_repos", () => {
    const conns = [conn("c1", "github_app", "revoked", "r1")];
    expect(nextGithubAction([reg("r1", "active")], conns)).toEqual({ kind: "install", regId: "r1" });
  });

  it("never attributes a LEGACY connection to a registration", () => {
    // registration_id === null means custody lives on the connection itself.
    // There is no registration to install into; never synthesise one.
    const legacy = [conn("c1", "github_app", "active", null)];
    expect(nextGithubAction([reg("r1", "active")], legacy)).toEqual({
      kind: "install",
      regId: "r1",
    });
  });
});

describe("pickNewConnection", () => {
  it("selects the single git connection that appeared", () => {
    const after = [conn("c1", "github_app", "active"), conn("c2", "github_app", "active")];
    expect(pickNewConnection(["c1"], after)).toBe("c2");
  });

  it("selects nothing when several appeared", () => {
    // Guessing would silently bind the wrong repo host to a run whose task
    // text is already typed. Make the user choose.
    const after = [conn("c1", "github_app", "active"), conn("c2", "github_app", "active")];
    expect(pickNewConnection([], after)).toBeNull();
  });

  it("selects nothing when nothing appeared", () => {
    expect(pickNewConnection(["c1"], [conn("c1", "github_app", "active")])).toBeNull();
  });

  it("ignores a new NON-git connection", () => {
    // Connecting an MCP server mid-flow must not hijack the repo picker.
    const after = [conn("c1", "github_app", "active"), conn("c2", "mcp_http", "active")];
    expect(pickNewConnection(["c1"], after)).toBeNull();
  });

  it("ignores a new git connection that is not yet active", () => {
    const after = [conn("c1", "github_app", "active"), conn("c2", "github_app", "pending")];
    expect(pickNewConnection(["c1"], after)).toBeNull();
  });
});
