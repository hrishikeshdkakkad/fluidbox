import { describe, expect, it } from "vitest";
import type { Connection } from "./api";
import {
  blockingIssue,
  cardMatches,
  eligibleConnections,
  groupByCategory,
  initialParams,
  listFromText,
  paramsForSubmit,
  recipeReady,
  triggerLabel,
  type RecipeCard,
  type RecipeParamSpec,
} from "./recipes";

const spec = (over: Partial<RecipeParamSpec>): RecipeParamSpec => ({
  name: "p",
  title: "P",
  description: null,
  required: false,
  default: null,
  widget: { kind: "text" },
  choices: null,
  ui: null,
  ...over,
});

const conn = (over: Partial<Connection>): Connection =>
  ({
    id: "c1",
    provider: "github",
    status: "active",
    display_name: "gh",
    ...over,
  }) as Connection;

describe("initialParams", () => {
  it("prefills only declared defaults", () => {
    const specs = [
      spec({ name: "a", default: ["opened"] }),
      spec({ name: "b" }),
      spec({ name: "c", default: "claude-haiku-4-5" }),
    ];
    expect(initialParams(specs)).toEqual({ a: ["opened"], c: "claude-haiku-4-5" });
  });
});

describe("blockingIssue", () => {
  const specs = [
    spec({
      name: "github_connection",
      title: "GitHub connection",
      required: true,
      widget: { kind: "connection", provider: "github", mcp: false },
    }),
    spec({ name: "repository", title: "Repository", required: true }),
    spec({ name: "callback_url", title: "Webhook" }),
  ];
  it("walks name → first missing required, phrased as the next action", () => {
    expect(blockingIssue("", specs, {})).toBe("Name this deployment");
    expect(blockingIssue("x".repeat(49), specs, {})).toContain("48 characters");
    expect(blockingIssue("Brief", specs, {})).toBe("Choose a github connection");
    expect(blockingIssue("Brief", specs, { github_connection: "id" })).toBe(
      "Fill in repository",
    );
    expect(
      blockingIssue("Brief", specs, { github_connection: "id", repository: "a/b" }),
    ).toBeNull();
  });
  it("treats empty strings and empty lists as missing", () => {
    expect(blockingIssue("Brief", specs, { github_connection: "  " })).toBe(
      "Choose a github connection",
    );
  });
});

describe("paramsForSubmit", () => {
  it("drops blanks and coerces number-widget strings", () => {
    const specs = [
      spec({ name: "n", widget: { kind: "number" } }),
      spec({ name: "s" }),
      spec({ name: "gone" }),
      spec({ name: "list", widget: { kind: "repositories" } }),
    ];
    expect(
      paramsForSubmit(specs, { n: "3", s: "x", gone: "", list: [] }),
    ).toEqual({ n: 3, s: "x" });
  });
});

describe("listFromText", () => {
  it("splits on commas and newlines, trims, drops empties", () => {
    expect(listFromText(" acme/site,\nacme/api\n\n")).toEqual(["acme/site", "acme/api"]);
  });
});

describe("eligibleConnections", () => {
  const conns = [
    conn({ id: "1", provider: "github" }),
    conn({ id: "2", provider: "github_app" }),
    conn({ id: "3", provider: "mcp_http" }),
    conn({ id: "4", provider: "github", status: "error" }),
  ] as Connection[];
  it("github filter matches BOTH github shapes, never inactive rows", () => {
    const got = eligibleConnections(
      { kind: "connection", provider: "github", mcp: false },
      conns,
    ).map((c) => c.id);
    expect(got).toEqual(["1", "2"]);
  });
  it("mcp filter matches only mcp_http", () => {
    const got = eligibleConnections(
      { kind: "connection", provider: null, mcp: true },
      conns,
    ).map((c) => c.id);
    expect(got).toEqual(["3"]);
  });
});

describe("recipeReady", () => {
  const facets = {
    agent_count: 1,
    multi_agent: false,
    trigger_kinds: ["api"],
    cost_ceiling_usd: 1,
    instant_run: false,
    success_criteria: [],
    connectors: [
      { param: "gh", title: "GitHub", provider: "github", mcp: false, required: true },
      { param: "cb", title: "Webhook", provider: null, mcp: false, required: false },
    ],
  };
  it("requires an active match per REQUIRED connector only", () => {
    expect(recipeReady(facets, [conn({ provider: "github_app" })] as Connection[])).toBe(true);
    expect(recipeReady(facets, [conn({ provider: "mcp_http" })] as Connection[])).toBe(false);
    expect(recipeReady(facets, [])).toBe(false);
  });
});

describe("catalog shaping", () => {
  const card = (slug: string, category: string): RecipeCard => ({
    id: slug,
    slug,
    name: slug,
    tagline: "does things",
    category,
    tags: ["github"],
    tier: "official",
    icon: "x",
    custom: false,
    latest_version: 1,
    updated_at: "",
    facets: {
      agent_count: 1,
      multi_agent: false,
      trigger_kinds: [],
      connectors: [],
      cost_ceiling_usd: 0,
      instant_run: false,
      success_criteria: [],
    },
  });
  it("cardMatches searches name/tagline/category/tags", () => {
    expect(cardMatches(card("a", "ci-cd"), "GITHUB")).toBe(true);
    expect(cardMatches(card("a", "ci-cd"), "zzz")).toBe(false);
    expect(cardMatches(card("a", "ci-cd"), "  ")).toBe(true);
  });
  it("groupByCategory keeps the curated order first", () => {
    const groups = groupByCategory([
      card("z", "zeta"),
      card("s", "support"),
      card("r", "code-review"),
    ]);
    expect(groups.map(([k]) => k)).toEqual(["code-review", "support", "zeta"]);
  });
  it("triggerLabel names every kind", () => {
    for (const k of ["event", "schedule", "api", "instant"]) {
      expect(triggerLabel(k)).not.toBe(k);
    }
  });
});
