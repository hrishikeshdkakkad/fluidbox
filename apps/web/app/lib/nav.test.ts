import { describe, expect, it } from "vitest";
import { NAV, crumbsFor, sectionFor } from "./nav";

describe("sectionFor — every dashboard route resolves to exactly one section", () => {
  const cases: [string, string][] = [
    ["/app", "overview"],
    ["/app/activity", "activity"],
    ["/app/sessions/019ff5d7-fa7e-7310-95b9-93a7a865e211", "activity"],
    ["/app/automations", "activity"],
    ["/app/automations/abc123", "activity"],
    ["/app/resources", "resources"],
    ["/app/agents", "resources"],
    ["/app/agents/new", "resources"],
    ["/app/capabilities", "resources"],
    ["/app/integrations", "resources"],
    ["/app/governance", "governance"],
    ["/app/governance/default", "governance"],
    ["/app/recipes", "recipes"],
    ["/app/recipes/pr-review", "recipes"],
    ["/app/recipes/instances/xyz", "recipes"],
    ["/app/settings", "settings"],
  ];
  for (const [path, section] of cases) {
    it(`${path} -> ${section}`, () => expect(sectionFor(path)).toBe(section));
  }

  it("returns null off the dashboard, so public routes light nothing", () => {
    for (const p of ["/", "/docs", "/pricing", "/login", "/applesauce"]) {
      expect(sectionFor(p), p).toBeNull();
    }
  });

  it("never resolves a route to a section that is not in the nav", () => {
    const ids = new Set(NAV.map((n) => n.id));
    for (const [path] of cases) expect(ids.has(sectionFor(path)!), path).toBe(true);
  });
});

describe("crumbsFor — every deep page can walk back to a real route", () => {
  it("gives section-index pages no trail (they ARE the top level)", () => {
    for (const p of [
      "/app",
      "/app/activity",
      "/app/resources",
      "/app/governance",
      "/app/recipes",
      "/app/settings",
    ]) {
      expect(crumbsFor(p), p).toEqual([]);
    }
  });

  it("puts the owning section first and the current page last", () => {
    expect(crumbsFor("/app/agents")).toEqual([
      { label: "resources", href: "/app/resources" },
      { label: "agents" },
    ]);
    expect(crumbsFor("/app/capabilities")).toEqual([
      { label: "resources", href: "/app/resources" },
      { label: "mcp" },
    ]);
  });

  it("walks three levels when the route is three deep", () => {
    expect(crumbsFor("/app/agents/new")).toEqual([
      { label: "resources", href: "/app/resources" },
      { label: "agents", href: "/app/agents" },
      { label: "new agent" },
    ]);
  });

  it("labels a dynamic leaf with the value it was given, not the raw id", () => {
    const trail = crumbsFor("/app/sessions/019ff5d7-fa7e-7310", { leaf: "019ff5d7" });
    expect(trail[0]).toEqual({ label: "activity", href: "/app/activity" });
    expect(trail.at(-1)).toEqual({ label: "019ff5d7" });
  });

  it("falls back to the path segment when no leaf label is supplied", () => {
    expect(crumbsFor("/app/governance/default").at(-1)).toEqual({ label: "default" });
  });

  // The whole point of the trail: the LAST crumb is where you are, so it must
  // not be a link, and every crumb BEFORE it must be somewhere you can go.
  it("makes only the last crumb unlinked, and every other crumb a real route", () => {
    for (const p of [
      "/app/agents/new",
      "/app/sessions/x",
      "/app/automations/y",
      "/app/recipes/z",
      "/app/governance/g",
    ]) {
      const trail = crumbsFor(p);
      expect(trail.at(-1)!.href, p).toBeUndefined();
      for (const crumb of trail.slice(0, -1)) {
        expect(crumb.href, `${p} :: ${crumb.label}`).toMatch(/^\/app(\/|$)/);
      }
    }
  });

  it("returns nothing off the dashboard", () => {
    expect(crumbsFor("/docs/getting-started")).toEqual([]);
  });
});
