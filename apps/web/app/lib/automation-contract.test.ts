import { describe, expect, it } from "vitest";
import {
  buildCurl,
  classifyVariables,
  contextExample,
  SYSTEM_VARIABLES,
  templateVariables,
} from "./automation-contract";

describe("templateVariables", () => {
  it("extracts unique placeholder names", () => {
    expect(templateVariables("do {{ticket}} for {{ team }} re {{ticket}}")).toEqual([
      "ticket",
      "team",
    ]);
    expect(templateVariables(null)).toEqual([]);
  });
});

describe("classifyVariables", () => {
  it("api kind: everything is caller-supplied, nothing invalid", () => {
    const r = classifyVariables("api", "do {{ticket}}");
    expect(r).toEqual({ caller: ["ticket"], system: [], invalid: [] });
  });
  it("schedule kind: fire_time is system, anything else is invalid (no caller exists)", () => {
    const r = classifyVariables("schedule", "sweep {{fire_time}} for {{team}}");
    expect(r.system).toEqual(["fire_time"]);
    expect(r.caller).toEqual([]);
    expect(r.invalid).toEqual(["team"]);
  });
  it("event kind knows the full GitHub context, not just three names", () => {
    // Mirrors connectors/github.rs sample_context() — 12 variables.
    expect(SYSTEM_VARIABLES.event).toEqual([
      "repository", "pr_number", "pr_title", "pr_url", "pr_author",
      "head_sha", "head_ref", "base_sha", "base_ref", "action", "event", "fork",
    ]);
    const r = classifyVariables("event", "review {{pr_url}} by {{pr_author}} ({{oops}})");
    expect(r.system).toEqual(["pr_url", "pr_author"]);
    expect(r.invalid).toEqual(["oops"]);
  });
});

describe("buildCurl", () => {
  const url = "https://fb.example/v1/triggers/x/invoke";
  it("real token rides in single quotes", () => {
    expect(
      buildCurl({ invokeUrl: url, token: "fbx_trig_abc", caller: [], hasTemplate: true })
    ).toContain("-H 'Authorization: Bearer fbx_trig_abc'");
  });
  it("durable form uses DOUBLE quotes so the shell expands the variable", () => {
    const durable = buildCurl({ invokeUrl: url, token: null, caller: ["ticket"], hasTemplate: true });
    expect(durable).toContain('-H "Authorization: Bearer ${FLUIDBOX_TRIGGER_TOKEN}"');
    expect(durable).toContain('"ticket": "…"');
  });
  it("template-less automation sends a task, not {} (invoke would 400)", () => {
    const c = buildCurl({ invokeUrl: url, token: null, caller: [], hasTemplate: false });
    expect(c).toContain('"task"');
    expect(c).not.toContain("-d '{}'");
  });
});

describe("contextExample", () => {
  it("is {} with no caller variables", () => {
    expect(contextExample([])).toBe("{}");
    expect(contextExample(["a", "b"])).toBe('{"context": {"a": "…", "b": "…"}}');
  });
});
