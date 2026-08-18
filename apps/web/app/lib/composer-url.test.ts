import { describe, expect, it } from "vitest";
import {
  clearComposerUrl,
  composerHref,
  readComposerUrl,
  writeComposerUrl,
} from "./composer-url";

describe("readComposerUrl", () => {
  it("reads every selection it owns", () => {
    const params = new URLSearchParams(
      "compose=run&mode=automation&agentChoice=existing&agent=Attention%20radar" +
        "&harness=codex&model=gpt-5.4-mini&policy=default&approvals=auto" +
        "&workspace=git&trigger=schedule"
    );

    expect(readComposerUrl(params)).toEqual({
      compose: "run",
      mode: "automation",
      agentChoice: "existing",
      agent: "Attention radar",
      harness: "codex",
      model: "gpt-5.4-mini",
      policy: "default",
      approvals: "auto",
      workspace: "git",
      trigger: "schedule",
    });
  });

  it("returns nothing for an empty query", () => {
    expect(readComposerUrl(new URLSearchParams(""))).toEqual({});
  });

  it("drops unrecognised enum values instead of surfacing them", () => {
    // A bad value must fall through to the component's own default, never
    // select something that does not exist.
    const params = new URLSearchParams("mode=sideways&approvals=maybe&workspace=s3&trigger=carrier");
    expect(readComposerUrl(params)).toEqual({});
  });

  it("ignores an over-long name rather than seeding state with it", () => {
    const params = new URLSearchParams();
    params.set("model", "x".repeat(129));
    params.set("harness", "y".repeat(128));
    const state = readComposerUrl(params);
    expect(state.model).toBeUndefined();
    expect(state.harness).toBe("y".repeat(128));
  });

  it("trims names and treats blank as absent", () => {
    const params = new URLSearchParams("agent=%20%20&policy=%20standard%20");
    const state = readComposerUrl(params);
    expect(state.agent).toBeUndefined();
    expect(state.policy).toBe("standard");
  });
});

describe("writeComposerUrl", () => {
  it("preserves params it does not own", () => {
    const existing = new URLSearchParams("filter=failed&page=2");
    const search = writeComposerUrl({ compose: "run", mode: "once" }, existing);
    const out = new URLSearchParams(search);

    expect(out.get("filter")).toBe("failed");
    expect(out.get("page")).toBe("2");
    expect(out.get("compose")).toBe("run");
    expect(out.get("mode")).toBe("once");
  });

  it("removes a key whose value is undefined or empty", () => {
    const existing = new URLSearchParams("compose=run&agent=Attention%20radar&trigger=api");
    const search = writeComposerUrl({ compose: "run", agent: "", trigger: undefined }, existing);
    const out = new URLSearchParams(search);

    expect(out.get("compose")).toBe("run");
    expect(out.has("agent")).toBe(false);
    expect(out.has("trigger")).toBe(false);
  });

  it("round-trips through readComposerUrl", () => {
    const state = {
      compose: "run",
      mode: "automation",
      agent: "Vendor renewal watch",
      approvals: "wait",
      workspace: "local",
    } as const;

    const search = writeComposerUrl(state, new URLSearchParams());
    expect(readComposerUrl(new URLSearchParams(search))).toEqual(state);
  });
});

describe("clearComposerUrl", () => {
  it("strips only the composer's own keys", () => {
    const existing = new URLSearchParams("filter=live&compose=run&mode=once&agent=A&view=x");
    const out = new URLSearchParams(clearComposerUrl(existing));

    expect(out.get("filter")).toBe("live");
    expect(out.get("view")).toBe("x");
    expect(out.has("compose")).toBe(false);
    expect(out.has("mode")).toBe(false);
    expect(out.has("agent")).toBe(false);
  });

  it("leaves an empty string when nothing else remains", () => {
    expect(clearComposerUrl(new URLSearchParams("compose=run&mode=once"))).toBe("");
  });
});

describe("composerHref", () => {
  it("omits the ? when there is no query", () => {
    expect(composerHref("/app", "")).toBe("/app");
    expect(composerHref("/app", "compose=run")).toBe("/app?compose=run");
  });
});
