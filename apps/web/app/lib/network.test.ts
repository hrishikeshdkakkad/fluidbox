import { describe, expect, it } from "vitest";
import { NetworkRequest, PolicyContent, TargetRule } from "./api";
import {
  describeTarget,
  MODE_ORDER,
  networkOf,
  OFFLINE_NETWORK,
  OFFLINE_REQUEST,
  portsLabel,
  requestOf,
  summarizeRequest,
} from "./network";

const base = { name: "p" } as unknown as PolicyContent;

describe("networkOf", () => {
  it("synthesizes the offline default when the server omitted the key", () => {
    // `network` is skip_serializing_if default on the Rust side, so an
    // untouched policy arrives with NO network key at all.
    expect(networkOf(base)).toEqual(OFFLINE_NETWORK);
    expect(networkOf(base).max_mode).toBe("offline");
    expect(networkOf(base).allow).toEqual([]);
  });

  it("returns the stored section when present", () => {
    const withNet = { ...base, network: { ...OFFLINE_NETWORK, max_mode: "public" as const } };
    expect(networkOf(withNet).max_mode).toBe("public");
  });
});

describe("portsLabel", () => {
  it("renders a single port bare and a range with a dash", () => {
    expect(portsLabel([{ from: 443, to: 443 }])).toBe("443");
    expect(portsLabel([{ from: 443, to: 444 }])).toBe("443-444");
    expect(portsLabel([{ from: 80, to: 80 }, { from: 443, to: 443 }])).toBe("80, 443");
  });

  it("says so when a rule names no ports", () => {
    expect(portsLabel([])).toBe("any port");
  });
});

describe("describeTarget", () => {
  it("renders a wildcard dns rule", () => {
    const t: TargetRule = {
      kind: "dns",
      pattern: { kind: "wildcard", suffix: "nvidia.com" },
      ports: [{ from: 443, to: 443 }],
      protocol: "tcp",
    };
    expect(describeTarget(t)).toBe("*.nvidia.com TCP 443");
  });

  it("renders an exact dns rule", () => {
    const t: TargetRule = {
      kind: "dns",
      pattern: { kind: "exact", name: "nvidia.com" },
      ports: [{ from: 443, to: 443 }],
      protocol: "tcp",
    };
    expect(describeTarget(t)).toBe("nvidia.com TCP 443");
  });

  it("renders a cidr rule", () => {
    const t: TargetRule = {
      kind: "cidr",
      cidr: "10.0.0.0/8",
      ports: [{ from: 5432, to: 5432 }],
      protocol: "udp",
    };
    expect(describeTarget(t)).toBe("10.0.0.0/8 UDP 5432");
  });
});

describe("mode ordering", () => {
  it("orders offline < approved < public, the ceiling order", () => {
    // Pinned because the selectors render in this order and a reader will
    // take the order as meaning "increasingly permissive". It does.
    expect(MODE_ORDER).toEqual(["offline", "approved", "public"]);
  });
});

describe("requestOf", () => {
  it("reads an absent revision declaration as offline, never as unknown", () => {
    // The server documents `network` on a revision as "omitted means offline"
    // (api.rs), so an absent field is a FACT, not a gap — unlike a policy read
    // that FAILED, which must stay unknown.
    expect(requestOf(undefined)).toEqual(OFFLINE_REQUEST);
    expect(requestOf(null)).toEqual(OFFLINE_REQUEST);
    expect(requestOf(OFFLINE_REQUEST).mode).toBe("offline");
  });

  it("returns the stored declaration untouched when present", () => {
    const r: NetworkRequest = { mode: "public", targets: [], duration_secs: null };
    expect(requestOf(r)).toBe(r);
  });
});

describe("summarizeRequest", () => {
  it("names the mode for offline and public, which carry no targets", () => {
    expect(summarizeRequest({ mode: "offline", targets: [], duration_secs: null })).toBe("Offline");
    expect(summarizeRequest({ mode: "public", targets: [], duration_secs: null })).toBe("Public");
  });

  it("counts targets under approved, singular and plural", () => {
    const t: TargetRule = {
      kind: "dns",
      pattern: { kind: "exact", name: "pypi.org" },
      ports: [{ from: 443, to: 443 }],
      protocol: "tcp",
    };
    expect(summarizeRequest({ mode: "approved", targets: [t], duration_secs: null })).toBe(
      "Approved targets · 1 target",
    );
    expect(summarizeRequest({ mode: "approved", targets: [t, t], duration_secs: null })).toBe(
      "Approved targets · 2 targets",
    );
  });

  it("says an approved declaration with no targets grants nothing", () => {
    // Not cosmetic: approved+[] is inert, and reading it as plain "Approved
    // targets" would suggest the agent has egress it does not have.
    expect(summarizeRequest({ mode: "approved", targets: [], duration_secs: null })).toBe(
      "Approved targets · none yet",
    );
  });
});
