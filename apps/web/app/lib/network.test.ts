import { describe, expect, it } from "vitest";
import { PolicyContent, TargetRule } from "./api";
import {
  describeTarget,
  MODE_ORDER,
  networkOf,
  OFFLINE_NETWORK,
  portsLabel,
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
