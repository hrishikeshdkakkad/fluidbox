import { describe, expect, it } from "vitest";
import { NetworkRequest, PolicyContent, PortSpec, TargetRule } from "./api";
import {
  agentSelectionChanged,
  describeTarget,
  isCeilingOptionAllowed,
  MAX_PORT,
  MIN_PORT,
  MODE_ORDER,
  networkOf,
  OFFLINE_NETWORK,
  OFFLINE_REQUEST,
  portsLabel,
  requestForWire,
  requestOf,
  runNetworkOverride,
  singleRange,
  summarizeRequest,
  withPortEdge,
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

const dns = (name: string, ports: PortSpec[]): TargetRule => ({
  kind: "dns",
  pattern: { kind: "exact", name },
  ports,
  protocol: "tcp",
});

describe("singleRange", () => {
  it("returns the one range a two-box editor can represent", () => {
    expect(singleRange([{ from: 80, to: 443 }])).toEqual({ from: 80, to: 443 });
  });

  it("returns null for a rule that names no ports", () => {
    // `[]` MEANS "any port" (portsLabel says so). An editor that answered 443
    // here rendered an any-port grant as 443-only, contradicting the very
    // description printed beside it, and narrowed the rule on first keystroke.
    expect(singleRange([])).toBeNull();
  });

  it("returns null for several ranges, which one pair of boxes cannot hold", () => {
    expect(singleRange([{ from: 80, to: 80 }, { from: 443, to: 443 }])).toBeNull();
  });
});

describe("withPortEdge", () => {
  const one: PortSpec[] = [{ from: 443, to: 443 }];

  it("carries `to` up when `from` is raised past it", () => {
    expect(withPortEdge(one, "from", "8443")).toEqual([{ from: 8443, to: 8443 }]);
  });

  it("carries `from` down when `to` is lowered past it", () => {
    // The bug this pins: only the `from` handler clamped, so typing 80 into
    // `to` on a 443 rule built the inverted range 443-80 and the whole save
    // failed server-side with a raw 4xx.
    expect(withPortEdge(one, "to", "80")).toEqual([{ from: 80, to: 80 }]);
  });

  it("widens without disturbing the other edge", () => {
    expect(withPortEdge([{ from: 80, to: 80 }], "to", "443")).toEqual([{ from: 80, to: 443 }]);
  });

  it("leaves the range alone while the field is empty", () => {
    // `Number("")` is 0, and port 0 is refused by core — so an empty field
    // must mean "mid-edit", never "port zero".
    expect(withPortEdge(one, "from", "")).toEqual(one);
    expect(withPortEdge(one, "to", "  ")).toEqual(one);
  });

  it("leaves the range alone for something that is not a number", () => {
    expect(withPortEdge(one, "to", "http")).toEqual(one);
  });

  it("clamps to the range the wire can carry", () => {
    expect(withPortEdge(one, "from", "0")).toEqual([{ from: MIN_PORT, to: 443 }]);
    expect(withPortEdge(one, "to", "70000")).toEqual([{ from: 443, to: MAX_PORT }]);
    expect(withPortEdge(one, "to", "-5")).toEqual([{ from: MIN_PORT, to: MIN_PORT }]);
  });

  it("floors a fractional entry rather than sending one to a u16", () => {
    expect(withPortEdge(one, "to", "8443.9")).toEqual([{ from: 443, to: 8443 }]);
  });

  it("seeds a range for a rule that had none rather than editing in place", () => {
    // An any-port rule is read-only in the editor, but the function must still
    // answer sanely if it is ever handed one.
    expect(withPortEdge([], "from", "80")).toEqual([{ from: 80, to: 80 }]);
  });

  it("does not mutate the ports it was given", () => {
    const before: PortSpec[] = [{ from: 443, to: 443 }];
    withPortEdge(before, "to", "80");
    expect(before).toEqual([{ from: 443, to: 443 }]);
  });
});

describe("requestForWire", () => {
  const t = dns("pypi.org", [{ from: 443, to: 443 }]);

  it("keeps targets under approved, the one mode that carries them", () => {
    expect(requestForWire({ mode: "approved", targets: [t], duration_secs: 900 })).toEqual({
      mode: "approved",
      targets: [t],
      duration_secs: 900,
    });
  });

  it("drops targets from an offline declaration the editor never showed", () => {
    // Switching approved -> offline hid the target editor but kept the targets
    // in the payload. Core accepts offline+targets (only public+targets is
    // refused), so the stored declaration disagreed with what was approved.
    expect(requestForWire({ mode: "offline", targets: [t], duration_secs: null })).toEqual({
      mode: "offline",
      targets: [],
      duration_secs: null,
    });
  });

  it("drops targets from a public declaration, which core refuses outright", () => {
    expect(requestForWire({ mode: "public", targets: [t], duration_secs: null }).targets).toEqual([]);
  });

  it("does not mutate its argument, so a mode toggle keeps the typed work", () => {
    const draft: NetworkRequest = { mode: "offline", targets: [t], duration_secs: null };
    requestForWire(draft);
    expect(draft.targets).toEqual([t]);
  });
});

describe("runNetworkOverride", () => {
  it("sends offline, the sole narrowing a run may ask for", () => {
    expect(runNetworkOverride(true)).toEqual(OFFLINE_REQUEST);
  });

  it("sends nothing when the run inherits what the agent declared", () => {
    expect(runNetworkOverride(false)).toBeUndefined();
  });
});

describe("agentSelectionChanged", () => {
  it("is false when the same agent is selected again", () => {
    // THE regression this file exists for: the revision-load effect re-runs
    // when the agent list arrives or a draft is restored, not only when the
    // selection moves. Resetting THEN discarded the operator's "offline only"
    // choice and launched the run with the agent's full declared egress.
    expect(agentSelectionChanged("triage-bot", "triage-bot")).toBe(false);
  });

  it("is true when the selection moves to another agent", () => {
    // A narrowing chosen against one declaration means nothing against another.
    expect(agentSelectionChanged("triage-bot", "release-bot")).toBe(true);
  });

  it("is true for the first selection, when nothing is loaded yet", () => {
    expect(agentSelectionChanged(null, "triage-bot")).toBe(true);
  });
});

describe("isCeilingOptionAllowed", () => {
  it("allows every ceiling when the provider enforces egress", () => {
    for (const m of MODE_ORDER) expect(isCeilingOptionAllowed(m, "offline", true)).toBe(true);
  });

  it("allows LOWERING a stored ceiling with no enforcer present", () => {
    // Disabling the whole control locked an admin out of remediating a
    // too-permissive ceiling — the opposite of what the guard is for.
    expect(isCeilingOptionAllowed("offline", "public", false)).toBe(true);
    expect(isCeilingOptionAllowed("approved", "public", false)).toBe(true);
  });

  it("allows keeping the ceiling exactly where it is", () => {
    expect(isCeilingOptionAllowed("public", "public", false)).toBe(true);
  });

  it("refuses to widen a ceiling the deployment cannot enforce", () => {
    expect(isCeilingOptionAllowed("public", "offline", false)).toBe(false);
    expect(isCeilingOptionAllowed("approved", "offline", false)).toBe(false);
  });
});
