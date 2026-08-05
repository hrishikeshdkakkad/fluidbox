// Presentation helpers for sandbox network grants. Formatting and ordering
// ONLY — what a policy MEANS is resolved server-side by /policies/preview.

import {
  NetworkGrantMode,
  NetworkPolicy,
  NetworkRequest,
  PolicyContent,
  PortSpec,
  TargetRule,
} from "./api";

/** The fail-safe section a policy has when it has never configured egress. */
export const OFFLINE_NETWORK: NetworkPolicy = {
  max_mode: "offline",
  allow: [],
  deny: [],
  require_approval: false,
  allow_public_with_brokered: false,
  max_grant_secs: null,
};

/** The server OMITS `network` when it is at its default, so this is not a
 *  convenience — every read of the section must go through it. */
export function networkOf(content: PolicyContent): NetworkPolicy {
  return content.network ?? OFFLINE_NETWORK;
}

/** Ceiling order. A test pins this: reordering it would silently widen or
 *  narrow every comparison built on it. */
export const MODE_ORDER: NetworkGrantMode[] = ["offline", "approved", "public"];

export const MODE_LABEL: Record<NetworkGrantMode, string> = {
  offline: "Offline",
  approved: "Approved targets",
  public: "Public",
};

export const MODE_HINT: Record<NetworkGrantMode, string> = {
  offline: "No egress at all beyond the control plane. The default.",
  approved: "Exactly the targets listed below, and nothing else.",
  public: "Everything the deployment's deny wall does not forbid.",
};

export function portsLabel(ports: PortSpec[]): string {
  if (ports.length === 0) return "any port";
  return ports.map((p) => (p.from === p.to ? `${p.from}` : `${p.from}-${p.to}`)).join(", ");
}

export function describeTarget(t: TargetRule): string {
  const where =
    t.kind === "cidr"
      ? t.cidr
      : t.pattern.kind === "exact"
        ? t.pattern.name
        : `*.${t.pattern.suffix}`;
  return `${where} ${t.protocol.toUpperCase()} ${portsLabel(t.ports)}`;
}

/** What a revision declares when it declares nothing. The server documents the
 *  field as "omitted means offline" (api.rs), so an ABSENT declaration is a
 *  known fact — unlike a policy read that FAILED, which must stay "unknown". */
export const OFFLINE_REQUEST: NetworkRequest = {
  mode: "offline",
  targets: [],
  duration_secs: null,
};

/** Every read of a revision's declaration goes through this, for the same
 *  reason `networkOf` exists for a policy: the field is routinely absent. */
export function requestOf(network: NetworkRequest | null | undefined): NetworkRequest {
  return network ?? OFFLINE_REQUEST;
}

/** One line for a chip or a header row. `approved` carries its target count
 *  because an approved declaration with NO targets grants nothing, and
 *  rendering it as a bare "Approved targets" would imply egress it lacks. */
export function summarizeRequest(n: NetworkRequest): string {
  if (n.mode !== "approved") return MODE_LABEL[n.mode];
  if (n.targets.length === 0) return `${MODE_LABEL[n.mode]} \u00b7 none yet`;
  return `${MODE_LABEL[n.mode]} \u00b7 ${n.targets.length} target${n.targets.length === 1 ? "" : "s"}`;
}
