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

/** The port a fresh target starts on, and the range the wire can carry: a
 *  `PortSpec` is a pair of `u16`s server-side and core refuses port 0
 *  outright, so both ends of an edit have to land inside this. */
export const DEFAULT_PORT = 443;
export const MIN_PORT = 1;
export const MAX_PORT = 65535;

export type PortEdge = "from" | "to";

/** The one range a two-box editor can represent. `null` for a rule naming NO
 *  ports (which means "any port", not 443) and for one naming SEVERAL, because
 *  showing either as a concrete pair misstates the rule and editing it would
 *  silently rewrite `ports` to just the pair on screen. */
export function singleRange(ports: PortSpec[]): PortSpec | null {
  return ports.length === 1 ? ports[0] : null;
}

/** What a typed port MEANS, or `null` for "the field is mid-edit". Kept apart
 *  from the edit below for the reason `policy-caps.ts` exists: `Number("")` is
 *  `0`, and 0 is a port core refuses — so an empty field must never reach the
 *  model as a value. Anything usable is clamped into the wire's range and
 *  floored, never rounded. */
function parsePort(raw: string): number | null {
  const t = raw.trim();
  if (t === "") return null;
  const n = Number(t);
  if (!Number.isFinite(n)) return null;
  return Math.min(Math.max(Math.floor(n), MIN_PORT), MAX_PORT);
}

/** Immutable single-range edit that cannot produce a range the server will
 *  reject: raising `from` carries `to` up with it and lowering `to` carries
 *  `from` down, so the pair can never invert, and an unusable entry leaves the
 *  range untouched. Both edges go through this — having only one of them clamp
 *  is how `443-80` reached the API and failed the whole save. */
export function withPortEdge(ports: PortSpec[], edge: PortEdge, raw: string): PortSpec[] {
  const value = parsePort(raw);
  if (value === null) return ports;
  const current = singleRange(ports) ?? { from: value, to: value };
  return [
    edge === "from"
      ? { from: value, to: Math.max(value, current.to) }
      : { from: Math.min(value, current.from), to: value },
  ];
}

/** What actually leaves the browser. ONLY `approved` carries targets: core
 *  refuses public+targets outright, and it ACCEPTS offline+targets — which is
 *  worse, because the editor hides the target list for offline, so the stored
 *  declaration would keep authority nobody saw or approved.
 *
 *  Deliberately applied at submit rather than on the mode select, so toggling
 *  modes while deciding does not destroy the targets already typed. */
export function requestForWire(n: NetworkRequest): NetworkRequest {
  return { ...n, targets: n.mode === "approved" ? n.targets : [] };
}

/** The per-run override, whose whole authority is to NARROW: offline is the
 *  only thing this UI can ask for, and `undefined` means "inherit whatever the
 *  agent declared". */
export function runNetworkOverride(offlineOnly: boolean): NetworkRequest | undefined {
  return offlineOnly ? OFFLINE_REQUEST : undefined;
}

/** Whether the composer must drop the declaration on screen AND the per-run
 *  narrowing chosen against it.
 *
 *  TRUE only when the selection actually moved to a DIFFERENT agent. The
 *  revision-load effect also re-runs when the agent list arrives or a draft is
 *  restored; resetting on those re-runs silently discarded the operator's
 *  "offline only" choice and launched the run with the agent's full declared
 *  egress — a widening nothing on screen reported. A narrowing is meaningless
 *  against a declaration it was never chosen against, which is why the agent
 *  identity, not the effect firing, is what decides. */
export function agentSelectionChanged(loadedFor: string | null, selected: string): boolean {
  return loadedFor !== selected;
}

/** Whether a ceiling is selectable. A deployment whose provider cannot enforce
 *  egress must not be able to RAISE the ceiling — but it must always be able
 *  to LOWER one it already carries (set via the API, or left behind when an
 *  enforcer was removed). Disabling the control outright locked an admin out
 *  of remediating exactly the too-permissive policy it meant to guard. */
export function isCeilingOptionAllowed(
  option: NetworkGrantMode,
  current: NetworkGrantMode,
  supportsEgressGrants: boolean,
): boolean {
  if (supportsEgressGrants) return true;
  return MODE_ORDER.indexOf(option) <= MODE_ORDER.indexOf(current);
}

/** One line for a chip or a header row. `approved` carries its target count
 *  because an approved declaration with NO targets grants nothing, and
 *  rendering it as a bare "Approved targets" would imply egress it lacks. */
export function summarizeRequest(n: NetworkRequest): string {
  if (n.mode !== "approved") return MODE_LABEL[n.mode];
  if (n.targets.length === 0) return `${MODE_LABEL[n.mode]} \u00b7 none yet`;
  return `${MODE_LABEL[n.mode]} \u00b7 ${n.targets.length} target${n.targets.length === 1 ? "" : "s"}`;
}
