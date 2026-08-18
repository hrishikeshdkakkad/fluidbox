// The run composer's selections, as URL state.
//
// The composer is a modal with ~30 pieces of state, and until now none of it
// survived a reload or a shared link: two people could not look at the same
// half-configured run, and the browser's back button did nothing.
//
// What goes in the URL is deliberately narrower than the draft that goes to
// localStorage: only the DISCRETE CHOICES a person clicks. Free text (the
// task, the system prompt, an agent's description) stays out — it is not a
// selection, it can be long enough to blow past URL limits, and a task
// describes work that may be nobody else's business. localStorage already
// keeps that text across a reload in the same tab.
//
// Pure functions over URLSearchParams so they are testable in this repo's
// node-only vitest setup (composer-url.test.ts) — the same reason lib/nav.ts
// and lib/activity.ts are shaped this way.

/** Which composer is open. Absent means none. */
export type ComposeKind = "run" | "agent";

export type ApprovalsChoice = "wait" | "auto";

export interface ComposerUrl {
  compose: ComposeKind;
  /** Run once, or save the same governed run behind a trigger. */
  mode: "once" | "automation";
  agentChoice: "existing" | "new";
  /** The selected agent by NAME — ids are opaque and this is a shareable URL. */
  agent: string;
  harness: string;
  model: string;
  policy: string;
  approvals: ApprovalsChoice;
  workspace: "default" | "scratch" | "local" | "git";
  /** Automation mode only: what fires the run. */
  trigger: "api" | "schedule" | "event";
}

/** Every key this module owns. Anything else in the query is left alone. */
export const COMPOSER_PARAMS = [
  "compose",
  "mode",
  "agentChoice",
  "agent",
  "harness",
  "model",
  "policy",
  "approvals",
  "workspace",
  "trigger",
] as const satisfies readonly (keyof ComposerUrl)[];

const COMPOSE: readonly ComposeKind[] = ["run", "agent"];
const MODES: readonly ComposerUrl["mode"][] = ["once", "automation"];
const AGENT_CHOICES: readonly ComposerUrl["agentChoice"][] = ["existing", "new"];
const APPROVALS: readonly ApprovalsChoice[] = ["wait", "auto"];
const WORKSPACES: readonly ComposerUrl["workspace"][] = ["default", "scratch", "local", "git"];
const TRIGGERS: readonly ComposerUrl["trigger"][] = ["api", "schedule", "event"];

/** Longest agent/harness/model/policy name we will read back out of a URL. */
const MAX_NAME_CHARS = 128;

function readEnum<T extends string>(
  params: URLSearchParams,
  key: string,
  allowed: readonly T[]
): T | undefined {
  const raw = params.get(key);
  return raw !== null && (allowed as readonly string[]).includes(raw) ? (raw as T) : undefined;
}

function readName(params: URLSearchParams, key: string): string | undefined {
  const raw = params.get(key)?.trim();
  // A hand-edited URL is untrusted input: ignore an over-long value rather
  // than seeding state with it. Nothing here is a security boundary — every
  // choice is re-validated server-side at submit — but a 50KB "model" in a
  // select is a broken screen.
  if (!raw || raw.length > MAX_NAME_CHARS) return undefined;
  return raw;
}

/**
 * Read the composer's selections out of a query string. Unknown or malformed
 * values are DROPPED, never surfaced: an unrecognised `model=` must fall back
 * to the component's own default rather than select nothing at all.
 */
export function readComposerUrl(params: URLSearchParams): Partial<ComposerUrl> {
  const state: Partial<ComposerUrl> = {};

  const compose = readEnum(params, "compose", COMPOSE);
  if (compose) state.compose = compose;
  const mode = readEnum(params, "mode", MODES);
  if (mode) state.mode = mode;
  const agentChoice = readEnum(params, "agentChoice", AGENT_CHOICES);
  if (agentChoice) state.agentChoice = agentChoice;
  const approvals = readEnum(params, "approvals", APPROVALS);
  if (approvals) state.approvals = approvals;
  const workspace = readEnum(params, "workspace", WORKSPACES);
  if (workspace) state.workspace = workspace;
  const trigger = readEnum(params, "trigger", TRIGGERS);
  if (trigger) state.trigger = trigger;

  const agent = readName(params, "agent");
  if (agent) state.agent = agent;
  const harness = readName(params, "harness");
  if (harness) state.harness = harness;
  const model = readName(params, "model");
  if (model) state.model = model;
  const policy = readName(params, "policy");
  if (policy) state.policy = policy;

  return state;
}

/**
 * Merge composer selections into an existing query, preserving params this
 * module does not own. An `undefined` or empty value REMOVES its key, so a
 * closed composer leaves the address bar exactly as it found it.
 *
 * Returns the search string WITHOUT a leading "?" (empty when no params
 * remain), so callers can build a path without special-casing.
 */
export function writeComposerUrl(
  state: Partial<ComposerUrl>,
  existing: URLSearchParams
): string {
  const next = new URLSearchParams(existing);
  for (const key of COMPOSER_PARAMS) {
    const value = state[key];
    if (value === undefined || value === "") {
      next.delete(key);
    } else {
      next.set(key, value);
    }
  }
  return next.toString();
}

/** Strip every composer key — what closing the composer leaves behind. */
export function clearComposerUrl(existing: URLSearchParams): string {
  const next = new URLSearchParams(existing);
  for (const key of COMPOSER_PARAMS) next.delete(key);
  return next.toString();
}

/** A path plus a search string, for history.replaceState. */
export function composerHref(pathname: string, search: string): string {
  return search ? `${pathname}?${search}` : pathname;
}
