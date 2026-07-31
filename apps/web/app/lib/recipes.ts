// Recipes: types mirroring the Rust /v1/recipes responses + the PURE form
// model the deploy wizard renders from. The server is the only validator —
// everything here is presentation shaping (prefill, blocking-issue message,
// value coercion) and is vitest-covered like every other lib/ module.

import type { Connection } from "./api";

// ─── Wire types (mirror crates/fluidbox-server/src/recipes.rs) ────────────

export interface RecipeConnectorFacet {
  param: string;
  title: string;
  provider: string | null;
  mcp: boolean;
  required: boolean;
}

export interface RecipeFacets {
  agent_count: number;
  multi_agent: boolean;
  trigger_kinds: string[];
  connectors: RecipeConnectorFacet[];
  cost_ceiling_usd: number;
  instant_run: boolean;
  success_criteria: string[];
}

export interface RecipeCard {
  id: string;
  slug: string;
  name: string;
  tagline: string;
  category: string;
  tags: string[];
  tier: string;
  icon: string;
  custom: boolean;
  latest_version: number;
  facets: RecipeFacets;
  updated_at: string;
}

export type RecipeWidget =
  | { kind: "text" }
  | { kind: "textarea" }
  | { kind: "url" }
  | { kind: "number" }
  | { kind: "boolean" }
  | { kind: "select" }
  | { kind: "string_list" }
  | { kind: "repositories" }
  | { kind: "cron" }
  | { kind: "timezone" }
  | { kind: "model"; harness: string }
  | { kind: "connection"; provider: string | null; mcp: boolean }
  | { kind: "connection_tools"; connection_param: string }
  | { kind: "events" };

export interface RecipeParamSpec {
  name: string;
  title: string;
  description: string | null;
  required: boolean;
  default: unknown;
  widget: RecipeWidget;
  choices: unknown[] | null;
  ui: Record<string, unknown> | null;
}

export interface RecipeManifest {
  policy: boolean;
  agents: { slot: string; harness: string }[];
  subscriptions: { slot: string; agent_slot: string; kind: string }[];
  first_run: boolean;
}

export interface RecipePolicySummary {
  embedded: boolean;
  note?: string;
  default_action?: string;
  autonomy_permitted?: boolean;
  on_approval_rule?: string;
  budgets?: Record<string, number | null>;
  rules?: { tools: string[]; action: string; constrained: boolean }[];
}

export interface RecipeDetail {
  recipe: RecipeCard & { description: string };
  version: {
    version: number;
    definition: unknown;
    params_schema: unknown;
    changelog: string | null;
    created_at: string;
  };
  params: RecipeParamSpec[];
  facets: RecipeFacets;
  manifest: RecipeManifest;
  policy_summary: RecipePolicySummary;
  summary_md: string | null;
  versions: { version: number; changelog: string | null; author: string; created_at: string }[];
}

export interface RecipeInstance {
  id: string;
  recipe_id: string;
  recipe_slug: string;
  recipe_version: number;
  name: string;
  params: Record<string, unknown>;
  status: "active" | "paused" | "deleted";
  created_by_user_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface RecipeInstanceListEntry {
  instance: RecipeInstance;
  latest_version: number;
  update_available: boolean;
}

export interface InstanceObject {
  kind: "policy" | "agent" | "subscription" | "session";
  object_id: string;
  slot: string;
  name: string | null;
  session_status: string | null;
  subscription_enabled: boolean | null;
  created_at: string;
}

export interface InstanceContract {
  slot: string;
  subscription_id: string;
  base_url: string;
  invoke_url: string;
  poll_url_template: string;
  ingress_url: string | null;
}

export interface DeployPlan {
  instance: { name: string };
  policy: { name: string } | null;
  agents: { slot: string; name: string; harness: string; model: string; budgets: Record<string, number | null> }[];
  subscriptions: {
    slot: string;
    name: string;
    kind: string;
    agent_slot: string;
    events: unknown;
    repositories: unknown;
    publish: unknown;
    schedule: { cron: string; timezone: string; missed_run_policy: string; first_fire_at: string } | null;
    signed_webhook: boolean;
    autonomous: boolean;
  }[];
  first_run: { agent_slot: string } | null;
  cost_ceiling_usd: number;
  policy_summary: RecipePolicySummary;
}

export interface DeployResult {
  instance: RecipeInstance;
  objects: { kind: string; id: string; slot: string; name?: string; trigger_kind?: string }[];
  plan: DeployPlan;
  secrets: {
    note: string;
    trigger_tokens: Record<string, string>;
    callback_secrets: Record<string, string>;
  };
  contracts: InstanceContract[];
  first_run: { session_id?: string; error?: string } | null;
}

export interface UpgradePlan {
  from_version: number;
  to_version: number;
  agents_updated: string[];
  subscriptions_updated: { slot: string; updated: boolean }[];
  policy_updated: boolean;
}

// ─── Pure form model ──────────────────────────────────────────────────────

/** Prefill: every param with a declared default starts filled. */
export function initialParams(specs: RecipeParamSpec[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const s of specs) {
    if (s.default !== null && s.default !== undefined) out[s.name] = s.default;
  }
  return out;
}

function isBlank(v: unknown): boolean {
  if (v === null || v === undefined) return true;
  if (typeof v === "string") return v.trim() === "";
  if (Array.isArray(v)) return v.length === 0;
  return false;
}

/**
 * The single always-live gate message for the primary button (the RunComposer
 * `blockingIssue` pattern): the FIRST missing input, phrased as the next
 * action. Server-side validation still runs on submit; this only shapes UX.
 */
export function blockingIssue(
  name: string,
  specs: RecipeParamSpec[],
  values: Record<string, unknown>,
): string | null {
  if (name.trim() === "") return "Name this deployment";
  if (name.trim().length > 48) return "Deployment names are at most 48 characters";
  for (const s of specs) {
    if (!s.required) continue;
    if (isBlank(values[s.name])) {
      if (s.widget.kind === "connection") return `Choose a ${s.title.toLowerCase()}`;
      if (s.widget.kind === "connection_tools") return `Pick the ${s.title.toLowerCase()}`;
      return `Fill in ${s.title.toLowerCase()}`;
    }
  }
  return null;
}

/** "a, b, c" or newline-separated text → trimmed string list (chips inputs). */
export function listFromText(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Send only non-blank values — absent optional params must stay absent. */
export function paramsForSubmit(
  specs: RecipeParamSpec[],
  values: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const s of specs) {
    const v = values[s.name];
    if (isBlank(v)) continue;
    if (s.widget.kind === "number" && typeof v === "string") {
      const n = Number(v);
      if (!Number.isNaN(n)) out[s.name] = n;
      continue;
    }
    out[s.name] = v;
  }
  return out;
}

/** Which of the tenant's connections satisfy a connection widget's filter. */
export function eligibleConnections(
  widget: Extract<RecipeWidget, { kind: "connection" }>,
  connections: Connection[],
): Connection[] {
  return connections.filter((c) => {
    if (c.status !== "active") return false;
    if (widget.mcp) return c.provider === "mcp_http";
    if (widget.provider === "github")
      return c.provider === "github" || c.provider === "github_app";
    if (widget.provider) return c.provider === widget.provider;
    return true;
  });
}

/** "Ready to deploy": every REQUIRED connector facet has an active match. */
export function recipeReady(facets: RecipeFacets, connections: Connection[]): boolean {
  return facets.connectors
    .filter((c) => c.required)
    .every((c) =>
      eligibleConnections(
        { kind: "connection", provider: c.provider, mcp: c.mcp },
        connections,
      ).length > 0,
    );
}

/** Case-insensitive match over the card's searchable text. */
export function cardMatches(card: RecipeCard, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [card.name, card.tagline, card.category, card.slug, ...(card.tags ?? [])]
    .join(" ")
    .toLowerCase()
    .includes(q);
}

/** Stable category ordering: official curated order first, then the rest. */
const CATEGORY_ORDER = ["code-review", "ci-cd", "compliance", "support", "onboarding"];
export function groupByCategory(cards: RecipeCard[]): [string, RecipeCard[]][] {
  const groups = new Map<string, RecipeCard[]>();
  for (const c of cards) {
    const list = groups.get(c.category) ?? [];
    list.push(c);
    groups.set(c.category, list);
  }
  return [...groups.entries()].sort(([a], [b]) => {
    const ia = CATEGORY_ORDER.indexOf(a);
    const ib = CATEGORY_ORDER.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib) || a.localeCompare(b);
  });
}

/** Human trigger-kind labels for card chips. */
export function triggerLabel(kind: string): string {
  switch (kind) {
    case "event":
      return "On pull request";
    case "schedule":
      return "Scheduled";
    case "api":
      return "API trigger";
    case "instant":
      return "Runs on deploy";
    default:
      return kind;
  }
}

const PREFILL_KEY = "fluidbox-recipe-prefill";

/** Duplicate flow: the instance page stashes name+params; the wizard reads
 * them once. sessionStorage (not URL) — params may be large and are not
 * secrets, but they don't belong in history either. */
export function stashPrefill(slug: string, name: string, params: Record<string, unknown>) {
  try {
    sessionStorage.setItem(PREFILL_KEY, JSON.stringify({ slug, name, params }));
  } catch {
    /* storage full/blocked — duplicate degrades to a blank form */
  }
}

export function takePrefill(slug: string): { name: string; params: Record<string, unknown> } | null {
  try {
    const raw = sessionStorage.getItem(PREFILL_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { slug: string; name: string; params: Record<string, unknown> };
    if (parsed.slug !== slug) return null;
    sessionStorage.removeItem(PREFILL_KEY);
    return { name: parsed.name, params: parsed.params };
  } catch {
    return null;
  }
}
