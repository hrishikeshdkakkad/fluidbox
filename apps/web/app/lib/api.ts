// Browser-side client. All calls go to the same-origin proxy, which injects
// the admin token server-side. The browser never holds a credential.

const BASE = "/api/fluidbox";

export async function apiGet<T = unknown>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
  return res.json();
}

export async function apiPost<T = unknown>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(text || `${res.status}`);
  return text ? JSON.parse(text) : ({} as T);
}

export function streamUrl(sessionId: string): string {
  return `${BASE}/sessions/${sessionId}/events/stream`;
}

// ─── Types ────────────────────────────────────────────────────────────────

export interface Session {
  id: string;
  status: string;
  autonomy: string;
  task: string;
  agent_id: string;
  result_summary: string | null;
  created_at: string;
  base_commit: string | null;
  repo_source: WorkspaceSpec | null;
  trigger: InvocationEnvelope | null;
  /** The frozen RunSpec (jsonb); only the slices the UI renders are typed. */
  run_spec?: {
    capabilities?: FrozenBundle[];
  } | null;
}

/** Mirrors fluidbox-core FrozenBundle (RunSpec.capabilities entries). */
export interface FrozenBundle {
  id: string;
  name: string;
  version: number;
  definition_digest: string;
  servers: { class: "sandbox" | "brokered"; name: string; tools: { name: string }[] }[];
}

/** Mirrors fluidbox-core InvocationContext (sessions.trigger jsonb). */
export interface InvocationEnvelope {
  kind: string; // manual | api | schedule | event
  subscription_id?: string;
  actor?: string;
  attributes?: Record<string, unknown>;
  received_at?: string;
}

export interface Agent {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
}

export interface Revision {
  id: string;
  rev: number;
  harness: string;
  model: string;
  runner_image: string;
  system_prompt: string | null;
  policy_id: string;
  budgets: Record<string, unknown>;
  default_workspace: WorkspaceSpec | null;
  /** §17 #7 pins: exact bundle versions resolved at attach time. */
  capability_bundles: BundleRef[];
  created_at: string;
}

/** Mirrors fluidbox-core BundleRef (agent_revisions.capability_bundles). */
export interface BundleRef {
  id: string;
  name: string;
  version: number;
}

/** "name@version, name@version" — the attachment refs as text. */
export function bundleRefsLabel(refs: BundleRef[] | null | undefined): string {
  if (!refs || refs.length === 0) return "";
  return refs.map((r) => `${r.name}@${r.version}`).join(", ");
}

/** One version row of the capability-bundle registry (list shape). */
export interface CapabilityBundle {
  id: string;
  name: string;
  version: number;
  description: string | null;
  definition_digest: string;
  server_count: number;
  tool_count: number;
  classes: string[];
  created_at: string;
}

/** Mirrors fluidbox-core WorkspaceSpec (tagged by `kind`). */
export interface WorkspaceSpec {
  kind: "scratch" | "local_copy" | "git_repository" | "none" | "local_path";
  path?: string;
  connection_id?: string;
  repository?: string;
  clone_url?: string;
  ref?: string;
  commit_sha?: string;
}

/** Human one-liner for a workspace spec (old + new wire tags). */
export function workspaceLabel(ws: WorkspaceSpec | null | undefined): string {
  if (!ws || ws.kind === "scratch" || ws.kind === "none") return "scratch";
  if (ws.kind === "local_copy" || ws.kind === "local_path") return `local: ${ws.path}`;
  const repo = ws.repository || ws.clone_url || "?";
  const at = ws.commit_sha ? `@${ws.commit_sha.slice(0, 8)}` : ws.ref ? `@${ws.ref}` : "";
  return `${repo}${at}`;
}

export interface Connection {
  id: string;
  provider: string; // github (PAT) | github_app | mcp_http
  external_account_id: string;
  display_name: string;
  granted_scopes: string[];
  status: string; // active | pending | error | revoked
  metadata: {
    login?: string;
    app_slug?: string;
    account_login?: string;
    installation_id?: string;
    base_url?: string;
    header_name?: string;
    scheme?: string;
  };
  /** static (pasted secret) | oauth (custodied rotating refresh token). */
  auth_kind: string;
  /** Non-secret OAuth custody state; null on static connections. */
  oauth: {
    resource?: string;
    issuer?: string;
    client_id?: string;
    client_id_source?: string; // preregistered | cimd | dcr
    scopes?: string[];
    error?: string;
  } | null;
  created_at: string;
}

/** One connector-catalog entry (untrusted reference data; tool_hints are
 *  policy-default seeds — the permission gate stays the judge). */
export interface CatalogEntry {
  id: string;
  slug: string;
  name: string;
  icon: string | null;
  description: string | null;
  categories: string[];
  tier: string; // verified | community | custom
  url: string | null;
  transport: string; // streamable_http | stdio
  auth_mode: "none" | "api_key" | "oauth";
  auth_hints: {
    header_name?: string;
    scheme?: string;
    composite?: string;
    key_url?: string;
    placeholder?: string;
  };
  scopes: string[];
  egress: string[];
  tool_hints: { pattern: string; action: string; note?: string }[];
  sandbox_launch: unknown | null;
  created_at: string;
}

/** POST /catalog/{slug}/connect response (fields vary by auth_mode). */
export interface CatalogConnectResult {
  bundle?: { name: string; version: number };
  connection?: Connection;
  authorize_url?: string;
}

/** Where a github_app connection receives provider webhooks. */
export function ingressPath(c: Connection): string | null {
  return c.provider === "github_app" ? `/v1/ingress/github/${c.id}` : null;
}

export interface Repo {
  id: number;
  full_name: string;
  private: boolean;
  default_branch: string;
  html_url: string;
}

export interface TriggerSubscription {
  id: string;
  agent_id: string;
  name: string;
  trigger_kind: string; // api | schedule | event
  pinned_revision_id: string | null;
  enabled: boolean;
  task_template: string | null;
  allow_task_override: boolean;
  allow_workspace_override: boolean;
  autonomy: string | null;
  concurrency_policy: string;
  result_destinations: { kind: string; url?: string }[];
  /* event subscriptions only */
  connection_id: string | null;
  resource_selector: { repositories?: string[] } | null;
  event_filter: { events?: string[] } | null;
  event_publish: string[] | null;
  /** Capability keep-list (§3.5 narrowing); null = keep all attached. */
  capability_bundles: string[] | null;
  created_at: string;
}

/** The clock on a subscription (schedules table). */
export interface Schedule {
  id: string;
  subscription_id: string;
  cron: string;
  timezone: string;
  next_fire_at: string | null;
  missed_run_policy: string;
  last_fired_at: string | null;
}

/** One claim row: a firing/invoke bound to a run, or a recorded skip. */
export interface TriggerInvocation {
  id: string;
  subscription_id: string;
  idempotency_key: string;
  session_id: string | null;
  skip_reason: string | null;
  created_at: string;
}

export interface ResultDelivery {
  id: string;
  session_id: string;
  subscription_id: string | null;
  destination: { kind: string; url?: string };
  status: string; // pending | delivered | failed
  attempts: number;
  next_attempt_at: string;
  last_error: string | null;
  delivered_at: string | null;
  created_at: string;
}

export interface Approval {
  id: string;
  session_id: string;
  tool_call_id: string;
  tool: string;
  summary: string;
  risk: string | null;
  scope: string;
  status: string;
  requested_at: string;
  expires_at: string;
}

export interface Artifact {
  id: string;
  kind: string;
  name: string;
  content: string;
  content_type: string;
}

export interface Usage {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  cost_usd: number;
  requests: number;
}

export interface EventRow {
  seq: number;
  type: string;
  actor: string;
  payload: { type?: string; data?: Record<string, unknown> };
  occurred_at: string;
}

export const TERMINAL = ["completed", "failed", "cancelled", "budget_exceeded"];
export function isTerminal(status: string): boolean {
  return TERMINAL.includes(status);
}
