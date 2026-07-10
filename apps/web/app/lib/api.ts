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
  provider: string; // github (PAT) | github_app
  external_account_id: string;
  display_name: string;
  granted_scopes: string[];
  status: string;
  metadata: {
    login?: string;
    app_slug?: string;
    account_login?: string;
    installation_id?: string;
  };
  created_at: string;
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
