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
