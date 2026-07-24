// Browser-side client. All calls go to the same-origin proxy. In admin mode the
// proxy injects the admin token server-side; in sso mode it forwards the
// browser's session cookie. Either way the browser never holds a credential.

const BASE = "/api/fluidbox";

// The deployment mode is server-authoritative: the root layout stamps it onto
// <html data-web-mode>. Only two things vary by mode client-side, and both are
// presentation, not authorization: writes carry the CSRF header (required in
// sso, inert under the admin bearer path), and a 401 in sso mode means the
// browser session is missing/expired, so we send the user to /login.
function ssoMode(): boolean {
  return (
    typeof document !== "undefined" &&
    document.documentElement.dataset.webMode === "sso"
  );
}

/** Cookie-authenticated writes require this header (the control plane rejects
 *  cookie non-GETs without it); the admin bearer path ignores it. */
const CSRF_HEADERS = { "x-fluidbox-csrf": "1" } as const;

/** In sso mode a 401 means "no live session" — route the browser to the login
 *  page, carrying the current location so the deep link survives the IdP
 *  round-trip (login-form.tsx forwards it as redirect_to; the control plane
 *  validates it). Guarded against a redirect loop when already on /login.
 *  Admin mode never triggers this (the injected bearer is always present). */
function redirectOnUnauthorized(res: Response): void {
  if (res.status !== 401 || !ssoMode() || typeof window === "undefined") return;
  if (window.location.pathname !== "/login") {
    const here = window.location.pathname + window.location.search;
    const next = here === "/" ? "" : `?next=${encodeURIComponent(here)}`;
    window.location.href = `/login${next}`;
  }
}

type CachedGet = { value: unknown; expiresAt: number };
const getCache = new Map<string, CachedGet>();
const inflightGets = new Map<string, Promise<unknown>>();
let cacheGeneration = 0;

async function fetchGet<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { cache: "no-store" });
  if (!res.ok) {
    redirectOnUnauthorized(res);
    throw new Error(`${res.status}: ${await res.text()}`);
  }
  return res.json();
}

/**
 * Forget cached read models after a write. Prefix invalidation is available for
 * targeted refresh buttons; writes clear everything because these projections
 * overlap (a new connection changes catalog, resources, and picker options).
 */
export function invalidateApiCache(prefix = ""): void {
  cacheGeneration += 1;
  for (const path of getCache.keys()) {
    if (!prefix || path.startsWith(prefix)) getCache.delete(path);
  }
  for (const path of inflightGets.keys()) {
    if (!prefix || path.startsWith(prefix)) inflightGets.delete(path);
  }
}

export async function apiGet<T = unknown>(path: string): Promise<T> {
  const existing = inflightGets.get(path);
  if (existing) return existing as Promise<T>;

  const request = fetchGet<T>(path);
  const tracked = request.finally(() => {
    // An invalidation may have removed this request and allowed a newer one to
    // occupy the same path. The older completion must not evict the newer read.
    if (inflightGets.get(path) === tracked) inflightGets.delete(path);
  });
  inflightGets.set(path, tracked);
  return tracked;
}

/**
 * Private, per-tab read-through cache for reusable control-plane projections.
 * The underlying response remains `no-store`, so credentials and tenant data
 * never enter a browser or shared HTTP cache.
 */
export async function apiGetCached<T = unknown>(
  path: string,
  { maxAgeMs = 15_000, force = false }: { maxAgeMs?: number; force?: boolean } = {}
): Promise<T> {
  if (force) invalidateApiCache(path);
  const cached = getCache.get(path);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.value as T;
  }

  const generation = cacheGeneration;
  const value = await apiGet<T>(path);
  // A successful write or explicit refresh may have invalidated this read
  // while it was in flight. Return it to its original caller, but never let
  // that older projection repopulate the shared per-tab cache.
  if (generation === cacheGeneration) {
    getCache.set(path, { value, expiresAt: Date.now() + Math.max(0, maxAgeMs) });
  }
  return value;
}

export async function apiPost<T = unknown>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...CSRF_HEADERS },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    redirectOnUnauthorized(res);
    throw new Error(text || `${res.status}`);
  }
  invalidateApiCache();
  return text ? JSON.parse(text) : ({} as T);
}

export async function apiPut<T = unknown>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "PUT",
    headers: { "content-type": "application/json", ...CSRF_HEADERS },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    redirectOnUnauthorized(res);
    throw new Error(text || `${res.status}`);
  }
  invalidateApiCache();
  return text ? JSON.parse(text) : ({} as T);
}

// No call sites yet — this exists so a future partial-update goes through the
// sanctioned surface (CSRF header + 401→/login) instead of a raw fetch.
export async function apiPatch<T = unknown>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "PATCH",
    headers: { "content-type": "application/json", ...CSRF_HEADERS },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    redirectOnUnauthorized(res);
    throw new Error(text || `${res.status}`);
  }
  invalidateApiCache();
  return text ? JSON.parse(text) : ({} as T);
}

export async function apiDelete<T = unknown>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { method: "DELETE", headers: { ...CSRF_HEADERS } });
  const text = await res.text();
  if (!res.ok) {
    redirectOnUnauthorized(res);
    throw new Error(text || `${res.status}`);
  }
  invalidateApiCache();
  return text ? JSON.parse(text) : ({} as T);
}

export function streamUrl(sessionId: string): string {
  return `${BASE}/sessions/${sessionId}/events/stream`;
}

/** GET /auth/me — who the current browser session belongs to (sso mode). The
 *  admin token yields `{ operator: true }` instead; users get org + identity.
 *  The dashboard renders this; it never derives authority from it. */
export interface AuthMe {
  operator?: boolean;
  /** Stable id of the signed-in user (Phase C): lets the dashboard tell "my
   *  personal connection" from a teammate's. Absent for the operator and in
   *  admin mode — ownership rendering degrades to org/personal without "yours".
   *  The server still owner-filters; this is presentation only. */
  user_id?: string;
  org?: { slug: string; display_name: string } | null;
  user?: { email: string | null; name: string | null } | null;
  roles?: string[];
  auth_kind?: string;
}

/** sso mode: end the browser session, then return to the login page. The write
 *  carries the CSRF header; the response body is irrelevant. */
export async function logout(): Promise<void> {
  await fetch(`${BASE}/auth/logout`, { method: "POST", headers: { ...CSRF_HEADERS } });
  if (typeof window !== "undefined") window.location.href = "/login";
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
  /** Phase C (design :349-389): brokered connection requirements this revision
   *  declares — *what* it needs per slot, never *whose* credential. Resolved
   *  per-run into bindings. Defaults to [] on pre-Phase-C revisions. */
  connection_requirements?: ConnectionRequirement[];
  created_at: string;
}

/** Which identity's credential should satisfy a requirement's binding at run
 *  creation (mirrors fluidbox-core BindingMode, snake_case on the wire). */
export type BindingMode = "invoking_user" | "organization";

/** How a requirement names the connector it needs. `url` is the load-bearing
 *  selector (the brokered MCP endpoint); `slug` is an optional catalog hint. */
export interface ConnectorSelector {
  url: string;
  slug?: string | null;
}

/** What an agent revision declares it needs per slot (mirrors fluidbox-core
 *  ConnectionRequirement). `required_tools` is a fail-closed contract: every
 *  entry must exist in the bound connection's snapshot at run creation. */
export interface ConnectionRequirement {
  slot: string;
  connector: ConnectorSelector;
  required_tools: string[];
  binding_mode: BindingMode;
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
  /** Wire value, server-controlled. See ConnectionProvider for the ones this
   *  client has classified; unknown values fail safe (neither git nor tool). */
  provider: string;
  external_account_id: string;
  display_name: string;
  granted_scopes: string[];
  status: string; // active | pending | suspended | error | revoked
  /** Set on seamless github_app connections: custody lives on the App
   *  registration (created via the manifest dance), not on this row. */
  registration_id: string | null;
  metadata: {
    login?: string;
    app_slug?: string;
    account_login?: string;
    installation_id?: string;
    registration_id?: string;
    base_url?: string;
    /** The exact MCP endpoint a static mcp_http connection was photographed at
     *  (= base_url for a static server). Used to match a connection to an agent
     *  requirement's connector url — display convenience; the server re-verifies. */
    endpoint_url?: string;
    header_name?: string;
    scheme?: string;
  };
  /** static (pasted secret) | oauth (custodied rotating refresh token). */
  auth_kind: string;
  /** Ownership (Phase C, design :274-296). `owner_type` is the WIRE value —
   *  "organization" (visible to every member) or "user" (one member's personal
   *  custody, rendered as "Personal"). `owner_user_id` is set iff owner_type is
   *  "user". These arrive on every row post-Phase-C; the list is already
   *  viewer-filtered server-side, so other users' personal rows never appear. */
  owner_type?: "organization" | "user";
  owner_user_id?: string | null;
  created_by_user_id?: string | null;
  /** Bumps on every re-consent/rotation so stale run bindings fail closed. */
  authorization_generation?: number;
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

/** Every connection provider this dashboard has classified. The server is the
 *  source of truth for what exists; this union states what we have decided
 *  about. Adding a member without adding it to PROVIDER_CLASS is a build
 *  failure — that is the point. */
export type ConnectionProvider = "github" | "github_app" | "mcp_http";

/** Which surface a provider belongs to.
 *
 *    git  — can back a workspace checkout (repositories, refs, commits).
 *    tool — a credential the BROKER calls during a run. It has no repositories.
 *
 *  This Record is the only place the rule lives. It replaces four hand-rolled
 *  predicates that each re-derived it from a prose comment; WorkspacePicker
 *  forgot, which is how mcp_http reached the git picker.
 *
 *  It is an allowlist BY CONSTRUCTION: Record<ConnectionProvider, …> requires
 *  every union member as a key, so adding `slack` (Phase 7) fails the build
 *  until someone classifies it. The old `provider !== "mcp_http"` form would
 *  have silently admitted slack to the repo picker instead. */
const PROVIDER_CLASS: Record<ConnectionProvider, "git" | "tool"> = {
  github: "git",
  github_app: "git",
  mcp_http: "tool",
};

/** Can this connection back a git workspace checkout?
 *
 *  A provider the server knows but this client does not is neither git nor
 *  tool: it stays out of every picker rather than defaulting into one. */
export const isGitConnection = (c: Connection): boolean =>
  PROVIDER_CLASS[c.provider as ConnectionProvider] === "git";

/** Is this a brokered tool-server credential? The mirror of isGitConnection. */
export const isToolConnection = (c: Connection): boolean =>
  PROVIDER_CLASS[c.provider as ConnectionProvider] === "tool";

// ─── Connection ownership (Phase C, presentation only) ──────────────────────
// The server is the sole authority on who may see/use a connection (the list is
// already viewer-filtered). Everything below only SHAPES the UI: badges, which
// owner radios to offer. Every write re-checks server-side.

/** The badge for a connection row: "Organization" or "Personal", with `yours`
 *  set only when a personal connection's owner matches the viewer. Needs
 *  `meUserId` (from GET /auth/me); absent in admin mode, where `yours` stays
 *  false. Returns null when the row carries no ownership (pre-Phase-C shape). */
export interface OwnerBadge {
  label: "Organization" | "Personal";
  yours: boolean;
}
export function ownerBadge(c: Connection, meUserId?: string | null): OwnerBadge | null {
  if (!c.owner_type) return null;
  if (c.owner_type === "user") {
    return { label: "Personal", yours: !!meUserId && c.owner_user_id === meUserId };
  }
  return { label: "Organization", yours: false };
}

export type OwnerChoice = "organization" | "personal";

/** Which owner options a principal may pick when creating a connection, and the
 *  default. Mirrors the server's `resolve_owner` gate (design :274-296):
 *  `organization` needs admin/owner (or the operator); `personal` needs a
 *  signed-in member and is refused for the operator and for github_app custody
 *  (`allowPersonal=false`). Pure so the radio gating is unit-tested; the server
 *  RE-ENFORCES — this only shapes the form. */
export interface OwnerOptions {
  canOrganization: boolean;
  canPersonal: boolean;
  default: OwnerChoice;
}
export function ownerOptions(me: AuthMe | null, allowPersonal = true): OwnerOptions {
  const operator = !!me?.operator;
  const isUser = !!me && !operator; // a signed-in member (browser/pat)
  const roles = me?.roles ?? [];
  const elevated = operator || roles.includes("admin") || roles.includes("owner");
  // me absent (auth/me failed) → fall back to organization-only, the
  // pre-Phase-C behavior; the server still enforces authority.
  const canOrganization = elevated || !me;
  const canPersonal = allowPersonal && isUser;
  const dflt: OwnerChoice =
    canOrganization && (elevated || !me) ? "organization" : canPersonal ? "personal" : "organization";
  return { canOrganization, canPersonal, default: dflt };
}

/** Normalize a URL to origin+path without a trailing slash, lowercased — so
 *  `https://H/mcp/` and `https://h/mcp` compare equal. Falls back to a trimmed
 *  string for non-URLs. */
function normUrl(u: string): string {
  const trimmed = u.trim();
  try {
    const p = new URL(trimmed);
    return (p.origin + p.pathname).replace(/\/+$/, "").toLowerCase();
  } catch {
    return trimmed.replace(/\/+$/, "").toLowerCase();
  }
}

/** Does this connection back the connector at `connectorUrl`? Matched against
 *  the stored `endpoint_url`/`base_url` (equal, or one contains the other at a
 *  path boundary — audience binding). Display-only convenience for the run
 *  composer's per-slot picker; the server re-verifies every binding. */
export function connectionMatchesConnector(c: Connection, connectorUrl: string): boolean {
  const target = normUrl(connectorUrl);
  if (!target) return false;
  const candidates = [c.metadata?.endpoint_url, c.metadata?.base_url]
    .filter((x): x is string => !!x && x.trim().length > 0)
    .map(normUrl);
  return candidates.some(
    (u) => u === target || target.startsWith(`${u}/`) || u.startsWith(`${target}/`)
  );
}

/** A connection's append-only tool photograph (GET /connections/{id}/tools).
 *  Mirrors the server's `snapshot_json` (schemas stay server-side). */
export interface ConnectionToolSnapshot {
  version: number;
  protocol_version: string;
  tools_digest: string;
  discovered_at: string;
  authorization_generation: number;
  tools: { name: string; description: string }[];
}

/** GET /connections/{id}/tools — the latest snapshot, or null when none has
 *  been photographed yet (404) or the row is not visible. Other errors throw. */
export async function fetchConnectionTools(id: string): Promise<ConnectionToolSnapshot | null> {
  try {
    const r = await apiGet<{ snapshot: ConnectionToolSnapshot }>(`/connections/${id}/tools`);
    return r.snapshot;
  } catch (e) {
    if (e instanceof Error && e.message.startsWith("404")) return null;
    throw e;
  }
}

/** POST /connections/{id}/tools/refresh — re-photograph into a new version.
 *  4xx bodies (e.g. reauthorization guidance) are actionable — surface them
 *  verbatim to the caller (this throws them as-is). */
export async function refreshConnectionTools(id: string): Promise<ConnectionToolSnapshot> {
  const r = await apiPost<{ snapshot: ConnectionToolSnapshot }>(
    `/connections/${id}/tools/refresh`,
    {}
  );
  return r.snapshot;
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
  transport: string; // streamable_http | stdio | rest_action (reference-only)
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
  /** Live decoration (derived server-side): the non-revoked connection
   *  covering this entry, and the latest bundle named after the slug. */
  connection: { id: string; status: string; auth_kind: string } | null;
  bundle: { id: string; name: string; version: number } | null;
  /** Derived server-side: false for imported `rest_action` reference cards
   *  whose Connect is refused until the REST action executor lands. */
  connectable?: boolean;
}

/** POST /catalog/{slug}/connect response (fields vary by auth_mode). */
export interface CatalogConnectResult {
  bundle?: { name: string; version: number };
  connection?: Connection;
  /** OAuth: the control-plane /v1/oauth/go URL — it binds the per-flow browser
   *  cookie, then 302s to the authorization server (invariant 20). */
  go_url?: string;
  /** Photographed servers/tools (none/api_key connects). */
  servers?: BundleServer[];
}

/** One photographed tool (name + description; schema stays server-side). */
export interface ToolPreview {
  name: string;
  description: string;
}

/** A server inside a bundle detail (GET /capabilities/{id}). */
export interface BundleServer {
  name: string;
  class: "sandbox" | "brokered";
  tool_count: number;
  tools_digest: string;
  tools: ToolPreview[];
}

/** GET /capabilities/{id} — the full bundle with per-server tool lists. */
export interface BundleDetail {
  bundle: CapabilityBundle;
  servers: BundleServer[];
}

/** POST /mcp/probe response — non-committing auth + tool detection. */
export interface ProbeResult {
  url: string;
  transport: string;
  reachable: boolean;
  auth_mode: "none" | "api_key" | "oauth";
  oauth_available: boolean;
  static_possible: boolean;
  tools_preview: ToolPreview[];
  oauth: { issuer?: string; authorization_endpoint?: string; scopes_supported?: string[] } | null;
  auth_hints: { header_name?: string; scheme?: string };
  notes: string[];
}

/** POST /mcp/servers response (fields vary by auth_mode, + derived slug).
 *  Phase C: a remote (none/api_key) connect returns `{connection, snapshot}`
 *  (brokered tools are a per-connection snapshot now, not a bundle); a sandbox
 *  (stdio) connect still returns a `bundle`; oauth returns `{connection,
 *  go_url}` and the snapshot is photographed by the callback. */
export interface AddServerResult {
  slug?: string;
  bundle?: { name: string; version: number };
  servers?: BundleServer[];
  connection?: Connection;
  snapshot?: ConnectionToolSnapshot;
  /** OAuth: the control-plane /v1/oauth/go URL (binds the browser cookie, then
   *  302s to the authorization server — invariant 20). */
  go_url?: string;
}

/** What the Add-server wizard hands back on success: the sandbox bundle (legacy
 *  path) OR the freshly-connected brokered connection + its photographed
 *  snapshot + derived slug (Phase C), so an embedded caller can append a
 *  matching ConnectionRequirement. */
export interface AddServerCompletion {
  bundle: { name: string; version: number } | null;
  connection?: Connection;
  snapshot?: ConnectionToolSnapshot;
  slug?: string;
}

/** One model offered for a harness (GET /harnesses). */
export interface HarnessModel {
  id: string;
  display_name: string;
  hint: string;
}

/** GET /harnesses entry — the supported harness + model catalog (server is
 *  the single source of truth; the frontend no longer hardcodes models). */
export interface HarnessInfo {
  id: string;
  display_name: string;
  hint: string;
  available: boolean;
  default_model: string | null;
  models: HarnessModel[];
}

/** Where a LEGACY (hand-pasted) github_app connection receives provider
 *  webhooks. Seamless connections receive events on their registration's
 *  app-level ingress instead — shown on the registration card. */
export function ingressPath(c: Connection): string | null {
  return c.provider === "github_app" && !c.registration_id
    ? `/v1/ingress/github/${c.id}`
    : null;
}

/** A GitHub App created through the manifest dance (one per GitHub
 *  account/org — private apps install only on the account that owns them).
 *  Secrets never appear here; the server custodies them sealed. */
export interface GithubAppRegistration {
  id: string;
  status: string; // pending | active | revoked
  target_kind: string; // personal | organization
  target_org: string | null;
  app_id: string | null;
  slug: string | null;
  name: string | null;
  client_id: string | null;
  html_url: string | null;
  owner_login: string | null;
  has_webhook_secret: boolean;
  created_at: string;
  updated_at: string;
}

/** App-level webhook ingress for a registration (ONE URL for every
 *  installation — GitHub App webhooks are app-scoped). */
export function appIngressPath(r: GithubAppRegistration): string {
  return `/v1/ingress/github/app/${r.id}`;
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

// ─── Governance ───────────────────────────────────────────────────────────
// The control plane resolves every verdict below and sends the answer. None of
// it is re-derived here: the dashboard renders policy, it never computes it.

/** A permission verdict as the policy engine reports it. Displayed as
 *  Allow / Ask / Deny — "approve" means the run pauses for a human. */
export type PolicyAction = "allow" | "approve" | "deny";

/** Why a rule's verdict depends on more than the tool name: the path touched
 *  or the command run. `paths_on_no_match` / `shell_on_no_match` carry the
 *  fallback verdict — render them, never restate them in TypeScript. */
export interface RuleConstraints {
  paths_allow: string[];
  paths_deny: string[];
  paths_on_no_match: PolicyAction | null;
  shell_allow_prefixes: string[];
  shell_deny_regex: string[];
  shell_on_no_match: PolicyAction | null;
}

/** Internally tagged on `status`. A `conditional` rule carries path/shell
 *  constraints, so no single action can express it — such rows are shown as a
 *  sentence and never as a control. Setting one would flatten the rule and
 *  drop its constraints (e.g. `paths.deny: **\/.env`); the server refuses the
 *  same override with a 400, and the UI must not offer what it will refuse. */
export type ToolStatus =
  | { status: "unconditional"; action: PolicyAction; rule: number }
  | {
      status: "conditional";
      action: PolicyAction;
      rule: number;
      constraints: RuleConstraints;
    }
  | { status: "default"; action: PolicyAction }
  | { status: "overridden"; action: PolicyAction; underlying: ToolStatus };

/** One row of the resolved permission matrix (GET /policies/{name}).
 *  `group` is set for canonical tools; for `mcp__*` rows it is null and
 *  `server` carries the grouping key instead. */
export interface MatrixRow {
  tool: string;
  group: string | null;
  server: string | null;
  overridable: boolean;
  status: ToolStatus;
}

export interface AutonomySummary {
  permitted: boolean;
  default_fallback: "allow" | "deny";
  allow_overrides: number;
  deny_overrides: number;
}

/** Mirrors `policy::PolicyDefaults`: the verdict when no rule matches. Already
 *  visible as the matrix's `default` rows. */
export interface PolicyDefaults {
  tool_action: PolicyAction;
}

/** Mirrors `spec::Budgets`. Every cap is an `Option` in Rust, so an unset one
 *  arrives as `null` — meaning this policy imposes no ceiling of that kind, not
 *  zero. These are a CEILING: an agent revision and each run may only tighten
 *  them (`Budgets::tightened_by`). */
export interface Budgets {
  max_wall_clock_secs: number | null;
  max_tokens: number | null;
  max_cost_usd: number | null;
  max_tool_calls: number | null;
}

/** `policy::ApprovalScope` — how far one human decision reaches. */
export type ApprovalScope = "once" | "session";

/** `policy::TimeoutAction`. One variant today: an unanswered approval denies.
 *  Human absence narrows permissions, never widens them. */
export type TimeoutAction = "deny";

export interface ApprovalSettings {
  default_ttl_secs: number;
  scope: ApprovalScope;
  timeout_action: TimeoutAction;
}

/** `policy::EgressMode` — kebab-case on the wire. */
export type EgressMode = "none" | "proxy-only" | "allowlist";

export interface Egress {
  mode: EgressMode;
}

/** GET /policies list row. */
export interface PolicySummary {
  id: string;
  name: string;
  version: number;
  updated_at: string;
  agents_using: number;
  autonomy_summary: AutonomySummary;
}

/** GET /policies/{name} — the fully-resolved policy behind a run. */
export interface PolicyDetail {
  policy: { id: string; name: string; version: number; updated_at: string };
  agents_using: number;
  autonomy_summary: AutonomySummary;
  defaults: PolicyDefaults;
  budgets: Budgets;
  approvals: ApprovalSettings;
  egress: Egress;
  matrix: MatrixRow[];
}

export const TERMINAL = ["completed", "failed", "cancelled", "budget_exceeded"];
export function isTerminal(status: string): boolean {
  return TERMINAL.includes(status);
}
