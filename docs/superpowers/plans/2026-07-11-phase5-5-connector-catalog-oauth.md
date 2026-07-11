# Phase 5.5 — Connector catalog & OAuth custody (user-selected slice, ahead of Phase 6)

**Date:** 2026-07-11 · **Brief:** `docs/handovers/2026-07-11-connector-catalog-session-brief.md` §B
**Research:** `docs/research/2026-07-11-connector-catalog-oauth-findings.md` (+ Phase-5 baseline note)

**Settles (user, 2026-07-11, at the boundary):**
1. **Both increments in this one phase** (catalog + OAuth custody).
2. **API-only catalog** (deviates from the brief's checked-in+boot-synced recommendation):
   `connector_catalog` rows live in the DB and are managed via `/v1/catalog`; the curated
   seed entries ship **inside migration 0007** (the only checked-in artifact is the
   migration SQL itself — unavoidable, since schema is too); there is NO seed file and NO
   boot-sync code path.
3. **Generic confidential-client support now** (pre-registered `client_id` + sealed
   `client_secret` on the connection; priority pre-registered → CIMD → DCR). The **Slack
   seed entry is deferred to Phase 7**; **Notion IS seeded** (the OAuth showcase).
4. **Catalog Connect auto-registers the bundle** (photograph with the fresh credential;
   authless immediately, api_key right after sealing, oauth at callback completion).

## Framing (non-negotiable)

- The catalog is the **user-facing layer over the Phase-5 seams**: pick → connect →
  photograph → attach. No new tool class, no gate change, no RunSpec/freeze change, no
  photograph change. `run_service::create_run` is **untouched** — its existing
  "connection must be `active`" check already fails OAuth-dead connections closed.
- OAuth is a **second `auth_kind` on the same custody object** (`integration_connections`).
  Only credential RESOLUTION in the broker grows. The sandbox never sees any token
  (unchanged inversion; token-passthrough stays prohibited).
- Catalog records are **untrusted reference data**. `tool_hints` are policy-default
  SEEDS for display/suggestion only — the gate remains the judge; nothing enforces off
  catalog data.

## Decision record (implementation choices)

- **Refresh token custody = the existing `credential_sealed` column.** `auth_kind`
  (`static` | `oauth`) tells the broker to send it verbatim (composed per scheme) or
  exchange it (refresh grant). `connection_credential_sealed()`'s active-only invariant
  covers OAuth for free. `credential_sealed` becomes **nullable** (a pending OAuth row
  has no credential yet); every unseal path is already status-gated.
- **Rotation is a single UPDATE** (`credential_sealed = $new where id = $1 and
  status = 'active'`) — atomic by Postgres. **Refreshes serialize per connection** via an
  in-memory lock registry (double-checked cache after acquiring), so concurrent brokered
  calls mint ONE refresh — rotation-safe (Notion keeps ≤2 valid).
- **Access tokens are never persisted**: the existing `connector_tokens` in-memory cache
  (connection_id → (token, expiry)) holds them; restart just re-mints. Proactive refresh
  when <5 min to expiry; reactive on MCP-call 401 with exactly ONE retry (a 401 at the
  auth layer proves the tool never executed).
- **`invalid_grant`/`invalid_client` on exchange or refresh ⇒ `status='error'`** (+ note
  in `oauth` jsonb). New runs fail closed at zero spend (existing check); in-flight
  brokered calls fail visibly (`tool.brokered` ok=false). **Reconnect = re-run the dance
  on the same connection id** (start endpoint accepts status pending|error|active).
- **OAuth `state` = AEAD-sealed JSON via the existing `Sealer`** (opaque + tamper-proof
  + stateless; survives restarts; no verifier table): `{connection_id, verifier, exp}`,
  base64url, 10-min expiry. Sealed ⊃ signed; the AS/browser can't read or forge it.
- **PKCE S256 always**; refuse an AS whose `code_challenge_methods_supported` lacks S256.
  `resource=<canonical base_url>` (RFC 8707) on BOTH legs (authorize + token). Canonical =
  lowercased scheme+host, default port elided, path preserved, no trailing slash.
- **Client identity priority: pre-registered → CIMD → DCR.** CIMD document served at
  `GET /.well-known/fluidbox-client.json` (root-level, unauthenticated; its URL IS the
  client_id; `token_endpoint_auth_method: none`) — used only when the AS advertises
  `client_id_metadata_document_supported`. DCR (RFC 7591) is the workhorse fallback:
  minted `client_id` stored per connection (no re-registration per connect). Confidential
  clients authenticate `client_secret_basic`; public clients send `client_id` in the body.
- **Refresh token REQUIRED at exchange** — an AS that returns none can't be custodied;
  mark the connection `error` with a clear message. On refresh, a response WITHOUT a new
  refresh token keeps the old one (non-rotating AS tolerated; rotation honored whenever
  offered). `offline_access` scope is appended when the AS advertises it.
- **INC-1 custom headers ride mcp_http `metadata`**: optional `header_name` (default
  `authorization`; RFC 7230 token chars; protocol headers denylisted) + `scheme`
  (`Bearer` default | `Basic` | `""` raw). The sealed credential is always the RAW
  secret; the broker composes the header value at send time (`Basic` = base64 of the
  stored `email:token`; `""` = bare token, the Sentry shape).
- **Callback + CIMD routes are unauthenticated by design** (browser redirect / AS fetch
  can't carry the admin token): auth is the sealed `state` (callback) / public-by-nature
  (CIMD doc) — same pattern as webhook ingress.
- **Catalog table is GLOBAL (tenant-less)**: deployment-level reference data (mirrors
  the public MCP registry it's a superset of); also avoids migration-time FK ordering on
  the boot-seeded tenant row. Connections/bundles stay tenant-scoped.
- **New config `FLUIDBOX_PUBLIC_URL`** (browser/AS-facing base; default
  `http://127.0.0.1:8787`) → redirect_uri `{public}/v1/oauth/callback`, CIMD client_id
  `{public}/.well-known/fluidbox-client.json`.

## Files

### 1. `migrations/0007_connector_catalog.sql`
```sql
-- Global (tenant-less) reference catalog; superset of MCP-registry server.json.
create table connector_catalog (
    id uuid primary key default gen_random_uuid(),
    slug text not null unique,          -- doubles as server alias + default bundle name
    name text not null,
    icon text,                          -- short glyph/emoji for the grid card
    description text,
    categories jsonb not null default '[]',
    tier text not null default 'custom',        -- verified | community | custom
    url text,                                   -- remote MCP endpoint (null for in-image)
    transport text not null default 'streamable_http', -- streamable_http | stdio
    auth_mode text not null default 'none',     -- none | api_key | oauth
    auth_hints jsonb not null default '{}',     -- {header_name?, scheme?, composite?, key_url?, placeholder?}
    scopes jsonb not null default '[]',
    egress jsonb not null default '[]',         -- informational host list
    tool_hints jsonb not null default '[]',     -- POLICY-DEFAULT SEEDS (untrusted): [{pattern, action, note}]
    sandbox_launch jsonb,                       -- in-image entries: {command, args, tools[]}
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
insert into connector_catalog (slug, name, icon, description, categories, tier, url, auth_mode, auth_hints, scopes, egress, tool_hints) values
 ('github','GitHub','🐙','Repos, issues, PRs via the hosted GitHub MCP server.','["dev","vcs"]','verified','https://api.githubcopilot.com/mcp/','api_key','{"scheme":"Bearer","placeholder":"ghp_… (PAT; App install tokens are NOT accepted)","key_url":"https://github.com/settings/tokens"}','[]','["api.githubcopilot.com"]','[{"pattern":"mcp__github__list_*","action":"allow","note":"read"},{"pattern":"mcp__github__get_*","action":"allow","note":"read"},{"pattern":"mcp__github__search_*","action":"allow","note":"read"},{"pattern":"mcp__github__*","action":"approve","note":"writes (create/update/merge) should ask"}]'),
 ('stripe','Stripe','💳','Payments data via mcp.stripe.com.','["payments"]','verified','https://mcp.stripe.com','api_key','{"scheme":"Bearer","placeholder":"rk_… (restricted key recommended)","key_url":"https://dashboard.stripe.com/apikeys"}','[]','["mcp.stripe.com"]','[{"pattern":"mcp__stripe__list_*","action":"allow","note":"read"},{"pattern":"mcp__stripe__get_*","action":"allow","note":"read"},{"pattern":"mcp__stripe__*","action":"approve","note":"money moves ask"}]'),
 ('linear','Linear','📐','Issues & projects via mcp.linear.app.','["project-mgmt"]','verified','https://mcp.linear.app/mcp','api_key','{"scheme":"Bearer","placeholder":"lin_api_…","key_url":"https://linear.app/settings/api"}','[]','["mcp.linear.app"]','[{"pattern":"mcp__linear__list_*","action":"allow","note":"read"},{"pattern":"mcp__linear__get_*","action":"allow","note":"read"},{"pattern":"mcp__linear__*","action":"approve"}]'),
 ('sentry','Sentry','🛰️','Issues & events via mcp.sentry.dev. NOTE: custom auth header.','["observability"]','verified','https://mcp.sentry.dev/mcp','api_key','{"header_name":"Sentry-Bearer","scheme":"","placeholder":"sntrys_… (sent as Sentry-Bearer: <token>)"}','[]','["mcp.sentry.dev"]','[{"pattern":"mcp__sentry__find_*","action":"allow","note":"read"},{"pattern":"mcp__sentry__*","action":"approve"}]'),
 ('atlassian','Atlassian','🧩','Jira/Confluence (cloud) via mcp.atlassian.com. Basic email:token.','["project-mgmt","docs"]','verified','https://mcp.atlassian.com/v1/mcp','api_key','{"scheme":"Basic","composite":"email:api_token","placeholder":"you@co.com:ATATT…","key_url":"https://id.atlassian.com/manage-profile/security/api-tokens"}','[]','["mcp.atlassian.com"]','[{"pattern":"mcp__atlassian__get*","action":"allow","note":"read"},{"pattern":"mcp__atlassian__*","action":"approve"}]'),
 ('notion','Notion','🗂️','Pages & databases via mcp.notion.com. OAuth-only (integration tokens are rejected on MCP).','["docs","knowledge"]','verified','https://mcp.notion.com/mcp','oauth','{}','[]','["mcp.notion.com"]','[{"pattern":"mcp__notion__*search*","action":"allow","note":"read"},{"pattern":"mcp__notion__*get*","action":"allow","note":"read"},{"pattern":"mcp__notion__*","action":"approve"}]');
insert into connector_catalog (slug, name, icon, description, categories, tier, transport, auth_mode, sandbox_launch, tool_hints) values
 ('workspace-info','Workspace info','📁','In-image sandbox stdio server: file & grep counts over /workspace. Credential-free.','["workspace"]','verified','stdio','none',
  '{"command":"node","args":["/opt/fluidbox-runner/servers/workspace-info.mjs"],"tools":[{"name":"workspace_file_count","description":"Count files in the workspace","input_schema":{"type":"object","properties":{},"additionalProperties":false}},{"name":"workspace_grep_count","description":"Count lines containing a plain pattern","input_schema":{"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}}]}',
  '[{"pattern":"mcp__workspace-info__*","action":"allow","note":"read-only, sandbox-contained"}]');

alter table integration_connections
    alter column credential_sealed drop not null,
    add column auth_kind text not null default 'static',  -- static | oauth
    add column oauth jsonb,                               -- non-secret: {resource, issuer, authorization_endpoint, token_endpoint, registration_endpoint?, client_id?, client_id_source?, scopes?, pending_bundle?, error?}
    add column client_secret_sealed bytea;                -- confidential clients only
-- 'pending' joins active|revoked|error as a status value (no constraint change needed).
```
(Note: the workspace-info insert column list differs — `url`, `scopes`, `egress` omitted/defaulted; write the SQL with explicit per-row column lists as above.)

### 2. `crates/fluidbox-db/src/lib.rs`
- `IntegrationConnectionRow` += `auth_kind: String`, `oauth: Option<Value>` — update the
  **four** explicit column lists (create/list/get/revoke) in sync.
- `create_connection` grows a `NewConnectionAuth<'a> { auth_kind: &'a str, oauth: Option<&'a Value>, client_secret_sealed: Option<&'a [u8]>, status: &'a str }`
  parameter (existing callers pass `{"static", None, None, "active"}`); `credential_sealed`
  becomes `Option<&[u8]>`.
- New fns:
  - `activate_connection_oauth(pool, id, sealed_refresh: &[u8], oauth: &Value, scopes: &Value) -> Option<Row>` — sets credential, oauth, granted_scopes, `status='active'`, updated_at.
  - `rotate_connection_refresh(pool, id, sealed_new: &[u8]) -> bool` — the atomic overwrite (`where id=$1 and status='active'`).
  - `update_connection_oauth(pool, id, oauth: &Value)` — persist discovery/client-identity/pending_bundle patches pre-activation.
  - `mark_connection_error(pool, id, note: &str)` — `status='error'` + `oauth['error']=note` (jsonb_set; oauth may be null → coalesce `'{}'`).
  - `connection_client_secret_sealed(pool, id) -> Option<Vec<u8>>` — any non-revoked status (client identity outlives token state; needed while pending/error during the dance).
  - Catalog: `ConnectorCatalogRow` (all columns), `list_catalog(pool)` (tier: verified first, then name), `get_catalog_by_slug(pool, slug)`, `create_catalog_entry(pool, …)` (tier forced `custom`).
- DB tests (real Neon, self-skip pattern): seeds present (`workspace-info` + `notion` rows, count ≥ 7); custom entry insert + slug-unique conflict; oauth connection lifecycle (create pending w/ null credential → activate → rotate changes bytes → mark_error blocks `connection_credential_sealed`).

### 3. `crates/fluidbox-core` — **no changes** (state it in the commit message; the
connection carries everything; `CapabilityServer`/gate/freeze untouched).

### 4. `crates/fluidbox-server/src/oauth.rs` (new, ~450 lines)
- `OauthStateToken { connection_id: Uuid, verifier: String, exp: i64 }` — `seal_state(&Sealer)` → base64url(no-pad) of AEAD box; `open_state` verifies + expiry. 10-min TTL.
- `pkce_challenge(verifier) -> String` (S256: base64url(sha256)); `new_verifier()` = 32 random bytes (AEAD OsRng) → base64url = 43 chars.
- `canonical_resource(base_url) -> String` (tested: host lowercased, default port elided, no trailing slash).
- Discovery (`discover(state, mcp_url) -> Result<AsMeta, String>`):
  1. GET mcp_url; on 401 parse `WWW-Authenticate` `resource_metadata="…"`;
  2. else/fallback: RFC 9728 well-known (`/.well-known/oauth-protected-resource{path}` then bare);
  3. GET PRM → `authorization_servers[0]` (refuse if absent);
  4. AS metadata: `/.well-known/oauth-authorization-server{path}` → bare → `/.well-known/openid-configuration`; require `authorization_endpoint` + `token_endpoint`; **refuse unless `code_challenge_methods_supported` contains "S256"**.
  `AsMeta { issuer, authorization_endpoint, token_endpoint, registration_endpoint: Option, code_challenge_methods: Vec, cimd_supported: bool, scopes_supported: Vec }`.
- `resolve_client(state, conn, &AsMeta) -> Result<ClientIdentity, String>`:
  pre-registered (`oauth.client_id_source=="preregistered"` or request-supplied) → CIMD
  (when `cimd_supported`; client_id = `{public}/.well-known/fluidbox-client.json`) → DCR
  (POST registration_endpoint `{client_name:"fluidbox", redirect_uris:[callback], grant_types:["authorization_code","refresh_token"], response_types:["code"], token_endpoint_auth_method:"none"}`;
  store minted client_id (+ seal secret if returned) on the connection — registered once, reused).
- Handlers:
  - `POST /v1/connections/{id}/oauth/start` (Admin) → connection must be `auth_kind='oauth'`, status ∈ pending|error|active → run discovery + resolve_client (idempotent; persists AS meta + client identity into `oauth` jsonb) → mint verifier/state → `{authorize_url}` with `response_type=code, client_id, redirect_uri, state, code_challenge(+method=S256), resource, scope?` (params APPENDED to the AS URL's existing query).
  - `GET /v1/oauth/callback?code&state[&error]` (**no Admin**) → open_state → load connection (reject revoked) → token exchange (form: `grant_type=authorization_code, code, redirect_uri, client_id, code_verifier, resource`; `client_secret_basic` when a sealed secret exists) → require `refresh_token` → seal + `activate_connection_oauth` → cache access token → **auto-register pending bundle** (`oauth.pending_bundle: {name, url}` → shared `capabilities::register_bundle`; photograph runs with the fresh token) → tiny HTML success page. AS `error=` param or exchange failure → HTML error page (+ `mark_connection_error` on `invalid_grant`-class errors only; `access_denied` leaves it pending).
  - `GET /.well-known/fluidbox-client.json` (**no Admin**, root-level): `{client_id: <its own URL>, client_name: "fluidbox", client_uri, redirect_uris: [callback], grant_types, response_types, token_endpoint_auth_method: "none"}`.
- `ensure_access_token(state, conn) -> Result<String, String>` (used by broker):
  cache hit with >5 min margin → return; else per-connection lock (`state.oauth_locks`),
  double-check cache, unseal refresh (**active-only** — error/pending refuse), POST
  token_endpoint `{grant_type=refresh_token, refresh_token, client_id, resource}`
  (+ secret) → cache access (expiry = now + expires_in, default 3600) → if response
  carries a new refresh_token: `rotate_connection_refresh` (atomic). `invalid_grant`/
  `invalid_client` → `mark_connection_error` + Err("… reconnect …").
- Unit tests: state roundtrip/tamper/expiry/garbage; PKCE S256 known-answer (RFC 7636
  appendix B vector); canonical_resource; `WWW-Authenticate` parser; AS-metadata parse +
  S256 refusal (fixture JSON, no network).

### 5. `crates/fluidbox-server/src/broker.rs`
- `pub struct BrokeredAuth { pub header: String, pub value: String, pub oauth_connection: Option<Uuid> }`.
- `brokered_auth(…) -> Result<Option<BrokeredAuth>, String>`: same lookup/audience-binding;
  then by `auth_kind`: `static` → unseal + `compose_header_value(scheme, secret)` with
  `header = metadata.header_name | "authorization"`; `oauth` → `oauth::ensure_access_token`
  → `("authorization", "Bearer {access}", oauth_connection=Some(id))`.
- `compose_header_value(scheme, secret)`: `Bearer`→`"Bearer {s}"`, `Basic`→`"Basic "+b64(s)`,
  `""`→`s`. `valid_header_name()`: RFC 7230 token chars, case-insensitive denylist
  {host, content-length, content-type, accept, mcp-session-id, mcp-protocol-version}.
- `post_rpc`/`rpc`/`handshake`/`discover_tools`/`call_tool` take `Option<&BrokeredAuth>`
  and send `req.header(&auth.header, &auth.value)`.
- Internal error type distinguishes 401: `rpc` maps HTTP 401 → `Unauthorized`; public
  wrappers `discover_tools_auth(state, server)` and `call_tool_auth(state, server, tool, args)`
  resolve auth → call → on `Unauthorized` **for oauth connections only**: drop cached
  access token, `ensure_access_token` again (fresh mint), retry ONCE (401 at auth layer
  proves the tool never executed). `photograph_brokered` + `internal.rs` call these
  wrappers (internal.rs:460-470 swaps two calls for one; the gate above is untouched).
- Tests: compose_header_value; valid_header_name; existing tests unchanged.

### 6. `crates/fluidbox-server/src/connections.rs`
- `CreateConnection` += `header_name: Option<String>`, `scheme: Option<String>`,
  `auth_kind: Option<String>`, `scopes: Option<Vec<String>>`, `client_id: Option<String>`,
  `client_secret: Option<String>`.
- `create_mcp_http` branches on `auth_kind` (default `static`):
  - `static`: as today + validated `header_name`/`scheme` into metadata.
  - `oauth`: **no token required/accepted** → row with `status='pending'`, null credential,
    `oauth: {resource: canonical, scopes, client_id?/source:"preregistered"}`, sealed
    client_secret if given → response includes `"next": "/v1/connections/{id}/oauth/start"`.
- Sweep: no response path ever includes credential/refresh/client_secret (rows never
  select sealed columns — unchanged pattern).

### 7. `crates/fluidbox-server/src/catalog.rs` (new, ~250 lines)
- `GET /v1/catalog` (Admin) → `{connectors: […]}`; `GET /v1/catalog/{slug}`.
- `POST /v1/catalog` (Admin) — custom entries: slug `^[a-z0-9][a-z0-9-]{0,63}$` (must
  also satisfy the bundle-name + server-alias charset since it becomes both), url http(s)
  for remote, `auth_mode` ∈ {none, api_key, oauth}, tier **forced `custom`**, arrays
  validated shallowly. (Registry-import compat: accept unknown `_meta` silently.)
- `POST /v1/catalog/{slug}/connect` (Admin) body `{display_name?, token?, bundle_name?, client_id?, client_secret?, scopes?}`:
  - `none` + `sandbox_launch` → `register_bundle` with the declared Sandbox server (alias = slug) → `{bundle}`.
  - `none` + `url` → `register_bundle` Brokered w/o connection (photograph) → `{bundle}`.
  - `api_key` → require token → create `mcp_http` static connection (metadata header/scheme from `auth_hints`) → `register_bundle` Brokered w/ connection (photograph turns the sealed key) → `{connection, bundle}`.
  - `oauth` → create pending oauth connection (resource = canonical(url), scopes = catalog ∪ request, `pending_bundle: {name: bundle_name|slug, url}`) → run `oauth::start` internals → `{connection, authorize_url}`.
  Bundle name defaults to the slug; a re-connect publishes the next version (append-only registry unchanged).
- `capabilities.rs`: extract the body of `create` into
  `pub async fn register_bundle(state, name, description, servers) -> ApiResult<CapabilityBundleRow>`
  (validation → photograph → re-validate → digest → insert); the HTTP handler and
  catalog/oauth callers share it.

### 8. `crates/fluidbox-server/src/state.rs` + `config.rs` + `main.rs`
- `AppStateInner` += `oauth_locks: Mutex<HashMap<Uuid, Arc<tokio::Mutex<()>>>>`.
- `Config` += `public_url: String` (`FLUIDBOX_PUBLIC_URL`, default `http://127.0.0.1:8787`, trailing `/` trimmed).
- Routes: `/v1/catalog` GET+POST, `/v1/catalog/{slug}` GET, `/v1/catalog/{slug}/connect` POST,
  `/v1/connections/{id}/oauth/start` POST, `/v1/oauth/callback` GET (public nest, no Admin),
  root-level `/.well-known/fluidbox-client.json` GET; `mod catalog; mod oauth;`.

### 9. `run_service.rs`, `internal.rs` gate, `fluidbox-core`, runner image — **untouched**
(the internal.rs execution call-site swap in §5 is below the gate; assert in review).

### 10. Dashboard (presentation-only)
- `app/capabilities/page.tsx`: "Add from catalog" grid (icon, name, tier badge, categories,
  auth-mode chip, description, egress hosts, tool-hint counts) → Connect panel branches:
  none → one click; api_key → secret field (+ composite hint e.g. `email:token`);
  oauth → button that POSTs connect then `window.open(authorize_url)` + polls
  `/v1/connections` until `active` → success shows the registered bundle. Custom-entry
  form (POST /v1/catalog).
- `app/connections/page.tsx`: `auth_kind` chip; `pending`/`error` states with a
  **Reconnect** button (POST …/oauth/start → open authorize_url).
- `app/lib/api.ts`: catalog list/create/connect, oauth start.

### 11. `scripts/e2e-connectors.sh` (new suite phase 8/9; failures becomes 9/9)
Fixtures (both logged to jsonl, both killed on EXIT):
- **fake-sentry MCP** (python, port 8896): static MCP; **requires header `Sentry-Bearer: <raw token>`**
  (401 otherwise); tools `sn_find_issues` (read) / `sn_update_issue`; logs every request's headers.
- **fake-oauth MCP + AS combo** (python, port 8897): one process, path-routed:
  - `/mcp`: requires `Authorization: Bearer <currently-valid ACCESS token>`; 401 with
    `WWW-Authenticate: Bearer resource_metadata="http://127.0.0.1:8897/.well-known/oauth-protected-resource/mcp"` otherwise; tools `nt_search`/`nt_create_page`.
  - `/.well-known/oauth-protected-resource/mcp`: PRM `{resource, authorization_servers:["http://127.0.0.1:8897"]}`.
  - `/.well-known/oauth-authorization-server`: metadata (S256; endpoints; `registration_endpoint`; `client_id_metadata_document_supported` per mode).
  - `/authorize` (GET): validates client_id/redirect_uri/code_challenge/resource presence; auto-consents → 302 `{redirect_uri}?code=…&state=…`.
  - `/token` (POST form): `authorization_code` grant verifies PKCE (S256 of stored challenge) + `resource` + code single-use → `{access_token, token_type, expires_in: <mode TTL>, refresh_token, scope}`; `refresh_token` grant: **rotates** (old RT invalidated, new minted; using a dead RT → 400 `{"error":"invalid_grant"}`); after `/admin/revoke` every RT is dead.
  - `/register` (POST): DCR — mints `client_id`, logs the request.
  - `/admin/state` (GET): `{valid_refresh_tokens, valid_access_tokens, grants: […]}`;
    `/admin/mode` (POST): `{cimd: bool, access_ttl: secs}`; `/admin/expire-access` (POST):
    invalidates current access tokens (forces the reactive-401 path); `/admin/revoke` (POST).
No-model tier (always):
- CATALOG: `GET /v1/catalog` → ≥7 entries; `notion.auth_mode=oauth`; `sentry.auth_hints.header_name=Sentry-Bearer`; `workspace-info` tier=verified transport=stdio; tool_hints arrays present (seed data plumbed); no slack entry (Phase-7 deferral pinned); POST custom entry (tier forced custom; bad slug → 400; dup slug → 409/400).
- INC1 CONNECT (api_key, custom header): POST custom entry `fx-sentry` (url = fake-sentry, auth_hints Sentry-Bearer/raw) → `/connect` with token → `{connection, bundle}`; fake-sentry log shows **`Sentry-Bearer: <token>`** and NO `Authorization` header on tools/list; bundle photographed (`sn_find_issues` snapshot present); token never echoed (connect response, /v1/connections, /v1/catalog); broker `tools/call` end-to-end through the custom header (session probe like e2e-capabilities GATE/BROKER blocks); authless connect (`workspace-info`) → bundle registered immediately, attachable.
- INC2 DANCE (DCR mode first): POST custom entry `fx-notion` (auth_mode oauth, url = fake `/mcp`) → `/connect` → `{connection(pending), authorize_url}`; assert authorize_url carries `code_challenge` + `code_challenge_method=S256` + `resource=http://127.0.0.1:8897/mcp` + DCR-minted client_id (AS log shows `/register` hit); "browser" = `curl -s` authorize → Location → curl the callback → HTML success; connection now `active`; `credential_sealed` non-null (psql) and refresh never in any response; **pending bundle auto-registered** (photograph ran with the minted access token — AS+MCP logs agree); token request carried `code_verifier` + `resource` (AS grant log).
- CIMD mode: `/admin/mode {cimd:true}` → second oauth connection → authorize client_id == `{public}/.well-known/fluidbox-client.json`; `curl` the CIMD doc directly (client_id self-reference + redirect_uris + auth method none); no `/register` hit for this connection.
- ROTATION + REFRESH: `/admin/mode {access_ttl: 4}` …; broker call #1 OK; sleep past TTL; broker call #2 succeeds after a `refresh_token` grant (AS log) — **old RT invalid** (`/admin/state` shows exactly one valid RT ≠ the first; psql shows `credential_sealed` bytes CHANGED = rotation persisted atomically); `/admin/expire-access` (keep RT valid) → next call = reactive-401 → refresh → retry → success (grants log ordering proves 401-then-refresh).
- REVOKE/FAIL-CLOSED/RECONNECT: `/admin/revoke` → broker call fails visibly (`tool.brokered` ok=false + error mentions reconnect) → connection status `error` → `POST /v1/sessions` for an agent pinned to that bundle → **400 at zero spend**; reconnect: `…/oauth/start` on the SAME connection → curl dance → `active` again → new run creates fine.
- SECRETS SWEEP: refresh token, access tokens, client_secret, api keys appear NOWHERE: connection list/creates, catalog, session RunSpec JSON, `/v1/sessions/{id}/events`, docker inspect env of a probe run's container.
- CIMD doc + callback are reachable WITHOUT the admin token; callback with tampered/expired state → 400, nothing mutated.
Live tier (self-skips): connect `workspace-info` from the CATALOG (authless auto-register) → attach to a live agent → task instructs one `mcp__workspace-info__workspace_file_count` call → run completes; `tool.requested` for the tool in the ledger. (Runs on the existing runner image — no image rebuild in this phase.)

### 12. `scripts/e2e.sh` + docs
- Insert `PHASE 8/9 — connector catalog & oauth custody` (runs `e2e-connectors.sh`);
  failure paths becomes 9/9; update header comment + phase labels (`n/8` → `n/9`).
- `CLAUDE.md`: `just e2e` description + a connector-catalog/OAuth-custody invariant bullet
  (catalog untrusted; refresh custody in credential_sealed; rotation atomic; callback/CIMD
  unauthenticated-by-design; broker-only resolution growth).
- `docs/HANDOVER.md` rev 8 (shipped section, settles, rough edges: e.g. "one dance at a
  time per connection — a second start invalidates the first's state token? (no — states
  are independent; last exchange wins)", "no logout/token-revocation call on revoke",
  "CIMD only when AS advertises it").
- Memory: update `fluidbox-sequencing`.

## Order
migration 0007 → db layer (+db tests) → oauth.rs (+unit tests) → broker (+tests) →
connections/catalog/capabilities-refactor → state/config/main → `cargo test -p fluidbox-server`
→ dashboard → `just check` → e2e-connectors.sh + e2e.sh wiring → `just e2e` → docs → commit.
