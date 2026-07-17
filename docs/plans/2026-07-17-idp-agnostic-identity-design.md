# fluidbox — IdP-agnostic, per-organization identity layer

**Date:** 2026-07-17
**Status:** FINALIZED v2 (2026-07-17) — v1 revised after adversarial review by Codex (gpt-5.6-sol, max reasoning; REVISE verdict, 17 findings, 16 incorporated); companion to the multi-user MCP control plane design (Phase B input); nothing here is implemented
**Audience:** fluidbox maintainers and engineers implementing Phase B (identity and tenant enforcement)
**Relationship to other docs:** `docs/plans/2026-07-14-multi-user-mcp-control-plane-design.md` (v4) defines the multi-user architecture this layer authenticates; its Phase B references this document. `docs/plans/2026-07-11-github-seamless-connect-design.md` defined the one-time browser-flow pattern this design reuses. `PLAN.md` remains authoritative for product invariants.

## Executive summary

fluidbox becomes multi-user without depending on any particular identity
vendor. The Rust control plane is a **generic OIDC relying party**: every
organization configures its own issuer (`issuer` URL + client ID + sealed
client secret + claim mappings), and any conformant OIDC provider — Okta,
Entra ID, Auth0, Keycloak, Google, Dex, a homegrown AS — works without
fluidbox-side code. There is no SAML support, no password store, and no
bundled IdP: **no IdP configured means multi-user is off**, and today's
single-admin-token mode continues unchanged for local/dev. The operator's
admin token doubles as the break-glass path, so a dead or misconfigured IdP
can never lock an organization out permanently.

Three existing mechanisms carry most of the weight:

1. the **`github_app_flows` one-time-claim pattern** (a per-flow `HttpOnly`
   cookie whose hash sits inside the one-time `UPDATE … WHERE` predicate) —
   reused pattern-for-pattern in a new `login_flows` table;
2. **`seal.rs`** (XChaCha20-Poly1305) — custody for IdP client secrets and
   PKCE verifiers, inheriting the Phase D KMS re-seal path; and
3. **`api_tokens`** (sha256-hashed) — extended with a `pat` kind so CLI/API
   access never needs a browser or the IdP.

ID-token verification (JWKS signature, `iss`/`aud`/`azp`, `exp`/`iat`/`nbf`,
`nonce`, `at_hash`, algorithm allowlist) uses the `openidconnect` crate. The
in-house `oauth.rs` continues to serve **connector** (machine-to-MCP-server)
authorization — it never verifies ID tokens, and login never touches it.

## Goals

- Any conformant OIDC issuer, configured **per organization**, with zero
  vendor-specific code paths.
- One deployable unit: the Rust binary is the relying party; the Next.js
  dashboard stays presentation-only.
- Fail-closed everywhere: unknown issuer, stale discovery, unverified email,
  replayed flow, deactivated membership — all refuse.
- JIT provisioning with configurable claim→role mapping; no pre-provisioning
  required for ~300 seats.
- Break-glass bootstrap and recovery that never depends on the IdP.
- Machine access (CLI/API) independent of browser flows and the IdP.
- Alignment with the parent design's principals, one-time-state discipline,
  tenant-scoped repositories, and Phase D custody plans.

## Non-goals (v1)

- SAML (SAML-only enterprises bridge via Dex/Keycloak on their side).
- A password store, MFA enforcement, or account recovery UX (the IdP owns
  authentication; fluidbox owns sessions and authorization).
- Cross-organization identity linking (same human in two orgs = two users).
- SCIM provisioning and email-domain login routing (later; JIT covers v1).
- Device-code flow for CLI login (PATs cover v1).
- RP-initiated and back-channel logout (`idp_sid` is captured as
  informational scaffolding; nothing consumes it in v1).
- **Refresh-token custody.** fluidbox does not request offline access and
  discards any refresh token an IdP returns. Periodic IdP re-validation and
  SEP-990 arrive later with their own custody design (see Lifecycle).
- SEP-990 Enterprise-Managed Authorization (target-state hook only; see
  the parent doc's "Enterprise-managed authorization" section).

## Framing decisions (settled)

**Organizations ARE tenants.** The existing `tenants` table gains org-facing
columns (`slug`, `display_name`, `status`); `tenant_id` is never renamed —
it is load-bearing in nine tables, nearly every tenant-owned handler, and
`AppState`. "Tenant" and "organization" are the same object at different
layers of speech.

**Users are org-scoped.** The identity key is
`(tenant_id, idp_config_id, subject)` — the issuer is pinned through the IdP
config that provisioned the identity, and `iss` is verified on every token.
The same human in two organizations is two `users` rows with two
memberships. This makes cross-org identity leakage structurally impossible
and keeps `UserPrincipal.tenant_id` unambiguous. Never key on `sub` alone,
and never on email at all.

**Multi-user is derived per organization; proxy mode is static per
deployment.** An organization with an `active` `org_idp_configs` row is
multi-user; an organization without one keeps the admin-token path. The
dashboard proxy's credential behavior, however, is **explicit static
deployment configuration, never a per-request decision** (see Session
custody) — a hosted deployment can never fall back to operator authority
because a cookie was missing.

**The admin token survives as the operator/break-glass credential.** It
never becomes a user; it acts through an explicit `/v1/admin/*` surface and
(in single-admin mode) today's `/v1` surface, both audited.

## Current state this builds on (verified on `main` `c967192`, merged into this branch at `8b1508c`)

- Auth is extractor-based with no middleware (`auth.rs`): `Admin`
  (sha256 compare against `FLUIDBOX_ADMIN_TOKEN`), `TriggerAuth`
  (subscription-scoped `api_tokens`), `SessionAuth` (runner tokens; runner
  session tokens use the `fbx_sess_` prefix — `orchestrator.rs`).
- One boot tenant: `ensure_default_tenant` seeds `tenants('default')`;
  `AppStateInner.tenant_id` is consumed by nearly every tenant-owned
  handler.
- The dashboard proxy (`apps/web/app/api/fluidbox/[...path]/route.ts`)
  injects the admin token server-side; it does not currently forward
  cookies or `Set-Cookie`; the browser holds no fluidbox credential today.
- The public `/v1` router currently applies `CorsLayer::permissive()`
  (`main.rs`) — Phase B must replace this (see CSRF).
- `github_app_flows` implements one-time browser-bound claims:
  `claim_github_app_bootstrap` binds `browser_hash = sha256(cookie nonce)`
  exactly once; `claim_github_app_flow` consumes the flow only when the
  presented cookie's hash matches inside the `UPDATE … WHERE` predicate,
  and a mismatch does not burn the flow.
- `seal.rs::Sealer` (XChaCha20-Poly1305; key `FLUIDBOX_CREDENTIAL_KEY`) is
  optional at boot; every sealed feature refuses when absent — the identity
  layer inherits that rule (no IdP config without a sealer).
- `oauth.rs` has PKCE S256, `random_urlsafe`, `b64url`, a `seal_state`
  helper (whose current payload is the connector shape `{connection,
  verifier, expiry}` — login defines its own payload), and RFC 8414/OIDC
  discovery. It has no ID-token/JWKS verification, no callback cookie, and
  no server-side state row (its state is deliberately stateless): login
  reuses the *helpers*, not the flow.
- `FLUIDBOX_PUBLIC_URL` is the browser-facing base URL feeding OAuth
  redirect URIs; the same base serves the login callback here.
- No `users`, `memberships`, `roles`, or `organizations` tables exist.
- Migrations end at `0011_finalization_intent`; this layer takes `0012`.

## Data model (migration `0012_identity_layer.sql`)

Every new table carries `tenant_id` plus a `unique (tenant_id, id)` key so
children can use composite `(tenant_id, …)` foreign keys, per the parent
design's mandate — the **single declared exception** is `auth_audit_log`,
which is an append-only log, not a tenant-owned resource: its `tenant_id`
is nullable (deployment-level operator actions carry none) and nothing
references it. Row-level security is added as depth; `TenantScope`
repository signatures remain the primary control.

Migration order: `tenants` alterations → `org_idp_configs` → `users` →
`org_memberships` → `login_flows` → `user_sessions` → `auth_audit_log` →
`api_tokens` alterations (each FK target exists before its referrer).

### `tenants` (extended in place)

    alter table tenants
      add column slug text,                -- URL-safe org identifier
      add column display_name text,
      add column status text not null default 'active';  -- active|suspended
    -- backfill: the boot tenant gets slug 'default'; then:
    alter table tenants alter column slug set not null;
    alter table tenants add constraint tenants_slug_shape
      check (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$');
    create unique index tenants_slug on tenants (slug);

### `org_idp_configs`

    id                    uuid primary key
    tenant_id             uuid not null references tenants(id)
    generation            int not null default 1     -- bumps on issuer migration
    issuer                text not null              -- https issuer URL; IMMUTABLE
    client_id             text not null              -- IMMUTABLE
    client_secret_sealed  bytea                      -- Sealer; null = public/PKCE-only client
    token_endpoint_auth   text not null default 'client_secret_basic'
                          -- client_secret_basic|client_secret_post|none;
                          -- validated against discovered
                          -- token_endpoint_auth_methods_supported
    scopes                text[] not null default '{openid,email,profile}'
    alg_allowlist         text[] not null default
                          '{RS256,ES256,PS256,RS384,ES384,RS512,ES512}'
                          -- asymmetric only; HS*/none REJECTED at validation
    claim_mappings        jsonb not null             -- see below
    bootstrap_owner_email text                       -- one-time first-owner binding; nulled on use
    discovered_metadata   jsonb                      -- cached RFC 8414/OIDC discovery document
    jwks                  jsonb                      -- cached signing keys
    discovered_at         timestamptz
    status                text not null default 'staged'  -- staged|active|retired|disabled
    created_by            text                       -- 'operator' | membership id
    created_at, updated_at timestamptz
    unique (tenant_id, id)
    unique (tenant_id, generation)
    create unique index one_active_idp_per_org
      on org_idp_configs (tenant_id) where status = 'active';

**Identity fields are immutable.** `issuer`, `client_id`, and `generation`
never change on an existing row — "fixing the issuer" is an issuer
migration (new row, new generation; see Lifecycle), because the identity
key of every provisioned user pins this row. Mutable: `client_secret_sealed`
(rotation), `token_endpoint_auth`, `scopes`, `claim_mappings`,
`alg_allowlist`, `bootstrap_owner_email`, caches, `status`
(`staged → active → retired/disabled` only).

`claim_mappings` default:

    {
      "email": "email",
      "email_verified": "email_verified",
      "name": "name",
      "roles_path": "groups",
      "role_map": {},
      "default_role": "member",
      "require_email_verified": true
    }

**The subject is not mappable.** The identity subject is always the
standard OIDC `sub` claim from the verified ID token — required nonempty,
bounded (≤255 bytes), stored verbatim. Only display attributes
(email/name) and roles may be mapped. `roles_path` points at a claim
(top-level or dotted path) whose values are looked up in `role_map` to
produce fluidbox roles; unmapped users get `default_role`. `role_map` may
map to `member|approver|admin` — mapping to `owner` is refused at config
validation unless the operator explicitly sets `"allow_owner_mapping":
true` (default absent): an IdP group must not silently mint the org's root
authority.

### `users`

    id                uuid primary key
    tenant_id         uuid not null references tenants(id)
    idp_config_id     uuid not null      -- the config that provisioned this identity
    subject           text not null      -- OIDC `sub`, verbatim
    email             text
    email_normalized  text               -- lower(trim(email)); attribute, NOT unique
    email_verified    boolean not null default false
    name              text
    status            text not null default 'active'   -- active|deactivated
    created_at, updated_at, last_login_at timestamptz
    unique (tenant_id, idp_config_id, subject)   -- the identity key
    unique (tenant_id, id)
    foreign key (tenant_id, idp_config_id) references org_idp_configs (tenant_id, id)

Email is deliberately **not** unique: two distinct `sub`s may legitimately
share an email (aliases, shared mailboxes). `sub` scoped by issuer is the
identity; email is display/bootstrap metadata.

### `org_memberships`

    id            uuid primary key
    tenant_id     uuid not null
    user_id       uuid not null
    roles         text[] not null default '{member}'  -- ⊆ {member, approver, admin, owner}
    status        text not null default 'active'      -- active|deactivated
    created_at, updated_at, deactivated_at timestamptz
    unique (tenant_id, user_id)
    unique (tenant_id, id)
    unique (tenant_id, id, user_id)      -- composite-FK target for sessions/PATs
    foreign key (tenant_id, user_id) references users (tenant_id, id)

1:1 with `users` in v1, but a distinct object because the parent design's
`UserPrincipal` carries `membership_id` and because **the membership is the
recheck target**: the broker's owner-membership recheck before every
credentialed binding use resolves this row's `status`. Deactivating it is
the kill switch for sessions, PATs, and personal-connection use.
Roles live in a `text[]` (small closed set, app-validated); `owner` is never
grantable from IdP claims absent the explicit opt-in above.

### `login_flows` (one-time browser-bound state rows)

    id                    uuid primary key
    tenant_id             uuid not null
    idp_config_id         uuid not null          -- binds issuer + client + generation
    pkce_verifier_sealed  bytea not null         -- Sealer; never plaintext at rest
    nonce                 text not null          -- OIDC nonce, single-use
    browser_hash          text not null          -- sha256(per-flow cookie nonce)
    redirect_to           text not null          -- validated LOCAL path only
    consumed_at           timestamptz
    expires_at            timestamptz not null   -- start + 600s
    created_at            timestamptz
    unique (tenant_id, id)
    foreign key (tenant_id, idp_config_id)
      references org_idp_configs (tenant_id, id) on delete cascade

Bound to issuer/client (via `idp_config_id`), tenant, PKCE context, nonce,
expiry, and the initiating browser — the cookie hash sits **inside** the
one-time claim predicate, exactly as `claim_github_app_flow` does, so a
leaked authorization URL can neither complete nor burn the flow. This is
the same *mechanism* as the parent design's invariant 20; the applicable
binding set differs because login is pre-authentication — there is no
initiating user or canonical resource to bind, and no claim of literal
invariant-20 satisfaction is made (that invariant governs connector
OAuth). A future step-up/re-auth flow would add `user_id`. Expired rows
are GC'd on insert, like `github_app_flows`.

### `user_sessions`

    id                       uuid primary key
    tenant_id                uuid not null
    membership_id            uuid not null
    user_id                  uuid not null    -- ALWAYS derived from the membership row
    session_token_sha256     text not null unique
    idp_config_id            uuid not null    -- config + generation this login used
    acr                      text             -- verbatim from the ID token, if present
    amr                      text[]           -- verbatim from the ID token, if present
    auth_time                timestamptz      -- from the ID token, if present
    idp_sid                  text             -- informational; nothing consumes it in v1
    created_at, last_seen_at timestamptz
    idle_expires_at          timestamptz not null   -- sliding, capped by absolute
    absolute_expires_at      timestamptz not null   -- hard cap
    revoked_at               timestamptz
    unique (tenant_id, id)
    foreign key (tenant_id, membership_id, user_id)
      references org_memberships (tenant_id, id, user_id) on delete cascade

The three-column FK makes `{tenant, user, membership}` mismatches
relationally impossible: a session's `user_id` is valid only as the user of
its own membership. Sessions are server-side rows, not JWTs: revocation is
a row update, and the cookie value is random (sha256 stored, like every
fluidbox token). Browser session tokens use the prefix **`fbx_web_`** —
`fbx_sess_` is already the runner session-token prefix
(`orchestrator.rs`) and must not be overloaded. Do not overload
`api_tokens` for browser sessions — the lifecycle (sliding expiry, browser
binding, IdP context) is different. There is no refresh-token column
(non-goal above).

### `auth_audit_log`

    id uuid primary key
    tenant_id uuid                 -- nullable: deployment-level operator actions
    actor_kind text not null       -- operator|user|system
    actor_id text
    source_ip text
    request_id text
    action text not null
    target text
    success boolean not null
    detail jsonb                   -- before/after digests; secrets redacted
    created_at timestamptz

Append-only **enforced, not asserted**: the runtime database role is
granted `INSERT`/`SELECT` only (`UPDATE`/`DELETE` revoked). Audit rows for
security mutations (IdP config changes, break-glass actions, role changes,
owner promotion) are written **in the same transaction as the mutation —
if the audit insert fails, the mutation fails.** Both accepted and
rejected break-glass attempts are recorded; bootstrap-owner arming and
consumption events are linked (the consumption row references the arming
row's id in `detail`). Recommended: export/alert to an operator-controlled
sink; that sink is deployment tooling, not schema.

### `api_tokens` (extended for PATs)

    alter table api_tokens
      add column membership_id uuid,
      add column user_id uuid,
      add column name text,
      add column display_prefix text,     -- first 12 chars, for listing UI
      add column last_used_at timestamptz;
    -- kind gains 'pat'; shape enforced:
    alter table api_tokens add constraint api_tokens_kind_shape check (
      (kind = 'session' and session_id is not null and membership_id is null)
      or (kind = 'trigger' and subscription_id is not null and membership_id is null)
      or (kind = 'pat' and membership_id is not null and user_id is not null
          and session_id is null and subscription_id is null)
    );
    alter table api_tokens add constraint api_tokens_pat_membership
      foreign key (tenant_id, membership_id, user_id)
      references org_memberships (tenant_id, id, user_id);

## Login routing (the per-org problem)

Each organization has its own issuer, so the browser must be routed to the
right IdP **before** anyone is authenticated.

- **Org-slug URLs are canonical:** `GET /v1/auth/login/{slug}/start`.
  Deterministic, bookmarkable, and works for any number of orgs with
  different IdPs. Slugs are constrained by the `tenants_slug_shape` check
  and embedded only as a single encoded path segment.
- **A neutral entry page is the human fallback:** `GET /v1/auth/login`
  renders a single "organization" field (strict CSP, output-encoded) and
  redirects to the slug URL. It never enumerates organizations (an org
  picker would leak tenant existence) and answers identically for unknown
  and IdP-less slugs.
- **Email-domain auto-routing is deferred** — it needs a verified-domains
  model and a trust story for shared domains; JIT + slug URLs cover v1.

**One session = one organization.** `UserPrincipal` carries exactly one
`tenant_id`; working in another org means logging in against that org's
IdP. (Users are org-scoped rows, so there is no global identity to switch.)

**One stable redirect URI for every org's IdP client:**
`{FLUIDBOX_PUBLIC_URL}/v1/auth/callback`. The sealed `state` parameter —
built with the existing `seal_state` helper but a login-specific payload —
carries `{purpose: "login", v: 1, flow_id, tenant_id, idp_config_id, exp}`,
so a single callback route serves every issuer. The typed
`purpose`/version fields keep login states and connector states mutually
unredeemable.

## Login flow, end to end

`GET /v1/auth/login/{slug}/start?redirect_to=/` (top-level browser GET;
rate-limited per IP and per org; outstanding unconsumed flows per org are
capped):

1. Resolve `slug` → tenant; load its `active` `org_idp_configs` row. None →
   fail-closed page: "SSO is not configured for this organization."
2. Ensure the discovery cache is fresh (see fail-closed edges); refuse if
   discovery cannot be validated.
3. Validate `redirect_to` (see fail-closed edges); mint a `login_flows`
   row: sealed PKCE verifier, fresh `nonce`,
   `browser_hash = sha256_hex(cookie nonce)`,
   `expires_at = now() + 600s`.
4. `Set-Cookie: __Host-fbx_login_{flow_id}=<nonce>; HttpOnly;
   SameSite=Lax; Secure; Path=/` — the `__Host-` prefix (Secure, no
   `Domain`, `Path=/`) makes the cookie untossable by sibling subdomains.
   Hosted multi-user mode **requires** an https `FLUIDBOX_PUBLIC_URL`;
   login refuses to start over plain http outside loopback dev.
5. 302 to the issuer's `authorization_endpoint` with `response_type=code`,
   `client_id`, `redirect_uri={public_url}/v1/auth/callback`,
   `scope=openid email profile …` (never `offline_access`), sealed
   `state`, `code_challenge` (S256) and `nonce`.

`GET /v1/auth/callback?code&state` (unauthenticated by design — the sealed
`state` plus the flow cookie ARE the authentication; rate-limited;
`no-store`, no-referrer):

1. `open_state` → verify `purpose == "login"`, extract
   `{flow_id, tenant_id, idp_config_id}`; tampered/expired/wrong-purpose →
   refuse.
2. Read cookie `__Host-fbx_login_{flow_id}`; duplicate cookie names for
   the flow → refuse. Compute `browser_hash`.
3. **One-time claim, conditional on the config still being active:**

       update login_flows f set consumed_at = now()
        from org_idp_configs c
        where f.id = $flow and f.tenant_id = $tenant
          and f.idp_config_id = $config
          and c.tenant_id = f.tenant_id and c.id = f.idp_config_id
          and c.status = 'active'
          and f.consumed_at is null
          and f.browser_hash = $hash
          and f.expires_at > now()
        returning f.pkce_verifier_sealed, f.nonce, f.redirect_to

   Zero rows → fail closed (replay, wrong browser, expiry, or a config
   retired mid-flight) without burning anything.
4. Exchange the code at the `token_endpoint` (PKCE verifier; client
   authentication per the config's validated `token_endpoint_auth`; exact
   `redirect_uri`). The token response **must** include an access token.
5. **Verify the ID token with `openidconnect`:** JWKS signature (alg must
   be in `alg_allowlist`; symmetric algorithms and `none` are always
   rejected), `iss == config.issuer` exactly, `client_id ∈ aud`; when
   `aud` is multi-valued `azp` is required and must equal `client_id`;
   when `azp` is present at all it must equal `client_id`. Time checks
   with skew `s`: `now < exp + s`, `now ≥ nbf − s` (if present), and
   `iat ∈ [flow.created_at − s, now + s]` (binds token freshness to this
   flow). `nonce` equals the stored nonce. `at_hash` is validated when the
   claim is present; an `at_hash` claim with no access token fails.
   `sub` must be present, nonempty, ≤255 bytes.
6. Map claims per `claim_mappings`; apply `require_email_verified`.
7. **JIT provision:** upsert `users` on `(tenant_id, idp_config_id,
   subject)` (refresh email/name/`last_login_at`); upsert `org_memberships`
   with mapped roles (never removing `owner` on refresh); a `deactivated`
   membership refuses login.
8. Consume `bootstrap_owner_email` if armed (single-winner transaction;
   see break-glass).
9. **Session replacement is never silent:** if the browser presents a
   valid existing `__Host-fbx_web` session for a *different* user or
   organization, the callback does not swap it — it renders a same-origin
   confirmation page whose POST (CSRF-protected) completes the switch.
   This closes forced-login/session-substitution via attacker-initiated
   top-level navigation.
10. Mint the session: token `fbx_web_<hex>`, store its sha256 in
    `user_sessions` with the membership triple, IdP context
    (`idp_config_id`, `acr`/`amr`/`auth_time`), and
    `idle_expires_at = least(now() + idle, absolute_expires_at)`.
11. `Set-Cookie: __Host-fbx_web=<token>; HttpOnly; SameSite=Lax; Secure;
    Path=/`; clear the login cookie; 302 to the validated `redirect_to`.

## Session custody and dashboard integration

**Rust owns sessions.** The dashboard proxy's credential behavior is
**static deployment configuration** (`FLUIDBOX_WEB_MODE=admin|sso` in the
web app's environment), never inferred per request:

| Mode | Proxy behavior |
|---|---|
| `admin` (local/dev, no IdPs) | Today's behavior: inject `Bearer FLUIDBOX_ADMIN_TOKEN` server-side. No login UI. |
| `sso` (hosted) | **Cookie passthrough only:** forward fluidbox cookies (allowlist: `__Host-fbx_web`, `__Host-fbx_login_*`), forward the CSRF header and the normalized `Origin`, propagate every `Set-Cookie` response header separately, support GET/POST/PUT/PATCH/DELETE. The admin token is **not present in the web app's environment at all** — there is nothing to fall back to. |

A hosted deployment therefore cannot leak operator authority on a missing
or invalid cookie: the failure mode is 401, not admin. IdP-less
organizations in a mixed deployment are reachable only through
bearer-authenticated `/v1/admin/*` routes, never through the browser
proxy. Requests presenting **both** a session cookie and a bearer
credential are rejected (400) rather than resolved by precedence.
`FLUIDBOX_REQUIRE_SSO=1` (server-side) confines the admin token to
`/v1/admin/*`: with it set, `Admin` no longer authorizes data-plane
routes. The same-origin topology (`/` → web, `/v1` → API, one origin) is a
deployment invariant the Helm chart's ingress already implements.

**`UserPrincipal` extractor** (`FromRequestParts`, same style as `Admin`):
resolves the `__Host-fbx_web` cookie **or** a `Bearer fbx_pat_…` token to a
live row, **rechecks membership `active` on every request**, updates
`idle_expires_at = least(now() + idle, absolute_expires_at)` atomically
with the validity check, and yields:

    UserPrincipal {
      tenant_id, user_id, membership_id, roles,
      auth: BrowserSession { session_id, idp_config_id, acr, amr, auth_time }
          | Pat { token_id },
    }

`auth` is a closed enum — a PAT principal has no browser session and never
pretends to. The parent design's `authentication_strength` field is
**derived** from this context (a normalized assurance: `idp`, or `mfa`
when the config's operator maps specific `acr`/`amr` values to it — the
mere presence of `acr` proves nothing), and a `Pat` context never
satisfies any assurance or step-up requirement. A **`Principal` resolver**
lets `UserPrincipal` coexist with `Admin` (admin token ⇒ operator
principal over the `default` tenant — today's semantics) and with the
parent design's trigger/schedule/webhook/system variants.

**Phase B's repository refactor is total, not identity-only.** The parent
design requires every normal `fluidbox-db` method to take a `TenantScope`;
today's `get_session`/`get_connection`/`events_after` are UUID-only. Phase
B refactors **all tenant-owned repositories and worker call sites**, not
just the new identity tables — replacing `state.tenant_id` reads with
`principal.tenant_id` does not repair an unscoped SQL query underneath.
The one narrow exception: credential resolution (session cookie, PAT,
trigger, runner token) necessarily starts tenant-less — it accepts only a
server-computed token digest, atomically returns the row **with** its
tenant and live membership, and constructs the `TenantScope` from that.
Nothing else may bootstrap a scope, and a browser-supplied tenant never
does.

**CSRF:** `SameSite=Lax` + a required custom header (e.g.
`x-fluidbox-csrf: 1`) on every non-GET + an `Origin` check. This argument
is valid **only after Phase B removes the current
`CorsLayer::permissive()`** and replaces it with the single configured
browser origin (or no CORS layer at all — the same-origin proxy needs
none). Authenticated application GETs are read-only; the enumerated
exceptions are the protocol-forced GET writes (connector OAuth callback,
GitHub App flow legs, and this design's login start/callback), each
protected by its own one-time claims, not by CSRF headers.

**SSE and long-lived streams:** the handshake authenticates via the
session cookie and enforces the `Origin` check like any GET. Because an
extractor runs once, **every long-lived stream re-authorizes on a bounded
interval (≤60 s): membership still active, session neither revoked nor
past either expiry — and terminates the stream otherwise.** A WebSocket
surface, if ever added, inherits the same handshake + periodic re-auth
rules.

## Break-glass bootstrap and recovery

Bootstrap rides the **existing admin token** (usable from curl with zero
IdP), on an explicit, fully audited surface:

- `POST /v1/admin/orgs {slug, display_name}` — create the organization.
- `POST /v1/admin/orgs/{slug}/idp { issuer, client_id, client_secret,
  token_endpoint_auth, scopes, claim_mappings, alg_allowlist,
  bootstrap_owner_email }` — **discovery-validated at save time**
  (unreachable or non-conformant issuer ⇒ refuse to save), secret sealed,
  created `staged`, then activated (`POST …/idp/{id}/activate`) — a
  no-op transition when no other active row exists.
- **First-owner binding is a single-winner transaction.** The FIRST
  successful login whose **verified** normalized email equals the armed
  value wins, decided atomically:

      -- inside the login transaction, after JIT provisioning:
      update org_idp_configs
         set bootstrap_owner_email = null
       where tenant_id = $t and id = $config
         and bootstrap_owner_email = $normalized_email
         and not exists (select 1 from org_memberships m
                          where m.tenant_id = $t
                            and m.status = 'active'
                            and 'owner' = any(m.roles))
       returning id;

  One row returned ⇒ this login (and only this login) promotes its
  membership to `owner`, in the same transaction, with the audit row.
  Zero rows ⇒ someone already won, or an active owner exists. Note the
  `status = 'active'` filter: a deactivated ex-owner never blocks
  recovery. **Accepted residual, documented:** email is not an identity —
  if two distinct subjects at the IdP share the armed verified address,
  the first to log in wins; the operator armed a specific address
  deliberately, the audit row records the winning `sub`, and re-arming
  after a wrong winner is one break-glass call away.
- **Lockout recovery:** `PATCH /v1/admin/orgs/{slug}/idp/{id}` fixes only
  the **mutable** fields (secret, mappings, scopes, auth method, algs);
  a wrong issuer or client is fixed by an issuer migration (below), never
  in place. `POST …/idp/{id}/reactivate` re-enables a `disabled` row when
  no other row is active. `POST /v1/admin/orgs/{slug}/break-glass-owner
  {email}` re-arms `bootstrap_owner_email`.

Every action above — accepted **and rejected** — writes `auth_audit_log`
in the same transaction as its mutation, with `actor_kind='operator'`.

## Machine access: personal API tokens

- **Minting and revoking PATs requires a browser-session principal** —
  `POST /v1/auth/tokens {name, expires_in}` refuses a `Pat` auth context.
  A PAT can never mint, extend, or revoke PATs (including itself): a
  stolen token cannot self-replicate past its expiry.
- Default TTL 90 days; maximum 1 year (`expires_in` clamped). Returns
  `fbx_pat_<hex>` **once**; sha256 stored with the membership triple and a
  `display_prefix` for listing.
- **PAT authority is the live membership, minus step-up surfaces.** PAT
  auth re-reads membership status and roles on every use (deactivation
  kills it instantly — the join is one indexed row at this scale), but a
  `Pat` context is refused for: IdP config management, PAT
  minting/revocation, break-glass routes, and membership role changes.
  Those require a browser session.
- `GET /v1/auth/tokens` (list: names, display prefixes, last-used),
  `DELETE /v1/auth/tokens/{id}` (revoke; browser session required).
- IdP-independent by design: the CLI and API never need a browser flow. A
  device-code flow can layer on later without schema change.

## Lifecycle

- **Session TTLs:** idle default 8h (sliding), absolute default 7d;
  `FLUIDBOX_SESSION_IDLE_SECS` / `FLUIDBOX_SESSION_ABSOLUTE_SECS`. The
  idle bump is always `least(now() + idle, absolute_expires_at)`.
- **Deactivation windows, stated honestly.** Deactivating a membership in
  fluidbox takes effect at the next authorization boundary after commit:
  one transaction sets the membership `deactivated`, revokes its sessions
  and PATs, and notifies; open streams terminate within the ≤60 s re-auth
  interval. **IdP-side-only** deactivation is invisible until
  re-authentication: an actively-used session survives until its
  **absolute** expiry (the sliding idle timeout bounds only inactive
  sessions — an active attacker resets it). The residual window for
  IdP-only deactivation is therefore ≤ the absolute TTL (7d default);
  operators who need tighter should lower the absolute TTL or deactivate
  in fluidbox too. Periodic IdP re-validation is future work and requires
  its own token-custody design (no refresh tokens are stored in v1); note
  a successful token refresh would not universally prove account liveness
  anyway.
- **Logout:** local-only v1 — `POST /v1/auth/logout` revokes the session
  row and clears the cookie. RP-initiated and back-channel logout are
  later work; `idp_sid` is captured informationally.
- **Client-secret rotation** is a re-seal on the same row (no generation
  bump; in-flight `login_flows` never hold the secret).
- **Issuer migration is a staged atomic swap, never an edit.** Because
  `issuer`/`client_id` are immutable and one active row is enforced by
  the partial index, migration is:
  1. create the new row (`generation + 1`) as `staged`; validate
     discovery;
  2. in ONE transaction that locks the org's IdP rows: old row →
     `retired`, new row → `active` (the partial index permits this order
     inside the transaction), cancel unconsumed `login_flows` of the old
     config, revoke every `user_sessions` row minted under the old
     config, and — the default policy — deactivate memberships of users
     provisioned by the old config, which revokes their PATs via the
     deactivation cascade. Operators may instead explicitly re-arm
     `bootstrap_owner_email` and let users re-provision under the new
     config (new `users` rows — subjects are not portable across
     issuers).
  3. The callback's claim predicate (`c.status = 'active'`) makes a
     mid-migration old-config callback fail closed; the session insert
     lives in the same transaction as the claim, so no old-generation
     session can be minted after the swap commits.

## Fail-closed edges

- **Discovery:** validated at config-save time (refuse to save an
  unreachable or non-conformant issuer; discovered `issuer` must equal
  the configured issuer exactly) and cached
  (`discovered_metadata`/`jwks`, `FLUIDBOX_OIDC_DISCOVERY_MAX_AGE_SECS`,
  default 3600). At login, a stale cache refreshes; refresh failure with a
  still-valid cache uses the cache; with none, refuses. **All discovery,
  JWKS, and token-endpoint fetches apply the parent design's SSRF rules:**
  https required, redirects re-validated, private/loopback/link-local/
  metadata address ranges rejected at resolution time.
- **JWKS cache + key selection:** keyed
  `(tenant_id, idp_config_id, generation)`; refresh is singleflighted per
  config. Exactly **one** forced refresh is attempted when no compatible
  key is found **or when signature verification fails with a cached key**
  (a same-`kid` rotation looks like the latter); after that forced
  refresh, failure is terminal for the login. Key matching requires
  `kid` + `alg` + `kty` (+ `use`/`key_ops` when present); multiple
  ambiguous candidates ⇒ refuse. Unknown `kid`s are negative-cached
  briefly (bounds junk-`kid` refresh storms without blocking a real
  rotation, which enters via the signature-failure path). Last-known-good
  JWKS persists until its explicit expiry. JWKS documents are bounded in
  size and key count.
- **Algorithms:** `none` and all symmetric (HS*) algorithms are rejected
  unconditionally in v1 — the allowlist can only narrow within the
  asymmetric set. (This matches the parent design's threat model; a
  shared `client_secret` must never be able to forge identities.)
- **Clock skew:** `FLUIDBOX_OIDC_CLOCK_SKEW_SECS` (default 60), applied
  as defined in login-flow step 5 (including `iat` bounded to the flow's
  lifetime).
- **`email_verified=false`:** never satisfies `bootstrap_owner_email`;
  blocks login when `require_email_verified` (default true).
- **Subject collisions:** impossible across issuers by construction — the
  identity key includes `idp_config_id` and `iss` is verified per token.
- **`redirect_to`:** parsed once, canonically; accepted only as a
  single-slash absolute local path — reject `//…`, backslashes, control
  characters, userinfo, scheme or authority forms, dot-segments, and
  separator-encoding tricks (`%2F%2F`, `/%5C…`); preferably allowlisted
  to known dashboard path prefixes. Built into the redirect only from the
  claimed row.
- **Unsolicited/replayed callbacks:** no unconsumed `login_flows` row
  matching `(flow, tenant, config, browser_hash, unexpired, config
  active)` ⇒ refuse; the claim predicate makes the check atomic. Start
  and callback endpoints are rate-limited (per IP, per org) and
  unconsumed flows per org are capped, bounding DB- and IdP-amplification
  from the unauthenticated surface.

## What "any IdP" requires of the IdP (conformance floor)

Documented for operators; anything meeting this floor works:

- OIDC discovery at `{issuer}/.well-known/openid-configuration` (RFC
  8414/OIDC Discovery) with `authorization_endpoint`, `token_endpoint`,
  `jwks_uri`.
- Authorization-code flow with PKCE `S256`.
- A token-endpoint client authentication method among
  `client_secret_basic`, `client_secret_post`, or `none` (public client).
- ID tokens signed with an asymmetric algorithm in the config's allowlist,
  carrying a stable nonempty `sub`; an access token in the token response.
- `email`/`email_verified` claims strongly recommended (required when
  `require_email_verified` or bootstrap-owner binding is used).
- A group/role claim only if role mapping is wanted; otherwise every JIT
  user lands at `default_role`.

## Security invariants (this layer)

1. No IdP credential or ID/access token is ever stored unsealed; session
   and PAT secrets are stored only as sha256; refresh tokens are not
   stored at all in v1.
2. Login state is a one-time server-side row bound to issuer, client,
   tenant, PKCE context, nonce, expiry, and the initiating browser
   (cookie hash inside the claim predicate) — the parent invariant-20
   mechanism, with the bindings applicable to a pre-authentication flow.
3. Every ID token is verified — signature against the issuer's JWKS with
   an asymmetric allowlisted algorithm, exact `iss`, `aud` (+`azp`
   whenever present), `exp`/`iat`/`nbf` with defined skew, `nonce`,
   `at_hash` when present — before any user row is touched.
4. Identity is `(tenant, idp_config, subject)` with `subject` = the
   verified standard `sub`, never mappable; email is never an identity
   key; `sub` is never trusted across issuers.
5. The browser supplies no `tenant_id`/`user_id`; principals derive solely
   from verified sessions, PATs, or the operator token; requests bearing
   two credential classes are rejected.
6. Authorization is the live membership row, rechecked on every request,
   every PAT use, and on a bounded interval inside every long-lived
   stream — deactivation cascades to sessions and PATs in one
   transaction.
7. `owner` is never minted from IdP claims absent an explicit operator
   opt-in; bootstrap-owner promotion is a single-winner atomic claim.
8. No IdP configured ⇒ no multi-user surface exists for that org;
   single-admin mode is unchanged; the hosted browser proxy has no
   operator credential to fall back to.
9. Break-glass actions ride the operator credential on an explicit
   surface; every attempt (accepted or rejected) is audited in the same
   transaction as its mutation.
10. IdP config identity (`issuer`, `client_id`, `generation`) is
    immutable; issuer migration is a staged atomic swap that cancels old
    flows and revokes old-config sessions and PATs.
11. A PAT can never mint, extend, or revoke PATs, and never satisfies a
    step-up or assurance requirement.
12. All identity-layer sealed columns (`org_idp_configs.
    client_secret_sealed`, `login_flows.pkce_verifier_sealed`) join the
    Phase D KMS re-seal inventory.

## Phase B mapping

This document is the design for Phase B's identity bullets in the parent
doc. Implementation order inside Phase B:

1. Migration `0012` (tables above, in the stated order) + `TenantScope`
   repository methods.
2. **The full repository refactor:** every tenant-owned `fluidbox-db`
   method gains a `TenantScope` signature (not only the new identity
   families); workers carry explicit tenant context; the
   credential-resolution bootstrap exception is the single tenant-less
   entry point. Replace `state.tenant_id` reads with
   `principal.tenant_id` behind the `Principal` resolver.
3. `/v1/auth/*` routes (entry page, start, callback, logout, tokens)
   using `openidconnect` for verification and the flows/claims machinery
   above; remove `CorsLayer::permissive()` in the same change.
4. `/v1/admin/orgs*` bootstrap + break-glass surface (staged IdP
   activation, single-winner owner claim, transactional audit).
5. Dashboard: login redirect page, static `FLUIDBOX_WEB_MODE` proxy
   (cookie allowlist, CSRF/Origin forwarding, multi-`Set-Cookie`,
   PATCH), session-aware shell (org name, user, logout).
6. CI acceptance against a real conformant issuer (Keycloak or Dex in a
   container) — the parent doc's Phase B acceptance list carries the
   specific negative cases, plus: PAT-mints-PAT refused; SSE stream
   terminates within the re-auth interval after deactivation; issuer
   migration mid-flight callback fails closed; forced-login session
   replacement requires the confirmation POST.

## Open questions (defaults chosen, explicitly marked)

1. **Issuer-migration membership policy:** default deactivates
   old-config memberships (with their sessions/PATs); explicit
   carry-forward is operator work. Confirm at Phase B review.
2. **Owner-from-claims:** default refused; `allow_owner_mapping` exists
   for operators who insist.
3. **Bootstrap-owner shared-email residual:** first verified matching
   subject wins (documented above). If that is unacceptable, the
   alternative is a pending-owner state requiring operator confirmation
   of the winning `sub`.
4. **`roles text[]` vs a child table:** `text[]` for v1 simplicity;
   revisit only if per-role metadata (grantor, expiry) becomes real.

## Revision history

**v2 (2026-07-17)** — adversarial review by Codex (gpt-5.6-sol, max
reasoning): REVISE verdict, 17 findings, 16 incorporated (1 adapted:
the parent's invariant 20 is left untouched — it governs connector OAuth;
this doc now states its own binding set instead of claiming literal
satisfaction). Changes: relational integrity completed (migration order;
`unique(tenant_id,id)` everywhere with `auth_audit_log` as the declared
exception; sessions/PATs bound to the membership triple via three-column
FKs; `api_tokens` kind-shape checks; `unique(tenant_id, generation)`);
IdP config identity made immutable with a staged atomic issuer-migration
swap (old flows cancelled, old sessions/PATs revoked, callback claim
conditional on config-active); bootstrap owner became a single-winner
transactional claim filtering active owners; revocation windows stated
honestly (IdP-only disable ≤ absolute TTL; idle bounds inactive sessions
only; idle bump capped by absolute) and SSE re-authorizes on a ≤60 s
interval; proxy mode became static deployment config with no operator
fallback and dual-credential rejection; `sub` made unmappable and
required; PATs cannot mint PATs, are TTL-clamped, and are barred from
step-up surfaces; browser session prefix renamed `fbx_web_` (the
`fbx_sess_` prefix already belongs to runner tokens); OIDC verification
made normative (azp-whenever-present, at_hash-when-present with a
required access token, symmetric algorithms unconditionally rejected,
skew directions and flow-bound `iat`, discovered token-endpoint auth
method); JWKS caching specified (generation-keyed, singleflight, one
forced refresh on signature failure covering same-`kid` rotation,
ambiguity rejection, negative caching, size bounds, SSRF-validated
fetches); `__Host-` cookies, forced-login confirmation interstitial, and
rate/flow caps; `redirect_to` and slug validation made normative;
`CorsLayer::permissive()` removal made an explicit Phase B change with
GET-write exceptions enumerated; audit made transactional and
role-enforced append-only; refresh-token custody removed from v1
entirely; the principal's auth context became a closed enum with derived
assurance; factual corrections (nine tables, checkout baseline including
the merge commit, `seal_state` payload, pattern-not-verbatim reuse,
"JavaScript-readable credential" phrasing); Phase B scope corrected to
the full repository refactor with the credential-resolution bootstrap
exception.

**v1 (2026-07-17)** — initial companion design.

## References

- Parent design: `2026-07-14-multi-user-mcp-control-plane-design.md` (v4)
- One-time browser-flow pattern: `2026-07-11-github-seamless-connect-design.md`
- [`openidconnect` crate](https://github.com/ramosbugs/openidconnect-rs)
- [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html) ·
  [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) ·
  [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) ·
  [RFC 7636 (PKCE)](https://www.rfc-editor.org/rfc/rfc7636)
- [SEP-990: Enterprise-Managed Authorization](https://modelcontextprotocol.io/seps/990-enable-enterprise-idp-policy-controls-during-mcp-o) ·
  [EMA announcement](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/) ·
  [RFC 8693 (token exchange)](https://www.rfc-editor.org/rfc/rfc8693) ·
  [RFC 7523 (JWT bearer)](https://www.rfc-editor.org/rfc/rfc7523)
