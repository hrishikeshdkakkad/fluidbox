# fluidbox — IdP-agnostic, per-organization identity layer

**Date:** 2026-07-17
**Status:** FINALIZED v1 — companion to the multi-user MCP control plane design (Phase B input); nothing here is implemented
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
   reused verbatim for login flows, satisfying the parent design's
   invariant 20;
2. **`seal.rs`** (XChaCha20-Poly1305) — custody for IdP client secrets, PKCE
   verifiers, and optional refresh tokens, inheriting the Phase D KMS
   re-seal path; and
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
- Alignment with the parent design's principals, invariant 20, tenant-scoped
  repositories, and Phase D custody plans.

## Non-goals (v1)

- SAML (SAML-only enterprises bridge via Dex/Keycloak on their side).
- A password store, MFA enforcement, or account recovery UX (the IdP owns
  authentication; fluidbox owns sessions and authorization).
- Cross-organization identity linking (same human in two orgs = two users).
- SCIM provisioning and email-domain login routing (later; JIT covers v1).
- Device-code flow for CLI login (PATs cover v1).
- RP-initiated and back-channel logout (scaffolded via `idp_sid`, not built).
- SEP-990 Enterprise-Managed Authorization (target-state hook only; see
  the parent doc's "Enterprise-managed authorization" section).

## Framing decisions (settled)

**Organizations ARE tenants.** The existing `tenants` table gains org-facing
columns (`slug`, `display_name`, `status`); `tenant_id` is never renamed —
it is load-bearing in ten tables, every handler, and `AppState`. "Tenant"
and "organization" are the same object at different layers of speech.

**Users are org-scoped.** The identity key is
`(tenant_id, idp_config_id, subject)` — the issuer is pinned through the IdP
config that provisioned the identity, and `iss` is verified on every token.
The same human in two organizations is two `users` rows with two
memberships. This makes cross-org identity leakage structurally impossible
and keeps `UserPrincipal.tenant_id` unambiguous. Never key on `sub` alone.

**Multi-user is derived, not a flag.** An organization with an `active`
`org_idp_configs` row is multi-user; an organization without one (including
the boot-seeded `default` tenant) keeps today's admin-token path. There is
no deployment-wide toggle to misconfigure; the absence of an IdP is the
fail-closed state.

**The admin token survives as the operator/break-glass credential.** It
never becomes a user; it acts through an explicit `/v1/admin/*` surface and
(in single-admin mode) today's `/v1` surface, both audited.

## Current state this builds on (verified on `main` @ `c967192`)

- Auth is extractor-based with no middleware (`auth.rs`): `Admin`
  (sha256 compare against `FLUIDBOX_ADMIN_TOKEN`), `TriggerAuth`
  (subscription-scoped `api_tokens`), `SessionAuth` (runner tokens).
- One boot tenant: `ensure_default_tenant` seeds `tenants('default')`;
  `AppStateInner.tenant_id` is consumed by nearly every handler.
- The dashboard proxy (`apps/web/app/api/fluidbox/[...path]/route.ts`)
  injects the admin token server-side; the browser holds no credential.
- `github_app_flows` implements one-time browser-bound claims:
  `claim_github_app_bootstrap` binds `browser_hash = sha256(cookie nonce)`
  exactly once; `claim_github_app_flow` consumes the flow only when the
  presented cookie's hash matches inside the `UPDATE … WHERE` predicate.
- `seal.rs::Sealer` (XChaCha20-Poly1305; key `FLUIDBOX_CREDENTIAL_KEY`) is
  optional at boot; every sealed feature refuses when absent — the identity
  layer inherits that rule (no IdP config without a sealer).
- `oauth.rs` has PKCE S256, `random_urlsafe`, `b64url`, `seal_state`, and
  RFC 8414/OIDC discovery — but no ID-token/JWKS verification (it targets
  MCP connector authorization, not login).
- `FLUIDBOX_PUBLIC_URL` is the browser-facing base URL feeding OAuth
  redirect URIs; the same base serves the login callback here.
- No `users`, `memberships`, `roles`, or `organizations` tables exist.
- Migrations end at `0011_finalization_intent`; this layer takes `0012`.

## Data model (migration `0012_identity_layer.sql`)

Every new table carries `tenant_id` plus a `unique (tenant_id, id)` key so
children can use composite `(tenant_id, …)` foreign keys, per the parent
design's mandate. Row-level security is added as depth; `TenantScope`
repository signatures remain the primary control.

### `tenants` (extended in place)

    alter table tenants
      add column slug text,                -- URL-safe org identifier
      add column display_name text,
      add column status text not null default 'active';  -- active|suspended
    create unique index tenants_slug on tenants (lower(slug));
    -- backfill: the boot tenant gets slug 'default'

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
    foreign key (tenant_id, user_id) references users (tenant_id, id)

1:1 with `users` in v1, but a distinct object because the parent design's
`UserPrincipal` carries `membership_id` and because **the membership is the
recheck target**: the broker's owner-membership recheck before every
credentialed binding use resolves this row's `status`. Deactivating it is
the instant kill switch for sessions, PATs, and personal-connection use.
Roles live in a `text[]` (small closed set, app-validated); `owner` is never
grantable from IdP claims (see claim mapping).

### `org_idp_configs`

    id                    uuid primary key
    tenant_id             uuid not null references tenants(id)
    generation            int not null default 1     -- bumps on issuer migration
    issuer                text not null              -- https issuer URL
    client_id             text not null
    client_secret_sealed  bytea                      -- Sealer; null = public/PKCE-only client
    scopes                text[] not null default '{openid,email,profile}'
    alg_allowlist         text[] not null default
                          '{RS256,ES256,PS256,RS384,ES384,RS512,ES512}'  -- asymmetric only
    claim_mappings        jsonb not null             -- see below
    bootstrap_owner_email text                       -- one-time first-owner binding; nulled on use
    discovered_metadata   jsonb                      -- cached RFC 8414/OIDC discovery document
    jwks                  jsonb                      -- cached signing keys
    discovered_at         timestamptz
    status                text not null default 'active'   -- active|disabled
    created_by            text                       -- 'operator' | membership id
    created_at, updated_at timestamptz
    unique (tenant_id, id)
    create unique index one_active_idp_per_org
      on org_idp_configs (tenant_id) where status = 'active';

`claim_mappings` default:

    {
      "subject": "sub",
      "email": "email",
      "email_verified": "email_verified",
      "name": "name",
      "roles_path": "groups",
      "role_map": {},
      "default_role": "member",
      "require_email_verified": true
    }

`roles_path` points at a claim (top-level or dotted path) whose values are
looked up in `role_map` to produce fluidbox roles; unmapped users get
`default_role`. `role_map` may map to `member|approver|admin` — mapping to
`owner` is refused at config validation unless the operator explicitly sets
`"allow_owner_mapping": true` (default absent): an IdP group must not
silently mint the org's root authority.

### `login_flows` (invariant-20 one-time state rows)

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
    foreign key (tenant_id, idp_config_id)
      references org_idp_configs (tenant_id, id) on delete cascade

Satisfies invariant 20: bound to issuer/client (via `idp_config_id`),
tenant, PKCE context, nonce, expiry, and the initiating browser — the
cookie hash sits **inside** the one-time claim predicate, exactly as
`claim_github_app_flow` does, so a leaked authorization URL can neither
complete nor burn the flow. Login is unauthenticated, so no user binds at
start; a future step-up/re-auth flow would add `user_id`. Expired rows are
GC'd on insert, like `github_app_flows`.

### `user_sessions`

    id                       uuid primary key
    tenant_id                uuid not null
    user_id                  uuid not null
    membership_id            uuid not null
    session_token_sha256     text not null unique
    authentication_strength  text not null default 'idp'  -- 'idp' | 'mfa' (from acr/amr) | 'pat'
    idp_sid                  text            -- IdP session id (back-channel logout hook)
    refresh_token_sealed     bytea           -- optional; periodic re-validation + SEP-990 seam
    created_at, last_seen_at timestamptz
    idle_expires_at          timestamptz not null   -- sliding
    absolute_expires_at      timestamptz not null   -- hard cap
    revoked_at               timestamptz
    foreign key (tenant_id, membership_id)
      references org_memberships (tenant_id, id) on delete cascade

Sessions are server-side rows, not JWTs: revocation is a row update, and the
cookie value is random (sha256 stored, like every fluidbox token). Do not
overload `api_tokens` for browser sessions — the lifecycle (sliding expiry,
browser binding, `idp_sid`) is different.

### `auth_audit_log`

    id uuid primary key, tenant_id uuid, actor_kind text, actor_id text,
    action text, target text, detail jsonb, created_at timestamptz

Append-only. Records: login success/failure (with reason class, never
tokens), JIT provisioning, role changes, PAT mint/revoke, session revoke,
IdP config create/update/disable, and **every** break-glass action.

### `api_tokens` (extended for PATs)

    alter table api_tokens
      add column user_id uuid,
      add column membership_id uuid,
      add column name text,
      add column last_used_at timestamptz;
    -- kind gains 'pat'

## Login routing (the per-org problem)

Each organization has its own issuer, so the browser must be routed to the
right IdP **before** anyone is authenticated.

- **Org-slug URLs are canonical:** `GET /v1/auth/login/{slug}/start`.
  Deterministic, bookmarkable, and works for any number of orgs with
  different IdPs.
- **A neutral entry page is the human fallback:** `GET /v1/auth/login`
  renders a single "organization" field and redirects to the slug URL. It
  never enumerates organizations (an org picker would leak tenant
  existence) and answers identically for unknown and IdP-less slugs.
- **Email-domain auto-routing is deferred** — it needs a verified-domains
  model and a trust story for shared domains; JIT + slug URLs cover v1.

**One session = one organization.** `UserPrincipal` carries exactly one
`tenant_id`; working in another org means logging in against that org's
IdP. (Users are org-scoped rows, so there is no global identity to switch.)

**One stable redirect URI for every org's IdP client:**
`{FLUIDBOX_PUBLIC_URL}/v1/auth/callback`. The sealed `state` parameter
carries `{flow_id, tenant_id, idp_config_id, exp}` (existing `seal_state`
shape), so a single callback route serves every issuer — mirroring the
connector dance's single `/v1/oauth/callback`.

## Login flow, end to end

`GET /v1/auth/login/{slug}/start?redirect_to=/` (top-level browser GET):

1. Resolve `slug` → tenant; load its `active` `org_idp_configs` row. None →
   fail-closed page: "SSO is not configured for this organization."
2. Ensure the discovery cache is fresh (see fail-closed edges); refuse if
   discovery cannot be validated.
3. Mint a `login_flows` row: sealed PKCE verifier, fresh `nonce`,
   `browser_hash = sha256_hex(cookie nonce)`, validated **local**
   `redirect_to`, `expires_at = now() + 600s`.
4. `Set-Cookie: fbx_login_{flow_id}=<nonce>; HttpOnly; SameSite=Lax;
   Path=/v1/auth; Max-Age=600` (+ `Secure` when `FLUIDBOX_PUBLIC_URL` is
   https — the same switch the GitHub App flows use).
5. 302 to the issuer's `authorization_endpoint` with `response_type=code`,
   `client_id`, `redirect_uri={public_url}/v1/auth/callback`,
   `scope=openid email profile …`, sealed `state`,
   `code_challenge` (S256) and `nonce`.

`GET /v1/auth/callback?code&state` (unauthenticated by design — the sealed
`state` plus the flow cookie ARE the authentication, exactly like the
connector callback):

1. `open_state` → `{flow_id, tenant_id, idp_config_id}`; tampered or
   expired → refuse.
2. Read cookie `fbx_login_{flow_id}`; compute `browser_hash`.
3. **One-time claim:**

       update login_flows set consumed_at = now()
        where id = $flow and tenant_id = $tenant
          and idp_config_id = $config
          and consumed_at is null
          and browser_hash = $hash
          and expires_at > now()
        returning pkce_verifier_sealed, nonce, redirect_to

   Zero rows → fail closed (replay, wrong browser, or expiry) without
   burning anything.
4. Exchange the code at the `token_endpoint` (PKCE verifier; client secret
   via HTTP basic auth when the config is confidential; exact
   `redirect_uri`).
5. **Verify the ID token with `openidconnect`:** JWKS signature (alg must be
   in `alg_allowlist`; `none`/HS256 rejected), `iss == config.issuer`,
   `client_id ∈ aud` and `azp == client_id` when `aud` is multi-valued,
   `exp`/`iat`/`nbf` within configured skew, `nonce` equals the stored
   nonce, `at_hash` matches the access token.
6. Map claims per `claim_mappings`; apply `require_email_verified`.
7. **JIT provision:** upsert `users` on `(tenant_id, idp_config_id,
   subject)` (refresh email/name/`last_login_at`); upsert `org_memberships`
   with mapped roles (never removing `owner` on refresh); a `deactivated`
   membership refuses login.
8. Consume `bootstrap_owner_email` if armed (see break-glass).
9. Mint the session: token `fbx_sess_<hex>`, store its sha256 in
   `user_sessions` with `membership_id`, `authentication_strength` from
   `acr`/`amr` (`mfa` when present), idle + absolute expiries, optional
   sealed refresh token and `idp_sid`.
10. `Set-Cookie: fbx_session=<token>; HttpOnly; SameSite=Lax; Secure;
    Path=/`; clear the `fbx_login_*` cookie; 302 to the validated
    `redirect_to`.

## Session custody and dashboard integration

**Rust owns sessions.** The Next.js proxy's behavior is per deployment
mode, and the browser never holds a bearer credential in either:

| Mode | Proxy behavior |
|---|---|
| Single-admin (org has no IdP) | Unchanged: inject `Bearer FLUIDBOX_ADMIN_TOKEN` server-side. No login UI. |
| Multi-user (org has an active IdP) | **Cookie passthrough:** forward the browser's `Cookie` header, propagate `Set-Cookie` responses, never inject the admin token. |

**`UserPrincipal` extractor** (`FromRequestParts`, same style as `Admin`):
resolves the `fbx_session` cookie **or** a `Bearer fbx_pat_…` token to a
live row, **rechecks membership `active` on every request**, bumps the
sliding expiry, and yields
`UserPrincipal { tenant_id, user_id, membership_id, roles,
authentication_strength, session_id }`. A **`Principal` resolver** lets it
coexist with `Admin` (admin token ⇒ operator principal over the `default`
tenant — today's semantics) and with the parent design's trigger/schedule/
webhook/system variants. **Phase B's first refactor is mechanical:** replace
every `state.tenant_id` read with `principal.tenant_id`. Cross-org operator
actions live only on the explicit `/v1/admin/orgs/{slug}/…` surface.

**CSRF:** `SameSite=Lax` + a required custom header (e.g.
`x-fluidbox-csrf: 1`) on every non-GET + an `Origin`/`Referer` check.
Browsers cannot attach custom headers cross-site without a CORS preflight
the server never grants. Double-submit tokens are the documented fallback if
a future cross-site embed ever needs `SameSite=None`.

**SSE:** `EventSource` cannot set headers, but the same-origin session
cookie rides automatically — the SSE routes authenticate via
`UserPrincipal` from the cookie. GET routes remain side-effect-free, so the
custom-header rule applying only to non-GET is sound.

## Break-glass bootstrap and recovery

Bootstrap rides the **existing admin token** (usable from curl with zero
IdP), on an explicit, fully audited surface:

- `POST /v1/admin/orgs {slug, display_name}` — create the organization.
- `POST /v1/admin/orgs/{slug}/idp {issuer, client_id, client_secret,
  scopes, claim_mappings, alg_allowlist, bootstrap_owner_email}` —
  **discovery-validated at save time** (unreachable or non-conformant
  issuer ⇒ refuse to save), secret sealed, stored `active`.
- **First-owner binding:** the first successful login whose **verified**
  email equals `bootstrap_owner_email`, while the org has zero owners, is
  promoted to `owner` through a one-time claim
  (`… where not exists (select 1 from org_memberships where tenant_id = $t
  and 'owner' = any(roles))`), after which `bootstrap_owner_email` is
  nulled. Email is chosen because the operator can know it in advance; a
  raw `sub` usually isn't knowable before first login.
- **Lockout recovery:** because break-glass rides the operator credential,
  a dead IdP can't lock the operator out —
  `PATCH /v1/admin/orgs/{slug}/idp/{id}` (fix issuer/secret),
  `POST /v1/admin/orgs/{slug}/idp/{id}/reactivate`, and
  `POST /v1/admin/orgs/{slug}/break-glass-owner {email}` (re-arm the
  one-time owner claim when all owners are gone).
- Optional hosted hardening: `FLUIDBOX_REQUIRE_SSO=1` confines the admin
  token to the `/v1/admin/*` break-glass surface (no data-plane access).

Every action above writes `auth_audit_log` with `actor_kind='operator'`.

## Machine access: personal API tokens

- `POST /v1/auth/tokens {name, expires_in}` (requires `UserPrincipal`) →
  returns `fbx_pat_<hex>` **exactly once**; sha256 stored in `api_tokens`
  (`kind='pat'`, `tenant_id`, `user_id`, `membership_id`, `name`).
- `GET /v1/auth/tokens` lists (names, prefixes, last-used); 
  `DELETE /v1/auth/tokens/{id}` revokes.
- PAT authentication resolves to a `UserPrincipal` with
  `authentication_strength='pat'`, **re-reading live membership status and
  roles on every use** — authority is the live membership, never a frozen
  snapshot, so deactivation kills PATs instantly.
- IdP-independent by design: the CLI and API never need a browser or the
  org's issuer. A device-code flow can layer on later without schema
  change.

## Lifecycle

- **Session TTLs:** idle default 8h (sliding), absolute default 7d;
  `FLUIDBOX_SESSION_IDLE_SECS` / `FLUIDBOX_SESSION_ABSOLUTE_SECS`.
- **IdP-side deactivation:** fluidbox cannot see an IdP-side disable until
  the user re-authenticates. The primary control is fluidbox-side: the
  per-request membership recheck makes in-fluidbox deactivation instant,
  and the idle timeout bounds the residual window for IdP-only
  deactivation. That window (≤ idle timeout) is **documented honestly**
  rather than pretended away. Periodic re-validation against the IdP via
  the sealed refresh token is scaffolded (`refresh_token_sealed`) and
  default-off in v1.
- **Membership deactivation cascade:** set `status='deactivated'` → revoke
  all `user_sessions` and PATs for the membership → the parent design's
  owner-membership recheck fails closed at the broker for any run binding
  that references it.
- **Logout:** local-only v1 — `POST /v1/auth/logout` deletes the session
  row and clears the cookie. RP-initiated logout (`end_session_endpoint`)
  and back-channel logout are later work; `idp_sid` custody already leaves
  room.
- **IdP config rotation:** a client-secret change is a re-seal on the same
  row (no generation bump; in-flight `login_flows` never hold the secret).
  An **issuer migration is a new generation**: insert a new
  `org_idp_configs` row (`generation + 1`, `active`), disable the old one;
  users re-provision under the new config at next login (new `users` rows —
  subjects are not portable across issuers), sessions minted under the old
  config are revoked, and break-glass owner re-seed is the safety net for
  re-linking authority. A `subject_carryover` mapping is explicitly out of
  scope for v1.

## Fail-closed edges

- **Discovery:** validated at config-save time (refuse to save an
  unreachable or non-conformant issuer) and cached
  (`discovered_metadata`/`jwks`, `FLUIDBOX_OIDC_DISCOVERY_MAX_AGE_SECS`,
  default 3600). At login, a stale cache refreshes; refresh failure with no
  valid cache refuses login. JWKS refreshes on unknown `kid`,
  rate-bounded; no matching key ⇒ refuse.
- **Algorithms:** `none` always rejected; HS256 rejected unless explicitly
  configured (a symmetric key shared with the client would let the client
  forge tokens); default allowlist is asymmetric-only.
- **Clock skew:** `FLUIDBOX_OIDC_CLOCK_SKEW_SECS` (default 60) applied to
  `exp`/`iat`/`nbf`.
- **`email_verified=false`:** never satisfies `bootstrap_owner_email`;
  blocks login when `require_email_verified` (default true).
- **Subject collisions:** impossible across issuers by construction — the
  identity key includes `idp_config_id` and `iss` is verified per token.
- **Multiple audiences:** require `client_id ∈ aud` **and**
  `azp == client_id`; otherwise refuse.
- **Unsolicited/replayed callbacks:** no unconsumed `login_flows` row
  matching `(flow, tenant, config, browser_hash, unexpired)` ⇒ refuse; the
  claim predicate makes the check atomic.
- **Redirect targets:** `redirect_to` must be a local absolute path
  (`/…`), never a scheme/host — validated at flow start, stored, and used
  only from the claimed row.

## What "any IdP" requires of the IdP (conformance floor)

Documented for operators; anything meeting this floor works:

- OIDC discovery at `{issuer}/.well-known/openid-configuration` (RFC
  8414/OIDC Discovery) with `authorization_endpoint`, `token_endpoint`,
  `jwks_uri`.
- Authorization-code flow with PKCE `S256`.
- ID tokens signed with an asymmetric algorithm in the config's allowlist.
- `sub` stable per user; `email`/`email_verified` claims strongly
  recommended (required when `require_email_verified` or bootstrap-owner
  binding is used).
- A group/role claim only if role mapping is wanted; otherwise every JIT
  user lands at `default_role`.

## Security invariants (this layer)

1. No password, IdP credential, or ID/access/refresh token is ever stored
   unsealed; session and PAT secrets are stored only as sha256.
2. Login state is a one-time server-side row bound to issuer, client,
   tenant, PKCE context, nonce, expiry, and the initiating browser (cookie
   hash inside the claim predicate) — the parent design's invariant 20.
3. Every ID token is verified — signature against the issuer's JWKS with
   an asymmetric allowlisted algorithm, `iss`, `aud`(+`azp`), `exp`/`iat`/
   `nbf`, `nonce`, `at_hash` — before any user row is touched.
4. Identity is `(tenant, idp_config, subject)`; email is never an identity
   key; `sub` is never trusted across issuers.
5. The browser supplies no `tenant_id`/`user_id`; principals derive solely
   from verified sessions, PATs, or the operator token.
6. Authorization is the live membership row, rechecked on every request
   and every PAT use — deactivation is instant and cascades to sessions
   and PATs.
7. `owner` is never minted from IdP claims absent an explicit operator
   opt-in; bootstrap-owner promotion happens at most once per arming.
8. No IdP configured ⇒ no multi-user surface exists for that org;
   single-admin mode is unchanged.
9. Break-glass actions ride the operator credential on an explicit surface
   and are always audited.
10. All identity-layer sealed columns join the Phase D KMS re-seal
    inventory.

## Phase B mapping

This document is the design for Phase B's identity bullets in the parent
doc. Implementation order inside Phase B:

1. Migration `0012` (tables above) + `TenantScope` repository methods for
   the new families.
2. `UserPrincipal`/`Principal` extractors; replace `state.tenant_id` reads
   with `principal.tenant_id` (the single most invasive step — do it first,
   behind the resolver, while `Admin` still maps to the boot tenant).
3. `/v1/auth/*` routes (entry page, start, callback, logout, tokens) using
   `openidconnect` for verification and the flows/claims machinery above.
4. `/v1/admin/orgs*` bootstrap + break-glass surface.
5. Dashboard: login redirect page, cookie-passthrough proxy mode, CSRF
   header, session-aware shell (org name, user, logout).
6. CI acceptance against a real conformant issuer (Keycloak or Dex in a
   container) — the parent doc's Phase B acceptance list carries the
   specific negative cases.

## Open questions (defaults chosen, explicitly marked)

1. **Periodic IdP re-validation in v1?** Default: no — the ≤ idle-timeout
   window for IdP-only deactivation is documented; revalidation ships
   scaffolded but off.
2. **Owner-from-claims:** default refused; `allow_owner_mapping` exists for
   operators who insist. Confirm at Phase B review.
3. **Issuer migration ergonomics:** default is re-provision + break-glass
   re-seed; a `subject_carryover` mapping is deliberately unbuilt until a
   real migration demands it.
4. **`roles text[]` vs a child table:** `text[]` for v1 simplicity;
   revisit only if per-role metadata (grantor, expiry) becomes real.

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
