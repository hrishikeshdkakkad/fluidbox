# fluidbox — IdP-agnostic, per-organization identity layer

**Date:** 2026-07-17
**Status:** FINALIZED v5 (2026-07-17) — v2–v5 produced by four adversarial review rounds with Codex (gpt-5.6-sol, max reasoning); companion to the multi-user MCP control plane design (Phase B input); nothing here is implemented
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
- `oauth.rs` has PKCE S256, `random_urlsafe`, `b64url`, sealing
  primitives, and RFC 8414/OIDC discovery. Its `seal_state` helper
  hard-codes the connector wire payload `{c, v, x}` and cannot carry the
  login payload — login adds a **new typed login-state helper** built on
  the same `Sealer` primitives. The module has no ID-token/JWKS
  verification, no callback cookie, and no server-side state row (its
  state is deliberately stateless): login reuses primitives, not the
  flow.
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
`org_memberships` → `login_flows` → `user_sessions` →
`pending_login_switches` → `auth_audit_log` → `api_tokens` alterations
(each FK target exists before its referrer).

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
    bootstrap_owner_expires_at timestamptz           -- arming expiry (default now()+7d)
    discovered_metadata   jsonb                      -- cached RFC 8414/OIDC discovery document
    jwks                  jsonb                      -- cached signing keys
    discovered_at         timestamptz
    status                text not null default 'staged'  -- see transition graph below
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
`alg_allowlist`, `bootstrap_owner_email` (+ expiry), caches, and `status`.

**Status transition graph:** `staged → active`; `active ↔ disabled`
(disable is reversible operator action); `active → retired` (terminal —
only the issuer-migration swap produces it; a retired row is never
reactivated). Every `active → disabled` and `active → retired` transition,
in one transaction, cancels the config's unconsumed `login_flows` and
pending login switches and revokes the `user_sessions` minted under it —
a flow started before a disable can never complete after a reactivation.
PATs are membership-bound, not config-bound: they survive disable/retire
unless the membership itself is deactivated (the issuer-migration default
does exactly that). `reactivate` permits only `disabled → active`, and
only while no other row is active.

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
    foreign key (tenant_id, idp_config_id)
      references org_idp_configs (tenant_id, id)

The three-column FK makes `{tenant, user, membership}` mismatches
relationally impossible: a session's `user_id` is valid only as the user of
its own membership, and its `idp_config_id` must be a config of the same
tenant (that it is the config that provisioned this session's user is an
application-transaction guarantee — the login transaction writes both from
one verified token — not a relational one). Sessions are server-side rows, not JWTs: revocation is
a row update, and the cookie value is random (sha256 stored, like every
fluidbox token). Browser session tokens use the prefix **`fbx_web_`** —
`fbx_sess_` is already the runner session-token prefix
(`orchestrator.rs`) and must not be overloaded. Do not overload
`api_tokens` for browser sessions — the lifecycle (sliding expiry, browser
binding, IdP context) is different. There is no refresh-token column
(non-goal above).

### `pending_login_switches` (one-time session-replacement confirmations)

    id                  uuid primary key
    tenant_id           uuid not null       -- the NEW login's organization
    idp_config_id       uuid not null       -- config + generation of the NEW login
    new_membership_id   uuid not null       -- the verified identity awaiting confirmation
    new_user_id         uuid not null
    replaced_tenant_id  uuid not null       -- the CURRENT session's organization
    replaced_session_id uuid not null       -- (may differ from tenant_id: org switch)
    redirect_to         text not null       -- copied from the claimed login flow
    browser_hash        text not null       -- sha256 of a fresh confirmation-cookie nonce
    acr text, amr text[], auth_time timestamptz   -- carried from the verified ID token
    consumed_at         timestamptz
    expires_at          timestamptz not null      -- creation + 120s
    created_at          timestamptz
    unique (tenant_id, id)
    foreign key (tenant_id, new_membership_id, new_user_id)
      references org_memberships (tenant_id, id, user_id) on delete cascade
    foreign key (tenant_id, idp_config_id)
      references org_idp_configs (tenant_id, id) on delete cascade
    foreign key (replaced_tenant_id, replaced_session_id)
      references user_sessions (tenant_id, id) on delete cascade

When a callback verifies a NEW identity while the browser holds a live
session for a *different* user or organization, the flow does not end in a
session — it ends in this row plus a fresh confirmation cookie
(`__Host-fbx_switch_{id}=<nonce>; HttpOnly; SameSite=Lax; Secure;
Path=/`), and renders the confirmation page (which POSTs same-origin to
`/v1/auth/switch/{id}`). **An org switch is deliberately a cross-tenant
transition, and the schema says so:** the row carries both tenants, and
the replaced session is composite-FK'd in its own tenant. Resolving the
confirmation cookie is the second — and last — credential-like bootstrap
exception to single-tenant scoping: it accepts only the server-computed
cookie hash, atomically returns BOTH tenant contexts, and the dual-tenant
mutation runs through one narrowly named repository method (with explicit
RLS treatment), never a generic UUID lookup. The claiming UPDATE's
predicate requires the cookie hash, unexpired/unconsumed state, AND that
the browser's currently presented live session equals
`(replaced_tenant_id, replaced_session_id)` and is still valid; the same
transaction rechecks config- and membership-active, revokes the replaced
session, mints the new one, and redirects only from the row's stored
`redirect_to`. No form-carried identity or redirect is ever trusted, no
consumed flow is reused, and an expired, declined, or issuer-migrated
pending switch fails closed keeping the original session (the migration
swap and config disable cancel these rows too).

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
granted `INSERT`/`SELECT` only (`UPDATE`/`DELETE` revoked). Audit
semantics are split by outcome: an **accepted** security mutation (IdP
config change, break-glass action, role change, owner promotion) writes
its audit row **in the same transaction — if the audit insert fails, the
mutation fails.** A **rejected** attempt cannot ride an aborted
transaction; it is audited in a separate transaction committed after the
rollback (a required code path, best-effort only against a fully dead
database). Bootstrap-owner arming and consumption events are linked (the
consumption row references the arming row's id in `detail`). Recommended: export/alert to an operator-controlled
sink; that sink is deployment tooling, not schema.

### `api_tokens` (extended for PATs)

    alter table api_tokens
      add column membership_id uuid,
      add column user_id uuid,
      add column name text,
      add column display_prefix text,     -- first 12 chars, for listing UI
      add column last_used_at timestamptz;
    -- kind gains 'pat'; shape enforced, mutually exclusive authority columns:
    alter table api_tokens add constraint api_tokens_kind_shape check (
      (kind = 'session' and session_id is not null
         and subscription_id is null and membership_id is null and user_id is null)
      or (kind = 'trigger' and subscription_id is not null
         and session_id is null and membership_id is null and user_id is null)
      or (kind = 'pat' and membership_id is not null and user_id is not null
         and session_id is null and subscription_id is null
         and expires_at is not null and name is not null
         and display_prefix is not null)
    );
    alter table api_tokens add constraint api_tokens_pat_membership
      foreign key (tenant_id, membership_id, user_id)
      references org_memberships (tenant_id, id, user_id);
    -- and the EXISTING authority columns stop being UUID-only:
    -- migration 0012 adds unique (tenant_id, id) to sessions and
    -- trigger_subscriptions, then:
    alter table api_tokens add constraint api_tokens_session_tenant
      foreign key (tenant_id, session_id) references sessions (tenant_id, id);
    alter table api_tokens add constraint api_tokens_subscription_tenant
      foreign key (tenant_id, subscription_id)
      references trigger_subscriptions (tenant_id, id);

The PAT shape check makes the claimed finite lifetime relational
(`expires_at` is non-null for every PAT), and the composite FKs on the
pre-existing `session_id`/`subscription_id` columns extend the same
tenant-integrity discipline to the token kinds that already exist.

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
built by the new typed login-state helper on the same sealing primitives —
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
3. **Transaction A — the one-time claim, short and free of external
   I/O:**

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
   retired mid-flight) without burning anything. One row → the flow is
   burned and the transaction **commits immediately** — the token
   exchange and verification that follow hold no database transaction or
   connection, so an unauthenticated caller cycling self-created flows
   through a slow IdP cannot occupy the pool. If the exchange then
   fails, the flow stays consumed and the user restarts login (one-time
   means one attempt).
4. Exchange the code at the `token_endpoint` — **outside any database
   transaction** (PKCE verifier; client authentication per the config's
   validated `token_endpoint_auth`; exact `redirect_uri`). The token
   response **must** include an access token.
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
7. **Transaction B — provisioning and session mint, config-locked:**
   `select … from org_idp_configs where tenant_id=$t and id=$config and
   status='active' for update`. The lock is exclusive from the start — a
   share-then-upgrade pattern would deadlock between two concurrent
   logins that both reach the bootstrap-claim UPDATE — and it is the
   same lock the issuer-migration swap takes, so the two serialize: a
   swap that commits first makes B fail closed; a B holding the lock
   delays the swap until the session exists to be revoked. Logins within
   one org serialize on this row; acceptable at login volume. Inside
   the same transaction: JIT provision — upsert `users` on
   `(tenant_id, idp_config_id, subject)` (refresh
   email/name/`last_login_at`); upsert `org_memberships` with mapped
   roles (never removing `owner` on refresh); a `deactivated` membership
   refuses login.
8. Still inside B: consume `bootstrap_owner_email` if armed
   (single-winner claim; see break-glass).
9. **Session replacement is never silent.** If the browser presents a
   valid existing `__Host-fbx_web` session for a *different* user or
   organization, B does not mint a session — it inserts a
   `pending_login_switches` row (both tenants, the verified new
   identity, the replaced session composite-FK'd in its own tenant, the
   config generation, the validated `redirect_to`, and a fresh
   confirmation cookie's hash), commits, sets
   `__Host-fbx_switch_{id}`, and renders the same-origin confirmation
   page. The confirming POST (CSRF-protected) atomically claims that
   row — cookie hash inside the one-time predicate, which also requires
   the browser's currently presented session to equal the row's
   replaced session and still be valid — rechecks config- and
   membership-active, revokes the replaced session, mints the new one,
   and redirects from the row's stored `redirect_to`, all in one
   transaction (the dual-tenant repository exception in the table
   section). Decline, expiry (120 s), or an intervening issuer
   migration fails closed and keeps the original session. This closes
   forced-login/session-substitution via attacker-initiated top-level
   navigation without trusting form-carried identity, a form-carried
   redirect, or a consumed flow.
10. Otherwise B mints the session directly: token `fbx_web_<hex>`, sha256
    stored in `user_sessions` with the membership triple, IdP context
    (`idp_config_id`, `acr`/`amr`/`auth_time`), and
    `idle_expires_at = least(now() + idle, absolute_expires_at)`; B
    commits.
11. `Set-Cookie: __Host-fbx_web=<token>; HttpOnly; SameSite=Lax; Secure;
    Path=/`; clear the login cookie; 302 to the validated `redirect_to`.

## Session custody and dashboard integration

**Rust owns sessions.** The dashboard proxy's credential behavior is
**static deployment configuration** (`FLUIDBOX_WEB_MODE=admin|sso` in the
web app's environment), never inferred per request:

| Mode | Proxy behavior |
|---|---|
| `admin` (local/dev, no IdPs) | Today's behavior: inject `Bearer FLUIDBOX_ADMIN_TOKEN` server-side. No login UI. |
| `sso` (hosted) | **Cookie passthrough only:** forward fluidbox cookies (allowlist: `__Host-fbx_web`, `__Host-fbx_login_*`, `__Host-fbx_switch_*`), forward the CSRF header and the normalized `Origin`, propagate every `Set-Cookie` response header separately, support GET/POST/PUT/PATCH/DELETE. The admin token is **not present in the web app's environment at all** — there is nothing to fall back to. |

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
Exactly two narrow exceptions exist. First, credential resolution
(session cookie, PAT, trigger, runner token) necessarily starts
tenant-less — it accepts only a server-computed token digest, atomically
returns the row **with** its tenant and live membership, and constructs
the `TenantScope` from that. Second, pending-switch confirmation
resolution (the cross-tenant org switch) accepts only the server-computed
confirmation-cookie hash and returns **both** tenant contexts for the one
narrowly named dual-tenant method. Nothing else may bootstrap a scope,
and a browser-supplied tenant never does.

**CSRF — scoped to cookie authentication only:** requests authenticating
via the `__Host-fbx_web` cookie (a `BrowserSession` context) require, on
every non-GET, a custom header (e.g. `x-fluidbox-csrf: 1`) and a passing
`Origin` check. Bearer-authenticated principals (PATs, trigger tokens,
the admin token) are **exempt** — a CLI has no `Origin`, and bearer
credentials are not ambient, so CSRF does not apply to them (they are
still subject to the dual-credential rejection). This argument is valid
**only after Phase B removes the current `CorsLayer::permissive()`** and
replaces it with the single configured browser origin (or no CORS layer
at all — the same-origin proxy needs none). Authenticated application GETs are read-only; the enumerated
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

      -- inside transaction B: the opening `select … for update` already
      -- captured bootstrap_owner_email / bootstrap_owner_expires_at.
      -- When the email matches, consume the arm:
      update org_idp_configs
         set bootstrap_owner_email = null,
             bootstrap_owner_expires_at = null
       where tenant_id = $t and id = $config
         and bootstrap_owner_email = $normalized_email
       returning id;

  `was_unexpired` is computed from the expiry **captured by B's opening
  locked SELECT** — never from `UPDATE … RETURNING`, whose unqualified
  columns observe the post-update row (the expiry is already NULL there;
  the naive `returning (bootstrap_owner_expires_at > now())` is always
  NULL). The `FOR UPDATE` lock makes the captured value authoritative.
  A matching arm is ALWAYS consumed by this single-winner UPDATE; what
  follows is a three-way decision inside the same transaction (owner
  reads are consistent because every owner-role mutation serializes on
  the config lock):

  - consumed, `was_unexpired`, and no **active** owner exists ⇒ this
    login (and only this login) promotes its membership to `owner`, with
    the audit row — a deactivated ex-owner never blocks recovery;
  - consumed but expired, or an active owner exists ⇒ the promotion is
    refused and the now-cleared arm is audited as reject-and-consume;
  - no row returned ⇒ nothing was armed for this email; no bootstrap
    mutation. **Arming cannot go latent:**
  - arming is **rejected while an active owner exists** (the operator
    must deactivate the owner first — a deliberate, audited sequence,
    never a standing trap);
  - an armed value **expires** (`bootstrap_owner_expires_at`, default
    7 days) — an expired arm never promotes (a matching expired arm is
    deliberately consumed and audited);
  - a matching login that finds an active owner anyway (armed before the
    owner appeared) **clears the arm and refuses the promotion**
    (reject-and-consume, audited) rather than leaving it live; and
  - arming, consumption, and owner-role mutations all serialize on the
    config row lock.
  **Accepted residual, documented:** email is not an identity — if two
  distinct subjects at the IdP share the armed verified address, the
  first to log in wins; the operator armed a specific address
  deliberately, the audit row records the winning `sub`, and re-arming
  after a wrong winner is one break-glass call away.
- **Lockout recovery:** `PATCH /v1/admin/orgs/{slug}/idp/{id}` fixes only
  the **mutable** fields (secret, mappings, scopes, auth method, algs);
  a wrong issuer or client is fixed by an issuer migration (below), never
  in place. `POST …/idp/{id}/reactivate` re-enables a `disabled` row when
  no other row is active. `POST /v1/admin/orgs/{slug}/break-glass-owner
  {email}` re-arms `bootstrap_owner_email` — refused while an active
  owner exists, and armed with the standard expiry.

Every action above is audited with `actor_kind='operator'`: accepted
mutations and their audit rows commit atomically; rejected attempts are
audited in a separate transaction committed after the rollback.

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
  2. in ONE transaction that locks the org's IdP rows `FOR UPDATE`: old
     row → `retired`, new row → `active` (the partial index permits this
     order inside the transaction), cancel unconsumed `login_flows` AND
     `pending_login_switches` of the old config, revoke every
     `user_sessions` row minted under the old config, and — the default
     policy — deactivate memberships of users provisioned by the old
     config, which revokes their PATs via the deactivation cascade.
     Operators may instead explicitly re-arm `bootstrap_owner_email` and
     let users re-provision under the new config (new `users` rows —
     subjects are not portable across issuers).
  3. Mid-migration logins fail closed at both phases: the flow claim
     (transaction A) requires `c.status = 'active'`, and the
     provisioning/session transaction (B) re-verifies it under the same
     `FOR UPDATE` row lock this swap takes — the two serialize. A swap
     that commits first makes B fail; a B that holds the lock delays
     the swap until its session exists and is then revoked by it. No
     old-generation session survives the swap's commit.

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
  refresh, failure is terminal for the login. Key matching, when the
  token carries a `kid`, requires `kid` + `alg` + `kty`
  (+ `use`/`key_ops` when present); multiple ambiguous candidates ⇒
  refuse. Unknown `kid`s are negative-cached
  briefly (bounds junk-`kid` refresh storms without blocking a real
  rotation, which enters via the signature-failure path). Last-known-good
  JWKS persists until its explicit expiry. JWKS documents are bounded in
  size and key count. **A missing `kid` is not a rejection:** a
  conformant issuer may omit `kid` when only one signing key exists —
  when the token carries no `kid`, exactly one cached key compatible on
  `alg`/`kty` (+`use`/`key_ops`) is accepted; zero or multiple
  candidates ⇒ refuse.
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
   surface; accepted mutations and their audit rows commit atomically,
   and rejected attempts are audited in a committed transaction after
   rollback.
10. IdP config identity (`issuer`, `client_id`, `generation`) is
    immutable; issuer migration is a staged atomic swap — and config
    disable a reversible transition — each of which cancels the config's
    unconsumed flows and pending switches and revokes its sessions in
    the same transaction; `retired` is terminal.
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
   families); workers carry explicit tenant context; the two
   bootstrap exceptions (credential resolution; pending-switch
   confirmation) are the only tenant-less entry points. Replace
   `state.tenant_id` reads with `principal.tenant_id` behind the
   `Principal` resolver.
3. `/v1/auth/*` routes (entry page, start, callback, switch
   confirmation, logout, tokens) using `openidconnect` for verification
   and the flows/claims machinery above; remove `CorsLayer::permissive()`
   in the same change.
4. `/v1/admin/orgs*` bootstrap + break-glass surface (staged IdP
   activation, single-winner owner claim, transactional audit).
5. Dashboard: login redirect page, static `FLUIDBOX_WEB_MODE` proxy
   (cookie allowlist, CSRF/Origin forwarding, multi-`Set-Cookie`,
   PATCH), session-aware shell (org name, user, logout).
6. CI acceptance against a real conformant issuer (Keycloak or Dex in a
   container) — the parent doc's Phase B acceptance list carries the
   specific negative cases, plus: PAT-mints-PAT refused; SSE stream
   terminates within the re-auth interval after deactivation; issuer
   migration mid-flight fails closed at both callback phases; a
   forced-login session replacement completes only through the
   pending-switch confirmation POST (replayed/expired/wrong-cookie
   switch claims refused); arming while an active owner exists is
   refused and an expired arm never matches; a kid-less token verifies
   against a single-key JWKS.

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

**v5 (2026-07-17)** — Codex round 4 (gpt-5.6-sol, max reasoning): all
round-3 groups verified resolved except one newly introduced SQL defect,
fixed here: the bootstrap decision's `was_unexpired` was computed in
`UPDATE … RETURNING`, whose unqualified columns observe the post-update
row — after the SET it is always NULL, so a fresh organization could
never mint its first owner (fail-closed, but broken). The decision value
now comes from the expiry captured by transaction B's opening
`FOR UPDATE` SELECT, with the pitfall documented; "an expired arm never
matches" corrected to "never promotes" (expired matches are deliberately
consumed and audited).

**v4 (2026-07-17)** — Codex round 3 (gpt-5.6-sol, max reasoning): the
round-2 approval set verified; two High and three smaller residuals
fixed. The pending switch is now an explicitly **cross-tenant** object:
`replaced_tenant_id` + composite FK to `user_sessions`, both tenant
contexts returned by the cookie-hash bootstrap exception (the second and
last credential-like exception to single-tenant scoping), the claim
predicate binding the currently presented live session, the validated
`redirect_to` stored in the row (never form-carried), the confirmation
cookie named and attributed (`__Host-fbx_switch_{id}`), and the
dual-tenant mutation confined to one narrowly named repository method.
The bootstrap SQL now matches its prose: consume-on-match single-winner
UPDATE clearing both arm and expiry, a three-way decision
(promote / reject-and-consume when expired or owner-blocked / no-op),
and transaction B locks the config `FOR UPDATE` from the start (a
share-then-upgrade would deadlock two concurrent bootstrap-matching
logins) — the migration-swap interleaving analysis updated to match.
The two stale audit statements (break-glass section, invariant 9) now
carry the accepted-atomic / rejected-after-rollback split. Low fixes:
the routing section credits the new typed login-state helper (not the
hard-coded `seal_state`), `pending_login_switches` joined the migration
order, and JWKS key matching is conditional on a `kid` being present.
No parent-doc changes were required.

**v3 (2026-07-17)** — Codex round 2 (gpt-5.6-sol, max reasoning): 12 of
17 round-1 findings verified RESOLVED, 5 PARTIAL, 7 new defects — all
incorporated. Changes: the callback became two-phase (transaction A =
the one-time flow claim, committed before any external I/O; token
exchange/verification hold no DB transaction; transaction B = JIT +
session mint under a `FOR SHARE` config lock serializing against the
issuer-migration swap's `FOR UPDATE`); session replacement got a real
one-time browser-bound continuation (`pending_login_switches` — cookie
hash inside the claim predicate, 120 s expiry, cancelled by migration);
the config status graph was defined (`staged → active`,
`active ↔ disabled`, `active → retired` terminal; disable/retire cancel
flows and pending switches and revoke that config's sessions
transactionally; PATs are membership-bound and unaffected except via
membership deactivation); bootstrap arming can no longer go latent
(refused while an active owner exists, expires in 7 days, cleared by a
blocked match, serialized on the config lock); audit semantics split
(accepted mutations audit in-transaction; rejected attempts audit in a
committed transaction after rollback); CSRF scoped to
cookie-authenticated `BrowserSession` requests only (bearer clients
exempt); kid-less JWKS accepted when exactly one compatible key exists;
relational completions (`user_sessions.idp_config_id` composite FK;
`sessions`/`trigger_subscriptions` gain `unique(tenant_id, id)` so
existing `api_tokens` authority columns get composite FKs; the kind
CHECK made authority columns mutually exclusive and PAT
`expires_at`/`name`/`display_prefix` mandatory); the `seal_state`
description corrected (hard-coded `{c,v,x}` wire payload — login adds a
new typed helper on the same primitives). Parent-doc alignment edits in
the same commit: the Phase B bullet no longer calls these "invariant-20
login flows" (they use the invariant-20 *mechanism* with
companion-defined bindings), the principal sketch carries a closed
`auth_context` instead of a bare `session_id`, and the `at_hash`
acceptance bullet now reads "access token required; `at_hash` verified
whenever present."

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
