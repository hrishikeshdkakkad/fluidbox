-- Phase B — IdP-agnostic identity + tenant enforcement (data model).
-- Design: docs/plans/2026-07-17-idp-agnostic-identity-design.md.
--
-- Every new tenant-owned table carries `tenant_id` plus a `unique
-- (tenant_id, id)` key so children reference parents with composite
-- `(tenant_id, …)` foreign keys — a cross-tenant id is then a relational
-- impossibility, not merely a Rust-side `.filter(tenant_id ==)` (the current
-- read boundary). The ONE declared exception is `auth_audit_log`, an
-- append-only deployment log that nothing references and whose `tenant_id`
-- is nullable (operator actions carry none).
--
-- Order: tenants alterations → org_idp_configs → users → org_memberships →
-- login_flows → user_sessions → pending_login_switches → auth_audit_log →
-- api_tokens/sessions/trigger_subscriptions alterations. Each FK target
-- exists before its referrer.

-- ─── tenants (extended in place) ────────────────────────────────────────────
-- slug is the URL-safe org identifier (login routing is per-slug, pre-auth).
alter table tenants
    add column slug text,                                    -- URL-safe org id
    add column display_name text,
    add column status text not null default 'active';        -- active | suspended

-- Backfill trap: a live DB may hold tenant rows besides the boot 'default'.
-- The boot row (name='default') takes slug 'default'; every OTHER pre-existing
-- row gets a derived, unique slug before the NOT NULL + shape check + unique
-- index land. On a fresh DB both updates touch nothing.
update tenants set slug = 'default' where name = 'default' and slug is null;
update tenants set slug = 'org-' || left(id::text, 8) where slug is null;

alter table tenants alter column slug set not null;
alter table tenants add constraint tenants_slug_shape
    check (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$');
create unique index tenants_slug on tenants (slug);

-- ─── org_idp_configs ────────────────────────────────────────────────────────
-- The OIDC provider binding for an org. issuer/client_id/generation are
-- IMMUTABLE — fixing an issuer is a staged migration (new row, new
-- generation), never an edit, because every provisioned user pins this row.
create table org_idp_configs (
    id                          uuid primary key,
    tenant_id                   uuid not null references tenants(id),
    generation                  int not null default 1,      -- bumps on issuer migration
    issuer                      text not null,               -- https issuer; IMMUTABLE
    client_id                   text not null,               -- IMMUTABLE
    client_secret_sealed        bytea,                       -- Sealer; null = public/PKCE client
    token_endpoint_auth         text not null default 'client_secret_basic',
    scopes                      text[] not null default '{openid,email,profile}',
    alg_allowlist               text[] not null default
                                '{RS256,ES256,PS256,RS384,ES384,RS512,ES512}',
    claim_mappings              jsonb not null,
    bootstrap_owner_email       text,                        -- one-time first-owner; nulled on use
    bootstrap_owner_expires_at  timestamptz,
    discovered_metadata         jsonb,                       -- cached RFC 8414/OIDC discovery
    jwks                        jsonb,                       -- cached signing keys
    discovered_at               timestamptz,
    status                      text not null default 'staged',
                                -- staged | active | disabled | retired
    created_by                  text,                        -- 'operator' | membership id
    created_at                  timestamptz not null default now(),
    updated_at                  timestamptz not null default now(),
    unique (tenant_id, id),
    unique (tenant_id, generation)
);
-- At most one active config per org (issuer migration flips old→new inside one
-- transaction; the partial index permits that order mid-transaction).
create unique index one_active_idp_per_org
    on org_idp_configs (tenant_id) where status = 'active';

-- ─── users ──────────────────────────────────────────────────────────────────
-- Identity = (tenant, idp_config, subject); subject is the verified OIDC `sub`,
-- stored verbatim, never mappable. email is display/bootstrap metadata, NOT an
-- identity key (two distinct subs may share an email). email_normalized is
-- maintained by the repo layer (lower(trim(email))), not a generated column.
create table users (
    id                uuid primary key,
    tenant_id         uuid not null references tenants(id),
    idp_config_id     uuid not null,          -- the config that provisioned this identity
    subject           text not null,          -- OIDC `sub`, verbatim
    email             text,
    email_normalized  text,                   -- lower(trim(email)); attribute, NOT unique
    email_verified    boolean not null default false,
    name              text,
    status            text not null default 'active',   -- active | deactivated
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now(),
    last_login_at     timestamptz,
    unique (tenant_id, idp_config_id, subject),           -- the identity key
    unique (tenant_id, id),
    foreign key (tenant_id, idp_config_id) references org_idp_configs (tenant_id, id)
);

-- ─── org_memberships ────────────────────────────────────────────────────────
-- The authorization object and the kill switch: the broker's owner-membership
-- recheck and the deactivation cascade both resolve this row's status.
-- `owner` is never grantable from IdP claims absent an explicit config opt-in.
create table org_memberships (
    id              uuid primary key,
    tenant_id       uuid not null references tenants(id),
    user_id         uuid not null,
    roles           text[] not null default '{member}',   -- ⊆ {member, approver, admin, owner}
    status          text not null default 'active',        -- active | deactivated
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    deactivated_at  timestamptz,
    unique (tenant_id, user_id),
    unique (tenant_id, id),
    unique (tenant_id, id, user_id),      -- composite-FK target for sessions/PATs
    foreign key (tenant_id, user_id) references users (tenant_id, id)
);

-- ─── login_flows (one-time browser-bound state rows) ────────────────────────
-- Same mechanism as github_app_flows: the cookie hash sits INSIDE the one-time
-- claim predicate, so a leaked authorization URL can neither complete nor burn
-- the flow. Bound to issuer/client (via idp_config_id), tenant, PKCE, nonce,
-- expiry, and the initiating browser. Expired rows are GC'd on insert.
create table login_flows (
    id                    uuid primary key,
    tenant_id             uuid not null references tenants(id),
    idp_config_id         uuid not null,              -- binds issuer + client + generation
    pkce_verifier_sealed  bytea not null,             -- Sealer; never plaintext at rest
    nonce                 text not null,              -- OIDC nonce, single-use
    browser_hash          text not null,              -- sha256(per-flow cookie nonce)
    redirect_to           text not null,              -- validated LOCAL path only
    consumed_at           timestamptz,
    expires_at            timestamptz not null,       -- start + 600s
    created_at            timestamptz not null default now(),
    unique (tenant_id, id),
    foreign key (tenant_id, idp_config_id)
        references org_idp_configs (tenant_id, id) on delete cascade
);
create index login_flows_expiry on login_flows (expires_at);

-- ─── user_sessions ──────────────────────────────────────────────────────────
-- Server-side rows, not JWTs: revocation is a row update, the cookie value is
-- random (only its sha256 is stored). The three-column FK makes {tenant, user,
-- membership} mismatches relationally impossible. Browser tokens use the
-- `fbx_web_` prefix (never overload the runner `fbx_sess_`). No refresh token.
create table user_sessions (
    id                    uuid primary key,
    tenant_id             uuid not null references tenants(id),
    membership_id         uuid not null,
    user_id               uuid not null,              -- ALWAYS the membership's user
    session_token_sha256  text not null unique,
    idp_config_id         uuid not null,              -- config + generation this login used
    acr                   text,                       -- verbatim from the ID token, if present
    amr                   text[],                     -- verbatim from the ID token, if present
    auth_time             timestamptz,                -- from the ID token, if present
    idp_sid               text,                       -- informational; unused in v1
    created_at            timestamptz not null default now(),
    last_seen_at          timestamptz,
    idle_expires_at       timestamptz not null,       -- sliding, capped by absolute
    absolute_expires_at   timestamptz not null,       -- hard cap
    revoked_at            timestamptz,
    unique (tenant_id, id),
    foreign key (tenant_id, membership_id, user_id)
        references org_memberships (tenant_id, id, user_id) on delete cascade,
    foreign key (tenant_id, idp_config_id)
        references org_idp_configs (tenant_id, id)
);
create index user_sessions_membership on user_sessions (tenant_id, membership_id);

-- ─── pending_login_switches (one-time session-replacement confirmations) ────
-- An org switch is deliberately a cross-tenant transition, and the schema says
-- so: the row carries BOTH tenants and the replaced session is composite-FK'd
-- in its own tenant. Resolving the confirmation cookie is the second (and
-- last) credential-like bootstrap exception to single-tenant scoping.
create table pending_login_switches (
    id                  uuid primary key,
    tenant_id           uuid not null references tenants(id),   -- the NEW login's org
    idp_config_id       uuid not null,           -- config + generation of the NEW login
    new_membership_id   uuid not null,           -- the verified identity awaiting confirm
    new_user_id         uuid not null,
    replaced_tenant_id  uuid not null references tenants(id),   -- the CURRENT session's org
    replaced_session_id uuid not null,           -- (may differ from tenant_id: org switch)
    redirect_to         text not null,           -- copied from the claimed login flow
    browser_hash        text not null,           -- sha256 of a fresh confirmation-cookie nonce
    acr                 text,
    amr                 text[],
    auth_time           timestamptz,             -- carried from the verified ID token
    consumed_at         timestamptz,
    expires_at          timestamptz not null,    -- creation + 120s
    created_at          timestamptz not null default now(),
    unique (tenant_id, id),
    foreign key (tenant_id, new_membership_id, new_user_id)
        references org_memberships (tenant_id, id, user_id) on delete cascade,
    foreign key (tenant_id, idp_config_id)
        references org_idp_configs (tenant_id, id) on delete cascade,
    foreign key (replaced_tenant_id, replaced_session_id)
        references user_sessions (tenant_id, id) on delete cascade
);
create index pending_login_switches_expiry on pending_login_switches (expires_at);

-- ─── auth_audit_log ─────────────────────────────────────────────────────────
-- Append-only "enforced, not asserted" (design §"auth_audit_log"): the runtime
-- role is granted INSERT/SELECT only. Single-role deployments (Neon owner)
-- cannot express that — the owner keeps UPDATE/DELETE by ownership regardless
-- of the REVOKE — so a BEFORE UPDATE OR DELETE trigger ALSO refuses at the
-- statement level. This is the one table without unique (tenant_id, id):
-- tenant_id is nullable (deployment-level operator actions carry none) and
-- nothing references this log.
create table auth_audit_log (
    id          uuid primary key,
    tenant_id   uuid,                    -- nullable: deployment-level operator actions
    actor_kind  text not null,           -- operator | user | system
    actor_id    text,
    source_ip   text,
    request_id  text,
    action      text not null,
    target      text,
    success     boolean not null,
    detail      jsonb,                   -- before/after digests; secrets redacted
    created_at  timestamptz not null default now()
);
create index auth_audit_log_tenant on auth_audit_log (tenant_id, created_at desc);

revoke update, delete on auth_audit_log from public;

create or replace function auth_audit_log_reject_mutation() returns trigger
    language plpgsql as $$
begin
    raise exception 'auth_audit_log is append-only';
end;
$$;

create trigger auth_audit_log_append_only
    before update or delete on auth_audit_log
    for each row execute function auth_audit_log_reject_mutation();

-- ─── sessions / trigger_subscriptions composite-unique targets ──────────────
-- Neither table had a (tenant_id, id) key; api_tokens' new composite FKs need
-- one. A composite unique that includes the PK column is permitted.
alter table sessions
    add constraint sessions_tenant_id_id_key unique (tenant_id, id);
alter table trigger_subscriptions
    add constraint trigger_subscriptions_tenant_id_id_key unique (tenant_id, id);

-- Parent Phase B "tenant/user audit fields": who invoked a run. Nullable, no
-- FK (historical sessions may outlive users); stamped by run_service (Task 3).
alter table sessions
    add column invoked_by_kind text,
    add column invoked_by_user_id uuid;

-- ─── api_tokens (extended for PATs) ─────────────────────────────────────────
alter table api_tokens
    add column membership_id uuid,
    add column user_id uuid,
    add column name text,
    add column display_prefix text,      -- first 12 chars of plaintext, for listing UI
    add column last_used_at timestamptz;

-- kind gains 'pat'; authority columns are mutually exclusive per kind, and a
-- PAT's finite lifetime is relational (expires_at non-null for every PAT).
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

-- The pre-existing session/subscription authority columns gain composite
-- tenant FKs too (a NULL member of a MATCH SIMPLE FK is trivially satisfied,
-- so session tokens skip the subscription FK and vice-versa).
alter table api_tokens add constraint api_tokens_session_tenant
    foreign key (tenant_id, session_id) references sessions (tenant_id, id);
alter table api_tokens add constraint api_tokens_subscription_tenant
    foreign key (tenant_id, subscription_id)
    references trigger_subscriptions (tenant_id, id);
