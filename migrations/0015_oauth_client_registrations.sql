-- Phase D (#32) — reusable OAuth client registrations (Task 3).
-- Design: docs/plans/2026-07-14-multi-user-mcp-control-plane-design.md (v4),
--   client identity vs grant :658-671 ("one client registration serves many
--   user grants; do not DCR per connection"); Phase D :1512.
-- Plan: .superpowers/sdd/phase-d-plan.md decision D6.
--
-- Today every OAuth connection re-resolves its own client identity: two
-- connections against the same authorization server each mint their own DCR
-- client_id and seal their own client_secret per-connection. This table dedups
-- Dynamic Client Registration (RFC 7591) identities into ONE row keyed on
-- (issuer, redirect_uri): the first connect registers, every later connect to
-- the same issuer reuses it. CIMD identities also get a row (no secret) so the
-- one-time state flows (Task 4) can FK the client identity. Operator-pasted
-- pre-registered identities stay per-connection custody — they get NO row.
--
-- v1 code only ever creates GLOBAL rows (tenant_id NULL): the redirect_uri is
-- deployment-wide, so one registration per (issuer, redirect_uri) serves the
-- whole deployment. The nullable tenant_id + the per-tenant partial unique are
-- forward-compat only (a future per-tenant client identity, mirroring
-- connector_catalog's global-vs-tenant split, migration 0013).
--
-- Sealed columns are envelope-native (Phase D Task 1): global rows seal under
-- the DEPLOYMENT tenant's DEK (seal.rs `Sealer::deployment_ctx`; a real tenants
-- row — tenant_deks has an FK, so the nil UUID cannot key them). With KMS off
-- they seal v1 exactly like every other family; the `_key_version` companion
-- discriminates and keeps the re-seal job's count parity (families
-- RegistrationClientSecret / RegistrationAccessToken).
--
-- NOTE: migrations run BEFORE the boot seed; this file assumes no tenant exists.

create table oauth_client_registrations (
    id                                    uuid        primary key,
    -- NULL = deployment-global (v1 always). A future per-tenant identity sets it.
    tenant_id                             uuid        references tenants(id),
    issuer                                text        not null,
    redirect_uri                          text        not null,
    source                                text        not null
        check (source in ('dcr', 'cimd', 'preregistered')),
    client_id                             text        not null,
    -- Confidential-client secret (rare with token_endpoint_auth_method 'none').
    -- Sealed; the companion follows Task 1's convention (not null default 1) so
    -- the re-seal lock/CAS reader always decodes a valid version and a no-secret
    -- row carries the same default `Sealed::split` yields for a None secret.
    client_secret_sealed                  bytea,
    client_secret_key_version             smallint    not null default 1
        check (client_secret_key_version in (1, 2)),
    -- Where this client was registered (RFC 7591), so an invalid_client self-heal
    -- can re-register without re-discovering the AS metadata.
    registration_endpoint                 text,
    -- RFC 7592 registration-access token (custody for a future management call).
    registration_access_token_sealed      bytea,
    registration_access_token_key_version smallint    not null default 1
        check (registration_access_token_key_version in (1, 2)),
    token_endpoint_auth_method            text,
    created_at                            timestamptz not null default now(),
    last_used_at                          timestamptz
);

-- One client identity per (issuer, redirect_uri): a partial unique per scope so
-- a global row and a same-key tenant row can coexist (connector_catalog pattern,
-- 0013). v1 uses only the global index.
create unique index oauth_client_registrations_global
    on oauth_client_registrations (issuer, redirect_uri)
    where tenant_id is null;
create unique index oauth_client_registrations_tenant
    on oauth_client_registrations (tenant_id, issuer, redirect_uri)
    where tenant_id is not null;
