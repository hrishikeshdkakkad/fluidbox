-- Phase D (#32) — one-time server-side OAuth state rows + browser binding (Task 4).
-- Design: docs/plans/2026-07-14-multi-user-mcp-control-plane-design.md (v4),
--   state binding :633-644, cross-user grant injection defense :646-656,
--   Phase D :1513-1517; security invariant 20 (:1396-1400).
-- Plan: .superpowers/sdd/phase-d-plan.md decision D5.
--
-- Replaces the stateless AEAD `state` param (oauth.rs `seal_state`/`open_state`,
-- DELETED this task) with a durable one-time row. The stateless value was
-- replayable within its 600s TTL and carried NO browser binding, so a victim's
-- browser could complete an attacker's flow (grant injection). This row makes the
-- callback authenticate the FULL initiating context and bind the initiating
-- browser: the per-flow cookie hash sits INSIDE the one-time claim predicate
-- (login_flows / github_app_flows precedent), so a leaked authorization URL
-- WITHOUT the initiating browser's cookie can neither complete NOR burn a flow.
--
-- The row also freezes the discovered issuer/endpoints/client/resource/redirect at
-- START time: the callback exchanges against the ROW's endpoints, never
-- re-discovering, which closes authorization-server mix-up attacks and
-- discovery-change races between start and callback (design :641-644).
--
-- Restart-survivable by construction (durable Postgres row, no in-memory flow
-- state) — a control-plane restart mid-dance changes nothing, exactly as the old
-- stateless value did, and the browser cookie survives in the browser.
--
-- NOTE: migrations run BEFORE the boot seed; this file assumes no tenant exists.

create table connector_oauth_flows (
    id                        uuid        primary key,
    tenant_id                 uuid        not null references tenants(id),
    connection_id             uuid        not null,
    -- The initiating fluidbox user (None for the operator/admin token — the cookie
    -- still binds the browser). Audit + future owner-confirmation UI.
    initiated_by_user_id      uuid,
    -- sha256(hex) of the opaque random `s` carried (sealed) in the boot token and
    -- echoed back by the AS as the `state` param. UNIQUE — this is the callback's
    -- pre-auth lookup key (the row IS the auth). Doubles as the design's nonce
    -- (one random per flow, stored hashed).
    state_hash                text        not null unique,
    -- sha256(hex) of the per-flow cookie value `c`. Bound at START; sits INSIDE the
    -- one-time claim predicate so only the initiating browser can complete.
    browser_hash              text        not null,
    -- Discovered authorization-server binding, frozen at start (mix-up / discovery-
    -- change defense). `metadata_digest` fingerprints the full discovered metadata.
    issuer                    text        not null,
    authorization_endpoint    text        not null,
    token_endpoint            text        not null,
    metadata_digest           text        not null,
    resource                  text        not null,
    redirect_uri              text        not null,
    -- The requested OAuth scopes, frozen with the flow so the go page rebuilds the
    -- authorize URL entirely FROM THE ROW (design D5) — mirrors what the pre-D
    -- dance sent (incl. `offline_access`). Not a security binding; a request param.
    scopes                    jsonb       not null default '[]',
    -- The PUBLIC PKCE S256 challenge (BASE64URL(SHA256(verifier))), sent on the
    -- authorize leg. Stored (design :640 "the S256 method/challenge") so the
    -- unauthenticated go page rebuilds the authorize URL without unsealing custody.
    challenge                 text        not null,
    challenge_method          text        not null default 'S256',
    -- The shared client identity this dance resolved (Task 3); NULL for a
    -- per-connection pre-registered identity (its secret stays on the connection).
    -- ON DELETE SET NULL: a registration the authorization server rejects with
    -- `invalid_client` is RETIRED (oauth.rs `retire_rejected_registration`) so the
    -- next dance re-resolves a fresh identity — and consumed flow rows are kept 7
    -- days for audit, so a plain reference would make that delete a guaranteed
    -- 23503. The flow's own frozen `client_id` (not this FK) is what the exchange
    -- used, so nulling the pointer loses nothing: the flow is already single-use.
    client_registration_id    uuid        references oauth_client_registrations(id)
                                              on delete set null,
    client_id                 text        not null,
    -- The PKCE verifier, sealed at rest (never plaintext) — the challenge alone
    -- cannot perform the token exchange (design :638-639). Envelope-native
    -- (family OauthFlowPkceVerifier); the companion discriminates legacy vs v2.
    pkce_verifier_sealed      bytea       not null,
    pkce_verifier_key_version smallint    not null default 1
        check (pkce_verifier_key_version in (1, 2)),
    -- The connection's authorization_generation at start. The callback refuses if
    -- it moved (a reconnect landed mid-authorization) — never seals a fresh grant
    -- onto a superseded binding (design :1535, generation acceptance).
    expected_generation       int         not null,
    created_at                timestamptz not null default now(),
    -- start + STATE_TTL_SECS (600s). Inside the claim/peek predicates; also the GC
    -- key. The boot token carries the same expiry so the go page double-checks it.
    expires_at                timestamptz not null,
    -- Single-use: set the moment the callback claims the row. NULL = unconsumed.
    consumed_at               timestamptz,
    -- The composite FK (Phase B convention) ties the flow to a connection IN THE
    -- SAME tenant; references the 0013 unique(tenant_id, id). NO ACTION (repo
    -- convention: children-first cleanup) — flows are ephemeral (600s TTL).
    foreign key (tenant_id, connection_id)
        references integration_connections (tenant_id, id)
);

-- GC-on-insert + the go-page liveness check both filter on expires_at.
create index connector_oauth_flows_expires on connector_oauth_flows (expires_at);
