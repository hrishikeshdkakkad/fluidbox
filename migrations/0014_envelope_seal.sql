-- Phase D (#32) — versioned envelope sealing with per-tenant DEKs.
-- Design: docs/plans/2026-07-14-multi-user-mcp-control-plane-design.md (v4),
--   Gap 5 :1179-1200 (one deployment credential key → KMS envelope, per-tenant
--   DEKs, key versioning, resumable re-seal, retirement gate);
--   security invariant 20 :1367-1405.
-- Plan: .superpowers/sdd/phase-d-plan.md (D1-D4).
--
-- D1: blob-format discrimination is a per-column companion `<base>_key_version`
-- smallint (1 = legacy `nonce||ct`, 2 = envelope `[0x02][dek_version][nonce][ct]`),
-- NOT an in-band magic byte (legacy blobs begin with 24 random nonce bytes, so
-- any prefix scheme is only probabilistic). A deterministic companion column makes
-- count-parity one indexed predicate.
-- D2: per-tenant DEKs live in `tenant_deks`, wrapped by a KEK backend
-- (static KEK or AWS KMS). The DEK is minted lazily on a tenant's first v2 seal.
--
-- NOTE: migrations run BEFORE the boot seed (main.rs runs `connect()` — which
-- applies migrations — then `seed::run`). This file must NOT assume the
-- `default` tenant exists yet. The companion columns default to 1, so every
-- pre-existing sealed row is correctly marked legacy without a backfill.

-- ─── (a) per-tenant data-encryption keys ────────────────────────────────────
-- One wrapped DEK per (tenant, version). `wrapped_dek` is the DEK sealed by the
-- KEK backend (never the raw DEK); `kek_id` records which KEK wrapped it so a
-- future rotation can tell generations apart. v1 code only ever writes version 1
-- (rotation is a documented runbook concern, not code here). `retired_at` marks a
-- superseded version once a future rotation lands.
create table tenant_deks (
    tenant_id   uuid        not null references tenants(id),
    version     int         not null,
    kek_id      text        not null,
    wrapped_dek bytea       not null,
    created_at  timestamptz not null default now(),
    retired_at  timestamptz,
    primary key (tenant_id, version)
);

-- ─── (b) companion key-version columns for every sealed bytea column ─────────
-- `<base>_key_version` where the sealed column is `<base>_sealed`; 1 = legacy
-- (default, so existing rows need no backfill), 2 = envelope. The check keeps the
-- domain closed so an unknown version can never slip in.

alter table integration_connections
    add column credential_key_version     smallint not null default 1
        check (credential_key_version in (1, 2)),
    add column webhook_secret_key_version smallint not null default 1
        check (webhook_secret_key_version in (1, 2)),
    add column client_secret_key_version  smallint not null default 1
        check (client_secret_key_version in (1, 2));

alter table trigger_subscriptions
    add column callback_secret_key_version smallint not null default 1
        check (callback_secret_key_version in (1, 2));

alter table github_app_registrations
    add column pem_key_version            smallint not null default 1
        check (pem_key_version in (1, 2)),
    add column webhook_secret_key_version smallint not null default 1
        check (webhook_secret_key_version in (1, 2)),
    add column client_secret_key_version  smallint not null default 1
        check (client_secret_key_version in (1, 2));

alter table org_idp_configs
    add column client_secret_key_version  smallint not null default 1
        check (client_secret_key_version in (1, 2));

alter table login_flows
    add column pkce_verifier_key_version  smallint not null default 1
        check (pkce_verifier_key_version in (1, 2));

-- ─── (c) parity/paging indexes on the three unbounded families ──────────────
-- integration_connections is the only unbounded sealed family (≥1 per user per
-- connected service). Partial indexes on the still-legacy rows make the re-seal
-- job's paging (`WHERE <col> is not null AND <col>_key_version = 1 ORDER BY id`)
-- and the retirement parity count cheap. The bounded families (github_app_registrations,
-- org_idp_configs, trigger_subscriptions, login_flows) are small enough to scan.
create index integration_connections_credential_legacy_idx
    on integration_connections (id)
    where credential_key_version = 1 and credential_sealed is not null;

create index integration_connections_webhook_secret_legacy_idx
    on integration_connections (id)
    where webhook_secret_key_version = 1 and webhook_secret_sealed is not null;

create index integration_connections_client_secret_legacy_idx
    on integration_connections (id)
    where client_secret_key_version = 1 and client_secret_sealed is not null;
