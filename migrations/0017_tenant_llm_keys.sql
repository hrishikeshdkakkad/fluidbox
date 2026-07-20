-- Migration 0017: per-tenant LiteLLM virtual keys (Phase D, #32;
-- design "Per-tenant LLM quota" :1087-1098, plan D7).
--
-- One LiteLLM virtual key per tenant. In FLUIDBOX_LLM_KEY_MODE=tenant the facade
-- presents this key on every upstream model request, so the LiteLLM MASTER key is
-- confined to ONE job: minting/deleting these virtual keys (llm_keys.rs). The key
-- is a durable custody value, sealed at rest under the tenant's own DEK — family
-- `tenant_llm_keys.litellm_key_sealed`, versioned like every Phase D sealed column
-- (companion `litellm_key_key_version`: 1 = legacy, 2 = envelope). It is NEVER
-- returned in an API response; the plaintext exists only at mint time and in the
-- in-memory cache (AppState.tenant_llm_keys).
--
-- Keyed by tenant_id (one key per tenant): the mint's ON CONFLICT (tenant_id)
-- target, the facade/rotate lookup key, and the re-seal job's paging/lock key
-- (system_worker's reseal_* helpers page this family by tenant_id, not `id`).
-- RLS policies land in Task 6 (migration 0018), which covers this table.

create table tenant_llm_keys (
    tenant_id uuid primary key references tenants (id),
    litellm_key_sealed bytea not null,
    litellm_key_key_version smallint not null default 1 check (litellm_key_key_version in (1, 2)),
    key_alias text not null,
    -- Informational only: LiteLLM /key/delete takes the key value itself
    -- ({"keys": ["sk-..."]}), which the broker unseals at rotation time, so
    -- deletion never needs this. Populated from the mint response when present.
    litellm_token_id text,
    created_at timestamptz not null default now(),
    rotated_at timestamptz
);
