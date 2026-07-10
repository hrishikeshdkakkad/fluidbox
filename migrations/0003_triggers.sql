-- Phase 2 of "borrow the agent, on demand": generic API borrowing.
-- (docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md §3.5/§6.1/§9/§10)

-- A subscription is the standing instruction that says when an agent may be
-- borrowed. It may only narrow the agent/policy authority — never widen it.
-- §17 #6 (settled 2026-07-10): caller task/workspace overrides are opt-in
-- per subscription and default OFF.
create table trigger_subscriptions (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    agent_id uuid not null references agents(id),
    name text not null,
    trigger_kind text not null default 'api',   -- api (schedule/event later)
    pinned_revision_id uuid references agent_revisions(id), -- null = latest
    enabled boolean not null default true,
    task_template text,                          -- {{key}} ← invoke context
    allow_task_override boolean not null default false,
    allow_workspace_override boolean not null default false,
    autonomy text,                               -- null = supervised
    budget_override jsonb,                       -- tightens; never widens
    workspace_override jsonb,                    -- WorkspaceSpec
    result_destinations jsonb not null default '[]',
    -- AEAD-sealed HMAC secret for signed_webhook destinations (seal.rs).
    -- Never selected by row queries; never returned after creation.
    callback_secret_sealed bytea,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, name)
);
create index trigger_subscriptions_tenant on trigger_subscriptions(tenant_id);

-- One row per invoke (a generated key when the caller omits Idempotency-Key).
-- unique(subscription_id, idempotency_key) is what makes retries create
-- exactly one run.
create table trigger_invocations (
    id uuid primary key,
    subscription_id uuid not null references trigger_subscriptions(id) on delete cascade,
    idempotency_key text not null,
    request_digest text not null,
    session_id uuid references sessions(id) on delete cascade,
    created_at timestamptz not null default now(),
    unique (subscription_id, idempotency_key)
);
create index trigger_invocations_session on trigger_invocations(session_id);

-- Result publication state — independent of the session lifecycle by
-- construction (design §9): a completed run stays completed even when its
-- callback fails forever.
create table result_deliveries (
    id uuid primary key,
    session_id uuid not null references sessions(id) on delete cascade,
    subscription_id uuid references trigger_subscriptions(id) on delete cascade,
    destination jsonb not null,                  -- ResultDestination
    status text not null default 'pending',      -- pending|delivered|failed
    attempts int not null default 0,
    next_attempt_at timestamptz not null default now(),
    last_error text,
    payload_digest text,
    delivered_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index result_deliveries_due on result_deliveries(next_attempt_at) where status = 'pending';
create index result_deliveries_session on result_deliveries(session_id);
create index result_deliveries_subscription on result_deliveries(subscription_id);

-- Scoped trigger tokens ride the existing api_tokens table (kind='trigger').
alter table api_tokens add column subscription_id uuid references trigger_subscriptions(id) on delete cascade;
create index api_tokens_subscription on api_tokens(subscription_id);
