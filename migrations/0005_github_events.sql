-- Phase 4 of "borrow the agent, on demand": connected-service events
-- (design doc §6.3/§6.4/§7/§10/§12 Phase 4).
-- §17 #1–#3 settled 2026-07-10: results appear under the App identity only;
-- default subscribed events are pull_request.opened + reopened (synchronize
-- is an explicit opt-in — it fires on every push); later events UPDATE the
-- stable comment in place (the ledger keeps history).

-- A connection that can receive webhooks stores its verification secret
-- AEAD-sealed, like the credential. Deliberately a separate column: it is
-- read on every ingress request, while the credential is only unsealed for
-- fetch/publish. Never selected by row queries.
alter table integration_connections add column webhook_secret_sealed bytea;

-- Event subscriptions: which connection to listen on, which resources and
-- event types to match, and which provider-side publishers to use. NULL for
-- api/schedule subscriptions (store-but-ignore config would lie).
alter table trigger_subscriptions
    add column connection_id uuid references integration_connections(id),
    add column resource_selector jsonb,  -- {"repositories": ["owner/name", …]}; null/[] = all
    add column event_filter jsonb,       -- {"events": ["pull_request.opened", …]}
    add column event_publish jsonb;      -- ["pr_comment", "check"]
create index trigger_subscriptions_connection
    on trigger_subscriptions(connection_id) where connection_id is not null;

-- Idempotency level 1 (design §6.4): the same external delivery is stored
-- exactly once — webhook retries collapse onto this row and then re-walk
-- the dispatch table, which makes a retry HEAL a partial fan-out instead of
-- duplicating it.
create table trigger_deliveries (
    id uuid primary key,
    connection_id uuid not null references integration_connections(id) on delete cascade,
    external_event_id text not null,
    event_type text not null,
    payload jsonb not null,
    payload_digest text not null,
    occurred_at timestamptz,
    received_at timestamptz not null default now(),
    unique (connection_id, external_event_id)
);

-- Idempotency level 2: at most one run per (delivery, subscription). Same
-- claim-row discipline as trigger_invocations: every matched subscription
-- ends as exactly one row — bound to a session, or terminally
-- skipped/errored (skip_reason says why).
create table trigger_dispatches (
    id uuid primary key,
    delivery_id uuid not null references trigger_deliveries(id) on delete cascade,
    subscription_id uuid not null references trigger_subscriptions(id) on delete cascade,
    session_id uuid references sessions(id) on delete set null,
    status text not null default 'created',  -- created | skipped | error
    skip_reason text,
    created_at timestamptz not null default now(),
    unique (delivery_id, subscription_id)
);
create index trigger_dispatches_subscription on trigger_dispatches(subscription_id);

-- §17 #3: the stable external identity of a published result, per
-- (subscription, kind, resource). Later events UPDATE the same external
-- object instead of spamming new ones; full history stays in the ledger and
-- result_deliveries.
create table external_results (
    id uuid primary key,
    subscription_id uuid not null references trigger_subscriptions(id) on delete cascade,
    kind text not null,           -- 'github_pr_comment'
    resource_key text not null,   -- 'owner/name#42'
    external_id text not null,
    external_url text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (subscription_id, kind, resource_key)
);
