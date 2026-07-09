-- fluidbox initial schema. Multi-tenant-ready (tenant_id everywhere),
-- single-tenant in the MVP.

create table tenants (
    id uuid primary key,
    name text not null unique,
    created_at timestamptz not null default now()
);

create table policies (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    name text not null,
    version int not null default 1,
    yaml_source text not null,
    parsed jsonb not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, name)
);

-- Agent identity; the recipe lives in immutable revisions.
create table agents (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    name text not null,
    description text,
    created_at timestamptz not null default now(),
    unique (tenant_id, name)
);

create table agent_revisions (
    id uuid primary key,
    agent_id uuid not null references agents(id) on delete cascade,
    rev int not null,
    harness text not null,
    runner_image text not null,
    model text not null,
    system_prompt text,
    policy_id uuid not null references policies(id),
    budgets jsonb not null,
    capability_bundles jsonb not null default '[]',
    created_at timestamptz not null default now(),
    unique (agent_id, rev)
);

create table sessions (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    agent_id uuid not null references agents(id),
    agent_revision_id uuid not null references agent_revisions(id),
    status text not null default 'created',
    status_reason text,
    autonomy text not null default 'supervised',
    trust_tier text not null default 'trusted',
    task text not null,
    repo_source jsonb not null,
    -- The frozen RunSpec: the immutable photograph governing this run.
    run_spec jsonb not null,
    trigger jsonb,
    sandbox_handle jsonb,
    budgets jsonb not null,
    base_commit text,
    result_summary text,
    event_seq bigint not null default 0,
    last_heartbeat_at timestamptz,
    started_at timestamptz,
    finished_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index sessions_status on sessions(status);
create index sessions_created on sessions(created_at desc);

-- Append-only ledger. seq is assigned by append_event(); the unique
-- constraint makes per-session ordering gapless and race-free.
create table events (
    event_id uuid primary key,
    session_id uuid not null references sessions(id) on delete cascade,
    seq bigint not null,
    schema_version int not null default 1,
    actor text not null,
    type text not null,
    payload jsonb not null,
    occurred_at timestamptz not null,
    recorded_at timestamptz not null default now(),
    unique (session_id, seq)
);
create index events_session_seq on events(session_id, seq);

create or replace function append_event(
    p_session uuid,
    p_event uuid,
    p_actor text,
    p_type text,
    p_payload jsonb,
    p_occurred timestamptz
) returns bigint language plpgsql as $$
declare
    v_seq bigint;
begin
    -- Row-lock the session to serialize seq assignment.
    update sessions
       set event_seq = event_seq + 1, updated_at = now()
     where id = p_session
     returning event_seq into v_seq;
    if v_seq is null then
        raise exception 'session % not found', p_session;
    end if;
    insert into events(event_id, session_id, seq, actor, type, payload, occurred_at)
    values (p_event, p_session, v_seq, p_actor, p_type, p_payload, p_occurred);
    -- NOTIFY is only a wakeup; the seq catch-up query is the source of truth.
    perform pg_notify('fluidbox_events', p_session::text || ':' || v_seq::text);
    return v_seq;
end $$;

create table approvals (
    id uuid primary key,
    session_id uuid not null references sessions(id) on delete cascade,
    tool_call_id text not null,
    tool text not null,
    summary text not null,
    input_digest text,
    risk text,
    scope text not null default 'once',
    scope_key text not null,
    status text not null default 'pending', -- pending|approved_once|approved_session|denied|expired
    requested_at timestamptz not null default now(),
    expires_at timestamptz not null,
    decided_at timestamptz,
    decided_by text,
    unique (session_id, tool_call_id)
);
create index approvals_pending on approvals(status) where status = 'pending';
create index approvals_scope on approvals(session_id, scope_key, status);

create table artifacts (
    id uuid primary key,
    session_id uuid not null references sessions(id) on delete cascade,
    kind text not null, -- diff|summary|log
    name text not null,
    content text not null,
    content_type text not null default 'text/plain',
    created_at timestamptz not null default now()
);

create table usage_entries (
    id uuid primary key,
    session_id uuid not null references sessions(id) on delete cascade,
    model text not null,
    input_tokens bigint not null default 0,
    output_tokens bigint not null default 0,
    cache_read_tokens bigint not null default 0,
    cache_write_tokens bigint not null default 0,
    cost_usd double precision,
    source text not null default 'facade', -- facade|litellm_callback
    external_id text,
    created_at timestamptz not null default now()
);
create unique index usage_external on usage_entries(external_id) where external_id is not null;
create index usage_session on usage_entries(session_id);

create table api_tokens (
    id uuid primary key,
    tenant_id uuid not null references tenants(id),
    kind text not null, -- admin|session
    session_id uuid references sessions(id) on delete cascade,
    token_sha256 text not null unique,
    expires_at timestamptz,
    created_at timestamptz not null default now(),
    revoked_at timestamptz
);
create index api_tokens_session on api_tokens(session_id);

create table settings (
    tenant_id uuid not null references tenants(id),
    key text not null,
    value jsonb not null,
    updated_at timestamptz not null default now(),
    primary key (tenant_id, key)
);
