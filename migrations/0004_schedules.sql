-- Phase 3 of "borrow the agent, on demand": scheduled borrowing
-- (design doc §6.2/§10/§12 Phase 3).
-- §17 #5 settled 2026-07-10: overlap default 'allow', missed-run default
-- 'skip'; concurrency_policy is enforced for ALL invocations inside
-- run_service::create_run (API invokes and schedule firings alike).

-- Deferred from Phase 2 so config never lies; now create_run enforces it.
-- allow | skip_if_running | replace.
alter table trigger_subscriptions
    add column concurrency_policy text not null default 'allow';

-- A skipped firing is recorded on the SAME claim table that makes firing
-- exactly-once: every scheduled fire time ends as exactly one row — bound
-- to a session, or marked skipped (overlap | missed | error: …). Skipped
-- rows are terminal: never re-claimable, never stealable.
alter table trigger_invocations add column skip_reason text;

-- The clock on a subscription (§6.2): a schedule is NOT a new kind of
-- object — subscription_id is unique, enabled-ness rides the subscription
-- (a disabled subscription's schedule does not advance; the gap becomes a
-- missed-run case on re-enable, same as a scheduler outage), and each
-- firing is an ordinary run through run_service::create_run.
create table schedules (
    id uuid primary key,
    subscription_id uuid not null unique references trigger_subscriptions(id) on delete cascade,
    cron text not null,
    timezone text not null,                 -- explicit IANA name; DST-correct
    next_fire_at timestamptz,               -- null = no future firing
    missed_run_policy text not null default 'skip',  -- skip | catch_up
    last_fired_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index schedules_due on schedules(next_fire_at) where next_fire_at is not null;
