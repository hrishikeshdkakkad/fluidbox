-- Durable finalization intent (K8s design 2026-07-15, Phase 0).
--
-- The terminal finalizer is "collect BEFORE terminal, on every path". That
-- means there is a window — enter finalizing → collect diff → terminal — that
-- must survive a control-plane restart, or a crash strands the session (the
-- lossy `tokio::spawn` in /result today). This table is the persisted intent:
-- the outcome/summary to apply once collection completes, plus claim metadata
-- so a restart-recoverable worker can resume an interrupted finalization.
--
-- `sessions.status` is unconstrained text, so `cancelling`/`finalizing` need
-- no enum migration (settled Q11). One row per session; first writer wins the
-- outcome (idempotent begin), and the finalizing→terminal transition is the
-- single-winner gate that actually enqueues delivery.

create table session_finalizations (
    session_id uuid primary key references sessions(id) on delete cascade,
    -- terminal state to land once collection completes.
    outcome text not null,            -- completed|failed|cancelled|budget_exceeded
    summary text,
    reason text,                      -- status_reason carried to the terminal transition
    -- cancel needs a runner quiesce (heartbeat-response) before collection;
    -- result/fail/budget collect immediately.
    needs_quiesce boolean not null default false,
    quiesce_deadline timestamptz,     -- past it: hard-stop + artifact_missing(quiesce_timeout)
    -- restart-recoverable claim: a driver takes the row (claimed_at), and a
    -- stale claim (driver crashed mid-finalize) is retaken by the worker.
    claimed_at timestamptz,
    attempts int not null default 0,
    created_at timestamptz not null default now()
);
create index session_finalizations_claim on session_finalizations(claimed_at);
