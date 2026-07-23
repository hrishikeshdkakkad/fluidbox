-- Phase E (#33) — audience-scoped sandbox credentials (Gap 10, invariant 19;
-- design :1313-1330; plan .superpowers/sdd/phase-e-plan.md E11). Column-add ONLY.
--
-- WHY
-- Until now the SINGLE `fbx_sess_…` bearer opened every internal route: the LLM
-- facade, the tool-intent gate (/permission, /tools/call), the runner-control
-- endpoints (/events, /heartbeat, /result, /token/renew), and the workspace
-- archive fetch. That bearer lives in the sandbox's `process.env`, so any agent
-- shell could `echo` it and post /result, forge /events, or drain the budget.
-- Gap 10 splits it into FOUR audience-scoped `api_tokens` rows — one per
-- audience — and the route extractors (auth.rs) enforce which audience each
-- route accepts. `kind` STAYS 'session' (the 0012 kind-shape CHECK is unchanged);
-- the audience is a NEW discriminator ON the session-kind row.
--
-- NO RLS CHANGE. api_tokens' 0018 `tenant_isolation` policy keys on `tenant_id`
-- and is COLUMN-AGNOSTIC (survey B §7) — a new column needs no new policy and no
-- new grant, and the session-token resolvers already run under the `worker_tx`
-- audited bypass (the credential-digest bootstrap exception). This migration is
-- therefore a plain column-add on an existing table.
--
-- DEFAULT 'all' IS PERMANENT — a feature, not a migration artifact. Two callers
-- rely on it forever: (1) an in-flight session that spans the deploy already
-- minted its single legacy token BEFORE the split, and its running sandbox holds
-- only that one token — it must keep authenticating on every route; (2) the e2e
-- psql token forgers (secrets-e2e.sh, bindings-e2e.sh) INSERT without an audience
-- and must resolve to a universally-accepted token. auth.rs treats 'all' as
-- satisfying every route (audience_allows), so both keep working unchanged.
--
-- LOCK DISCIPLINE (review, minor). `api_tokens` is the table EVERY internal
-- request, PAT and session cookie resolves against, and both statements below take
-- ACCESS EXCLUSIVE on it. Two rules keep that from becoming an auth outage:
--
--   (1) `lock_timeout` — matching 0018/0019/0021/0022. Without it, a long-running
--       reader makes the ALTER queue, and an ACCESS EXCLUSIVE request in the lock
--       queue blocks every LATER reader behind it: one slow query would stall all
--       authentication for as long as it ran. With it the migration FAILS FAST
--       (and is simply re-run) instead.
--
--   (2) `NOT VALID` on the CHECK. A validating ADD CONSTRAINT scans the whole
--       table WHILE HOLDING that ACCESS EXCLUSIVE lock, so the outage window grows
--       with the table. `NOT VALID` is a catalog-only change — O(1) under the lock
--       — and Postgres still enforces the constraint on every subsequent INSERT
--       and UPDATE; only pre-existing rows go unverified. Here there is nothing to
--       verify: the ADD COLUMN wrote 'all' into every existing row earlier in this
--       same transaction (its ACCESS EXCLUSIVE lock means nothing else could have
--       written another value in between), and 'all' satisfies the check by
--       construction. A later `ALTER TABLE api_tokens VALIDATE CONSTRAINT
--       api_tokens_audience_check` can flip `convalidated` out-of-band whenever
--       cosmetics demand — it takes only SHARE UPDATE EXCLUSIVE and blocks nobody.
set local lock_timeout = '5s';

alter table api_tokens
  add column audience text not null default 'all';

alter table api_tokens
  add constraint api_tokens_audience_check
  check (audience in ('all', 'llm', 'tool', 'control', 'workspace'))
  not valid;
