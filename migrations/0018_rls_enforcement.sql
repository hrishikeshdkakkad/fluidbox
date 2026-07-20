-- Phase D (#32, #75) — Postgres Row-Level Security: tenant isolation enforced by
-- the database, not just by a Rust `where tenant_id = $n` convention.
-- Design: docs/plans/2026-07-14-multi-user-mcp-control-plane-design.md (v4),
--   Gap 4 :1164-1177 (RLS defense-in-depth), security invariant 22.
-- Plan: .superpowers/sdd/phase-d-plan.md decision D8; survey .superpowers/sdd/phase-d-survey-d.md §2.
--
-- WHAT THIS DOES
-- 1. Enables + FORCEs RLS on every tenant-owned table (37 of them) and attaches a
--    policy. Standard tables key on `current_setting('fluidbox.tenant_id')`; child
--    tables (no tenant_id column) compose their parent's policy via `EXISTS(parent)`;
--    four special tables get bespoke shapes. FORCE makes the policy bind even the
--    table OWNER (a plain owner otherwise bypasses RLS — the reason Phase B deferred
--    this). A superuser STILL bypasses RLS entirely — the RLS negative tests connect
--    as the non-superuser `fluidbox_runtime` role precisely so the policy actually runs.
-- 2. The GUC contract (plumbed in fluidbox-db `scoped_tx`/`worker_tx`, transaction-local
--    so a pooled connection never leaks context):
--      - `fluidbox.tenant_id` = the scope's tenant  → tenant rows visible/writable;
--      - `fluidbox.bypass = 'system_worker'`         → the audited cross-tenant bypass
--        (the category rides IN the GUC value — one grep-able choke point, plan D8);
--      - neither set                                 → zero rows on a policy'd table.
-- 3. Creates a NOLOGIN least-privilege `fluidbox_runtime` role (opt-in via
--    FLUIDBOX_RUNTIME_ROLE + `after_connect SET ROLE`) with table DML MINUS
--    auth_audit_log UPDATE/DELETE (the 0012:208-210 deferred grant lands here). On a
--    managed host that restricts CREATE ROLE the DO-block WARNS instead of failing;
--    RLS still binds the owner via the GUC, so single-role deployments are fully
--    enforced without the role.
--
-- DEPLOY ORDER — STOP THE OLD BINARY, MIGRATE, THEN DEPLOY. This is NOT a
-- migrate-then-deploy: an old binary against a 0018 database sets no GUC and so
-- reads zero rows from every table, AND it holds transactions open across outbound
-- HTTP (the OAuth token exchange and the DCR /register both span a tx touching
-- tables locked below). A slow authorization server would therefore park this
-- migration behind an ACCESS EXCLUSIVE lock request that in turn blocks ALL
-- traffic. `lock_timeout` below bounds that to a fast, retryable failure instead of
-- a stall — but the ordering above is what avoids it.
--
-- 37×(ENABLE + FORCE) + the CREATE POLICYs run in sqlx's single migration
-- transaction and each takes ACCESS EXCLUSIVE on its table. They are catalog-only
-- (no table rewrite), so with no competing traffic this is milliseconds.
--
-- NOTE: migrations run BEFORE the boot seed and on the migration OWNER connection
-- (fluidbox-db `connect()` splits owner-migrate from the app pool). This file assumes
-- no `default` tenant exists yet and creates no data.

-- Bound the worst case above: fail fast and retryably rather than queue behind a
-- long-running transaction (and take the whole database's traffic with it).
-- Transaction-local — sqlx runs each migration inside one transaction.
set local lock_timeout = '3s';

-- ─── (a) least-privilege runtime role + grants (plan D8) ─────────────────────
-- Created NOLOGIN + granted here so `SET ROLE fluidbox_runtime` works for the
-- app pool's after_connect hook AND the RLS negative tests. The runtime role is
-- a NON-owner, so FORCE is not even needed for it — but FORCE is set anyway so a
-- single-role (owner) deployment is equally bound. Guarded so a restricted host
-- (Neon: role creation is a managed op) warns rather than aborting the migration.
do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'fluidbox_runtime') then
        begin
            create role fluidbox_runtime nologin;
        exception
            when insufficient_privilege then
                raise warning 'migration 0018: cannot CREATE ROLE fluidbox_runtime (insufficient privilege). On a managed host create it out-of-band (CREATE ROLE fluidbox_runtime NOLOGIN; GRANT fluidbox_runtime TO CURRENT_USER; plus the grants below), then restart. RLS still binds the owner via the tenant GUC, so single-role enforcement is unaffected.';
        end;
    end if;
    if exists (select 1 from pg_roles where rolname = 'fluidbox_runtime') then
        grant usage on schema public to fluidbox_runtime;
        -- Every application table: full DML. RLS (below) is the tenant floor; the
        -- table grant is the coarse floor beneath it.
        grant select, insert, update, delete on all tables in schema public to fluidbox_runtime;
        -- 0012:208-210 deferred grant: the process the API runs as literally cannot
        -- MUTATE the append-only auth log — INSERT/SELECT only. The owner keeps these
        -- by ownership (the triggers backstop that); this closes it for the runtime role.
        revoke update, delete, truncate on auth_audit_log from fluidbox_runtime;
        -- The runtime role has no business in sqlx's own migration ledger.
        revoke all on table _sqlx_migrations from fluidbox_runtime;
        grant usage, select on all sequences in schema public to fluidbox_runtime;
        -- append_event() + others run as the caller (SECURITY INVOKER); grant EXECUTE.
        grant execute on all functions in schema public to fluidbox_runtime;
        -- So the migration owner (current_user) can SET ROLE fluidbox_runtime — the
        -- app-pool after_connect hook and the RLS negative tests both rely on it.
        execute format('grant fluidbox_runtime to %I', current_user);
    end if;
end $$;

-- ─── (b) standard tenant tables ─────────────────────────────────────────────
-- tenant_id column keyed directly on the GUC (+ the system_worker bypass arm).
-- One identical policy per table; USING and WITH CHECK are the same predicate so a
-- row is invisible to read AND refused on insert/update unless it is in-tenant (or
-- the bypass is set). A DO-block keeps the 20 predicates a single source of truth.
do $$
declare t text;
begin
    foreach t in array array[
        'policies', 'agents', 'sessions', 'api_tokens', 'settings',
        'integration_connections', 'trigger_subscriptions', 'capability_bundles',
        'github_app_registrations', 'org_idp_configs', 'users', 'org_memberships',
        'login_flows', 'user_sessions', 'pending_login_switches',
        'connection_tool_snapshots', 'run_resource_bindings',
        'tenant_deks', 'connector_oauth_flows', 'tenant_llm_keys'
    ]
    loop
        execute format('alter table %I enable row level security', t);
        execute format('alter table %I force row level security', t);
        execute format(
            'create policy tenant_isolation on %I as permissive for all to public '
            'using (tenant_id::text = current_setting(''fluidbox.tenant_id'', true) '
            '       or current_setting(''fluidbox.bypass'', true) = ''system_worker'') '
            'with check (tenant_id::text = current_setting(''fluidbox.tenant_id'', true) '
            '       or current_setting(''fluidbox.bypass'', true) = ''system_worker'')',
            t);
    end loop;
end $$;

-- ─── (c) child tables (no tenant_id: tenancy is the parent FK) ───────────────
-- The policy is `EXISTS(parent)`: the parent's own policy composes through the
-- subquery (the subquery runs under RLS too), so a child row is visible/writable
-- iff its parent is. Under the bypass GUC the parent policy opens, so the child
-- opens with it. (child, parent, fk) pairs are verified against the DDL (survey-d §2).
do $$
declare r record;
begin
    for r in select * from (values
        ('agent_revisions',      'agents',                   'agent_id'),
        ('events',               'sessions',                 'session_id'),
        ('approvals',            'sessions',                 'session_id'),
        ('artifacts',            'sessions',                 'session_id'),
        ('usage_entries',        'sessions',                 'session_id'),
        ('trigger_invocations',  'trigger_subscriptions',    'subscription_id'),
        ('result_deliveries',    'sessions',                 'session_id'),
        ('trigger_deliveries',   'integration_connections',  'connection_id'),
        ('trigger_dispatches',   'trigger_subscriptions',    'subscription_id'),
        ('external_results',     'trigger_subscriptions',    'subscription_id'),
        ('schedules',            'trigger_subscriptions',    'subscription_id'),
        ('github_app_flows',     'github_app_registrations', 'registration_id'),
        ('session_finalizations','sessions',                 'session_id')
    ) as x(child, parent, fk)
    loop
        execute format('alter table %I enable row level security', r.child);
        execute format('alter table %I force row level security', r.child);
        execute format(
            'create policy tenant_isolation on %I as permissive for all to public '
            'using (exists (select 1 from %I p where p.id = %I.%I)) '
            'with check (exists (select 1 from %I p where p.id = %I.%I))',
            r.child, r.parent, r.child, r.fk,
            r.parent, r.child, r.fk);
    end loop;
end $$;

-- ─── (d) special-shape tables ───────────────────────────────────────────────

-- tenants: the registry itself — keyed on its OWN id (not tenant_id). A scoped tx
-- sees only its own tenant row; the boot seed's `ensure_default_tenant` writes it
-- under the bypass (it may read/update a pre-existing default of unknown id).
alter table tenants enable row level security;
alter table tenants force row level security;
create policy tenant_isolation on tenants as permissive for all to public
    using (id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker')
    with check (id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');

-- The two MIXED tables — `connector_catalog` and `oauth_client_registrations` —
-- hold cross-tenant SHARED state: rows with `tenant_id NULL` are deployment-global
-- (curated catalog entries; the deployment-wide OAuth client_id + its sealed
-- client_secret) and every tenant reads them. READ and WRITE are therefore split
-- deliberately, and this is the ONLY place in the file where they differ:
--
--   FOR SELECT  → tenant-or-GLOBAL-or-bypass. Global rows are shared reference
--                 data; a scoped read must see them (this is also why catalog
--                 reads work pre-scope).
--   FOR INSERT/UPDATE/DELETE → tenant-or-bypass, NEVER "or tenant_id is null".
--                 A tenant-scoped transaction must not be able to create a global
--                 row, nor mutate/delete one another tenant depends on. Writing a
--                 global row is principal-less deployment work, so it takes the one
--                 audited escape hatch (`fluidbox.bypass = 'system_worker'`, via
--                 `fluidbox-db::system_worker`) like every other cross-tenant write.
-- A single `for all` policy cannot express this: its USING clause is what filters
-- UPDATE/DELETE, so a read-permissive USING would also make global rows mutable.
--
-- Who writes what, so the split stays checkable:
--   connector_catalog          — `create_catalog_entry`/`delete_catalog_entry` are
--                                scoped_tx + explicitly tenant-bound; global rows
--                                are written ONLY by migrations (pre-RLS DDL).
--   oauth_client_registrations — v1 rows are ALWAYS global, and the DCR/CIMD
--                                resolution is principal-less, so all four writers
--                                go through `system_worker::*_global_registration`.
--
-- CONSEQUENCE FOR FUTURE MIGRATIONS: a migration that seeds GLOBAL rows into
-- either table (e.g. a generated `just catalog-import` file) runs as the table
-- OWNER with no GUC, and FORCE binds the owner — so it MUST open with
--   set local fluidbox.bypass = 'system_worker';
-- or every INSERT is refused. Migrations 0007/0013 predate this file and are
-- unaffected (RLS was not yet enabled when they ran).

alter table connector_catalog enable row level security;
alter table connector_catalog force row level security;
create policy catalog_read on connector_catalog as permissive for select to public
    using (tenant_id is null
           or tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');
create policy catalog_insert on connector_catalog as permissive for insert to public
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');
create policy catalog_update on connector_catalog as permissive for update to public
    using (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker')
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');
create policy catalog_delete on connector_catalog as permissive for delete to public
    using (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');

alter table oauth_client_registrations enable row level security;
alter table oauth_client_registrations force row level security;
create policy registration_read on oauth_client_registrations as permissive for select to public
    using (tenant_id is null
           or tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');
create policy registration_insert on oauth_client_registrations as permissive for insert to public
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');
create policy registration_update on oauth_client_registrations as permissive for update to public
    using (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker')
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');
create policy registration_delete on oauth_client_registrations as permissive for delete to public
    using (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');

-- auth_audit_log: append-only, tenant_id NULLABLE (operator actions carry none).
-- INSERT is ALWAYS allowed (the writer may be pool-direct with no GUC, e.g. a
-- rejected-attempt audit). SELECT is tenant-or-null-or-bypass.
--
-- This migration REORDERS the append-only defence, so 0012's framing ("the
-- triggers are the real guard — only a trigger can stop the owner") now describes
-- only one of three layers. Post-0018:
--   • RLS-BOUND role (the FORCEd owner, and fluidbox_runtime): no UPDATE/DELETE
--     policy exists at all, so those commands match no rows and are FILTERED to
--     zero — they return OK, the row is untouched, and the 0012 trigger is never
--     reached. This is the primary guard on the normal path.
--   • RLS-BYPASSING role (superuser / BYPASSRLS — Neon's neon_superuser, CI's
--     postgres): policies are skipped entirely and the 0012 trigger is what
--     refuses. It is now the BACKSTOP for exactly these roles.
--   • fluidbox_runtime: refused one layer earlier still, by the UPDATE/DELETE
--     revoke above (0012:208-210's deferred grant).
-- identity.rs::audit_log_is_append_only asserts whichever layer applies to the
-- connecting role, plus the grant layer unconditionally.
alter table auth_audit_log enable row level security;
alter table auth_audit_log force row level security;
create policy audit_insert on auth_audit_log as permissive for insert to public
    with check (true);
create policy audit_select on auth_audit_log as permissive for select to public
    using (current_setting('fluidbox.bypass', true) = 'system_worker'
           or tenant_id is null
           or tenant_id::text = current_setting('fluidbox.tenant_id', true));

-- EXEMPT: `_sqlx_migrations` (sqlx's own ledger, written only by the migration
-- owner, never by the runtime role — the role's grant on it is revoked above) gets
-- no RLS policy. No other table is exempt.
