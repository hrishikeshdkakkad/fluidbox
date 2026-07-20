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
-- 3. Creates a NOLOGIN least-privilege runtime role (opt-in via
--    FLUIDBOX_RUNTIME_ROLE + `after_connect SET ROLE`) with ENUMERATED table DML
--    MINUS auth_audit_log UPDATE/DELETE (the 0012:208-210 deferred grant lands here).
--    On a managed host that restricts CREATE ROLE the DO-block WARNS instead of
--    failing; RLS still binds the owner via the GUC, so single-role deployments are
--    fully enforced without the role.
--
--    The role NAME is deployment-selectable: `fluidbox-db::connect()` publishes
--    FLUIDBOX_RUNTIME_ROLE as the session GUC `fluidbox.runtime_role` on the
--    migration connection, and this file reads it (default `fluidbox_runtime`).
--    That matters because PostgreSQL ROLES are CLUSTER-global while these GRANTs
--    are DATABASE-local: on a shared cluster a single hardcoded name is a name
--    COLLISION with someone else's principal, and granting it DML here would hand
--    that principal every tenant's rows (it could then `set role <name>;
--    set fluidbox.bypass = 'system_worker'`). So the role is also POSTURE-VALIDATED
--    below — attributes and memberships, not just existence — and boot re-validates
--    (`connect()`), because a role can be altered after the migration ran.
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

-- ─── (a) least-privilege runtime role: create + POSTURE VALIDATION ───────────
-- Created NOLOGIN so `SET ROLE <runtime>` works for the app pool's after_connect
-- hook AND the RLS negative tests. The runtime role is a NON-owner, so FORCE is
-- not even needed for it — but FORCE is set anyway so a single-role (owner)
-- deployment is equally bound. Guarded so a restricted host (Neon: role creation
-- is a managed op) WARNS rather than aborting the migration.
--
-- Existence is NOT trust. A role that already exists was created by someone else,
-- and PostgreSQL roles are cluster-global. Before granting it anything we REFUSE
-- (hard, not a warning) on:
--   • unsafe ATTRIBUTES — LOGIN (it is meant to be reachable only via SET ROLE
--     from our own connection, never a principal you can authenticate as),
--     SUPERUSER / BYPASSRLS (RLS would be skipped entirely — the pool split would
--     be theatre), CREATEROLE / CREATEDB / REPLICATION (escalation surface);
--   • INHERITED privileges — a least-privilege role must be a member of NOTHING,
--     or it silently carries whatever the granting role can do;
--   • unexpected MEMBERS — anyone other than this migration's `current_user` who
--     can `SET ROLE` into it. That is the shared-cluster attack in one predicate:
--     another database's owner holding the grant would inherit the DML we are
--     about to give, plus the `fluidbox.bypass` GUC, i.e. every tenant's rows.
--     Both membership checks read DIRECT `pg_auth_members` rows, not the
--     transitive closure (`pg_has_role`), on purpose: a transitive path runs
--     through a role that is already an admin over `current_user` — flagging that
--     would refuse every managed host whose owner sits under a platform admin
--     group (Neon's `neon_superuser`), without describing a new capability.
-- The fix for every refusal is the same and is named in the message: pick a
-- deployment-specific FLUIDBOX_RUNTIME_ROLE, or repair the role out-of-band.
do $$
declare
    v_role text := coalesce(nullif(current_setting('fluidbox.runtime_role', true), ''),
                            'fluidbox_runtime');
    v_bad text;
    v_inherits text;
    v_members text;
begin
    -- The name is interpolated into DDL below (an identifier can never be a bind
    -- parameter), and `connect()` validates the same shape before publishing it.
    if v_role !~ '^[a-z_][a-z0-9_]*$' or length(v_role) > 63 then
        raise exception 'migration 0018: runtime role name % is not a valid identifier (expected ^[a-z_][a-z0-9_]*$, <=63 chars)', quote_literal(v_role);
    end if;

    if not exists (select 1 from pg_roles where rolname = v_role) then
        begin
            execute format('create role %I nologin', v_role);
        exception
            when insufficient_privilege then
                raise warning 'migration 0018: cannot CREATE ROLE % (insufficient privilege). On a managed host create it out-of-band (CREATE ROLE % NOLOGIN; GRANT % TO CURRENT_USER; plus the grants in section (e) of this file), then restart. RLS still binds the owner via the tenant GUC, so single-role enforcement is unaffected.', v_role, v_role, v_role;
        end;
    end if;

    if not exists (select 1 from pg_roles where rolname = v_role) then
        return; -- managed host, warned above: no role, no grants, nothing to validate.
    end if;

    select string_agg(a, ', ') into v_bad from (
        select 'LOGIN'       as a from pg_roles where rolname = v_role and rolcanlogin
        union all select 'SUPERUSER'   from pg_roles where rolname = v_role and rolsuper
        union all select 'BYPASSRLS'   from pg_roles where rolname = v_role and rolbypassrls
        union all select 'CREATEROLE'  from pg_roles where rolname = v_role and rolcreaterole
        union all select 'CREATEDB'    from pg_roles where rolname = v_role and rolcreatedb
        union all select 'REPLICATION' from pg_roles where rolname = v_role and rolreplication
    ) x;
    if v_bad is not null then
        raise exception 'migration 0018: role % already exists with unsafe attribute(s): %. fluidbox refuses to grant table DML to it (LOGIN/SUPERUSER/BYPASSRLS would defeat the RLS split outright). Either ALTER ROLE % NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION, or set FLUIDBOX_RUNTIME_ROLE to a name this deployment owns and re-run.', v_role, v_bad, v_role;
    end if;

    select string_agg(distinct g.rolname, ', ') into v_inherits
      from pg_auth_members m
      join pg_roles g on g.oid = m.roleid
      join pg_roles r on r.oid = m.member
     where r.rolname = v_role;
    if v_inherits is not null then
        raise exception 'migration 0018: role % is a member of %, so it inherits privileges fluidbox did not grant. A least-privilege runtime role must be a member of nothing. REVOKE those memberships, or set FLUIDBOX_RUNTIME_ROLE to a name this deployment owns.', v_role, v_inherits;
    end if;

    select string_agg(distinct mm.rolname, ', ') into v_members
      from pg_auth_members m
      join pg_roles mm on mm.oid = m.member
      join pg_roles r on r.oid = m.roleid
     where r.rolname = v_role and mm.rolname <> current_user;
    if v_members is not null then
        raise exception 'migration 0018: role % is already granted to %, which can therefore SET ROLE into it and read every tenant of this database. PostgreSQL roles are cluster-global; this is the shared-cluster name collision. REVOKE % FROM those roles, or set FLUIDBOX_RUNTIME_ROLE to a deployment-specific name.', v_role, v_members, v_role;
    end if;

    -- So the migration owner (current_user) can SET ROLE — the app-pool
    -- after_connect hook and the RLS negative tests both rely on it. Idempotent.
    execute format('grant %I to %I', v_role, current_user);
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
--
-- INSERT carries the SAME tenant floor as every other tenant-owned write (review
-- M3). It used to be `with check (true)`, which made this the one write surface
-- where the database floor did not match the verified scope: a transaction scoped
-- to tenant A could insert a row stamped `tenant_id = B`, and because the log is
-- append-only the forged entry in the victim tenant's permanent security history
-- could never be corrected through the runtime role. The two legitimate shapes
-- that needed the permissive policy now carry an explicit GUC instead:
--   • deployment-level operator rows (`tenant_id IS NULL` — re-seal job, operator
--     actions whose tenant is unknown/none) run under the audited system-worker
--     bypass, like every other principal-less write;
--   • pre-auth / rejected-attempt audits, which used to run pool-direct with no
--     GUC at all, now open a SHORT scoped tx when the tenant is known and a worker
--     tx when it is not (`identity::insert_audit_standalone`).
-- Every in-transaction audit already rode its mutation's scoped/worker tx, so it
-- is unchanged. SELECT stays tenant-or-null-or-bypass (deployment-level rows carry
-- no tenant data; there is no such reader in production code).
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
    with check (tenant_id::text = current_setting('fluidbox.tenant_id', true)
           or current_setting('fluidbox.bypass', true) = 'system_worker');
create policy audit_select on auth_audit_log as permissive for select to public
    using (current_setting('fluidbox.bypass', true) = 'system_worker'
           or tenant_id is null
           or tenant_id::text = current_setting('fluidbox.tenant_id', true));

-- EXEMPT: `_sqlx_migrations` (sqlx's own ledger, written only by the migration
-- owner, never by the runtime role — it is simply absent from the grant list in
-- section (e)) gets no RLS policy. No other table is exempt.

-- ─── (e) ENUMERATED grants to the runtime role ──────────────────────────────
-- Deliberately NOT `GRANT ... ON ALL TABLES/SEQUENCES/FUNCTIONS IN SCHEMA public`
-- (review H1). `public` is a SHARED schema by default: an ALL-IN-SCHEMA grant
-- reaches whatever else happens to live there, and — because a bare `GRANT
-- EXECUTE` re-adds a privilege — can silently re-open functions whose PUBLIC
-- EXECUTE an operator deliberately revoked. So we name exactly the fluidbox
-- surface: the 37 tables this file put RLS on, and the ONE function the
-- application calls at runtime.
--
-- Runs AFTER the policies so the drift guard below can see them: every table
-- this migration attached a policy to must appear in the grant list, or the
-- migration aborts (a future table added to (b)/(c)/(d) and forgotten here would
-- otherwise surface as a runtime "permission denied" on the role split only).
--
-- CONSEQUENCE FOR FUTURE MIGRATIONS: a migration that adds a tenant-owned table
-- must ALSO (1) enable+force RLS and attach a policy, and (2) grant DML on it to
-- the runtime role — copy the two statements from here. Nothing is implicit.
--
-- No sequences exist (every id is a client-side uuidv7 and `events.seq` is
-- assigned by `append_event`), so there is no sequence grant; add one alongside
-- the first sequence if that ever changes.
do $$
declare
    v_role text := coalesce(nullif(current_setting('fluidbox.runtime_role', true), ''),
                            'fluidbox_runtime');
    -- The fluidbox surface, in the order sections (b), (c), (d) protect it.
    v_tables text[] := array[
        -- (b) standard tenant tables
        'policies', 'agents', 'sessions', 'api_tokens', 'settings',
        'integration_connections', 'trigger_subscriptions', 'capability_bundles',
        'github_app_registrations', 'org_idp_configs', 'users', 'org_memberships',
        'login_flows', 'user_sessions', 'pending_login_switches',
        'connection_tool_snapshots', 'run_resource_bindings',
        'tenant_deks', 'connector_oauth_flows', 'tenant_llm_keys',
        -- (c) child tables
        'agent_revisions', 'events', 'approvals', 'artifacts', 'usage_entries',
        'trigger_invocations', 'result_deliveries', 'trigger_deliveries',
        'trigger_dispatches', 'external_results', 'schedules', 'github_app_flows',
        'session_finalizations',
        -- (d) special shapes
        'tenants', 'connector_catalog', 'oauth_client_registrations', 'auth_audit_log'
    ];
    -- Functions the APPLICATION invokes (`select append_event(...)`). The 0013
    -- `fluidbox_convert_*` helpers are migration-only and the 0012 trigger function
    -- is fired by the engine (EXECUTE is checked when the trigger is created, not
    -- when it fires) — neither is granted.
    v_functions text[] := array['append_event'];
    v_missing text;
    v_absent text;
    t text;
    r record;
begin
    if not exists (select 1 from pg_roles where rolname = v_role) then
        return; -- managed host: section (a) already warned; nothing to grant.
    end if;

    -- Drift guard A: every table THIS migration attached a policy to is in the
    -- list. Keyed on our own policy names, not on `relrowsecurity`, so an
    -- unrelated RLS-protected table sharing this `public` schema is none of our
    -- business (that is the whole point of not granting ALL IN SCHEMA).
    select string_agg(distinct c.relname, ', ') into v_missing
      from pg_policy p
      join pg_class c on c.oid = p.polrelid
      join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public'
       and p.polname in ('tenant_isolation',
                         'catalog_read', 'catalog_insert', 'catalog_update', 'catalog_delete',
                         'registration_read', 'registration_insert', 'registration_update',
                         'registration_delete',
                         'audit_insert', 'audit_select')
       and not (c.relname::text = any(v_tables));
    if v_missing is not null then
        raise exception 'migration 0018: fluidbox RLS policies exist on table(s) % that are absent from the runtime grant list — the role split would fail closed at runtime. Add them to v_tables in section (e).', v_missing;
    end if;
    -- Drift guard B: every listed table exists (catches a typo/rename).
    select string_agg(t2, ', ') into v_absent
      from unnest(v_tables) as t2
     where to_regclass('public.' || quote_ident(t2)) is null;
    if v_absent is not null then
        raise exception 'migration 0018: grant list names table(s) % that do not exist.', v_absent;
    end if;

    execute format('grant usage on schema public to %I', v_role);
    foreach t in array v_tables loop
        execute format('grant select, insert, update, delete on table %I to %I', t, v_role);
    end loop;
    -- 0012:208-210 deferred grant: the process the API runs as literally cannot
    -- MUTATE the append-only auth log — INSERT/SELECT only. The owner keeps these
    -- by ownership (the triggers backstop that); this closes it for the runtime role.
    execute format('revoke update, delete, truncate on table auth_audit_log from %I', v_role);
    -- SECURITY INVOKER functions run as the caller; grant EXECUTE by exact
    -- signature (regprocedure) so an overload change is a visible failure here.
    for r in
        select p.oid::regprocedure::text as sig
          from pg_proc p
          join pg_namespace n on n.oid = p.pronamespace
         where n.nspname = 'public' and p.proname::text = any(v_functions)
    loop
        execute format('grant execute on function %s to %I', r.sig, v_role);
    end loop;
end $$;
