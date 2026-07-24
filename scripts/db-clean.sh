#!/usr/bin/env bash
# fluidbox DB cleanup — remove e2e/test cruft, preserve the seed + real integrations.
#
# The e2e suite (and ad-hoc live runs) write test data to the real Neon DB and
# do not tear themselves down, so sessions/events/agents/subscriptions/bundles
# accumulate. This reclaims them SAFELY:
#
#   KEEP  — the tenant, all policies, all integration_connections + github_app_
#           registrations (your REAL integrations — never auto-deleted), and the
#           seed/curated agents (default: claude-fixer, repo-reporter). The boot
#           seeder re-creates the curated agent anyway if it's ever gone.
#   DROP  — all sessions + their run history (events, approvals, artifacts,
#           usage, result deliveries, invocations, session tokens — all cascade),
#           all trigger_subscriptions + their schedules/invocations/dispatches/
#           trigger tokens (cascade; this also stops the */5 test-schedule log
#           spam), trigger_deliveries, capability_bundles, github_app_flows,
#           every non-kept agent (+ its revisions, cascade), and custom
#           connector_catalog entries (the verified seeds stay).
#
# Runs inside ONE transaction and prints BEFORE/AFTER counts. DRY-RUN by default
# (rolls back); pass `apply` to commit.
#
#   just db-clean           # dry-run — show what WOULD be deleted
#   just db-clean apply     # actually delete
#
# Override the keep-list:  FLUIDBOX_DB_CLEAN_KEEP="'claude-fixer'" just db-clean
set -euo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env

APPLY="${1:-}"
KEEP_AGENTS="${FLUIDBOX_DB_CLEAN_KEEP:-'claude-fixer','repo-reporter'}"

if [ "$APPLY" = "apply" ]; then
  END="commit;"; MODE="APPLY (committing)"
else
  END="rollback;"; MODE="DRY-RUN (rolling back — pass 'apply' to commit)"
fi
echo "fluidbox db-clean — $MODE"
echo "keeping agents: $KEEP_AGENTS"

counts_sql="
select 'sessions' t,count(*) n from sessions
union all select 'events',count(*) from events
union all select 'agents',count(*) from agents
union all select 'agent_revisions',count(*) from agent_revisions
union all select 'subscriptions',count(*) from trigger_subscriptions
union all select 'schedules',count(*) from schedules
union all select 'trigger_invocations',count(*) from trigger_invocations
union all select 'trigger_deliveries',count(*) from trigger_deliveries
union all select 'capability_bundles',count(*) from capability_bundles
union all select 'github_app_flows',count(*) from github_app_flows
union all select 'api_tokens',count(*) from api_tokens
union all select 'catalog(custom)',count(*) from connector_catalog where tier='custom'
order by 1;"

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -P pager=off <<SQL
-- Migration 0018 FORCEs RLS on every table below, which binds the table OWNER
-- too. Without this GUC the counts all read 0 and every DELETE silently affects
-- 0 rows — a cleanup that reports SUCCESS while deleting nothing. Session-level
-- SET on a custom (dotted) option: no privilege required, survives the
-- begin/rollback below (it is set outside that transaction).
set fluidbox.bypass = 'system_worker';
\echo '── BEFORE ─────────────────────────────'
$counts_sql
begin;
delete from sessions;                                   -- run history (cascade)
delete from trigger_subscriptions;                      -- + schedules/invocations/dispatches/tokens (cascade)
delete from trigger_deliveries;                         -- webhook dedup rows (+ dispatches cascade)
delete from capability_bundles;                         -- test bundles
delete from github_app_flows;                           -- ephemeral flow rows
delete from agents where name not in ($KEEP_AGENTS);    -- test agents (+ revisions cascade)
delete from connector_catalog where tier = 'custom';    -- test custom catalog entries
\echo ''
\echo '── AFTER (in-transaction) ─────────────'
$counts_sql
\echo ''
\echo '── PRESERVED ──────────────────────────'
select 'integration_connections' t, count(*) n from integration_connections
union all select 'github_app_registrations', count(*) from github_app_registrations
union all select 'policies', count(*) from policies
union all select 'tenants', count(*) from tenants
union all select 'agents (kept)', count(*) from agents
order by 1;
$END
SQL

echo
if [ "$APPLY" = "apply" ]; then
  echo "✓ committed — DB cleaned."
else
  echo "(dry-run only — nothing changed. Re-run: just db-clean apply)"
fi
