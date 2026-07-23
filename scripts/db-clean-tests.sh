#!/usr/bin/env bash
# fluidbox db-clean-tests — remove ONLY test-suite residue. A scalpel.
#
# Not to be confused with `just db-clean`, which is a RESET: that one drops ALL
# sessions, ALL capability_bundles (including real ones like `cloudflare`) and
# every agent outside a keep-list. This script deletes only rows the test suite
# itself creates, and is safe to run against a database with real work in it.
#
# WHY THIS EXISTS: `fluidbox-db` tests call ensure_default_tenant(), so they
# write fixtures into the SAME tenant as real data (see
# docs/plans/2026-07-15-test-data-isolation-design.md). Until tests get their
# own tenant, fixtures can only be identified by exact name.
#
# EXACT NAMES, NEVER PATTERNS. `%test%` would delete the real agents
# `clouflare-test` and `clouflare-mcp-test-resource`. The list below is
# drift-guarded against the test source: add a fixture agent without listing it
# here and this script FAILS rather than silently leaving residue behind.
#
#   just db-clean-tests           # dry-run — show what WOULD be deleted
#   just db-clean-tests apply     # actually delete
set -euo pipefail
source "$(dirname "$0")/e2e-lib.sh"
load_env

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APPLY="${1:-}"

# Fixture agents created by crates/fluidbox-db/src/lib.rs tests.
FIXTURE_AGENTS="'test-seq-agent','test-token-agent','test-intent-agent','test-cap-agent','test-ws-agent','test-del-agent','test-idem-agent','test-sched-agent','test-stale-agent','test-trig-agent','pau-agent','pmt-agent-a','pmt-agent-b'"

# ── Drift guard ────────────────────────────────────────────────────────────
# Every agent the db tests create must appear above. A new fixture that nobody
# adds here would otherwise accumulate silently — the exact failure this script
# exists to stop. Fail loudly instead.
missing=""
while read -r n; do
  [ -z "$n" ] && continue
  case "$FIXTURE_AGENTS" in *"'$n'"*) ;; *) missing="$missing $n" ;; esac
done < <(grep -oE 'create_agent\(&pool, tenant, "[^"]+"' "$ROOT/crates/fluidbox-db/src/lib.rs" 2>/dev/null |
  sed -E 's/.*"([^"]+)"$/\1/' | sort -u)
if [ -n "$missing" ]; then
  echo "✗ DRIFT: these agents are created by fluidbox-db tests but are not in FIXTURE_AGENTS:"
  echo "   $missing"
  echo "  Add them to scripts/db-clean-tests.sh, then re-run."
  exit 1
fi

if [ "$APPLY" = "apply" ]; then
  END="commit;"; MODE="APPLY (committing)"
else
  END="rollback;"; MODE="DRY-RUN (rolling back — pass 'apply' to commit)"
fi
echo "fluidbox db-clean-tests — $MODE"
echo "fixture agents: $FIXTURE_AGENTS"
echo "fixture bundles: pmt-bundle-%"
echo

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -P pager=off <<SQL
-- Migration 0018 FORCEs RLS on every table below, which binds the table OWNER
-- too. Without this GUC the counts all read 0 and every DELETE silently affects
-- 0 rows — a cleanup that reports SUCCESS while deleting nothing. Session-level
-- SET on a custom (dotted) option: no privilege required, survives the
-- begin/rollback below (it is set outside that transaction).
set fluidbox.bypass = 'system_worker';
\echo '── WILL DELETE ────────────────────────'
select 'fixture agents' t, count(*) n from agents where name in ($FIXTURE_AGENTS)
union all select 'their sessions', count(*) from sessions s
  where s.agent_id in (select id from agents where name in ($FIXTURE_AGENTS))
union all select 'pmt-bundle-* bundles', count(*) from capability_bundles where name like 'pmt-bundle-%'
order by 1;

\echo ''
\echo '── WILL KEEP (everything else) ────────'
select name, (select count(*) from sessions s where s.agent_id = a.id) as sessions
from agents a where a.name not in ($FIXTURE_AGENTS) order by name;

begin;
-- sessions BEFORE agents: sessions.agent_id is NO ACTION, not CASCADE.
-- Session children (events, approvals, artifacts, usage_entries, api_tokens,
-- result_deliveries, trigger_invocations) cascade from here.
delete from sessions
 where agent_id in (select id from agents where name in ($FIXTURE_AGENTS));

-- Subscriptions also reference agents with NO ACTION.
delete from trigger_subscriptions
 where agent_id in (select id from agents where name in ($FIXTURE_AGENTS));

-- agent_revisions cascade from agents.
delete from agents where name in ($FIXTURE_AGENTS);

-- crates/fluidbox-db/src/lib.rs:4414 mints these as pmt-bundle-{uuid}.
delete from capability_bundles where name like 'pmt-bundle-%';

-- e2e-capabilities' kb-upstream connection (scripts/e2e-capabilities.sh) leaks
-- when a run aborts before its own end-of-phase cleanup, and TWO active copies
-- make the requirement resolver refuse as ambiguous on the next run. REVOKE
-- rather than delete: old runs' bindings may still reference the row, and a
-- revoked connection can never resolve. Triple predicate so a real connection
-- is untouchable (name AND provider AND loopback base_url).
update integration_connections set status = 'revoked'
 where provider = 'mcp_http' and display_name = 'kb-upstream'
   and metadata->>'base_url' like 'http://127.0.0.1:%'
   and status <> 'revoked';

-- Pending deliveries to LOOPBACK fixture receivers (e2e callback servers that
-- died with their run). Real destinations are never loopback; leaving these
-- costs retry attempts every server boot until the 6-attempt cap.
delete from result_deliveries
 where status = 'pending' and destination->>'url' like 'http://127.0.0.1%';

\echo ''
\echo '── AFTER (in-transaction) ─────────────'
select 'fixture agents' t, count(*) n from agents where name in ($FIXTURE_AGENTS)
union all select 'pmt-bundle-* bundles', count(*) from capability_bundles where name like 'pmt-bundle-%'
union all select 'agents remaining', count(*) from agents
union all select 'sessions remaining', count(*) from sessions
order by 1;
$END
SQL

echo
if [ "$APPLY" = "apply" ]; then
  echo "✓ committed — test residue removed."
else
  echo "(dry-run only — nothing changed. Re-run: just db-clean-tests apply)"
fi
