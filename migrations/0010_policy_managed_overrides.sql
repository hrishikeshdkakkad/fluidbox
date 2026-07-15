-- UI-owned, per-tool policy overrides (Governance page).
--
-- Deliberately NOT part of yaml_source: that column is the AUTHORED policy and
-- stays git-owned (its comments carry the §10 decision reasoning). Keeping
-- overrides in their own column means `just policy-sync` can keep force-pushing
-- the base rules while UI decisions survive — the two never contend.
--
-- `parsed` stays the single thing run_service evaluates: every write here also
-- republishes parsed = base ++ overrides. This column is the durable record of
-- the UI's decisions; parsed is the merged view derived from it.
alter table policies
  add column managed_overrides jsonb not null default '[]'::jsonb;
