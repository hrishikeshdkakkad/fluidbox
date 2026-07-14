-- Connector-catalog bulk import — schema + honesty for untrusted reference data.
-- Plan: docs/superpowers/plans/2026-07-14-connector-catalog-bulk-import.md (§6).
--
-- This is increment 1: it makes the catalog import-READY without importing a
-- single row. The offline `catalog-import` tool (crates/fluidbox-catalog-import)
-- regenerates an append-only `00NN_catalog_import.sql` from a pinned
-- open-connector checkout; that generated payload is a SEPARATE migration
-- (increment 4), gated on legal sign-off. Nothing here fetches open-connector.

-- Provenance is a first-class, auditable column (plan D4). The curated seed
-- rows from 0007 carry {"source":"fluidbox"} and are NEVER overwritten by an
-- import — the idempotent upsert in the generated migration keys off exactly
-- this predicate (`provenance->>'source' <> 'fluidbox'`), so a re-import can
-- refresh a prior import but can never clobber a hand-curated verified entry.
alter table connector_catalog
    add column provenance jsonb not null default '{"source":"fluidbox"}';

-- 'rest_action' joins the transport vocabulary as a REFERENCE-ONLY shape
-- (plan D3): an imported row with no hosted MCP endpoint to photograph — a
-- packaged-only MCP Registry server, or an open-connector REST provider —
-- imports as a browsable card whose Connect is refused until the matching
-- executor/packaging lands. There is deliberately no CHECK constraint on
-- transport — connectability is enforced at Connect (catalog.rs), and the
-- dashboard derives a `connectable` flag from transport. No data changes here;
-- existing rows stay streamable_http / stdio. (MCP Registry entries that DO
-- expose a streamable-http remote import as normal streamable_http and connect.)
