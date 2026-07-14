# Connector catalog bulk import — breadth from the MCP Registry (primary) + open-connector (supplement), as untrusted reference data

**Date:** 2026-07-14 · rev 2 · **Author:** capabilities review (`claude/connector-catalog-bulk-import-plan`)
**Parent:** `docs/plans/2026-07-11-phase5-5-connector-catalog-oauth.md` (the catalog + OAuth slice)
**Sources under evaluation:**
- [`modelcontextprotocol/registry`](https://github.com/modelcontextprotocol/registry) — the official MCP Registry (Apache-2.0) · **PRIMARY**
- [`oomol-lab/open-connector`](https://github.com/oomol-lab/open-connector) (Apache-2.0) · **SUPPLEMENT** (REST-only long tail)

**Prior art / threat model:** [Invariant Labs `mcp-scan`](https://invariantlabs.ai/blog/introducing-mcp-scan) — coined "tool poisoning" and "rug pull"; its "tool pinning" (hash tool descriptions, alarm on drift) IS our `tools_digest` + frozen-photograph model. Cited as the recognized mitigation our poison screen implements.

**Status (2026-07-14):** increments 1–3 IMPLEMENTED — schema + guard (migration 0009, Connect refusal, `connectable` decoration, dashboard "Reference only" badge), the two-source importer (`crates/fluidbox-catalog-import`, `just catalog-import-registry`) with 18 fixture tests, and attribution (`NOTICE`). The importer pages the live MCP Registry (or a pinned snapshot) as primary + an open-connector checkout as supplement, screens every string, and emits a deterministic append-only migration. Increment 4 (the generated payload) stays deferred: it needs a pinned snapshot + legal sign-off (O1) and applies against real Neon. One refinement vs D6: the generated upsert predicate is `provenance->>'source' in ('mcp-registry','open-connector')` (refresh ONLY prior imports) rather than `<> 'fluidbox'` — strictly safer, it also protects a user's `custom` BYO entries.

## 1. Problem

The connector catalog (`connector_catalog`, migration `0007`) ships **7 hand-curated
entries**. The security model around it is deep — photograph rule, definition digests,
poison screen, frozen-set gate, audience-bound brokered credentials — but the **breadth is
thin**, and adding an entry is manual SQL curation.

We want breadth **now**, as **untrusted reference rows**, without a code dependency and
without touching the gate / RunSpec / photograph. Two public catalogs supply it, at
different value:

- **The official MCP Registry is the high-value source.** It is the canonical, community
  registry (backed by Anthropic, GitHub, PulseMCP, Microsoft), Apache-2.0, with a live
  paginated REST API, and — critically — **its entries are real MCP servers, many exposing
  remote streamable-http URLs that are DIRECTLY CONNECTABLE through our existing broker /
  photograph path today.** Its `server.json` is the same shape our `ServerIdentity` struct
  already mirrors (reverse-DNS name, version, package coords).
- **open-connector is the long-tail supplement.** Its 1,000+ providers are REST-API Actions,
  not MCP servers, so they import as *reference-only* and cannot Connect until the separate,
  deferred `RestAction` executor lands. Valuable for coverage of SaaS that has no MCP server
  yet, but strictly secondary to the Registry for *connectable* breadth.

### 1.1 The connectability split (read this before anything else)

fluidbox's catalog knows two **connectable** shapes:

- `transport='streamable_http'` + `url` → a **remote MCP endpoint** the broker photographs.
- `transport='stdio'` + `sandbox_launch` → an **in-image MCP server** (declared tools).

Mapping each source onto that:

| Source | Entry kind | Imports as | Connectable now? |
|---|---|---|---|
| MCP Registry | `remotes[].type = streamable-http` (remote URL) | `streamable_http` + `url` | **Yes** — existing broker path |
| MCP Registry | `packages[]` only (npm/pypi/docker, no remote) | `rest_action` reference (see D3) | No — needs local/stdio launch we don't package |
| open-connector | REST-API provider | `rest_action` reference | No — needs deferred `RestAction` executor |

So: **the Registry gives connectable breadth immediately; packaged-only Registry entries and
all open-connector entries import as honest reference cards** (mirroring open-connector's own
`catalogOnly` vs `locallyExecutable` split, and the Registry's own remote-vs-package
distinction). When a stdio-packaging path and/or the `RestAction` class land, those reference
rows light up with no re-import.

## 2. Non-negotiables (inherited constraints)

- **Catalog rows are UNTRUSTED reference data.** `tool_hints` are policy-default seeds for
  display/suggestion only; the permission gate (`internal.rs::decide_tool_call`) stays the
  judge. Nothing enforces off catalog data. (Phase 5.5 framing, unchanged.)
- **No boot-sync, no runtime seed file.** The only sanctioned checked-in artifact for catalog
  content is **migration SQL** (Phase 5.5 settle #2). The importer is an *offline* developer
  tool that regenerates a migration; the server never fetches the Registry or open-connector
  at boot or runtime. (The Registry API is hit only by the offline importer, at generate time.)
- **No gate change, no RunSpec/freeze change, no photograph change.** `run_service::create_run`
  is untouched. Import only adds rows to a reference table. **Connect still photographs each
  server fresh** — imported tool metadata is never trusted as the frozen set.
- **Tier honesty.** The `/v1/catalog` API forces `tier='custom'` because verified/community
  are curation judgements the API cannot self-award. Imported rows are third-party curation,
  not ours → they are **`community`** tier, set by the migration (not via the API). The
  original 7 curated `verified` rows are never overwritten (D6).
- **Backend stays 100% Rust; dashboard stays presentation-only.** The importer is a small Rust
  binary/xtask; no TypeScript enters the backend. (open-connector `.ts` definitions and the
  Registry JSON are read as *input data*, never executed.)

## 3. Decision record

- **D0 — Two sources, one importer, Registry first.** The importer pulls the MCP Registry
  first (connectable breadth) and open-connector second (REST-only supplement), de-duplicating
  by canonical identity (D6). Each row records which source it came from (D4). The Registry is
  authoritative on collision (a real MCP server beats a REST-only card for the same service).

- **D1 — Import at PROVIDER/SERVER granularity, not Action granularity.** ~hundreds–thousand
  rows, NOT 10,000 actions. Catalog rows never stored per-tool schemas (tools are photographed
  at connect); they hold server-level metadata + coarse `tool_hints` globs. Keeps the migration
  diff-reviewable and matches the existing row shape exactly.

- **D2 — Output is a generated migration, pinned.** The importer records the Registry snapshot
  cursor/date and the open-connector commit SHA in the migration header (LiteLLM-digest-pinning
  culture) and emits `migrations/00NN_catalog_import.sql`. Re-running against a newer snapshot
  produces the *next* migration (append-only; we never rewrite `0007`).

- **D3 — A `transport='rest_action'` marks reference-only rows.** Non-connectable imports
  (open-connector REST providers; packaged-only Registry entries with no remote URL) get
  `transport='rest_action'`, `url` = informational base if any, and **Connect refuses them**
  with a clear "reference-only — not yet connectable" message. `list` derives
  `"connectable": transport != 'rest_action'` so the Store badges cards. Registry entries WITH
  a remote streamable-http URL import as normal `streamable_http` + `url` and Connect works today.

- **D4 — Provenance is a first-class column.** `provenance jsonb` =
  `{"source": "mcp-registry" | "open-connector" | "fluidbox", "source_ref": "<cursor|sha>",
  "upstream_id": "<server.json name | provider dir>", "status": "<registry status>"}`.
  Reference rows are auditable and refreshable; a future re-import diffs by
  `(source, upstream_id)`. The curated 7 carry `{"source":"fluidbox"}` and are import-immune.

- **D5 — Import runs the poison screen (the mcp-scan-recognized mitigation).** Names,
  descriptions, and `tool_hints` notes are model-/operator-visible strings from external
  sources. The importer runs the SAME objective lint as capability registration
  (`fluidbox_core::capability::lint_text`: control/zero-width/bidi/ANSI rejection, length caps)
  over every imported string and **drops** any offending entry (logged). This is the poison
  screen at the door, applied to reference data — the static-analysis half of what mcp-scan
  does; the digest/rug-pull half is already covered by the photograph at Connect.

- **D6 — Idempotent upsert by canonical identity; curated rows win; Registry beats open-connector.**
  The migration uses `insert … on conflict (slug) do update … where
  connector_catalog.provenance->>'source' <> 'fluidbox'` — an import can refresh a prior import
  but never clobbers a hand-curated verified entry (GitHub stays GitHub). When both sources
  describe the same service, the Registry (connectable) row wins the slug; the open-connector
  row is dropped (logged). Cross-source slug collisions between distinct services get a numeric
  suffix (reuse `catalog.rs::derive_slug`).

- **D7 — Registry `status` is honored.** `server.json` carries a status (`active` /
  `deprecated` / …). Only `active` entries import; non-active are skipped (logged) and recorded
  nowhere. A later re-import naturally drops a server that went deprecated (append-only migration
  can `on conflict … do update set … ` to flip it to `rest_action`+note, or we simply stop
  refreshing it — O2).

- **D8 — Attribution retained (both Apache-2.0).** Keep a `NOTICE`/attribution entry crediting
  the MCP Registry (Anthropic et al.) and oomol-lab; record `source_ref` in provenance; note
  both licenses in the migration header. Apache-2.0 permits reuse with attribution, so we
  attribute rather than paraphrase. Legal sign-off gates the payload migration merge (O1).

## 4. Field mapping

### 4.1 MCP Registry `server.json` → `connector_catalog` (PRIMARY)

Sample entry shape (verified against the live API,
`GET https://registry.modelcontextprotocol.io/v0/servers?limit=&cursor=`):

```json
{ "server": { "name": "ac.inference.sh/mcp", "title": "inference.sh",
    "description": "Run 150+ AI apps…", "version": "1.0.0",
    "remotes": [{ "type": "streamable-http", "url": "https://api.inference.sh/mcp" }] },
  "_meta": { "io.modelcontextprotocol.registry/official": { "status": "active", … } } }
```

| catalog column | source | notes |
|---|---|---|
| `slug` | `server.title` or last path segment of `name`, slugified | `catalog.rs::slugify`; alias charset `[a-z0-9-]` |
| `name` | `server.title` \|\| `server.name` | linted (D5) |
| `description` | `server.description` | linted, length-capped |
| `url` | first `remotes[]` where `type` ∈ {streamable-http, http} | present ⇒ **connectable** |
| `transport` | derived | `streamable_http` if a remote URL exists; else `rest_action` (packaged-only) |
| `auth_mode` | `none` by default; `remotes[].headers`/probe hints if present | most remotes are OAuth/none; Connect's probe still decides (unchanged) |
| `categories` | none in server.json → `[]` | Registry has no category taxonomy; leave empty or infer from name |
| `tier` | — | forced `'community'` |
| `provenance` | — | `{source:"mcp-registry", upstream_id:server.name, source_ref:<cursor/date>, status}` |
| `sandbox_launch` | — | null (we don't auto-package npm/pypi Registry entries this pass) |

Notably the Registry has **no scopes/egress/tool_hints taxonomy**; those import empty and get
the coarse default hint seed (§4.3). Egress host is derived from the remote URL.

### 4.2 open-connector `definition.ts` → `connector_catalog` (SUPPLEMENT, unchanged from rev 1)

| catalog column | source | notes |
|---|---|---|
| `slug` | provider dir name, slugified | alias charset |
| `name` / `description` / `icon` | provider fields | linted |
| `categories` | provider category/tags | jsonb array |
| `url` | API base | informational only |
| `transport` | — | always `rest_action` (never a hosted MCP endpoint) |
| `auth_mode` | provider auth type | `oauth2`→`oauth`, `api_key`→`api_key`, `no_auth`→`none` |
| `auth_hints` | auth field metadata | `{scheme?, header_name?, composite?, key_url?, placeholder?}` |
| `scopes` | union of Actions' `requiredScopes` | de-duplicated jsonb array |
| `egress` | host(s) from base URL | informational |
| `tool_hints` | derived from Action read/write | coarse globs (§4.3) |
| `provenance` | — | `{source:"open-connector", upstream_id:dir, source_ref:<sha>}` |

### 4.3 tool_hints seeding (both sources)

A coarse, display-only policy-default posture (the gate never reads it):
`{"pattern":"mcp__<slug>__*get*","action":"allow"}`, `…*list*/*search* → allow`, catch-all
`mcp__<slug>__* → approve`. open-connector's read/write Action metadata refines it where
available; Registry entries just get the default. Matches the shape the 7 curated entries use.

## 5. Importer design (the offline tool)

- **Location:** `crates/xtask` (or `scripts/`) — a dev-only Rust binary `catalog-import`, NOT
  in the server crate graph. `just catalog-import --registry --open-connector <path> --out migrations/00NN_catalog_import.sql`.
- **MCP Registry ingest:** page `GET /v0/servers?limit=100&cursor=…` following `nextCursor` to
  exhaustion; keep `status=active`; map §4.1. This is a network fetch **at generate time only**,
  pinned by recording the run date/final cursor in the migration header.
- **open-connector ingest:** read a **pinned local checkout**; prefer its generated
  `catalog/apps` JSON (`npm run generate:catalog`) over parsing `.ts`; map §4.2. SHA in header.
- **Merge:** Registry first, then open-connector; drop open-connector rows whose service already
  has a Registry row (D6); suffix distinct-service slug collisions.
- **Screen:** apply D5 lint; drop-and-log offenders and entries missing required fields.
- **Emit:** deterministic, sorted-by-slug `INSERT … ON CONFLICT` SQL (D6). No timestamps in row
  bodies (`imported_at` uses the migration's `now()` at apply time) → same inputs = byte-identical
  migration, diff-reviewable.

## 6. Schema changes (one small migration, ahead of the generated one)

`migrations/00NN_catalog_provenance.sql`:

```sql
alter table connector_catalog
  add column provenance jsonb not null default '{"source":"fluidbox"}';
-- 'rest_action' joins the transport vocabulary as a REFERENCE-ONLY shape.
-- (No check constraint on transport today; Connect enforces connectability.)
```

`catalog.rs::connect_entry` gains a top guard:

```rust
if entry.transport == "rest_action" {
    return Err(ApiError::BadRequest(
        "this connector is reference-only (imported catalog entry); it is not yet \
         connectable from fluidbox".into(),
    ));
}
```

`catalog.rs::list` decoration adds derived `"connectable": entry.transport != "rest_action"`;
`ConnectorCatalogRow` gains `pub provenance: Value`.

## 7. Testing acceptance

- **Importer unit tests (fixtures, no network):** a captured Registry page (one streamable-http
  remote → connectable; one packaged-only → `rest_action`; one `status=deprecated` → dropped)
  and an open-connector JSON (oauth / api_key+custom-header / no_auth / poisoned-description →
  dropped / slug collision → suffixed) → assert emitted SQL rows and drops.
- **Merge test:** a service present in BOTH sources yields ONE row, `source=mcp-registry`,
  `transport=streamable_http`.
- **Migration test (`fluidbox-db`, real Neon):** after apply, `list_catalog` returns ≥ N rows;
  the original 7 verified rows are unchanged (provenance `fluidbox`, tier `verified`); a
  Registry row is `community` + `streamable_http` + `connectable`; an open-connector row is
  `community` + `rest_action`.
- **Connect guard test:** `connect` on a `rest_action` entry → 400 reference-only; `connect` on
  an imported streamable-http entry still photographs via the existing api_key/oauth paths.
- **e2e catalog assertions:** Store lists verified + community tiers and reports
  `connectable` correctly for both a Registry and a reference row. `events.rs`/`run_service.rs`
  stay grep-clean (no new provider names).
- **`just check`** green.

## 8. Rollout increments

1. **Schema + guard** (§6): `provenance` column, `rest_action` handling, Connect guard,
   `connectable` decoration. Self-contained, shippable alone.
2. **Importer tool** (§5) — Registry + open-connector ingest, fixture tests. Produces a
   migration; not merged yet.
3. **Attribution + legal gate** (D8 / O1): `NOTICE`, license notes; sign-off.
4. **Generated import migration merged** — the breadth lands. The **Registry slice is the
   connectable payload**; the open-connector slice is reference breadth.

## 9. Explicitly out of scope

- **`CapabilityServer::RestAction` executor** — makes REST-only rows connectable. Separate plan;
  this import dovetails with it (D3) but neither delivers nor depends on it.
- **Auto-packaging npm/pypi/docker Registry entries as stdio in-image servers** — would make
  packaged-only Registry rows connectable, but pulling third-party packages into the runner
  image is a supply-chain decision of its own. Deferred; those rows import as `rest_action` now.
- **Running the Registry / open-connector as a live brokered MCP server.** Rejected: collapses
  per-tool governance to a meta-tool and adds a second credential custodian (violates §8.3 +
  the credential-inversion invariant).
- **Per-Action / per-tool schema import.** We import server rows, not tool schemas (D1); Connect
  photographs the real tools.

## 10. Open questions

- **O1 (legal):** confirm Apache-2.0 attribution suffices to redistribute Registry + open-connector
  metadata/descriptions verbatim in a migration, else paraphrase. Blocks increment 4 only.
- **O2 (refresh cadence):** manual, on-demand re-pin → new append-only migration; no automation
  (respects no-boot-sync). How do we retire rows for servers that leave/deprecate on the Registry?
  Proposal: a refresh flips them to `rest_action` + a `status:"deprecated"` provenance note
  rather than deleting (keeps slug/dedup history continuous).
- **O3 (auth detection for Registry remotes):** most remotes are OAuth or authless, but
  `server.json` doesn't always declare it. Proposal: import `auth_mode='none'` and rely on the
  existing non-committing **probe** (`/v1/mcp/probe`) at Connect to detect 401 → OAuth vs api_key
  — no guessing at import time.
