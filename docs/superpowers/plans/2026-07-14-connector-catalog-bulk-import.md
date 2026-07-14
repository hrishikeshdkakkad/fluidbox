# Connector catalog bulk import — breadth from open-connector as untrusted reference data

**Date:** 2026-07-14 · **Author:** capabilities review (`claude/mcp-capabilities-review`)
**Parent:** `docs/superpowers/plans/2026-07-11-phase5-5-connector-catalog-oauth.md` (the catalog + OAuth slice)
**Source under evaluation:** [`oomol-lab/open-connector`](https://github.com/oomol-lab/open-connector) (Apache-2.0)

## 1. Problem

The connector catalog (`connector_catalog`, migration `0007`) ships **7 hand-curated
entries** (GitHub, Stripe, Linear, Sentry, Atlassian, Notion, workspace-info). The
security model around it is deep — photograph rule, definition digests, poison screen,
frozen-set gate, audience-bound brokered credentials — but the **breadth is thin**, and
adding an entry today is manual SQL curation.

open-connector is an open-source "Composio alternative" whose entire value is **breadth**:
1,000+ providers and 10,000+ prebuilt Actions declared in `src/providers/<service>/definition.ts`.
It is a data asset we can learn from without taking a code dependency. This plan imports
that breadth into `connector_catalog` as **untrusted reference rows**, so the dashboard
Store goes from 7 cards to hundreds overnight — while every existing invariant holds.

### 1.1 The load-bearing tension (read this before anything else)

**open-connector providers are REST-API Actions, not MCP servers.** Its runtime turns a
REST endpoint into an agent-callable Action and executes it itself (proxy/executor).
fluidbox's catalog, by contrast, only knows two connectable shapes:

- `transport='streamable_http'` + `url` → a **remote MCP endpoint** the broker photographs.
- `transport='stdio'` + `sandbox_launch` → an **in-image MCP server** (declared tools).

A generic open-connector provider is **neither**. It has no hosted MCP endpoint to
photograph and no in-image server. So importing its metadata gives us a **browsable card**,
but pressing **Connect** cannot succeed under today's model — there is nothing to
photograph. Only the minority of providers that *also* expose a hosted MCP endpoint
(GitHub, Stripe, Linear, Notion, Sentry, Atlassian, …) are connectable now.

This is not a blocker; it is the correct scope boundary. open-connector solves the exact
same problem internally with its `catalogOnly` vs `locallyExecutable` status split. We
adopt the same honesty: **import buys discovery breadth; connectability for REST-only
providers waits on the separate, deferred `CapabilityServer::RestAction` class** (the
"REST Action" learning from the capabilities review; out of scope here). When that
class lands, these reference rows light up with a one-line executor change — no re-import.

## 2. Non-negotiables (inherited constraints)

- **Catalog rows are UNTRUSTED reference data.** `tool_hints` are policy-default seeds for
  display/suggestion only; the permission gate (`internal.rs::decide_tool_call`) stays the
  judge. Nothing enforces off catalog data. (Phase 5.5 framing, unchanged.)
- **No boot-sync, no runtime seed file.** The only sanctioned checked-in artifact for
  catalog content is **migration SQL** (Phase 5.5 settle #2). The importer is an *offline*
  developer tool that regenerates a migration; the server never fetches open-connector at
  boot or runtime.
- **No gate change, no RunSpec/freeze change, no photograph change.** `run_service::create_run`
  is untouched. Import only adds rows to a reference table.
- **Tier honesty.** The `/v1/catalog` API forces `tier='custom'` because verified/community
  are curation judgements the API cannot self-award. Imported rows are third-party curation,
  not ours → they are **`community`** tier, set by the migration (not via the API).
- **Backend stays 100% Rust; dashboard stays presentation-only.** The importer is a small
  Rust binary/xtask; no TypeScript enters the backend. (We read open-connector's `.ts`
  definitions as *input data*, not as code we run.)

## 3. Decision record

- **D1 — Import at PROVIDER granularity, not Action granularity.** We import ~1,000 provider
  rows, NOT 10,000 actions. Catalog rows never stored per-tool schemas (tools are
  photographed at connect); they hold provider-level metadata + coarse `tool_hints` globs.
  This keeps the migration to ~1k INSERTs (fine) and matches the existing shape exactly.

- **D2 — Output is a generated migration, pinned to an open-connector commit.** The importer
  reads a **pinned** open-connector checkout (commit SHA recorded in the migration header,
  LiteLLM-digest-pinning culture) and emits `migrations/00NN_catalog_import.sql`. Re-running
  against a newer pin produces the *next* migration (append-only; we never rewrite `0007`).

- **D3 — A new `transport='rest_action'` marks reference-only rows.** REST-only providers
  import with `transport='rest_action'`, `url` = their API base (informational), and
  **Connect refuses them** with a clear "not yet connectable — needs the REST action
  executor" message (mirrors open-connector's `catalogOnly`). Providers with a known hosted
  MCP endpoint import as normal `streamable_http` + `url` and Connect works today. The
  dashboard derives a `connectable` boolean from `transport` so the Store can badge cards.

- **D4 — Provenance is a first-class column.** Add `provenance jsonb` (`{source, source_ref,
  imported_at, upstream_id}`). Reference rows are auditable and refreshable; a future
  re-import can diff by `(source, upstream_id)`. Curated `verified` rows (the original 7)
  carry `provenance = {"source":"fluidbox"}` and are never overwritten by an import.

- **D5 — Import runs the poison screen.** Names, descriptions, and `tool_hints` notes are
  model-/operator-visible strings from an external source. The importer runs the SAME
  objective lint as capability registration (`fluidbox_core::capability::lint_text`:
  control/zero-width/bidi/ANSI rejection, length caps) over every imported string and
  **drops** any offending provider (logged), never smuggling it in. This is the "poison
  screen at the door" applied to reference data too.

- **D6 — Idempotent upsert by slug; curated rows win.** The migration uses
  `insert … on conflict (slug) do update … where connector_catalog.provenance->>'source' <> 'fluidbox'`
  — an import can refresh a prior import but can **never** clobber a hand-curated verified
  entry (GitHub stays GitHub). Slug collisions between two imported providers get a numeric
  suffix (reuse `catalog.rs::derive_slug` logic).

- **D7 — Attribution retained (Apache-2.0).** open-connector is Apache-2.0. We keep a
  `NOTICE`/attribution entry crediting oomol-lab, record `source_ref` (commit) in
  provenance, and note the license in the migration header. Factual API metadata (names,
  endpoints, scopes) carries thin copyright, but their descriptions/curation may not — Apache-2.0
  permits reuse with attribution, so we attribute rather than paraphrase. Legal sign-off is
  an explicit gate before the generated migration is merged (§8, open question O1).

## 4. Field mapping (open-connector `definition.ts` → `connector_catalog`)

| catalog column | source | notes |
|---|---|---|
| `slug` | provider dir name, slugified | `catalog.rs::slugify`; must satisfy alias charset `[a-z0-9-]` (no `_`) |
| `name` | provider `displayName`/`name` | linted (D5) |
| `icon` | provider icon if present | short glyph only; else null |
| `description` | provider description | linted, length-capped |
| `categories` | provider category/tags | jsonb array of strings |
| `tier` | — | forced `'community'` in migration (D4/tier honesty) |
| `url` | hosted MCP endpoint if known, else API base | connectable only when a real MCP endpoint |
| `transport` | derived | `streamable_http` if hosted MCP known; else `rest_action` (D3) |
| `auth_mode` | provider auth type | `oauth2`→`oauth`, `api_key`→`api_key`, `no_auth`→`none` |
| `auth_hints` | auth field metadata | `{scheme?, header_name?, composite?, key_url?, placeholder?}`; sane defaults |
| `scopes` | union of Actions' `requiredScopes` | de-duplicated jsonb array |
| `egress` | host(s) from base URL | informational host list for the card |
| `tool_hints` | derived from Action `readOnly`/method | coarse globs: read/GET → `allow`, write → `approve` (see §4.1) |
| `sandbox_launch` | — | always null (imported providers are never in-image) |
| `provenance` | — | `{"source":"open-connector","source_ref":"<sha>","upstream_id":"<dir>"}` |

### 4.1 tool_hints seeding (genuinely useful enrichment)

open-connector Action metadata distinguishes read vs write (HTTP method,
`readOnly`/`providerPermissions`). We fold that into a coarse **policy-default display seed**:
`{"pattern":"mcp__<slug>__*get*","action":"allow"}`, `…*list*/*search* → allow`, catch-all
`mcp__<slug>__* → approve`. This is exactly the shape the 7 curated entries already use, and
it is **display/suggestion only** — the gate never reads it. It gives every imported card a
sensible default posture instead of a blank one.

## 5. Importer design (the offline tool)

- **Location:** `crates/xtask` (or `scripts/`) — a dev-only Rust binary `catalog-import`,
  NOT part of the server crate graph. Invoked as `just catalog-import --src <path-to-open-connector> --out migrations/00NN_catalog_import.sql`.
- **Input:** a **pinned local checkout** of open-connector (the SHA is an argument and is
  written into the migration header). We do not fetch at build time; the operator clones/pins.
- **Parse:** open-connector definitions are TypeScript. We do **not** execute them. Two options,
  in preference order:
  1. **Their generated catalog JSON** — open-connector emits `catalog/apps` via `npm run
     generate:catalog`. Parsing that JSON is robust and avoids TS parsing entirely. **Primary path.**
  2. Fallback: a thin regex/AST extraction over `definition.ts` for the handful of fields we
     need, if the generated JSON is unavailable. Lower fidelity; documented as best-effort.
- **Transform:** apply §4 mapping + §4.1 hint seeding.
- **Screen:** apply D5 lint; drop-and-log offenders; drop providers missing required fields
  (name, auth_mode).
- **Emit:** deterministic, sorted-by-slug `INSERT … ON CONFLICT` SQL (D6). Deterministic
  ordering keeps the migration diff-reviewable and reproducible.
- **Reproducibility:** same source SHA → byte-identical migration (no timestamps in row
  bodies; `imported_at` uses the migration's own `now()` at apply time, not generation time).

## 6. Schema changes (one small migration, ahead of the generated one)

`migrations/00NN_catalog_provenance.sql`:

```sql
alter table connector_catalog
  add column provenance jsonb not null default '{"source":"fluidbox"}';

-- 'rest_action' joins the transport vocabulary as a REFERENCE-ONLY shape.
-- (No check constraint on transport today; Connect enforces connectability.)
```

Then `catalog.rs::connect_entry` gains a guard at the top:

```rust
if entry.transport == "rest_action" {
    return Err(ApiError::BadRequest(
        "this connector is reference-only (imported catalog entry); \
         a REST action executor is required to connect it — not yet available".into(),
    ));
}
```

And `catalog.rs::list` decoration adds a derived `"connectable": entry.transport != "rest_action"`
so the dashboard badges Store cards without embedding logic. `ConnectorCatalogRow` gains
`pub provenance: Value`.

## 7. Testing acceptance

- **Importer unit tests:** a fixture open-connector JSON with (a) an oauth2 provider,
  (b) an api_key provider with a custom header, (c) a no_auth provider, (d) a poisoned
  description (must be dropped), (e) a slug collision (must suffix) → assert emitted SQL rows.
- **Migration test** (extends `fluidbox-db` lib tests, real Neon): after the generated
  migration applies, `list_catalog` returns ≥ N rows; the original 7 curated verified rows
  are **unchanged** (provenance still `fluidbox`, tier still `verified`); a spot-checked
  imported row has `tier='community'`, `provenance.source='open-connector'`.
- **Connect guard test:** `connect` on a `rest_action` entry returns 400 with the
  reference-only message; `connect` on an imported entry that DOES have a hosted MCP endpoint
  still photographs (reuses existing api_key/oauth paths).
- **e2e (`scripts/e2e`) catalog assertions:** the connector-catalog block asserts the Store
  lists both verified and community tiers and that a reference-only card reports
  `connectable=false`. Keep `events.rs`/`run_service.rs` grep-clean (no new provider names).
- **`just check`** green (fmt + clippy -D warnings + test + web build).

## 8. Rollout increments

1. **Schema + guard** (§6): `provenance` column, `rest_action` transport handling, Connect
   guard, `connectable` decoration. Small, self-contained, shippable alone.
2. **Importer tool** (§5) with fixture tests. Produces a migration but we don't merge a
   1k-row one yet.
3. **Attribution + legal gate** (D7 / O1): `NOTICE` entry, license note; sign-off.
4. **Generated import migration** merged: the actual breadth lands. Reviewable because it's
   deterministic, sorted, and every row is `community`/provenanced.

Increment 1 is valuable on its own (it makes the catalog import-ready and honest about
connectability); 4 is the payload.

## 9. Explicitly out of scope

- **`CapabilityServer::RestAction` executor** — the thing that makes REST-only entries
  actually connectable. Separate plan; this import is designed to dovetail with it (D3) but
  does not depend on or deliver it.
- **Running open-connector as a brokered MCP server.** Rejected in the review: its MCP
  surface is 4 meta-tools (`search_actions`/`execute_action`/…), so the photograph would
  freeze `execute_action` and collapse per-tool governance, and credentials would live in a
  second custodian. Direct violation of §8.3 and the credential-inversion invariant.
- **Per-Action schema import.** We import provider rows, not 10k action schemas (D1).

## 10. Open questions

- **O1 (legal):** confirm Apache-2.0 attribution is sufficient for redistributing the
  curated metadata + descriptions in a migration, or whether we paraphrase descriptions.
  Blocks increment 4, not 1–3.
- **O2 (refresh cadence):** how often do we re-pin and re-import? Proposal: manual, on demand,
  each producing a new append-only migration. No automation (respects no-boot-sync).
- **O3 (hosted-MCP discovery):** the set of providers that also expose a hosted MCP endpoint
  (→ `streamable_http`, connectable now) is small and moves. Proposal: maintain a tiny
  hand-kept allowlist mapping `slug → mcp_url` inside the importer; everything else imports as
  `rest_action`. Keeps connectable-now honest without guessing.
