//! Offline connector-catalog importer: turn two public catalogs into an
//! append-only `connector_catalog` migration of UNTRUSTED, community-tier
//! reference rows.
//!
//! Plan: docs/superpowers/plans/2026-07-14-connector-catalog-bulk-import.md (rev 2).
//!
//! Two sources, one importer, **Registry first** (plan D0):
//!   1. The official **MCP Registry** (`modelcontextprotocol/registry`) — real
//!      MCP servers. Entries exposing a remote `streamable-http` URL import as
//!      `streamable_http` + `url` and are **connectable today** through the
//!      existing broker/photograph path; packaged-only entries import as
//!      reference-only `rest_action`.
//!   2. **open-connector** — REST-API providers, the long-tail supplement. They
//!      have no hosted MCP endpoint, so they ALWAYS import as `rest_action`
//!      reference cards, and are dropped when the Registry already covers the
//!      same slug (a real MCP server beats a REST-only card — plan D6).
//!
//! This crate is pure transform + emit — no DB, no clock, no network (the thin
//! `main` does the Registry HTTP paging / snapshot read + open-connector file
//! read). Every model-/operator-visible string passes the SAME poison screen
//! (`fluidbox_core::capability::lint_text`) that guards capability registration;
//! an offender drops its whole entry (plan D5).

use fluidbox_core::capability::lint_text;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

// ─── MCP Registry `GET /v0/servers` shape (verified against the live API) ──
// { "servers": [ { "server": {...}, "_meta": {...} } ], "metadata": { nextCursor, count } }

/// One page of the Registry servers endpoint.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegistryPage {
    #[serde(default)]
    pub servers: Vec<RegistryEntry>,
    #[serde(default)]
    pub metadata: RegistryMeta,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegistryMeta {
    #[serde(rename = "nextCursor", default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub count: u64,
}

/// One Registry server record: the server document + the official `_meta`
/// envelope (status / isLatest live under a reverse-DNS key).
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryEntry {
    pub server: RegistryServer,
    #[serde(rename = "_meta", default)]
    pub meta: Value,
}

/// The `server.json` document (parsed leniently — unused fields default).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RegistryServer {
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub version: Option<String>,
    pub remotes: Vec<RegistryRemote>,
    pub website_url: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RegistryRemote {
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
}

fn registry_official(meta: &Value) -> &Value {
    &meta["io.modelcontextprotocol.registry/official"]
}
fn registry_status(meta: &Value) -> Option<&str> {
    registry_official(meta)
        .get("status")
        .and_then(Value::as_str)
}
fn registry_is_latest(meta: &Value) -> bool {
    registry_official(meta)
        .get("isLatest")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

// ─── open-connector `catalog/apps/<service>.json` shape ───────────────────
// A serialized ProviderDefinition (src/core/types.ts), parsed leniently.

/// One open-connector provider definition.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OcProvider {
    pub service: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub categories: Vec<String>,
    pub auth_types: Vec<String>,
    /// Union of no_auth | api_key | custom_credential | oauth2 — raw Values;
    /// we only read `type`/`placeholder`.
    pub auth: Vec<Value>,
    pub homepage_url: Option<String>,
    pub icon_url: Option<String>,
    pub actions: Vec<OcAction>,
}

/// One prebuilt Action; we only need its required scopes (folded into the
/// provider-level `scopes` union — we import providers, not 10k actions, D1).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OcAction {
    pub name: String,
    pub required_scopes: Vec<String>,
    pub provider_permissions: Vec<String>,
}

// ─── the mapped, screened catalog row ─────────────────────────────────────

/// A screened row ready to be emitted as SQL. Always community tier; provenance
/// is reconstructed at emit time from the source fields below.
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogRow {
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub categories: Vec<String>,
    pub url: Option<String>,
    pub transport: String,
    pub auth_mode: String,
    pub auth_hints: Value,
    pub scopes: Vec<String>,
    pub egress: Vec<String>,
    pub tool_hints: Value,
    /// "mcp-registry" | "open-connector".
    pub source: &'static str,
    /// Registry snapshot cursor/date, or the open-connector commit SHA.
    pub source_ref: String,
    /// server.json name, or open-connector provider dir — the re-import diff key.
    pub upstream_id: String,
    /// Registry status (`active`); None for open-connector.
    pub status: Option<String>,
}

/// An entry the importer refused, with the objective reason (logged, never
/// smuggled in) — poison screen, missing fields, non-active status, or a
/// Registry-superseded open-connector duplicate.
#[derive(Debug, Clone)]
pub struct DropReason {
    pub service: String,
    pub reason: String,
}

/// The result of a build: screened rows (sorted by slug) + a drop log.
#[derive(Debug, Default)]
pub struct TransformOutput {
    pub rows: Vec<CatalogRow>,
    pub dropped: Vec<DropReason>,
}

/// The pins recorded in the generated migration header + row provenance.
#[derive(Debug, Clone, Default)]
pub struct Pins {
    /// Registry snapshot ref (final cursor / date). Used as `source_ref` for
    /// Registry rows and in the header.
    pub registry_ref: Option<String>,
    /// open-connector commit SHA. Used as `source_ref` for open-connector rows.
    pub open_connector_sha: Option<String>,
}

/// The whole pipeline: Registry rows first (reserving their slugs), then
/// open-connector rows (dropped where a Registry slug already covers them),
/// all screened and returned sorted by slug for a diff-reviewable migration.
pub fn build(
    registry: &[RegistryEntry],
    oc_providers: Vec<OcProvider>,
    pins: &Pins,
) -> TransformOutput {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let reg_ref = pins.registry_ref.as_deref().unwrap_or("");
    let mut out = transform_registry(registry, reg_ref, &mut seen);

    let registry_slugs: BTreeSet<String> = out.rows.iter().map(|r| r.slug.clone()).collect();
    if !oc_providers.is_empty() {
        let sha = pins.open_connector_sha.as_deref().unwrap_or("");
        let oc = transform_open_connector(oc_providers, sha, &mut seen, &registry_slugs);
        out.rows.extend(oc.rows);
        out.dropped.extend(oc.dropped);
    }
    out.rows.sort_by(|a, b| a.slug.cmp(&b.slug));
    out
}

// ─── MCP Registry → rows ──────────────────────────────────────────────────

/// Map the Registry's active, latest servers to screened rows. Non-active
/// servers and non-latest versions are collapsed away (logged as skips).
pub fn transform_registry(
    entries: &[RegistryEntry],
    source_ref: &str,
    seen: &mut BTreeSet<String>,
) -> TransformOutput {
    let mut out = TransformOutput::default();
    let (chosen, skipped) = registry_latest_active(entries);
    for (name, reason) in skipped {
        out.dropped.push(DropReason {
            service: name,
            reason,
        });
    }
    for e in chosen {
        match map_registry_server(e, source_ref, seen) {
            Ok(r) => out.rows.push(r),
            Err(reason) => out.dropped.push(DropReason {
                service: e.server.name.clone(),
                reason,
            }),
        }
    }
    out
}

/// One row per server name: the `active` + `isLatest` version (falling back to
/// the highest active version when no `isLatest` flag is present in the batch).
/// A name with no active version at all is reported as a skip (plan D7).
fn registry_latest_active(
    entries: &[RegistryEntry],
) -> (Vec<&RegistryEntry>, Vec<(String, String)>) {
    let mut groups: BTreeMap<&str, Vec<&RegistryEntry>> = BTreeMap::new();
    for e in entries {
        groups.entry(e.server.name.as_str()).or_default().push(e);
    }
    let mut chosen = Vec::new();
    let mut skipped = Vec::new();
    for (name, group) in groups {
        let actives: Vec<&RegistryEntry> = group
            .into_iter()
            .filter(|e| registry_status(&e.meta) == Some("active"))
            .collect();
        if actives.is_empty() {
            skipped.push((name.to_string(), "no active version".to_string()));
            continue;
        }
        let best = actives
            .iter()
            .copied()
            .find(|e| registry_is_latest(&e.meta))
            .or_else(|| {
                actives.iter().copied().max_by(|a, b| {
                    version_key(a.server.version.as_deref().unwrap_or(""))
                        .cmp(&version_key(b.server.version.as_deref().unwrap_or("")))
                })
            });
        if let Some(b) = best {
            chosen.push(b);
        }
    }
    (chosen, skipped)
}

/// Numeric-aware version key so 1.10.0 > 1.9.0 (used only to break isLatest
/// ties within a name group).
fn version_key(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect()
}

fn map_registry_server(
    e: &RegistryEntry,
    source_ref: &str,
    seen: &mut BTreeSet<String>,
) -> Result<CatalogRow, String> {
    let s = &e.server;
    let name = s
        .title
        .clone()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| s.name.clone())
        .trim()
        .to_string();
    if name.is_empty() {
        return Err("registry server has no name/title".into());
    }
    lint_text("name", &name)?;

    let description = match s.description.as_deref().map(str::trim) {
        Some(d) if !d.is_empty() => {
            lint_text("description", d)?;
            Some(d.to_string())
        }
        _ => None,
    };

    // Slug from the title; fall back to the full reverse-DNS name (NOT just the
    // last path segment, which is usually a generic "mcp" that mass-collides).
    let mut base = slugify(&name);
    if !valid_slug(&base) {
        base = slugify(&s.name);
    }
    if !valid_slug(&base) {
        return Err("could not derive a valid slug".into());
    }
    let slug = dedup_slug(base, seen);

    // Connectable iff a remote streamable-http/http endpoint exists; else a
    // reference-only card with the website (or first remote) as informational.
    let remote = s.remotes.iter().find(|r| {
        matches!(r.kind.as_str(), "streamable-http" | "http") && !r.url.trim().is_empty()
    });
    let (transport, url) = match remote {
        Some(r) => (
            "streamable_http".to_string(),
            Some(r.url.trim().to_string()),
        ),
        None => (
            "rest_action".to_string(),
            s.website_url
                .as_deref()
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .or_else(|| {
                    s.remotes
                        .first()
                        .map(|r| r.url.trim().to_string())
                        .filter(|x| !x.is_empty())
                }),
        ),
    };

    let egress: Vec<String> = url.as_deref().and_then(host_of).into_iter().collect();
    let tool_hints = default_tool_hints(&slug);
    let status = registry_status(&e.meta).map(str::to_string);

    Ok(CatalogRow {
        slug,
        name,
        description,
        categories: Vec::new(), // Registry has no category taxonomy
        url,
        transport,
        // auth is decided at Connect by the non-committing probe (plan O3);
        // importing 'none' keeps us honest instead of guessing at import time.
        auth_mode: "none".to_string(),
        auth_hints: json!({}),
        scopes: Vec::new(),
        egress,
        tool_hints,
        source: "mcp-registry",
        source_ref: source_ref.to_string(),
        upstream_id: s.name.clone(),
        status,
    })
}

// ─── open-connector → rows (always reference-only) ────────────────────────

/// Map open-connector providers to reference-only rows, dropping any whose slug
/// the Registry already covers (Registry wins — plan D6).
pub fn transform_open_connector(
    mut providers: Vec<OcProvider>,
    sha: &str,
    seen: &mut BTreeSet<String>,
    registry_slugs: &BTreeSet<String>,
) -> TransformOutput {
    providers.sort_by(|a, b| a.service.cmp(&b.service));
    let mut out = TransformOutput::default();
    for p in &providers {
        match map_oc_provider(p, sha, seen, registry_slugs) {
            Ok(row) => out.rows.push(row),
            Err(reason) => out.dropped.push(DropReason {
                service: p.service.clone(),
                reason,
            }),
        }
    }
    out
}

fn map_oc_provider(
    p: &OcProvider,
    sha: &str,
    seen: &mut BTreeSet<String>,
    registry_slugs: &BTreeSet<String>,
) -> Result<CatalogRow, String> {
    let name = p
        .display_name
        .clone()
        .unwrap_or_else(|| p.service.clone())
        .trim()
        .to_string();
    if name.is_empty() {
        return Err("provider has no usable name".into());
    }
    lint_text("name", &name)?;

    let description = match p.description.as_deref().map(str::trim) {
        Some(d) if !d.is_empty() => {
            lint_text("description", d)?;
            Some(d.to_string())
        }
        _ => None,
    };

    let mut categories = Vec::new();
    for c in &p.categories {
        lint_text("category", c)?;
        let c = c.trim();
        if !c.is_empty() {
            categories.push(c.to_string());
        }
    }

    let auth_mode = resolve_auth_mode(p).ok_or("no resolvable auth_mode")?;

    let mut base = slugify(&p.service);
    if !valid_slug(&base) {
        base = slugify(&name);
    }
    if !valid_slug(&base) {
        return Err("could not derive a valid slug".into());
    }
    // Registry-wins dedup (plan D6): a real MCP server for this slug beats a
    // REST-only card, so drop rather than suffix.
    if registry_slugs.contains(&base) {
        return Err("superseded by an MCP Registry entry for the same slug".into());
    }
    let slug = dedup_slug(base, seen);

    // open-connector providers are REST-API Actions — never a hosted MCP
    // endpoint — so they are ALWAYS reference-only (plan §4.2).
    let url = p
        .homepage_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let auth_hints = match auth_mode {
        "api_key" => {
            let mut h = json!({ "scheme": "Bearer" });
            if let Some(ph) = p
                .auth
                .iter()
                .find_map(|a| a.get("placeholder").and_then(Value::as_str))
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if lint_text("placeholder", ph).is_ok() {
                    h["placeholder"] = json!(ph);
                }
            }
            h
        }
        _ => json!({}),
    };

    let mut scope_set: BTreeSet<String> = BTreeSet::new();
    for a in &p.actions {
        for s in &a.required_scopes {
            let s = s.trim();
            if !s.is_empty() {
                scope_set.insert(s.to_string());
            }
        }
    }
    let scopes: Vec<String> = scope_set.into_iter().collect();
    let egress: Vec<String> = url.as_deref().and_then(host_of).into_iter().collect();
    let tool_hints = default_tool_hints(&slug);

    Ok(CatalogRow {
        slug,
        name,
        description,
        categories,
        url,
        transport: "rest_action".to_string(),
        auth_mode: auth_mode.to_string(),
        auth_hints,
        scopes,
        egress,
        tool_hints,
        source: "open-connector",
        source_ref: sha.to_string(),
        upstream_id: p.service.clone(),
        status: None,
    })
}

/// Map open-connector's auth vocabulary onto the catalog's. `custom_credential`
/// (Sentry/Atlassian-style header shapes) is a static secret → `api_key`.
/// None ⇒ nothing declared ⇒ drop the provider (plan §5).
fn resolve_auth_mode(p: &OcProvider) -> Option<&'static str> {
    let raw = p
        .auth
        .iter()
        .find_map(|a| a.get("type").and_then(Value::as_str))
        .or_else(|| p.auth_types.first().map(String::as_str))?;
    match raw {
        "no_auth" => Some("none"),
        "api_key" | "custom_credential" => Some("api_key"),
        "oauth2" => Some("oauth"),
        _ => None,
    }
}

/// The coarse, DISPLAY-ONLY policy-default seed every imported card gets: reads
/// (get/list/search) default allow, everything else defaults approve. Identical
/// shape to the curated seeds — and the gate never reads it (plan §4.3).
fn default_tool_hints(slug: &str) -> Value {
    json!([
        { "pattern": format!("mcp__{slug}__*get*"), "action": "allow", "note": "read" },
        { "pattern": format!("mcp__{slug}__*list*"), "action": "allow", "note": "read" },
        { "pattern": format!("mcp__{slug}__*search*"), "action": "allow", "note": "read" },
        { "pattern": format!("mcp__{slug}__*"), "action": "approve", "note": "writes should ask" },
    ])
}

/// Best-effort host extraction (dep-free — a url crate has no place in a build
/// tool). Strips scheme, path, userinfo, and port.
fn host_of(url: &str) -> Option<String> {
    let after = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = after.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    let host = host.trim().trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

// ─── slug helpers (same rules as catalog.rs — mcp__<alias>__<tool> parsing) ─

/// 1-64 chars of `[a-z0-9-]`, leading alnum (no leading hyphen, no underscore).
fn valid_slug(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Slugify to `[a-z0-9-]`, collapsing runs of other chars to a single hyphen
/// and capping length to leave room for a `-N` dedup suffix.
fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for c in s.chars() {
        let lc = c.to_ascii_lowercase();
        if lc.is_ascii_lowercase() || lc.is_ascii_digit() {
            out.push(lc);
            prev_dash = false;
        } else if !out.is_empty() && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed: String = out.trim_matches('-').chars().take(58).collect();
    trimmed.trim_end_matches('-').to_string()
}

/// Reserve a unique slug in the batch, appending `-2`, `-3`, … on collision.
fn dedup_slug(base: String, seen: &mut BTreeSet<String>) -> String {
    if seen.insert(base.clone()) {
        return base;
    }
    for n in 2..10_000u32 {
        let cand = format!("{base}-{n}");
        if cand.len() <= 64 && seen.insert(cand.clone()) {
            return cand;
        }
    }
    base
}

// ─── SQL emission ─────────────────────────────────────────────────────────

/// Emit the deterministic, append-only import migration. Same rows + same pins →
/// byte-identical SQL: no clock is baked in (`imported_at` is `now()` at APPLY).
pub fn emit_migration(rows: &[CatalogRow], pins: &Pins) -> String {
    let mut out = header(rows, pins);
    if rows.is_empty() {
        out.push_str("-- (no entries survived screening — nothing to import)\n");
        return out;
    }
    out.push_str(
        "insert into connector_catalog\n  \
         (slug, name, icon, description, categories, tier, url, transport,\n   \
         auth_mode, auth_hints, scopes, egress, tool_hints, provenance)\nvalues\n",
    );
    for (i, r) in rows.iter().enumerate() {
        let sep = if i + 1 < rows.len() { "," } else { "" };
        out.push_str(&format!("  ({}){sep}\n", row_values(r)));
    }
    out.push_str(ON_CONFLICT);
    out
}

fn header(rows: &[CatalogRow], pins: &Pins) -> String {
    let reg = rows.iter().filter(|r| r.source == "mcp-registry").count();
    let oc = rows.iter().filter(|r| r.source == "open-connector").count();
    let reg_ref = pins.registry_ref.as_deref().unwrap_or("n/a");
    let oc_sha = pins.open_connector_sha.as_deref().unwrap_or("n/a");
    format!(
        "-- GENERATED by `just catalog-import` — do not edit by hand.\n\
         -- Connector-catalog bulk import: UNTRUSTED, community-tier reference rows.\n\
         -- Plan: docs/superpowers/plans/2026-07-14-connector-catalog-bulk-import.md (rev 2).\n\
         --\n\
         -- Sources (both Apache-2.0; see NOTICE):\n\
         --   MCP Registry (modelcontextprotocol/registry) — {reg} rows, pinned {reg_ref}\n\
         --     streamable-http remotes import connectable; packaged-only import reference-only.\n\
         --   open-connector (oomol-lab/open-connector) — {oc} rows, pinned {oc_sha}\n\
         --     REST-API providers; always reference-only (transport='rest_action').\n\
         --\n\
         -- Every row is tier='community' and provenance-tagged with its source + upstream id.\n\
         -- The upsert ONLY refreshes rows whose provenance.source is an import source, so it\n\
         -- can never clobber a hand-curated fluidbox seed or a user's custom entry. Registry\n\
         -- entries win a slug over open-connector (a real MCP server beats a REST-only card).\n\
         -- Determinism: same pins → identical SQL (imported_at is now() at APPLY).\n\n"
    )
}

fn row_values(r: &CatalogRow) -> String {
    format!(
        "{slug}, {name}, null, {desc}, {cats}, 'community', {url}, {transport}, \
         {auth_mode}, {hints}, {scopes}, {egress}, {tool_hints}, {prov}",
        slug = sql_str(&r.slug),
        name = sql_str(&r.name),
        desc = opt_str(r.description.as_deref()),
        cats = jsonb(&json!(r.categories)),
        url = opt_str(r.url.as_deref()),
        transport = sql_str(&r.transport),
        auth_mode = sql_str(&r.auth_mode),
        hints = jsonb(&r.auth_hints),
        scopes = jsonb(&json!(r.scopes)),
        egress = jsonb(&json!(r.egress)),
        tool_hints = jsonb(&r.tool_hints),
        prov = provenance_expr(r),
    )
}

/// `imported_at` is `now()` at apply time (never generation time) so the file
/// stays reproducible; the rest is a literal reconstruction from the source.
fn provenance_expr(r: &CatalogRow) -> String {
    let mut parts = format!(
        "'source',{}, 'source_ref',{}, 'upstream_id',{}",
        sql_str(r.source),
        sql_str(&r.source_ref),
        sql_str(&r.upstream_id),
    );
    if let Some(st) = &r.status {
        parts.push_str(&format!(", 'status',{}", sql_str(st)));
    }
    parts.push_str(", 'imported_at',now()");
    format!("jsonb_build_object({parts})")
}

const ON_CONFLICT: &str = "\
on conflict (slug) do update set
  name = excluded.name, icon = excluded.icon, description = excluded.description,
  categories = excluded.categories, tier = excluded.tier, url = excluded.url,
  transport = excluded.transport, auth_mode = excluded.auth_mode,
  auth_hints = excluded.auth_hints, scopes = excluded.scopes,
  egress = excluded.egress, tool_hints = excluded.tool_hints,
  provenance = excluded.provenance, updated_at = now()
where connector_catalog.provenance->>'source' in ('mcp-registry', 'open-connector');
";

fn sql_str(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn opt_str(o: Option<&str>) -> String {
    match o {
        Some(s) => sql_str(s),
        None => "null".to_string(),
    }
}

fn jsonb(v: &Value) -> String {
    format!(
        "{}::jsonb",
        sql_str(&serde_json::to_string(v).unwrap_or_default())
    )
}

#[cfg(test)]
mod tests;
