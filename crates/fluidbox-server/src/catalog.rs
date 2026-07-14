//! The connector catalog (Phase 5.5, increment 1): a curated, user-selectable
//! menu over the Phase-5 seams. A catalog entry is UNTRUSTED reference data —
//! a superset of the MCP registry's server.json; its tool_hints are
//! policy-default seeds for display, never enforcement.
//!
//! Settled 2026-07-11: the catalog is API-only (rows seeded by migration
//! 0007, managed here — no seed file, no boot sync), and Connect
//! AUTO-REGISTERS the capability bundle:
//!   none    → register + photograph immediately (in-image sandbox launch
//!             or credential-free remote)
//!   api_key → seal the pasted secret into an mcp_http connection (custom
//!             header/scheme from auth_hints) + photograph with it — a
//!             rejected credential rolls the connection back
//!   oauth   → pending connection + the oauth.rs dance; the callback
//!             photographs with the freshly minted access token

use crate::auth::Admin;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use fluidbox_core::capability::{CapabilityServer, ToolSnapshot};
use serde::Deserialize;
use serde_json::{json, Value};

/// Slugs become the server alias AND the default bundle name, so they must
/// satisfy the strictest of the two charsets (alias: lowercase alnum +
/// hyphens, no underscores — `mcp__<alias>__<tool>` must parse).
fn valid_slug(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Whether pressing Connect on an entry can succeed under today's model.
/// `rest_action` entries (imported open-connector providers) are REFERENCE-ONLY
/// — a browsable card with no hosted MCP endpoint to photograph — so Connect is
/// refused until the deferred REST action executor lands (bulk-import plan D3).
/// Everything else (streamable_http remote, stdio in-image) connects normally.
fn is_connectable(transport: &str) -> bool {
    transport != "rest_action"
}

/// List entries DECORATED with their live state — which non-revoked
/// connection already covers the entry (matched by exact base_url) and the
/// latest bundle named after the slug. Pure presentation derivation, done
/// server-side so the dashboard stays logic-free; overridden bundle names
/// deliberately don't count as "this entry's bundle".
pub async fn list(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let rows = fluidbox_db::list_catalog(&state.pool).await?;
    let conns = fluidbox_db::list_connections(&state.pool, state.tenant_id).await?;
    let bundles = fluidbox_db::list_capability_bundles(&state.pool, state.tenant_id).await?;
    let connectors: Vec<Value> = rows
        .iter()
        .map(|r| {
            let mut v = serde_json::to_value(r).unwrap_or_default();
            if let Some(o) = v.as_object_mut() {
                o.insert("connection".into(), entry_connection(r, &conns));
                o.insert("bundle".into(), entry_bundle(r, &bundles));
                // Derived server-side so the Store can badge reference-only
                // cards without embedding any logic in the dashboard.
                o.insert("connectable".into(), json!(is_connectable(&r.transport)));
            }
            v
        })
        .collect();
    Ok(Json(json!({ "connectors": connectors })))
}

/// The connection that covers this entry: same base_url, not revoked;
/// active beats error beats pending, newest wins within a class
/// (list_connections is created_at-descending and min_by_key keeps the
/// first minimum).
fn entry_connection(
    entry: &fluidbox_db::ConnectorCatalogRow,
    conns: &[fluidbox_db::IntegrationConnectionRow],
) -> Value {
    let Some(url) = entry.url.as_deref() else {
        return Value::Null;
    };
    conns
        .iter()
        .filter(|c| {
            c.provider == "mcp_http"
                && c.status != "revoked"
                && c.metadata.get("base_url").and_then(Value::as_str) == Some(url)
        })
        .min_by_key(|c| match c.status.as_str() {
            "active" => 0,
            "error" => 1,
            _ => 2,
        })
        .map(|c| json!({ "id": c.id, "status": c.status, "auth_kind": c.auth_kind }))
        .unwrap_or(Value::Null)
}

fn entry_bundle(
    entry: &fluidbox_db::ConnectorCatalogRow,
    bundles: &[fluidbox_db::CapabilityBundleRow],
) -> Value {
    // list_capability_bundles orders by (name, version desc) — the first
    // slug match is the latest version.
    bundles
        .iter()
        .find(|b| b.name == entry.slug)
        .map(|b| json!({ "id": b.id, "name": b.name, "version": b.version }))
        .unwrap_or(Value::Null)
}

pub async fn get(
    _: Admin,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> ApiResult<Json<Value>> {
    let row = fluidbox_db::get_catalog_by_slug(&state.pool, &slug)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "connector": row })))
}

#[derive(Deserialize)]
pub struct CreateEntry {
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub categories: Option<Value>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub auth_mode: Option<String>,
    #[serde(default)]
    pub auth_hints: Option<Value>,
    #[serde(default)]
    pub scopes: Option<Value>,
    #[serde(default)]
    pub egress: Option<Value>,
    #[serde(default)]
    pub tool_hints: Option<Value>,
    #[serde(default)]
    pub sandbox_launch: Option<Value>,
}

/// `POST /v1/catalog` — add a CUSTOM entry (the tier is forced server-side;
/// verified/community are curation judgements the API cannot self-award).
pub async fn create(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<CreateEntry>,
) -> ApiResult<Json<Value>> {
    let row = create_entry_row(&state, &req).await?;
    Ok(Json(json!({ "connector": row })))
}

/// Shared body of `POST /v1/catalog` — validates a custom-entry request and
/// inserts the (tier-forced-custom) row. Reused by the one-shot BYO flow
/// (`add_custom`) so a pasted URL and a raw catalog POST land identically.
async fn create_entry_row(
    state: &AppState,
    req: &CreateEntry,
) -> ApiResult<fluidbox_db::ConnectorCatalogRow> {
    let slug = req.slug.trim();
    if !valid_slug(slug) {
        return Err(ApiError::BadRequest(
            "slug must be 1-64 chars of [a-z0-9-] (it becomes the server alias and bundle name)"
                .into(),
        ));
    }
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    let transport = req.transport.as_deref().unwrap_or("streamable_http");
    let auth_mode = req.auth_mode.as_deref().unwrap_or("none");
    if !matches!(auth_mode, "none" | "api_key" | "oauth") {
        return Err(ApiError::BadRequest(
            "auth_mode must be none, api_key, or oauth".into(),
        ));
    }
    match transport {
        "streamable_http" => {
            let url = req.url.as_deref().map(str::trim).unwrap_or_default();
            let parsed = reqwest::Url::parse(url)
                .map_err(|_| ApiError::BadRequest("a valid http(s) url is required".into()))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(ApiError::BadRequest("url must be http(s)".into()));
            }
        }
        "stdio" => {
            let ok = req
                .sandbox_launch
                .as_ref()
                .and_then(|l| {
                    let cmd = l.get("command")?.as_str()?;
                    let tools = l.get("tools")?.as_array()?;
                    Some(!cmd.is_empty() && !tools.is_empty())
                })
                .unwrap_or(false);
            if !ok {
                return Err(ApiError::BadRequest(
                    "stdio entries need sandbox_launch {command, args?, tools[]}".into(),
                ));
            }
            if auth_mode != "none" {
                return Err(ApiError::BadRequest(
                    "stdio (in-image) entries are credential-free by construction — auth_mode must be none".into(),
                ));
            }
        }
        other => {
            return Err(ApiError::BadRequest(format!(
                "transport '{other}' is not supported (streamable_http | stdio)"
            )));
        }
    }
    if fluidbox_db::get_catalog_by_slug(&state.pool, slug)
        .await?
        .is_some()
    {
        return Err(ApiError::Conflict(format!(
            "catalog slug '{slug}' already exists"
        )));
    }
    let row = fluidbox_db::create_catalog_entry(
        &state.pool,
        slug,
        name,
        req.icon.as_deref(),
        req.description.as_deref(),
        req.categories.as_ref().unwrap_or(&json!([])),
        req.url.as_deref().map(str::trim),
        transport,
        auth_mode,
        req.auth_hints.as_ref().unwrap_or(&json!({})),
        req.scopes.as_ref().unwrap_or(&json!([])),
        req.egress.as_ref().unwrap_or(&json!([])),
        req.tool_hints.as_ref().unwrap_or(&json!([])),
        req.sandbox_launch.as_ref(),
    )
    .await?;
    Ok(row)
}

#[derive(Deserialize)]
pub struct ConnectReq {
    #[serde(default)]
    pub display_name: Option<String>,
    /// api_key entries: the raw secret (for Basic-composite connectors,
    /// paste `email:api_token` — see the entry's auth_hints).
    #[serde(default)]
    pub token: Option<String>,
    /// Bundle name override (defaults to the slug). Re-connecting publishes
    /// the next version — the registry stays append-only.
    #[serde(default)]
    pub bundle_name: Option<String>,
    /// oauth entries: optional pre-registered client identity (confidential
    /// clients supply both; the secret is sealed and never returned).
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

/// `POST /v1/catalog/{slug}/connect` — settle #4: one click from catalog
/// entry to attachable bundle, branched on the entry's auth_mode.
pub async fn connect(
    _: Admin,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(req): Json<ConnectReq>,
) -> ApiResult<Json<Value>> {
    let entry = fluidbox_db::get_catalog_by_slug(&state.pool, &slug)
        .await?
        .ok_or(ApiError::NotFound)?;
    connect_entry(&state, entry, req).await
}

/// The three-branch connect body (none / api_key / oauth), factored out of the
/// HTTP handler so the one-shot BYO flow (`add_custom`) drives the identical
/// path: connection creation, credential rollback on photograph failure, the
/// photograph, and the OAuth dance all live here unchanged.
async fn connect_entry(
    state: &AppState,
    entry: fluidbox_db::ConnectorCatalogRow,
    req: ConnectReq,
) -> ApiResult<Json<Value>> {
    // Reference-only rows (imported open-connector providers) have no hosted
    // MCP endpoint to photograph — refuse Connect with a clear message rather
    // than manufacture a broken bundle (bulk-import plan D3). This mirrors
    // open-connector's own catalogOnly vs locallyExecutable split.
    if !is_connectable(&entry.transport) {
        return Err(ApiError::BadRequest(
            "this connector is reference-only (imported catalog entry); a REST \
             action executor is required to connect it — not yet available"
                .into(),
        ));
    }
    let bundle_name = req
        .bundle_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&entry.slug)
        .to_string();

    match entry.auth_mode.as_str() {
        "none" => {
            let server = authless_server(&entry)?;
            let row = crate::capabilities::register_bundle(
                state,
                &bundle_name,
                entry.description.as_deref(),
                vec![server],
            )
            .await?;
            Ok(Json(crate::capabilities::bundle_json(&row)))
        }
        "api_key" => {
            let url = entry
                .url
                .as_deref()
                .ok_or_else(|| ApiError::BadRequest("catalog entry has no url".into()))?;
            let token = req.token.as_deref().map(str::trim).unwrap_or_default();
            if token.is_empty() {
                return Err(ApiError::BadRequest(
                    "token is required to connect this entry (see its auth_hints)".into(),
                ));
            }
            // Ride the existing mcp_http static path — header/scheme come
            // from the entry's auth_hints (Sentry's custom header, Atlassian
            // Basic) unless the caller overrides nothing here by design.
            let create = crate::connections::CreateConnection {
                provider: "mcp_http".into(),
                token: Some(token.to_string()),
                app_id: None,
                installation_id: None,
                private_key: None,
                webhook_secret: None,
                display_name: Some(
                    req.display_name
                        .clone()
                        .unwrap_or_else(|| entry.name.clone()),
                ),
                base_url: Some(url.to_string()),
                header_name: entry.auth_hints["header_name"].as_str().map(str::to_string),
                scheme: entry.auth_hints["scheme"].as_str().map(str::to_string),
                auth_kind: Some("static".into()),
                scopes: None,
                client_id: None,
                client_secret: None,
            };
            let created = crate::connections::create_mcp_http_connection(state, create).await?;
            let connection_id = created.id;
            let server = CapabilityServer::Brokered {
                name: entry.slug.clone(),
                url: url.to_string(),
                connection_id: Some(connection_id),
                identity: None,
                tools: Vec::new(),
            };
            match crate::capabilities::register_bundle(
                state,
                &bundle_name,
                entry.description.as_deref(),
                vec![server],
            )
            .await
            {
                Ok(row) => {
                    // Return the photographed servers/tools too so the wizard's
                    // success screen can show what was discovered.
                    let bj = crate::capabilities::bundle_json(&row);
                    Ok(Json(json!({
                        "connection": created,
                        "bundle": bj["bundle"],
                        "servers": bj["servers"],
                    })))
                }
                Err(e) => {
                    // The photograph is the credential's proof-of-life; a
                    // refused key must not leave a dangling connection.
                    fluidbox_db::revoke_connection(&state.pool, connection_id)
                        .await
                        .ok();
                    Err(match e {
                        ApiError::BadRequest(m) => ApiError::BadRequest(format!(
                            "the server rejected this credential (connection rolled back): {m}"
                        )),
                        other => other,
                    })
                }
            }
        }
        "oauth" => {
            let url = entry
                .url
                .as_deref()
                .ok_or_else(|| ApiError::BadRequest("catalog entry has no url".into()))?;
            let sealer = state.sealer.as_ref().ok_or_else(|| {
                ApiError::BadRequest(
                    "OAuth connections are disabled: set FLUIDBOX_CREDENTIAL_KEY".into(),
                )
            })?;
            let resource = crate::oauth::canonical_resource(url).map_err(ApiError::BadRequest)?;
            // Scopes: catalog seed ∪ caller extras.
            let mut scopes: Vec<String> = entry
                .scopes
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            for s in req.scopes.clone().unwrap_or_default() {
                if !scopes.contains(&s) {
                    scopes.push(s);
                }
            }
            let mut oauth = json!({
                "resource": resource,
                "scopes": scopes,
                "pending_bundle": { "name": bundle_name, "url": url },
                "catalog_slug": entry.slug,
            });
            if let Some(cid) = req
                .client_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                oauth["client_id"] = json!(cid);
                oauth["client_id_source"] = json!("preregistered");
            }
            let sealed_secret = req
                .client_secret
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| sealer.seal(s));
            let host = reqwest::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .unwrap_or_else(|| "mcp".into());
            let row = fluidbox_db::create_connection(
                &state.pool,
                state.tenant_id,
                "mcp_http",
                &host,
                req.display_name.as_deref().unwrap_or(&entry.name),
                None,
                &json!([]),
                &json!({}),
                &json!({ "base_url": url }),
                None,
                fluidbox_db::ConnectionAuth {
                    auth_kind: "oauth",
                    status: "pending",
                    oauth: Some(&oauth),
                    client_secret_sealed: sealed_secret.as_deref(),
                    registration_id: None,
                },
            )
            .await?;
            let authorize_url = crate::oauth::start_dance(state, row.id).await?;
            Ok(Json(json!({
                "connection": row,
                "authorize_url": authorize_url,
            })))
        }
        other => Err(ApiError::BadRequest(format!(
            "catalog entry has unsupported auth_mode '{other}'"
        ))),
    }
}

/// Build the server for an authless entry: in-image stdio launch (declared
/// tools) or a credential-free remote (photographed without a connection).
fn authless_server(entry: &fluidbox_db::ConnectorCatalogRow) -> ApiResult<CapabilityServer> {
    if let Some(launch) = &entry.sandbox_launch {
        let command = launch["command"]
            .as_str()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| ApiError::BadRequest("catalog sandbox_launch has no command".into()))?
            .to_string();
        let args: Vec<String> = launch["args"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        let tools: Vec<ToolSnapshot> = serde_json::from_value(launch["tools"].clone())
            .map_err(|e| ApiError::BadRequest(format!("catalog sandbox_launch tools: {e}")))?;
        return Ok(CapabilityServer::Sandbox {
            name: entry.slug.clone(),
            command,
            args,
            identity: None,
            tools,
        });
    }
    let url = entry.url.as_deref().ok_or_else(|| {
        ApiError::BadRequest("catalog entry has neither url nor sandbox_launch".into())
    })?;
    Ok(CapabilityServer::Brokered {
        name: entry.slug.clone(),
        url: url.to_string(),
        connection_id: None,
        identity: None,
        tools: Vec::new(),
    })
}

// ─── Bring-your-own-MCP: probe + one-shot connect ─────────────────────────

#[derive(Deserialize)]
pub struct ProbeReq {
    pub url: String,
}

/// `POST /v1/mcp/probe` — NON-COMMITTING auth + tool detection for a pasted
/// MCP URL. Persists nothing and sends no secret. Credential-free discovery
/// distinguishes an authless server (tools come back — display-only preview)
/// from one that wants a credential (401); on 401 we walk `oauth::discover`
/// to tell OAuth from a static API key. Ambiguity (a server that accepts
/// both) is surfaced via `oauth_available` + `static_possible` + `notes`,
/// never guessed silently.
pub async fn probe(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<ProbeReq>,
) -> ApiResult<Json<Value>> {
    let url = req.url.trim();
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| ApiError::BadRequest("a valid http(s) url is required".into()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ApiError::BadRequest("url must be http(s)".into()));
    }
    let mut notes: Vec<String> = Vec::new();
    match crate::broker::probe_tools(&state, url).await {
        crate::broker::ProbeOutcome::Tools(tools) => {
            // Display-only preview (capped at the core per-server tool cap of
            // 64); the authoritative photograph still runs at connect.
            let preview: Vec<Value> = tools
                .iter()
                .take(64)
                .map(|t| json!({ "name": t.name, "description": t.description }))
                .collect();
            Ok(Json(json!({
                "url": url,
                "transport": "streamable_http",
                "reachable": true,
                "auth_mode": "none",
                "oauth_available": false,
                "static_possible": false,
                "tools_preview": preview,
                "oauth": Value::Null,
                "auth_hints": {},
                "notes": notes,
            })))
        }
        crate::broker::ProbeOutcome::Unauthorized => {
            match crate::oauth::discover(&state, url).await {
                Ok(meta) => {
                    notes.push(
                    "This server also returned 401 to an anonymous request, so a static API key may work too — pick 'API key' instead if you have one.".into(),
                );
                    Ok(Json(json!({
                        "url": url,
                        "transport": "streamable_http",
                        "reachable": true,
                        "auth_mode": "oauth",
                        "oauth_available": true,
                        "static_possible": true,
                        "tools_preview": [],
                        // Non-secret AS summary only — no client/registration material.
                        "oauth": {
                            "issuer": meta.issuer,
                            "authorization_endpoint": meta.authorization_endpoint,
                            "scopes_supported": meta.scopes_supported,
                        },
                        "auth_hints": {},
                        "notes": notes,
                    })))
                }
                Err(e) => {
                    notes.push(format!(
                    "No OAuth authorization server was discoverable ({e}); assuming a static API key."
                ));
                    Ok(Json(json!({
                        "url": url,
                        "transport": "streamable_http",
                        "reachable": true,
                        "auth_mode": "api_key",
                        "oauth_available": false,
                        "static_possible": true,
                        "tools_preview": [],
                        "oauth": Value::Null,
                        "auth_hints": { "scheme": "Bearer" },
                        "notes": notes,
                    })))
                }
            }
        }
        crate::broker::ProbeOutcome::Unreachable(msg) => {
            notes.push(msg);
            Ok(Json(json!({
                "url": url,
                "transport": "streamable_http",
                "reachable": false,
                "auth_mode": "api_key",
                "oauth_available": false,
                "static_possible": true,
                "tools_preview": [],
                "oauth": Value::Null,
                "auth_hints": { "scheme": "Bearer" },
                "notes": notes,
            })))
        }
    }
}

#[derive(Deserialize)]
pub struct AddCustomReq {
    pub url: String,
    pub name: String,
    /// none | api_key | oauth (default none).
    #[serde(default)]
    pub auth_mode: Option<String>,
    /// api_key: the raw secret (Basic-composite connectors: `email:api_token`).
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// api_key: custom header name (default `authorization`) + scheme
    /// (`Bearer` | `Basic` | "" for a bare token).
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub scheme: Option<String>,
    /// oauth: extra scopes + optional pre-registered client identity.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// `POST /v1/mcp/servers` — the one-shot "bring your own MCP server" flow: a
/// pasted URL becomes a `tier=custom` catalog entry AND is connected in one
/// call, reusing `create_entry_row` + `connect_entry` verbatim. For the
/// none/api_key branches a failed connect rolls the just-created entry back so
/// no orphan card survives; for oauth the entry MUST persist (the callback
/// re-fetches it by `catalog_slug` to auto-register the bundle).
pub async fn add_custom(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<AddCustomReq>,
) -> ApiResult<Json<Value>> {
    let url = req.url.trim();
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| ApiError::BadRequest("a valid http(s) url is required".into()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ApiError::BadRequest("url must be http(s)".into()));
    }
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    let auth_mode = req.auth_mode.as_deref().unwrap_or("none");
    if !matches!(auth_mode, "none" | "api_key" | "oauth") {
        return Err(ApiError::BadRequest(
            "auth_mode must be none, api_key, or oauth".into(),
        ));
    }
    let host = parsed.host_str().unwrap_or("mcp");
    let slug = derive_slug(&state, host, name).await?;

    // api_key custom header/scheme ride the entry's auth_hints — exactly the
    // shape connect_entry's api_key branch reads (Sentry's custom header etc.).
    let mut auth_hints = json!({});
    if auth_mode == "api_key" {
        if let Some(h) = req
            .header_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            auth_hints["header_name"] = json!(h);
        }
        // Scheme is tri-state and an EXPLICIT "" is meaningful (the Sentry
        // "bare token" shape), so only an ABSENT field falls through to the
        // Bearer default — never trim an empty string away. This mirrors
        // `create_mcp_http_connection`, which stores "" and defaults to
        // Bearer only when nothing is passed.
        if let Some(s) = req.scheme.as_deref().map(str::trim) {
            auth_hints["scheme"] = json!(s);
        }
    }

    let create = CreateEntry {
        slug: slug.clone(),
        name: name.to_string(),
        icon: req.icon.clone(),
        description: req.description.clone(),
        categories: None,
        url: Some(url.to_string()),
        transport: Some("streamable_http".into()),
        auth_mode: Some(auth_mode.to_string()),
        auth_hints: Some(auth_hints),
        scopes: Some(json!(req.scopes.clone().unwrap_or_default())),
        egress: None,
        tool_hints: None,
        sandbox_launch: None,
    };
    let entry = create_entry_row(&state, &create).await?;

    let connect_req = ConnectReq {
        display_name: req.display_name.clone(),
        token: req.token.clone(),
        bundle_name: None,
        client_id: req.client_id.clone(),
        client_secret: req.client_secret.clone(),
        scopes: req.scopes.clone(),
    };

    let with_slug = |mut out: Json<Value>| {
        if let Some(o) = out.0.as_object_mut() {
            o.insert("slug".into(), json!(slug));
        }
        out
    };

    // Every branch keeps the entry on SUCCESS (it becomes the custom Store
    // card; for OAuth the callback re-fetches it by slug to auto-register) and
    // rolls it back on FAILURE — including a failed OAuth dance (a discover /
    // insert / start_dance error means no callback is ever coming, so the
    // entry would otherwise orphan exactly like a refused api_key).
    match connect_entry(&state, entry, connect_req).await {
        Ok(out) => Ok(with_slug(out)),
        Err(e) => {
            if let Err(del) = fluidbox_db::delete_catalog_entry(&state.pool, &slug).await {
                tracing::warn!(
                    "BYO connect for '{slug}' failed ({e}); entry rollback also failed: {del}"
                );
            }
            Err(e)
        }
    }
}

/// Slugify to the strict alias/bundle charset (`[a-z0-9-]`, no underscores —
/// `mcp__<alias>__<tool>` must parse). Collapses runs of other chars to a
/// single hyphen and caps length to leave room for a dedup suffix.
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

/// Derive a UNIQUE catalog slug from the server name (host as fallback),
/// appending `-2`, `-3`, … on collision.
async fn derive_slug(state: &AppState, host: &str, name: &str) -> ApiResult<String> {
    let mut base = slugify(name);
    if !valid_slug(&base) {
        base = slugify(host);
    }
    if !valid_slug(&base) {
        base = "mcp-server".to_string();
    }
    for n in 0u32..1000 {
        let cand = if n == 0 {
            base.clone()
        } else {
            format!("{base}-{}", n + 1)
        };
        if valid_slug(&cand)
            && fluidbox_db::get_catalog_by_slug(&state.pool, &cand)
                .await?
                .is_none()
        {
            return Ok(cand);
        }
    }
    Err(ApiError::Conflict(
        "could not derive a unique slug for this server".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_rest_action_is_reference_only() {
        assert!(is_connectable("streamable_http"));
        assert!(is_connectable("stdio"));
        assert!(!is_connectable("rest_action"));
    }

    #[test]
    fn slugs_must_fit_alias_and_bundle_charsets() {
        assert!(valid_slug("github"));
        assert!(valid_slug("workspace-info"));
        assert!(valid_slug("a2"));
        assert!(!valid_slug("Under_Score")); // '_' breaks mcp__ parsing
        assert!(!valid_slug("-lead"));
        assert!(!valid_slug(""));
        assert!(!valid_slug("UPPER"));
        assert!(!valid_slug(&"x".repeat(65)));
    }

    #[test]
    fn slugify_produces_valid_slugs_without_underscores() {
        assert_eq!(slugify("My Cool Server"), "my-cool-server");
        assert_eq!(slugify("mcp.example.com"), "mcp-example-com");
        assert_eq!(slugify("Under_Score"), "under-score"); // '_' → hyphen, never kept
        assert_eq!(slugify("  --Trim!!--  "), "trim");
        assert_eq!(slugify("a__b___c"), "a-b-c"); // runs collapse
                                                  // A name of only punctuation slugifies to empty → caller falls back.
        assert_eq!(slugify("!!!"), "");
        // Every non-empty result is a valid alias/bundle slug.
        for s in ["My Cool Server", "mcp.example.com", "Under_Score", "123abc"] {
            let out = slugify(s);
            assert!(
                out.is_empty() || valid_slug(&out),
                "slugify({s:?}) = {out:?}"
            );
        }
        // Long input is capped with room left for a `-NN` dedup suffix.
        assert!(slugify(&"x".repeat(200)).len() <= 58);
    }
}
