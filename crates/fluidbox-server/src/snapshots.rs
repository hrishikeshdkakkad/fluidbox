//! Connection tool snapshots (Phase C, design :298-343): the append-only
//! photograph of a brokered connection's `tools/list`. Registration used to
//! freeze brokered tools into a capability bundle; now each connection carries
//! its own versioned snapshots, and a run freezes the exact snapshot version its
//! binding resolved. The photograph forces a real MCP `initialize` so the
//! snapshot records a trustworthy negotiated protocol version (unlike the
//! stateless legacy path — survey A §2e).

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::rbac;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use fluidbox_core::capability::{tools_digest, ToolSnapshot};
use fluidbox_db::TenantScope;
use serde_json::{json, Value};
use uuid::Uuid;

/// Photograph a connection's brokered tool surface into a new append-only
/// snapshot. Loads the connection FRESH and requires it be `active` (the OAuth
/// callback photographs immediately after activation, so a fresh read already
/// sees the active row), forces a protocol-version negotiation via
/// `broker::discover_snapshot`, and stamps the connection's CURRENT
/// `authorization_generation` — so a later reconnect's generation bump leaves
/// this snapshot pinned to the generation it was taken under.
pub async fn photograph_connection(
    state: &AppState,
    scope: TenantScope,
    connection_id: Uuid,
    endpoint_url: &str,
) -> ApiResult<fluidbox_db::ConnectionToolSnapshotRow> {
    // Unfiltered read by design: this internal helper runs only AFTER a create
    // or a mutation authorization (`connection_for_mutation`) has established
    // authority — it photographs the row the caller already owns/created. Tenant is
    // known → scoped_tx (RLS: set the GUC). Read + insert take separate short txns
    // so the discovery HTTP round-trip below never holds a DB transaction open.
    let mut read_tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
    let conn = fluidbox_db::get_connection(&mut *read_tx, scope, connection_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    read_tx.commit().await?;
    if conn.status != "active" {
        return Err(ApiError::Conflict(format!(
            "connection is {} — only an active connection can be photographed",
            conn.status
        )));
    }
    // Discovery/upstream failures surface as BadRequest so the catalog/manual
    // rollback branches (which match BadRequest) render a clean message.
    let (protocol_version, tools) =
        crate::broker::discover_snapshot(state, scope, &conn, endpoint_url)
            .await
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let tools_json = serde_json::to_value(&tools)?;
    // R3.3: reject a surface whose SERIALIZED size exceeds the same 2 MiB ceiling
    // fluidbox-core enforces on bundle definitions — a snapshot is frozen into
    // every bound run's RunSpec jsonb. (The discovery rpc path also caps the
    // upstream Content-Length before buffering; full streaming caps are Phase E.)
    let serialized_len = tools_json.to_string().len();
    if serialized_len > fluidbox_core::capability::MAX_DEFINITION_BYTES {
        return Err(ApiError::BadRequest(format!(
            "discovered tool snapshot is {serialized_len} bytes serialized (max {}) — the server advertises too large a surface",
            fluidbox_core::capability::MAX_DEFINITION_BYTES
        )));
    }
    let digest = tools_digest(&tools);
    // The generation guard lives in the INSERT (it fires only when the connection
    // is still at `conn.authorization_generation`); a concurrent reconnect that
    // moved the generation, or a concurrent refresh that already took the next
    // version, both map to one actionable retry error (R1.7).
    let mut ins_tx = fluidbox_db::scoped_tx(&state.pool, scope).await?;
    let row = fluidbox_db::insert_connection_tool_snapshot(
        &mut *ins_tx,
        scope,
        conn.id,
        conn.authorization_generation,
        &protocol_version,
        &tools_json,
        &digest,
    )
    .await
    .map_err(map_snapshot_insert_err)?;
    ins_tx.commit().await?;
    Ok(row)
}

/// A snapshot INSERT can fail two ways that both mean "a concurrent
/// reauthorization/refresh moved things underneath discovery — retry" (R1.7):
/// `RowNotFound` (the generation guard saw the connection had already left the
/// captured generation) and a unique-violation on
/// (tenant, connection, snapshot_version) (a racing refresh already claimed the
/// next version). Everything else propagates unchanged.
fn map_snapshot_insert_err(e: sqlx::Error) -> ApiError {
    let stale = matches!(&e, sqlx::Error::RowNotFound)
        || e.as_database_error()
            .map(|d| d.is_unique_violation())
            .unwrap_or(false);
    if stale {
        ApiError::Conflict("connection was reauthorized during discovery — retry refresh".into())
    } else {
        ApiError::from(e)
    }
}

/// Wrap a photograph failure as a "connection rolled back" message. The
/// api_key/manual paths pass the credential-rejection lead-in (the e2e asserts
/// "rejected this credential"); other kinds pass through unchanged.
pub(crate) fn rolled_back(reason: &str, e: ApiError) -> ApiError {
    match e {
        ApiError::BadRequest(m) => {
            ApiError::BadRequest(format!("{reason} (connection rolled back): {m}"))
        }
        other => other,
    }
}

/// The dashboard projection of a snapshot — the latest tool surface WITHOUT
/// input schemas (mirroring `bundle_json`'s payload-weight rule; the digest is
/// the integrity anchor).
pub(crate) fn snapshot_json(row: &fluidbox_db::ConnectionToolSnapshotRow) -> Value {
    let tools: Vec<Value> = serde_json::from_value::<Vec<ToolSnapshot>>(row.tools_json.clone())
        .map(|ts| {
            ts.iter()
                .map(|t| json!({ "name": t.name, "description": t.description }))
                .collect()
        })
        .unwrap_or_default();
    json!({
        "version": row.snapshot_version,
        "protocol_version": row.protocol_version,
        "tools_digest": row.tools_digest,
        "discovered_at": row.discovered_at,
        "authorization_generation": row.authorization_generation,
        "tools": tools,
    })
}

/// Preference order for the MCP endpoint to (re-)photograph, given the metadata
/// and an already-resolved catalog-entry url. Pure so the ordering is unit
/// tested without a DB. Every connect branch now stores the exact endpoint it
/// used as `metadata.endpoint_url`, so that wins; then the catalog entry's url
/// (when `catalog_slug` still resolves, covering pre-`endpoint_url` rows); then
/// the audience-binding `metadata.base_url` itself.
fn resolve_endpoint(metadata: &Value, catalog_entry_url: Option<&str>) -> Option<String> {
    let field = |k: &str| {
        metadata
            .get(k)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    field("endpoint_url")
        .or_else(|| {
            catalog_entry_url
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .or_else(|| field("base_url"))
}

/// Resolve the endpoint to re-photograph for a connection, resolving the catalog
/// entry only when the stored `endpoint_url` is absent (avoids a needless read).
async fn refresh_endpoint_url(
    state: &AppState,
    scope: TenantScope,
    conn: &fluidbox_db::IntegrationConnectionRow,
) -> ApiResult<String> {
    let has_endpoint = conn
        .metadata
        .get("endpoint_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());
    let catalog_url = if has_endpoint {
        None
    } else if let Some(slug) = conn
        .metadata
        .get("catalog_slug")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        fluidbox_db::get_catalog_by_slug(&state.pool, scope, slug)
            .await?
            .and_then(|e| e.url)
    } else {
        None
    };
    resolve_endpoint(&conn.metadata, catalog_url.as_deref()).ok_or_else(|| {
        ApiError::BadRequest("connection has no MCP endpoint to photograph — reconnect it".into())
    })
}

/// `POST /v1/connections/{id}/tools/refresh` — re-photograph a connection's
/// tools into a new snapshot version. Authz (design :274-296): a personal
/// connection is owner-only (a non-owner 404s, invisibility preserved); an
/// organization connection needs `can_mutate_resources`. Both are enforced by
/// `connection_for_mutation`.
pub async fn refresh_tools(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let conn =
        crate::connections::connection_for_mutation(&state, &principal, id, "refreshing tools for")
            .await?;
    let scope = principal.scope();
    let endpoint = refresh_endpoint_url(&state, scope, &conn).await?;
    let snap = photograph_connection(&state, scope, conn.id, &endpoint).await?;
    Ok(Json(json!({ "snapshot": snapshot_json(&snap) })))
}

/// `GET /v1/connections/{id}/tools` — the connection's latest tool snapshot.
/// Owner-filtered: a personal connection's tools are visible only to its owner
/// (the visibility fetch returns None for a non-owner ⇒ 404).
pub async fn get_tools(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let scope = principal.scope();
    // Gate the snapshot read on connection visibility so another member's
    // personal tool surface can never be inspected.
    fluidbox_db::get_connection_visible(
        &state.pool,
        scope,
        id,
        rbac::connection_viewer(&principal),
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    let snap = fluidbox_db::latest_connection_tool_snapshot(&state.pool, scope, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "snapshot": snapshot_json(&snap) })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_preference_prefers_stored_then_catalog_then_base() {
        // 1. endpoint_url wins over everything.
        let meta = json!({ "endpoint_url": "https://h/mcp", "base_url": "https://h" });
        assert_eq!(
            resolve_endpoint(&meta, Some("https://h/catalog")).as_deref(),
            Some("https://h/mcp")
        );
        // 2. no endpoint_url → the resolved catalog entry url.
        let meta = json!({ "base_url": "https://h", "catalog_slug": "x" });
        assert_eq!(
            resolve_endpoint(&meta, Some("https://h/entry")).as_deref(),
            Some("https://h/entry")
        );
        // 3. no endpoint_url and no catalog url → base_url.
        let meta = json!({ "base_url": "https://h" });
        assert_eq!(resolve_endpoint(&meta, None).as_deref(), Some("https://h"));
        // Empty strings are skipped, not preferred.
        let meta = json!({ "endpoint_url": "  ", "base_url": "https://h" });
        assert_eq!(
            resolve_endpoint(&meta, Some("")).as_deref(),
            Some("https://h")
        );
        // Nothing usable → None (the caller fails closed).
        assert_eq!(resolve_endpoint(&json!({}), None), None);
    }
}
