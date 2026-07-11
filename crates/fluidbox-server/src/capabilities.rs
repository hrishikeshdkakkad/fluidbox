//! Capability-bundle registry (design §3.6/§8): versioned, append-only
//! bundles of MCP servers. Registration is where the PHOTOGRAPH happens —
//! brokered servers are discovered (tools/list) right here, sandbox servers
//! declare their tools — and where the poison screen runs (fluidbox-core
//! lint: control/zero-width/bidi characters are rejected outright).

use crate::auth::Admin;
use crate::broker;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use fluidbox_core::capability::{
    definition_digest, tools_digest, CapabilityBundleDef, CapabilityServer,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

fn valid_bundle_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    // '@' is the version separator in attachment refs ("name@2"); keep it
    // (and anything exotic) out of the name itself.
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase() | bytes[0].is_ascii_digit()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

#[derive(Deserialize)]
pub struct CreateBundle {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub servers: Vec<CapabilityServer>,
}

/// `POST /v1/capabilities` — register a bundle version. Publishing the same
/// name again appends version max+1; existing rows (and every RunSpec that
/// froze them) never change.
pub async fn create(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<CreateBundle>,
) -> ApiResult<Json<Value>> {
    let name = req.name.trim();
    if !valid_bundle_name(name) {
        return Err(ApiError::BadRequest(
            "bundle name must be 1-64 chars of [a-z0-9_-]".into(),
        ));
    }
    let mut def = CapabilityBundleDef {
        servers: req.servers,
    };
    // Brokered tools are DISCOVERED, never declared — a registrant-supplied
    // list would be a photograph of nothing.
    for server in &def.servers {
        if server.is_brokered() && !server.tools().is_empty() {
            return Err(ApiError::BadRequest(format!(
                "brokered server '{}' must not declare tools — they are discovered (photographed) at registration",
                server.name()
            )));
        }
    }
    // Structural validation first (aliases, sandbox declarations, lint)…
    def.validate().map_err(ApiError::BadRequest)?;
    // …then the photograph: connect to each brokered server with its sealed
    // credential and freeze what tools/list returns.
    for server in &mut def.servers {
        if server.is_brokered() {
            let tools = broker::photograph_brokered(&state, server).await?;
            let CapabilityServer::Brokered { tools: slot, .. } = server else {
                unreachable!()
            };
            *slot = tools;
        }
    }
    // Re-validate with the discovered snapshots in place: the remote server
    // is untrusted input — its tool names/descriptions pass the same
    // charset + poison screen as declared ones.
    def.validate().map_err(|e| {
        ApiError::BadRequest(format!("discovered tool snapshot failed validation: {e}"))
    })?;

    let digest = definition_digest(&def);
    let row = fluidbox_db::create_capability_bundle(
        &state.pool,
        state.tenant_id,
        name,
        req.description.as_deref(),
        &serde_json::to_value(&def)?,
        &digest,
    )
    .await?;
    Ok(Json(bundle_json(&row)))
}

pub async fn list(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let rows = fluidbox_db::list_capability_bundles(&state.pool, state.tenant_id).await?;
    let bundles: Vec<Value> = rows.iter().map(summary_json).collect();
    Ok(Json(json!({ "bundles": bundles })))
}

pub async fn get(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let row = fluidbox_db::get_capability_bundle(&state.pool, id)
        .await?
        .filter(|b| b.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    Ok(Json(bundle_json(&row)))
}

/// Full bundle + per-server tool digests (the SEP-1766-style integrity
/// anchor operators can compare out of band).
fn bundle_json(row: &fluidbox_db::CapabilityBundleRow) -> Value {
    let servers = serde_json::from_value::<CapabilityBundleDef>(row.definition.clone())
        .map(|def| {
            def.servers
                .iter()
                .map(|s| {
                    json!({
                        "name": s.name(),
                        "class": s.class_str(),
                        "tool_count": s.tools().len(),
                        "tools_digest": tools_digest(s.tools()),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({ "bundle": row, "servers": servers })
}

fn summary_json(row: &fluidbox_db::CapabilityBundleRow) -> Value {
    let (server_count, tool_count, classes) =
        match serde_json::from_value::<CapabilityBundleDef>(row.definition.clone()) {
            Ok(def) => (
                def.servers.len(),
                def.servers.iter().map(|s| s.tools().len()).sum::<usize>(),
                def.servers
                    .iter()
                    .map(|s| s.class_str().to_string())
                    .collect::<Vec<_>>(),
            ),
            Err(_) => (0, 0, vec![]),
        };
    json!({
        "id": row.id,
        "name": row.name,
        "version": row.version,
        "description": row.description,
        "definition_digest": row.definition_digest,
        "server_count": server_count,
        "tool_count": tool_count,
        "classes": classes,
        "created_at": row.created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_names_reject_ref_separators_and_junk() {
        assert!(valid_bundle_name("github-tools"));
        assert!(valid_bundle_name("kb_tools2"));
        assert!(!valid_bundle_name("name@2")); // '@' is the version separator
        assert!(!valid_bundle_name("Name"));
        assert!(!valid_bundle_name(""));
        assert!(!valid_bundle_name("-x"));
        assert!(!valid_bundle_name(&"x".repeat(65)));
    }
}
