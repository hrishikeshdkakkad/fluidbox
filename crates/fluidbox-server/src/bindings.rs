//! Binding resolution — the heart of Phase C (design §"Run resource binding",
//! `:391-463`; binding rules `:486-523`; invariants 6, 7, 21).
//!
//! Run creation resolves every requirement — brokered MCP tools, the git
//! workspace fetch, and each result-publish destination — to an authorized,
//! frozen [`ResolvedBinding`] BEFORE any model spend or sandbox provisioning.
//! `create_run` writes those bindings in the SAME transaction as the session
//! (Task 1's `create_session`), stamps their ids into the RunSpec, and from
//! then on the orchestrator, broker, and delivery worker consume the BINDING
//! ID — never a `connection_id` carried in user-controlled input (invariant 21).
//!
//! Fail-closed everywhere: an unresolvable or ambiguous requirement, a missing
//! or stale tool snapshot, a deactivated owner, or a credential named by a
//! caller who may not use it all REFUSE the run — never guess, never silently
//! narrow, never pick "the latest" connection (design `:498`).
//!
//! This module only ever reads (`state.pool`); it mints no credentials and
//! makes no upstream calls. The upstream rechecks (status + generation +
//! owner-membership at every credentialed use) are the consumers' job (Task 6).

use crate::error::ApiError;
use crate::state::AppState;
use fluidbox_core::capability::{
    tools_digest, BindingMode, ConnectionRequirement, FrozenBundle, ToolSnapshot,
};
use fluidbox_core::spec::{BrokeredSurface, ResultDestination, TrustTier, WorkspaceSpec};
use fluidbox_db::{
    ConnectionViewer, IntegrationConnectionRow, NewRunResourceBinding, TenantScope,
    TriggerSubscriptionRow,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

// ─── Resolved shapes (fixed by the Phase C plan Interfaces) ─────────────────

/// A binding's frozen authority source — the tagged union the design demands
/// (`:418-427`): a nullable `connection_id` cannot represent all three
/// legitimate cases.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedAuthority {
    /// An `integration_connections` grant, pinned to one `generation`.
    Connection {
        id: Uuid,
        generation: i32,
        owner_type: String,
        owner_user_id: Option<Uuid>,
    },
    /// A subscription-owned signing/callback secret (invariant 7 spans it too).
    SubscriptionSecret { id: Uuid, generation: i32 },
    /// Explicitly credentialless (public repo, open destination) — never an
    /// implicit missing value.
    None,
}

/// The photographed brokered surface an `mcp` binding freezes: the exact
/// required-tool subset (in requirement order) and its digest — the run's
/// tool contract (design `:367-389`).
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedMcpSurface {
    pub url: String,
    pub snapshot_version: i32,
    pub tools: Vec<ToolSnapshot>,
    pub tools_digest: String,
}

/// One resolved requirement, ready to (a) stamp into the RunSpec and (b) write
/// as a `run_resource_bindings` row. `id` is pre-minted (`now_v7`) so the
/// RunSpec can reference the row before it is inserted.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedBinding {
    pub id: Uuid,
    pub slot: String,
    pub slot_kind: &'static str,
    pub authority: ResolvedAuthority,
    pub resource_scope: Value,
    pub binding_mode: &'static str,
    pub mcp: Option<ResolvedMcpSurface>,
}

/// The workspace's resolved authority source. The connection id is NEVER
/// trusted raw from user input: on the manual path (`manual = true`) it gets
/// the full explicit-mode verification (viewer read + owner check + a
/// git-capable provider); server-derived workspaces (trigger/schedule/event)
/// carry organization authority as today.
pub struct WorkspaceBindingInput<'a> {
    pub spec: &'a WorkspaceSpec,
    pub manual: bool,
}

/// Everything binding resolution needs, assembled by `create_run` from the
/// resolved revision, the invocation, and the caller's verified explicit
/// choices.
pub struct BindingInputs<'a> {
    /// Parsed from the resolved revision's `connection_requirements`.
    pub requirements: &'a [ConnectionRequirement],
    pub trust_tier: TrustTier,
    /// `user | operator | trigger | schedule | webhook` — stamped on every row.
    pub principal_kind: &'a str,
    pub principal_id: Option<String>,
    /// Some only for an interactive user principal (invoking-user binding).
    pub invoking_user: Option<Uuid>,
    /// Sanctioned explicit override: slot → connection id (user-supplied; this
    /// module verifies it).
    pub explicit: &'a HashMap<String, Uuid>,
    /// The resolved workspace + its authority source.
    pub workspace: Option<WorkspaceBindingInput<'a>>,
    pub result_destinations: &'a [ResultDestination],
    pub subscription: Option<&'a TriggerSubscriptionRow>,
}

// ─── Public entry point ─────────────────────────────────────────────────────

/// Resolve every requirement to a frozen, authorized binding. The signature is
/// fixed across Phase C tasks; the body only ever touches `state.pool` (all the
/// work is DB reads + pure matching), so the DB tests drive the pool-based
/// [`resolve_bindings`] directly.
pub async fn resolve_run_bindings(
    state: &AppState,
    scope: TenantScope,
    inp: &BindingInputs<'_>,
) -> Result<Vec<ResolvedBinding>, ApiError> {
    resolve_bindings(&state.pool, scope, inp).await
}

async fn resolve_bindings(
    pool: &PgPool,
    scope: TenantScope,
    inp: &BindingInputs<'_>,
) -> Result<Vec<ResolvedBinding>, ApiError> {
    let mut out = Vec::new();

    // MCP requirements. TrustTier::ReadOnly strips them entirely (fork PRs must
    // still run — read-only — so this mirrors `frozen_capabilities`' strip, not
    // a failure). Workspace/publish slots are unaffected by tier.
    if inp.trust_tier != TrustTier::ReadOnly {
        for req in inp.requirements {
            out.push(resolve_mcp_requirement(pool, scope, inp, req).await?);
        }
    }

    // Workspace fetch (at most one — the single `workspace` slot).
    if let Some(ws) = &inp.workspace {
        if let Some(rb) = resolve_workspace_binding(pool, scope, inp, ws).await? {
            out.push(rb);
        }
    }

    // Result publish, one binding per destination index.
    for (i, dest) in inp.result_destinations.iter().enumerate() {
        out.push(resolve_publish_binding(pool, scope, inp, i, dest).await?);
    }

    Ok(out)
}

// ─── MCP requirement resolution ─────────────────────────────────────────────

async fn resolve_mcp_requirement(
    pool: &PgPool,
    scope: TenantScope,
    inp: &BindingInputs<'_>,
    req: &ConnectionRequirement,
) -> Result<ResolvedBinding, ApiError> {
    // Explicit override wins: the caller named a connection for this slot.
    if let Some(cid) = inp.explicit.get(&req.slot) {
        return resolve_explicit_mcp(pool, scope, inp, req, *cid).await;
    }
    let (conn, binding_mode) = match req.binding_mode {
        BindingMode::InvokingUser => {
            let uid = inp.invoking_user.ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "requirement '{}' binds the invoking user; schedules and webhooks need an \
                     organization connection or an explicit binding",
                    req.slot
                ))
            })?;
            let all = fluidbox_db::list_connections(pool, scope).await?;
            let candidates: Vec<&IntegrationConnectionRow> = all
                .iter()
                .filter(|c| {
                    c.owner_type == "user"
                        && c.owner_user_id == Some(uid)
                        && connection_matches_connector(c, &req.connector.url)
                })
                .collect();
            (
                pick_one(&candidates, req, "personal")?.clone(),
                "invoking_user",
            )
        }
        BindingMode::Organization => {
            let all = fluidbox_db::list_connections(pool, scope).await?;
            let candidates: Vec<&IntegrationConnectionRow> = all
                .iter()
                .filter(|c| {
                    c.owner_type == "organization"
                        && connection_matches_connector(c, &req.connector.url)
                })
                .collect();
            (
                pick_one(&candidates, req, "organization")?.clone(),
                "organization",
            )
        }
    };
    let mcp = resolve_snapshot_surface(pool, scope, &conn, req).await?;
    Ok(ResolvedBinding {
        id: Uuid::now_v7(),
        slot: req.slot.clone(),
        slot_kind: "mcp",
        authority: authority_from_conn(&conn),
        resource_scope: conn.resource_selection.clone(),
        binding_mode,
        mcp: Some(mcp),
    })
}

async fn resolve_explicit_mcp(
    pool: &PgPool,
    scope: TenantScope,
    inp: &BindingInputs<'_>,
    req: &ConnectionRequirement,
    cid: Uuid,
) -> Result<ResolvedBinding, ApiError> {
    // Viewer-filtered read: Bob naming Alice's personal connection resolves to
    // None here — the SAME "not found" as a truly missing id (do not leak that
    // it exists). No unfiltered read ever serves this user-supplied id.
    let conn = fluidbox_db::get_connection_visible(pool, scope, cid, viewer_for(inp))
        .await?
        .ok_or_else(|| not_found_conn(&req.slot, cid))?;
    // Caller may use it: a user-owned connection is usable only by its owner.
    // (The viewer read already enforces this for a user principal; this closes
    // the operator/All-viewer case with the same non-leaking "not found".)
    if conn.owner_type == "user" && conn.owner_user_id != inp.invoking_user {
        return Err(not_found_conn(&req.slot, cid));
    }
    if conn.status != "active" {
        return Err(ApiError::BadRequest(format!(
            "requirement '{}': connection '{}' is {} — reconnect it",
            req.slot, conn.display_name, conn.status
        )));
    }
    if !connection_matches_connector(&conn, &req.connector.url) {
        return Err(ApiError::BadRequest(format!(
            "requirement '{}': connection '{}' does not serve this connector",
            req.slot, conn.display_name
        )));
    }
    let mcp = resolve_snapshot_surface(pool, scope, &conn, req).await?;
    Ok(ResolvedBinding {
        id: Uuid::now_v7(),
        slot: req.slot.clone(),
        slot_kind: "mcp",
        authority: authority_from_conn(&conn),
        resource_scope: conn.resource_selection.clone(),
        binding_mode: "explicit",
        mcp: Some(mcp),
    })
}

/// Snapshot rules (all modes, design `:367-389`): the latest snapshot must
/// exist, its `authorization_generation` must equal the connection's CURRENT
/// generation (else it was reauthorized), and `required_tools ⊆ snapshot`
/// (satisfaction: all). The effective surface is EXACTLY the required subset in
/// requirement order, schemas from the snapshot, digest over the subset.
async fn resolve_snapshot_surface(
    pool: &PgPool,
    scope: TenantScope,
    conn: &IntegrationConnectionRow,
    req: &ConnectionRequirement,
) -> Result<ResolvedMcpSurface, ApiError> {
    let snap = fluidbox_db::latest_connection_tool_snapshot(pool, scope, conn.id)
        .await?
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "requirement '{}': connection '{}' has no tool snapshot — refresh the connection's tools",
                req.slot, conn.display_name
            ))
        })?;
    if snap.authorization_generation != conn.authorization_generation {
        return Err(ApiError::BadRequest(format!(
            "requirement '{}': connection '{}' was reauthorized — refresh its tools",
            req.slot, conn.display_name
        )));
    }
    let snap_tools: Vec<ToolSnapshot> = serde_json::from_value(snap.tools_json.clone())
        .map_err(|e| ApiError::Internal(format!("bad stored tool snapshot: {e}")))?;
    let mut effective = Vec::with_capacity(req.required_tools.len());
    let mut missing = Vec::new();
    for t in &req.required_tools {
        match snap_tools.iter().find(|s| &s.name == t) {
            Some(s) => effective.push(s.clone()),
            None => missing.push(t.as_str()),
        }
    }
    if !missing.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "requirement '{}': connection '{}' snapshot is missing required tools: {}",
            req.slot,
            conn.display_name,
            missing.join(", ")
        )));
    }
    Ok(ResolvedMcpSurface {
        url: req.connector.url.clone(),
        snapshot_version: snap.snapshot_version,
        tools_digest: tools_digest(&effective),
        tools: effective,
    })
}

// ─── Workspace resolution ───────────────────────────────────────────────────

async fn resolve_workspace_binding(
    pool: &PgPool,
    scope: TenantScope,
    inp: &BindingInputs<'_>,
    ws: &WorkspaceBindingInput<'_>,
) -> Result<Option<ResolvedBinding>, ApiError> {
    // Only a git workspace credentials a fetch; scratch/local copy → no row.
    let WorkspaceSpec::GitRepository {
        connection_id,
        clone_url,
        r#ref,
        commit_sha,
        ..
    } = ws.spec
    else {
        return Ok(None);
    };
    // Exactly what the orchestrator may fetch (mechanical, design `:449-451`).
    let resource_scope = json!({ "url": clone_url, "ref": r#ref, "commit": commit_sha });
    let binding_mode = if ws.manual {
        "explicit"
    } else {
        "organization"
    };
    let authority = match connection_id {
        Some(cid) => {
            let conn = if ws.manual {
                // User-supplied id → explicit-mode verification (invariant 21).
                let conn = fluidbox_db::get_connection_visible(pool, scope, *cid, viewer_for(inp))
                    .await?
                    .ok_or_else(|| {
                        ApiError::BadRequest(format!("workspace connection {cid} not found"))
                    })?;
                if conn.owner_type == "user" && conn.owner_user_id != inp.invoking_user {
                    return Err(ApiError::BadRequest(format!(
                        "workspace connection {cid} not found"
                    )));
                }
                if conn.status != "active" {
                    return Err(ApiError::BadRequest(format!(
                        "workspace connection {cid} is {} — reconnect it",
                        conn.status
                    )));
                }
                if crate::connectors::connector_for(&conn.provider) != Some("github") {
                    return Err(ApiError::BadRequest(format!(
                        "workspace connection '{}' provider '{}' does not supply git workspaces",
                        conn.display_name, conn.provider
                    )));
                }
                conn
            } else {
                // Server-derived id (trigger/schedule/event) → unfiltered read.
                let conn = fluidbox_db::get_connection(pool, scope, *cid)
                    .await?
                    .ok_or_else(|| {
                        ApiError::BadRequest(format!("workspace connection {cid} is missing"))
                    })?;
                if conn.status != "active" {
                    return Err(ApiError::BadRequest(format!(
                        "workspace connection {cid} is {} — reconnect it",
                        conn.status
                    )));
                }
                conn
            };
            authority_from_conn(&conn)
        }
        // Public / credentialless git: authority None (never an implicit miss).
        None => ResolvedAuthority::None,
    };
    Ok(Some(ResolvedBinding {
        id: Uuid::now_v7(),
        slot: "workspace".into(),
        slot_kind: "workspace_fetch",
        authority,
        resource_scope,
        binding_mode,
        mcp: None,
    }))
}

// ─── Result-publish resolution ──────────────────────────────────────────────

async fn resolve_publish_binding(
    pool: &PgPool,
    scope: TenantScope,
    inp: &BindingInputs<'_>,
    index: usize,
    dest: &ResultDestination,
) -> Result<ResolvedBinding, ApiError> {
    // The destination holds no secret (the signing secret stays sealed on the
    // subscription), so it is safe to freeze verbatim as the resource scope.
    let resource_scope = serde_json::to_value(dest)?;
    let authority = match dest {
        ResultDestination::GitHubPrComment { connection_id, .. }
        | ResultDestination::GitHubCheck { connection_id, .. } => {
            // Server-derived github_app connection (subscription/event config).
            let conn = fluidbox_db::get_connection(pool, scope, *connection_id)
                .await?
                .ok_or_else(|| {
                    ApiError::BadRequest(format!(
                        "result destination {index}: connection {connection_id} is missing"
                    ))
                })?;
            if conn.status != "active" {
                return Err(ApiError::BadRequest(format!(
                    "result destination {index}: connection {connection_id} is {} — reconnect it",
                    conn.status
                )));
            }
            authority_from_conn(&conn)
        }
        ResultDestination::SignedWebhook { .. } => {
            let sub = inp.subscription.ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "result destination {index}: signed webhook needs a subscription"
                ))
            })?;
            // The subscription must actually hold a callback secret to sign with.
            if fluidbox_db::subscription_callback_secret_sealed(pool, scope, sub.id)
                .await?
                .is_none()
            {
                return Err(ApiError::BadRequest(format!(
                    "result destination {index}: subscription has no callback secret for signed delivery"
                )));
            }
            ResolvedAuthority::SubscriptionSecret {
                id: sub.id,
                generation: sub.authority_generation,
            }
        }
    };
    Ok(ResolvedBinding {
        id: Uuid::now_v7(),
        slot: format!("publish:{index}"),
        slot_kind: "result_publish",
        authority,
        resource_scope,
        // Publish authorities are administrator-managed (the subscription's
        // github_app connection / callback secret) → organization mode.
        binding_mode: "organization",
        mcp: None,
    })
}

// ─── Shared helpers ─────────────────────────────────────────────────────────

fn viewer_for(inp: &BindingInputs<'_>) -> ConnectionViewer {
    match inp.invoking_user {
        Some(uid) => ConnectionViewer::User(uid),
        None => ConnectionViewer::All,
    }
}

fn not_found_conn(slot: &str, cid: Uuid) -> ApiError {
    ApiError::BadRequest(format!("requirement '{slot}': connection {cid} not found"))
}

fn authority_from_conn(conn: &IntegrationConnectionRow) -> ResolvedAuthority {
    ResolvedAuthority::Connection {
        id: conn.id,
        generation: conn.authorization_generation,
        owner_type: conn.owner_type.clone(),
        owner_user_id: conn.owner_user_id,
    }
}

/// The base a connection's credential is audience-bound to for matching:
/// `endpoint_url` when present (the concrete server) else `base_url`.
fn connection_base(conn: &IntegrationConnectionRow) -> Option<&str> {
    conn.metadata
        .get("endpoint_url")
        .and_then(|v| v.as_str())
        .or_else(|| conn.metadata.get("base_url").and_then(|v| v.as_str()))
}

/// A connection can serve a requirement iff it is an active mcp_http grant whose
/// base contains the requirement's endpoint url (the slug is a display aid; the
/// url decides). A url mismatch reads as "no matching connection", never a scary
/// audience error.
fn connection_matches_connector(conn: &IntegrationConnectionRow, req_url: &str) -> bool {
    if conn.provider != "mcp_http" || conn.status != "active" {
        return false;
    }
    match connection_base(conn) {
        Some(base) => crate::broker::url_within_base(req_url, base),
        None => false,
    }
}

fn connector_label(req: &ConnectionRequirement) -> &str {
    req.connector.slug.as_deref().unwrap_or(&req.connector.url)
}

/// Exactly one candidate must match — 0 fails (connect it first), >1 fails
/// ambiguous (naming the display names; NEVER pick the latest, design `:498`).
fn pick_one<'a>(
    candidates: &[&'a IntegrationConnectionRow],
    req: &ConnectionRequirement,
    kind: &str,
) -> Result<&'a IntegrationConnectionRow, ApiError> {
    match candidates {
        [] => Err(ApiError::BadRequest(if kind == "personal" {
            format!(
                "requirement '{}': connect {} first (no active personal connection matches)",
                req.slot,
                connector_label(req)
            )
        } else {
            format!(
                "requirement '{}': no active organization connection for {}",
                req.slot,
                connector_label(req)
            )
        })),
        [one] => Ok(one),
        many => {
            let names: Vec<&str> = many.iter().map(|c| c.display_name.as_str()).collect();
            Err(ApiError::BadRequest(format!(
                "requirement '{}' matches multiple {} connections ({}) — disambiguate with an explicit binding",
                req.slot,
                kind,
                names.join(", ")
            )))
        }
    }
}

// ─── Freeze-time refusals (pure; shared by create_run + tests) ──────────────

/// The Phase C cutoff (design `:346-347`): the first brokered server still
/// riding a frozen capability bundle, as `(server_alias, bundle_name,
/// bundle_version)`. Brokered tools are agent connection requirements now — a
/// revision still pinning one predates Phase C and its run is refused.
pub fn first_brokered_server(bundles: &[FrozenBundle]) -> Option<(&str, &str, i32)> {
    for b in bundles {
        for s in &b.servers {
            if s.is_brokered() {
                return Some((s.name(), b.name.as_str(), b.version));
            }
        }
    }
    None
}

/// The first requirement-slot ⇄ sandbox-server-alias collision, if any.
/// `RunSpec::mcp_tool_available` unions brokered surfaces and sandbox servers,
/// so a shared alias would let one shadow the other — create_run refuses it.
pub fn slot_collision(
    brokered: &[BrokeredSurface],
    capabilities: &[FrozenBundle],
) -> Option<String> {
    let sandbox_aliases: std::collections::BTreeSet<&str> = capabilities
        .iter()
        .flat_map(|b| b.servers.iter().map(|s| s.name()))
        .collect();
    brokered
        .iter()
        .find(|s| sandbox_aliases.contains(s.slot.as_str()))
        .map(|s| s.slot.clone())
}

// ─── RunSpec stamping + DB-row mapping (pure; shared by create_run + tests) ──

/// The brokered surfaces frozen into `RunSpec.brokered` — one per `mcp` binding.
pub fn brokered_surfaces(resolved: &[ResolvedBinding]) -> Vec<BrokeredSurface> {
    resolved
        .iter()
        .filter_map(|rb| {
            rb.mcp.as_ref().map(|m| BrokeredSurface {
                slot: rb.slot.clone(),
                url: m.url.clone(),
                binding_id: rb.id,
                snapshot_version: m.snapshot_version,
                tools: m.tools.clone(),
                tools_digest: m.tools_digest.clone(),
            })
        })
        .collect()
}

/// Stamp the resolved binding ids into the workspace + result destinations, so
/// the orchestrator/delivery worker resolve the binding (never the raw
/// connection id). The RunSpec then references each binding row 1:1.
pub fn apply_binding_ids(
    resolved: &[ResolvedBinding],
    workspace: &mut WorkspaceSpec,
    result_destinations: &mut [ResultDestination],
) {
    for rb in resolved {
        match rb.slot_kind {
            "workspace_fetch" => {
                if let WorkspaceSpec::GitRepository { binding_id, .. } = workspace {
                    *binding_id = Some(rb.id);
                }
            }
            "result_publish" => {
                if let Some(i) = rb
                    .slot
                    .strip_prefix("publish:")
                    .and_then(|s| s.parse::<usize>().ok())
                {
                    if let Some(dest) = result_destinations.get_mut(i) {
                        set_destination_binding_id(dest, rb.id);
                    }
                }
            }
            _ => {}
        }
    }
}

fn set_destination_binding_id(dest: &mut ResultDestination, id: Uuid) {
    match dest {
        ResultDestination::SignedWebhook { binding_id, .. }
        | ResultDestination::GitHubPrComment { binding_id, .. }
        | ResultDestination::GitHubCheck { binding_id, .. } => *binding_id = Some(id),
    }
}

/// Map resolved bindings to the write-once DB rows (`create_session` inserts
/// them in the session's transaction). Every row carries the resolving
/// principal; the tagged authority union projects onto the typed columns the
/// migration-0013 CHECK constraints enforce.
pub fn to_new_binding_rows(
    resolved: &[ResolvedBinding],
    principal_kind: &str,
    principal_id: Option<&str>,
) -> Result<Vec<NewRunResourceBinding>, ApiError> {
    resolved
        .iter()
        .map(|rb| {
            let (
                authority_kind,
                connection_id,
                subscription_id,
                authority_generation,
                connection_owner_type,
                connection_owner_user_id,
            ) = match &rb.authority {
                ResolvedAuthority::Connection {
                    id,
                    generation,
                    owner_type,
                    owner_user_id,
                } => (
                    "connection",
                    Some(*id),
                    None,
                    Some(*generation),
                    Some(owner_type.clone()),
                    *owner_user_id,
                ),
                ResolvedAuthority::SubscriptionSecret { id, generation } => (
                    "subscription_secret",
                    None,
                    Some(*id),
                    Some(*generation),
                    None,
                    None,
                ),
                ResolvedAuthority::None => ("none", None, None, None, None, None),
            };
            let (snapshot_version, effective_tools_json, effective_tools_digest) = match &rb.mcp {
                Some(m) => (
                    Some(m.snapshot_version),
                    Some(serde_json::to_value(&m.tools)?),
                    Some(m.tools_digest.clone()),
                ),
                None => (None, None, None),
            };
            Ok(NewRunResourceBinding {
                id: rb.id,
                requirement_slot: rb.slot.clone(),
                slot_kind: rb.slot_kind.to_string(),
                authority_kind: authority_kind.to_string(),
                connection_id,
                subscription_id,
                authority_generation,
                connection_owner_type,
                connection_owner_user_id,
                snapshot_version,
                effective_tools_json,
                effective_tools_digest,
                resource_scope: rb.resource_scope.clone(),
                resolved_by_principal_kind: principal_kind.to_string(),
                resolved_by_principal_id: principal_id.map(str::to_string),
                binding_mode: rb.binding_mode.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluidbox_core::capability::{
        definition_digest, CapabilityBundleDef, CapabilityServer, ConnectorSelector,
    };

    // ── DB-free unit tests (pure mapping / ordering / message shapes) ────────

    fn sandbox_server(name: &str) -> CapabilityServer {
        CapabilityServer::Sandbox {
            name: name.into(),
            command: "node".into(),
            args: vec![],
            identity: None,
            tools: vec![tool("t")],
        }
    }

    fn brokered_server(name: &str) -> CapabilityServer {
        CapabilityServer::Brokered {
            name: name.into(),
            url: "https://x.test/mcp".into(),
            connection_id: None,
            identity: None,
            tools: vec![tool("t")],
        }
    }

    fn frozen(name: &str, servers: Vec<CapabilityServer>) -> FrozenBundle {
        let def = CapabilityBundleDef {
            servers: servers.clone(),
        };
        FrozenBundle {
            id: Uuid::now_v7(),
            name: name.into(),
            version: 1,
            definition_digest: definition_digest(&def),
            servers,
        }
    }

    #[test]
    fn first_brokered_server_is_the_cutoff() {
        // Sandbox-only bundles freeze as today (no cutoff).
        let sandbox_only = vec![frozen("ws-tools", vec![sandbox_server("ws")])];
        assert!(first_brokered_server(&sandbox_only).is_none());
        // Any brokered server trips the cutoff, naming the offending bundle.
        let with_brokered = vec![
            frozen("ws-tools", vec![sandbox_server("ws")]),
            frozen("kb-tools", vec![brokered_server("kb")]),
        ];
        assert_eq!(
            first_brokered_server(&with_brokered),
            Some(("kb", "kb-tools", 1))
        );
    }

    #[test]
    fn slot_collision_flags_a_shared_alias() {
        let caps = vec![frozen("ws-tools", vec![sandbox_server("github")])];
        let surface = |slot: &str| BrokeredSurface {
            slot: slot.into(),
            url: "https://x/mcp".into(),
            binding_id: Uuid::now_v7(),
            snapshot_version: 1,
            tools: vec![tool("t")],
            tools_digest: "sha256:x".into(),
        };
        // A brokered surface sharing a sandbox alias collides.
        assert_eq!(
            slot_collision(&[surface("github")], &caps),
            Some("github".to_string())
        );
        // A distinct alias does not.
        assert_eq!(slot_collision(&[surface("gh")], &caps), None);
        // No sandbox servers → nothing to collide with.
        assert_eq!(slot_collision(&[surface("github")], &[]), None);
    }

    fn surface_binding(slot: &str, tools: Vec<ToolSnapshot>) -> ResolvedBinding {
        ResolvedBinding {
            id: Uuid::now_v7(),
            slot: slot.into(),
            slot_kind: "mcp",
            authority: ResolvedAuthority::Connection {
                id: Uuid::now_v7(),
                generation: 2,
                owner_type: "user".into(),
                owner_user_id: Some(Uuid::now_v7()),
            },
            resource_scope: json!({}),
            binding_mode: "invoking_user",
            mcp: Some(ResolvedMcpSurface {
                url: "https://mcp.example.test/mcp".into(),
                snapshot_version: 3,
                tools_digest: tools_digest(&tools),
                tools,
            }),
        }
    }

    fn tool(name: &str) -> ToolSnapshot {
        ToolSnapshot {
            name: name.into(),
            description: format!("does {name}"),
            input_schema: json!({"type": "object"}),
            annotations: None,
        }
    }

    #[test]
    fn brokered_surfaces_only_from_mcp_bindings() {
        let mcp = surface_binding("gh", vec![tool("get_pr")]);
        let ws = ResolvedBinding {
            id: Uuid::now_v7(),
            slot: "workspace".into(),
            slot_kind: "workspace_fetch",
            authority: ResolvedAuthority::None,
            resource_scope: json!({"url": "https://x/r.git"}),
            binding_mode: "organization",
            mcp: None,
        };
        let surfaces = brokered_surfaces(&[mcp.clone(), ws]);
        assert_eq!(surfaces.len(), 1);
        assert_eq!(surfaces[0].slot, "gh");
        assert_eq!(surfaces[0].binding_id, mcp.id);
        assert_eq!(surfaces[0].snapshot_version, 3);
        assert_eq!(surfaces[0].tools.len(), 1);
    }

    #[test]
    fn apply_binding_ids_stamps_workspace_and_indexed_publish() {
        let ws_binding = ResolvedBinding {
            id: Uuid::now_v7(),
            slot: "workspace".into(),
            slot_kind: "workspace_fetch",
            authority: ResolvedAuthority::None,
            resource_scope: json!({}),
            binding_mode: "explicit",
            mcp: None,
        };
        let pub0 = ResolvedBinding {
            id: Uuid::now_v7(),
            slot: "publish:0".into(),
            slot_kind: "result_publish",
            authority: ResolvedAuthority::SubscriptionSecret {
                id: Uuid::now_v7(),
                generation: 1,
            },
            resource_scope: json!({}),
            binding_mode: "organization",
            mcp: None,
        };
        let pub1 = ResolvedBinding {
            id: Uuid::now_v7(),
            slot: "publish:1".into(),
            slot_kind: "result_publish",
            authority: ResolvedAuthority::Connection {
                id: Uuid::now_v7(),
                generation: 1,
                owner_type: "organization".into(),
                owner_user_id: None,
            },
            resource_scope: json!({}),
            binding_mode: "organization",
            mcp: None,
        };
        let mut workspace = WorkspaceSpec::GitRepository {
            connection_id: Some(Uuid::now_v7()),
            binding_id: None,
            repository: None,
            clone_url: "https://x/r.git".into(),
            r#ref: None,
            commit_sha: None,
            checkout_mode: Default::default(),
        };
        let mut dests = vec![
            ResultDestination::SignedWebhook {
                url: "https://cb".into(),
                binding_id: None,
            },
            ResultDestination::GitHubCheck {
                connection_id: Uuid::now_v7(),
                repository: "o/r".into(),
                head_sha: "a".repeat(40),
                binding_id: None,
            },
        ];
        apply_binding_ids(
            &[ws_binding.clone(), pub0.clone(), pub1.clone()],
            &mut workspace,
            &mut dests,
        );
        let WorkspaceSpec::GitRepository { binding_id, .. } = &workspace else {
            panic!("wrong variant");
        };
        assert_eq!(*binding_id, Some(ws_binding.id));
        let ResultDestination::SignedWebhook { binding_id, .. } = &dests[0] else {
            panic!("wrong variant");
        };
        assert_eq!(*binding_id, Some(pub0.id));
        let ResultDestination::GitHubCheck { binding_id, .. } = &dests[1] else {
            panic!("wrong variant");
        };
        assert_eq!(*binding_id, Some(pub1.id));
    }

    #[test]
    fn to_new_binding_rows_projects_the_tagged_union() {
        let mcp = surface_binding("gh", vec![tool("get_pr")]);
        let webhook = ResolvedBinding {
            id: Uuid::now_v7(),
            slot: "publish:0".into(),
            slot_kind: "result_publish",
            authority: ResolvedAuthority::SubscriptionSecret {
                id: Uuid::now_v7(),
                generation: 5,
            },
            resource_scope: json!({"kind": "signed_webhook", "url": "https://cb"}),
            binding_mode: "organization",
            mcp: None,
        };
        let public_ws = ResolvedBinding {
            id: Uuid::now_v7(),
            slot: "workspace".into(),
            slot_kind: "workspace_fetch",
            authority: ResolvedAuthority::None,
            resource_scope: json!({"url": "https://x/r.git"}),
            binding_mode: "organization",
            mcp: None,
        };
        let rows = to_new_binding_rows(
            &[mcp.clone(), webhook.clone(), public_ws.clone()],
            "user",
            Some("u1"),
        )
        .unwrap();
        assert_eq!(rows.len(), 3);

        // mcp → connection authority, snapshot columns populated.
        let m = &rows[0];
        assert_eq!(m.slot_kind, "mcp");
        assert_eq!(m.authority_kind, "connection");
        assert!(m.connection_id.is_some());
        assert!(m.subscription_id.is_none());
        assert_eq!(m.authority_generation, Some(2));
        assert_eq!(m.connection_owner_type.as_deref(), Some("user"));
        assert!(m.connection_owner_user_id.is_some());
        assert_eq!(m.snapshot_version, Some(3));
        assert!(m.effective_tools_json.is_some());
        assert!(m.effective_tools_digest.is_some());
        assert_eq!(m.resolved_by_principal_kind, "user");
        assert_eq!(m.resolved_by_principal_id.as_deref(), Some("u1"));

        // subscription_secret → subscription authority, no connection/owner/snapshot.
        let w = &rows[1];
        assert_eq!(w.authority_kind, "subscription_secret");
        assert!(w.connection_id.is_none());
        assert!(w.subscription_id.is_some());
        assert_eq!(w.authority_generation, Some(5));
        assert!(w.connection_owner_type.is_none());
        assert!(w.snapshot_version.is_none());
        assert!(w.effective_tools_json.is_none());

        // none → everything null, non-mcp slot.
        let p = &rows[2];
        assert_eq!(p.authority_kind, "none");
        assert!(p.connection_id.is_none());
        assert!(p.subscription_id.is_none());
        assert!(p.authority_generation.is_none());
        assert!(p.connection_owner_type.is_none());
        assert!(p.snapshot_version.is_none());
    }

    #[test]
    fn pick_one_zero_and_ambiguous_messages() {
        let req = ConnectionRequirement {
            slot: "github".into(),
            connector: ConnectorSelector {
                url: "https://mcp.github.test/mcp".into(),
                slug: Some("github-mcp".into()),
            },
            required_tools: vec!["get_pr".into()],
            binding_mode: BindingMode::InvokingUser,
        };
        // Zero personal candidates → "connect … first".
        let empty: Vec<&IntegrationConnectionRow> = vec![];
        let err = pick_one(&empty, &req, "personal").unwrap_err().to_string();
        assert!(err.contains("connect github-mcp first"), "got: {err}");
        // Zero org candidates → the org-flavored message.
        let err = pick_one(&empty, &req, "organization")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no active organization connection"),
            "got: {err}"
        );
    }

    #[test]
    fn effective_tools_preserve_requirement_order_and_digest() {
        // The digest and subset are order-sensitive: the requirement declares
        // [b, a] and the effective surface must be [b, a] (not the snapshot's
        // order), so the digest matches a [b, a] subset.
        let ordered = vec![tool("b"), tool("a")];
        let binding = surface_binding("gh", ordered.clone());
        let surface = binding.mcp.unwrap();
        assert_eq!(
            surface
                .tools
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "a"]
        );
        assert_eq!(surface.tools_digest, tools_digest(&ordered));
        // A different order is a different digest (drift-sensitive).
        assert_ne!(surface.tools_digest, tools_digest(&[tool("a"), tool("b")]));
    }

    // ── DB-backed tests (real Neon; self-skip when DATABASE_URL is unset) ────
    //
    // They drive `resolve_bindings` directly (pool-based) with hand-seeded
    // connection + snapshot rows; the happy path also runs the result through
    // the pure `brokered_surfaces` + `to_new_binding_rows` stamping the RunSpec
    // and `create_session` (Task 1) consume. Children-first cleanup runs BEFORE
    // the asserts so a failing assert never leaks fixtures.

    use fluidbox_db::{connect, identity, ConnectionAuth, ConnectionOwner};

    /// A user + active membership under `scope` (its own staged idp config), by
    /// raw SQL — the FK target for a connection's `owner_user_id`. Mirrors the
    /// db-crate test seeder.
    async fn seed_user(pool: &PgPool, scope: TenantScope, subject: &str) -> Uuid {
        let cfg_id = Uuid::now_v7();
        sqlx::query(
            "insert into org_idp_configs
               (id, tenant_id, generation, issuer, client_id, claim_mappings, status)
             values ($1, $2,
                     coalesce((select max(generation) from org_idp_configs where tenant_id = $2), 0) + 1,
                     $3, 'client-test', '{}'::jsonb, 'staged')",
        )
        .bind(cfg_id)
        .bind(scope.tenant_id())
        .bind(format!("https://idp.test/{subject}"))
        .execute(pool)
        .await
        .unwrap();
        let user_id = Uuid::now_v7();
        sqlx::query(
            "insert into users
               (id, tenant_id, idp_config_id, subject, email, email_normalized, email_verified, status)
             values ($1, $2, $3, $4, $5, $5, true, 'active')",
        )
        .bind(user_id)
        .bind(scope.tenant_id())
        .bind(cfg_id)
        .bind(subject)
        .bind(format!("{subject}@example.com"))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "insert into org_memberships (id, tenant_id, user_id, roles, status)
             values ($1, $2, $3, '{member}', 'active')",
        )
        .bind(Uuid::now_v7())
        .bind(scope.tenant_id())
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
        user_id
    }

    async fn seed_mcp_connection(
        pool: &PgPool,
        scope: TenantScope,
        owner: ConnectionOwner,
        display: &str,
        base_url: &str,
    ) -> IntegrationConnectionRow {
        fluidbox_db::create_connection(
            pool,
            scope,
            "mcp_http",
            &format!("acct-{}", Uuid::now_v7().simple()),
            display,
            Some(b"sealed-token"),
            &json!([]),
            &json!({"projects": ["p1"]}),
            &json!({ "base_url": base_url }),
            None,
            ConnectionAuth::static_active(),
            owner,
            None,
        )
        .await
        .unwrap()
    }

    async fn seed_snapshot(
        pool: &PgPool,
        scope: TenantScope,
        conn: &IntegrationConnectionRow,
        generation: i32,
        tools: &[ToolSnapshot],
    ) {
        fluidbox_db::insert_connection_tool_snapshot(
            pool,
            scope,
            conn.id,
            generation,
            "2025-06-18",
            &serde_json::to_value(tools).unwrap(),
            &tools_digest(tools),
        )
        .await
        .unwrap();
    }

    async fn cleanup(pool: &PgPool, tenant: Uuid) {
        // Children-first (tenant FKs are NO ACTION): bindings/snapshots ahead of
        // connections, memberships/users ahead of the idp config, then the org.
        for stmt in [
            "delete from run_resource_bindings where tenant_id = $1",
            "delete from connection_tool_snapshots where tenant_id = $1",
            "delete from integration_connections where tenant_id = $1",
            "delete from org_memberships where tenant_id = $1",
            "delete from users where tenant_id = $1",
            "delete from org_idp_configs where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            let _ = sqlx::query(stmt).bind(tenant).execute(pool).await;
        }
    }

    fn req(slot: &str, url: &str, tools: &[&str], mode: BindingMode) -> ConnectionRequirement {
        ConnectionRequirement {
            slot: slot.into(),
            connector: ConnectorSelector {
                url: url.into(),
                slug: Some("cat".into()),
            },
            required_tools: tools.iter().map(|s| s.to_string()).collect(),
            binding_mode: mode,
        }
    }

    fn inputs<'a>(
        requirements: &'a [ConnectionRequirement],
        trust_tier: TrustTier,
        principal_kind: &'a str,
        invoking_user: Option<Uuid>,
        explicit: &'a HashMap<String, Uuid>,
    ) -> BindingInputs<'a> {
        BindingInputs {
            requirements,
            trust_tier,
            principal_kind,
            principal_id: invoking_user.map(|u| u.to_string()),
            invoking_user,
            explicit,
            workspace: None,
            result_destinations: &[],
            subscription: None,
        }
    }

    #[tokio::test]
    async fn invoking_user_happy_path_freezes_required_subset() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);
        let uid = seed_user(&pool, scope, "alice@test.dev").await;
        let base = "https://mcp.example.test";
        let conn = seed_mcp_connection(
            &pool,
            scope,
            ConnectionOwner::User(uid),
            "Alice personal",
            base,
        )
        .await;
        // Snapshot advertises MORE than required; the effective set is exactly
        // the required subset, in requirement order.
        seed_snapshot(
            &pool,
            scope,
            &conn,
            conn.authorization_generation,
            &[
                tool("create_review"),
                tool("get_pull_request"),
                tool("extra"),
            ],
        )
        .await;
        let reqs = vec![req(
            "github",
            "https://mcp.example.test/mcp",
            &["get_pull_request", "create_review"],
            BindingMode::InvokingUser,
        )];
        let explicit = HashMap::new();
        let inp = inputs(&reqs, TrustTier::Trusted, "user", Some(uid), &explicit);

        let resolved = resolve_bindings(&pool, scope, &inp).await;

        // Feed the result through the pure stamping helpers create_run uses.
        let mapped = resolved.as_ref().ok().map(|rb| {
            (
                brokered_surfaces(rb),
                to_new_binding_rows(rb, "user", Some(&uid.to_string())).unwrap(),
            )
        });

        cleanup(&pool, org.id).await;

        let resolved = resolved.expect("resolve ok");
        assert_eq!(resolved.len(), 1);
        let b = &resolved[0];
        assert_eq!(b.slot, "github");
        assert_eq!(b.slot_kind, "mcp");
        assert_eq!(b.binding_mode, "invoking_user");
        let surface = b.mcp.as_ref().expect("mcp surface");
        assert_eq!(
            surface
                .tools
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>(),
            vec!["get_pull_request", "create_review"],
            "effective = exactly the required subset, in requirement order"
        );
        assert_eq!(surface.url, "https://mcp.example.test/mcp");
        match &b.authority {
            ResolvedAuthority::Connection {
                id,
                owner_type,
                owner_user_id,
                ..
            } => {
                assert_eq!(*id, conn.id);
                assert_eq!(owner_type, "user");
                assert_eq!(*owner_user_id, Some(uid));
            }
            other => panic!("expected connection authority, got {other:?}"),
        }
        // RunSpec.brokered would be populated with exactly this surface, and the
        // write-once row projects a legal `connection`/`mcp` shape.
        let (surfaces, rows) = mapped.expect("resolved single binding");
        assert_eq!(surfaces.len(), 1);
        assert_eq!(surfaces[0].slot, "github");
        assert_eq!(surfaces[0].binding_id, b.id);
        assert_eq!(surfaces[0].tools.len(), 2);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].authority_kind, "connection");
        assert_eq!(rows[0].slot_kind, "mcp");
        assert!(rows[0].effective_tools_digest.is_some());
    }

    #[tokio::test]
    async fn missing_required_tool_fails_before_any_write() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);
        let uid = seed_user(&pool, scope, "a@test.dev").await;
        let conn = seed_mcp_connection(
            &pool,
            scope,
            ConnectionOwner::User(uid),
            "personal",
            "https://mcp.example.test",
        )
        .await;
        // Snapshot lacks `create_review` → satisfaction:all fails.
        seed_snapshot(
            &pool,
            scope,
            &conn,
            conn.authorization_generation,
            &[tool("get_pull_request")],
        )
        .await;
        let reqs = vec![req(
            "github",
            "https://mcp.example.test/mcp",
            &["get_pull_request", "create_review"],
            BindingMode::InvokingUser,
        )];
        let explicit = HashMap::new();
        let inp = inputs(&reqs, TrustTier::Trusted, "user", Some(uid), &explicit);

        let err = resolve_bindings(&pool, scope, &inp).await;
        // No binding row could have been written: resolution errored, so
        // create_run returns before create_session (no session, no rows).
        let bindings_written: i64 =
            sqlx::query_scalar("select count(*) from run_resource_bindings where tenant_id = $1")
                .bind(org.id)
                .fetch_one(&pool)
                .await
                .unwrap();

        cleanup(&pool, org.id).await;

        let msg = err.expect_err("missing tool must fail").to_string();
        assert!(msg.contains("missing required tools"), "got: {msg}");
        assert!(
            msg.contains("create_review"),
            "names the missing tool: {msg}"
        );
        assert_eq!(bindings_written, 0, "nothing written on failure");
    }

    #[tokio::test]
    async fn ambiguous_two_personal_candidates_fails() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);
        let uid = seed_user(&pool, scope, "a@test.dev").await;
        let base = "https://mcp.example.test";
        for name in ["personal one", "personal two"] {
            let conn =
                seed_mcp_connection(&pool, scope, ConnectionOwner::User(uid), name, base).await;
            seed_snapshot(
                &pool,
                scope,
                &conn,
                conn.authorization_generation,
                &[tool("get_pull_request")],
            )
            .await;
        }
        let reqs = vec![req(
            "github",
            "https://mcp.example.test/mcp",
            &["get_pull_request"],
            BindingMode::InvokingUser,
        )];
        let explicit = HashMap::new();
        let inp = inputs(&reqs, TrustTier::Trusted, "user", Some(uid), &explicit);

        let err = resolve_bindings(&pool, scope, &inp).await;
        cleanup(&pool, org.id).await;

        let msg = err.expect_err("ambiguous must fail").to_string();
        assert!(
            msg.contains("matches multiple personal connections"),
            "got: {msg}"
        );
        assert!(
            msg.contains("personal one") && msg.contains("personal two"),
            "names both: {msg}"
        );
    }

    #[tokio::test]
    async fn explicit_cross_user_refused_as_not_found() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);
        let alice = seed_user(&pool, scope, "alice@test.dev").await;
        let bob = seed_user(&pool, scope, "bob@test.dev").await;
        let base = "https://mcp.example.test";
        let alice_conn =
            seed_mcp_connection(&pool, scope, ConnectionOwner::User(alice), "Alice", base).await;
        seed_snapshot(
            &pool,
            scope,
            &alice_conn,
            alice_conn.authorization_generation,
            &[tool("get_pull_request")],
        )
        .await;
        // Bob explicitly names Alice's personal connection.
        let reqs = vec![req(
            "github",
            "https://mcp.example.test/mcp",
            &["get_pull_request"],
            BindingMode::InvokingUser,
        )];
        let mut explicit = HashMap::new();
        explicit.insert("github".to_string(), alice_conn.id);
        let inp = inputs(&reqs, TrustTier::Trusted, "user", Some(bob), &explicit);

        let err = resolve_bindings(&pool, scope, &inp).await;
        cleanup(&pool, org.id).await;

        let msg = err.expect_err("cross-user must fail").to_string();
        // Same shape as a genuinely missing id — existence is not leaked.
        assert!(msg.contains("not found"), "got: {msg}");
        assert!(
            !msg.contains("Alice"),
            "must not leak the connection name: {msg}"
        );
    }

    #[tokio::test]
    async fn schedule_path_invoking_user_requirement_fails() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);
        let reqs = vec![req(
            "github",
            "https://mcp.example.test/mcp",
            &["get_pull_request"],
            BindingMode::InvokingUser,
        )];
        let explicit = HashMap::new();
        // A schedule tick has no invoking user.
        let inp = inputs(&reqs, TrustTier::Trusted, "schedule", None, &explicit);

        let err = resolve_bindings(&pool, scope, &inp).await;
        cleanup(&pool, org.id).await;

        let msg = err
            .expect_err("schedule + invoking_user must fail")
            .to_string();
        assert!(
            msg.contains("binds the invoking user") && msg.contains("organization connection"),
            "org-connection message: {msg}"
        );
    }

    #[tokio::test]
    async fn generation_mismatch_snapshot_fails_refresh() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);
        let uid = seed_user(&pool, scope, "a@test.dev").await;
        let base = "https://mcp.example.test";
        let conn =
            seed_mcp_connection(&pool, scope, ConnectionOwner::User(uid), "personal", base).await;
        // Snapshot was taken at an OLDER generation than the connection now holds.
        seed_snapshot(
            &pool,
            scope,
            &conn,
            conn.authorization_generation,
            &[tool("get_pull_request")],
        )
        .await;
        fluidbox_db::bump_connection_generation(&pool, scope, conn.id)
            .await
            .unwrap();
        let reqs = vec![req(
            "github",
            "https://mcp.example.test/mcp",
            &["get_pull_request"],
            BindingMode::InvokingUser,
        )];
        let explicit = HashMap::new();
        let inp = inputs(&reqs, TrustTier::Trusted, "user", Some(uid), &explicit);

        let err = resolve_bindings(&pool, scope, &inp).await;
        cleanup(&pool, org.id).await;

        let msg = err.expect_err("generation mismatch must fail").to_string();
        assert!(
            msg.contains("reauthorized") && msg.contains("refresh"),
            "got: {msg}"
        );
    }

    #[tokio::test]
    async fn read_only_strips_mcp_bindings() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);
        // A requirement that WOULD fail (no connection) is simply skipped on
        // ReadOnly — the strip, not a failure.
        let reqs = vec![req(
            "github",
            "https://mcp.example.test/mcp",
            &["get_pull_request"],
            BindingMode::InvokingUser,
        )];
        let explicit = HashMap::new();
        let inp = inputs(&reqs, TrustTier::ReadOnly, "webhook", None, &explicit);

        let resolved = resolve_bindings(&pool, scope, &inp).await;
        cleanup(&pool, org.id).await;

        assert!(
            resolved.expect("read-only resolves").is_empty(),
            "no mcp bindings on ReadOnly"
        );
    }

    #[tokio::test]
    async fn workspace_none_authority_for_public_git() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);
        let ws = WorkspaceSpec::GitRepository {
            connection_id: None,
            binding_id: None,
            repository: Some("o/r".into()),
            clone_url: "https://github.com/o/r.git".into(),
            r#ref: Some("main".into()),
            commit_sha: None,
            checkout_mode: Default::default(),
        };
        let reqs: Vec<ConnectionRequirement> = vec![];
        let explicit = HashMap::new();
        let mut inp = inputs(&reqs, TrustTier::Trusted, "user", None, &explicit);
        inp.workspace = Some(WorkspaceBindingInput {
            spec: &ws,
            manual: true,
        });

        let resolved = resolve_bindings(&pool, scope, &inp).await;
        cleanup(&pool, org.id).await;

        let resolved = resolved.expect("resolve ok");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].slot, "workspace");
        assert_eq!(resolved[0].slot_kind, "workspace_fetch");
        assert_eq!(resolved[0].authority, ResolvedAuthority::None);
        assert_eq!(
            resolved[0].resource_scope["url"],
            "https://github.com/o/r.git"
        );
    }
}
