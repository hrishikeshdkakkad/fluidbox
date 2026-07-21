//! The brokered-tool gateway's MCP side (design §8.3 class 2): the control
//! plane speaks MCP Streamable HTTP to remote servers so the sandbox never
//! has to — the sealed credential is unsealed here, used for one call, and
//! dropped. Fourth instance of the credential inversion (LLM facade, git
//! fetch, webhook verify, tool broker).
//!
//! Per-run MCP session manager (Phase E, E5–E8): the client `initialize`s FIRST
//! for every new `(run, peer)`, persists the negotiated protocol version +
//! optional session id in a replica-local registry, reuses that session across
//! the run's brokered calls (sending `MCP-Protocol-Version` on every
//! post-initialize request), re-initializes ONCE on a 404-with-session, DELETEs
//! the session at the run's terminal transition, and speaks a real incremental
//! SSE parser ([`crate::mcp_sse`]) with content-type + jsonrpc + id validation.
//! It accepts both `application/json` and SSE-framed responses, replies
//! `-32601` to unsupported server→client requests, and treats an SEP-835
//! `insufficient_scope` challenge as terminal (never a re-mint).

use crate::state::{AppState, McpPeer, McpUpstreamSession};
use fluidbox_core::capability::{CapabilityServer, ToolSnapshot};
use futures::StreamExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const MCP_TIMEOUT: Duration = Duration::from_secs(30);
/// Best-effort cap on the terminal session-DELETE (never blocks terminalization).
const MCP_DELETE_TIMEOUT: Duration = Duration::from_secs(5);
/// Protocol revision we OFFER at initialize (2025-11-25). We accept any version
/// in [`SUPPORTED_PROTOCOLS`], and — once a surface is frozen (Task 3) — the one
/// the snapshot recorded.
const OFFERED_PROTOCOL: &str = "2025-11-25";
/// The protocol revisions this client can speak. A server negotiating anything
/// outside this set (with no frozen snapshot to defer to) fails the call.
const SUPPORTED_PROTOCOLS: [&str; 2] = ["2025-11-25", "2025-06-18"];
/// Discovery pagination bound (tools beyond this are a config smell; the
/// per-server tool cap in fluidbox-core rejects them at validation anyway).
const MAX_LIST_PAGES: usize = 4;
/// Result payloads larger than this are replaced by a truncated text block
/// — the ledger stores only digests either way.
const MAX_RESULT_BYTES: usize = 256 * 1024;
/// Hard ceiling on an MCP response we will buffer: a server advertising a
/// Content-Length over this is refused BEFORE the body is read into memory
/// (R3.3), AND the decoded body is streamed into a buffer capped at the same
/// ceiling (D) so a chunked/compressed response without Content-Length cannot
/// buffer unboundedly. `cap_content` still truncates tool results after the fact,
/// and discovery re-validates the whole surface against fluidbox-core's 2 MiB
/// serialized ceiling.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// A resolved outbound credential: which header to set, its full value, and
/// — for OAuth connections — the connection whose access token can be
/// re-minted after a 401 (`None` = static credential; a 401 is terminal).
pub struct BrokeredAuth {
    pub header: String,
    pub value: String,
    pub oauth_connection: Option<uuid::Uuid>,
}

impl BrokeredAuth {
    /// The bare OAuth access token this credential carries (the header value
    /// minus its `Bearer ` scheme). Only an OAuth connection has one — a static
    /// credential returns `None`. The reactive-401 path uses it to evict
    /// EXACTLY the token the upstream rejected, never a fresher one a
    /// concurrent caller just minted (`oauth::invalidate_rejected_access`).
    fn oauth_access(&self) -> Option<&str> {
        self.oauth_connection?;
        self.value.strip_prefix("Bearer ")
    }
}

/// Compose the header VALUE from the connection's scheme and the sealed
/// raw secret: `Bearer` prefixes, `Basic` base64-encodes (the stored secret
/// is `email:token`), empty scheme sends the bare token (the Sentry shape).
pub fn compose_header_value(scheme: &str, secret: &str) -> String {
    use base64::Engine;
    match scheme {
        "Bearer" => format!("Bearer {secret}"),
        "Basic" => format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(secret)
        ),
        _ => secret.to_string(),
    }
}

/// RFC 7230 token charset, with headers the MCP transport itself owns
/// denylisted — a connection must not be able to smuggle protocol fields.
pub fn valid_header_name(name: &str) -> bool {
    const DENY: &[&str] = &[
        "host",
        "content-length",
        "content-type",
        "accept",
        "mcp-session-id",
        "mcp-protocol-version",
    ];
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        && !DENY.contains(&name.to_ascii_lowercase().as_str())
}

/// Resolve the auth header for a brokered server (frozen-RunSpec path): fetch
/// the embedded connection fresh, then defer to [`brokered_auth_for_conn`].
/// `Ok(None)` = the server declared no connection (credential-free legacy
/// bundle).
pub async fn brokered_auth(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    server: &CapabilityServer,
) -> Result<Option<BrokeredAuth>, String> {
    let CapabilityServer::Brokered {
        name,
        url,
        connection_id,
        ..
    } = server
    else {
        return Err("not a brokered server".into());
    };
    let Some(cid) = connection_id else {
        return Ok(None);
    };
    auth_for_connection_id(state, scope, *cid, url)
        .await
        .map_err(|e| format!("capability server '{name}': {e}"))
}

/// The LEGACY embedded-connection resolution core: fetch the connection fresh by
/// id under `scope`, then defer to [`brokered_auth_for_conn`]. Shared by
/// [`brokered_auth`] (the frozen-RunSpec call path) and the terminal session
/// DELETE, so both send exactly the credential a live call would.
///
/// Unfiltered read by design: the LEGACY broker path's authority comes from the
/// frozen RunSpec's embedded `connection_id`, never a request viewer — so no
/// owner-visibility filter applies. This path (a pre-Phase-C bundle) froze no
/// binding, so there is no generation/owner to recheck; the status read inside
/// [`brokered_auth_for_conn`] is the only live check. Phase C runs route through
/// the binding path ([`recheck_binding`] + [`call_tool_for_conn`]), never here.
async fn auth_for_connection_id(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    cid: uuid::Uuid,
    url: &str,
) -> Result<Option<BrokeredAuth>, String> {
    // Tenant known (the frozen RunSpec's scope) → scoped_tx so the RLS GUC rides
    // the executor-generic read.
    let mut conn_tx = fluidbox_db::scoped_tx(&state.pool, scope)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?;
    let conn = fluidbox_db::get_connection(&mut *conn_tx, scope, cid)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?
        .ok_or_else(|| format!("connection {cid} is missing"))?;
    conn_tx
        .commit()
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?;
    brokered_auth_for_conn(state, scope, &conn, url).await
}

/// Credential-resolution CORE, callable with an ALREADY-FETCHED connection row
/// and an explicit endpoint url — the single function serving the frozen-RunSpec
/// broker path ([`brokered_auth`]), snapshot discovery ([`discover_snapshot`]),
/// and (Task 6) binding resolution. Enforces the same audience binding (the
/// connection pins `base_url`, and its credential is only ever sent to URLs
/// under that base — our RFC-8707 equivalent), the same custom header/scheme
/// composition, and the same OAuth minting. `Ok(None)` = no credential to send
/// (`auth_kind = "none"`, a credentialless remote).
pub async fn brokered_auth_for_conn(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    conn: &fluidbox_db::IntegrationConnectionRow,
    url: &str,
) -> Result<Option<BrokeredAuth>, String> {
    if conn.status != "active" {
        return Err(format!(
            "connection {} is {} — reconnect it",
            conn.id, conn.status
        ));
    }
    if conn.provider != "mcp_http" {
        return Err(format!(
            "connection provider '{}' does not hold MCP credentials",
            conn.provider
        ));
    }
    let base = conn
        .metadata
        .get("base_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("connection {} has no base_url — reconnect it", conn.id))?;
    if !url_within_base(url, base) {
        return Err(
            "url is outside the connection's base_url — refusing to send its credential (audience binding)".into(),
        );
    }
    // Credentialless remote (`auth_kind = "none"`): no header at all. MUST come
    // BEFORE the static branch, which would fail on the NULL sealed credential.
    if conn.auth_kind == "none" {
        return Ok(None);
    }
    if conn.auth_kind == "oauth" {
        let access = crate::oauth::ensure_access_token(state, conn).await?;
        return Ok(Some(BrokeredAuth {
            header: "authorization".into(),
            value: format!("Bearer {access}"),
            oauth_connection: Some(conn.id),
        }));
    }
    let sealer = state
        .sealer
        .as_ref()
        .ok_or("FLUIDBOX_CREDENTIAL_KEY not configured")?;
    // Tenant known (the connection's own scope) → scoped_tx so the RLS GUC rides
    // the executor-generic sealed-credential read.
    let mut cred_tx = fluidbox_db::scoped_tx(&state.pool, scope)
        .await
        .map_err(|e| format!("credential lookup failed: {e}"))?;
    let (sealed, kv) = fluidbox_db::connection_credential_sealed(&mut *cred_tx, scope, conn.id)
        .await
        .map_err(|e| format!("credential lookup failed: {e}"))?
        .ok_or("connection is not active (revoked or missing)")?;
    cred_tx
        .commit()
        .await
        .map_err(|e| format!("credential lookup failed: {e}"))?;
    let token = sealer
        .open(
            &sealed,
            kv,
            crate::seal::SealCtx::new(
                scope.tenant_id(),
                crate::seal::SealFamily::ConnectionCredential,
            ),
        )
        .await
        .map_err(|e| e.to_string())?;
    let header = conn
        .metadata
        .get("header_name")
        .and_then(|v| v.as_str())
        .unwrap_or("authorization")
        .to_string();
    let scheme = conn
        .metadata
        .get("scheme")
        .and_then(|v| v.as_str())
        .unwrap_or("Bearer");
    Ok(Some(BrokeredAuth {
        header,
        value: compose_header_value(scheme, &token),
        oauth_connection: None,
    }))
}

/// Revocation recheck for a CONNECTION-authority run resource binding (design
/// `:705-723`, invariant 21): fresh-read the connection and fail closed on
/// anything that would let a stale or revoked authority still execute. Called
/// by every credentialed consumer — the brokered MCP call, the workspace fetch,
/// and the GitHub result publish — IMMEDIATELY before secret access, so a
/// revoke takes effect on in-flight runs within one call.
///
/// Refuses when: the connection is non-active; its `authorization_generation`
/// no longer equals the generation the run froze (it was reauthorized to a new
/// account/audience since — a rotation within the same generation is fine);
/// the binding is user-owned and the owner's tenant membership is not active
/// (UNCONDITIONAL for user-owned — design `:713-716`); or the binding does not
/// belong to `scope`'s tenant (belt-and-braces). Returns the freshly-read row so
/// the caller sends the credential without a second lookup.
///
/// NOT this function's job: `subscription_secret` authorities (the delivery
/// worker compares the subscription row's generation itself) and the mechanical
/// `resource_scope` match for workspace/publish slots (the consumer enforces it
/// — the mcp scope is enforced by the upstream grant, design `:718-720`).
pub async fn recheck_binding(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    binding: &fluidbox_db::RunResourceBindingRow,
) -> Result<fluidbox_db::IntegrationConnectionRow, String> {
    recheck_binding_pool(&state.pool, scope, binding).await
}

/// Revalidate the RUN's invoking authority (design `:716-717`), which is
/// ORTHOGONAL to the binding's own connection/secret authority: a run bound to a
/// still-valid org connection may nonetheless have been started by a user since
/// deactivated, or by a subscription since disabled/deleted. Applied at the same
/// seam as [`recheck_binding`] (and by the signed-webhook publish path, which
/// carries no connection authority to recheck) so EVERY credentialed use fails
/// closed on a revoked invoker.
///
/// The invoking principal is read straight off the binding row: `create_run`
/// stamps `resolved_by_principal_id` with the invoking USER's id for `user` runs,
/// the invoking TRIGGER TOKEN's id for `trigger` runs (E1/design :741/:748), and
/// the acting SUBSCRIPTION's id for `schedule`/`webhook` runs (run_service.rs), so
/// no session/trigger-context lookup is needed — the minimal correct source.
/// `operator` (break-glass admin) and `system` (worker) hold no revocable
/// membership/subscription and pass; any OTHER kind fails closed (E2).
pub(crate) async fn recheck_invoking_authority(
    pool: &sqlx::PgPool,
    scope: fluidbox_db::TenantScope,
    principal_kind: &str,
    principal_id: Option<&str>,
) -> Result<(), String> {
    match principal_kind {
        "user" => {
            let uid = principal_id
                .and_then(|s| s.parse::<uuid::Uuid>().ok())
                .ok_or("run's invoking user id is missing or malformed")?;
            let active = fluidbox_db::identity::get_membership_by_user(pool, scope, uid)
                .await
                .map_err(|e| format!("invoking-user membership lookup failed: {e}"))?
                .is_some_and(|m| m.status == "active");
            if !active {
                return Err(
                    "the run's invoking user is no longer an active member — its authority is revoked".into(),
                );
            }
            Ok(())
        }
        // A trigger run froze the exact TOKEN as its principal: the token row must
        // still be a live trigger token AND its (immutable-FK) subscription must
        // still exist + be enabled — so a revoked/expired token fails closed, not
        // just a disabled subscription (E1).
        "trigger" => {
            let tid = principal_id
                .and_then(|s| s.parse::<uuid::Uuid>().ok())
                .ok_or("run's invoking trigger token id is missing or malformed")?;
            let active = fluidbox_db::trigger_token_active(pool, scope, tid)
                .await
                .map_err(|e| format!("invoking-token lookup failed: {e}"))?;
            if !active {
                return Err(
                    "the run's invoking trigger token was revoked or expired, or its subscription \
                     was disabled — its authority is revoked"
                        .into(),
                );
            }
            Ok(())
        }
        "schedule" | "webhook" => {
            let sid = principal_id
                .and_then(|s| s.parse::<uuid::Uuid>().ok())
                .ok_or("run's invoking subscription id is missing or malformed")?;
            let sub = fluidbox_db::get_trigger_subscription(pool, scope, sid)
                .await
                .map_err(|e| format!("invoking-subscription lookup failed: {e}"))?
                .ok_or(
                    "the run's invoking subscription no longer exists — its authority is revoked",
                )?;
            if !sub.enabled {
                return Err(
                    "the run's invoking subscription is disabled — its authority is revoked".into(),
                );
            }
            Ok(())
        }
        // operator / system: no revocable membership or subscription to check.
        "operator" | "system" => Ok(()),
        // Fail closed on any unrecognized principal kind (E2) — never pass an
        // authority we cannot revalidate.
        other => Err(format!(
            "run has an unrecognized invoking principal kind '{other}' — refusing"
        )),
    }
}

/// Pool-based core of [`recheck_binding`] — the public fn (fixed to take
/// `&AppState` by the Phase C plan) only unwraps `state.pool`. Split out so the
/// matrix DB tests drive it without an `AppState` (matching `bindings.rs`).
async fn recheck_binding_pool(
    pool: &sqlx::PgPool,
    scope: fluidbox_db::TenantScope,
    binding: &fluidbox_db::RunResourceBindingRow,
) -> Result<fluidbox_db::IntegrationConnectionRow, String> {
    // Tenant equality (belt-and-braces): the scoped reads below already pin the
    // tenant, but a binding row handed in from elsewhere must match it.
    if binding.tenant_id != scope.tenant_id() {
        return Err("run resource binding belongs to a different tenant".into());
    }
    // R2.2: the run's INVOKING authority must still be valid — orthogonal to the
    // connection authority below and checked before any secret access.
    recheck_invoking_authority(
        pool,
        scope,
        &binding.resolved_by_principal_kind,
        binding.resolved_by_principal_id.as_deref(),
    )
    .await?;
    let cid = binding
        .connection_id
        .ok_or("run resource binding has no connection authority to recheck")?;
    let expected_generation = binding
        .authority_generation
        .ok_or("connection binding froze no authorization generation")?;
    // Tenant known (the run's binding scope) → scoped_tx so the RLS GUC rides the
    // executor-generic read.
    let mut conn_tx = fluidbox_db::scoped_tx(pool, scope)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?;
    let conn = fluidbox_db::get_connection(&mut *conn_tx, scope, cid)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?
        .ok_or_else(|| format!("connection {cid} is missing"))?;
    conn_tx
        .commit()
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?;
    if conn.status != "active" {
        return Err(format!(
            "connection {} is {} — reconnect it",
            conn.id, conn.status
        ));
    }
    if conn.authorization_generation != expected_generation {
        return Err(format!(
            "connection {} was reauthorized after this run started — its binding is stale",
            conn.id
        ));
    }
    // R1.4(a): the connection's owner fields are immutable in v1, so the fresh
    // row MUST still match the owner the binding froze. A divergence is
    // corruption (or a would-be ownership swap) — fail closed rather than serve
    // a credential under a different owner than the run authorized.
    if conn.owner_type != binding.connection_owner_type.as_deref().unwrap_or_default()
        || conn.owner_user_id != binding.connection_owner_user_id
    {
        return Err(format!(
            "connection {} ownership changed since this run bound it — its binding is stale",
            conn.id
        ));
    }
    // User-owned connections: the owner must still hold an active membership —
    // unconditionally, never "where applicable" (design `:713-716`). A missing
    // membership row fails closed exactly like a deactivated one.
    if binding.connection_owner_type.as_deref() == Some("user") {
        let owner = binding
            .connection_owner_user_id
            .ok_or("user-owned binding is missing its owner id")?;
        let active = fluidbox_db::identity::get_membership_by_user(pool, scope, owner)
            .await
            .map_err(|e| format!("owner membership lookup failed: {e}"))?
            .is_some_and(|m| m.status == "active");
        if !active {
            return Err("the connection owner's tenant membership is not active".into());
        }
    }
    Ok(conn)
}

/// scheme + host + port must match; the base path must prefix the url path
/// at a `/` boundary. Case-insensitive host; default ports normalized by
/// the Url parser.
pub fn url_within_base(url: &str, base: &str) -> bool {
    let (Ok(u), Ok(b)) = (reqwest::Url::parse(url), reqwest::Url::parse(base)) else {
        return false;
    };
    if u.scheme() != b.scheme()
        || !u
            .host_str()
            .unwrap_or("")
            .eq_ignore_ascii_case(b.host_str().unwrap_or("?"))
        || u.port_or_known_default() != b.port_or_known_default()
    {
        return false;
    }
    let bp = b.path().trim_end_matches('/');
    if bp.is_empty() {
        return true;
    }
    let up = u.path();
    up == bp || up.starts_with(&format!("{bp}/"))
}

// ─── Per-run MCP session manager ──────────────────────────────────────────

/// The classification of ONE logical brokered dispatch (Phase E, #33; Gap 11,
/// plan E10) — INCLUDING its sanctioned single 401-reauth retry. The execution
/// claim is completed from this: `Definitive&&!is_error → succeeded`,
/// `Definitive&&is_error → failed_upstream`, `NeverSent → failed_before_send`
/// (the ONLY re-claimable state), `Ambiguous → ambiguous` (never auto-retried,
/// invariant 15). Err-free by design: every early return (auth resolution, URL
/// admission, breaker-open) is one of the three variants, so no caller can forget
/// to classify a failure.
#[derive(Debug)]
pub enum DispatchOutcome {
    /// The upstream answered definitively. `is_error=false` = a real MCP result;
    /// `is_error=true` = an MCP `isError` result OR a definitive upstream error
    /// (HTTP error status / JSON-RPC error object), rendered as an error result.
    Definitive {
        content: Value,
        is_error: bool,
        structured: Option<Value>,
    },
    /// POSITIVE proof no request bytes were written (URL admission refusal, auth
    /// resolution failure, binding recheck refusal, breaker-open, or a reqwest
    /// `is_connect()` transport error). Re-claimable.
    NeverSent(String),
    /// The request was (or may have been) sent but the outcome is unknown: a
    /// timeout, a mid-stream body-read/decode failure, or a post-connect redirect
    /// refusal. Terminal — never auto-retried.
    Ambiguous(String),
}

/// Broker call outcomes that stay distinguishable above the transport:
/// - `Unauthorized` — HTTP 401 with no scope challenge: an OAuth connection may
///   re-mint and retry exactly once (the 401 proves the tool never executed).
/// - `InsufficientScope` — an SEP-835 challenge: the grant lacks a scope, so a
///   re-mint cannot help; terminal for the call (the caller marks the
///   connection). Carries the (sanitized) scope the server asked for.
/// - `SessionExpired` — HTTP 404 on a request that carried a session id: the
///   session manager re-initializes ONCE and replays (never escapes as-is).
/// - `Other` — a DEFINITIVE upstream protocol error (HTTP 4xx, JSON-RPC error
///   object): the tool call resolved to an error → `failed_upstream`.
/// - `UpstreamUnavailable` — a DEFINITIVE 5xx. Classified exactly like `Other`
///   for the dispatch outcome (`failed_upstream`, never ambiguous), but split out
///   because it is the one definitive response that ALSO counts as an
///   upstream-HEALTH failure for the circuit breaker (plan E14).
/// - `NeverSent` — provable no-send (admit_url refusal, reqwest `is_connect()`).
/// - `Ambiguous` — sent/maybe-sent, outcome unknown (timeout, redirect after
///   connect, mid-stream body-read/decode failure).
#[derive(Debug)]
enum CallErr {
    Unauthorized,
    InsufficientScope(Option<String>),
    SessionExpired,
    Other(String),
    UpstreamUnavailable(String),
    NeverSent(String),
    Ambiguous(String),
}

impl CallErr {
    fn into_msg(self) -> String {
        match self {
            CallErr::Unauthorized => "mcp server rejected the credential (HTTP 401)".into(),
            CallErr::InsufficientScope(_) => {
                "insufficient scope — reconnect the connection with more scopes".into()
            }
            CallErr::SessionExpired => "mcp session expired and could not be re-initialized".into(),
            CallErr::Other(m)
            | CallErr::UpstreamUnavailable(m)
            | CallErr::NeverSent(m)
            | CallErr::Ambiguous(m) => m,
        }
    }
}

/// Classify one dialed HTTP status the session machinery could not use: a 5xx is
/// an upstream-health failure ([`CallErr::UpstreamUnavailable`]), any other error
/// status is a plain definitive error ([`CallErr::Other`]). Both render as
/// `failed_upstream`; only the former feeds the circuit breaker.
fn status_err(method: &str, status: reqwest::StatusCode) -> CallErr {
    let msg = format!("mcp {method} returned HTTP {status}");
    if status.is_server_error() {
        CallErr::UpstreamUnavailable(msg)
    } else {
        CallErr::Other(msg)
    }
}

impl From<String> for CallErr {
    fn from(m: String) -> Self {
        CallErr::Other(m)
    }
}

impl From<&str> for CallErr {
    fn from(m: &str) -> Self {
        CallErr::Other(m.into())
    }
}

/// A one-text-block error content array (an upstream/transport definitive error
/// carries no MCP `content`, so the runner-facing result synthesizes one). The
/// message is already sanitized (digests, not secrets).
fn err_content(msg: &str) -> Value {
    json!([{ "type": "text", "text": msg }])
}

/// Map the inner `call_tool` result (a real MCP result, or a classified
/// `CallErr`) to the dispatch's [`DispatchOutcome`] (plan E10). The retry logic
/// in the two public fns intercepts `Unauthorized`/`InsufficientScope` first;
/// the arms for them here are defensive.
fn outcome_from_call(r: Result<(Value, bool, Option<Value>), CallErr>) -> DispatchOutcome {
    match r {
        Ok((content, is_error, structured)) => DispatchOutcome::Definitive {
            content,
            is_error,
            structured,
        },
        Err(CallErr::NeverSent(m)) => DispatchOutcome::NeverSent(m),
        Err(CallErr::Ambiguous(m)) => DispatchOutcome::Ambiguous(m),
        // Definitive upstream protocol errors (HTTP status, JSON-RPC error) and
        // the terminal auth/session variants → an error RESULT (failed_upstream).
        Err(e) => DispatchOutcome::Definitive {
            content: err_content(&e.into_msg()),
            is_error: true,
            structured: None,
        },
    }
}

// ─── Outbound governor wiring (Phase E, E14) ──────────────────────────────

/// The upstream-host bucket key: the lowercased host, port-insensitive. Port
/// deliberately excluded — including it would let one connection evade its host
/// ceiling by cycling ports on the same machine. A URL with no parsable host
/// keys the empty bucket (its dial is refused a moment later by `admit_url`
/// anyway); the tenant/connection dimensions still bind either way.
fn host_key(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .unwrap_or_default()
}

/// The pre-dial governor gate for ONE brokered dispatch. Runs AFTER the execution
/// claim is won (the caller's `finish_won_claim`) and BEFORE anything touches the
/// wire — including before the per-peer MCP session mutex is acquired.
///
/// **Lock order (Task 2 rider):** governor → per-peer session mutex, never the
/// reverse. The governor's own lock is a leaf: `check` takes it, does pure
/// in-memory arithmetic, and releases it before returning — it never awaits, and
/// it never acquires the session registry map lock or a per-peer entry lock. So
/// this order cannot deadlock, and it also means a throttled or circuit-broken
/// call never blocks behind an in-flight call to the same peer just to be told no.
///
/// A refusal is a **pre-write proof of non-dispatch**, so it maps to
/// [`DispatchOutcome::NeverSent`] ⇒ claim `failed_before_send` ⇒ RE-CLAIMABLE,
/// which is exactly what makes the `retry after Ns` hint safe to act on. The
/// message carries the scope + the hint and a DIGEST of the upstream host — never
/// the host verbatim (same discipline as [`msg_digest`] on untrusted upstream
/// text). Returns the host key on admission, for the matching `report`.
fn governor_gate(
    gov: &crate::governor::EgressGovernor,
    tenant: uuid::Uuid,
    connection: uuid::Uuid,
    url: &str,
) -> Result<String, DispatchOutcome> {
    let host = host_key(url);
    match gov.check(tenant, connection, &host) {
        Ok(()) => Ok(host),
        Err(t) => {
            tracing::info!(
                target: "broker",
                "outbound dial refused by the egress governor (scope {}, upstream {}, retry {}s)",
                t.scope, msg_digest(&host), t.retry_after_secs
            );
            Err(DispatchOutcome::NeverSent(t.message(&msg_digest(&host))))
        }
    }
}

/// The circuit breaker's ONLY input: was this dial an upstream-HEALTH failure?
///
/// | dial result                                   | signal            |
/// |-----------------------------------------------|-------------------|
/// | `Ok(_)` — a real MCP result, `isError` or not | `Ok`              |
/// | JSON-RPC `error` object / HTTP 4xx (`Other`)  | `Ok`              |
/// | 401 / SEP-835 / 404-session-expired           | `Ok`              |
/// | HTTP 5xx (`UpstreamUnavailable`)              | `TransportFailure`|
/// | connect refused / SSRF-resolver / inadmissible URL (`NeverSent`) | `TransportFailure` |
/// | timeout / mid-stream read / refused redirect (`Ambiguous`)       | `TransportFailure` |
///
/// The load-bearing rule (plan E14): a DEFINITIVE upstream tool error means the
/// upstream is healthy and answering — an `isError` result, a JSON-RPC error, or
/// a 4xx MUST NOT trip the breaker. Only "we could not get a usable answer out of
/// this endpoint" does.
fn breaker_signal(r: &Result<(Value, bool, Option<Value>), CallErr>) -> crate::governor::Outcome {
    use crate::governor::Outcome;
    match r {
        Err(CallErr::UpstreamUnavailable(_))
        | Err(CallErr::NeverSent(_))
        | Err(CallErr::Ambiguous(_)) => Outcome::TransportFailure,
        _ => Outcome::Ok,
    }
}

/// The session-scoped headers set on every dialed request: the server-issued
/// `Mcp-Session-Id` (when present) and the negotiated `MCP-Protocol-Version`
/// (on every POST-initialize request — absent only DURING initialize, when
/// nothing is negotiated yet).
#[derive(Clone, Copy, Default)]
struct SessionHeaders<'a> {
    session_id: Option<&'a str>,
    protocol_version: Option<&'a str>,
}

/// One dialed JSON-RPC exchange's outcome at the transport layer.
#[derive(Debug)]
struct DialResponse {
    status: reqwest::StatusCode,
    /// The `Mcp-Session-Id` the server issued/echoed on THIS response, if any.
    session_id: Option<String>,
    /// The `WWW-Authenticate` challenge on a 401/403 (for SEP-835 parsing).
    www_authenticate: Option<String>,
    /// The selected JSON-RPC response value (Null on a non-2xx / empty body).
    value: Value,
}

/// Set the session headers a request carries, given the session's current state.
fn session_headers(sess: &McpUpstreamSession) -> SessionHeaders<'_> {
    SessionHeaders {
        session_id: sess.session_id.as_deref(),
        // `MCP-Protocol-Version` on every POST-initialize request; empty
        // negotiated (still handshaking) ⇒ no header.
        protocol_version: (!sess.negotiated.is_empty()).then_some(sess.negotiated.as_str()),
    }
}

/// Dial ONE request over the hardened `egress_http` and return the selected
/// JSON-RPC response. Admits the destination (scheme + host-literal IP block),
/// REFUSES any redirect (`Policy::none` — an MCP endpoint pivoting us onto a
/// fresh host is an SSRF vector), bounded-reads the DECODED body (8 MiB), runs
/// the incremental SSE parser (per-event cap) or JSON parse, validates the
/// content-type + `jsonrpc: "2.0"` + id match on success, replies `-32601` to
/// any server→client REQUEST and ignores notifications. Taking the client +
/// policy directly (not `&AppState`) keeps the redirect/parse contract testable
/// against a fake server.
async fn dial_rpc(
    client: &reqwest::Client,
    policy: &crate::egress::EgressPolicy,
    url: &str,
    auth: Option<&BrokeredAuth>,
    headers: SessionHeaders<'_>,
    body: &Value,
    timeout: Duration,
) -> Result<DialResponse, CallErr> {
    // URL admission is BEFORE any bytes leave — a refusal is provably no-send.
    crate::egress::admit_url(url, policy).map_err(|e| CallErr::NeverSent(e.to_string()))?;
    let res = match build_req(client, url, auth, headers)
        .timeout(timeout)
        .json(body)
        .send()
        .await
    {
        Ok(r) => r,
        // `Policy::none` can surface a refused redirect as an error; never echo
        // the Location target — log a digest of the request URL at debug only.
        // A redirect happens AFTER connect ⇒ the request was sent ⇒ Ambiguous.
        Err(e) if e.is_redirect() => {
            tracing::debug!(target: "broker", "mcp upstream redirect refused (req {})", msg_digest(url));
            return Err(CallErr::Ambiguous(
                "upstream attempted redirect (refused)".into(),
            ));
        }
        // A connect-phase error (DNS/SSRF-resolver rejection, refused TCP, TLS
        // handshake) is provable no-send; a timeout or any other transport error
        // after connect is Ambiguous (bytes may have gone out).
        Err(e) if e.is_connect() => {
            return Err(CallErr::NeverSent(format!("mcp server unreachable: {e}")));
        }
        Err(e) if e.is_timeout() => {
            return Err(CallErr::Ambiguous(format!("mcp request timed out: {e}")));
        }
        Err(e) => return Err(CallErr::Ambiguous(format!("mcp transport error: {e}"))),
    };
    let status = res.status();
    // A redirect the client did NOT follow comes back as a 3xx response under
    // `Policy::none`; refuse it identically and never echo the Location header.
    // The request WAS sent (we got a response) ⇒ Ambiguous.
    if status.is_redirection() {
        if let Some(loc) = res.headers().get("location").and_then(|v| v.to_str().ok()) {
            tracing::debug!(target: "broker", "mcp upstream redirect refused (loc {})", msg_digest(loc));
        }
        return Err(CallErr::Ambiguous(
            "upstream attempted redirect (refused)".into(),
        ));
    }
    let session_id = header_str(&res, "mcp-session-id");
    let www_authenticate = header_str(&res, "www-authenticate");
    let content_type = header_str(&res, "content-type").unwrap_or_default();
    let is_sse = content_type.contains("event-stream");
    let is_json = content_type.contains("application/json");
    // R3.3: refuse an over-large advertised body BEFORE buffering it in memory.
    // Sent + a response received but unusable ⇒ Ambiguous.
    if let Some(len) = res.content_length() {
        if len > MAX_RESPONSE_BYTES {
            return Err(CallErr::Ambiguous(format!(
                "mcp response advertises {len} bytes, over the {MAX_RESPONSE_BYTES}-byte cap"
            )));
        }
    }
    // The Content-Length pre-check only bounds a body that ADVERTISES its length;
    // a chunked/compressed response slips it and `text()` would buffer unboundedly
    // (D). Stream the DECODED body, aborting the moment it would exceed the cap.
    // A mid-stream read failure or over-cap ⇒ Ambiguous (the send happened).
    let mut stream = res.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| CallErr::Ambiguous(format!("mcp response unreadable: {e}")))?;
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES as usize {
            return Err(CallErr::Ambiguous(format!(
                "mcp response exceeds the {MAX_RESPONSE_BYTES}-byte cap while streaming"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    // The body is only interpreted as JSON-RPC on SUCCESS: an error status
    // (401/403/404/5xx) is classified by the caller off `status`; its body
    // (often text/html) is not our protocol payload.
    if !status.is_success() || buf.is_empty() {
        return Ok(DialResponse {
            status,
            session_id,
            www_authenticate,
            value: Value::Null,
        });
    }
    if !is_sse && !is_json {
        return Err(CallErr::Ambiguous(format!(
            "mcp response has an unexpected content-type '{content_type}' (want application/json or text/event-stream)"
        )));
    }
    let messages = parse_messages(&buf, is_sse).map_err(CallErr::Ambiguous)?;
    let value = select_response(client, url, auth, headers, messages, body.get("id"))
        .await
        .map_err(CallErr::Ambiguous)?;
    Ok(DialResponse {
        status,
        session_id,
        www_authenticate,
        value,
    })
}

/// Build the POST with content-type/accept + auth + session headers.
fn build_req(
    client: &reqwest::Client,
    url: &str,
    auth: Option<&BrokeredAuth>,
    headers: SessionHeaders<'_>,
) -> reqwest::RequestBuilder {
    // The per-request timeout is applied by the caller (`dial_rpc` uses
    // `MCP_TIMEOUT`; `reply_method_not_found` uses `MCP_DELETE_TIMEOUT`) so a test
    // can dial with a short timeout to exercise the Ambiguous timeout arm.
    let mut req = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(a) = auth {
        req = req.header(a.header.as_str(), a.value.as_str());
    }
    if let Some(sid) = headers.session_id {
        req = req.header("mcp-session-id", sid);
    }
    if let Some(v) = headers.protocol_version {
        req = req.header("mcp-protocol-version", v);
    }
    req
}

fn header_str(res: &reqwest::Response, name: &str) -> Option<String> {
    res.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Turn a decoded body into the list of JSON-RPC messages it carries: the SSE
/// path assembles events (per-event cap) and parses each `data:` payload; the
/// JSON path parses one object (or a batch array).
fn parse_messages(buf: &[u8], is_sse: bool) -> Result<Vec<Value>, String> {
    if is_sse {
        let mut asm = crate::mcp_sse::SseEventAssembler::new();
        let mut events = asm.feed(buf)?;
        events.extend(asm.finish());
        Ok(events
            .into_iter()
            .filter_map(|e| serde_json::from_str::<Value>(&e.data).ok())
            .collect())
    } else {
        match serde_json::from_slice::<Value>(buf) {
            Ok(Value::Array(a)) => Ok(a),
            Ok(v) => Ok(vec![v]),
            Err(e) => Err(format!("mcp response was not JSON: {e}")),
        }
    }
}

/// From the parsed messages: reply `-32601` to any server→client REQUEST, log
/// (and ignore) notifications, and return the RESPONSE whose id matches ours.
/// Validates `jsonrpc == "2.0"` on the selected response.
async fn select_response(
    client: &reqwest::Client,
    url: &str,
    auth: Option<&BrokeredAuth>,
    headers: SessionHeaders<'_>,
    messages: Vec<Value>,
    want_id: Option<&Value>,
) -> Result<Value, String> {
    let mut selected: Option<Value> = None;
    for m in messages {
        let has_method = m.get("method").is_some();
        let msg_id = m.get("id").cloned();
        if has_method && msg_id.is_some() {
            // A server→client REQUEST: we implement none of them — respond with
            // a JSON-RPC "method not found" rather than silently ignoring it
            // (2025-11-25 conformance), best-effort on the same session.
            reply_method_not_found(client, url, auth, headers, msg_id.as_ref()).await;
            continue;
        }
        if has_method {
            // A NOTIFICATION (no id): log and continue; a list-change is noted
            // specially but never acted on (the frozen snapshot is the surface).
            let method = m.get("method").and_then(Value::as_str).unwrap_or("");
            if method.contains("list_changed") {
                tracing::debug!(target: "broker", "mcp server sent {method} (ignored — snapshot is frozen)");
            } else {
                tracing::debug!(target: "broker", "mcp server notification {method} (ignored)");
            }
            continue;
        }
        // A RESPONSE. Match our id (or take the last when we sent none).
        let is_ours = match (want_id, &msg_id) {
            (Some(w), Some(i)) => w == i,
            (None, _) => true,
            _ => false,
        };
        if is_ours {
            if m.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                return Err("mcp response is not JSON-RPC 2.0".into());
            }
            selected = Some(m);
        }
    }
    Ok(selected.unwrap_or(Value::Null))
}

/// Best-effort `-32601` reply to a server→client request on the same session.
/// Fire-and-forget: we never read its response (and never recurse on it). The
/// url is already `admit_url`-vetted for this exchange.
async fn reply_method_not_found(
    client: &reqwest::Client,
    url: &str,
    auth: Option<&BrokeredAuth>,
    headers: SessionHeaders<'_>,
    req_id: Option<&Value>,
) {
    let body = json!({
        "jsonrpc": "2.0",
        "id": req_id.cloned().unwrap_or(Value::Null),
        "error": { "code": -32601, "message": "method not found" },
    });
    let _ = build_req(client, url, auth, headers)
        .timeout(MCP_DELETE_TIMEOUT)
        .json(&body)
        .send()
        .await;
}

/// A short, non-reversible fingerprint of an UNTRUSTED upstream error message
/// (C). A malicious MCP server can echo the bearer we just sent inside its
/// JSON-RPC error message; that string must never leave the broker verbatim (it
/// would flow into logs, the connection's persisted `oauth.error`, and the
/// dashboard). We surface method + JSON-RPC code + this digest so an operator can
/// still correlate repeated failures without the bytes. Shared with `oauth.rs`,
/// whose AS-error log boundary needs the identical treatment (an authorization
/// server can echo the sealed state/code/verifier/secret).
pub(crate) fn msg_digest(msg: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(&Sha256::digest(msg.as_bytes())[..8])
    )
}

fn unwrap_result(value: Value, method: &str) -> Result<Value, String> {
    if let Some(err) = value.get("error") {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        // The upstream message is untrusted — surface only its digest (C).
        let digest = err
            .get("message")
            .and_then(|m| m.as_str())
            .map(msg_digest)
            .unwrap_or_else(|| "none".into());
        return Err(format!("mcp {method} failed (code {code}, msg {digest})"));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| format!("mcp {method} returned no result"))
}

/// How the negotiated protocol version is validated after `initialize`.
enum VersionPolicy<'a> {
    /// Discovery/photograph: accept ANY non-empty version (it is what the
    /// snapshot RECORDS — survey A §2e), so a server speaking a valid-but-
    /// non-standard revision can still be photographed.
    Record,
    /// A runtime call: the negotiated version must be one we speak
    /// ([`SUPPORTED_PROTOCOLS`]), OR — once Task 3 threads it — exactly the
    /// version the frozen snapshot recorded (drift ⇒ deny, remedy /tools/refresh).
    Enforce { snapshot: Option<&'a str> },
}

/// Validate a runtime-call negotiated version (E5). `snapshot` is the frozen
/// surface's `protocol_version` when present (Task 3 threads it): when it is
/// `Some`, the ONLY requirement is an exact match (a server that photographed as
/// X must still speak X — otherwise it drifted); when `None`, membership in
/// [`SUPPORTED_PROTOCOLS`]. Never enforced on the discovery path (see
/// [`VersionPolicy::Record`]).
fn check_negotiated(negotiated: &str, snapshot: Option<&str>) -> Result<(), String> {
    if negotiated.is_empty() {
        return Err("mcp server negotiated no protocol version".into());
    }
    match snapshot.filter(|s| !s.is_empty()) {
        Some(snap) if negotiated == snap => Ok(()),
        Some(snap) => Err(format!(
            "mcp protocol drift: server now negotiates '{negotiated}' but this run's frozen \
             snapshot recorded '{snap}' — run POST /v1/connections/{{id}}/tools/refresh to re-photograph"
        )),
        None if SUPPORTED_PROTOCOLS.contains(&negotiated) => Ok(()),
        None => Err(format!(
            "mcp server negotiated unsupported protocol version '{negotiated}' (supported: {})",
            SUPPORTED_PROTOCOLS.join(", ")
        )),
    }
}

/// Classify a 401/403 for the reactive-auth path. An SEP-835
/// `insufficient_scope` challenge (E8) is TERMINAL — a re-mint cannot add a
/// scope the grant never had — and carries the scope the server asked for; a
/// plain 401 is a stale-credential signal (retry once after re-mint); a plain
/// 403 is neither (falls through to a hard error).
fn auth_error(status: reqwest::StatusCode, www_authenticate: Option<&str>) -> Option<CallErr> {
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        if let Some(chal) = www_authenticate.and_then(crate::oauth::parse_insufficient_scope) {
            return Some(CallErr::InsufficientScope(chal.scope));
        }
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Some(CallErr::Unauthorized);
        }
    }
    None
}

/// Send one request over the hardened client with the session's current headers.
async fn send_raw(
    client: &reqwest::Client,
    policy: &crate::egress::EgressPolicy,
    url: &str,
    auth: Option<&BrokeredAuth>,
    sess: &McpUpstreamSession,
    body: &Value,
) -> Result<DialResponse, CallErr> {
    dial_rpc(
        client,
        policy,
        url,
        auth,
        session_headers(sess),
        body,
        MCP_TIMEOUT,
    )
    .await
}

/// Ensure this session is `initialize`d (E5): if it has not negotiated yet, run
/// `initialize` FIRST (never a tools/* probe — stateless-first is gone), record
/// the negotiated version + optional session id, VALIDATE the version per
/// `policy`, then send `notifications/initialized` UNCONDITIONALLY (the old
/// session-id gate is dropped). Idempotent — a cache-hit (already negotiated)
/// returns immediately.
async fn ensure_initialized(
    client: &reqwest::Client,
    policy: &crate::egress::EgressPolicy,
    url: &str,
    auth: Option<&BrokeredAuth>,
    sess: &mut McpUpstreamSession,
    version: VersionPolicy<'_>,
) -> Result<(), CallErr> {
    if !sess.negotiated.is_empty() {
        return Ok(());
    }
    let id = sess.next();
    let body = json!({
        "jsonrpc": "2.0", "id": id, "method": "initialize",
        "params": {
            "protocolVersion": OFFERED_PROTOCOL,
            "capabilities": {},
            "clientInfo": { "name": "fluidbox-broker", "version": env!("CARGO_PKG_VERSION") },
        }
    });
    let resp = send_raw(client, policy, url, auth, sess, &body).await?;
    if let Some(e) = auth_error(resp.status, resp.www_authenticate.as_deref()) {
        return Err(e);
    }
    if !resp.status.is_success() {
        return Err(status_err("initialize", resp.status));
    }
    let result = unwrap_result(resp.value, "initialize")?;
    let negotiated = result
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    match version {
        VersionPolicy::Record => {
            if negotiated.is_empty() {
                return Err(CallErr::Other(
                    "mcp server negotiated no protocolVersion at initialize — cannot record a trustworthy snapshot".into(),
                ));
            }
        }
        // Runtime call: `snapshot` is the frozen surface's `protocol_version`
        // (threaded from `call_tool_for_conn` since Task 3, Gap 12). `Some(v)` ⇒
        // the negotiated version must equal `v` exactly (drift ⇒ deny); `None` ⇒
        // SUPPORTED-set membership (legacy surfaces / the embedded-connection path).
        VersionPolicy::Enforce { snapshot } => {
            check_negotiated(&negotiated, snapshot).map_err(CallErr::Other)?;
        }
    }
    sess.negotiated = negotiated;
    sess.session_id = resp.session_id;
    // `notifications/initialized` UNCONDITIONALLY after a successful initialize
    // (drop the old session-id gate); fire-and-forget (servers answer 202).
    let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let _ = send_raw(client, policy, url, auth, sess, &note).await;
    Ok(())
}

/// Send ONE JSON-RPC request within an already-initialized session, drawing a
/// fresh id from the session counter. Classifies auth (401/403 → Unauthorized /
/// InsufficientScope) and a 404-with-session (→ SessionExpired, for the caller's
/// single reinit) before unwrapping the result.
async fn call_in_session(
    client: &reqwest::Client,
    policy: &crate::egress::EgressPolicy,
    url: &str,
    auth: Option<&BrokeredAuth>,
    sess: &mut McpUpstreamSession,
    method: &str,
    params: Value,
) -> Result<Value, CallErr> {
    let had_session = sess.session_id.is_some();
    let id = sess.next();
    let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    let resp = send_raw(client, policy, url, auth, sess, &body).await?;
    // A server may (re)issue a session id on any response — adopt it.
    if resp.session_id.is_some() {
        sess.session_id = resp.session_id.clone();
    }
    if let Some(e) = auth_error(resp.status, resp.www_authenticate.as_deref()) {
        return Err(e);
    }
    // 404 on a request that carried a session id ⇒ the session was dropped
    // upstream; the caller re-initializes ONCE and replays.
    if resp.status == reqwest::StatusCode::NOT_FOUND && had_session {
        return Err(CallErr::SessionExpired);
    }
    if !resp.status.is_success() {
        return Err(status_err(method, resp.status));
    }
    unwrap_result(resp.value, method).map_err(Into::into)
}

/// A full managed request against a `(run, peer)` session: initialize if
/// needed, send, and on a 404-with-session re-initialize ONCE (reset in place —
/// same registry slot, so the entry count never grows) and replay ONCE. A
/// second 404 is terminal (never refreshes/expands the tool set).
#[allow(clippy::too_many_arguments)]
async fn managed_call(
    client: &reqwest::Client,
    policy: &crate::egress::EgressPolicy,
    url: &str,
    auth: Option<&BrokeredAuth>,
    entry: &Arc<Mutex<McpUpstreamSession>>,
    method: &str,
    params: Value,
    snapshot: Option<&str>,
) -> Result<Value, CallErr> {
    let mut sess = entry.lock().await;
    ensure_initialized(
        client,
        policy,
        url,
        auth,
        &mut sess,
        VersionPolicy::Enforce { snapshot },
    )
    .await?;
    match call_in_session(client, policy, url, auth, &mut sess, method, params.clone()).await {
        Err(CallErr::SessionExpired) => {
            // Reinit ONCE and replay ONCE. reset() keeps the same map slot (no
            // leak) but forces a fresh initialize.
            sess.reset();
            ensure_initialized(
                client,
                policy,
                url,
                auth,
                &mut sess,
                VersionPolicy::Enforce { snapshot },
            )
            .await?;
            match call_in_session(client, policy, url, auth, &mut sess, method, params).await {
                // A second 404 is terminal — surface a clear protocol error.
                Err(CallErr::SessionExpired) => Err(CallErr::Other(
                    "mcp session expired again after re-initialization".into(),
                )),
                other => other,
            }
        }
        other => other,
    }
}

/// Get (or create) the replica-local registry entry for one `(run, peer)`.
async fn session_entry(
    state: &AppState,
    run_session: uuid::Uuid,
    peer: McpPeer,
    url: &str,
) -> Arc<Mutex<McpUpstreamSession>> {
    state
        .mcp_sessions
        .lock()
        .await
        .entry((run_session, peer))
        .or_insert_with(|| Arc::new(Mutex::new(McpUpstreamSession::fresh(url))))
        .clone()
}

/// Terminal MCP cleanup for a finished run (E5): DELETE each live upstream
/// session best-effort and EVICT every registry entry for the run regardless of
/// the DELETE outcome. Hooked into the orchestrator's terminal driver. Runs are
/// replica-local — entries only exist on the replica that made the calls.
///
/// The DELETE carries the SAME authorization header a live call would (design
/// `:914` — "always send the OAuth/static authorization header on every upstream
/// HTTP request; an MCP session ID is routing state, not authentication"), so a
/// conforming upstream actually terminates the session instead of 401ing it.
/// The credential is RE-RESOLVED here through the live path (invariant 9: every
/// upstream call rechecks live revoke/status state) rather than cached on the
/// registry entry at call time: by teardown a cached header could name a
/// connection that has since been revoked, reauthorized to a new generation, or
/// whose owner left the org — and an access token minted minutes ago may have
/// expired. A revoked connection is precisely the case where we must NOT send a
/// credential, so a resolution/recheck failure SKIPS the DELETE entirely.
/// (Caching it would also park ambient credential state on a long-lived
/// in-memory map, which invariant 22 rules out. Do not "optimize" this into a
/// stored header.)
pub async fn run_terminal_mcp_cleanup(state: &AppState, session_id: uuid::Uuid) {
    // Evict FIRST and unconditionally — before any DB or network work, so a
    // wedged upstream (or an unresolvable tenant) never strands an entry.
    let drained = drain_run_sessions(&state.mcp_sessions, session_id).await;
    if drained.is_empty() {
        return;
    }
    // ONE cross-tenant session lookup for the whole run (a worker/system entry
    // holds only a bare id); the per-peer resolution below is tenant-scoped.
    let scope = match fluidbox_db::system_worker::get_session(&state.pool, session_id).await {
        Ok(Some(s)) => Some(fluidbox_db::TenantScope::assume(s.tenant_id)),
        Ok(None) => None,
        Err(e) => {
            tracing::debug!(target: "broker", "mcp cleanup tenant resolve failed (best-effort): {e}");
            None
        }
    };
    delete_upstream_sessions(
        &state.egress_http,
        &state.egress_policy,
        drained,
        |peer, url| async move {
            let scope = scope.ok_or_else(|| "run's tenant could not be resolved".to_string())?;
            terminal_peer_auth(state, scope, peer, &url).await
        },
    )
    .await;
}

/// Drain (evict) every registry entry for one run under the map lock, returning
/// them with their peer identity so each can be resolved + DELETEd outside the
/// lock. Eviction is unconditional and happens before any I/O.
async fn drain_run_sessions(
    registry: &crate::state::McpSessionRegistry,
    session_id: uuid::Uuid,
) -> Vec<(McpPeer, Arc<Mutex<McpUpstreamSession>>)> {
    let mut map = registry.lock().await;
    let keys: Vec<(uuid::Uuid, McpPeer)> = map
        .keys()
        .filter(|(sid, _)| *sid == session_id)
        .cloned()
        .collect();
    keys.iter()
        .filter_map(|k| map.remove(k).map(|e| (k.1, e)))
        .collect()
}

/// Re-resolve one drained peer's credential the way a live call does — the
/// binding path reverifies the binding (status + generation + owner + invoker)
/// via [`recheck_binding`] before [`brokered_auth_for_conn`]; the legacy
/// embedded-connection path takes the same fetch-then-resolve core the frozen
/// RunSpec path uses. Any refusal propagates, and the caller skips the DELETE.
async fn terminal_peer_auth(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    peer: McpPeer,
    url: &str,
) -> Result<Option<BrokeredAuth>, String> {
    match peer {
        McpPeer::Binding(binding_id) => {
            let binding = fluidbox_db::get_run_resource_binding(&state.pool, scope, binding_id)
                .await
                .map_err(|e| format!("run resource binding lookup failed: {e}"))?
                .ok_or("run resource binding is missing")?;
            let conn = recheck_binding(state, scope, &binding).await?;
            brokered_auth_for_conn(state, scope, &conn, url).await
        }
        McpPeer::Conn(cid) => auth_for_connection_id(state, scope, cid, url).await,
    }
}

/// The registry-free DELETE loop (client + policy + the resolver explicit, so a
/// fake server can assert the DELETE — and the skip — without a full
/// `AppState`). Best-effort and bounded by `MCP_DELETE_TIMEOUT`; nothing here
/// can block terminalization.
async fn delete_upstream_sessions<F, Fut>(
    client: &reqwest::Client,
    policy: &crate::egress::EgressPolicy,
    drained: Vec<(McpPeer, Arc<Mutex<McpUpstreamSession>>)>,
    resolve_auth: F,
) where
    F: Fn(McpPeer, String) -> Fut,
    Fut: std::future::Future<Output = Result<Option<BrokeredAuth>, String>>,
{
    for (peer, entry) in drained {
        let sess = entry.lock().await;
        let (Some(sid), url) = (sess.session_id.as_deref(), sess.url.as_str()) else {
            continue;
        };
        // Egress admission stays in front of the dial — and ahead of the
        // resolution, so a url we would refuse never mints a token.
        if crate::egress::admit_url(url, policy).is_err() {
            continue;
        }
        // Invariant 9: a refusal here (revoked connection, moved generation,
        // deactivated owner, unavailable credential) means we must not send a
        // credential — and an unauthorized DELETE would just 401 — so skip it.
        // Termination is best-effort; the upstream expires the session itself.
        let auth = match resolve_auth(peer, url.to_string()).await {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(target: "broker", "mcp session DELETE skipped (credential unavailable): {e}");
                continue;
            }
        };
        let mut req = client
            .delete(url)
            .timeout(MCP_DELETE_TIMEOUT)
            .header("mcp-session-id", sid);
        if let Some(a) = auth.as_ref() {
            req = req.header(a.header.as_str(), a.value.as_str());
        }
        if !sess.negotiated.is_empty() {
            req = req.header("mcp-protocol-version", sess.negotiated.as_str());
        }
        if let Err(e) = req.send().await {
            tracing::debug!(target: "broker", "mcp session DELETE failed (best-effort): {e}");
        }
    }
}

/// SEP-835 (E8): mark a connection `status='error'` with a reconnect-with-more-
/// scopes note and evict its rejected access token. The note records the
/// (sanitized) challenge scope only; routed through the SAME `mark_connection_error`
/// entry the `invalid_grant` writer uses, under the run's tenant scope.
async fn mark_insufficient_scope(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    connection_id: uuid::Uuid,
    rejected_token: &str,
    challenge_scope: Option<String>,
) {
    let note = match challenge_scope.filter(|s| !s.is_empty()) {
        Some(s) => {
            format!("insufficient_scope: reconnect with more scopes (server asked for: {s})")
        }
        None => "insufficient_scope: reconnect with more scopes".to_string(),
    };
    if let Ok(mut tx) = fluidbox_db::scoped_tx(&state.pool, scope).await {
        if fluidbox_db::mark_connection_error(&mut *tx, scope, connection_id, &note)
            .await
            .is_ok()
        {
            tx.commit().await.ok();
        }
    }
    // Compare-and-drop: only evict the exact token the upstream rejected (keeps
    // the singleflight intact if a concurrent caller already re-minted).
    crate::oauth::invalidate_rejected_access(state, connection_id, rejected_token).await;
}

// ─── The two operations fluidbox performs ─────────────────────────────────

/// Map one `tools/list` result page into snapshot shape (camelCase
/// `inputSchema` → snake `input_schema`; `outputSchema` → `output_schema` (E7);
/// annotations kept verbatim), appending to `out`, and return the page's
/// `nextCursor` (absent = last page). Shared by the probe path and the
/// forced-negotiation snapshot discovery so both map identically.
fn map_tools_page(result: &Value, out: &mut Vec<ToolSnapshot>) -> Result<Option<String>, CallErr> {
    for t in result
        .get("tools")
        .and_then(|v| v.as_array())
        .ok_or("mcp tools/list result has no tools array")?
    {
        out.push(ToolSnapshot {
            name: t
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or("mcp tools/list entry has no name")?
                .to_string(),
            description: t
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            input_schema: t
                .get("inputSchema")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "object" })),
            // E7: capture the declared output schema so the frozen surface can
            // carry it (and the digest covers it). Absent ⇒ None.
            output_schema: t.get("outputSchema").cloned(),
            annotations: t.get("annotations").cloned(),
        });
    }
    Ok(result
        .get("nextCursor")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string))
}

/// Credential-free pre-connect discovery (the probe). `initialize`s first (via
/// the SHARED session machinery — stateless-first is gone), accepts any
/// negotiated version ([`VersionPolicy::Record`]), and paginates tools/list.
/// A throwaway session (no registry): the probe persists nothing.
async fn discover_tools(
    state: &AppState,
    url: &str,
    auth: Option<&BrokeredAuth>,
) -> Result<Vec<ToolSnapshot>, CallErr> {
    let client = &state.egress_http;
    let policy = &state.egress_policy;
    let mut sess = McpUpstreamSession::fresh(url);
    ensure_initialized(client, policy, url, auth, &mut sess, VersionPolicy::Record).await?;
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_LIST_PAGES {
        let params = match &cursor {
            Some(c) => json!({ "cursor": c }),
            None => json!({}),
        };
        let result =
            call_in_session(client, policy, url, auth, &mut sess, "tools/list", params).await?;
        cursor = map_tools_page(&result, &mut tools)?;
        if cursor.is_none() {
            break;
        }
    }
    if tools.is_empty() {
        return Err(CallErr::Other("mcp server advertises no tools".into()));
    }
    Ok(tools)
}

/// The forced-negotiation photograph (design :298-343; Phase C). Rides the SAME
/// initialize-first machinery as the runtime call path ([`ensure_initialized`]);
/// records a REAL negotiated protocol version (`Record` accepts any non-empty
/// one, so a valid-but-non-standard revision can still be photographed — survey
/// A §2e), and — per design :1282-1283 — fails when a `nextCursor` still remains
/// after the page cap (freeze the whole surface or none). The remote list is
/// untrusted input: it passes core's IDENTICAL `validate_tools` screen (charset,
/// poison-screen, caps) before it can become a snapshot. Uses a throwaway
/// session (discovery is one-shot, not a per-run reused session).
pub async fn discover_snapshot(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    conn: &fluidbox_db::IntegrationConnectionRow,
    endpoint_url: &str,
) -> anyhow::Result<(String, Vec<ToolSnapshot>)> {
    let auth = brokered_auth_for_conn(state, scope, conn, endpoint_url)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let client = &state.egress_http;
    let policy = &state.egress_policy;
    let mut sess = McpUpstreamSession::fresh(endpoint_url);
    ensure_initialized(
        client,
        policy,
        endpoint_url,
        auth.as_ref(),
        &mut sess,
        VersionPolicy::Record,
    )
    .await
    .map_err(|e| anyhow::anyhow!(e.into_msg()))?;
    // `Record` guaranteed a non-empty negotiated version.
    let protocol_version = sess.negotiated.clone();
    // Paginate tools/list WITH the session; fail (not freeze) on a leftover cursor.
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    let mut complete = false;
    for _ in 0..MAX_LIST_PAGES {
        let params = match &cursor {
            Some(c) => json!({ "cursor": c }),
            None => json!({}),
        };
        let result = call_in_session(
            client,
            policy,
            endpoint_url,
            auth.as_ref(),
            &mut sess,
            "tools/list",
            params,
        )
        .await
        .map_err(|e| anyhow::anyhow!(e.into_msg()))?;
        cursor = map_tools_page(&result, &mut tools).map_err(|e| anyhow::anyhow!(e.into_msg()))?;
        if cursor.is_none() {
            complete = true;
            break;
        }
    }
    if !complete {
        anyhow::bail!(
            "mcp server advertises more tools than the discovery page cap — refusing to freeze a partial snapshot"
        );
    }
    fluidbox_core::capability::validate_tools("mcp connection", &tools)
        .map_err(|e| anyhow::anyhow!("discovered tool snapshot failed validation: {e}"))?;
    Ok((protocol_version, tools))
}

/// One brokered tool execution against a `(run, peer)` session. Returns
/// (content, is_error, structured_content) from the MCP result — `structuredContent`
/// (E7) is passed through when present. At-least-once under network failure by
/// design — the caller ledgers every attempt; we never blind-retry after a
/// request was sent.
#[allow(clippy::too_many_arguments)]
async fn call_tool(
    client: &reqwest::Client,
    policy: &crate::egress::EgressPolicy,
    url: &str,
    auth: Option<&BrokeredAuth>,
    entry: &Arc<Mutex<McpUpstreamSession>>,
    tool: &str,
    arguments: &Value,
    snapshot: Option<&str>,
) -> Result<(Value, bool, Option<Value>), CallErr> {
    let result = managed_call(
        client,
        policy,
        url,
        auth,
        entry,
        "tools/call",
        json!({ "name": tool, "arguments": arguments }),
        snapshot,
    )
    .await?;
    let is_error = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let content = result.get("content").cloned().unwrap_or(json!([]));
    let structured = result.get("structuredContent").cloned();
    Ok((cap_content(content), is_error, cap_structured(structured)))
}

/// Reactive-401 recovery, OAuth connections only: drop the REJECTED access
/// token and mint a fresh one. A static credential that 401s is terminal —
/// there is nothing to refresh.
///
/// The eviction is compare-and-drop, not unconditional: concurrent calls all
/// 401 on the same stale token, and wiping a token another caller has already
/// refreshed into place would defeat `ensure_access_token`'s singleflight and
/// rotate the refresh token once per concurrent 401.
async fn reauth_after_401(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    server: &CapabilityServer,
    auth: Option<BrokeredAuth>,
) -> Result<Option<BrokeredAuth>, String> {
    let Some(cid) = auth.as_ref().and_then(|a| a.oauth_connection) else {
        return Err("mcp server rejected the credential (HTTP 401)".into());
    };
    let rejected = auth.as_ref().and_then(|a| a.oauth_access()).unwrap_or("");
    crate::oauth::invalidate_rejected_access(state, cid, rejected).await;
    brokered_auth(state, scope, server).await
}

fn server_url(server: &CapabilityServer) -> Result<&str, String> {
    match server {
        CapabilityServer::Brokered { url, .. } => Ok(url),
        _ => Err("not a brokered server".into()),
    }
}

/// The embedded connection id of a legacy brokered server (`None` = a
/// credential-free legacy bundle — it keys no per-run registry entry and simply
/// re-initializes a throwaway session each call).
fn brokered_connection_id(server: &CapabilityServer) -> Option<uuid::Uuid> {
    match server {
        CapabilityServer::Brokered { connection_id, .. } => *connection_id,
        _ => None,
    }
}

/// Execute one brokered tool with credential resolution + the single
/// reactive-401 retry (safe: a 401 at the auth layer proves the tool never
/// executed). The legacy embedded-connection path — keys the per-run session
/// registry on the connection (`McpPeer::Conn`) so calls in the same run reuse
/// one `initialize`d session. `run_session` is the run's session id (registry
/// key). Returns (content, is_error, structured_content).
pub async fn call_tool_auth(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    server: &CapabilityServer,
    tool: &str,
    arguments: &Value,
    run_session: uuid::Uuid,
) -> DispatchOutcome {
    let url = match server_url(server) {
        Ok(u) => u,
        Err(e) => return DispatchOutcome::NeverSent(e),
    };
    // Auth resolution BEFORE any request write ⇒ a failure is provable no-send.
    let auth = match brokered_auth(state, scope, server).await {
        Ok(a) => a,
        Err(e) => return DispatchOutcome::NeverSent(e),
    };
    // E14: the governor gate, BEFORE the per-peer session mutex (see
    // `governor_gate` for the lock order) and before any bytes leave. A
    // credential-free legacy bundle has no connection to key on — it takes the
    // nil id, and the breaker's (connection, host) key still separates upstreams.
    let conn_key = brokered_connection_id(server).unwrap_or_else(uuid::Uuid::nil);
    let host = match governor_gate(&state.governor, scope.tenant_id(), conn_key, url) {
        Ok(h) => h,
        Err(refused) => return refused,
    };
    let entry = match brokered_connection_id(server) {
        Some(cid) => session_entry(state, run_session, McpPeer::Conn(cid), url).await,
        // Credential-free legacy bundle: no connection to key on — throwaway.
        None => Arc::new(Mutex::new(McpUpstreamSession::fresh(url))),
    };
    let client = &state.egress_http;
    let policy = &state.egress_policy;
    // Legacy path froze no snapshot ⇒ SUPPORTED-set negotiation (None).
    let first = call_tool(
        client,
        policy,
        url,
        auth.as_ref(),
        &entry,
        tool,
        arguments,
        None,
    )
    .await;
    state
        .governor
        .report(conn_key, &host, breaker_signal(&first));
    match first {
        Err(CallErr::Unauthorized) => {
            // A 401 proves the tool never executed. Static credential ⇒ terminal
            // definitive failure; OAuth ⇒ re-mint once and the RETRY's outcome
            // governs the whole dispatch (one claim, one logical dispatch).
            if auth.as_ref().and_then(|a| a.oauth_connection).is_none() {
                return DispatchOutcome::Definitive {
                    content: err_content("mcp server rejected the credential (HTTP 401)"),
                    is_error: true,
                    structured: None,
                };
            }
            match reauth_after_401(state, scope, server, auth).await {
                Ok(auth) => {
                    // The retry is a SECOND dial — its health is reported too.
                    let retry = call_tool(
                        client,
                        policy,
                        url,
                        auth.as_ref(),
                        &entry,
                        tool,
                        arguments,
                        None,
                    )
                    .await;
                    state
                        .governor
                        .report(conn_key, &host, breaker_signal(&retry));
                    outcome_from_call(retry)
                }
                // Re-mint failure = auth resolution failure ⇒ never sent.
                Err(e) => DispatchOutcome::NeverSent(e),
            }
        }
        Err(CallErr::InsufficientScope(challenge_scope)) => {
            if let Some(cid) = auth.as_ref().and_then(|a| a.oauth_connection) {
                let rejected = auth.as_ref().and_then(|a| a.oauth_access()).unwrap_or("");
                mark_insufficient_scope(state, scope, cid, rejected, challenge_scope).await;
            }
            DispatchOutcome::Definitive {
                content: err_content(
                    "insufficient scope — reconnect the connection with more scopes",
                ),
                is_error: true,
                structured: None,
            }
        }
        r => outcome_from_call(r),
    }
}

/// Execute one brokered tool against a run resource binding's connection (the
/// Phase C path). The caller has ALREADY run [`recheck_binding`] on this exact
/// connection immediately before — so the credential resolved here rides an
/// authority just verified live (status + generation + owner + invoker). The
/// counterpart to [`call_tool_auth`], but the credential comes from a connection
/// row + an explicit endpoint (the binding's frozen surface url). Keys the per-run
/// session registry on the binding (`McpPeer::Binding`, run = `binding.session_id`).
/// Same single reactive-401 retry: OAuth re-mints once (a 401 proves the tool
/// never executed); a static credential is terminal. An SEP-835 `insufficient_scope`
/// challenge marks the connection `error` and does NOT retry (E8).
///
/// R2.5 / invariant 9: the retry is a SECOND upstream call, so it RE-runs
/// [`recheck_binding`] before re-minting — a revoke/reauthorize/deactivate that
/// lands between the first call and the 401 fails the retry closed. It re-mints
/// against the FRESH connection row the recheck returns.
#[allow(clippy::too_many_arguments)]
pub async fn call_tool_for_conn(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    conn: &fluidbox_db::IntegrationConnectionRow,
    url: &str,
    tool: &str,
    arguments: &Value,
    binding: &fluidbox_db::RunResourceBindingRow,
    protocol_version: Option<&str>,
) -> DispatchOutcome {
    // Auth resolution BEFORE any request write ⇒ a failure is provable no-send.
    let auth = match brokered_auth_for_conn(state, scope, conn, url).await {
        Ok(a) => a,
        Err(e) => return DispatchOutcome::NeverSent(e),
    };
    // E14: the governor gate, BEFORE the per-peer session mutex (lock order
    // documented on `governor_gate`) and before any bytes leave.
    let host = match governor_gate(&state.governor, scope.tenant_id(), conn.id, url) {
        Ok(h) => h,
        Err(refused) => return refused,
    };
    let entry = session_entry(state, binding.session_id, McpPeer::Binding(binding.id), url).await;
    let client = &state.egress_http;
    let policy = &state.egress_policy;
    // Task 3 (Gap 12): the frozen `BrokeredSurface.protocol_version` the gate
    // resolved is threaded in as the negotiation snapshot. When `Some`, the
    // runtime `initialize` MUST negotiate exactly that version (drift ⇒ deny,
    // remedy /tools/refresh); when `None` (a surface frozen before the field
    // existed), negotiation falls back to SUPPORTED-set membership.
    let snapshot: Option<&str> = protocol_version;
    let first = call_tool(
        client,
        policy,
        url,
        auth.as_ref(),
        &entry,
        tool,
        arguments,
        snapshot,
    )
    .await;
    state
        .governor
        .report(conn.id, &host, breaker_signal(&first));
    match first {
        Err(CallErr::Unauthorized) => {
            // A 401 proves the tool never executed. Static credential ⇒ terminal
            // definitive failure; OAuth ⇒ recheck + re-mint once, retry governs.
            if auth.as_ref().and_then(|a| a.oauth_connection).is_none() {
                return DispatchOutcome::Definitive {
                    content: err_content("mcp server rejected the credential (HTTP 401)"),
                    is_error: true,
                    structured: None,
                };
            }
            // R2.5 / invariant 9: the retry re-runs recheck_binding first — a
            // refusal (revoke/reauthorize/deactivate) BEFORE the retry's write, or
            // a re-mint failure, is provable no-send.
            let fresh = match recheck_binding(state, scope, binding).await {
                Ok(c) => c,
                Err(e) => return DispatchOutcome::NeverSent(e),
            };
            match reauth_after_401_conn(state, scope, &fresh, url, auth).await {
                Ok(auth) => {
                    // The retry is a SECOND dial — its health is reported too.
                    let retry = call_tool(
                        client,
                        policy,
                        url,
                        auth.as_ref(),
                        &entry,
                        tool,
                        arguments,
                        snapshot,
                    )
                    .await;
                    state
                        .governor
                        .report(conn.id, &host, breaker_signal(&retry));
                    outcome_from_call(retry)
                }
                Err(e) => DispatchOutcome::NeverSent(e),
            }
        }
        Err(CallErr::InsufficientScope(challenge_scope)) => {
            let rejected = auth.as_ref().and_then(|a| a.oauth_access()).unwrap_or("");
            mark_insufficient_scope(state, scope, conn.id, rejected, challenge_scope).await;
            DispatchOutcome::Definitive {
                content: err_content(
                    "insufficient scope — reconnect the connection with more scopes",
                ),
                is_error: true,
                structured: None,
            }
        }
        r => outcome_from_call(r),
    }
}

/// Reactive-401 recovery for the binding path — OAuth connections only, re-minting
/// against the SAME connection + endpoint just rechecked. Mirrors
/// [`reauth_after_401`] but resolves via [`brokered_auth_for_conn`] (no
/// `CapabilityServer` in hand). A static credential that 401s is terminal.
/// Same compare-and-drop eviction — this is the path concurrent in-sandbox
/// brokered calls take, so it is the one that must not break singleflight.
async fn reauth_after_401_conn(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    conn: &fluidbox_db::IntegrationConnectionRow,
    url: &str,
    auth: Option<BrokeredAuth>,
) -> Result<Option<BrokeredAuth>, String> {
    let Some(cid) = auth.as_ref().and_then(|a| a.oauth_connection) else {
        return Err("mcp server rejected the credential (HTTP 401)".into());
    };
    let rejected = auth.as_ref().and_then(|a| a.oauth_access()).unwrap_or("");
    crate::oauth::invalidate_rejected_access(state, cid, rejected).await;
    brokered_auth_for_conn(state, scope, conn, url).await
}

/// Oversized results are replaced by a truncated text block so a hostile or
/// chatty server can't balloon the runner/context; the ledger stores only a
/// digest either way.
/// Cap `structuredContent` under the SAME 256 KiB ceiling as `content` (T4
/// rider). Without this an untrusted MCP server could hand back an unbounded
/// structured payload that we then persist verbatim into the execution claim's
/// `result_content` (the duplicate-adoption copy) and stream to the runner.
///
/// Unlike a `content` array — a list of typed blocks we can truncate down to one
/// text block — `structuredContent` is a single opaque JSON value paired with the
/// tool's `outputSchema`; truncating its interior would yield a value that no
/// longer satisfies that schema and could not be told apart from real data. So an
/// oversize payload is REPLACED WHOLESALE with an explicit truncation marker: the
/// paired (already capped) `content` still carries the human-readable result, and
/// the result digest covers whatever we actually stored.
fn cap_structured(structured: Option<Value>) -> Option<Value> {
    let s = structured?;
    if s.to_string().len() <= MAX_RESULT_BYTES {
        return Some(s);
    }
    Some(json!({
        "fluidbox_truncated": true,
        "reason": "structuredContent exceeded the 256 KiB result ceiling and was dropped by the fluidbox broker",
    }))
}

fn cap_content(content: Value) -> Value {
    let serialized = content.to_string();
    if serialized.len() <= MAX_RESULT_BYTES {
        return content;
    }
    let text: String = content
        .as_array()
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or(serialized);
    let truncated: String = text.chars().take(MAX_RESULT_BYTES / 4).collect();
    json!([{ "type": "text", "text": format!("{truncated}\n… (result truncated by fluidbox broker)") }])
}

/// The three outcomes of a NON-COMMITTING, credential-free probe of a remote
/// MCP endpoint. `Unauthorized` (a clean 401) is a *signal* the server wants
/// auth — the wizard branches on it; `Unreachable` is a genuine error. This
/// distinction is exactly why the probe rides the private `discover_tools`,
/// which surfaces `CallErr::Unauthorized` rather than collapsing a 401 into an
/// opaque credential-rejection message.
pub enum ProbeOutcome {
    /// Authless server — these tools are for DISPLAY only, never persisted;
    /// the authoritative photograph still happens at connect.
    Tools(Vec<ToolSnapshot>),
    /// The server answered 401 — it wants a credential (api_key or oauth).
    Unauthorized,
    /// Not reachable / not a well-behaved MCP endpoint (message for `notes`).
    Unreachable(String),
}

/// Credential-free discovery for the pre-connect probe. Persists nothing and
/// sends no secret. Reuses all of `discover_tools`' initialize-first paging/SSE
/// logic; bounded by `MCP_TIMEOUT` per request.
pub async fn probe_tools(state: &AppState, url: &str) -> ProbeOutcome {
    match discover_tools(state, url, None).await {
        Ok(tools) => ProbeOutcome::Tools(tools),
        Err(CallErr::Unauthorized) => ProbeOutcome::Unauthorized,
        Err(e) => ProbeOutcome::Unreachable(e.into_msg()),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_error_message_never_leaks_verbatim() {
        // A malicious server echoes the bearer it just received into its error
        // message. unwrap_result must surface method + code + a digest — NEVER
        // the token-shaped substring (C).
        let secret = "sk-live-abc123SECRETtoken";
        let value = json!({
            "jsonrpc": "2.0", "id": 1,
            "error": { "code": -32000, "message": format!("bad bearer {secret} rejected") }
        });
        let e2 = unwrap_result(value, "tools/call").unwrap_err();
        assert!(
            !e2.contains(secret),
            "sanitized unwrap error leaked the token: {e2}"
        );
        assert!(
            e2.contains("code -32000") && e2.contains("sha256:") && e2.contains("tools/call"),
            "sanitized unwrap error dropped method/code/digest: {e2}"
        );
    }

    #[test]
    fn version_negotiation_accepts_supported_and_rejects_others() {
        // The SUPPORTED set is accepted; an unknown version is rejected by name.
        assert!(check_negotiated("2025-11-25", None).is_ok());
        assert!(check_negotiated("2025-06-18", None).is_ok());
        let e = check_negotiated("2024-11-05", None).unwrap_err();
        assert!(
            e.contains("2024-11-05") && e.contains("unsupported"),
            "got: {e}"
        );
        // Empty negotiated is always a failure.
        assert!(check_negotiated("", None).is_err());
        // With a frozen snapshot, an EXACT match passes even if non-standard
        // (a server photographed at X must still speak X) …
        assert!(check_negotiated("2025-06-18-fakekb-1", Some("2025-06-18-fakekb-1")).is_ok());
        // … and any divergence is protocol drift (remedy names /tools/refresh).
        let e = check_negotiated("2025-11-25", Some("2025-06-18")).unwrap_err();
        assert!(
            e.contains("drift") && e.contains("tools/refresh"),
            "got: {e}"
        );
        // The bindings-e2e fakekb scenario in miniature (Gap 12): a NON-standard
        // negotiated version is ACCEPTED only because Task 3 threads the frozen
        // surface's `protocol_version` as the snapshot — with plain SUPPORTED-set
        // membership (None), the SAME version would be rejected. This is exactly
        // the flip `call_tool_for_conn` now performs by passing the surface's
        // `protocol_version` down.
        let fakekb = "2025-06-18-fakekb-1";
        assert!(
            check_negotiated(fakekb, Some(fakekb)).is_ok(),
            "the frozen surface version must accept the fakekb negotiation"
        );
        assert!(
            check_negotiated(fakekb, None).is_err(),
            "without the threaded snapshot, plain SUPPORTED membership rejects fakekb"
        );
    }

    // I1a: a hardened `egress_http` (Policy::none) must REFUSE an upstream 3xx
    // and NEVER follow the Location — a redirect is the classic SSRF pivot onto
    // an internal host. A raw-TCP fake returns 302 + Location and counts every
    // connection; the real `dial_rpc` transport funnel must error and leave the
    // fake having seen exactly ONE request.
    #[tokio::test]
    async fn dial_rpc_refuses_upstream_redirect_and_never_follows() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits_srv = hits.clone();
        let srv = tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                hits_srv.fetch_add(1, Ordering::SeqCst);
                // Best-effort drain of the request line/headers before replying.
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                // Location points BACK at this same fake so that a following
                // policy would re-hit it (hits >= 2) — making the count assertion
                // load-bearing (Policy::none keeps it at exactly 1).
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{addr}/next\r\ncontent-length: 0\r\n\r\n"
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });

        // Dev seam so the loopback fake is admissible; the client itself is
        // Policy::none, which is what refuses the redirect.
        let policy = crate::egress::EgressPolicy {
            dev_loopback: true,
            allow_cidrs: vec![],
            github_clone_base: None,
            proxy: None,
        };
        let client = crate::egress::build_egress_http(&policy);
        let url = format!("http://{addr}/mcp");
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
        let err = dial_rpc(
            &client,
            &policy,
            &url,
            None,
            SessionHeaders::default(),
            &body,
            MCP_TIMEOUT,
        )
        .await
        .expect_err("a 302 must be refused, not followed");
        // A redirect happens AFTER connect (the request was sent) ⇒ Ambiguous.
        assert!(
            matches!(err, CallErr::Ambiguous(_)),
            "a post-connect redirect refusal must classify Ambiguous"
        );
        let msg = err.into_msg();
        assert!(
            msg.contains("redirect") && msg.contains("refused"),
            "expected a redirect-refused error, got: {msg}"
        );
        // The decisive assertion: Policy::none did NOT dial the Location target.
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the client followed the redirect (saw a second request)"
        );
        srv.abort();
    }

    // ── DispatchOutcome classification (Phase E, Gap 11, plan E10) ──────────

    #[test]
    fn outcome_from_call_maps_every_arm() {
        // A real MCP success result.
        assert!(matches!(
            outcome_from_call(Ok((json!([]), false, None))),
            DispatchOutcome::Definitive {
                is_error: false,
                ..
            }
        ));
        // A real MCP isError result → failed_upstream (Definitive, is_error).
        assert!(matches!(
            outcome_from_call(Ok((json!([{"type":"text","text":"boom"}]), true, None))),
            DispatchOutcome::Definitive { is_error: true, .. }
        ));
        // A definitive upstream protocol error (HTTP status / JSON-RPC error) is
        // rendered as an error RESULT ⇒ failed_upstream, NEVER ambiguous.
        assert!(matches!(
            outcome_from_call(Err(CallErr::Other(
                "mcp tools/call returned HTTP 500".into()
            ))),
            DispatchOutcome::Definitive { is_error: true, .. }
        ));
        // Provable no-send is re-claimable.
        assert!(matches!(
            outcome_from_call(Err(CallErr::NeverSent("connect refused".into()))),
            DispatchOutcome::NeverSent(_)
        ));
        // Sent, unknown outcome — never auto-retried.
        assert!(matches!(
            outcome_from_call(Err(CallErr::Ambiguous("timeout".into()))),
            DispatchOutcome::Ambiguous(_)
        ));
        // A terminal session-expiry renders as an error result (failed_upstream).
        assert!(matches!(
            outcome_from_call(Err(CallErr::SessionExpired)),
            DispatchOutcome::Definitive { is_error: true, .. }
        ));
    }

    #[tokio::test]
    async fn dial_rpc_connect_refused_is_never_sent() {
        // Reserve a port, capture the addr, then DROP the listener so the dial
        // gets connection-refused (reqwest `is_connect()` ⇒ NeverSent — provable
        // no-send, re-claimable).
        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let url = format!("http://{addr}/mcp");
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
        let err = dial_rpc(
            &client,
            &policy,
            &url,
            None,
            SessionHeaders::default(),
            &body,
            MCP_TIMEOUT,
        )
        .await
        .expect_err("a refused connection must error");
        assert!(
            matches!(err, CallErr::NeverSent(_)),
            "connect-refused must classify NeverSent, got {err:?}"
        );
    }

    #[tokio::test]
    async fn dial_rpc_timeout_is_ambiguous() {
        // A fake that accepts the connection and NEVER responds; a short per-dial
        // timeout forces the `is_timeout()` ⇒ Ambiguous classification (the send
        // may have landed, so the outcome is unknown — never auto-retried).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                match listener.accept().await {
                    Ok((sock, _)) => held.push(sock), // keep open, never reply
                    Err(_) => return,
                }
            }
        });
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let url = format!("http://{addr}/mcp");
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
        let err = dial_rpc(
            &client,
            &policy,
            &url,
            None,
            SessionHeaders::default(),
            &body,
            Duration::from_millis(300),
        )
        .await
        .expect_err("a non-responding server must time out");
        assert!(
            matches!(err, CallErr::Ambiguous(_)),
            "a timeout must classify Ambiguous, got {err:?}"
        );
        srv.abort();
    }

    #[tokio::test]
    async fn call_tool_http_500_is_definitive_failed_upstream() {
        // A fake that initializes fine but returns HTTP 500 on tools/call → the
        // dispatch is a DEFINITIVE upstream error (is_error=true → failed_upstream),
        // NEVER ambiguous (the acceptance bullet: a definitive 500 is not unknown).
        let handler: Handler = Arc::new(|_i, rec: &Recorded| match rec.rpc_method.as_str() {
            "initialize" => FakeReply::json(200, init_result(rec, "2025-11-25")),
            "notifications/initialized" => FakeReply::empty(202),
            "tools/call" => FakeReply::json(500, json!({ "error": "boom" }).to_string()),
            _ => FakeReply::empty(202),
        });
        let (url, _records, jh) = spawn_fake(handler).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let entry = Arc::new(Mutex::new(McpUpstreamSession::fresh(&url)));
        let outcome = outcome_from_call(
            call_tool(&client, &policy, &url, None, &entry, "x", &json!({}), None).await,
        );
        jh.abort();
        assert!(
            matches!(outcome, DispatchOutcome::Definitive { is_error: true, .. }),
            "HTTP 500 must be Definitive/failed_upstream, got {outcome:?}"
        );
    }

    // ── Egress governor wiring (Phase E, E14) ───────────────────────────────

    #[test]
    fn breaker_signal_classification_boundary() {
        use crate::governor::Outcome;
        // HEALTHY upstream — every one of these is a definitive answer from a
        // server that is demonstrably alive, so NONE may trip the breaker.
        assert_eq!(breaker_signal(&Ok((json!([]), false, None))), Outcome::Ok);
        assert_eq!(
            breaker_signal(&Ok((
                json!([{"type":"text","text":"tool blew up"}]),
                true,
                None
            ))),
            Outcome::Ok,
            "an isError tool result must NEVER trip the breaker"
        );
        assert_eq!(
            breaker_signal(&Err(CallErr::Other(
                "mcp tools/call failed (code -32000, msg sha256:…)".into()
            ))),
            Outcome::Ok,
            "a JSON-RPC error object must NEVER trip the breaker"
        );
        assert_eq!(
            breaker_signal(&Err(status_err(
                "tools/call",
                reqwest::StatusCode::BAD_REQUEST
            ))),
            Outcome::Ok,
            "a 4xx is a definitive answer, not an upstream-health failure"
        );
        assert_eq!(breaker_signal(&Err(CallErr::Unauthorized)), Outcome::Ok);
        assert_eq!(
            breaker_signal(&Err(CallErr::InsufficientScope(None))),
            Outcome::Ok
        );
        assert_eq!(breaker_signal(&Err(CallErr::SessionExpired)), Outcome::Ok);
        // UNHEALTHY upstream — 5xx, provable no-send, and unknown-outcome dials.
        for status in [
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            reqwest::StatusCode::BAD_GATEWAY,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert_eq!(
                breaker_signal(&Err(status_err("tools/call", status))),
                Outcome::TransportFailure,
                "{status} must count as an upstream-health failure"
            );
        }
        assert_eq!(
            breaker_signal(&Err(CallErr::NeverSent("mcp server unreachable".into()))),
            Outcome::TransportFailure
        );
        assert_eq!(
            breaker_signal(&Err(CallErr::Ambiguous("mcp request timed out".into()))),
            Outcome::TransportFailure
        );
    }

    #[test]
    fn a_5xx_still_classifies_definitive_failed_upstream() {
        // Splitting 5xx out for the BREAKER must not change the claim outcome:
        // a definitive 500 is still `failed_upstream`, never `ambiguous`
        // (Task 4's acceptance bullet).
        assert!(matches!(
            outcome_from_call(Err(status_err(
                "tools/call",
                reqwest::StatusCode::INTERNAL_SERVER_ERROR
            ))),
            DispatchOutcome::Definitive { is_error: true, .. }
        ));
        // … and the message still names the status for an operator.
        let m = status_err("tools/call", reqwest::StatusCode::BAD_GATEWAY).into_msg();
        assert!(m.contains("502") && m.contains("tools/call"), "got: {m}");
    }

    #[test]
    fn host_key_is_lowercased_and_port_insensitive() {
        assert_eq!(host_key("https://MCP.Example.Test/mcp"), "mcp.example.test");
        assert_eq!(
            host_key("https://mcp.example.test:8443/mcp"),
            host_key("https://mcp.example.test/mcp"),
            "a port must not open a fresh host bucket"
        );
        // Unparsable → the shared empty bucket (admit_url refuses the dial).
        assert_eq!(host_key("not a url"), "");
    }

    #[test]
    fn a_governor_refusal_is_never_sent_and_leaks_no_host() {
        // The gate's refusal must be re-claimable (NeverSent), name the scope +
        // retry hint, and carry only a DIGEST of the upstream host.
        let gov = crate::governor::EgressGovernor::manual(crate::governor::GovernorLimits {
            tenant_per_min: 0,
            connection_per_min: 1,
            host_per_min: 0,
            breaker_threshold: 0,
            breaker_open_secs: 0,
        });
        let (t, c) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let url = "https://secret-internal.corp.example/mcp";
        assert!(
            governor_gate(&gov, t, c, url).is_ok(),
            "first dial admitted"
        );
        let refused = governor_gate(&gov, t, c, url).expect_err("second is throttled");
        let DispatchOutcome::NeverSent(msg) = refused else {
            panic!("a governor refusal MUST be NeverSent (re-claimable): {refused:?}");
        };
        assert!(
            msg.contains("connection") && msg.contains("retry after"),
            "{msg}"
        );
        assert!(
            !msg.contains("secret-internal.corp.example"),
            "the refusal leaked the raw upstream host: {msg}"
        );
        assert!(
            msg.contains("sha256:"),
            "the refusal dropped the digest: {msg}"
        );
    }

    #[tokio::test]
    async fn breaker_opens_on_repeated_5xx_and_then_stops_dialing_the_upstream() {
        // The production sequence, verbatim: governor_gate → call_tool →
        // report(breaker_signal(...)) — the same three calls `call_tool_auth`
        // and `call_tool_for_conn` make. A fake that 500s EVERYTHING must open
        // the breaker after `threshold` dials, and the next call must be refused
        // as NeverSent WITHOUT the fake seeing another request.
        const THRESHOLD: u32 = 3;
        let handler: Handler = Arc::new(|_i, _rec: &Recorded| {
            FakeReply::json(500, json!({ "error": "down" }).to_string())
        });
        let (url, records, jh) = spawn_fake(handler).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let gov = crate::governor::EgressGovernor::manual(crate::governor::GovernorLimits {
            tenant_per_min: 0,
            connection_per_min: 0,
            host_per_min: 0,
            breaker_threshold: THRESHOLD,
            breaker_open_secs: 60,
        });
        let (t, c) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());

        for i in 0..THRESHOLD {
            let host = governor_gate(&gov, t, c, &url)
                .unwrap_or_else(|e| panic!("dial {i} must be admitted, got {e:?}"));
            let entry = Arc::new(Mutex::new(McpUpstreamSession::fresh(&url)));
            let r = call_tool(&client, &policy, &url, None, &entry, "x", &json!({}), None).await;
            assert!(
                matches!(r, Err(CallErr::UpstreamUnavailable(_))),
                "dial {i} must classify as an upstream-health failure, got {r:?}"
            );
            gov.report(c, &host, breaker_signal(&r));
        }
        // Precondition: the fake WAS recording (a dead fake must not false-green
        // the "stopped dialing" assertion below).
        let before = records.lock().unwrap().len();
        assert!(
            before >= THRESHOLD as usize,
            "the fake recorded {before} requests — it never saw the dials"
        );

        // The (N+1)th never reaches the wire.
        let refused = governor_gate(&gov, t, c, &url).expect_err("the breaker must be open");
        assert!(
            matches!(refused, DispatchOutcome::NeverSent(_)),
            "a breaker refusal is a pre-write proof of non-dispatch: {refused:?}"
        );
        assert_eq!(
            records.lock().unwrap().len(),
            before,
            "the breaker refusal still contacted the upstream"
        );
        jh.abort();
    }

    #[tokio::test]
    async fn an_iserror_result_never_opens_the_breaker() {
        // A fake that initializes fine and answers EVERY tools/call with a
        // well-formed `isError: true` result. The upstream is healthy, so no
        // number of these may open the breaker (plan E14's binding rule).
        let handler: Handler = Arc::new(|_i, rec: &Recorded| match rec.rpc_method.as_str() {
            "initialize" => FakeReply::json(200, init_result(rec, "2025-11-25")),
            "notifications/initialized" => FakeReply::empty(202),
            "tools/call" => FakeReply::json(
                200,
                rpc_result(
                    rec,
                    json!({
                        "content": [{ "type": "text", "text": "the tool refused" }],
                        "isError": true,
                    }),
                ),
            ),
            _ => FakeReply::empty(202),
        });
        let (url, records, jh) = spawn_fake(handler).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let gov = crate::governor::EgressGovernor::manual(crate::governor::GovernorLimits {
            tenant_per_min: 0,
            connection_per_min: 0,
            host_per_min: 0,
            breaker_threshold: 2,
            breaker_open_secs: 60,
        });
        let (t, c) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let entry = Arc::new(Mutex::new(McpUpstreamSession::fresh(&url)));
        for i in 0..6 {
            let host = governor_gate(&gov, t, c, &url).unwrap_or_else(|e| {
                panic!("an isError result must never open the breaker (dial {i}): {e:?}")
            });
            let r = call_tool(&client, &policy, &url, None, &entry, "x", &json!({}), None).await;
            assert!(
                matches!(&r, Ok((_, true, _))),
                "dial {i} must be a real isError RESULT, got {r:?}"
            );
            gov.report(c, &host, breaker_signal(&r));
        }
        assert!(
            count_rpc(&records, "tools/call") >= 6,
            "the fake never saw the calls — the assertion above is vacuous"
        );
        jh.abort();
    }

    #[test]
    fn audience_binding_is_scheme_host_port_and_path_prefix() {
        let ok = |u: &str, b: &str| assert!(url_within_base(u, b), "{u} within {b}");
        let no = |u: &str, b: &str| assert!(!url_within_base(u, b), "{u} NOT within {b}");
        ok("https://mcp.example.test/mcp", "https://mcp.example.test");
        ok("https://mcp.example.test/mcp", "https://mcp.example.test/");
        ok(
            "https://MCP.example.test/mcp/sub",
            "https://mcp.example.test/mcp",
        );
        ok(
            "https://mcp.example.test:443/mcp",
            "https://mcp.example.test",
        );
        ok("http://127.0.0.1:8899/mcp", "http://127.0.0.1:8899");
        no("https://evil.test/mcp", "https://mcp.example.test");
        no("http://mcp.example.test/mcp", "https://mcp.example.test"); // scheme downgrade
        no(
            "https://mcp.example.test:8443/mcp",
            "https://mcp.example.test",
        );
        no(
            "https://mcp.example.test/mcpx",
            "https://mcp.example.test/mcp",
        ); // path boundary
        no(
            "https://mcp.example.test.evil.test/mcp",
            "https://mcp.example.test",
        );
        no("not a url", "https://mcp.example.test");
    }

    #[test]
    fn header_values_compose_per_scheme() {
        assert_eq!(compose_header_value("Bearer", "tok"), "Bearer tok");
        // Basic base64-encodes the stored email:token composite.
        assert_eq!(
            compose_header_value("Basic", "a@b.c:tok"),
            format!("Basic {}", {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode("a@b.c:tok")
            })
        );
        // Empty scheme = the bare token (Sentry's custom-header shape).
        assert_eq!(compose_header_value("", "raw-token"), "raw-token");
    }

    #[test]
    fn header_names_validate_and_denylist_protocol_fields() {
        assert!(valid_header_name("authorization"));
        assert!(valid_header_name("Sentry-Bearer"));
        assert!(valid_header_name("x-api-key"));
        assert!(!valid_header_name(""));
        assert!(!valid_header_name("bad header"));
        assert!(!valid_header_name("bad:header"));
        assert!(!valid_header_name("Content-Type"));
        assert!(!valid_header_name("mcp-session-id"));
        assert!(!valid_header_name("Host"));
        assert!(!valid_header_name(&"x".repeat(65)));
    }

    #[test]
    fn oversized_content_is_capped_to_a_text_block() {
        let small = serde_json::json!([{ "type": "text", "text": "ok" }]);
        assert_eq!(cap_content(small.clone()), small);
        let big = serde_json::json!([{ "type": "text", "text": "x".repeat(MAX_RESULT_BYTES + 1) }]);
        let capped = cap_content(big);
        let s = capped.to_string();
        assert!(s.len() < MAX_RESULT_BYTES);
        assert!(s.contains("truncated by fluidbox broker"));
    }

    #[test]
    fn oversized_structured_content_is_capped_to_a_marker() {
        // Absent stays absent; a small payload passes through byte-identical.
        assert_eq!(cap_structured(None), None);
        let small = serde_json::json!({ "answer": 42 });
        assert_eq!(cap_structured(Some(small.clone())), Some(small));
        // Oversize is REPLACED wholesale (never truncated in place — that would
        // silently violate the tool's outputSchema).
        let big = serde_json::json!({ "blob": "x".repeat(MAX_RESULT_BYTES + 1) });
        let capped = cap_structured(Some(big)).unwrap();
        let s = capped.to_string();
        assert!(
            s.len() < MAX_RESULT_BYTES,
            "capped structured content must fit the ceiling"
        );
        assert_eq!(capped["fluidbox_truncated"], serde_json::json!(true));
        assert!(!s.contains("xxxxxxxx"), "no oversize payload survives");
    }

    // ── Session-manager conformance (raw-TCP fake MCP server, no DB) ──────────
    //
    // A loopback fake records every request (HTTP method, jsonrpc method, headers,
    // body) and replies per a handler closure. Every count assertion carries a
    // `>0` precondition so a dead fake cannot false-green (Phase D discipline).

    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone)]
    struct Recorded {
        http_method: String,
        rpc_method: String,
        headers: HashMap<String, String>,
        body: Value,
    }
    impl Recorded {
        fn id(&self) -> Value {
            self.body.get("id").cloned().unwrap_or(Value::Null)
        }
    }

    struct FakeReply {
        status: u16,
        content_type: &'static str,
        session_id: Option<String>,
        www_auth: Option<String>,
        body: String,
    }
    impl FakeReply {
        fn json(status: u16, body: String) -> Self {
            FakeReply {
                status,
                content_type: "application/json",
                session_id: None,
                www_auth: None,
                body,
            }
        }
        fn empty(status: u16) -> Self {
            FakeReply {
                status,
                content_type: "",
                session_id: None,
                www_auth: None,
                body: String::new(),
            }
        }
        fn with_session(mut self, sid: &str) -> Self {
            self.session_id = Some(sid.to_string());
            self
        }
    }

    /// A JSON-RPC result envelope echoing the request id.
    fn rpc_result(rec: &Recorded, result: Value) -> String {
        json!({ "jsonrpc": "2.0", "id": rec.id(), "result": result }).to_string()
    }
    /// The standard initialize result at a given negotiated version.
    fn init_result(rec: &Recorded, version: &str) -> String {
        rpc_result(
            rec,
            json!({
                "protocolVersion": version,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "fake", "version": "1" },
            }),
        )
    }

    type Handler = Arc<dyn Fn(usize, &Recorded) -> FakeReply + Send + Sync>;

    /// Spawn a loopback fake; returns (url, records, abort-handle).
    async fn spawn_fake(
        handler: Handler,
    ) -> (
        String,
        Arc<StdMutex<Vec<Recorded>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let records = Arc::new(StdMutex::new(Vec::<Recorded>::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let recs = records.clone();
        let jh = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let Some(rec) = read_request(&mut sock).await else {
                    continue;
                };
                let idx = {
                    let mut r = recs.lock().unwrap();
                    r.push(rec.clone());
                    r.len() - 1
                };
                let reply = handler(idx, &rec);
                let _ = sock.write_all(&render_reply(&reply)).await;
                let _ = sock.flush().await;
            }
        });
        (format!("http://{addr}/mcp"), records, jh)
    }

    async fn read_request(sock: &mut tokio::net::TcpStream) -> Option<Recorded> {
        let mut buf = Vec::new();
        let head_end = loop {
            let mut tmp = [0u8; 2048];
            let n = sock.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut rl = request_line.split_whitespace();
        let http_method = rl.next().unwrap_or("").to_string();
        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        let clen: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body_bytes = buf[head_end..].to_vec();
        while body_bytes.len() < clen {
            let mut tmp = [0u8; 2048];
            let n = sock.read(&mut tmp).await.ok()?;
            if n == 0 {
                break;
            }
            body_bytes.extend_from_slice(&tmp[..n]);
        }
        body_bytes.truncate(clen);
        let body = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);
        let rpc_method = body
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        Some(Recorded {
            http_method,
            rpc_method,
            headers,
            body,
        })
    }

    fn render_reply(r: &FakeReply) -> Vec<u8> {
        let reason = match r.status {
            200 => "OK",
            202 => "Accepted",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "OK",
        };
        let mut s = format!("HTTP/1.1 {} {reason}\r\n", r.status);
        s.push_str("connection: close\r\n");
        s.push_str(&format!("content-length: {}\r\n", r.body.len()));
        if !r.content_type.is_empty() {
            s.push_str(&format!("content-type: {}\r\n", r.content_type));
        }
        if let Some(sid) = &r.session_id {
            s.push_str(&format!("mcp-session-id: {sid}\r\n"));
        }
        if let Some(w) = &r.www_auth {
            s.push_str(&format!("www-authenticate: {w}\r\n"));
        }
        s.push_str("\r\n");
        let mut out = s.into_bytes();
        out.extend_from_slice(r.body.as_bytes());
        out
    }

    fn dev_policy() -> crate::egress::EgressPolicy {
        crate::egress::EgressPolicy {
            dev_loopback: true,
            allow_cidrs: vec![],
            github_clone_base: None,
            proxy: None,
        }
    }

    fn count_rpc(records: &Arc<StdMutex<Vec<Recorded>>>, method: &str) -> usize {
        records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.rpc_method == method)
            .count()
    }
    fn count_http(records: &Arc<StdMutex<Vec<Recorded>>>, method: &str) -> usize {
        records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.http_method == method)
            .count()
    }

    /// A default sessionless handler: initialize (echo `version`), notifications,
    /// and a trivial tools/call echo. `version` = the negotiated protocol.
    fn basic_handler(version: &'static str) -> Handler {
        Arc::new(move |_idx, rec: &Recorded| match rec.rpc_method.as_str() {
            "initialize" => FakeReply::json(200, init_result(rec, version)),
            "notifications/initialized" => FakeReply::empty(202),
            "tools/call" => FakeReply::json(
                200,
                rpc_result(
                    rec,
                    json!({ "content": [{"type":"text","text":"ok"}], "isError": false }),
                ),
            ),
            _ => FakeReply::empty(202),
        })
    }

    #[tokio::test]
    async fn initialize_is_first_offers_2025_11_25_and_notifies_unconditionally() {
        let (url, records, jh) = spawn_fake(basic_handler("2025-11-25")).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let entry = Arc::new(Mutex::new(McpUpstreamSession::fresh(&url)));
        let out = managed_call(
            &client,
            &policy,
            &url,
            None,
            &entry,
            "tools/call",
            json!({ "name": "x", "arguments": {} }),
            None,
        )
        .await;
        jh.abort();
        assert!(
            out.is_ok(),
            "call failed: {:?}",
            out.err().map(|e| e.into_msg())
        );
        let recs = records.lock().unwrap();
        assert!(!recs.is_empty(), "the fake saw NO requests (dead fake)");
        // The FIRST request is initialize (stateless-first is gone) …
        assert_eq!(
            recs[0].rpc_method, "initialize",
            "first request must be initialize"
        );
        // … and it OFFERS 2025-11-25.
        assert_eq!(
            recs[0].body["params"]["protocolVersion"], "2025-11-25",
            "offer must be 2025-11-25"
        );
        // notifications/initialized is sent UNCONDITIONALLY (server issued no
        // session id) and carries none.
        let note = recs
            .iter()
            .find(|r| r.rpc_method == "notifications/initialized");
        let note = note.expect("notifications/initialized must be sent");
        assert!(
            !note.headers.contains_key("mcp-session-id"),
            "no session id was issued, so none must be sent"
        );
    }

    #[tokio::test]
    async fn version_negotiation_rejects_unsupported_over_the_wire() {
        // A server negotiating 2024-11-05 (unsupported, no frozen snapshot) fails
        // the call by name; 2025-06-18 succeeds.
        let (bad_url, bad_recs, jh1) = spawn_fake(basic_handler("2024-11-05")).await;
        let (ok_url, ok_recs, jh2) = spawn_fake(basic_handler("2025-06-18")).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let call = |url: String| {
            let client = client.clone();
            let policy = policy.clone();
            async move {
                let entry = Arc::new(Mutex::new(McpUpstreamSession::fresh(&url)));
                managed_call(
                    &client,
                    &policy,
                    &url,
                    None,
                    &entry,
                    "tools/call",
                    json!({ "name": "x", "arguments": {} }),
                    None,
                )
                .await
                .map_err(|e| e.into_msg())
            }
        };
        let bad = call(bad_url).await;
        let good = call(ok_url).await;
        jh1.abort();
        jh2.abort();
        assert!(count_rpc(&bad_recs, "initialize") > 0, "dead bad fake");
        assert!(count_rpc(&ok_recs, "initialize") > 0, "dead ok fake");
        let e = bad.expect_err("2024-11-05 must be rejected");
        assert!(
            e.contains("2024-11-05") && e.contains("unsupported"),
            "got: {e}"
        );
        assert!(good.is_ok(), "2025-06-18 must be accepted: {good:?}");
    }

    #[tokio::test]
    async fn request_ids_are_distinct_and_protocol_header_present() {
        let (url, records, jh) = spawn_fake(basic_handler("2025-11-25")).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let entry = Arc::new(Mutex::new(McpUpstreamSession::fresh(&url)));
        for _ in 0..2 {
            managed_call(
                &client,
                &policy,
                &url,
                None,
                &entry,
                "tools/call",
                json!({ "name": "x", "arguments": {} }),
                None,
            )
            .await
            .unwrap();
        }
        jh.abort();
        let recs = records.lock().unwrap();
        let call_ids: Vec<i64> = recs
            .iter()
            .filter(|r| r.rpc_method == "tools/call")
            .map(|r| r.id().as_i64().unwrap_or(-1))
            .collect();
        assert_eq!(call_ids.len(), 2, "the fake must have seen 2 tools/call");
        assert_ne!(call_ids[0], call_ids[1], "ids must be distinct");
        assert!(call_ids[1] > call_ids[0], "ids must increment");
        // Every post-initialize request carries MCP-Protocol-Version = negotiated.
        for r in recs.iter().filter(|r| r.rpc_method == "tools/call") {
            assert_eq!(
                r.headers.get("mcp-protocol-version").map(String::as_str),
                Some("2025-11-25"),
                "MCP-Protocol-Version header must be present post-init"
            );
        }
    }

    #[tokio::test]
    async fn reinit_once_on_404_with_session_then_replays() {
        // Issue a session id at initialize; 404 the FIRST tools/call; succeed after.
        let call_seen = Arc::new(AtomicUsize::new(0));
        let cs = call_seen.clone();
        let handler: Handler =
            Arc::new(move |_idx, rec: &Recorded| match rec.rpc_method.as_str() {
                "initialize" => {
                    FakeReply::json(200, init_result(rec, "2025-11-25")).with_session("sess-1")
                }
                "notifications/initialized" => FakeReply::empty(202),
                "tools/call" => {
                    if cs.fetch_add(1, Ordering::SeqCst) == 0 {
                        FakeReply::empty(404) // first call: session gone upstream
                    } else {
                        FakeReply::json(
                            200,
                            rpc_result(rec, json!({ "content": [], "isError": false })),
                        )
                    }
                }
                _ => FakeReply::empty(202),
            });
        let (url, records, jh) = spawn_fake(handler).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let entry = Arc::new(Mutex::new(McpUpstreamSession::fresh(&url)));
        let out = managed_call(
            &client,
            &policy,
            &url,
            None,
            &entry,
            "tools/call",
            json!({ "name": "x", "arguments": {} }),
            None,
        )
        .await;
        jh.abort();
        assert!(
            out.is_ok(),
            "reinit+replay must succeed: {:?}",
            out.err().map(|e| e.into_msg())
        );
        assert_eq!(
            count_rpc(&records, "initialize"),
            2,
            "exactly ONE reinit (2 initializes total)"
        );
        assert_eq!(
            count_rpc(&records, "tools/call"),
            2,
            "one 404'd call + one replay"
        );
    }

    #[tokio::test]
    async fn double_404_errors() {
        // Always 404 tools/call (even after reinit): the SECOND 404 is terminal.
        let handler: Handler = Arc::new(|_idx, rec: &Recorded| match rec.rpc_method.as_str() {
            "initialize" => {
                FakeReply::json(200, init_result(rec, "2025-11-25")).with_session("sess-1")
            }
            "tools/call" => FakeReply::empty(404),
            _ => FakeReply::empty(202),
        });
        let (url, records, jh) = spawn_fake(handler).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let entry = Arc::new(Mutex::new(McpUpstreamSession::fresh(&url)));
        let out = managed_call(
            &client,
            &policy,
            &url,
            None,
            &entry,
            "tools/call",
            json!({ "name": "x", "arguments": {} }),
            None,
        )
        .await;
        jh.abort();
        assert!(
            count_rpc(&records, "tools/call") >= 2,
            "must have tried twice"
        );
        let e = out.expect_err("a double-404 must error").into_msg();
        assert!(e.contains("session expired"), "got: {e}");
    }

    #[tokio::test]
    async fn server_request_gets_method_not_found_and_notification_ignored() {
        // The tools/call reply is an SSE stream with a server→client REQUEST, a
        // NOTIFICATION, and our RESPONSE. We must reply -32601 to the request,
        // ignore the notification, and still return the result.
        let handler: Handler = Arc::new(|_idx, rec: &Recorded| match rec.rpc_method.as_str() {
            "initialize" => FakeReply::json(200, init_result(rec, "2025-11-25")).with_session("s1"),
            "notifications/initialized" => FakeReply::empty(202),
            "tools/call" => {
                let sse = format!(
                    "event: message\ndata: {}\n\n\
                     data: {}\n\n\
                     data: {}\n\n",
                    json!({"jsonrpc":"2.0","id":"srv-1","method":"sampling/createMessage","params":{}}),
                    json!({"jsonrpc":"2.0","method":"notifications/progress","params":{}}),
                    json!({"jsonrpc":"2.0","id": rec.id(), "result": {"content":[{"type":"text","text":"done"}],"isError":false}}),
                );
                FakeReply {
                    status: 200,
                    content_type: "text/event-stream",
                    session_id: None,
                    www_auth: None,
                    body: sse,
                }
            }
            _ => FakeReply::empty(202),
        });
        let (url, records, jh) = spawn_fake(handler).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let entry = Arc::new(Mutex::new(McpUpstreamSession::fresh(&url)));
        let out = managed_call(
            &client,
            &policy,
            &url,
            None,
            &entry,
            "tools/call",
            json!({ "name": "x", "arguments": {} }),
            None,
        )
        .await;
        jh.abort();
        // The result still comes back despite the interleaved server traffic.
        let v = out.expect("call returns the result");
        assert_eq!(v["content"][0]["text"], "done");
        // A -32601 reply was POSTed back (an extra request carrying that error).
        let recs = records.lock().unwrap();
        assert!(
            recs.len() >= 3,
            "expected the -32601 reply POST (dead fake?)"
        );
        let saw_mnf = recs.iter().any(|r| {
            r.body
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(Value::as_i64)
                == Some(-32601)
        });
        assert!(
            saw_mnf,
            "the broker must reply -32601 to the server request"
        );
    }

    #[tokio::test]
    async fn structured_content_passes_through_and_is_capped() {
        let handler: Handler = Arc::new(|_idx, rec: &Recorded| match rec.rpc_method.as_str() {
            "initialize" => FakeReply::json(200, init_result(rec, "2025-11-25")),
            "tools/call" => FakeReply::json(
                200,
                rpc_result(
                    rec,
                    json!({
                        "content": [{"type":"text","text":"ok"}],
                        "isError": false,
                        "structuredContent": {"answer": 42},
                    }),
                ),
            ),
            _ => FakeReply::empty(202),
        });
        let (url, records, jh) = spawn_fake(handler).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let entry = Arc::new(Mutex::new(McpUpstreamSession::fresh(&url)));
        let (content, is_error, structured) =
            call_tool(&client, &policy, &url, None, &entry, "x", &json!({}), None)
                .await
                .expect("call ok");
        jh.abort();
        assert!(count_rpc(&records, "tools/call") > 0, "dead fake");
        assert!(!is_error);
        assert_eq!(content[0]["text"], "ok");
        assert_eq!(
            structured,
            Some(json!({"answer": 42})),
            "structuredContent must pass through"
        );
    }

    #[tokio::test]
    async fn insufficient_scope_is_terminal_and_names_reconnect() {
        // A 401 with an SEP-835 challenge: no re-mint retry at the managed layer;
        // the error names reconnect. (The connection status write is exercised by
        // the CI hardening suite — it is DB-gated behind mark_insufficient_scope.)
        let handler: Handler = Arc::new(|_idx, rec: &Recorded| match rec.rpc_method.as_str() {
            "initialize" => FakeReply::json(200, init_result(rec, "2025-11-25")),
            "notifications/initialized" => FakeReply::empty(202),
            "tools/call" => FakeReply {
                status: 401,
                content_type: "",
                session_id: None,
                www_auth: Some("Bearer error=\"insufficient_scope\", scope=\"read:issues\"".into()),
                body: String::new(),
            },
            _ => FakeReply::empty(202),
        });
        let (url, records, jh) = spawn_fake(handler).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let entry = Arc::new(Mutex::new(McpUpstreamSession::fresh(&url)));
        let out = managed_call(
            &client,
            &policy,
            &url,
            None,
            &entry,
            "tools/call",
            json!({ "name": "x", "arguments": {} }),
            None,
        )
        .await;
        jh.abort();
        // Exactly ONE tools/call — no retry (a re-mint cannot add a scope).
        assert_eq!(
            count_rpc(&records, "tools/call"),
            1,
            "must NOT retry an insufficient_scope 401"
        );
        match out {
            Err(CallErr::InsufficientScope(scope)) => {
                assert_eq!(scope.as_deref(), Some("read:issues"));
            }
            other => panic!(
                "expected InsufficientScope, got {:?}",
                other.map(|_| ()).map_err(|e| e.into_msg())
            ),
        }
        assert!(CallErr::InsufficientScope(None)
            .into_msg()
            .contains("reconnect"));
    }

    /// Drain + DELETE with a FIXED credential-resolution outcome, standing in for
    /// the production resolver (which needs an `AppState` + DB). `Ok(None)` = a
    /// credentialless remote, `Ok(Some((header, value)))` = a resolved credential,
    /// `Err` = resolution/recheck refused (revoked connection, moved generation,
    /// deactivated owner).
    async fn cleanup_with_auth(
        registry: &crate::state::McpSessionRegistry,
        client: &reqwest::Client,
        policy: &crate::egress::EgressPolicy,
        session_id: uuid::Uuid,
        resolved: Result<Option<(&'static str, &'static str)>, &'static str>,
    ) {
        let drained = drain_run_sessions(registry, session_id).await;
        delete_upstream_sessions(client, policy, drained, move |_peer, _url| async move {
            match resolved {
                Ok(Some((header, value))) => Ok(Some(BrokeredAuth {
                    header: header.into(),
                    value: value.into(),
                    oauth_connection: None,
                })),
                Ok(None) => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        })
        .await;
    }

    /// One registry entry for `run` with a live server-issued session id at `url`.
    fn live_registry(
        run: uuid::Uuid,
        peer: McpPeer,
        url: &str,
    ) -> HashMap<(uuid::Uuid, McpPeer), Arc<Mutex<McpUpstreamSession>>> {
        let mut map = HashMap::new();
        map.insert(
            (run, peer),
            Arc::new(Mutex::new(McpUpstreamSession {
                session_id: Some("live-session".into()),
                negotiated: "2025-11-25".into(),
                next_id: 3,
                url: url.to_string(),
            })),
        );
        map
    }

    #[tokio::test]
    async fn terminal_cleanup_deletes_the_session_and_evicts() {
        let handler: Handler = Arc::new(|_idx, _rec: &Recorded| FakeReply::empty(200));
        let (url, records, jh) = spawn_fake(handler).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let run = uuid::Uuid::now_v7();
        let peer = McpPeer::Conn(uuid::Uuid::now_v7());
        // A registry with one live session (has a server-issued session id).
        let registry: crate::state::McpSessionRegistry = Mutex::new(live_registry(run, peer, &url));
        cleanup_with_auth(&registry, &client, &policy, run, Ok(None)).await;
        jh.abort();
        // The fake saw a DELETE carrying the session id …
        assert!(
            count_http(&records, "DELETE") > 0,
            "no DELETE fired (dead fake?)"
        );
        {
            let recs = records.lock().unwrap();
            let del = recs.iter().find(|r| r.http_method == "DELETE").unwrap();
            assert_eq!(
                del.headers.get("mcp-session-id").map(String::as_str),
                Some("live-session")
            );
        }
        // … and the entry is evicted regardless.
        assert!(
            registry.lock().await.is_empty(),
            "the registry entry must be evicted"
        );
    }

    #[tokio::test]
    async fn terminal_cleanup_evicts_even_when_delete_fails() {
        // Point the session at a dead port: the DELETE errors, but eviction still
        // happens (best-effort teardown never strands an entry).
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let run = uuid::Uuid::now_v7();
        let registry: crate::state::McpSessionRegistry = Mutex::new(HashMap::new());
        registry.lock().await.insert(
            (run, McpPeer::Binding(uuid::Uuid::now_v7())),
            Arc::new(Mutex::new(McpUpstreamSession {
                session_id: Some("live".into()),
                negotiated: "2025-11-25".into(),
                next_id: 1,
                // 127.0.0.1:9 is the discard port — connect refuses immediately.
                url: "http://127.0.0.1:9/mcp".into(),
            })),
        );
        cleanup_with_auth(&registry, &client, &policy, run, Ok(None)).await;
        assert!(
            registry.lock().await.is_empty(),
            "eviction must happen even on DELETE failure"
        );
    }

    #[tokio::test]
    async fn terminal_cleanup_delete_carries_the_authorization_header() {
        // Design :914 — "always send the OAuth/static authorization header on
        // every upstream HTTP request; an MCP session ID is routing state, not
        // authentication". A conforming upstream 401s an unauthorized DELETE, so
        // the session would never actually terminate.
        let handler: Handler = Arc::new(|_idx, _rec: &Recorded| FakeReply::empty(200));
        let (url, records, jh) = spawn_fake(handler).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);
        let run = uuid::Uuid::now_v7();
        let registry: crate::state::McpSessionRegistry = Mutex::new(live_registry(
            run,
            McpPeer::Binding(uuid::Uuid::now_v7()),
            &url,
        ));
        cleanup_with_auth(
            &registry,
            &client,
            &policy,
            run,
            Ok(Some(("authorization", "Bearer terminal-tok"))),
        )
        .await;
        jh.abort();
        // Precondition: the fake recorded something at all.
        assert!(
            count_http(&records, "DELETE") > 0,
            "no DELETE fired (dead fake?)"
        );
        let recs = records.lock().unwrap();
        let del = recs.iter().find(|r| r.http_method == "DELETE").unwrap();
        assert_eq!(
            del.headers.get("authorization").map(String::as_str),
            Some("Bearer terminal-tok"),
            "the terminal DELETE must carry the re-resolved credential"
        );
        // …still alongside the routing headers it always sent.
        assert_eq!(
            del.headers.get("mcp-session-id").map(String::as_str),
            Some("live-session")
        );
    }

    #[tokio::test]
    async fn terminal_cleanup_skips_the_delete_when_the_credential_is_unavailable() {
        // Invariant 9: the credential is re-resolved at teardown, and a revoked
        // connection / moved generation / deactivated owner is precisely the case
        // where we must NOT send one. Termination is best-effort ⇒ skip the DELETE
        // (never send it unauthorized), while eviction still happens.
        let handler: Handler = Arc::new(|_idx, _rec: &Recorded| FakeReply::empty(200));
        let (url, records, jh) = spawn_fake(handler).await;
        let policy = dev_policy();
        let client = crate::egress::build_egress_http(&policy);

        // Positive control on the SAME fake: a resolvable credential DOES fire one.
        let ok_run = uuid::Uuid::now_v7();
        let ok_registry: crate::state::McpSessionRegistry = Mutex::new(live_registry(
            ok_run,
            McpPeer::Binding(uuid::Uuid::now_v7()),
            &url,
        ));
        cleanup_with_auth(
            &ok_registry,
            &client,
            &policy,
            ok_run,
            Ok(Some(("authorization", "Bearer live"))),
        )
        .await;
        assert_eq!(
            count_http(&records, "DELETE"),
            1,
            "the fake must record a DELETE when resolution succeeds (dead fake?)"
        );

        // Same fake, same shape — but resolution refuses.
        let bad_run = uuid::Uuid::now_v7();
        let bad_registry: crate::state::McpSessionRegistry = Mutex::new(live_registry(
            bad_run,
            McpPeer::Binding(uuid::Uuid::now_v7()),
            &url,
        ));
        cleanup_with_auth(
            &bad_registry,
            &client,
            &policy,
            bad_run,
            Err("connection is revoked — reconnect it"),
        )
        .await;
        jh.abort();
        assert_eq!(
            count_http(&records, "DELETE"),
            1,
            "a DELETE must NOT be sent when the credential cannot be re-resolved"
        );
        assert!(
            bad_registry.lock().await.is_empty(),
            "eviction must happen even when the DELETE is skipped"
        );
    }

    // ── recheck_binding matrix (real Neon; self-skips when DATABASE_URL unset) ──
    //
    // Drives the pool-based core with directly-constructed binding rows pointed
    // at real seeded connections + memberships: the happy paths pass, and each
    // single revocation-recheck violation refuses. Children-first cleanup runs
    // BEFORE the asserts so a failing assert never leaks fixtures.

    use chrono::Utc;
    use fluidbox_db::{
        connect, identity, ConnectionAuth, ConnectionOwner, IntegrationConnectionRow,
        RunResourceBindingRow, TenantScope,
    };
    use uuid::Uuid;

    async fn seed_user(
        pool: &sqlx::PgPool,
        scope: TenantScope,
        subject: &str,
        member: bool,
    ) -> Uuid {
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
        if member {
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
        }
        user_id
    }

    async fn seed_conn(
        pool: &sqlx::PgPool,
        scope: TenantScope,
        owner: ConnectionOwner,
        display: &str,
    ) -> IntegrationConnectionRow {
        fluidbox_db::create_connection(
            pool,
            scope,
            "mcp_http",
            &format!("acct-{}", Uuid::now_v7().simple()),
            display,
            Some(b"sealed-token"),
            1,
            &serde_json::json!([]),
            &serde_json::json!({}),
            &serde_json::json!({ "base_url": "https://mcp.example.test" }),
            None,
            1,
            ConnectionAuth::static_active(),
            owner,
            None,
        )
        .await
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn binding_row(
        tenant: Uuid,
        conn: &IntegrationConnectionRow,
        generation: i32,
        owner_type: &str,
        owner_user_id: Option<Uuid>,
    ) -> RunResourceBindingRow {
        RunResourceBindingRow {
            id: Uuid::now_v7(),
            tenant_id: tenant,
            session_id: Uuid::now_v7(),
            requirement_slot: "github".into(),
            slot_kind: "mcp".into(),
            authority_kind: "connection".into(),
            connection_id: Some(conn.id),
            subscription_id: None,
            authority_generation: Some(generation),
            connection_owner_type: Some(owner_type.into()),
            connection_owner_user_id: owner_user_id,
            snapshot_version: Some(1),
            effective_tools_json: None,
            effective_tools_digest: None,
            resource_scope: serde_json::json!({}),
            // `operator` invoker: the invoking-authority recheck (R2.2) is a
            // no-op for operator/system, so this matrix stays focused on the
            // CONNECTION-authority checks. A dedicated test below drives the
            // user/subscription invoker paths.
            resolved_by_principal_kind: "operator".into(),
            resolved_by_principal_id: None,
            binding_mode: "invoking_user".into(),
            created_at: Utc::now(),
        }
    }

    async fn cleanup(pool: &sqlx::PgPool, tenant: Uuid) {
        for stmt in [
            "delete from integration_connections where tenant_id = $1",
            "delete from org_memberships where tenant_id = $1",
            "delete from users where tenant_id = $1",
            "delete from org_idp_configs where tenant_id = $1",
            "delete from tenants where id = $1",
        ] {
            let _ = sqlx::query(stmt).bind(tenant).execute(pool).await;
        }
    }

    #[tokio::test]
    async fn recheck_binding_matrix_passes_happy_and_refuses_each_violation() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url, None).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);
        let alice = seed_user(&pool, scope, "alice@test.dev", true).await;
        let ghost = seed_user(&pool, scope, "ghost@test.dev", false).await; // no membership

        let org_conn = seed_conn(&pool, scope, ConnectionOwner::Organization, "Org").await;
        let alice_conn = seed_conn(&pool, scope, ConnectionOwner::User(alice), "Alice").await;
        let ghost_conn = seed_conn(&pool, scope, ConnectionOwner::User(ghost), "Ghost").await;
        // Connections start at authorization_generation = 1.
        let gen = org_conn.authorization_generation;

        // Collect (label, result) so ALL asserts run after cleanup.
        let happy_org = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(org.id, &org_conn, gen, "organization", None),
        )
        .await;
        let happy_user = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(org.id, &alice_conn, gen, "user", Some(alice)),
        )
        .await;
        let gen_mismatch = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(org.id, &org_conn, gen + 1, "organization", None),
        )
        .await;
        let tenant_mismatch = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(Uuid::now_v7(), &org_conn, gen, "organization", None),
        )
        .await;
        let missing_membership = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(org.id, &ghost_conn, gen, "user", Some(ghost)),
        )
        .await;

        // Deactivate Alice's membership → her user binding now fails closed.
        sqlx::query("update org_memberships set status = 'deactivated' where tenant_id = $1 and user_id = $2")
            .bind(org.id)
            .bind(alice)
            .execute(&pool)
            .await
            .unwrap();
        let deactivated_owner = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(org.id, &alice_conn, gen, "user", Some(alice)),
        )
        .await;

        // Revoke the org connection → its binding now fails closed.
        fluidbox_db::set_connection_status(&pool, scope, org_conn.id, "revoked", &["active"])
            .await
            .unwrap();
        let non_active = recheck_binding_pool(
            &pool,
            scope,
            &binding_row(org.id, &org_conn, gen, "organization", None),
        )
        .await;

        cleanup(&pool, org.id).await;

        // Happy paths pass; each single violation refuses with a distinct reason.
        assert_eq!(happy_org.expect("org happy").id, org_conn.id);
        assert_eq!(happy_user.expect("user happy").id, alice_conn.id);
        assert!(gen_mismatch
            .expect_err("gen mismatch")
            .contains("reauthorized"));
        assert!(tenant_mismatch
            .expect_err("tenant mismatch")
            .contains("different tenant"));
        assert!(missing_membership
            .expect_err("missing membership")
            .contains("membership is not active"));
        assert!(deactivated_owner
            .expect_err("deactivated owner")
            .contains("membership is not active"));
        assert!(non_active.expect_err("non active").contains("revoked"));
    }

    // ── invoking-authority recheck (R2.2): a run bound to a VALID org connection
    // still fails closed when its invoking user was deactivated or its invoking
    // subscription was disabled/deleted. The connection authority is held
    // constant (a live org connection) so the only variable is the invoker.
    #[tokio::test]
    async fn recheck_binding_refuses_revoked_invoker() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let pool = connect(&url, None).await.expect("connect");
        let org = identity::create_org(&pool, &format!("t-{}", Uuid::now_v7().simple()), None)
            .await
            .unwrap();
        let scope = TenantScope::assume(org.id);

        let conn = seed_conn(&pool, scope, ConnectionOwner::Organization, "Org").await;
        let gen = conn.authorization_generation;
        let member = seed_user(&pool, scope, "member@test.dev", true).await;
        let gone = seed_user(&pool, scope, "gone@test.dev", true).await;

        // A subscription to invoke under (needs agent + policy + revision).
        let policy = fluidbox_db::upsert_policy(
            &pool,
            scope,
            "inv-pol",
            "name: inv",
            &serde_json::json!({"name":"inv"}),
        )
        .await
        .unwrap();
        let agent = fluidbox_db::create_agent(&pool, scope, "inv-agent", None)
            .await
            .unwrap();
        let rev = fluidbox_db::append_agent_revision(
            &pool,
            scope,
            agent.id,
            "claude-agent-sdk",
            "img:test",
            "claude-haiku-4-5",
            Some("p"),
            policy.id,
            &serde_json::json!({}),
            None,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
        .await
        .unwrap();
        let sub = fluidbox_db::create_trigger_subscription(
            &pool,
            scope,
            agent.id,
            "inv-sub",
            "api",
            Some(rev.id),
            Some("t"),
            false,
            false,
            None,
            "allow",
            None,
            None,
            &serde_json::json!([]),
            None,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // A connection binding with an overridable invoking principal.
        let invoker_binding = |kind: &str, id: Option<String>| {
            let mut b = binding_row(org.id, &conn, gen, "organization", None);
            b.resolved_by_principal_kind = kind.into();
            b.resolved_by_principal_id = id;
            b
        };

        let user_ok = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("user", Some(member.to_string())),
        )
        .await;
        // A trigger run freezes the exact TOKEN as its principal (E1): mint a live
        // trigger token for the subscription and recheck against ITS id.
        let tok_plain = format!("fbx_trig_{}", Uuid::now_v7().simple());
        fluidbox_db::create_trigger_token(&pool, scope, sub.id, &tok_plain)
            .await
            .unwrap();
        let tok_id = fluidbox_db::subscription_for_token(&pool, &tok_plain)
            .await
            .unwrap()
            .unwrap()
            .token_id;
        let sub_ok = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("trigger", Some(tok_id.to_string())),
        )
        .await;
        // A forged/unknown trigger token id fails closed (E1).
        let trigger_bad = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("trigger", Some(Uuid::now_v7().to_string())),
        )
        .await;
        // An unrecognized principal kind fails closed (E2).
        let unknown_kind = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("martian", Some(Uuid::now_v7().to_string())),
        )
        .await;
        let missing_sub = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("schedule", Some(Uuid::now_v7().to_string())),
        )
        .await;

        sqlx::query("update org_memberships set status = 'deactivated' where tenant_id = $1 and user_id = $2")
            .bind(org.id)
            .bind(gone)
            .execute(&pool)
            .await
            .unwrap();
        let user_revoked = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("user", Some(gone.to_string())),
        )
        .await;

        fluidbox_db::set_trigger_subscription_enabled(&pool, scope, sub.id, false)
            .await
            .unwrap();
        let sub_disabled = recheck_binding_pool(
            &pool,
            scope,
            &invoker_binding("webhook", Some(sub.id.to_string())),
        )
        .await;

        for stmt in [
            "delete from trigger_subscriptions where tenant_id = $1",
            "delete from agent_revisions where agent_id in (select id from agents where tenant_id = $1)",
            "delete from agents where tenant_id = $1",
            "delete from policies where tenant_id = $1",
        ] {
            let _ = sqlx::query(stmt).bind(org.id).execute(&pool).await;
        }
        cleanup(&pool, org.id).await;

        assert_eq!(user_ok.expect("active member invoker").id, conn.id);
        assert_eq!(sub_ok.expect("live trigger token invoker").id, conn.id);
        assert!(trigger_bad
            .expect_err("forged trigger token")
            .contains("revoked or expired"));
        assert!(unknown_kind
            .expect_err("unrecognized principal kind")
            .contains("unrecognized invoking principal kind"));
        assert!(missing_sub
            .expect_err("missing subscription")
            .contains("no longer exists"));
        assert!(user_revoked
            .expect_err("deactivated invoker")
            .contains("no longer an active member"));
        assert!(sub_disabled
            .expect_err("disabled subscription")
            .contains("disabled"));
    }
}
