//! Seamless GitHub connect (Phase 5.6): the App manifest dance + the
//! installation dance, replacing hand-pasted app_id / installation_id /
//! private key / webhook secret with a "Connect GitHub" button.
//! Design: docs/plans/2026-07-11-github-seamless-connect-design.md.
//!
//! Trust model in one paragraph: creating/activating a connection is a
//! fluidbox-ADMIN act. The admin-token'd start endpoints mint one-time
//! `github_app_flows` rows; the unauthenticated browser legs must present
//! (a) an AEAD-sealed, type-tagged token and (b) the initiating browser's
//! HttpOnly cookie — the cookie hash sits INSIDE the one-time claim
//! predicate, so a leaked URL can neither complete nor burn a flow. GitHub-
//! supplied identifiers are never trusted: `installation_id` must resolve
//! via `GET /app/installations/{id}` under OUR app's JWT. Anything not
//! blessed by an admin flow lands `pending` (or is ignored) until an
//! explicit admin approve/sync.
//!
//! This module owns every GitHub-shaped detail of the dance; events.rs and
//! run_service.rs stay provider-ignorant (the app-level ingress below
//! resolves the connection, then calls the shared generic pipeline).

use crate::auth::Admin;
use crate::connectors::github;
use crate::error::{ApiError, ApiResult};
use crate::seal::Sealer;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use fluidbox_db::{GithubAppRegistrationRow, IntegrationConnectionRow};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

/// Flow TTL matches GitHub's manifest-code lifetime (1 hour).
const FLOW_TTL_SECS: i64 = 3600;
const TAG_BOOT: &str = "gh-boot";
const TAG_MANIFEST: &str = "gh-manifest";
const TAG_INSTALL: &str = "gh-install";
const PURPOSE_MANIFEST: &str = "manifest";
const PURPOSE_INSTALL: &str = "install";
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

fn sealer(state: &AppState) -> ApiResult<&Sealer> {
    state.sealer.as_ref().ok_or_else(|| {
        ApiError::BadRequest(
            "GitHub connect is disabled: set FLUIDBOX_CREDENTIAL_KEY (32-byte hex/base64) on the server".into(),
        )
    })
}

// ─── Pure pieces (unit-tested) ────────────────────────────────────────────

/// Minimal HTML escaping for every interpolated value on the browser pages.
pub(crate) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// GitHub org logins: alphanumeric + hyphens, no leading hyphen. Validated
/// before the value rides a URL path.
pub(crate) fn valid_org_name(org: &str) -> bool {
    !org.is_empty()
        && org.len() <= 100
        && !org.starts_with('-')
        && org.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// The two-token discipline: `B` (tag gh-boot) bootstraps the go page and
/// never goes to GitHub; `S` (gh-manifest / gh-install) rides through
/// GitHub. Tags make them non-interchangeable — and non-interchangeable
/// with oauth.rs's `{c,v,x}` states.
pub(crate) fn seal_flow_token(
    sealer: &Sealer,
    tag: &str,
    flow: Uuid,
    registration: Uuid,
) -> String {
    let payload = json!({
        "t": tag,
        "f": flow,
        "r": registration,
        "x": Utc::now().timestamp() + FLOW_TTL_SECS,
    });
    crate::oauth::b64url(&sealer.seal(&payload.to_string()))
}

pub(crate) fn open_flow_token(
    sealer: &Sealer,
    tag: &str,
    token: &str,
) -> Result<(Uuid, Uuid), String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| "malformed token")?;
    let plain = sealer.open(&raw).map_err(|_| "token failed verification")?;
    let v: Value = serde_json::from_str(&plain).map_err(|_| "token is corrupt")?;
    if v["t"].as_str() != Some(tag) {
        return Err("token is not valid for this step".into());
    }
    let exp = v["x"].as_i64().ok_or("token is corrupt")?;
    if Utc::now().timestamp() > exp {
        return Err("this link expired — start again from the dashboard".into());
    }
    let flow = v["f"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("token is corrupt")?;
    let reg = v["r"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("token is corrupt")?;
    Ok((flow, reg))
}

/// The manifest GitHub receives. Built server-side so the dashboard never
/// sees GitHub shapes; the registration id is embedded in the webhook and
/// setup URLs — that is how the unauthenticated ingress/setup endpoints
/// identify their registration without trusting GitHub-supplied values.
pub(crate) fn build_manifest(public_url: &str, registration_id: Uuid) -> Value {
    let host_hint = reqwest::Url::parse(public_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.replace('.', "-")))
        .unwrap_or_else(|| "local".into());
    json!({
        "name": format!("fluidbox-{host_hint}"),
        "url": public_url,
        "hook_attributes": {
            "url": format!("{public_url}/v1/ingress/github/app/{registration_id}"),
            "active": true,
        },
        "redirect_url": format!("{public_url}/v1/github/app/manifest/callback"),
        "setup_url": format!("{public_url}/v1/github/app/{registration_id}/setup"),
        "setup_on_update": true,
        "public": false,
        "default_permissions": {
            "contents": "read",
            "pull_requests": "write",
            "checks": "write",
        },
        "default_events": ["pull_request"],
    })
}

/// Where the manifest form POSTs: the account or organization app-creation
/// page, with our sealed state in the query (GitHub echoes it back).
pub(crate) fn manifest_action_url(
    web_url: &str,
    target_org: Option<&str>,
    state_param: &str,
) -> String {
    let base = match target_org {
        Some(org) => format!("{web_url}/organizations/{org}/settings/apps/new"),
        None => format!("{web_url}/settings/apps/new"),
    };
    let mut url = reqwest::Url::parse(&base)
        .unwrap_or_else(|_| reqwest::Url::parse("https://github.com/settings/apps/new").unwrap());
    url.query_pairs_mut().append_pair("state", state_param);
    url.to_string()
}

/// Per-flow cookie name — concurrent flows never clobber each other.
fn cookie_name(flow: Uuid) -> String {
    format!("fbx_gh_{}", flow.simple())
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

fn set_cookie(state: &AppState, flow: Uuid, nonce: &str) -> String {
    let secure = if state.cfg.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{}={nonce}; HttpOnly; SameSite=Lax; Path=/v1/github/app; Max-Age={FLOW_TTL_SECS}{secure}",
        cookie_name(flow)
    )
}

fn clear_cookie(flow: Uuid) -> String {
    format!(
        "{}=gone; HttpOnly; SameSite=Lax; Path=/v1/github/app; Max-Age=0",
        cookie_name(flow)
    )
}

/// Browser-facing page with the hostile-input policy applied: strict CSP
/// (form-action only when a form is present), no-store, no-referrer, DENY.
/// `body_html` is caller-built from already-escaped pieces.
fn page(
    status: StatusCode,
    title: &str,
    body_html: &str,
    form_action_origin: Option<&str>,
    cookies: &[String],
) -> Response {
    let csp = match form_action_origin {
        Some(origin) => {
            format!("default-src 'none'; style-src 'unsafe-inline'; form-action {origin}")
        }
        None => "default-src 'none'; style-src 'unsafe-inline'".to_string(),
    };
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>fluidbox — {t}</title></head>\
         <body style=\"font-family:system-ui;max-width:38rem;margin:4rem auto;line-height:1.5\">\
         <h2>{t}</h2>{body_html}</body></html>",
        t = html_escape(title),
    );
    let mut b = Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer")
        .header("x-frame-options", "DENY")
        .header("content-security-policy", csp);
    for c in cookies {
        b = b.header("set-cookie", c);
    }
    b.body(Body::from(html)).expect("static response builds")
}

fn refusal(reason: &str) -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "GitHub connect failed",
        &format!("<p>{}</p>", html_escape(reason)),
        None,
        &[],
    )
}

fn origin_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .map(|u| {
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            format!("{}://{}{port}", u.scheme(), u.host_str().unwrap_or(""))
        })
        .unwrap_or_else(|| "https://github.com".into())
}

/// Signing material for a registration: active-only sealed-pem reader —
/// there is deliberately NO fallback to connection custody.
async fn registration_signing(
    state: &AppState,
    reg: &GithubAppRegistrationRow,
) -> Result<(String, String), String> {
    if reg.status != "active" {
        return Err(format!("github app registration is {}", reg.status));
    }
    let sealer = state
        .sealer
        .as_ref()
        .ok_or("FLUIDBOX_CREDENTIAL_KEY not configured")?;
    let sealed = fluidbox_db::github_app_registration_pem_sealed(&state.pool, reg.id)
        .await
        .map_err(|e| format!("registration key lookup failed: {e}"))?
        .ok_or("github app registration key unavailable — recreate the app")?;
    let app_id = reg
        .app_id
        .clone()
        .ok_or("github app registration is incomplete")?;
    Ok((app_id, sealer.open(&sealed).map_err(|e| e.to_string())?))
}

/// Re-verify an installation under this registration's JWT — the approve
/// path's truth check (connections.rs).
pub(crate) async fn verify_installation(
    state: &AppState,
    reg: &GithubAppRegistrationRow,
    installation_id: &str,
) -> Result<Option<Value>, String> {
    let (app_id, pem) = registration_signing(state, reg).await?;
    github::fetch_installation(state, &app_id, &pem, installation_id).await
}

pub(crate) fn installation_display(reg: &GithubAppRegistrationRow, login: &str) -> String {
    format!("{} → {login}", reg.slug.as_deref().unwrap_or("github-app"))
}

pub(crate) fn installation_metadata(
    reg: &GithubAppRegistrationRow,
    installation_id: &str,
    login: &str,
) -> Value {
    json!({
        "app_id": reg.app_id,
        "installation_id": installation_id,
        "app_slug": reg.slug,
        "account_login": login,
        "registration_id": reg.id,
    })
}

/// Upsert the ONE live connection row for a verified installation.
/// `activate` distinguishes admin-intent paths (setup with a valid flow,
/// sync) from discovery (installation.created webhook → pending). Revoked
/// rows are never revived here — that is the explicit approve path — and a
/// row belonging to another custody path (legacy or another registration)
/// is a refusal, never a hijack.
async fn apply_verified_installation(
    state: &AppState,
    reg: &GithubAppRegistrationRow,
    installation_id: &str,
    account_login: &str,
    github_suspended: bool,
    activate: bool,
) -> Result<IntegrationConnectionRow, String> {
    let desired = if github_suspended {
        "suspended"
    } else if activate {
        "active"
    } else {
        "pending"
    };
    let display = installation_display(reg, account_login);
    let metadata = installation_metadata(reg, installation_id, account_login);
    // Two attempts: losing the unique-index insert race re-enters the
    // existing-row path so the surviving row still gets FULL custody
    // validation and the caller's desired transition (e.g. a webhook's
    // pending insert landing just before an admin setup's activate).
    for attempt in 0..2 {
        let existing = fluidbox_db::get_github_app_connection_by_installation(
            &state.pool,
            state.tenant_id,
            installation_id,
        )
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?;
        if let Some(row) = existing {
            if row.status == "revoked" {
                return Err(
                    "this installation was revoked in fluidbox — revive it from the dashboard (approve), or uninstall and reinstall on GitHub".into(),
                );
            }
            if row.registration_id != Some(reg.id) {
                return Err(
                    "this installation is already connected through another fluidbox connection"
                        .into(),
                );
            }
            fluidbox_db::refresh_connection_metadata(&state.pool, row.id, &display, &metadata)
                .await
                .map_err(|e| format!("metadata refresh failed: {e}"))?;
            let updated = if row.status == desired {
                fluidbox_db::get_connection(&state.pool, row.id)
                    .await
                    .map_err(|e| format!("connection lookup failed: {e}"))?
            } else {
                let from: &[&str] = match desired {
                    // Discovery never demotes an already-live row.
                    "pending" => &[],
                    "suspended" => &["active", "pending", "error"],
                    _ => &["pending", "suspended", "error"],
                };
                if from.is_empty() {
                    fluidbox_db::get_connection(&state.pool, row.id)
                        .await
                        .map_err(|e| format!("connection lookup failed: {e}"))?
                } else {
                    fluidbox_db::set_connection_status(&state.pool, row.id, desired, from)
                        .await
                        .map_err(|e| format!("status transition failed: {e}"))?
                        .or(fluidbox_db::get_connection(&state.pool, row.id)
                            .await
                            .map_err(|e| format!("connection lookup failed: {e}"))?)
                }
            };
            if desired == "suspended" {
                crate::oauth::invalidate_access(state, row.id).await;
            }
            return updated.ok_or_else(|| "connection changed state underneath".into());
        }
        // The never-existed check rides INSIDE the insert statement, so a
        // fresh row can never land just behind a concurrent revoke (F‑6:
        // revoked rows revive only via approve). None ⇒ some row appeared
        // (any status) — loop back through the existing-row path above.
        match fluidbox_db::create_github_app_connection_if_absent(
            &state.pool,
            state.tenant_id,
            installation_id,
            &display,
            &metadata,
            desired,
            reg.id,
        )
        .await
        {
            Ok(Some(row)) => return Ok(row),
            Ok(None) if attempt == 0 => continue,
            Ok(None) => {}
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() && attempt == 0 => continue,
            Err(e) => return Err(format!("connection create failed: {e}")),
        }
    }
    Err("connection race did not settle — retry".into())
}

// ─── Admin API ────────────────────────────────────────────────────────────

pub async fn list(_: Admin, State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let registrations =
        fluidbox_db::list_github_app_registrations(&state.pool, state.tenant_id).await?;
    Ok(Json(json!({ "registrations": registrations })))
}

#[derive(Deserialize)]
pub struct ManifestStart {
    /// Create the app under an organization instead of the admin's personal
    /// account. Private apps install only on the account that owns them.
    #[serde(default)]
    pub organization: Option<String>,
}

pub async fn manifest_start(
    _: Admin,
    State(state): State<AppState>,
    Json(req): Json<ManifestStart>,
) -> ApiResult<Json<Value>> {
    let sealer_ref = sealer(&state)?;
    let org = req
        .organization
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(o) = org {
        if !valid_org_name(o) {
            return Err(ApiError::BadRequest(format!(
                "'{o}' is not a valid GitHub organization name"
            )));
        }
    }
    let (target_kind, target_org) = match org {
        Some(o) => ("organization", Some(o)),
        None => ("personal", None),
    };
    let registration = fluidbox_db::create_github_app_registration(
        &state.pool,
        state.tenant_id,
        target_kind,
        target_org,
    )
    .await?;
    let flow = fluidbox_db::create_github_app_flow(
        &state.pool,
        registration.id,
        PURPOSE_MANIFEST,
        FLOW_TTL_SECS,
    )
    .await?;
    let boot = seal_flow_token(sealer_ref, TAG_BOOT, flow, registration.id);
    let go_url = format!(
        "{}/v1/github/app/manifest/go?boot={boot}",
        state.cfg.public_url
    );
    Ok(Json(
        json!({ "registration": registration, "go_url": go_url }),
    ))
}

pub async fn install_start(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let sealer_ref = sealer(&state)?;
    let reg = fluidbox_db::get_github_app_registration(&state.pool, id)
        .await?
        .filter(|r| r.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    if reg.status != "active" || reg.slug.is_none() {
        return Err(ApiError::Conflict(format!(
            "registration is {} — finish app creation first",
            reg.status
        )));
    }
    let flow =
        fluidbox_db::create_github_app_flow(&state.pool, reg.id, PURPOSE_INSTALL, FLOW_TTL_SECS)
            .await?;
    let boot = seal_flow_token(sealer_ref, TAG_BOOT, flow, reg.id);
    let go_url = format!(
        "{}/v1/github/app/install/go?boot={boot}",
        state.cfg.public_url
    );
    Ok(Json(json!({ "go_url": go_url, "registration": reg })))
}

/// Revoke the registration AND its child connections (one transaction),
/// then evict their cached installation tokens.
pub async fn revoke(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let reg = fluidbox_db::get_github_app_registration(&state.pool, id)
        .await?
        .filter(|r| r.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    let Some(connection_ids) =
        fluidbox_db::revoke_github_app_registration(&state.pool, reg.id).await?
    else {
        return Err(ApiError::Conflict("registration is already revoked".into()));
    };
    for cid in &connection_ids {
        crate::oauth::invalidate_access(&state, *cid).await;
    }
    Ok(Json(json!({
        "registration_id": reg.id,
        "revoked_connections": connection_ids,
    })))
}

/// Reconcile fluidbox against GitHub's installation list. Admin-token'd —
/// the call IS the intent, so unknown live installations import as ACTIVE
/// and pending rows activate. Revoked rows are never revived; rows owned by
/// another custody path are surfaced as conflicts, never hijacked.
pub async fn sync(
    _: Admin,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let reg = fluidbox_db::get_github_app_registration(&state.pool, id)
        .await?
        .filter(|r| r.tenant_id == state.tenant_id)
        .ok_or(ApiError::NotFound)?;
    let (app_id, pem) = registration_signing(&state, &reg)
        .await
        .map_err(ApiError::BadRequest)?;
    let installations = github::list_installations(&state, &app_id, &pem)
        .await
        .map_err(ApiError::Upstream)?;
    let mut synced = Vec::new();
    let mut conflicts = Vec::new();
    for inst in &installations {
        let Some(iid) = inst["id"].as_i64() else {
            continue;
        };
        let iid = iid.to_string();
        let login = inst["account"]["login"].as_str().unwrap_or("unknown");
        let suspended = inst["suspended_at"].is_string();
        let existing = fluidbox_db::get_github_app_connection_by_installation(
            &state.pool,
            state.tenant_id,
            &iid,
        )
        .await?;
        if let Some(row) = &existing {
            if row.status == "revoked" {
                conflicts.push(
                    json!({ "installation_id": iid, "reason": "revoked (approve to revive)" }),
                );
                continue;
            }
            if row.registration_id != Some(reg.id) {
                conflicts.push(
                    json!({ "installation_id": iid, "reason": "owned by another connection" }),
                );
                continue;
            }
        }
        match apply_verified_installation(&state, &reg, &iid, login, suspended, true).await {
            Ok(row) => synced.push(json!({
                "installation_id": iid,
                "connection_id": row.id,
                "status": row.status,
            })),
            Err(e) => conflicts.push(json!({ "installation_id": iid, "reason": e })),
        }
    }
    Ok(Json(json!({
        "registration_id": reg.id,
        "installations": installations.len(),
        "synced": synced,
        "conflicts": conflicts,
    })))
}

// ─── Browser leg 1: manifest go page ──────────────────────────────────────

#[derive(Deserialize)]
pub struct GoParams {
    #[serde(default)]
    pub boot: Option<String>,
}

pub async fn manifest_go(State(state): State<AppState>, Query(q): Query<GoParams>) -> Response {
    let Some(sealer_ref) = state.sealer.as_ref() else {
        return refusal("FLUIDBOX_CREDENTIAL_KEY is not configured.");
    };
    let Some(boot) = q.boot.as_deref() else {
        return refusal("Missing token.");
    };
    let (flow, reg_id) = match open_flow_token(sealer_ref, TAG_BOOT, boot) {
        Ok(v) => v,
        Err(e) => return refusal(&e),
    };
    // Bind THIS browser to the flow, exactly once. The nonce is minted
    // here, never derived from anything the URL carried.
    let nonce = crate::oauth::random_urlsafe();
    let claimed = fluidbox_db::claim_github_app_bootstrap(
        &state.pool,
        flow,
        PURPOSE_MANIFEST,
        &fluidbox_db::sha256_hex(&nonce),
    )
    .await;
    match claimed {
        Ok(Some(r)) if r == reg_id => {}
        Ok(_) => return refusal("This link was already used — start again from the dashboard."),
        Err(e) => {
            tracing::error!("bootstrap claim failed: {e}");
            return refusal("Something went wrong — try again from the dashboard.");
        }
    }
    let reg =
        match fluidbox_db::get_github_app_registration(&state.pool, reg_id).await {
            Ok(Some(r)) if r.tenant_id == state.tenant_id && r.status == "pending" => r,
            Ok(Some(r)) if r.status == "active" => return page(
                StatusCode::OK,
                "App already created",
                "<p>This GitHub App already exists — connect it from the fluidbox dashboard.</p>",
                None,
                &[],
            ),
            _ => return refusal("Unknown or revoked registration."),
        };
    let manifest = build_manifest(&state.cfg.public_url, reg.id);
    let state_param = seal_flow_token(sealer_ref, TAG_MANIFEST, flow, reg.id);
    let action = manifest_action_url(
        &state.cfg.github_web_url,
        reg.target_org.as_deref(),
        &state_param,
    );
    let body = format!(
        "<p>fluidbox will ask GitHub to create a <b>private GitHub App</b> with exactly the \
         permissions it needs (contents: read, pull requests: write, checks: write) and its \
         webhook pre-wired. You can adjust the name on GitHub's confirmation page; the app \
         installs on the account that owns it.</p>\
         <form method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" name=\"manifest\" value=\"{manifest}\">\
         <button type=\"submit\" style=\"font-size:1rem;padding:0.5rem 1.25rem;cursor:pointer\">\
         Continue to GitHub →</button></form>",
        action = html_escape(&action),
        manifest = html_escape(&manifest.to_string()),
    );
    page(
        StatusCode::OK,
        "Create the GitHub App",
        &body,
        Some(&origin_of(&state.cfg.github_web_url)),
        &[set_cookie(&state, flow, &nonce)],
    )
}

// ─── Browser leg 2: manifest callback (conversion) ────────────────────────

#[derive(Deserialize)]
pub struct ManifestCallbackParams {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

/// Strict typed conversion response — a partially parsed registration is
/// never activated.
#[derive(Deserialize)]
struct Conversion {
    id: i64,
    slug: Option<String>,
    name: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    webhook_secret: Option<String>,
    pem: String,
    html_url: String,
    owner: Option<ConversionOwner>,
}

#[derive(Deserialize)]
struct ConversionOwner {
    login: Option<String>,
}

pub async fn manifest_callback(
    State(state): State<AppState>,
    Query(p): Query<ManifestCallbackParams>,
    headers: HeaderMap,
) -> Response {
    let Some(sealer_ref) = state.sealer.as_ref() else {
        return refusal("FLUIDBOX_CREDENTIAL_KEY is not configured.");
    };
    let (Some(code), Some(state_param)) = (p.code.as_deref(), p.state.as_deref()) else {
        return refusal("Missing code or state parameter.");
    };
    if code.is_empty() || code.len() > 200 {
        return refusal("Malformed code parameter.");
    }
    let (flow, reg_id) = match open_flow_token(sealer_ref, TAG_MANIFEST, state_param) {
        Ok(v) => v,
        Err(e) => return refusal(&e),
    };
    // The browser cookie is the second factor; without it the flow is not
    // even burned (the hash sits inside the claim predicate).
    let Some(nonce) = cookie_value(&headers, &cookie_name(flow)) else {
        return refusal("This browser did not start the flow — start again from the dashboard.");
    };
    match fluidbox_db::claim_github_app_flow(
        &state.pool,
        flow,
        PURPOSE_MANIFEST,
        reg_id,
        &fluidbox_db::sha256_hex(&nonce),
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return refusal(
                "This link was already used or expired — start again from the dashboard.",
            )
        }
        Err(e) => {
            tracing::error!("flow claim failed: {e}");
            return refusal("Something went wrong — try again from the dashboard.");
        }
    }
    let reg = match fluidbox_db::get_github_app_registration(&state.pool, reg_id).await {
        Ok(Some(r)) if r.tenant_id == state.tenant_id => r,
        _ => return refusal("Unknown registration."),
    };
    if reg.status != "pending" {
        return refusal("This registration already completed.");
    }

    // Exchange the one-hour, single-use code. Unauthenticated by GitHub's
    // design; the flow claim above is OUR auth. The code rides a
    // percent-encoded path segment.
    let mut url = match reqwest::Url::parse(&state.cfg.github_api_url) {
        Ok(u) => u,
        Err(_) => return refusal("GitHub API base is misconfigured."),
    };
    if url
        .path_segments_mut()
        .map(|mut s| {
            s.pop_if_empty()
                .push("app-manifests")
                .push(code)
                .push("conversions");
        })
        .is_err()
    {
        return refusal("GitHub API base is misconfigured.");
    }
    let res = state
        .http
        .post(url)
        .timeout(HTTP_TIMEOUT)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "fluidbox")
        .header("x-github-api-version", "2022-11-28")
        .send()
        .await;
    let res = match res {
        Ok(r) => r,
        Err(e) => {
            // NEVER format this error with its URL: the path segment is the
            // unauthenticated conversion code — in a log it would let a
            // reader mint the app credentials themselves.
            tracing::warn!("manifest conversion unreachable: {}", e.without_url());
            return refusal(
                "GitHub was unreachable during the exchange — start again from the dashboard.",
            );
        }
    };
    let status = res.status();
    if status != reqwest::StatusCode::CREATED {
        return refusal(&format!(
            "GitHub refused the manifest exchange (HTTP {status}) — the code may have expired; start again from the dashboard."
        ));
    }
    let conv: Conversion = match res.json().await {
        Ok(v) => v,
        Err(_) => return refusal("GitHub's conversion response was not understood."),
    };
    let slug = conv.slug.clone().unwrap_or_else(|| conv.name.clone());
    let owner_login = conv.owner.as_ref().and_then(|o| o.login.clone());
    let pem_sealed = sealer_ref.seal(&conv.pem);
    let webhook_sealed = conv.webhook_secret.as_deref().map(|s| sealer_ref.seal(s));
    let client_sealed = conv.client_secret.as_deref().map(|s| sealer_ref.seal(s));
    let activated = fluidbox_db::activate_github_app_registration(
        &state.pool,
        reg.id,
        &conv.id.to_string(),
        &slug,
        &conv.name,
        conv.client_id.as_deref(),
        &conv.html_url,
        owner_login.as_deref(),
        &pem_sealed,
        webhook_sealed.as_deref(),
        client_sealed.as_deref(),
    )
    .await;
    match activated {
        Ok(Some(_)) => {}
        Ok(None) => {
            // A racing conversion won `pending → active`; this result is
            // discarded (the app it created is orphaned on GitHub under
            // whoever created it — delete it there).
            return refusal(
                "Another manifest exchange completed first — this attempt was discarded.",
            );
        }
        Err(e) => {
            tracing::error!("registration activation failed: {e}");
            return refusal("Storing the app failed — try again from the dashboard.");
        }
    }

    // Chain straight into the install dance THROUGH the install go page so
    // the browser gets bound to the new flow (never a direct GitHub link).
    let install_note = match fluidbox_db::create_github_app_flow(
        &state.pool,
        reg.id,
        PURPOSE_INSTALL,
        FLOW_TTL_SECS,
    )
    .await
    {
        Ok(f2) => {
            let boot2 = seal_flow_token(sealer_ref, TAG_BOOT, f2, reg.id);
            format!(
                "<p><a href=\"{href}\" style=\"font-size:1rem\">Install it now →</a></p>",
                href = html_escape(&format!(
                    "{}/v1/github/app/install/go?boot={boot2}",
                    state.cfg.public_url
                )),
            )
        }
        Err(_) => String::new(),
    };
    let degraded = if conv.webhook_secret.is_none() {
        "<p><b>Note:</b> GitHub returned no webhook secret — event ingress is disabled for this app (fetch and publish still work). Recreate the app to fix this.</p>"
    } else {
        ""
    };
    page(
        StatusCode::OK,
        "GitHub App created",
        &format!(
            "<p>The app <b>{name}</b> now exists and fluidbox custodies its credentials — nothing to paste anywhere.</p>{degraded}{install_note}",
            name = html_escape(&conv.name),
        ),
        None,
        &[clear_cookie(flow)],
    )
}

// ─── Browser leg 3: install go (bind + redirect) ──────────────────────────

pub async fn install_go(State(state): State<AppState>, Query(q): Query<GoParams>) -> Response {
    let Some(sealer_ref) = state.sealer.as_ref() else {
        return refusal("FLUIDBOX_CREDENTIAL_KEY is not configured.");
    };
    let Some(boot) = q.boot.as_deref() else {
        return refusal("Missing token.");
    };
    let (flow, reg_id) = match open_flow_token(sealer_ref, TAG_BOOT, boot) {
        Ok(v) => v,
        Err(e) => return refusal(&e),
    };
    let nonce = crate::oauth::random_urlsafe();
    match fluidbox_db::claim_github_app_bootstrap(
        &state.pool,
        flow,
        PURPOSE_INSTALL,
        &fluidbox_db::sha256_hex(&nonce),
    )
    .await
    {
        Ok(Some(r)) if r == reg_id => {}
        Ok(_) => return refusal("This link was already used — start again from the dashboard."),
        Err(e) => {
            tracing::error!("bootstrap claim failed: {e}");
            return refusal("Something went wrong — try again from the dashboard.");
        }
    }
    let reg = match fluidbox_db::get_github_app_registration(&state.pool, reg_id).await {
        Ok(Some(r)) if r.tenant_id == state.tenant_id && r.status == "active" => r,
        _ => return refusal("Unknown or inactive registration."),
    };
    let Some(slug) = reg.slug.as_deref() else {
        return refusal("Registration is incomplete.");
    };
    let state_param = seal_flow_token(sealer_ref, TAG_INSTALL, flow, reg.id);
    let mut url = match reqwest::Url::parse(&format!(
        "{}/apps/{slug}/installations/new",
        state.cfg.github_web_url
    )) {
        Ok(u) => u,
        Err(_) => return refusal("GitHub web base is misconfigured."),
    };
    url.query_pairs_mut().append_pair("state", &state_param);
    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", url.to_string())
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer")
        .header("set-cookie", set_cookie(&state, flow, &nonce))
        .body(Body::empty())
        .expect("static response builds")
}

// ─── Browser leg 4: setup callback ────────────────────────────────────────

#[derive(Deserialize)]
pub struct SetupParams {
    #[serde(default)]
    pub installation_id: Option<String>,
    // GitHub also sends `setup_action=install|update`; the handler treats
    // both identically (verify, then upsert) so it goes unread.
    #[serde(default)]
    pub state: Option<String>,
}

/// GitHub warns the setup `installation_id` is spoofable — it is verified
/// under our app JWT before anything happens. Without a valid admin flow
/// (missing/invalid state — including GitHub-initiated installs and repo-
/// selection updates), this endpoint performs ZERO writes and ZERO GitHub
/// calls: activation happens from the dashboard (sync/approve).
pub async fn setup(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(p): Query<SetupParams>,
    headers: HeaderMap,
) -> Response {
    let guidance = || {
        page(
            StatusCode::OK,
            "Almost connected",
            "<p>GitHub finished on its side. To activate the connection, open the fluidbox \
             dashboard → Connections and use <b>Sync &amp; activate installs</b> on the GitHub \
             App card.</p>",
            None,
            &[],
        )
    };
    let Some(sealer_ref) = state.sealer.as_ref() else {
        return refusal("FLUIDBOX_CREDENTIAL_KEY is not configured.");
    };
    let (flow, reg_from_state) = match p
        .state
        .as_deref()
        .map(|s| open_flow_token(sealer_ref, TAG_INSTALL, s))
    {
        Some(Ok(v)) => v,
        // No state (GitHub-initiated install / update, or GitHub dropped
        // it) or an invalid one: the guidance page, nothing else.
        _ => return guidance(),
    };
    if reg_from_state != id {
        return refusal("This link belongs to a different registration.");
    }
    let Some(nonce) = cookie_value(&headers, &cookie_name(flow)) else {
        return guidance();
    };
    let iid = match p.installation_id.as_deref() {
        Some(s) if !s.is_empty() && s.len() <= 20 && s.chars().all(|c| c.is_ascii_digit()) => s,
        _ => return refusal("Missing or malformed installation id."),
    };
    match fluidbox_db::claim_github_app_flow(
        &state.pool,
        flow,
        PURPOSE_INSTALL,
        id,
        &fluidbox_db::sha256_hex(&nonce),
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return refusal(
                "This link was already used or expired — start again from the dashboard.",
            )
        }
        Err(e) => {
            tracing::error!("flow claim failed: {e}");
            return refusal("Something went wrong — try again from the dashboard.");
        }
    }
    let reg = match fluidbox_db::get_github_app_registration(&state.pool, id).await {
        Ok(Some(r)) if r.tenant_id == state.tenant_id => r,
        _ => return refusal("Unknown registration."),
    };
    let (app_id, pem) = match registration_signing(&state, &reg).await {
        Ok(v) => v,
        Err(e) => return refusal(&e),
    };
    // The trust anchor: only OUR app's installations resolve under our JWT.
    let inst = match github::fetch_installation(&state, &app_id, &pem, iid).await {
        Ok(Some(v)) => v,
        Ok(None) => return refusal("That installation does not belong to this GitHub App."),
        Err(e) => return refusal(&e),
    };
    let login = inst["account"]["login"].as_str().unwrap_or("unknown");
    let suspended = inst["suspended_at"].is_string();
    match apply_verified_installation(&state, &reg, iid, login, suspended, true).await {
        Ok(row) => page(
            StatusCode::OK,
            "GitHub connected",
            &format!(
                "<p><b>{login}</b> is connected (installation {iid}, status <b>{status}</b>). \
                 You can close this tab — the dashboard picks it up automatically.</p>",
                login = html_escape(login),
                iid = html_escape(iid),
                status = html_escape(&row.status),
            ),
            None,
            &[clear_cookie(flow)],
        ),
        Err(e) => refusal(&e),
    }
}

// ─── App-level ingress ────────────────────────────────────────────────────

const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// `POST /v1/ingress/github/app/{registration_id}` — GitHub App webhooks
/// are app-level: ONE URL for every installation. Unauthenticated by
/// design; the HMAC against the REGISTRATION's sealed secret is the auth,
/// and nothing is stored before it verifies. After lifecycle handling, the
/// resolved connection rides the exact same provider-ignorant pipeline as
/// per-connection ingress.
pub async fn app_ingress(
    State(state): State<AppState>,
    Path(registration_id): Path<Uuid>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> Response {
    if body.len() > MAX_BODY_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "payload too large" })),
        )
            .into_response();
    }
    let Some(sealer_ref) = state.sealer.as_ref() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "event ingress is disabled: set FLUIDBOX_CREDENTIAL_KEY" })),
        )
            .into_response();
    };
    let reg = match fluidbox_db::get_github_app_registration(&state.pool, registration_id).await {
        Ok(Some(r)) if r.tenant_id == state.tenant_id && r.status == "active" => r,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("registration lookup failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let sealed =
        match fluidbox_db::github_app_registration_webhook_secret_sealed(&state.pool, reg.id).await
        {
            Ok(Some(s)) => s,
            Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
            Err(e) => {
                tracing::error!("webhook secret lookup failed: {e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    let secret = match sealer_ref.open(&sealed) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("webhook secret unseal failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let verified = match github::verify(&headers, &body, &secret) {
        Ok(v) => v,
        Err(reason) => {
            tracing::warn!("app ingress {registration_id}: rejected delivery: {reason}");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("payload is not json: {e}") })),
            )
                .into_response()
        }
    };

    // Installation lifecycle first — webhook ORDER is never authoritative
    // for suspend/unsuspend; current GitHub truth is.
    if let Some(lc) = github::installation_lifecycle(&verified.event_name, &payload) {
        return handle_lifecycle(&state, &reg, lc).await;
    }

    let Some(installation_id) = github::installation_ref(&payload) else {
        // Ping and app-level events: authentic, acknowledged, ignored.
        return (
            StatusCode::ACCEPTED,
            Json(json!({ "ignored": verified.event_name })),
        )
            .into_response();
    };
    let conn = match fluidbox_db::get_github_app_connection_by_installation(
        &state.pool,
        state.tenant_id,
        &installation_id.to_string(),
    )
    .await
    {
        Ok(Some(c)) if c.status == "active" && c.registration_id == Some(reg.id) => c,
        Ok(_) => {
            // Unknown / pending / suspended / foreign installation: a
            // deliberate ack (not a 404 — the delivery WAS authentic).
            return (
                StatusCode::ACCEPTED,
                Json(json!({ "ignored": verified.event_name, "installation_id": installation_id })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("connection lookup failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    // The digest covers the exact signed bytes — same discipline as the
    // per-connection route.
    let digest = format!(
        "sha256:{}",
        fluidbox_db::sha256_hex(std::str::from_utf8(&body).unwrap_or_default())
    );
    match crate::events::process_delivery(&state, &conn, "github", &verified, &payload, &digest)
        .await
    {
        Ok(json) => json.into_response(),
        Err(e) => e.into_response(),
    }
}

async fn handle_lifecycle(
    state: &AppState,
    reg: &GithubAppRegistrationRow,
    lc: github::InstallationLifecycle,
) -> Response {
    use github::InstallationLifecycle as L;
    let (iid, action) = match &lc {
        L::Created {
            installation_id, ..
        } => (*installation_id, "created"),
        L::Deleted { installation_id } => (*installation_id, "deleted"),
        L::Suspend { installation_id } => (*installation_id, "suspend"),
        L::Unsuspend { installation_id } => (*installation_id, "unsuspend"),
    };
    let iid_str = iid.to_string();
    let existing = match fluidbox_db::get_github_app_connection_by_installation(
        &state.pool,
        state.tenant_id,
        &iid_str,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("connection lookup failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    // Rows owned by another custody path (legacy paste / other
    // registration) are never touched from this app's ingress.
    let owned = existing
        .as_ref()
        .filter(|c| c.registration_id == Some(reg.id) && c.status != "revoked");
    // DATABASE failures must NOT be acknowledged: a swallowed error on
    // `installation.deleted` would leave the connection live forever (the
    // webhook is gone once acked). 500 makes GitHub redeliver; semantic
    // no-ops still ack.
    let db500 = |e: sqlx::Error| {
        tracing::error!("lifecycle transition failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    };
    let outcome = match lc {
        L::Created { account_login, .. } => {
            if existing.is_none() {
                // Discovery, not authority: the row lands PENDING until an
                // admin approves or syncs (design §3 rule 3). Errors here
                // (including insert races) 500 so the redelivery heals.
                match apply_verified_installation(
                    state,
                    reg,
                    &iid_str,
                    &account_login,
                    false,
                    false,
                )
                .await
                {
                    Ok(row) => {
                        json!({ "handled": action, "connection_id": row.id, "status": row.status })
                    }
                    Err(e) => {
                        tracing::error!("installation.created handling failed: {e}");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }
            } else {
                json!({ "handled": action, "note": "already known" })
            }
        }
        L::Deleted { .. } => match owned {
            Some(c) => {
                let done = match fluidbox_db::set_connection_status(
                    &state.pool,
                    c.id,
                    "revoked",
                    &["active", "pending", "suspended", "error"],
                )
                .await
                {
                    Ok(row) => row.is_some(),
                    Err(e) => return db500(e),
                };
                crate::oauth::invalidate_access(state, c.id).await;
                json!({ "handled": action, "revoked": done })
            }
            None => json!({ "handled": action, "note": "unknown installation" }),
        },
        L::Suspend { .. } | L::Unsuspend { .. } => match owned {
            Some(c) => {
                // Reconcile against current GitHub truth; a delayed
                // suspend after a genuine unsuspend must not win.
                let truth = match registration_signing(state, reg).await {
                    Ok((app_id, pem)) => {
                        github::fetch_installation(state, &app_id, &pem, &iid_str).await
                    }
                    Err(e) => Err(e),
                };
                match truth {
                    Ok(Some(inst)) => {
                        let suspended = inst["suspended_at"].is_string();
                        let (to, from): (&str, &[&str]) = if suspended {
                            ("suspended", &["active"])
                        } else {
                            ("active", &["suspended"])
                        };
                        let changed =
                            match fluidbox_db::set_connection_status(&state.pool, c.id, to, from)
                                .await
                            {
                                Ok(row) => row.is_some(),
                                Err(e) => return db500(e),
                            };
                        if suspended {
                            crate::oauth::invalidate_access(state, c.id).await;
                        }
                        json!({ "handled": action, "status": to, "changed": changed })
                    }
                    Ok(None) => {
                        // Installation vanished under us — treat as deleted.
                        if let Err(e) = fluidbox_db::set_connection_status(
                            &state.pool,
                            c.id,
                            "revoked",
                            &["active", "pending", "suspended", "error"],
                        )
                        .await
                        {
                            return db500(e);
                        }
                        crate::oauth::invalidate_access(state, c.id).await;
                        json!({ "handled": action, "status": "revoked" })
                    }
                    Err(e) => {
                        if action == "suspend" {
                            // GitHub unreachable: fail toward closed.
                            if let Err(db) = fluidbox_db::set_connection_status(
                                &state.pool,
                                c.id,
                                "suspended",
                                &["active"],
                            )
                            .await
                            {
                                return db500(db);
                            }
                            crate::oauth::invalidate_access(state, c.id).await;
                            json!({ "handled": action, "status": "suspended", "note": e })
                        } else {
                            json!({ "handled": action, "note": format!("left unchanged: {e}") })
                        }
                    }
                }
            }
            None => json!({ "handled": action, "note": "unknown installation" }),
        },
    };
    (StatusCode::OK, Json(outcome)).into_response()
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sealer() -> Sealer {
        Sealer::from_key_string(&"ab".repeat(32)).unwrap()
    }

    #[test]
    fn manifest_embeds_registration_scoped_urls_and_least_privilege() {
        let reg = Uuid::now_v7();
        let m = build_manifest("https://fbx.example.com", reg);
        assert_eq!(m["name"], "fluidbox-fbx-example-com");
        assert_eq!(
            m["hook_attributes"]["url"],
            format!("https://fbx.example.com/v1/ingress/github/app/{reg}")
        );
        assert_eq!(
            m["redirect_url"],
            "https://fbx.example.com/v1/github/app/manifest/callback"
        );
        assert_eq!(
            m["setup_url"],
            format!("https://fbx.example.com/v1/github/app/{reg}/setup")
        );
        assert_eq!(m["setup_on_update"], true);
        assert_eq!(m["public"], false);
        // Exactly the permissions the PR fan-out needs — nothing more.
        assert_eq!(
            m["default_permissions"],
            serde_json::json!({"contents": "read", "pull_requests": "write", "checks": "write"})
        );
        assert_eq!(m["default_events"], serde_json::json!(["pull_request"]));
    }

    #[test]
    fn manifest_action_targets_account_or_org_and_carries_state() {
        let a = manifest_action_url("https://github.com", None, "S1");
        assert_eq!(a, "https://github.com/settings/apps/new?state=S1");
        let o = manifest_action_url("https://github.com", Some("acme"), "S1");
        assert_eq!(
            o,
            "https://github.com/organizations/acme/settings/apps/new?state=S1"
        );
    }

    #[test]
    fn flow_tokens_are_tagged_one_purpose_each() {
        let s = test_sealer();
        let (f, r) = (Uuid::now_v7(), Uuid::now_v7());
        let boot = seal_flow_token(&s, TAG_BOOT, f, r);
        let manifest = seal_flow_token(&s, TAG_MANIFEST, f, r);
        // Round-trips under the right tag…
        assert_eq!(open_flow_token(&s, TAG_BOOT, &boot).unwrap(), (f, r));
        assert_eq!(
            open_flow_token(&s, TAG_MANIFEST, &manifest).unwrap(),
            (f, r)
        );
        // …and is refused under every other tag (boot can never drive a
        // callback; a GitHub-transited state can never re-bootstrap).
        assert!(open_flow_token(&s, TAG_MANIFEST, &boot).is_err());
        assert!(open_flow_token(&s, TAG_BOOT, &manifest).is_err());
        assert!(open_flow_token(&s, TAG_INSTALL, &manifest).is_err());
        // Cross-module: an oauth.rs state ({c,v,x}) is refused too.
        let oauth_state = crate::oauth::seal_state(&s, Uuid::now_v7(), "v");
        assert!(open_flow_token(&s, TAG_MANIFEST, &oauth_state).is_err());
        // Tampering and wrong keys fail closed.
        assert!(open_flow_token(&s, TAG_BOOT, "junk!!").is_err());
        let other = Sealer::from_key_string(&"cd".repeat(32)).unwrap();
        assert!(open_flow_token(&other, TAG_BOOT, &boot).is_err());
    }

    #[test]
    fn html_escaping_and_org_validation_close_the_injection_doors() {
        assert_eq!(
            html_escape(r#"<img src=x onerror="1">'"#),
            "&lt;img src=x onerror=&quot;1&quot;&gt;&#39;"
        );
        assert!(valid_org_name("acme-corp"));
        assert!(valid_org_name("a1"));
        assert!(!valid_org_name(""));
        assert!(!valid_org_name("-leading"));
        assert!(!valid_org_name("has space"));
        assert!(!valid_org_name("slash/../up"));
        assert!(!valid_org_name(&"x".repeat(101)));
    }

    #[test]
    fn cookie_helpers_are_flow_scoped() {
        let f = Uuid::now_v7();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("other=1; {}=nonce-123; x=2", cookie_name(f))
                .parse()
                .unwrap(),
        );
        assert_eq!(
            cookie_value(&headers, &cookie_name(f)).as_deref(),
            Some("nonce-123")
        );
        assert!(cookie_value(&headers, "fbx_gh_other").is_none());
        assert!(cookie_name(f).starts_with("fbx_gh_"));
    }
}
