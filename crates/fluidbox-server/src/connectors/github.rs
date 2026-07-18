//! The GitHub connector — the ONLY module that knows GitHub's shapes
//! (design §6.3; GitHub is the first tenant of the connector seam, not the
//! feature). Duties here: (1) verify webhook deliveries, (2) normalize PR
//! events, (3) resolve the event workspace; matching stays generic in
//! events.rs; (5) publish comments/checks (added with the publisher).

use super::{NormalizeCtx, NormalizedEvent, VerifiedDelivery};
use crate::state::AppState;
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use fluidbox_core::spec::{CheckoutMode, ResultDestination, TrustTier, WorkspaceSpec};
use fluidbox_db::IntegrationConnectionRow;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

const GITHUB_TIMEOUT: Duration = Duration::from_secs(15);

/// PR lifecycle actions fluidbox can react to. `synchronize` fires on EVERY
/// push to the PR branch — a cost amplifier, hence opt-in (§17 #2).
pub const SUPPORTED_EVENTS: [&str; 3] = [
    "pull_request.opened",
    "pull_request.reopened",
    "pull_request.synchronize",
];
/// §17 #2 (settled): default filter = opened + reopened.
pub const DEFAULT_EVENTS: [&str; 2] = ["pull_request.opened", "pull_request.reopened"];
pub const PUBLISH_MODES: [&str; 2] = ["pr_comment", "check"];

// ─── Duty #1: verify ──────────────────────────────────────────────────────

/// GitHub signs the raw body: `X-Hub-Signature-256: sha256=<hex hmac>`.
/// Errors stay generic — never echo the expected signature.
pub fn verify(headers: &HeaderMap, body: &[u8], secret: &str) -> Result<VerifiedDelivery, String> {
    let sig = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing X-Hub-Signature-256 header")?;
    let presented = sig
        .strip_prefix("sha256=")
        .ok_or("malformed X-Hub-Signature-256 header")?
        .to_ascii_lowercase();

    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(body);
    let expected = hex::encode(mac.finalize().into_bytes());
    // Constant-time-ish compare via sha256 of both sides (auth.rs pattern).
    if fluidbox_db::sha256_hex(&presented) != fluidbox_db::sha256_hex(&expected) {
        return Err("webhook signature mismatch".into());
    }

    let external_event_id = headers
        .get("x-github-delivery")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .ok_or("missing X-GitHub-Delivery header")?
        .to_string();
    let event_name = headers
        .get("x-github-event")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .ok_or("missing X-GitHub-Event header")?
        .to_string();
    Ok(VerifiedDelivery {
        external_event_id,
        event_name,
    })
}

// ─── Duties #2 + #3: normalize + event workspace ──────────────────────────

fn valid_sha(sha: &str) -> bool {
    (7..=40).contains(&sha.len()) && sha.chars().all(|c| c.is_ascii_hexdigit())
}

/// `Ok(None)` = authentic GitHub traffic fluidbox doesn't react to (ping,
/// other PR actions, other event families).
pub fn normalize(
    event_name: &str,
    payload: &Value,
    ctx: &NormalizeCtx,
) -> Result<Option<NormalizedEvent>, String> {
    if event_name != "pull_request" {
        return Ok(None);
    }
    let action = payload["action"]
        .as_str()
        .ok_or("pull_request payload has no action")?;
    if !matches!(action, "opened" | "reopened" | "synchronize") {
        return Ok(None);
    }
    let event_type = format!("pull_request.{action}");

    let repository = payload["repository"]["full_name"]
        .as_str()
        .ok_or("payload has no repository.full_name")?
        .to_string();
    // The payload is attacker-shaped even after signature verification (the
    // signature proves the sender, not the content's intent) — and this
    // value feeds a clone URL. Validate hard, derive the URL ourselves.
    if !crate::api::valid_repo_name(&repository) {
        return Err(format!(
            "payload repository '{repository}' is not owner/name"
        ));
    }

    let pr = &payload["pull_request"];
    let pr_number = pr["number"]
        .as_i64()
        .ok_or("payload has no pull_request.number")?;
    let head_sha = pr["head"]["sha"]
        .as_str()
        .ok_or("payload has no pull_request.head.sha")?
        .to_string();
    if !valid_sha(&head_sha) {
        return Err(format!("payload head sha '{head_sha}' is not a commit sha"));
    }
    let pr_title = pr["title"].as_str().unwrap_or("").to_string();
    let pr_url = pr["html_url"].as_str().unwrap_or("").to_string();
    let pr_author = pr["user"]["login"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let head_ref = pr["head"]["ref"].as_str().unwrap_or("").to_string();
    let base_sha = pr["base"]["sha"].as_str().unwrap_or("").to_string();
    let base_ref = pr["base"]["ref"].as_str().unwrap_or("").to_string();

    // Fork detection keys on repo identity, and FAILS TOWARD FORK: a payload
    // that hides the head repo gets the untrusted tier, never the trusted one.
    let fork = match (
        pr["head"]["repo"]["id"].as_i64(),
        pr["base"]["repo"]["id"].as_i64(),
    ) {
        (Some(h), Some(b)) => h != b,
        _ => true,
    };
    let (trust_tier, checkout_mode) = if fork {
        (TrustTier::ReadOnly, CheckoutMode::ReadOnly)
    } else {
        (TrustTier::Trusted, CheckoutMode::WritableCopy)
    };

    // Exact head SHA on the BASE repo clone URL: GitHub serves PR head
    // commits (fork ones included) by SHA from the base repository, and
    // materialize_git's branch-fetch fallback covers plain-git remotes.
    let workspace = WorkspaceSpec::GitRepository {
        connection_id: Some(ctx.connection_id),
        repository: Some(repository.clone()),
        clone_url: format!("{}/{repository}", ctx.clone_base.trim_end_matches('/')),
        r#ref: None,
        commit_sha: Some(head_sha.clone()),
        checkout_mode,
    };

    let context: BTreeMap<String, String> = [
        ("repository", repository.as_str()),
        ("pr_number", &pr_number.to_string()),
        ("pr_title", &pr_title),
        ("pr_url", &pr_url),
        ("pr_author", &pr_author),
        ("head_sha", &head_sha),
        ("head_ref", &head_ref),
        ("base_sha", &base_sha),
        ("base_ref", &base_ref),
        ("action", action),
        ("event", &event_type),
        ("fork", if fork { "true" } else { "false" }),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    let publishable: BTreeMap<String, ResultDestination> = [
        (
            "pr_comment".to_string(),
            ResultDestination::GitHubPrComment {
                connection_id: ctx.connection_id,
                repository: repository.clone(),
                pr_number,
            },
        ),
        (
            "check".to_string(),
            ResultDestination::GitHubCheck {
                connection_id: ctx.connection_id,
                repository: repository.clone(),
                head_sha: head_sha.clone(),
            },
        ),
    ]
    .into_iter()
    .collect();

    let occurred_at: Option<DateTime<Utc>> = pr["updated_at"]
        .as_str()
        .or(pr["created_at"].as_str())
        .and_then(|s| s.parse().ok());

    Ok(Some(NormalizedEvent {
        resource_key: format!("{repository}#{pr_number}"),
        resource: repository.clone(),
        actor: Some(format!("github:{pr_author}")),
        occurred_at,
        trust_tier,
        workspace: Some(workspace),
        context,
        publishable,
        attributes: json!({
            "provider": "github",
            "repository": repository,
            "pr_number": pr_number,
            "title": pr_title,
            "author": pr_author,
            "head_sha": head_sha,
            "base_sha": base_sha,
            "fork": fork,
            "action": action,
            "url": pr_url,
        }),
        event_type,
    }))
}

/// Representative context for config-time template validation. Keys must
/// stay a superset-match of what `normalize` produces.
pub fn sample_context() -> BTreeMap<String, String> {
    [
        ("repository", "acme/site"),
        ("pr_number", "1"),
        ("pr_title", "Example change"),
        ("pr_url", "https://github.com/acme/site/pull/1"),
        ("pr_author", "octocat"),
        ("head_sha", "0123456789abcdef0123456789abcdef01234567"),
        ("head_ref", "feature"),
        ("base_sha", "89abcdef0123456789abcdef0123456789abcdef"),
        ("base_ref", "main"),
        ("action", "opened"),
        ("event", "pull_request.opened"),
        ("fork", "false"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

// ─── GitHub REST plumbing ─────────────────────────────────────────────────

fn api_url(state: &AppState, path: &str) -> String {
    format!("{}{path}", state.cfg.github_api_url.trim_end_matches('/'))
}

/// One GitHub REST call. Errors only on transport/parse problems — callers
/// interpret the status. Error text carries the URL/path, never headers.
pub(crate) async fn api(
    state: &AppState,
    method: reqwest::Method,
    authorization: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<(reqwest::StatusCode, Value, reqwest::header::HeaderMap), String> {
    let mut req = state
        .http
        .request(method, api_url(state, path))
        .timeout(GITHUB_TIMEOUT)
        .header("authorization", authorization)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "fluidbox")
        .header("x-github-api-version", "2022-11-28");
    if let Some(b) = body {
        req = req.json(b);
    }
    let res = req
        .send()
        .await
        .map_err(|e| format!("github unreachable: {e}"))?;
    let status = res.status();
    let headers = res.headers().clone();
    let text = res
        .text()
        .await
        .map_err(|e| format!("github {path}: unreadable response: {e}"))?;
    let value = if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::Null)
    };
    Ok((status, value, headers))
}

// ─── GitHub App identity (§17 #1: results appear App-only) ───────────────

#[derive(serde::Serialize)]
struct AppJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

/// Short-lived RS256 JWT proving we are the App (GitHub caps exp at 10
/// minutes; iat is backdated 60s against clock drift).
pub fn app_jwt(app_id: &str, private_key_pem: &str) -> Result<String, String> {
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|_| "app private key is not a valid RSA PEM".to_string())?;
    let now = Utc::now().timestamp();
    let claims = AppJwtClaims {
        iat: now - 60,
        exp: now + 540,
        iss: app_id.to_string(),
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &key,
    )
    .map_err(|_| "app jwt signing failed".to_string())
}

fn app_metadata<'a>(conn: &'a IntegrationConnectionRow, key: &str) -> Result<&'a str, String> {
    conn.metadata
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("connection metadata is missing '{key}' — reconnect the app"))
}

/// Unseal the connection credential (PAT or App private key).
async fn unsealed_credential(
    state: &AppState,
    conn: &IntegrationConnectionRow,
) -> Result<String, String> {
    let sealer = state
        .sealer
        .as_ref()
        .ok_or("FLUIDBOX_CREDENTIAL_KEY not configured")?;
    let scope = fluidbox_db::TenantScope::assume(conn.tenant_id);
    let sealed = fluidbox_db::connection_credential_sealed(&state.pool, scope, conn.id)
        .await
        .map_err(|e| format!("credential lookup failed: {e}"))?
        .ok_or("connection is not active (revoked or missing)")?;
    sealer.open(&sealed).map_err(|e| e.to_string())
}

/// Mint (or reuse) the installation access token for an App connection.
/// Custody is gated by FRESH DB reads before the cache may serve (the cache
/// is an optimization, never the security boundary — design 5.6 §4.6): the
/// connection must be active, and a linked registration must itself be
/// active. Resolution never falls back across custody kinds: a linked
/// registration that is missing/revoked refuses outright. Tokens live ~1h;
/// the cache refreshes when <5 minutes remain. The durable secret (the
/// private key) never leaves this function's scope.
pub async fn installation_token(
    state: &AppState,
    conn: &IntegrationConnectionRow,
) -> Result<String, String> {
    // The passed-in connection row is already resolved and trusted; its own
    // tenant scopes the re-read and the registration lookup.
    let scope = fluidbox_db::TenantScope::assume(conn.tenant_id);
    // The caller's row may be stale (revoked/suspended out from under a
    // cached token) — re-read status from the database first.
    let conn = fluidbox_db::get_connection(&state.pool, scope, conn.id)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?
        .ok_or("connection is gone")?;
    if conn.status != "active" {
        return Err(format!(
            "connection is {} — reconnect it in Connections",
            conn.status
        ));
    }
    let registration = match conn.registration_id {
        Some(rid) => {
            let reg = fluidbox_db::get_github_app_registration(&state.pool, scope, rid)
                .await
                .map_err(|e| format!("registration lookup failed: {e}"))?
                .ok_or("github app registration is missing — reconnect GitHub")?;
            if reg.status != "active" {
                return Err(format!(
                    "github app registration is {} — reconnect GitHub",
                    reg.status
                ));
            }
            Some(reg)
        }
        None => None,
    };
    {
        let cache = state.connector_tokens.lock().await;
        if let Some((token, expires_at)) = cache.get(&conn.id) {
            if *expires_at > Utc::now() + chrono::Duration::seconds(300) {
                return Ok(token.clone());
            }
        }
    }
    let (app_id, pem) = match &registration {
        Some(reg) => {
            let sealer = state
                .sealer
                .as_ref()
                .ok_or("FLUIDBOX_CREDENTIAL_KEY not configured")?;
            let sealed =
                fluidbox_db::github_app_registration_pem_sealed(&state.pool, scope, reg.id)
                    .await
                    .map_err(|e| format!("registration key lookup failed: {e}"))?
                    .ok_or("github app registration key unavailable — recreate the app")?;
            let app_id = reg
                .app_id
                .clone()
                .ok_or("github app registration is incomplete")?;
            (app_id, sealer.open(&sealed).map_err(|e| e.to_string())?)
        }
        None => {
            let app_id = app_metadata(&conn, "app_id")?.to_string();
            (app_id, unsealed_credential(state, &conn).await?)
        }
    };
    // The AUTHORITATIVE installation identity is the row key (both flavors
    // store it there); metadata copies are display-only and must never
    // steer custody.
    let installation_id = conn.external_account_id.as_str();
    let jwt = app_jwt(&app_id, &pem)?;
    let (status, body, _) = api(
        state,
        reqwest::Method::POST,
        &format!("Bearer {jwt}"),
        &format!("/app/installations/{installation_id}/access_tokens"),
        Some(&json!({})),
    )
    .await?;
    if !status.is_success() {
        return Err(format!("github installation token mint returned {status}"));
    }
    let token = body["token"]
        .as_str()
        .ok_or("github token mint response has no token")?
        .to_string();
    let expires_at: DateTime<Utc> = body["expires_at"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| Utc::now() + chrono::Duration::minutes(55));
    state
        .connector_tokens
        .lock()
        .await
        .insert(conn.id, (token.clone(), expires_at));
    Ok(token)
}

/// Prove a pasted PAT works and identify its account (connection create).
pub async fn validate_pat(
    state: &AppState,
    token: &str,
) -> Result<(String, String, Vec<String>), String> {
    let (status, user, headers) = api(
        state,
        reqwest::Method::GET,
        &format!("Bearer {token}"),
        "/user",
        None,
    )
    .await?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(
            "github rejected the token (401) — check that it is valid and unexpired".into(),
        );
    }
    if !status.is_success() {
        return Err(format!("github /user returned {status}"));
    }
    let login = user["login"].as_str().unwrap_or("unknown").to_string();
    let account_id = user["id"]
        .as_i64()
        .map(|id| id.to_string())
        .unwrap_or_else(|| login.clone());
    // Classic PATs advertise scopes; fine-grained PATs don't (empty list).
    let scopes: Vec<String> = headers
        .get("x-oauth-scopes")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Ok((login, account_id, scopes))
}

/// Prove App credentials work and identify the installation (connection
/// create). Returns metadata to store on the row (all non-secret).
pub async fn validate_app(
    state: &AppState,
    app_id: &str,
    installation_id: &str,
    private_key_pem: &str,
) -> Result<Value, String> {
    let jwt = app_jwt(app_id, private_key_pem)?;
    let auth = format!("Bearer {jwt}");
    let (status, app, _) = api(state, reqwest::Method::GET, &auth, "/app", None).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(
            "github rejected the app credentials (401) — check app_id and the private key".into(),
        );
    }
    if !status.is_success() {
        return Err(format!("github /app returned {status}"));
    }
    let app_slug = app["slug"].as_str().unwrap_or("app").to_string();
    let (status, inst, _) = api(
        state,
        reqwest::Method::GET,
        &auth,
        &format!("/app/installations/{installation_id}"),
        None,
    )
    .await?;
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(format!(
            "installation {installation_id} not found for this app — install the app first"
        ));
    }
    if !status.is_success() {
        return Err(format!("github /app/installations returned {status}"));
    }
    let account_login = inst["account"]["login"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    Ok(json!({
        "app_id": app_id,
        "installation_id": installation_id,
        "app_slug": app_slug,
        "account_login": account_login,
    }))
}

// ─── Installation shapes (Phase 5.6 seamless connect) ────────────────────

/// GitHub App deliveries carry the installation scope when they have one;
/// ping and app-level events don't — extraction is Optional, never asserted
/// (design 5.6 [F‑10]).
pub fn installation_ref(payload: &Value) -> Option<i64> {
    payload["installation"]["id"].as_i64()
}

/// Installation lifecycle actions the app-level ingress reacts to. Webhook
/// ORDER is never authoritative for suspend/unsuspend — the caller
/// reconciles against `fetch_installation` truth (design 5.6 [F‑9]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallationLifecycle {
    Created {
        installation_id: i64,
        account_login: String,
    },
    Deleted {
        installation_id: i64,
    },
    Suspend {
        installation_id: i64,
    },
    Unsuspend {
        installation_id: i64,
    },
}

pub fn installation_lifecycle(event_name: &str, payload: &Value) -> Option<InstallationLifecycle> {
    if event_name != "installation" {
        return None;
    }
    let installation_id = payload["installation"]["id"].as_i64()?;
    let account_login = payload["installation"]["account"]["login"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    match payload["action"].as_str()? {
        "created" => Some(InstallationLifecycle::Created {
            installation_id,
            account_login,
        }),
        "deleted" => Some(InstallationLifecycle::Deleted { installation_id }),
        "suspend" => Some(InstallationLifecycle::Suspend { installation_id }),
        "unsuspend" => Some(InstallationLifecycle::Unsuspend { installation_id }),
        _ => None,
    }
}

/// One installation lookup under an app JWT — the identifier trust anchor:
/// `GET /app/installations/{id}` succeeds only for THIS app's
/// installations, so a spoofed setup `installation_id` gets `Ok(None)`.
pub(crate) async fn fetch_installation(
    state: &AppState,
    app_id: &str,
    pem: &str,
    installation_id: &str,
) -> Result<Option<Value>, String> {
    let jwt = app_jwt(app_id, pem)?;
    let (status, body, _) = api(
        state,
        reqwest::Method::GET,
        &format!("Bearer {jwt}"),
        &format!("/app/installations/{installation_id}"),
        None,
    )
    .await?;
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(format!("github /app/installations returned {status}"));
    }
    Ok(Some(body))
}

/// List this app's installations (first page, 100 — the sync endpoint's
/// source of truth).
pub(crate) async fn list_installations(
    state: &AppState,
    app_id: &str,
    pem: &str,
) -> Result<Vec<Value>, String> {
    let jwt = app_jwt(app_id, pem)?;
    let (status, body, _) = api(
        state,
        reqwest::Method::GET,
        &format!("Bearer {jwt}"),
        "/app/installations?per_page=100",
        None,
    )
    .await?;
    if !status.is_success() {
        return Err(format!("github /app/installations returned {status}"));
    }
    Ok(body.as_array().cloned().unwrap_or_default())
}

/// Repository picker for both connection flavors. The credential never
/// leaves the control plane.
pub async fn list_repos(
    state: &AppState,
    conn: &IntegrationConnectionRow,
    page: u32,
    per_page: u32,
) -> Result<Vec<Value>, String> {
    let (auth, path, items_key) = if conn.provider == "github_app" {
        let token = installation_token(state, conn).await?;
        (
            format!("Bearer {token}"),
            format!("/installation/repositories?per_page={per_page}&page={page}"),
            Some("repositories"),
        )
    } else {
        let pat = unsealed_credential(state, conn).await?;
        (
            format!("Bearer {pat}"),
            format!("/user/repos?per_page={per_page}&page={page}&sort=updated"),
            None,
        )
    };
    let (status, body, _) = api(state, reqwest::Method::GET, &auth, &path, None).await?;
    if !status.is_success() {
        return Err(format!("github repository listing returned {status}"));
    }
    let items = match items_key {
        Some(k) => body[k].as_array().cloned().unwrap_or_default(),
        None => body.as_array().cloned().unwrap_or_default(),
    };
    Ok(items
        .iter()
        .map(|r| {
            json!({
                "id": r.get("id"),
                "full_name": r.get("full_name"),
                "private": r.get("private"),
                "default_branch": r.get("default_branch"),
                "html_url": r.get("html_url"),
                // Freshness signals for reporting agents/UI.
                "updated_at": r.get("updated_at"),
                "pushed_at": r.get("pushed_at"),
            })
        })
        .collect())
}

/// Git-fetch `Authorization` header for workspace materialization: a PAT
/// directly, or a freshly minted installation token — the same
/// `basic x-access-token:…` shape either way.
pub async fn fetch_auth_header(
    state: &AppState,
    conn: &IntegrationConnectionRow,
) -> anyhow::Result<String> {
    let token = if conn.provider == "github_app" {
        installation_token(state, conn)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
    } else {
        unsealed_credential(state, conn)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
    };
    use base64::Engine;
    Ok(format!(
        "basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"))
    ))
}

// ─── Duty #5: publish (§17 #1 App-only, §17 #3 update in place) ──────────

pub async fn publish(
    state: &AppState,
    dest: &ResultDestination,
    ctx: &super::PublishContext,
) -> Result<super::PublishOutcome, String> {
    match dest {
        ResultDestination::GitHubPrComment {
            connection_id,
            repository,
            pr_number,
        } => publish_pr_comment(state, *connection_id, repository, *pr_number, ctx).await,
        ResultDestination::GitHubCheck {
            connection_id,
            repository,
            head_sha,
        } => publish_check(state, *connection_id, repository, head_sha, ctx).await,
        ResultDestination::SignedWebhook { .. } => Err("not a github destination".into()),
    }
}

/// Publishing identity is the App installation, never a user (§17 #1) —
/// checks REQUIRE it, and comments carry attribution in their content.
async fn app_connection(
    state: &AppState,
    scope: fluidbox_db::TenantScope,
    connection_id: uuid::Uuid,
) -> Result<IntegrationConnectionRow, String> {
    let conn = fluidbox_db::get_connection(&state.pool, scope, connection_id)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?
        .ok_or("destination connection is missing")?;
    if conn.provider != "github_app" {
        return Err("publishing requires a github_app connection (§17 #1: App identity)".into());
    }
    Ok(conn)
}

fn short_sha(sha: Option<&str>) -> String {
    sha.map(|s| s.chars().take(12).collect())
        .unwrap_or_else(|| "-".into())
}

/// The attributable comment body: agent name up top, run identity in the
/// footer. One agent's failure appears only here, on its own comment.
fn comment_body(ctx: &super::PublishContext) -> String {
    let status_note = if ctx.status == "completed" {
        String::new()
    } else {
        format!(
            "\n> ⚠️ this run ended `{}` — the review may be incomplete.\n",
            ctx.status
        )
    };
    let body = ctx
        .summary
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("(no summary produced)");
    format!(
        "### 🤖 {agent} review\n{status_note}\n{body}\n\n---\n_fluidbox · trigger **{sub}** · run `{run}` · commit `{sha}`_\n",
        agent = ctx.agent_name,
        status_note = status_note,
        body = body,
        sub = ctx.subscription_name,
        run = ctx.session_id,
        sha = short_sha(ctx.commit_sha.as_deref()),
    )
}

/// Run status → check conclusion. The check reports RUN health; the review
/// verdict itself lives in the output text.
fn check_conclusion(status: &str) -> &'static str {
    match status {
        "completed" => "success",
        "cancelled" => "cancelled",
        _ => "failure",
    }
}

async fn publish_pr_comment(
    state: &AppState,
    connection_id: uuid::Uuid,
    repository: &str,
    pr_number: i64,
    ctx: &super::PublishContext,
) -> Result<super::PublishOutcome, String> {
    let sub_id = ctx.subscription_id.ok_or(
        "comment publishing requires a subscription (stable identity is per subscription)",
    )?;
    let conn = app_connection(state, ctx.scope, connection_id).await?;
    let token = installation_token(state, &conn).await?;
    let auth = format!("Bearer {token}");
    let resource_key = format!("{repository}#{pr_number}");
    let body_md = comment_body(ctx);
    let digest = format!("sha256:{}", fluidbox_db::sha256_hex(&body_md));
    let payload = json!({ "body": body_md });

    // §17 #3: one stable comment per (subscription, PR) — update it in
    // place; recreate only if it was deleted out from under us.
    if let Some(existing) = fluidbox_db::get_external_result(
        &state.pool,
        ctx.scope,
        sub_id,
        "github_pr_comment",
        &resource_key,
    )
    .await
    .map_err(|e| format!("external result lookup failed: {e}"))?
    {
        let (status, body, _) = api(
            state,
            reqwest::Method::PATCH,
            &auth,
            &format!(
                "/repos/{repository}/issues/comments/{}",
                existing.external_id
            ),
            Some(&payload),
        )
        .await?;
        if status.is_success() {
            let url = body["html_url"]
                .as_str()
                .map(str::to_string)
                .or(existing.external_url.clone())
                .unwrap_or_default();
            fluidbox_db::upsert_external_result(
                &state.pool,
                ctx.scope,
                sub_id,
                "github_pr_comment",
                &resource_key,
                &existing.external_id,
                Some(&url),
            )
            .await
            .map_err(|e| format!("external result update failed: {e}"))?;
            return Ok(super::PublishOutcome {
                external_url: url,
                digest,
            });
        }
        if status != reqwest::StatusCode::NOT_FOUND && status != reqwest::StatusCode::GONE {
            return Err(format!("github comment update returned {status}"));
        }
        // Deleted externally → fall through and create a fresh one.
    }

    let (status, body, _) = api(
        state,
        reqwest::Method::POST,
        &auth,
        &format!("/repos/{repository}/issues/{pr_number}/comments"),
        Some(&payload),
    )
    .await?;
    if !status.is_success() {
        return Err(format!("github comment create returned {status}"));
    }
    let external_id = body["id"]
        .as_i64()
        .ok_or("github comment create response has no id")?
        .to_string();
    let url = body["html_url"].as_str().unwrap_or("").to_string();
    fluidbox_db::upsert_external_result(
        &state.pool,
        ctx.scope,
        sub_id,
        "github_pr_comment",
        &resource_key,
        &external_id,
        Some(&url),
    )
    .await
    .map_err(|e| format!("external result record failed: {e}"))?;
    Ok(super::PublishOutcome {
        external_url: url,
        digest,
    })
}

async fn publish_check(
    state: &AppState,
    connection_id: uuid::Uuid,
    repository: &str,
    head_sha: &str,
    ctx: &super::PublishContext,
) -> Result<super::PublishOutcome, String> {
    let conn = app_connection(state, ctx.scope, connection_id).await?;
    let token = installation_token(state, &conn).await?;
    // Stable name per subscription; one run per head SHA (that's how
    // commit-attached checks version — §17 #3).
    let name = format!("fluidbox/{}", ctx.subscription_name);
    let summary: String = ctx
        .summary
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("(no summary produced)")
        .chars()
        .take(60_000) // GitHub caps output.summary at 65535 chars
        .collect();
    let payload = json!({
        "name": name,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": check_conclusion(&ctx.status),
        "completed_at": Utc::now().to_rfc3339(),
        "output": {
            "title": format!("{}: {}", ctx.agent_name, ctx.status),
            "summary": summary,
        },
    });
    let digest = format!("sha256:{}", fluidbox_db::sha256_hex(&payload.to_string()));
    let (status, body, _) = api(
        state,
        reqwest::Method::POST,
        &format!("Bearer {token}"),
        &format!("/repos/{repository}/check-runs"),
        Some(&payload),
    )
    .await?;
    if !status.is_success() {
        return Err(format!("github check create returned {status}"));
    }
    Ok(super::PublishOutcome {
        external_url: body["html_url"].as_str().unwrap_or("").to_string(),
        digest,
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn signed_headers(sig: &str, delivery: &str, event: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-hub-signature-256", sig.parse().unwrap());
        h.insert("x-github-delivery", delivery.parse().unwrap());
        h.insert("x-github-event", event.parse().unwrap());
        h
    }

    #[test]
    fn verify_accepts_the_openssl_cross_checked_vector() {
        // printf '%s' '{"zen":"Design for failure."}' \
        //   | openssl dgst -sha256 -hmac 'whsec-test'
        let body = br#"{"zen":"Design for failure."}"#;
        let sig = "sha256=0b820ce48d200049fbcbe43352b3405156b0209a2494ef0e96eb21fafcf865e4";
        let v = verify(&signed_headers(sig, "d-1", "ping"), body, "whsec-test").unwrap();
        assert_eq!(v.external_event_id, "d-1");
        assert_eq!(v.event_name, "ping");
        // Uppercase hex from a proxy still verifies.
        let upper = format!(
            "sha256={}",
            sig.trim_start_matches("sha256=").to_uppercase()
        );
        assert!(verify(&signed_headers(&upper, "d-1", "ping"), body, "whsec-test").is_ok());
    }

    #[test]
    fn verify_rejects_tampering_wrong_secret_and_missing_headers() {
        let body = br#"{"zen":"Design for failure."}"#;
        let sig = "sha256=0b820ce48d200049fbcbe43352b3405156b0209a2494ef0e96eb21fafcf865e4";
        // Tampered body.
        assert!(verify(
            &signed_headers(sig, "d-1", "ping"),
            br#"{"zen":"Design for failure!"}"#,
            "whsec-test"
        )
        .is_err());
        // Wrong secret.
        assert!(verify(&signed_headers(sig, "d-1", "ping"), body, "other").is_err());
        // Missing signature / delivery / event headers.
        let mut no_sig = HeaderMap::new();
        no_sig.insert("x-github-delivery", "d".parse().unwrap());
        no_sig.insert("x-github-event", "ping".parse().unwrap());
        assert!(verify(&no_sig, body, "whsec-test").is_err());
        let mut no_delivery = signed_headers(sig, "d-1", "ping");
        no_delivery.remove("x-github-delivery");
        assert!(verify(&no_delivery, body, "whsec-test").is_err());
        // Malformed prefix.
        assert!(verify(
            &signed_headers("sha1=abcd", "d-1", "ping"),
            body,
            "whsec-test"
        )
        .is_err());
    }

    fn pr_payload(action: &str, head_repo_id: i64, base_repo_id: i64) -> Value {
        json!({
            "action": action,
            "repository": { "id": base_repo_id, "full_name": "acme/site" },
            "pull_request": {
                "number": 42,
                "title": "Fix multiply",
                "html_url": "https://github.com/acme/site/pull/42",
                "user": { "login": "octocat" },
                "created_at": "2026-07-10T10:00:00Z",
                "updated_at": "2026-07-10T11:30:00Z",
                "head": {
                    "sha": "abcdef0123456789abcdef0123456789abcdef01",
                    "ref": "fix-multiply",
                    "repo": { "id": head_repo_id, "full_name": "acme/site" }
                },
                "base": {
                    "sha": "0123456789abcdef0123456789abcdef01234567",
                    "ref": "main",
                    "repo": { "id": base_repo_id, "full_name": "acme/site" }
                }
            }
        })
    }

    fn ctx() -> NormalizeCtx {
        NormalizeCtx {
            connection_id: Uuid::now_v7(),
            clone_base: "https://github.com".into(),
        }
    }

    #[test]
    fn normalize_opened_produces_exact_sha_workspace_and_context() {
        let ctx = ctx();
        let ev = normalize("pull_request", &pr_payload("opened", 7, 7), &ctx)
            .unwrap()
            .expect("opened is handled");
        assert_eq!(ev.event_type, "pull_request.opened");
        assert_eq!(ev.resource, "acme/site");
        assert_eq!(ev.resource_key, "acme/site#42");
        assert_eq!(ev.trust_tier, TrustTier::Trusted);
        assert_eq!(ev.actor.as_deref(), Some("github:octocat"));
        assert!(ev.occurred_at.is_some());

        let Some(WorkspaceSpec::GitRepository {
            connection_id,
            repository,
            clone_url,
            r#ref,
            commit_sha,
            checkout_mode,
        }) = &ev.workspace
        else {
            panic!("expected a git workspace");
        };
        assert_eq!(*connection_id, Some(ctx.connection_id));
        assert_eq!(repository.as_deref(), Some("acme/site"));
        // URL derived from clone_base + validated name, never the payload.
        assert_eq!(clone_url, "https://github.com/acme/site");
        assert!(r#ref.is_none());
        assert_eq!(
            commit_sha.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef01")
        );
        assert_eq!(*checkout_mode, CheckoutMode::WritableCopy);

        assert_eq!(ev.context["repository"], "acme/site");
        assert_eq!(ev.context["pr_number"], "42");
        assert_eq!(
            ev.context["head_sha"],
            "abcdef0123456789abcdef0123456789abcdef01"
        );
        assert_eq!(ev.context["base_ref"], "main");
        assert_eq!(ev.context["fork"], "false");

        // Both publish modes instantiated with event data.
        assert!(matches!(
            ev.publishable.get("pr_comment"),
            Some(ResultDestination::GitHubPrComment { pr_number: 42, .. })
        ));
        assert!(matches!(
            ev.publishable.get("check"),
            Some(ResultDestination::GitHubCheck { .. })
        ));
        assert_eq!(ev.attributes["fork"], false);
    }

    #[test]
    fn normalize_handles_all_supported_actions_and_ignores_the_rest() {
        for action in ["opened", "reopened", "synchronize"] {
            let ev = normalize("pull_request", &pr_payload(action, 7, 7), &ctx())
                .unwrap()
                .expect("supported action");
            assert_eq!(ev.event_type, format!("pull_request.{action}"));
            assert!(SUPPORTED_EVENTS.contains(&ev.event_type.as_str()));
        }
        // Unhandled PR actions and other event families are ignored politely.
        assert!(
            normalize("pull_request", &pr_payload("labeled", 7, 7), &ctx())
                .unwrap()
                .is_none()
        );
        assert!(normalize("ping", &json!({"zen": "x"}), &ctx())
            .unwrap()
            .is_none());
        assert!(normalize("push", &json!({}), &ctx()).unwrap().is_none());
    }

    #[test]
    fn normalize_downgrades_forks_and_fails_toward_fork() {
        // Different head/base repo ids = fork → ReadOnly everything.
        let ev = normalize("pull_request", &pr_payload("opened", 999, 7), &ctx())
            .unwrap()
            .unwrap();
        assert_eq!(ev.trust_tier, TrustTier::ReadOnly);
        assert_eq!(ev.context["fork"], "true");
        let Some(WorkspaceSpec::GitRepository { checkout_mode, .. }) = &ev.workspace else {
            panic!()
        };
        assert_eq!(*checkout_mode, CheckoutMode::ReadOnly);

        // A payload that HIDES the head repo gets the fork treatment too.
        let mut hidden = pr_payload("opened", 7, 7);
        hidden["pull_request"]["head"]["repo"] = Value::Null;
        let ev = normalize("pull_request", &hidden, &ctx()).unwrap().unwrap();
        assert_eq!(ev.trust_tier, TrustTier::ReadOnly);
    }

    #[test]
    fn normalize_rejects_hostile_payload_fields() {
        // A repository name that could smuggle path/URL tricks is refused
        // outright (it feeds the clone URL).
        let mut bad_repo = pr_payload("opened", 7, 7);
        bad_repo["repository"]["full_name"] = json!("acme/../../etc");
        assert!(normalize("pull_request", &bad_repo, &ctx()).is_err());
        let mut no_repo = pr_payload("opened", 7, 7);
        no_repo["repository"] = json!({});
        assert!(normalize("pull_request", &no_repo, &ctx()).is_err());
        // Garbage head sha.
        let mut bad_sha = pr_payload("opened", 7, 7);
        bad_sha["pull_request"]["head"]["sha"] = json!("--upload-pack=evil");
        assert!(normalize("pull_request", &bad_sha, &ctx()).is_err());
    }

    /// Throwaway RSA key generated for this test only (never a real secret).
    const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCsOESN3lHbbsmz
upjUgGdPjymvaFA06ZjLCAPquiC2KhDpFnHaouEucrO18ByAzlSU5mGPmF1h7MNo
2dNOPNspKYWualjVxWKJs6wHLGTYSZdl37Sszmi4lHG4YHeoE2rp1AZHv0BuNPeC
9HdycodY4BLd4mFORGRrBPTVYa7BjX7/X1YI7RHcvvrqON9efr2XpIDZBE+2Fa6d
Hamdf+fzVgo8b3/xT67RgkyqQrJPQJjxJzB1pU/P6sHQOrRBHc+oLiD2EIpffPTV
H420KdkoDwnarjsTJG3o172S6+VXw4ReaY8XqOvsKTGqTm7rnZsODbjxXpTNGosh
PT/dRK3DAgMBAAECggEADu9J1QqApPVZRrdGgpy1Mm6Mifp5t76PZZstb8d+7h0w
Xm5EwFX1dI6cEnAfBw9QwW4UuGjZP3rSdVjFqZhYbxwVMv6XWcgMvaFLQhhk95nm
KBguwsYBlqQoFBOovMNP6oHDBUMxTLCJZR3BiZ2J92vMs9lqYJwVhm+L5dp01uVd
A9/C552GmgZR2W/c+Cmxyj9Go5bNv8/gKuQIyNYuhmf6DXVh14hM9Qraq1/vYzt5
ptliFuUjgTA0wMMZ+4JKBZlcOBbs/qN0WOkbZTxlyoLIX3CRyCRoycoPrfIhG2Yj
iBxTD6Y4ZrZ13pAyOSsmBE/hoNRwGZm3ebKHYXD1fQKBgQDrenCjnfbj7RZI/Aav
M1Bj04mSQSCzyk+B9kAbOA1KybWgn8lvw885frQn8LAuWcYw5cKIvQHYmvQMxc9S
X3+rZrBCOzNgTmeakavMboC4q+xprRuYPZB3zOByKBRCasIeiRwh94R40IA60kNs
TLNsJRkp6VI7uiK+6GKwwE4RpQKBgQC7OoU2mMLh3PgZp+LK+cBJgfff62K9gDLE
nVfP3EMwRMd6DlRt8hmazq5RtGxup4kGJOw1qBskzBYw9p/jb+ehQ17uzdIu6R0J
rAB+1sMTX0R/7OIB8LDFMhytoIREIiavHQ0IQ35zRfHdWjDgAqYF3zeBlKoWSi2N
/QH8vRpVRwKBgQCFJeGFEq/kp02fjSo2bLx7BcTXNw5HuxCD+vq6qVISxMV3goJD
OSP2baduohDs1IRVZ8U8ziq6ELwIcN1OxYMKJvFpMdJWFV9NrirHWIBea5AtHN3q
kn0a0HTk97ak63rCC2Ml7bAxJCwtlnDbTu9xKfT1luGRtikpa3tKWCKMpQKBgQCp
eS0/4EL3I4dH4dm+FRfi8cwnWe/EzJgntKzZr+z5ciiF6RavdqeKo27S8lf8SZYU
g7N0VjhLtJiZtYPA4XhvVoZF7vREFip8qL7CES//BwsAKLHjQ7Ueql+fIl7XNXqC
o+85/a4mNbfav1riSkNxqT2bA7B6AKb/kXcNCTce3QKBgQC6t7IeokZ5oO6p0H/m
RoJoJrIXrJVizujdLsk9W5/9F1q2rvm3HVvV6eBVWWIUUT0fGarVr2GeW/Zcz8y0
QXZUSO8W9IUDM0HDnU2s0GcyFEtOq1WvgeYf2OiIh4qCHEg0afzCNiEBGrgKOplc
o+rncG5hSLaqG1A2w8vlQ3BS7Q==
-----END PRIVATE KEY-----";

    #[test]
    fn app_jwt_has_rs256_header_and_app_claims() {
        let jwt = app_jwt("12345", TEST_PEM).expect("valid key signs");
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "jwt has three parts");
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header: Value = serde_json::from_slice(&b64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        let claims: Value = serde_json::from_slice(&b64.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "12345");
        // iat backdated 60s; exp 10 minutes after iat (GitHub's cap).
        let iat = claims["iat"].as_i64().unwrap();
        let exp = claims["exp"].as_i64().unwrap();
        assert_eq!(exp - iat, 600);
        assert!(iat <= Utc::now().timestamp());
        // Garbage keys are refused without panicking.
        assert!(app_jwt("12345", "not a pem").is_err());
    }

    #[test]
    fn comment_body_is_attributable_and_flags_failures() {
        let ctx = super::super::PublishContext {
            scope: fluidbox_db::TenantScope::assume(Uuid::now_v7()),
            session_id: Uuid::now_v7(),
            subscription_id: Some(Uuid::now_v7()),
            subscription_name: "security-review".into(),
            agent_name: "sec-agent".into(),
            status: "completed".into(),
            summary: Some("Looks solid. One nit on error handling.".into()),
            commit_sha: Some("abcdef0123456789abcdef0123456789abcdef01".into()),
        };
        let body = comment_body(&ctx);
        assert!(body.contains("sec-agent review"));
        assert!(body.contains("security-review"));
        assert!(body.contains(&ctx.session_id.to_string()));
        assert!(body.contains("abcdef012345")); // 12-char short sha
        assert!(body.contains("Looks solid"));
        assert!(!body.contains("⚠️"), "completed runs carry no warning");

        // One agent's failure shows only on its own comment — and honestly.
        let failed = super::super::PublishContext {
            status: "failed".into(),
            summary: None,
            ..ctx
        };
        let body = comment_body(&failed);
        assert!(body.contains("⚠️"));
        assert!(body.contains("`failed`"));
        assert!(body.contains("(no summary produced)"));
    }

    #[test]
    fn installation_extraction_is_optional_and_lifecycle_is_classified() {
        // Ping (no installation scope) → None, never an assertion failure.
        assert_eq!(installation_ref(&json!({"zen": "ok"})), None);
        assert_eq!(
            installation_ref(&json!({"installation": {"id": 77}})),
            Some(77)
        );

        let ev = |action: &str| {
            json!({
                "action": action,
                "installation": {"id": 99, "account": {"login": "acme2"}},
            })
        };
        assert_eq!(
            installation_lifecycle("installation", &ev("created")),
            Some(InstallationLifecycle::Created {
                installation_id: 99,
                account_login: "acme2".into()
            })
        );
        assert_eq!(
            installation_lifecycle("installation", &ev("deleted")),
            Some(InstallationLifecycle::Deleted {
                installation_id: 99
            })
        );
        assert_eq!(
            installation_lifecycle("installation", &ev("suspend")),
            Some(InstallationLifecycle::Suspend {
                installation_id: 99
            })
        );
        assert_eq!(
            installation_lifecycle("installation", &ev("unsuspend")),
            Some(InstallationLifecycle::Unsuspend {
                installation_id: 99
            })
        );
        // Unhandled actions and other event families are not lifecycle.
        assert_eq!(
            installation_lifecycle("installation", &ev("new_permissions_accepted")),
            None
        );
        assert_eq!(installation_lifecycle("pull_request", &ev("created")), None);
        // A lifecycle payload with no installation id is ignored politely.
        assert_eq!(
            installation_lifecycle("installation", &json!({"action": "created"})),
            None
        );
    }

    #[test]
    fn check_conclusion_maps_run_status() {
        assert_eq!(check_conclusion("completed"), "success");
        assert_eq!(check_conclusion("cancelled"), "cancelled");
        assert_eq!(check_conclusion("failed"), "failure");
        assert_eq!(check_conclusion("budget_exceeded"), "failure");
    }

    #[test]
    fn sample_context_renders_default_event_templates() {
        // Config-time validation depends on this: every key normalize emits
        // must exist in the sample, so a template that renders at create
        // time also renders for real events.
        let sample = sample_context();
        let real = normalize("pull_request", &pr_payload("opened", 7, 7), &ctx())
            .unwrap()
            .unwrap();
        for key in real.context.keys() {
            assert!(sample.contains_key(key), "sample_context missing '{key}'");
        }
        let rendered = crate::triggers::render_task_template(
            "Review {{repository}}#{{pr_number}} at {{head_sha}} by {{pr_author}}",
            &sample,
        )
        .unwrap();
        assert!(rendered.contains("acme/site#1"));
    }
}
