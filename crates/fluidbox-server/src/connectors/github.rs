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
        // Event-derived workspace; create_run resolves its binding (Task 5).
        binding_id: None,
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
                // create_run resolves the result_publish binding (Task 5).
                binding_id: None,
            },
        ),
        (
            "check".to_string(),
            ResultDestination::GitHubCheck {
                connection_id: ctx.connection_id,
                repository: repository.clone(),
                head_sha: head_sha.clone(),
                // create_run resolves the result_publish binding (Task 5).
                binding_id: None,
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
    // Tenant known (the connection's own) → scoped_tx so the RLS GUC rides the
    // executor-generic sealed-credential read.
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
    sealer
        .open(
            &sealed,
            kv,
            crate::seal::SealCtx::new(
                conn.tenant_id,
                crate::seal::SealFamily::ConnectionCredential,
            ),
        )
        .await
        .map_err(|e| e.to_string())
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
    // cached token) — re-read status from the database first. Tenant known →
    // scoped_tx so the RLS GUC rides the executor-generic read.
    let mut conn_tx = fluidbox_db::scoped_tx(&state.pool, scope)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?;
    let conn = fluidbox_db::get_connection(&mut *conn_tx, scope, conn.id)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?
        .ok_or("connection is gone")?;
    conn_tx
        .commit()
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?;
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
    // Cache key carries the generation (design :783-789). github_app custody
    // never bumps its generation — the installation id is a positively proven
    // stable identity — so this is effectively `(conn.id, 1)`, but keyed off the
    // row's field so it stays uniform with the OAuth path.
    let cache_key = (conn.id, conn.authorization_generation);
    {
        let cache = state.connector_tokens.lock().await;
        if let Some((token, expires_at)) = cache.get(&cache_key) {
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
            let (sealed, kv) =
                fluidbox_db::github_app_registration_pem_sealed(&state.pool, scope, reg.id)
                    .await
                    .map_err(|e| format!("registration key lookup failed: {e}"))?
                    .ok_or("github app registration key unavailable — recreate the app")?;
            let app_id = reg
                .app_id
                .clone()
                .ok_or("github app registration is incomplete")?;
            (
                app_id,
                sealer
                    .open(
                        &sealed,
                        kv,
                        crate::seal::SealCtx::new(
                            reg.tenant_id,
                            crate::seal::SealFamily::GithubAppPem,
                        ),
                    )
                    .await
                    .map_err(|e| e.to_string())?,
            )
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
        .insert(cache_key, (token.clone(), expires_at));
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
            ..
        } => publish_pr_comment(state, *connection_id, repository, *pr_number, ctx).await,
        ResultDestination::GitHubCheck {
            connection_id,
            repository,
            head_sha,
            ..
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
    let mut conn_tx = fluidbox_db::scoped_tx(&state.pool, scope)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?;
    let conn = fluidbox_db::get_connection(&mut *conn_tx, scope, connection_id)
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?
        .ok_or("destination connection is missing")?;
    conn_tx
        .commit()
        .await
        .map_err(|e| format!("connection lookup failed: {e}"))?;
    if conn.provider != "github_app" {
        return Err("publishing requires a github_app connection (§17 #1: App identity)".into());
    }
    Ok(conn)
}

fn short_sha(sha: Option<&str>) -> String {
    sha.map(|s| s.chars().take(12).collect())
        .unwrap_or_else(|| "-".into())
}

/// The DETERMINISTIC marker every published comment carries (Phase E, #33; Gap
/// 13; design :1082-1084). An HTML comment, so GitHub renders nothing, keyed on
/// the subscription — which is exactly the identity §17 #3 makes stable ("one
/// comment per (subscription, PR), updated in place").
///
/// It exists to close the create-path crash window: the external POST necessarily
/// precedes the `external_results` row that records its id, so a crash in between
/// used to leave the retry with no record and produce a DUPLICATE comment. There
/// is no distributed transaction to be had here, so the fix is reconciliation —
/// before creating, look for this marker among the PR's comments and ADOPT the
/// match instead. GitHub's issue-comment API offers no idempotency key, which is
/// the alternative the design names.
pub(crate) fn subscription_marker(subscription_id: uuid::Uuid) -> String {
    format!("<!-- fluidbox:sub:{subscription_id} -->")
}

/// Find a previously-created comment of OURS in a PR comment listing — the
/// reconcile half of reconcile-before-create. Returns `(external_id, html_url)`.
///
/// Pure and total: a malformed/partial listing (not an array, missing `id`, a
/// non-string `body`) yields `None`, which degrades to today's behavior (create a
/// fresh comment) rather than to an error.
///
/// WHAT ACTUALLY MAKES THIS SAFE (corrected — the first cut claimed the marker
/// "contains no user text, so it cannot be spoofed", which is false). The marker
/// carries no user text, but the BODY WE SEARCH DOES: [`comment_body`] embeds
/// `summary` (raw agent output) and `subscription_name` (user text). An agent that
/// writes another subscription's marker literal into its summary therefore plants
/// that marker in a comment we ourselves post, and the victim subscription would
/// adopt-and-PATCH it. Two things stop that:
///   1. **The subscription id is an unguessable UUIDv7.** This is the real
///      defense, and it is the only one that would survive on its own: the marker
///      is `<!-- fluidbox:sub:{uuid} -->`, so spoofing requires knowing the target
///      subscription's id — which no agent is ever told (it is not in the RunSpec's
///      task, not in the workspace, and not in the comment we publish).
///   2. **Position the agent cannot reach.** [`comment_body`] appends the marker
///      LAST, after the footer, so a genuine marker is always the final
///      non-whitespace token of the body; agent text is always ABOVE the footer.
///      Requiring the trailing position (below) therefore rejects an injected
///      marker structurally, without depending on (1) — the belt to that brace.
///
/// RESIDUAL, precisely. A trailing-position match still trusts that the comment
/// was authored by us. Anyone able to comment on the PR could post a comment whose
/// body ENDS with our marker and have the next reconcile adopt (and overwrite)
/// theirs — but that again needs the unguessable subscription id, and the payoff
/// is that we edit their comment into our own report. An author-identity check
/// (`performed_via_github_app` / the bot login) was considered and NOT added: it
/// does not close the vector this review found, because in that vector the
/// polluted comment IS authored by our App, and it would trade a real duplicate-
/// comment risk (adoption failing whenever GitHub omits the field) for coverage of
/// the weaker case only. If it is ever added, it must be IN ADDITION to the
/// positional check, never instead of it.
fn find_marker_comment(listing: &Value, marker: &str) -> Option<(String, String)> {
    listing.as_array()?.iter().find_map(|c| {
        let body = c.get("body").and_then(|b| b.as_str())?;
        // Trailing position only — `contains` would adopt a marker planted in the
        // agent-controlled summary. `trim_end` tolerates the trailing newline we
        // write and any whitespace GitHub normalizes onto the end.
        if !body.trim_end().ends_with(marker) {
            return None;
        }
        let id = c.get("id").and_then(|i| i.as_i64())?.to_string();
        let url = c
            .get("html_url")
            .and_then(|u| u.as_str())
            .unwrap_or_default()
            .to_string();
        Some((id, url))
    })
}

/// The attributable comment body: agent name up top, run identity in the
/// footer, and (Phase E) the deterministic per-subscription reconcile marker.
/// One agent's failure appears only here, on its own comment.
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
    // The marker is appended LAST and only when a subscription identifies the
    // comment (a subscription-less publish has nothing stable to reconcile
    // against, and `publish_pr_comment` already refuses it upstream).
    let marker = match ctx.subscription_id {
        Some(id) => format!("\n{}\n", subscription_marker(id)),
        None => String::new(),
    };
    format!(
        "### 🤖 {agent} review\n{status_note}\n{body}\n\n---\n_fluidbox · trigger **{sub}** · run `{run}` · commit `{sha}`_\n{marker}",
        agent = ctx.agent_name,
        status_note = status_note,
        body = body,
        sub = ctx.subscription_name,
        run = ctx.session_id,
        sha = short_sha(ctx.commit_sha.as_deref()),
        marker = marker,
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
    let recorded = fluidbox_db::get_external_result(
        &state.pool,
        ctx.scope,
        sub_id,
        "github_pr_comment",
        &resource_key,
    )
    .await
    .map_err(|e| format!("external result lookup failed: {e}"))?
    .map(|r| (r.external_id, r.external_url));

    // RECONCILE BEFORE CREATE (Phase E, #33; Gap 13; design :1082-1084). No
    // recorded id does NOT prove no comment exists: the POST necessarily precedes
    // the row that records it, so a crash (or a lost delivery claim) in that
    // window leaves a real comment with no local record — and the retry would
    // post a DUPLICATE. Before creating, list the PR's comments and adopt a
    // marker match.
    //
    // A LISTING ERROR FAILS THE ATTEMPT (#33 review 2). It used to warn and fall
    // through to the create, which quietly reinstated the duplicate this exists to
    // prevent: a transient list timeout on a RETRY is indistinguishable from "no
    // comment exists", and treating it as proof-of-absence posts a second comment.
    // Only `Ok(None)` — a completed walk that found nothing — is proof. Delivery
    // is at-least-once with backoff, so failing here costs a delayed comment and
    // buys never posting two; a duplicate is the worse outcome and it is not
    // repairable afterwards.
    let existing = match recorded {
        Some(r) => Some(r),
        None => reconcile_existing_comment(state, &auth, repository, pr_number, sub_id)
            .await
            .map_err(|e| {
                format!(
                    "pr comment reconcile for {repository}#{pr_number} failed ({e}); \
                     refusing to create — a retry will re-reconcile"
                )
            })?,
    };

    if let Some((external_id, external_url)) = existing {
        let (status, body, _) = api(
            state,
            reqwest::Method::PATCH,
            &auth,
            &format!("/repos/{repository}/issues/comments/{external_id}"),
            Some(&payload),
        )
        .await?;
        if status.is_success() {
            let url = body["html_url"]
                .as_str()
                .map(str::to_string)
                .or(external_url)
                .unwrap_or_default();
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

/// Comment pages walked while reconciling. 100 per page × 10 = 1000 comments,
/// far past any real review thread; the cap keeps a pathological PR from turning
/// one delivery attempt into an unbounded crawl.
const RECONCILE_MAX_PAGES: u32 = 10;

/// Worst-case wall clock ONE GitHub publish attempt can occupy, in seconds — the
/// number the delivery worker's claim TTL must clear (review I2). Every GitHub
/// call this path makes is capped by [`GITHUB_TIMEOUT`], and the longest path is
/// `publish_pr_comment`:
///
/// | leg                                              | calls |
/// |--------------------------------------------------|-------|
/// | `installation_token` mint (cache miss)            | 1     |
/// | `reconcile_existing_comment` pages                | `RECONCILE_MAX_PAGES` |
/// | PATCH an adopted comment that 404s, then POST     | 2     |
///
/// The CHECK path has the same shape but a smaller cap
/// (`RECONCILE_CHECK_MAX_PAGES`, and its listing is name-filtered), so it stays
/// strictly under this bound and does not move the number.
///
/// Lives here, next to the constants it derives from, so raising the page cap or
/// the timeout moves this number — and fails `deliveries`' TTL assertion — without
/// anyone having to remember the coupling. DB round trips are excluded; the TTL
/// carries explicit headroom for them.
pub(crate) const fn worst_case_publish_secs() -> i64 {
    GITHUB_TIMEOUT.as_secs() as i64 * (1 + RECONCILE_MAX_PAGES as i64 + 2)
}

/// Look for a comment WE created on this PR by its deterministic marker — the
/// reconcile half of reconcile-before-create. `Ok(None)` means "walked the whole
/// thread, ours is genuinely not there" (create is correct); `Err` means we could
/// not tell, and the caller degrades to create rather than failing the delivery.
async fn reconcile_existing_comment(
    state: &AppState,
    auth: &str,
    repository: &str,
    pr_number: i64,
    subscription_id: uuid::Uuid,
) -> Result<Option<(String, Option<String>)>, String> {
    let marker = subscription_marker(subscription_id);
    for page in 1..=RECONCILE_MAX_PAGES {
        let (status, body, _) = api(
            state,
            reqwest::Method::GET,
            auth,
            &format!("/repos/{repository}/issues/{pr_number}/comments?per_page=100&page={page}"),
            None,
        )
        .await?;
        if !status.is_success() {
            return Err(format!("github comment list returned {status}"));
        }
        if let Some((id, url)) = find_marker_comment(&body, &marker) {
            return Ok(Some((id, Some(url).filter(|u| !u.is_empty()))));
        }
        // Short page (or not an array) ⇒ the listing is exhausted.
        if body.as_array().map(|a| a.len()).unwrap_or(0) < 100 {
            break;
        }
    }
    Ok(None)
}

/// The app-controlled identity stamped on every check run we create, and the key
/// [`reconcile_existing_check`] adopts on. GitHub's check-run API gives apps an
/// `external_id` field verbatim, which is a far better handle than the display
/// name: the name is `fluidbox/<subscription_name>` (USER text — two orgs could
/// collide, and any other app may publish a check with the same name), while this
/// carries the subscription's unguessable UUIDv7. Same defense as the comment
/// marker, on a field no agent output can reach.
pub(crate) fn check_external_id(subscription_id: uuid::Uuid) -> String {
    format!("fluidbox:sub:{subscription_id}")
}

/// Check runs walked while reconciling one head SHA. GitHub returns at most 100
/// per page and the listing is already filtered to OUR check name, so one page is
/// generous; the cap exists for the same reason the comment one does.
const RECONCILE_CHECK_MAX_PAGES: u32 = 3;

/// Find the check run WE already created for this head SHA, by `external_id`.
/// `Ok(None)` means the (name-filtered) listing was walked to the end and ours is
/// genuinely absent — the only state in which creating is correct. `Err` means we
/// could not tell, and the caller must NOT create.
async fn reconcile_existing_check(
    state: &AppState,
    auth: &str,
    repository: &str,
    head_sha: &str,
    name: &str,
    subscription_id: uuid::Uuid,
) -> Result<Option<String>, String> {
    let want = check_external_id(subscription_id);
    for page in 1..=RECONCILE_CHECK_MAX_PAGES {
        // `name` is `fluidbox/<subscription_name>` — USER text, so it is
        // percent-encoded rather than interpolated. `Url::parse_with_params`
        // against a throwaway base is the encoder already in the tree (no new
        // dependency); only its query string is used.
        let query = reqwest::Url::parse_with_params(
            "https://github.invalid/",
            &[
                ("check_name", name),
                ("per_page", "100"),
                ("page", &page.to_string()),
            ],
        )
        .map_err(|e| format!("check list url build failed: {e}"))?;
        let (status, body, _) = api(
            state,
            reqwest::Method::GET,
            auth,
            &format!(
                "/repos/{repository}/commits/{head_sha}/check-runs?{}",
                query.query().unwrap_or_default()
            ),
            None,
        )
        .await?;
        if !status.is_success() {
            return Err(format!("github check list returned {status}"));
        }
        let runs = body["check_runs"].as_array().cloned().unwrap_or_default();
        if let Some(id) = find_marker_check(&runs, &want) {
            return Ok(Some(id));
        }
        if runs.len() < 100 {
            break;
        }
    }
    Ok(None)
}

/// Pure adoption rule for a `check_runs` page: our `external_id`, and an id we can
/// actually address. Extracted so the matching is unit-testable without GitHub.
fn find_marker_check(runs: &[Value], want: &str) -> Option<String> {
    runs.iter()
        .find(|r| r["external_id"].as_str() == Some(want))
        .and_then(|r| r["id"].as_i64())
        .map(|id| id.to_string())
}

async fn publish_check(
    state: &AppState,
    connection_id: uuid::Uuid,
    repository: &str,
    head_sha: &str,
    ctx: &super::PublishContext,
) -> Result<super::PublishOutcome, String> {
    // Same requirement as the comment path, and for the same reason: §17 #3's
    // contract is ONE check per (subscription, head SHA), so without a
    // subscription there is no identity to reconcile against and every retry
    // would create another check run.
    let sub_id = ctx
        .subscription_id
        .ok_or("check publishing requires a subscription (stable identity is per subscription)")?;
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
        "external_id": check_external_id(sub_id),
        "status": "completed",
        "conclusion": check_conclusion(&ctx.status),
        "completed_at": Utc::now().to_rfc3339(),
        "output": {
            "title": format!("{}: {}", ctx.agent_name, ctx.status),
            "summary": summary,
        },
    });
    let digest = format!("sha256:{}", fluidbox_db::sha256_hex(&payload.to_string()));
    let auth = format!("Bearer {token}");
    let resource_key = format!("{repository}@{head_sha}");

    // RECONCILE BEFORE CREATE — the same treatment the comment path gets (#33
    // review 2). Checks used to POST unconditionally with no idempotency key and
    // no adoption, so a crash after GitHub accepted the create (or any retry of a
    // delivery whose recording leg failed) added ANOTHER check run to the same
    // commit. They reconcile exactly as well as comments do: `external_id` is an
    // app-controlled field GitHub returns verbatim, and check runs are listable
    // per commit filtered by name, so `(head_sha, name, external_id)` is a
    // complete, deterministic identity. An UPDATE is a PATCH to the run's id, and
    // a completed run may be re-completed, so re-publishing is an in-place edit.
    //
    // A listing error FAILS the attempt, never falls through to create.
    let recorded = fluidbox_db::get_external_result(
        &state.pool,
        ctx.scope,
        sub_id,
        "github_check_run",
        &resource_key,
    )
    .await
    .map_err(|e| format!("external result lookup failed: {e}"))?
    .map(|r| r.external_id);
    let existing = match recorded {
        Some(id) => Some(id),
        None => reconcile_existing_check(state, &auth, repository, head_sha, &name, sub_id)
            .await
            .map_err(|e| {
                format!(
                    "check reconcile for {repository}@{head_sha} failed ({e}); \
                     refusing to create — a retry will re-reconcile"
                )
            })?,
    };

    let mut url: Option<String> = None;
    let mut external_id: Option<String> = None;
    if let Some(id) = existing {
        let (status, body, _) = api(
            state,
            reqwest::Method::PATCH,
            &auth,
            &format!("/repos/{repository}/check-runs/{id}"),
            Some(&payload),
        )
        .await?;
        if status.is_success() {
            url = Some(body["html_url"].as_str().unwrap_or("").to_string());
            external_id = Some(id);
        } else if status != reqwest::StatusCode::NOT_FOUND && status != reqwest::StatusCode::GONE {
            return Err(format!("github check update returned {status}"));
        }
        // 404/410 ⇒ deleted out from under us; fall through and create a fresh one.
    }

    if external_id.is_none() {
        let (status, body, _) = api(
            state,
            reqwest::Method::POST,
            &auth,
            &format!("/repos/{repository}/check-runs"),
            Some(&payload),
        )
        .await?;
        if !status.is_success() {
            return Err(format!("github check create returned {status}"));
        }
        url = Some(body["html_url"].as_str().unwrap_or("").to_string());
        // A create whose id we cannot read is still a real check run, so it MUST
        // NOT be recorded as absent — but it is reconcilable on the next attempt
        // via `external_id`, which is why that is the load-bearing handle here.
        external_id = body["id"].as_i64().map(|i| i.to_string());
    }

    // Record LAST: this row is only the fast path. The POST necessarily precedes
    // it, so a crash in between is exactly the window `reconcile_existing_check`
    // closes — the row is an optimization, not the source of truth.
    if let Some(id) = &external_id {
        fluidbox_db::upsert_external_result(
            &state.pool,
            ctx.scope,
            sub_id,
            "github_check_run",
            &resource_key,
            id,
            url.as_deref(),
        )
        .await
        .map_err(|e| format!("external result record failed: {e}"))?;
    }
    Ok(super::PublishOutcome {
        external_url: url.unwrap_or_default(),
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

    /// #33 review 2, the checks half. Checks used to POST unconditionally with no
    /// idempotency key at all, so a crash after GitHub accepted the create added a
    /// SECOND check run to the same commit on every retry. Adoption keys on the
    /// app-controlled `external_id`, never on the display name (user text, and any
    /// app may publish a check with the same one).
    #[test]
    fn a_check_run_is_adopted_by_its_external_id_and_nothing_else() {
        let sub = Uuid::now_v7();
        let other = Uuid::now_v7();
        let want = check_external_id(sub);
        assert!(
            want.contains(&sub.to_string()),
            "the identity carries the unguessable subscription id"
        );

        let ours = json!({"id": 77, "name": "fluidbox/x", "external_id": want.clone()});
        assert_eq!(
            find_marker_check(std::slice::from_ref(&ours), &want),
            Some("77".into())
        );

        // Another subscription's check on the same commit is NOT ours.
        let theirs = json!({"id": 78, "name": "fluidbox/x",
                            "external_id": check_external_id(other)});
        assert_eq!(
            find_marker_check(std::slice::from_ref(&theirs), &want),
            None
        );
        assert_eq!(
            find_marker_check(&[theirs, ours], &want),
            Some("77".into()),
            "ours is picked out of a mixed page"
        );

        // A same-NAMED check from another app carries no external_id of ours —
        // adopting it would PATCH someone else's check run.
        assert_eq!(
            find_marker_check(&[json!({"id": 79, "name": "fluidbox/x"})], &want),
            None
        );
        // No usable id ⇒ not adoptable (we could not address it anyway).
        assert_eq!(
            find_marker_check(&[json!({"external_id": want.clone()})], &want),
            None
        );
        assert_eq!(find_marker_check(&[], &want), None);
    }

    /// A reconciliation ERROR must never be read as proof-of-absence (#33 review
    /// 2). Both publish paths route the `Err` arm into `?` — no `unwrap_or`, no
    /// `None` fallback, no warn-and-continue — because a transient list timeout on
    /// a RETRY is indistinguishable from "nothing is there", and guessing wrong
    /// posts a duplicate that cannot be repaired afterwards. Asserted against the
    /// source because the failure needs a flaky GitHub to reproduce; needles are
    /// split so this test is not its own evidence.
    #[test]
    fn a_reconcile_error_never_falls_through_to_create() {
        let src = include_str!("github.rs");
        for (open, close, what) in [
            (
                concat!("async fn publish_pr_", "comment("),
                concat!("issues/{pr_number}/", "comments\""),
                "comment",
            ),
            (
                concat!("async fn publish_", "check("),
                concat!("reqwest::Method::", "POST,"),
                "check",
            ),
        ] {
            let start = src.find(open).expect("the publish fn exists");
            let end = src[start..]
                .find(close)
                .map(|i| start + i)
                .expect("its create call follows");
            let slice = &src[start..end];
            assert!(
                slice.contains(concat!("refusing to ", "create")),
                "the {what} path must FAIL the attempt when reconciliation errors"
            );
            for banned in [
                concat!("Ok(found) =", "> found"),
                concat!("tracing::", "warn!"),
            ] {
                assert!(
                    !slice.contains(banned),
                    "the {what} path swallows a reconcile error (`{banned}`) and \
                     falls through to create — that is the duplicate this closes"
                );
            }
        }
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
            ..
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

    /// Reconcile-before-create (Phase E, #33; Gap 13): the published body carries
    /// the deterministic per-subscription marker, and the reconciler finds OUR
    /// comment by it in a recorded GitHub listing — which is what stops a crash
    /// between the POST and the `external_results` write from producing a
    /// duplicate comment on retry.
    #[test]
    fn comment_marker_round_trips_through_a_recorded_listing() {
        let sub = Uuid::now_v7();
        let other_sub = Uuid::now_v7();
        let ctx = super::super::PublishContext {
            scope: fluidbox_db::TenantScope::assume(Uuid::now_v7()),
            session_id: Uuid::now_v7(),
            subscription_id: Some(sub),
            subscription_name: "security-review".into(),
            agent_name: "sec-agent".into(),
            status: "completed".into(),
            summary: Some("ok".into()),
            commit_sha: None,
        };
        let body = comment_body(&ctx);
        let marker = subscription_marker(sub);
        assert!(
            body.contains(&marker),
            "every published body carries its marker"
        );
        assert!(marker.starts_with("<!--"), "the marker renders as nothing");

        // A recorded GitHub `GET /issues/{n}/comments` page: a human comment, a
        // DIFFERENT subscription's fluidbox comment, then ours.
        let listing = json!([
            {"id": 1, "html_url": "https://github.test/c/1", "body": "LGTM"},
            {"id": 2, "html_url": "https://github.test/c/2",
             "body": format!("### 🤖 other review\n{}", subscription_marker(other_sub))},
            {"id": 3, "html_url": "https://github.test/c/3", "body": body},
        ]);
        assert_eq!(
            find_marker_comment(&listing, &marker),
            Some(("3".into(), "https://github.test/c/3".into())),
            "adopt OUR comment, never another subscription's"
        );
        // Nothing of ours on the PR ⇒ None ⇒ the caller creates (today's path).
        assert_eq!(
            find_marker_comment(&listing, &subscription_marker(Uuid::now_v7())),
            None
        );

        // Total on malformed input: never panics, never adopts a stranger.
        assert_eq!(
            find_marker_comment(&json!({"message": "Not Found"}), &marker),
            None
        );
        assert_eq!(find_marker_comment(&json!([]), &marker), None);
        assert_eq!(
            find_marker_comment(&json!([{"body": marker.clone()}]), &marker),
            None,
            "a comment with no usable id is not adoptable"
        );
        assert_eq!(
            find_marker_comment(&json!([{"id": 9, "body": marker.clone()}]), &marker),
            Some(("9".into(), String::new())),
            "a missing html_url still adopts (the id is what prevents the duplicate)"
        );

        // A subscription-less publish has no stable identity to reconcile
        // against — no marker is emitted (and publish_pr_comment refuses it).
        let anon = super::super::PublishContext {
            subscription_id: None,
            ..ctx
        };
        assert!(!comment_body(&anon).contains("<!-- fluidbox:sub:"));
    }

    /// The searched BODY carries agent output (`summary`) and user text
    /// (`subscription_name`), so "the marker contains no user text" never made
    /// adoption unspoofable. Adoption is restricted to a marker in the TRAILING
    /// position — which `comment_body` puts below the footer, out of the agent's
    /// reach — so a marker planted mid-body is not adopted (review Minor B).
    #[test]
    fn an_agent_planted_marker_is_not_adopted() {
        let victim = Uuid::now_v7();
        let attacker = Uuid::now_v7();
        let victim_marker = subscription_marker(victim);

        // The attacker's run emits the VICTIM's marker inside its summary; we
        // publish that text ourselves, so the body genuinely contains it — above
        // our own footer and our own trailing marker.
        let planted = super::super::PublishContext {
            scope: fluidbox_db::TenantScope::assume(Uuid::now_v7()),
            session_id: Uuid::now_v7(),
            subscription_id: Some(attacker),
            subscription_name: "attacker".into(),
            agent_name: "agent".into(),
            status: "completed".into(),
            summary: Some(format!("here is my report {victim_marker}")),
            commit_sha: None,
        };
        let body = comment_body(&planted);
        assert!(
            body.contains(&victim_marker),
            "the planted marker really is in the body — otherwise this test proves nothing"
        );
        let listing = json!([{"id": 42, "html_url": "https://github.test/c/42", "body": body}]);
        assert_eq!(
            find_marker_comment(&listing, &victim_marker),
            None,
            "a marker in agent-controlled text must NOT be adopted — the victim \
             subscription would PATCH another subscription's comment"
        );
        // The attacker's OWN trailing marker still adopts: the check is positional,
        // not a blanket refusal of bodies that mention a marker.
        assert_eq!(
            find_marker_comment(&listing, &subscription_marker(attacker)),
            Some(("42".into(), "https://github.test/c/42".into())),
            "our own trailing marker still reconciles"
        );
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
