use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method};
use chrono::{DateTime, Utc};
use fluidbox_db::TenantScope;
use uuid::Uuid;

/// The `__Host-fbx_web` browser-session cookie (design lines 326-331). `__Host-`
/// prefix is a browser-enforced integrity guarantee (Secure, Path=/, no Domain).
const WEB_COOKIE: &str = "__Host-fbx_web";

/// Custom header a cookie-authenticated write must carry. A cross-site
/// `<form>` / simple request cannot set a custom request header, so its
/// presence proves the request originated from our first-party JavaScript.
const CSRF_HEADER: &str = "x-fluidbox-csrf";

fn bearer(parts: &Parts) -> Option<String> {
    bearer_from_headers(&parts.headers)
}

/// Extract a `Bearer <token>` from a header map. Public so handlers that
/// need a non-standard auth path (e.g. /result acknowledging an
/// already-terminal session with a revoked token) can resolve it themselves.
pub fn bearer_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}

/// Every value of the `__Host-fbx_web` cookie present across all `Cookie`
/// headers. Zero values ⇒ no cookie; more than one ⇒ ambiguous (the caller
/// refuses). A pure function of the headers so it is unit-testable.
fn web_cookie_values(headers: &HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    for hv in headers.get_all(axum::http::header::COOKIE) {
        let Ok(s) = hv.to_str() else { continue };
        for pair in s.split(';') {
            if let Some((name, value)) = pair.split_once('=') {
                if name.trim() == WEB_COOKIE {
                    out.push(value.trim().to_string());
                }
            }
        }
    }
    out
}

/// Same web origin (scheme + host + port)? Parsed comparison — string prefixes
/// lie (`https://app.example.com.evil.tld`), parsed origins do not.
fn same_web_origin(a: &str, b: &str) -> bool {
    match (reqwest::Url::parse(a), reqwest::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            a.scheme() == b.scheme()
                && a.host_str() == b.host_str()
                && a.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

/// CSRF decision for a **cookie-authenticated** (`BrowserSession`) request.
/// Bearer principals never reach here — they are exempt (design lines 644-656:
/// a bearer credential is not ambient and a CLI has no `Origin`; the argument
/// holds only because Task 5 removes the current `CorsLayer::permissive()`).
///
/// Rules, stated precisely:
///  - Safe methods (`GET`/`HEAD`/`OPTIONS`) are read-only → no CSRF requirement.
///  - Non-safe methods MUST carry `x-fluidbox-csrf: 1`. A cross-site form or
///    simple request cannot set a custom header, so its presence is the proof.
///  - If an `Origin` header is present it MUST match `public_url`'s origin
///    (cross-origin ⇒ 403). A **missing** `Origin` is accepted — the custom
///    header already defeats the vectors that cannot send one; the `Origin`
///    check is defense in depth for browsers that do send it.
fn csrf_decision(method: &Method, headers: &HeaderMap, public_url: &str) -> Result<(), ApiError> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(());
    }
    let csrf_ok = headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    if !csrf_ok {
        return Err(ApiError::Forbidden(
            "a cookie-authenticated write requires the x-fluidbox-csrf header".into(),
        ));
    }
    if let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        if !same_web_origin(origin, public_url) {
            return Err(ApiError::Forbidden("cross-origin request refused".into()));
        }
    }
    Ok(())
}

/// Operator break-glass credential: gates `/v1/admin/*`, and — outside
/// `require_sso` — resolves to the Operator principal on the data plane. Under
/// `FLUIDBOX_REQUIRE_SSO` this is the ONLY extractor the admin token still
/// satisfies (`Principal` refuses it there), which confines the operator to
/// `/v1/admin/*`.
pub struct Admin;

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or(ApiError::Unauthorized)?;
        // Dual-credential rejection applies to the operator surface too: a
        // request bearing BOTH a session cookie and a bearer is refused rather
        // than resolved by precedence (design lines 599-601).
        if !web_cookie_values(&parts.headers).is_empty() {
            return Err(ApiError::BadRequest(
                "present a session cookie or an Authorization bearer, not both".into(),
            ));
        }
        // Constant-time-ish compare via sha256 of both sides.
        let expected = fluidbox_db::sha256_hex(&state.cfg.admin_token);
        let got = fluidbox_db::sha256_hex(&token);
        if got == expected {
            Ok(Admin)
        } else {
            Err(ApiError::Unauthorized)
        }
    }
}

/// The authenticated identity behind a `/v1` data-plane request. A closed set:
/// the operator token (over the boot tenant, today's semantics) or a verified
/// user membership (browser session or PAT). The browser never supplies a
/// tenant/user; a principal's tenant derives solely from the verified
/// credential (invariant 5).
pub enum Principal {
    Operator { scope: TenantScope },
    User(UserPrincipal),
}

pub struct UserPrincipal {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub membership_id: Uuid,
    pub roles: Vec<String>,
    pub auth: AuthContext,
}

/// A closed enum — a PAT principal has no browser session and never pretends to
/// (design lines 617-623). `authentication_strength` is DERIVED from this, and
/// a `Pat` context never satisfies a step-up requirement. The inner fields are
/// carried now and consumed by Task 5 (the assurance derivation and audit
/// stamping), so they read as dead here.
#[allow(dead_code)]
pub enum AuthContext {
    BrowserSession {
        session_id: Uuid,
        idp_config_id: Uuid,
        acr: Option<String>,
        amr: Vec<String>,
        auth_time: Option<DateTime<Utc>>,
    },
    Pat {
        token_id: Uuid,
    },
}

impl Principal {
    pub fn scope(&self) -> TenantScope {
        match self {
            Principal::Operator { scope } => *scope,
            Principal::User(u) => TenantScope::assume(u.tenant_id),
        }
    }

    /// The authenticated user id, when one exists. `None` for the operator
    /// (it has no membership) — run creation stamps this onto the session.
    pub fn user_id(&self) -> Option<Uuid> {
        match self {
            Principal::Operator { .. } => None,
            Principal::User(u) => Some(u.user_id),
        }
    }

    /// Membership roles. The operator holds no membership, so it has no roles —
    /// its authority is expressed by [`Principal::is_operator`], not a role.
    pub fn roles(&self) -> &[String] {
        match self {
            Principal::Operator { .. } => &[],
            Principal::User(u) => &u.roles,
        }
    }

    pub fn is_operator(&self) -> bool {
        matches!(self, Principal::Operator { .. })
    }

    /// The value stamped as `decided_by` on an approval / audit row. Never
    /// request-supplied — derived from the authenticated principal.
    pub fn decided_by(&self) -> String {
        match self {
            Principal::Operator { .. } => "operator".to_string(),
            Principal::User(u) => u.user_id.to_string(),
        }
    }
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let bearer = bearer_from_headers(&parts.headers);
        let cookies = web_cookie_values(&parts.headers);
        // Dual-credential rejection (design lines 599-601 / invariant 5).
        if bearer.is_some() && !cookies.is_empty() {
            return Err(ApiError::BadRequest(
                "present a session cookie or an Authorization bearer, not both".into(),
            ));
        }
        if let Some(token) = bearer {
            return principal_from_bearer(state, &token).await;
        }
        match cookies.as_slice() {
            [] => Err(ApiError::Unauthorized),
            [token] => principal_from_cookie(&parts.method, &parts.headers, state, token).await,
            // The cookie name appears more than once: ambiguous → refuse.
            _ => Err(ApiError::Unauthorized),
        }
    }
}

async fn principal_from_bearer(state: &AppState, token: &str) -> Result<Principal, ApiError> {
    // Operator (admin) token.
    if fluidbox_db::sha256_hex(token) == fluidbox_db::sha256_hex(&state.cfg.admin_token) {
        if state.cfg.require_sso {
            // Confined to /v1/admin/* via the `Admin` extractor, which stays.
            return Err(ApiError::Unauthorized);
        }
        return Ok(Principal::Operator {
            scope: TenantScope::assume(state.tenant_id),
        });
    }
    // Personal access token (live-membership recheck on every use).
    if token.starts_with("fbx_pat_") {
        let auth = fluidbox_db::identity::resolve_pat(&state.pool, token)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        if auth.membership_status != "active"
            || auth.user_status != "active"
            || auth.tenant_status != "active"
        {
            return Err(ApiError::Unauthorized);
        }
        return Ok(Principal::User(UserPrincipal {
            tenant_id: auth.tenant_id,
            user_id: auth.user_id,
            membership_id: auth.membership_id,
            roles: auth.roles,
            auth: AuthContext::Pat {
                token_id: auth.token_id,
            },
        }));
    }
    Err(ApiError::Unauthorized)
}

async fn principal_from_cookie(
    method: &Method,
    headers: &HeaderMap,
    state: &AppState,
    token: &str,
) -> Result<Principal, ApiError> {
    // CSRF is enforced BEFORE the DB touch, so a rejected write never slides
    // the session's idle expiry.
    csrf_decision(method, headers, &state.cfg.public_url)?;
    let auth =
        fluidbox_db::identity::resolve_web_session(&state.pool, token, state.cfg.session_idle_secs)
            .await?
            .ok_or(ApiError::Unauthorized)?;
    // Refusal decisions live here (resolution does not filter on status), so
    // membership / user / tenant liveness is one fail-closed gate.
    if auth.membership_status != "active"
        || auth.user_status != "active"
        || auth.tenant_status != "active"
    {
        return Err(ApiError::Unauthorized);
    }
    Ok(Principal::User(UserPrincipal {
        tenant_id: auth.tenant_id,
        user_id: auth.user_id,
        membership_id: auth.membership_id,
        roles: auth.roles,
        auth: AuthContext::BrowserSession {
            session_id: auth.session_id,
            idp_config_id: auth.idp_config_id,
            acr: auth.acr,
            amr: auth.amr.unwrap_or_default(),
            auth_time: auth.auth_time,
        },
    }))
}

/// Scoped trigger-token authentication. The token's entire authority is its
/// subscription: it can invoke that subscription and poll the runs it
/// created — it can never satisfy `Admin` or `SessionAuth`. `scope` is the
/// subscription's owning tenant, resolved alongside the token (the "bootstrap
/// exception" — token resolution keys on the sha256, then hands back a verified
/// tenant), so trigger handlers scope every DB call to the real tenant rather
/// than `state.tenant_id`.
pub struct TriggerAuth {
    pub subscription_id: Uuid,
    pub scope: TenantScope,
}

impl FromRequestParts<AppState> for TriggerAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or(ApiError::Unauthorized)?;
        let auth = fluidbox_db::subscription_for_token(&state.pool, &token)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        Ok(TriggerAuth {
            subscription_id: auth.subscription_id,
            scope: TenantScope::assume(auth.tenant_id),
        })
    }
}

/// Per-session authentication for the internal gateway. Resolves the bearer
/// token to the session it belongs to (unexpired, unrevoked) AND its owning
/// tenant — `scope` is derived from the token's row, never `state.tenant_id`,
/// so every internal-plane DB call scopes to the runner's real tenant.
pub struct SessionAuth {
    pub session_id: Uuid,
    pub token: String,
    pub scope: TenantScope,
}

impl FromRequestParts<AppState> for SessionAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or(ApiError::Unauthorized)?;
        let auth = fluidbox_db::session_for_token(&state.pool, &token)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        Ok(SessionAuth {
            session_id: auth.session_id,
            token,
            scope: TenantScope::assume(auth.tenant_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderMap, HeaderValue, Method};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn cookie_parsing_counts_the_web_session_cookie() {
        // Absent.
        assert!(web_cookie_values(&headers(&[])).is_empty());
        // Present once, alongside other cookies.
        assert_eq!(
            web_cookie_values(&headers(&[("cookie", "a=1; __Host-fbx_web=secret; b=2")])),
            vec!["secret".to_string()]
        );
        // A prefix collision must NOT match (exact name only).
        assert!(web_cookie_values(&headers(&[("cookie", "__Host-fbx_web_other=x")])).is_empty());
        // Duplicated across two Cookie headers → two values → ambiguous.
        assert_eq!(
            web_cookie_values(&headers(&[
                ("cookie", "__Host-fbx_web=one"),
                ("cookie", "__Host-fbx_web=two"),
            ]))
            .len(),
            2
        );
        // Duplicated within a single Cookie header → two values.
        assert_eq!(
            web_cookie_values(&headers(&[(
                "cookie",
                "__Host-fbx_web=a; __Host-fbx_web=b"
            )]))
            .len(),
            2
        );
    }

    #[test]
    fn same_web_origin_compares_parsed_origins() {
        assert!(same_web_origin(
            "https://app.example.com",
            "https://app.example.com/"
        ));
        assert!(same_web_origin(
            "https://app.example.com:443",
            "https://app.example.com"
        ));
        assert!(!same_web_origin(
            "http://app.example.com",
            "https://app.example.com"
        ));
        assert!(!same_web_origin(
            "https://app.example.com.evil.tld",
            "https://app.example.com"
        ));
        assert!(!same_web_origin("null", "https://app.example.com"));
    }

    const PUB: &str = "https://app.example.com";

    #[test]
    fn csrf_allows_safe_methods_regardless_of_headers() {
        for m in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(csrf_decision(&m, &headers(&[]), PUB).is_ok());
        }
    }

    #[test]
    fn csrf_requires_the_header_on_writes() {
        // No CSRF header → refused.
        assert!(csrf_decision(&Method::POST, &headers(&[]), PUB).is_err());
        // Wrong value → refused.
        assert!(csrf_decision(&Method::POST, &headers(&[("x-fluidbox-csrf", "0")]), PUB).is_err());
        // Header present, no Origin → allowed.
        assert!(csrf_decision(&Method::POST, &headers(&[("x-fluidbox-csrf", "1")]), PUB).is_ok());
        // Header present, same-origin Origin → allowed.
        assert!(csrf_decision(
            &Method::DELETE,
            &headers(&[("x-fluidbox-csrf", "1"), ("origin", PUB)]),
            PUB,
        )
        .is_ok());
        // Header present, cross-origin Origin → refused.
        assert!(csrf_decision(
            &Method::POST,
            &headers(&[("x-fluidbox-csrf", "1"), ("origin", "https://evil.example")]),
            PUB,
        )
        .is_err());
    }
}
