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
    /// The exact api_tokens row id — frozen as a trigger run's invoking principal
    /// so the binding recheck can fail closed on a revoked/expired token (E1).
    pub token_id: Uuid,
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
        // Dual-credential rejection (design lines 599-600): a request bearing
        // BOTH a session cookie and a bearer is refused, never resolved by
        // precedence — the same rule the Principal/Admin extractors apply.
        if !web_cookie_values(&parts.headers).is_empty() {
            return Err(ApiError::BadRequest(
                "present a session cookie or an Authorization bearer, not both".into(),
            ));
        }
        let auth = fluidbox_db::subscription_for_token(&state.pool, &token)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        Ok(TriggerAuth {
            token_id: auth.token_id,
            subscription_id: auth.subscription_id,
            scope: TenantScope::assume(auth.tenant_id),
        })
    }
}

// ─── Audience names (Gap 10, invariant 19) ────────────────────────────────
//
// The audience a route requires is a NAMED constant, never a bare string
// literal at the call site. The literals are indistinguishable to the compiler
// and to every existing test — `events` asking for `"tool"` would build clean
// and pass the whole suite — so this removes that typo class, and nothing more.
//
// It does NOT prove the mapping is right. That each route demands the audience
// it SHOULD is proven route-by-route by the CI `hardening` job's negative
// matrix (`scripts/hardening-e2e.sh`, plan Task 9) — that suite is the
// authority on the mapping; these constants only make it hard to fat-finger.
//
// The values are the wire/DB vocabulary: migration 0020's CHECK constrains the
// `api_tokens.audience` column to exactly this set, so changing a value here
// without changing that CHECK breaks minting (pinned by a test below).

/// Tool intent: `/permission` and `/tools/call`.
pub const AUD_TOOL: &str = "tool";
/// Runner control: `/events`, `/heartbeat`, `/result`, `/token/renew`.
pub const AUD_CONTROL: &str = "control";
/// Model egress at the LLM facade.
pub const AUD_LLM: &str = "llm";
/// The workspace archive route — the init container's ONLY credential.
pub const AUD_WORKSPACE: &str = "workspace";
/// The pre-split legacy audience: the `api_tokens.audience` column DEFAULT, so
/// an in-flight session's single token (and the e2e forgers' rows) carry it.
pub const AUD_ALL: &str = "all";

/// True iff a token carrying `actual` audience may act on a route requiring
/// `required` (Gap 10, invariant 19). The legacy `'all'` audience — a pre-split
/// token minted before this deploy, or an e2e forger relying on the column
/// DEFAULT — satisfies EVERY route (in-flight compat); otherwise the audiences
/// must match exactly. Pure, so it is unit-tested without a DB.
pub fn audience_allows(required: &str, actual: &str) -> bool {
    actual == AUD_ALL || actual == required
}

// ─── Workload identity (Phase F, Gap 6) ────────────────────────────────────
//
// WHAT THIS BINDS. Phase E narrowed the sandbox's ONE bearer into four
// audience-scoped tokens, which bounds what a stolen credential can DO. It says
// nothing about WHO holds it: any process anywhere that can reach `:8788` and
// present the bytes is, to the control plane, the sandbox. The design has always
// required "workload identity or mTLS in addition to run bearer tokens" (design
// :1233-1240) and the threat model's T7 row says it outright. This binds a run's
// credentials to the network identity the control plane itself recorded for the
// workload it issued them to, so the same token presented from somewhere else is
// refusable.
//
// WHAT IT IS NOT. A source address is a NETWORK fact, not a cryptographic one. It
// is unforgeable only to the extent the network makes it so, and it identifies a
// LOCATION, not a process. mTLS is the strictly stronger control and is the
// disclosed follow-up; this is what can be built without a per-run PKI, a rustls
// listener, and a client-certificate path through two Node runner images.
//
// THE PEER IS THE SOCKET PEER. NEVER A HEADER. Not `X-Forwarded-For`, not
// `X-Real-IP`, not `Forwarded`, and NOT gated on `FLUIDBOX_TRUST_FORWARDED_FOR`
// (which exists for the PUBLIC plane, where the peer really can be a trusted
// reverse proxy). The reason is specific to this plane: the entity we are trying
// to identify is the entity sending the request. A sandbox can set any header it
// likes, so honouring one here would let the caller assert its own identity —
// a control that authenticates the attacker's claim about themselves is worse
// than no control, because it reads as protection in the threat model while
// providing none. If a proxy is ever interposed on `:8788`, this control must be
// redesigned (the proxy's own identity becomes the peer for every run), not
// patched by trusting a header.

/// The `SandboxHandle::attrs` key a provider reports workload addresses under.
/// This is a CONTRACT with the provider crates; a test below `include_str!`s the
/// Kubernetes provider and fails if the two sides ever disagree, so renaming one
/// alone cannot silently disable the binding.
pub const WORKLOAD_ADDR_ATTR: &str = "workload_addrs";

/// The refusal body code for a workload-identity mismatch.
///
/// DELIBERATELY NOT `wrong_audience`. `images/runner-lib/contract.mjs:51-61`
/// keys a FATAL process abort on that exact code (by body substring, not status),
/// with a diagnostic that says "this runner image predates the audience-scoped
/// credential split". Reusing it would make a workload mismatch abort the run
/// with a confidently wrong explanation. The substring `wrong_workload` does not
/// contain `wrong_audience`, so the runner's check cannot false-positive on it —
/// pinned by a test below.
///
/// WHAT THE RUNNER DOES WITH IT TODAY: nothing specific. It has no branch for this
/// code, so a 403 carrying it falls into the ordinary "the session is gone"
/// handling — `/permission` answers a hard `deny` logged as "session terminal",
/// token renew stops, heartbeats are swallowed until the watchdog terminalizes the
/// run, and the facade's 403 fails the model call (so spend does NOT continue past
/// the refusal). For a genuine replay from elsewhere that is the right outcome. For
/// a FALSE POSITIVE it is a correct-but-misdiagnosed death: the run ends and the
/// runner-side log blames session termination. Accepted for this phase because the
/// server-side warning names the real cause on every request and `observe` mode
/// exists to find false positives before anything is refused. Teaching runner-lib
/// this code (a named diagnostic, like `EXIT_AUDIENCE_MISMATCH`) is the follow-up;
/// a test below asserts the runner does not know it yet, so that stays a decision.
pub const WRONG_WORKLOAD_CODE: &str = "wrong_workload";

/// Pull the provider-reported workload addresses out of a persisted
/// [`SandboxHandle`]. Tolerant by design — a provider that reports nothing (the
/// Docker provider) and a provider that reports a list are both ordinary — but it
/// never invents: a non-array, or an array of non-strings, yields what it can and
/// nothing more.
pub fn workload_addrs_from_handle(handle: &fluidbox_core::traits::SandboxHandle) -> Vec<String> {
    handle
        .attrs
        .get(WORKLOAD_ADDR_ATTR)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The socket peer of a request, or `None` if the connect-info extension is
/// absent. Reads `parts.extensions` ONLY — see the header discussion above.
///
/// `main.rs` serves both planes with `into_make_service_with_connect_info::<SocketAddr>()`,
/// so `None` here is a WIRING DEFECT, not a deployment state. It is handled as
/// [`WorkloadVerdict::Unverifiable`] (fail-closed under `enforce`) rather than as
/// "no opinion", because a control that silently switches itself off when someone
/// refactors the service builder is the failure this whole module exists to avoid.
pub fn peer_addr(parts: &Parts) -> Option<std::net::SocketAddr> {
    parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0)
}

/// The socket peer, as a handler parameter. Infallible: a missing connect-info
/// extension yields `None` rather than a rejection, so the decision about what
/// absence MEANS is made in one place ([`workload_verdict`]) instead of by an
/// extractor rejection nobody would notice.
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub Option<std::net::SocketAddr>);

impl<S: Send + Sync> FromRequestParts<S> for PeerAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(PeerAddr(peer_addr(parts)))
    }
}

/// The outcome of checking one request's socket peer against the workload
/// identity recorded for its run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadVerdict {
    /// `FLUIDBOX_WORKLOAD_IDENTITY=off` — not evaluated at all.
    Disabled,
    /// No provider-asserted identity for this run: the Docker provider, a session
    /// provisioned before migration 0025, an adopted orphan, or a provider whose
    /// API did not report an address. ADMITTED, and counted. See the ruling below.
    Unbindable,
    /// The peer is one of the recorded addresses.
    Match,
    /// The peer is a valid address and is NOT one of the recorded addresses.
    Mismatch,
    /// An identity WAS recorded but this request cannot be judged against it:
    /// the connect-info extension is missing (a wiring defect), or every recorded
    /// address is unparseable (a provider defect). Treated as a mismatch under
    /// `enforce` — we know what this run's identity should be and cannot confirm
    /// it, which is the definition of failing closed.
    Unverifiable,
}

impl WorkloadVerdict {
    /// Stable label for logs and counters.
    pub fn as_str(self) -> &'static str {
        match self {
            WorkloadVerdict::Disabled => "disabled",
            WorkloadVerdict::Unbindable => "unbindable",
            WorkloadVerdict::Match => "match",
            WorkloadVerdict::Mismatch => "mismatch",
            WorkloadVerdict::Unverifiable => "unverifiable",
        }
    }
}

/// Normalize an address for comparison. An IPv4-mapped IPv6 peer
/// (`::ffff:10.4.2.9`, which is what a dual-stack listener reports for an IPv4
/// connection) and the IPv4 literal a provider records (`10.4.2.9`) are the SAME
/// host; comparing them as strings, or as un-normalized `IpAddr`s, would call that
/// a mismatch and take down every run on a dual-stack cluster.
fn canonical_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => std::net::IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Decide one request. PURE — no I/O, no clock, no counters — so the whole matrix
/// is unit-testable and the impure wrapper below has nothing to get wrong.
///
/// The SOURCE PORT is deliberately ignored: it is chosen per-connection by the
/// client's kernel and carries no identity.
pub fn workload_verdict(
    mode: crate::config::WorkloadIdentityMode,
    recorded: &[String],
    peer: Option<std::net::SocketAddr>,
) -> WorkloadVerdict {
    if !mode.evaluates() {
        return WorkloadVerdict::Disabled;
    }
    if recorded.is_empty() {
        return WorkloadVerdict::Unbindable;
    }
    let parsed: Vec<std::net::IpAddr> = recorded
        .iter()
        .filter_map(|s| s.trim().parse::<std::net::IpAddr>().ok())
        .map(canonical_ip)
        .collect();
    // Something was recorded and NONE of it is an address. Checked before the peer
    // so a provider defect is reported as a provider defect, not as a mismatch.
    if parsed.is_empty() {
        return WorkloadVerdict::Unverifiable;
    }
    let Some(peer) = peer else {
        return WorkloadVerdict::Unverifiable;
    };
    if parsed.contains(&canonical_ip(peer.ip())) {
        WorkloadVerdict::Match
    } else {
        WorkloadVerdict::Mismatch
    }
}

/// Whether a verdict REFUSES the request in this mode. PURE, and separate from
/// [`workload_verdict`] on purpose: `observe` must compute the identical verdict
/// that `enforce` would, so what an operator watches is exactly what they later
/// turn on — not a second code path that merely resembles it.
///
/// [`WorkloadVerdict::Unbindable`] never refuses, in ANY mode. That is the ruling
/// on "what if no address was recorded", and it is deliberate:
///
///   * We do NOT do trust-on-first-use. TOFU would pin whatever address makes the
///     first authenticated call, which means the identity is asserted by the
///     CLAIMANT rather than recorded by the PROVISIONER — the same defect as
///     trusting a forwarded-for header, one layer up. Its race is real and its
///     losing side is worse than the status quo: an attacker who exfiltrates the
///     token before the sandbox's first call pins THEIR address, gains an
///     EXCLUSIVE credential, and locks the legitimate workload out for the rest of
///     the run. Today that same attacker gets a credential they SHARE with a
///     running sandbox. TOFU would therefore convert a confidentiality failure
///     into a confidentiality failure plus a denial of service, in exchange for
///     stopping an attacker who steals the token strictly LATER than the first
///     call — a narrower window than it appears, since the first call happens
///     within seconds of the pod starting.
///   * Refusing unbindable runs outright would mean `enforce` breaks every Docker
///     deployment, every in-flight session, and every adopted orphan — none of
///     which are attacks. A control that cannot be switched on does not protect
///     anything.
///
/// What "admit unbindable" therefore does NOT stop: token theft against any run
/// whose provider reports no address. That is exactly today's exposure, unchanged
/// — the gain is that it is now COUNTED and logged, so an operator can see how
/// much of their fleet the control actually covers instead of assuming all of it.
pub fn workload_refused(
    mode: crate::config::WorkloadIdentityMode,
    verdict: WorkloadVerdict,
) -> bool {
    matches!(mode, crate::config::WorkloadIdentityMode::Enforce)
        && matches!(
            verdict,
            WorkloadVerdict::Mismatch | WorkloadVerdict::Unverifiable
        )
}

/// Per-process verdict tallies. Not a `state.rs` field on purpose (that file is
/// not this task's to change), and per-replica like the egress governor's — the
/// numbers answer "is this control covering my fleet, and is it about to refuse
/// anything", which is a per-replica question an operator asks of logs.
#[derive(Default)]
pub struct WorkloadCounts {
    pub unbindable: std::sync::atomic::AtomicU64,
    pub matched: std::sync::atomic::AtomicU64,
    pub mismatch: std::sync::atomic::AtomicU64,
    pub unverifiable: std::sync::atomic::AtomicU64,
    pub refused: std::sync::atomic::AtomicU64,
}

static WORKLOAD_COUNTS: std::sync::LazyLock<WorkloadCounts> =
    std::sync::LazyLock::new(WorkloadCounts::default);

/// Read the tallies (operators via the boot/periodic logs; tests directly).
pub fn workload_counts() -> &'static WorkloadCounts {
    &WORKLOAD_COUNTS
}

/// Log the unbindable running total at 1, 10, 100, … rather than on every
/// request. An unbindable run is the NORMAL state on the Docker provider, so
/// logging each one would be pure noise and logging none would make the coverage
/// gap invisible; powers of ten give an operator a visible, order-of-magnitude
/// signal at bounded cost. Pure, so the schedule is testable.
pub fn should_log_unbindable(count: u64) -> bool {
    let mut n = count;
    if n == 0 {
        return false;
    }
    while n.is_multiple_of(10) {
        n /= 10;
    }
    n == 1
}

/// Evaluate the binding for one internal-gateway request, record it, and refuse
/// if the mode says to. The ONE place a workload refusal is produced.
///
/// Called from the three places a sandbox credential is resolved: the
/// [`SessionAuth`] extractor (which covers six of the seven internal routes),
/// `facade::messages`, and `internal::result` — the two handlers that resolve a
/// session token by hand and so are not covered by the extractor.
pub fn enforce_workload_identity(
    mode: crate::config::WorkloadIdentityMode,
    session_id: Uuid,
    recorded: &[String],
    peer: Option<std::net::SocketAddr>,
    route: &str,
) -> Result<(), ApiError> {
    use std::sync::atomic::Ordering::Relaxed;
    let verdict = workload_verdict(mode, recorded, peer);
    let refused = workload_refused(mode, verdict);
    let counts = workload_counts();
    match verdict {
        WorkloadVerdict::Disabled => return Ok(()),
        WorkloadVerdict::Match => {
            counts.matched.fetch_add(1, Relaxed);
        }
        WorkloadVerdict::Unbindable => {
            let n = counts.unbindable.fetch_add(1, Relaxed) + 1;
            if should_log_unbindable(n) {
                tracing::info!(
                    target: "workload_identity",
                    verdict = verdict.as_str(),
                    "{n} internal-gateway request(s) so far had NO recorded workload identity \
                     and were admitted on the bearer token alone (mode={}); these runs are not \
                     covered by workload-identity enforcement",
                    mode.as_str()
                );
            }
        }
        WorkloadVerdict::Mismatch => {
            counts.mismatch.fetch_add(1, Relaxed);
            // Always logged, never throttled: by construction this is either an
            // attack or a deployment shape we got wrong, and both are rare enough
            // that every instance is worth a line. `observe` mode exists to
            // produce exactly these without refusing anything.
            tracing::warn!(
                target: "workload_identity",
                verdict = verdict.as_str(),
                "workload identity MISMATCH on {route} for session {session_id}: peer {} is not \
                 among the recorded workload address(es) {recorded:?} (mode={}, {})",
                peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "<none>".into()),
                mode.as_str(),
                if refused { "REFUSED" } else { "admitted" },
            );
        }
        WorkloadVerdict::Unverifiable => {
            counts.unverifiable.fetch_add(1, Relaxed);
            tracing::error!(
                target: "workload_identity",
                verdict = verdict.as_str(),
                "workload identity UNVERIFIABLE on {route} for session {session_id}: recorded \
                 address(es) {recorded:?}, socket peer {} — either the connect-info extension \
                 is not wired on this listener or the provider recorded a non-address \
                 (mode={}, {})",
                peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "<none>".into()),
                mode.as_str(),
                if refused { "REFUSED" } else { "admitted" },
            );
        }
    }
    if refused {
        counts.refused.fetch_add(1, Relaxed);
        return Err(ApiError::Forbidden(WRONG_WORKLOAD_CODE.into()));
    }
    Ok(())
}

/// Per-session authentication for the internal gateway. Resolves the bearer
/// token to the session it belongs to (unexpired, unrevoked) AND its owning
/// tenant — `scope` is derived from the token's row, never `state.tenant_id`,
/// so every internal-plane DB call scopes to the runner's real tenant. The
/// token's `audience` (Gap 10) is carried so each handler enforces its route's
/// required audience via [`SessionAuth::require_audience`].
pub struct SessionAuth {
    pub session_id: Uuid,
    pub token: String,
    pub scope: TenantScope,
    pub audience: String,
}

impl SessionAuth {
    /// Enforce the route's audience. A token whose audience is neither `all` nor
    /// `required` is refused with a machine-readable 403 `{"error":"wrong_audience"}`
    /// — so a leaked LLM or tool-intent credential can never reach a
    /// runner-control route (the invariant-19 acceptance bullet).
    pub fn require_audience(&self, required: &str) -> Result<(), ApiError> {
        if audience_allows(required, &self.audience) {
            Ok(())
        } else {
            Err(ApiError::Forbidden("wrong_audience".into()))
        }
    }
}

impl FromRequestParts<AppState> for SessionAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or(ApiError::Unauthorized)?;
        // Dual-credential rejection (design lines 599-600): cookie + bearer on
        // one request is refused rather than resolved by precedence.
        if !web_cookie_values(&parts.headers).is_empty() {
            return Err(ApiError::BadRequest(
                "present a session cookie or an Authorization bearer, not both".into(),
            ));
        }
        let auth = fluidbox_db::session_for_token(&state.pool, &token)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        // Gap 6 (Phase F): bind the credential to the workload it was issued to.
        // Here rather than per-handler because this extractor is the FIRST thing
        // six of the seven internal routes run — including `/events`, the one route
        // that never loads the session row, whose recorded addresses ride the token
        // lookup above at the cost of one primary-key join. Refuses BEFORE the
        // audience check on purpose: a caller at the wrong address should learn
        // nothing about which audiences exist.
        enforce_workload_identity(
            state.cfg.workload_identity,
            auth.session_id,
            &auth.workload_addrs,
            peer_addr(parts),
            parts.uri.path(),
        )?;
        Ok(SessionAuth {
            session_id: auth.session_id,
            token,
            scope: TenantScope::assume(auth.tenant_id),
            audience: auth.audience,
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
    fn audience_matrix_allow_deny_and_legacy_all() {
        // The four route classes, as the plan's enforcement table (§Task 5).
        for required in [AUD_CONTROL, AUD_TOOL, AUD_LLM, AUD_WORKSPACE] {
            // Exact match allows.
            assert!(
                audience_allows(required, required),
                "{required} == {required}"
            );
            // Legacy 'all' passes EVERY route (in-flight compat).
            assert!(
                audience_allows(required, AUD_ALL),
                "all satisfies {required}"
            );
            // Every OTHER scoped audience is refused on this route.
            for actual in [AUD_CONTROL, AUD_TOOL, AUD_LLM, AUD_WORKSPACE] {
                if actual != required {
                    assert!(
                        !audience_allows(required, actual),
                        "{actual} must NOT satisfy {required}"
                    );
                }
            }
        }
        // The load-bearing cell: neither a tool nor an llm token reaches
        // runner-control, and control reaches neither the gate nor the facade.
        assert!(!audience_allows(AUD_CONTROL, AUD_TOOL));
        assert!(!audience_allows(AUD_CONTROL, AUD_LLM));
        assert!(!audience_allows(AUD_TOOL, AUD_CONTROL));
        assert!(!audience_allows(AUD_LLM, AUD_CONTROL));
    }

    #[test]
    fn audience_constants_match_the_migration_0020_check_vocabulary() {
        // These constants ARE the wire/DB values: migration 0020 constrains
        // `api_tokens.audience` to `('all','llm','tool','control','workspace')`,
        // so renaming a value here without amending that CHECK would make token
        // minting fail at runtime — a failure no other unit test would catch
        // (they all read the same constants). Pinned against those literals.
        let mut names = [AUD_ALL, AUD_LLM, AUD_TOOL, AUD_CONTROL, AUD_WORKSPACE];
        names.sort_unstable();
        assert_eq!(names, ["all", "control", "llm", "tool", "workspace"]);
    }

    #[test]
    fn require_audience_body_is_machine_readable() {
        use axum::response::IntoResponse;
        let sa = SessionAuth {
            session_id: Uuid::nil(),
            token: "fbx_sess_x".into(),
            scope: TenantScope::assume(Uuid::nil()),
            audience: AUD_TOOL.into(),
        };
        // A matching / legacy audience passes; a mismatch is 403 whose BODY
        // carries the machine-readable `wrong_audience` code (not just a status).
        assert!(sa.require_audience(AUD_TOOL).is_ok());
        let err = sa.require_audience(AUD_CONTROL).unwrap_err();
        assert_eq!(err.to_string(), "wrong_audience", "the 403 body error code");
        assert_eq!(
            err.into_response().status(),
            axum::http::StatusCode::FORBIDDEN
        );
        // 'all' passes everywhere.
        let legacy = SessionAuth {
            session_id: Uuid::nil(),
            token: "fbx_sess_y".into(),
            scope: TenantScope::assume(Uuid::nil()),
            audience: AUD_ALL.into(),
        };
        assert!(legacy.require_audience(AUD_CONTROL).is_ok());
        assert!(legacy.require_audience(AUD_LLM).is_ok());
    }

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

    // ─── Workload identity (Phase F, Gap 6) ────────────────────────────────

    use crate::config::WorkloadIdentityMode as Mode;
    use std::net::SocketAddr;

    fn sock(s: &str) -> Option<SocketAddr> {
        Some(s.parse().expect("test address"))
    }
    fn rec(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// This file's PRODUCTION half. The source guards below count occurrences, and
    /// a test module that quotes the strings it counts would count itself.
    fn production_src() -> &'static str {
        let src = include_str!("auth.rs");
        let end = src
            .find("#[cfg(test)]\nmod tests {")
            .expect("this file has a test module");
        &src[..end]
    }

    #[test]
    fn mode_parsing_defaults_off_and_refuses_junk() {
        assert_eq!(Mode::parse(""), Some(Mode::Off));
        assert_eq!(Mode::parse("off"), Some(Mode::Off));
        assert_eq!(Mode::parse("  OFF "), Some(Mode::Off));
        assert_eq!(Mode::parse("observe"), Some(Mode::Observe));
        assert_eq!(Mode::parse("Enforce"), Some(Mode::Enforce));
        // The near-miss that must NEVER silently mean "off".
        assert_eq!(Mode::parse("enforc"), None);
        assert_eq!(Mode::parse("true"), None);
        assert_eq!(Mode::parse("1"), None);
        // Unset MUST be today's behaviour.
        assert_eq!(Mode::default(), Mode::Off);
        assert!(!Mode::Off.evaluates());
        assert!(Mode::Observe.evaluates());
        assert!(Mode::Enforce.evaluates());
    }

    /// The whole decision matrix, in one place. Rows are
    /// (mode, recorded, peer) → verdict, refused.
    #[test]
    fn the_decision_matrix() {
        let a = "10.4.2.9";
        let b = "10.4.2.10";
        type Row = (Mode, Vec<String>, Option<SocketAddr>, WorkloadVerdict, bool);
        let rows: Vec<Row> = vec![
            // off: never evaluated, whatever the inputs.
            (
                Mode::Off,
                rec(&[a]),
                sock("10.9.9.9:5"),
                WorkloadVerdict::Disabled,
                false,
            ),
            (Mode::Off, vec![], None, WorkloadVerdict::Disabled, false),
            // no recorded identity ⇒ unbindable, ADMITTED in both live modes.
            (
                Mode::Observe,
                vec![],
                sock("10.4.2.9:1"),
                WorkloadVerdict::Unbindable,
                false,
            ),
            (
                Mode::Enforce,
                vec![],
                sock("10.4.2.9:1"),
                WorkloadVerdict::Unbindable,
                false,
            ),
            // match.
            (
                Mode::Observe,
                rec(&[a]),
                sock("10.4.2.9:33000"),
                WorkloadVerdict::Match,
                false,
            ),
            (
                Mode::Enforce,
                rec(&[a]),
                sock("10.4.2.9:33000"),
                WorkloadVerdict::Match,
                false,
            ),
            // mismatch: observed but admitted / refused.
            (
                Mode::Observe,
                rec(&[a]),
                sock("10.4.2.10:1"),
                WorkloadVerdict::Mismatch,
                false,
            ),
            (
                Mode::Enforce,
                rec(&[a]),
                sock("10.4.2.10:1"),
                WorkloadVerdict::Mismatch,
                true,
            ),
            // dual-stack: EITHER recorded family matches.
            (
                Mode::Enforce,
                rec(&[a, "fd00::5"]),
                sock("[fd00::5]:1"),
                WorkloadVerdict::Match,
                false,
            ),
            (
                Mode::Enforce,
                rec(&[a, "fd00::5"]),
                sock("[fd00::6]:1"),
                WorkloadVerdict::Mismatch,
                true,
            ),
            // recorded, but no socket peer ⇒ unverifiable, fail closed under enforce.
            (
                Mode::Observe,
                rec(&[a]),
                None,
                WorkloadVerdict::Unverifiable,
                false,
            ),
            (
                Mode::Enforce,
                rec(&[a]),
                None,
                WorkloadVerdict::Unverifiable,
                true,
            ),
            // recorded garbage ⇒ unverifiable, NOT "mismatch" (a provider defect
            // must not read as an attack), and fail closed under enforce.
            (
                Mode::Enforce,
                rec(&["not-an-address"]),
                sock("10.4.2.9:1"),
                WorkloadVerdict::Unverifiable,
                true,
            ),
            // a partly-garbage list still binds on its usable entries.
            (
                Mode::Enforce,
                rec(&["not-an-address", b]),
                sock("10.4.2.10:1"),
                WorkloadVerdict::Match,
                false,
            ),
        ];
        for (mode, recorded, peer, want, want_refused) in rows {
            let got = workload_verdict(mode, &recorded, peer);
            assert_eq!(
                got, want,
                "verdict for mode={mode:?} recorded={recorded:?} peer={peer:?}"
            );
            assert_eq!(
                workload_refused(mode, got),
                want_refused,
                "refusal for mode={mode:?} recorded={recorded:?} peer={peer:?}"
            );
        }
    }

    #[test]
    fn an_ipv4_mapped_peer_matches_the_ipv4_the_provider_recorded() {
        // A dual-stack listener reports an IPv4 client as ::ffff:a.b.c.d while the
        // Kubernetes API reports the pod's address as a.b.c.d. Comparing those as
        // strings — or as un-normalized IpAddrs — refuses every legitimate request.
        assert_eq!(
            workload_verdict(
                Mode::Enforce,
                &rec(&["10.4.2.9"]),
                sock("[::ffff:10.4.2.9]:44000"),
            ),
            WorkloadVerdict::Match
        );
        // ...and the reverse direction (provider records the mapped form).
        assert_eq!(
            workload_verdict(
                Mode::Enforce,
                &rec(&["::ffff:10.4.2.9"]),
                sock("10.4.2.9:1")
            ),
            WorkloadVerdict::Match
        );
        // The mapping must not make DIFFERENT hosts equal.
        assert_eq!(
            workload_verdict(
                Mode::Enforce,
                &rec(&["10.4.2.9"]),
                sock("[::ffff:10.4.2.10]:1"),
            ),
            WorkloadVerdict::Mismatch
        );
    }

    #[test]
    fn the_source_port_is_not_part_of_the_identity() {
        for port in ["1", "33000", "65535"] {
            assert_eq!(
                workload_verdict(
                    Mode::Enforce,
                    &rec(&["10.4.2.9"]),
                    sock(&format!("10.4.2.9:{port}")),
                ),
                WorkloadVerdict::Match
            );
        }
    }

    #[test]
    fn the_refusal_code_cannot_be_mistaken_for_the_audience_refusal() {
        // `images/runner-lib/contract.mjs` aborts the whole run on a body
        // CONTAINING "wrong_audience" (substring, not exact match), with a
        // diagnostic that would be plainly wrong here.
        assert!(!WRONG_WORKLOAD_CODE.contains("wrong_audience"));
        assert_ne!(WRONG_WORKLOAD_CODE, "wrong_audience");
        // And the runner's real predicate, transcribed: the substring test it runs.
        let body = format!("{{\"error\":\"{WRONG_WORKLOAD_CODE}\"}}");
        assert!(!body.contains("wrong_audience"));
        // Belt: the runner-lib source really does key on that substring, so the
        // assertion above is testing the rule that exists rather than one we
        // remember. If contract.mjs stops doing this, revisit the choice of code.
        let contract = include_str!("../../../images/runner-lib/contract.mjs");
        assert!(
            contract.contains("bodyText.includes(\"wrong_audience\")"),
            "runner-lib no longer substring-matches wrong_audience; re-check WRONG_WORKLOAD_CODE"
        );
        // The runner has no branch for our code today (disclosed): it falls into
        // the ordinary 401/403 handling. Assert that absence so it is a decision,
        // not an oversight — flip this when a runner learns the code.
        assert!(!contract.contains(WRONG_WORKLOAD_CODE));
    }

    #[test]
    fn the_refusal_is_a_403_carrying_exactly_that_code() {
        use axum::response::IntoResponse;
        let err = enforce_workload_identity(
            Mode::Enforce,
            Uuid::nil(),
            &rec(&["10.4.2.9"]),
            sock("10.9.9.9:1"),
            "/internal/sessions/{id}/events",
        )
        .expect_err("a mismatch under enforce must refuse");
        let resp = err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        // Every other verdict admits.
        for (mode, recorded, peer) in [
            (Mode::Off, rec(&["10.4.2.9"]), sock("10.9.9.9:1")),
            (Mode::Observe, rec(&["10.4.2.9"]), sock("10.9.9.9:1")),
            (Mode::Enforce, vec![], sock("10.9.9.9:1")),
            (Mode::Enforce, rec(&["10.4.2.9"]), sock("10.4.2.9:1")),
        ] {
            assert!(
                enforce_workload_identity(mode, Uuid::nil(), &recorded, peer, "/x").is_ok(),
                "mode={mode:?} recorded={recorded:?} peer={peer:?} must be admitted"
            );
        }
    }

    #[test]
    fn the_unbindable_log_schedule_is_powers_of_ten() {
        assert!(!should_log_unbindable(0));
        for n in [1u64, 10, 100, 1_000, 10_000, 1_000_000] {
            assert!(should_log_unbindable(n), "{n} should log");
        }
        for n in [2u64, 9, 11, 99, 101, 999, 1_001, 20, 300] {
            assert!(!should_log_unbindable(n), "{n} should NOT log");
        }
    }

    #[test]
    fn handle_attrs_are_read_leniently_and_never_invented() {
        use fluidbox_core::traits::SandboxHandle;
        let h = |attrs: serde_json::Value| SandboxHandle {
            runtime: "kubernetes".into(),
            external_id: "fbx-x".into(),
            attrs,
        };
        assert_eq!(
            workload_addrs_from_handle(&h(serde_json::json!({
                "namespace": "s", "uid": "u", "workload_addrs": ["10.4.2.9", "fd00::5"]
            }))),
            rec(&["10.4.2.9", "fd00::5"])
        );
        // The Docker handle: no such key ⇒ empty ⇒ unbindable.
        assert!(
            workload_addrs_from_handle(&h(serde_json::json!({"network": "n", "name": "c"})))
                .is_empty()
        );
        // Junk shapes yield nothing rather than panicking or fabricating.
        assert!(
            workload_addrs_from_handle(&h(serde_json::json!({"workload_addrs": "10.4.2.9"})))
                .is_empty()
        );
        assert!(
            workload_addrs_from_handle(&h(serde_json::json!({"workload_addrs": [1, null]})))
                .is_empty()
        );
        assert!(
            workload_addrs_from_handle(&h(serde_json::json!({"workload_addrs": ["  "]})))
                .is_empty()
        );
        assert_eq!(
            workload_addrs_from_handle(&h(serde_json::json!({"workload_addrs": [" 10.4.2.9 "]}))),
            rec(&["10.4.2.9"])
        );
    }

    /// The provider writes the attribute; the control plane reads it. Nothing in
    /// the type system connects the two, so this reads the OTHER CRATE'S SOURCE and
    /// fails if either side renames the key.
    #[test]
    fn the_provider_and_the_control_plane_agree_on_the_handle_attribute() {
        let k8s = include_str!("../../fluidbox-provider-k8s/src/lib.rs");
        assert!(
            k8s.contains(&format!("\"{WORKLOAD_ADDR_ATTR}\"")),
            "the Kubernetes provider no longer writes the '{WORKLOAD_ADDR_ATTR}' handle \
             attribute that auth.rs reads — the workload binding is silently disabled"
        );
        // And it must actually be captured from the Pod, not hardcoded empty.
        assert!(k8s.contains("pod_workload_addrs(&pod)"));
    }

    /// DESIGN CONSTRAINT: the internal plane's peer is the SOCKET peer, never a
    /// header. A sandbox can set headers, so honouring one would let the caller
    /// assert its own identity. Proven two ways: the production source names no
    /// forwarding header in this region, and the live-socket test below shows a
    /// forged one changes nothing.
    #[test]
    fn no_forwarding_header_is_consulted_on_the_internal_plane() {
        let src = production_src();
        let start = src
            .find("pub fn peer_addr(")
            .expect("peer_addr is defined in this file");
        let end = src
            .find("/// Per-session authentication for the internal gateway")
            .expect("the workload region ends at SessionAuth");
        let region = &src[start..end].to_lowercase();
        for banned in [
            "x-forwarded-for",
            "x-real-ip",
            "trust_forwarded_for",
            "headers",
        ] {
            assert!(
                !region.contains(banned),
                "the workload-identity decision path must not reach for '{banned}'"
            );
        }
        // It reads the connect-info extension and nothing else.
        assert!(src.contains("parts\n        .extensions\n        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()"));
    }

    /// Live socket. Proves (a) `PeerAddr` reports the REAL peer, and (b) forged
    /// forwarding headers do not move it — including under a header set crafted to
    /// look exactly like a trusted-proxy deployment.
    #[tokio::test]
    async fn the_peer_is_the_socket_peer_even_under_forged_forwarding_headers() {
        use axum::routing::get;
        let app = axum::Router::new().route(
            "/peer",
            get(|PeerAddr(p): PeerAddr| async move {
                p.map(|s| s.ip().to_string())
                    .unwrap_or_else(|| "none".into())
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        });
        let client = reqwest::Client::new();
        let body = client
            .get(format!("http://{addr}/peer"))
            .header("x-forwarded-for", "10.4.2.9")
            .header("x-real-ip", "10.4.2.9")
            .header("forwarded", "for=10.4.2.9")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        // The loopback client's real address — never the forged 10.4.2.9.
        assert_eq!(body, "127.0.0.1", "a forged header moved the peer");
    }

    /// Without `into_make_service_with_connect_info`, the extension is absent.
    /// That is a WIRING DEFECT, and the matrix above turns it into `Unverifiable`
    /// (fail-closed under enforce) rather than into a silent no-op.
    #[tokio::test]
    async fn a_listener_without_connect_info_reports_no_peer() {
        use axum::routing::get;
        let app = axum::Router::new().route(
            "/peer",
            get(|PeerAddr(p): PeerAddr| async move {
                p.map(|s| s.ip().to_string())
                    .unwrap_or_else(|| "none".into())
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let body = reqwest::get(format!("http://{addr}/peer"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "none");
        assert_eq!(
            workload_verdict(Mode::Enforce, &rec(&["10.4.2.9"]), None),
            WorkloadVerdict::Unverifiable
        );
        assert!(workload_refused(
            Mode::Enforce,
            WorkloadVerdict::Unverifiable
        ));
    }

    /// CALL-SITE GUARD. The matrix above is pure, so every one of its assertions
    /// passes with the guard deleted from production. These assertions are what
    /// make deleting a call site fail: the three places a sandbox credential is
    /// resolved must each run it, and both listeners must supply connect info.
    #[test]
    fn every_sandbox_credential_resolution_runs_the_workload_guard() {
        // (1) the extractor, covering six of seven internal routes.
        assert!(
            production_src()
                .contains("enforce_workload_identity(\n            state.cfg.workload_identity,"),
            "SessionAuth::from_request_parts no longer enforces the workload binding"
        );
        // (2) + (3) the two handlers that resolve a session token by hand.
        for (file, src) in [
            ("facade.rs", include_str!("facade.rs")),
            ("internal.rs", include_str!("internal.rs")),
        ] {
            assert!(
                src.contains("crate::auth::enforce_workload_identity("),
                "{file} resolves a session token without the workload binding"
            );
            assert!(
                src.contains("crate::auth::PeerAddr(peer): crate::auth::PeerAddr"),
                "{file} must take the socket peer as a handler parameter"
            );
        }
        // The extension only exists because both listeners are built with it.
        let main_src = include_str!("main.rs");
        assert_eq!(
            main_src
                .matches("into_make_service_with_connect_info::<SocketAddr>()")
                .count(),
            2,
            "both planes must supply ConnectInfo or the guard degrades to unverifiable"
        );
        // The orchestrator must actually RECORD an identity, or every run is
        // unbindable and the guard never has anything to compare against.
        let orch = include_str!("orchestrator.rs");
        assert!(orch.contains("crate::auth::workload_addrs_from_handle(&handle)"));
        assert!(orch.contains("fluidbox_db::set_workload_addrs("));
    }

    /// THE SILENT-DEATH GUARD. Every credential resolution reads the recorded
    /// addresses off the token lookup's join. Drop that one column from either
    /// resolver and `workload_addrs` is always empty, every request becomes
    /// `Unbindable`, and the feature is disabled with every test above still green
    /// (they are pure, and the call-site guard only proves the call happens). This
    /// is what makes deleting the join fail — no database required.
    #[test]
    fn both_session_token_resolvers_carry_the_recorded_addresses() {
        let db = include_str!("../../fluidbox-db/src/lib.rs");
        assert_eq!(
            db.matches("select t.session_id, t.tenant_id, t.audience, s.workload_addrs")
                .count(),
            2,
            "session_for_token and session_for_token_incl_revoked must BOTH carry \
             sessions.workload_addrs, or the workload binding silently sees nothing"
        );
        assert_eq!(
            db.matches("left join sessions s on s.id = t.session_id")
                .count(),
            2
        );
        // ...and the row shaper must not drop it on the floor.
        assert!(db.contains("workload_addrs: r"));
        // The writer must exist and target the column the readers read.
        assert!(db.contains("update sessions set workload_addrs = $2"));
    }
}
