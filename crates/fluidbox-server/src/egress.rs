//! The shared egress boundary (Phase E, invariant 22 / Gap 7).
//!
//! Generalizes the per-hop SSRF machinery that used to live only in `login.rs`
//! (OIDC identity fetches) into ONE place every control-plane→internet dial can
//! reuse. The pure address predicate (`ip_blocked` + `IpCidr`) lives in
//! `fluidbox-core::netpolicy` so `fluidbox-workspace` (git clone) can share it
//! without importing this crate; here we re-export it and add the reqwest-level
//! wrappers: a DNS resolver that filters resolved addresses at connect time
//! (DNS-rebinding/TOCTOU defense), a per-hop redirect validator, bounded reads,
//! and pre-dial `admit_url`.
//!
//! TWO hardened clients are built from one [`EgressPolicy`]:
//!   - [`build_identity_http`] — OIDC discovery/JWKS/token AND connector-OAuth
//!     (discovery, PRM, AS metadata, DCR, exchange, refresh). Custom redirect
//!     policy re-validates ≤10 hops.
//!   - [`build_egress_http`] — broker MCP + snapshot/probe discovery + delivery
//!     webhook publish. `redirect::Policy::none()`: a 3xx is refused, not
//!     followed (an arbitrary MCP/webhook endpoint has no business redirecting
//!     us onto a fresh host).
//!
//! `state.http` stays the plain client for the OPERATOR-configured seams
//! (GitHub REST/App, LLM facade + admin) — those hosts are set by the operator
//! (GHES, a private LiteLLM), never by attacker input, and forcing them through
//! the private-IP block would break legitimate internal deployments.
//!
//! The dev-loopback seam (`dev_loopback`, keyed off a loopback-http
//! `FLUIDBOX_PUBLIC_URL`) is baked into both clients + `admit_url` at build
//! time, so the e2e fakes on 127.0.0.1 keep working while every hosted
//! (https public URL) deployment auto-closes the loopback allowance.

use crate::config::Config;
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub(crate) use fluidbox_core::netpolicy::{ip_blocked, IpCidr};

/// Body ceiling for a bounded JSON read (identity/OAuth documents).
pub(crate) const MAX_HTTP_BODY_BYTES: usize = 256 * 1024;

/// The resolved egress policy, built ONCE in `main.rs` from config and stored on
/// `AppState` so the broker, deliveries, and the git-clone derivation all consult
/// the same decision. `github_clone_base` is carried here only so the orchestrator
/// can derive the workspace [`fluidbox_workspace::GitEgressPolicy`]'s file prefix.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    pub dev_loopback: bool,
    pub allow_cidrs: Vec<IpCidr>,
    pub github_clone_base: Option<String>,
    pub proxy: Option<String>,
}

impl EgressPolicy {
    /// Build from config: the loopback seam from `FLUIDBOX_PUBLIC_URL`, the
    /// operator allowlist + proxy already parsed by `config.rs`.
    pub fn from_config(cfg: &Config) -> Self {
        EgressPolicy {
            dev_loopback: dev_loopback(&cfg.public_url),
            allow_cidrs: cfg.egress_allow_cidrs.clone(),
            github_clone_base: Some(cfg.github_clone_base.clone()),
            proxy: cfg.egress_proxy.clone(),
        }
    }
}

/// A pre-dial admission denial. The message is a non-secret, static-shaped
/// string (never echoes a resolved IP or a redirect target).
#[derive(Debug)]
pub struct EgressDenied(String);

impl EgressDenied {
    fn new(msg: &str) -> Self {
        EgressDenied(msg.to_string())
    }
}

impl std::fmt::Display for EgressDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn host_is_loopback(u: &reqwest::Url) -> bool {
    match u.host_str() {
        Some(h) if h.eq_ignore_ascii_case("localhost") => true,
        Some(h) => h
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false),
        None => false,
    }
}

/// True iff the deployment IS loopback dev — `FLUIDBOX_PUBLIC_URL` is `http://`
/// on a loopback host. The single switch that green-lights the e2e loopback/
/// plain-http/file seams; a hosted https public URL closes it automatically.
pub(crate) fn dev_loopback(public_url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(public_url) else {
        return false;
    };
    u.scheme() == "http" && host_is_loopback(&u)
}

/// Pre-dial admission for an OUTBOUND request URL (broker MCP, delivery webhook,
/// and — mirrored in `fluidbox-workspace` — git clone). E3 scheme policy: only
/// https leaves the control plane unless the dev-loopback seam is open; plus a
/// host-literal short-circuit so a URL whose host is already a private/metadata
/// IP literal never even opens a socket. A DNS *name* is validated at connect
/// time by the client's [`SsrfDnsResolver`] (rebinding-safe) — resolving here
/// too would only add a TOCTOU window and a wasted lookup.
pub(crate) fn admit_url(url: &str, policy: &EgressPolicy) -> Result<(), EgressDenied> {
    let u = reqwest::Url::parse(url)
        .map_err(|_| EgressDenied::new("egress target is not a valid URL"))?;
    match u.scheme() {
        "https" => {}
        "http" if policy.dev_loopback && host_is_loopback(&u) => {}
        "http" => {
            return Err(EgressDenied::new(
                "refusing a plain-http egress target (https required)",
            ))
        }
        _ => return Err(EgressDenied::new("refusing a non-http(s) egress target")),
    }
    if let Some(host) = u.host_str() {
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            if ip_blocked(ip, policy.dev_loopback, &policy.allow_cidrs) {
                return Err(EgressDenied::new(
                    "refusing an egress target at a private/loopback/link-local address",
                ));
            }
        }
    }
    Ok(())
}

/// Pre-flight (and final-URL) validation for identity/OAuth fetches: https-only
/// (loopback http under dev), then resolve the host and refuse if ANY resolved
/// address is private. The per-hop client is the real guard; this is cheap
/// defense in depth at the request and response URLs.
pub(crate) async fn validate_fetch_target(
    u: &reqwest::Url,
    dev: bool,
    allow: &[IpCidr],
) -> Result<(), String> {
    match u.scheme() {
        "https" => {}
        "http" if dev && host_is_loopback(u) => {}
        _ => return Err("OIDC endpoints must be https".into()),
    }
    let host = u.host_str().ok_or("URL has no host")?;
    let port = u.port_or_known_default().ok_or("URL has no port")?;
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| "could not resolve host".to_string())?
        .map(|s| s.ip())
        .collect();
    if addrs.is_empty() {
        return Err("host did not resolve".into());
    }
    if addrs.iter().any(|ip| ip_blocked(*ip, dev, allow)) {
        return Err("refusing to fetch a private/loopback/link-local address".into());
    }
    Ok(())
}

/// The addresses that survive the SSRF filter (loopback kept only in dev). The
/// pure core of the hardened clients' DNS resolver — tested without a network.
fn filter_public_addrs(
    addrs: impl Iterator<Item = std::net::SocketAddr>,
    dev: bool,
    allow: &[IpCidr],
) -> Vec<std::net::SocketAddr> {
    addrs.filter(|s| !ip_blocked(s.ip(), dev, allow)).collect()
}

/// One redirect hop's scheme + host-literal gate: https always (loopback http
/// only in dev), and a host that is a private/loopback/link-local IP literal is
/// refused. The DNS resolver still filters the *resolved* addresses at connect
/// time; this is the cheap host-literal defense-in-depth on every hop.
pub(crate) fn redirect_hop_allowed(
    u: &reqwest::Url,
    dev: bool,
    allow: &[IpCidr],
) -> Result<(), String> {
    match u.scheme() {
        "https" => {}
        "http" if dev && host_is_loopback(u) => {}
        _ => return Err("redirect to a non-https endpoint refused".into()),
    }
    if let Some(host) = u.host_str() {
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            if ip_blocked(ip, dev, allow) {
                return Err("redirect to a private/loopback address refused".into());
            }
        }
    }
    Ok(())
}

/// A `reqwest::dns::Resolve` that resolves via the system resolver and drops
/// every non-public address at resolution time — DNS-rebinding and per-hop
/// private targets die here (loopback survives only in dev). Empty after the
/// filter ⇒ a resolution error, so the connection never opens.
struct SsrfDnsResolver {
    dev: bool,
    allow: Vec<IpCidr>,
}

impl reqwest::dns::Resolve for SsrfDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let dev = self.dev;
        let allow = self.allow.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port 0: reqwest overrides it with the URL's port; we only care
            // about the resolved IPs.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed = filter_public_addrs(resolved, dev, &allow);
            if allowed.is_empty() {
                return Err("refusing to resolve to a private/loopback/link-local address".into());
            }
            let addrs: reqwest::dns::Addrs = Box::new(allowed.into_iter());
            Ok(addrs)
        })
    }
}

/// Apply the optional egress proxy (`FLUIDBOX_EGRESS_PROXY`) to both hardened
/// clients. The value is VALIDATED at boot (`config::parse_egress_proxy` runs the
/// same `Proxy::all`), so a rejection here is unreachable in practice — we log
/// and skip rather than panic (M1: defense in depth, never a first-dial crash;
/// the builder receives a pre-validated value).
///
/// M2 — proxy semantics, BOTH cases:
/// - A proxy IS configured: target DNS resolution moves to the PROXY, so this
///   client's [`SsrfDnsResolver`] name-filtering no longer applies to proxied
///   requests (the resolver only runs for direct connections). The `admit_url`
///   literal + scheme checks still apply, and the proxy becomes the egress
///   control point — operators point `FLUIDBOX_EGRESS_PROXY` at an allowlisting
///   forward proxy to regain destination control for proxied traffic.
/// - NO proxy configured: `.no_proxy()` is MANDATORY. reqwest otherwise reads
///   the ambient `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` environment, which would
///   silently move target resolution to a proxy nobody configured and bypass
///   [`SsrfDnsResolver`] entirely for MCP, discovery/probe, OAuth and delivery
///   traffic. The proxy is therefore an EXPLICIT, boot-validated setting or
///   nothing at all — never inherited from the process environment.
fn with_proxy(mut b: reqwest::ClientBuilder, policy: &EgressPolicy) -> reqwest::ClientBuilder {
    match &policy.proxy {
        Some(p) => match reqwest::Proxy::all(p) {
            Ok(proxy) => b = b.proxy(proxy),
            Err(e) => {
                tracing::error!(
                    "FLUIDBOX_EGRESS_PROXY rejected at client build \
                     (should have failed boot in config::parse_egress_proxy): {e}"
                );
                // A rejected value must NOT silently fall back to the ambient
                // environment's proxy — fail closed onto a direct client.
                b = b.no_proxy();
            }
        },
        None => b = b.no_proxy(),
    }
    b
}

/// The hardened client for connector traffic to ARBITRARY user-supplied
/// endpoints: broker MCP calls, snapshot/probe discovery, and delivery webhook
/// publish. `redirect::Policy::none()` refuses any 3xx (callers surface it as a
/// protocol error / failed attempt), the DNS resolver filters resolved
/// addresses at connect time, and no cookie store exists (the `cookies` feature
/// is off crate-wide — invariant 22 by construction).
pub fn build_egress_http(policy: &EgressPolicy) -> reqwest::Client {
    with_proxy(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15 * 60))
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(SsrfDnsResolver {
                dev: policy.dev_loopback,
                allow: policy.allow_cidrs.clone(),
            })),
        policy,
    )
    .build()
    .expect("egress HTTP client builds")
}

/// The per-hop-SSRF client for identity fetches (OIDC discovery, JWKS, token)
/// AND connector-OAuth (discovery, PRM, AS metadata, DCR, code exchange, refresh
/// — `oauth.rs`). A custom redirect policy re-validates every hop's scheme +
/// host literal (≤10), and the DNS resolver filters resolved addresses at
/// connect time, closing the intermediate-hop TOCTOU. No cookie store.
pub fn build_identity_http(policy: &EgressPolicy) -> reqwest::Client {
    let dev = policy.dev_loopback;
    let allow = policy.allow_cidrs.clone();
    let redirect = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 10 {
            return attempt.error("too many redirects");
        }
        match redirect_hop_allowed(attempt.url(), dev, &allow) {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(e),
        }
    });
    with_proxy(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15 * 60))
            .redirect(redirect)
            .dns_resolver(Arc::new(SsrfDnsResolver {
                dev: policy.dev_loopback,
                allow: policy.allow_cidrs.clone(),
            })),
        policy,
    )
    .build()
    .expect("identity HTTP client builds")
}

/// Read a JSON body under the byte ceiling ENFORCED BEFORE full buffering: a
/// declared `Content-Length` over the cap is refused up front, and the body is
/// then read chunk-by-chunk with the running total re-checked, so a lying or
/// absent length cannot smuggle an oversized document past the bound.
pub(crate) async fn read_json_bounded(res: &mut reqwest::Response) -> Result<Value, String> {
    if let Some(len) = res.content_length() {
        if len > MAX_HTTP_BODY_BYTES as u64 {
            return Err("identity response exceeds the size bound".into());
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| format!("response read failed: {e}"))?
    {
        if buf.len() + chunk.len() > MAX_HTTP_BODY_BYTES {
            return Err("identity response exceeds the size bound".into());
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice::<Value>(&buf).map_err(|e| format!("response was not JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_policy(allow: Vec<IpCidr>) -> EgressPolicy {
        EgressPolicy {
            dev_loopback: true,
            allow_cidrs: allow,
            github_clone_base: None,
            proxy: None,
        }
    }
    fn prod_policy(allow: Vec<IpCidr>) -> EgressPolicy {
        EgressPolicy {
            dev_loopback: false,
            allow_cidrs: allow,
            github_clone_base: None,
            proxy: None,
        }
    }

    #[test]
    fn dev_loopback_only_for_loopback_http() {
        assert!(dev_loopback("http://127.0.0.1:8787"));
        assert!(dev_loopback("http://localhost:8787"));
        assert!(!dev_loopback("https://127.0.0.1:8787")); // https closes it
        assert!(!dev_loopback("http://example.com")); // non-loopback
        assert!(!dev_loopback("not a url"));
    }

    // ─── admit_url (pre-dial, E3) ─────────────────────────────────────────
    //
    // HERMETIC BY CONSTRUCTION: every predicate asserted in this module —
    // `admit_url`, `redirect_hop_allowed`, `filter_public_addrs`, and their
    // callers `oauth::admit_oauth` / `connections::admit_connector_base_url` —
    // is a SYNCHRONOUS `fn` that parses a URL and range-checks a literal. None
    // of them resolves a name; the only resolution in this crate lives in
    // `SsrfDnsResolver` and `validate_fetch_target`, which are on neither path.
    // So no test here performs a live lookup, and none can be made flaky or slow
    // by the network. The hostnames below are RFC 2606 reserved names used only
    // to exercise the "host is NOT an IP literal" branch; each is paired with an
    // IP-literal assertion pinning the same property with no name involved.
    #[test]
    fn admit_url_requires_https_outside_dev() {
        let prod = prod_policy(vec![]);
        assert!(admit_url("https://mcp.example.com/x", &prod).is_ok());
        // plain http is refused when not dev…
        assert!(admit_url("http://mcp.example.com/x", &prod).is_err());
        // …and the identical scheme rule holds on a hostname-FREE input, so the
        // property is asserted without any name at all.
        assert!(admit_url("https://93.184.216.34/x", &prod).is_ok());
        assert!(admit_url("http://93.184.216.34/x", &prod).is_err());
        // …but allowed for loopback under the dev seam (the e2e fakes).
        let dev = dev_policy(vec![]);
        assert!(admit_url("http://127.0.0.1:9/mcp", &dev).is_ok());
        // a non-loopback http host is refused even in dev.
        assert!(admit_url("http://10.0.0.1/x", &dev).is_err());
        // non-http(s) schemes never admit.
        assert!(admit_url("ftp://host/x", &prod).is_err());
        assert!(admit_url("not-a-url", &prod).is_err());
    }

    #[test]
    fn admit_url_blocks_ip_literals_and_metadata() {
        let prod = prod_policy(vec![]);
        assert!(admit_url("https://10.0.0.1/x", &prod).is_err());
        assert!(admit_url("https://169.254.169.254/latest", &prod).is_err());
        assert!(admit_url("https://[::1]/x", &prod).is_err());
        // metadata stays blocked even in dev (loopback ≠ link-local).
        let dev = dev_policy(vec![]);
        assert!(admit_url("http://169.254.169.254/latest", &dev).is_err());
        // FALSE-GREEN guard: an allow-CIDR opens the SAME literal that is
        // otherwise refused.
        assert!(admit_url("https://10.0.0.1/x", &prod).is_err());
        let allowed = prod_policy(vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(admit_url("https://10.0.0.1/x", &allowed).is_ok());
    }

    // ─── per-hop redirect + DNS filter (moved from login.rs, allow threaded) ─
    #[test]
    fn redirect_hop_validation() {
        let u = |s: &str| reqwest::Url::parse(s).unwrap();
        assert!(redirect_hop_allowed(&u("https://issuer.example/x"), false, &[]).is_ok());
        assert!(redirect_hop_allowed(&u("http://issuer.example/x"), false, &[]).is_err());
        // The same scheme rule on a hostname-FREE public literal (no name).
        assert!(redirect_hop_allowed(&u("https://93.184.216.34/x"), false, &[]).is_ok());
        assert!(redirect_hop_allowed(&u("http://93.184.216.34/x"), false, &[]).is_err());
        assert!(redirect_hop_allowed(&u("https://169.254.169.254/latest"), false, &[]).is_err());
        assert!(redirect_hop_allowed(&u("https://10.0.0.1/x"), false, &[]).is_err());
        assert!(redirect_hop_allowed(&u("https://[::1]/x"), false, &[]).is_err());
        assert!(redirect_hop_allowed(&u("http://127.0.0.1:5556/x"), true, &[]).is_ok());
        assert!(redirect_hop_allowed(&u("http://127.0.0.1:5556/x"), false, &[]).is_err());
        // allow-CIDR opens an otherwise-blocked private redirect target.
        let allow: Vec<IpCidr> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(redirect_hop_allowed(&u("https://10.0.0.1/x"), false, &allow).is_ok());
    }

    // ─── bounded reads (I3: the ceiling connector-OAuth now shares) ────────
    #[tokio::test]
    async fn read_json_bounded_refuses_an_over_cap_body_both_ways() {
        // Hermetic: a synthetic `reqwest::Response`, no socket and no resolver.
        let body = |n: usize| format!("{{\"pad\":\"{}\"}}", "x".repeat(n));
        // 1. NO declared length (a chunked/streamed body, which is how a hostile
        //    server evades a length pre-check) ⇒ the running total is the only
        //    enforcement, so this case must exercise THAT branch.
        let chunks = (0..40).map(|_| Ok::<_, std::io::Error>(vec![b'x'; 8 * 1024]));
        let streamed =
            axum::http::Response::new(reqwest::Body::wrap_stream(futures::stream::iter(chunks)));
        let mut res = reqwest::Response::from(streamed);
        assert_eq!(
            res.content_length(),
            None,
            "this case must have no declared length, or it tests the wrong branch"
        );
        let err = read_json_bounded(&mut res)
            .await
            .expect_err("an over-cap streamed body must be refused");
        assert!(err.contains("size bound"), "got: {err}");
        // 2. A DECLARED length over the cap is refused before buffering.
        let declared = axum::http::Response::builder()
            .header(
                "content-length",
                (MAX_HTTP_BODY_BYTES as u64 + 1).to_string(),
            )
            .body(body(MAX_HTTP_BODY_BYTES + 1024))
            .unwrap();
        let mut res = reqwest::Response::from(declared);
        assert!(read_json_bounded(&mut res).await.is_err());
        // FALSE-GREEN guard: an UNDER-cap document still parses, so the two
        // assertions above are about the ceiling and not about reads failing.
        let small = axum::http::Response::new(body(16));
        let mut res = reqwest::Response::from(small);
        let v = read_json_bounded(&mut res).await.expect("under cap parses");
        assert_eq!(v["pad"].as_str().map(str::len), Some(16));
    }

    /// The AMBIENT-PROXY bypass (M2): reqwest reads `HTTP_PROXY`/`HTTPS_PROXY`/
    /// `ALL_PROXY` from the process environment unless told not to. A proxied
    /// request resolves the TARGET at the proxy, so [`SsrfDnsResolver`] never
    /// sees the name and the whole DNS boundary is bypassed — for MCP, probe/
    /// discovery, OAuth and delivery alike. Both hardened clients must therefore
    /// use ONLY an explicitly configured proxy.
    ///
    /// The probe: point `HTTPS_PROXY` at a listener we own and dial an
    /// unresolvable `.invalid` host. A client that honors the ambient proxy
    /// CONNECTs to the listener (it never resolves the target itself); a client
    /// with `.no_proxy()` resolves directly, fails, and touches nothing. So
    /// "zero accepted connections" is the discriminator.
    #[tokio::test]
    async fn hardened_clients_ignore_ambient_proxy_env() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_bg = seen.clone();
        tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                seen_bg.fetch_add(1, Ordering::SeqCst);
            }
        });

        // The env window is kept to the two `build`s (reqwest reads the
        // environment there, not at request time) so a concurrently-building
        // client in another test is not caught by it.
        let prev = std::env::var("HTTPS_PROXY").ok();
        std::env::set_var("HTTPS_PROXY", format!("http://127.0.0.1:{port}"));
        let policy = prod_policy(vec![]);
        let egress = build_egress_http(&policy);
        let identity = build_identity_http(&policy);
        match prev {
            Some(v) => std::env::set_var("HTTPS_PROXY", v),
            None => std::env::remove_var("HTTPS_PROXY"),
        }

        // `.invalid` is RFC 2606 — guaranteed never to resolve, so a direct
        // client fails locally without emitting a packet.
        for client in [&egress, &identity] {
            let _ = client
                .get("https://fluidbox-egress-probe.invalid/x")
                .timeout(Duration::from_secs(5))
                .send()
                .await;
        }
        assert_eq!(
            seen.load(Ordering::SeqCst),
            0,
            "a hardened client dialed the ambient HTTPS_PROXY — target DNS would \
             happen at that proxy, bypassing SsrfDnsResolver entirely"
        );
    }

    /// The property the OAuth token legs depend on: `build_egress_http` REFUSES
    /// a 3xx (it never re-sends the body to the redirect target), while
    /// `build_identity_http` follows one. On 307/308 the body is replayed
    /// verbatim, so "which client" decides whether an authorization code, PKCE
    /// verifier or refresh token can be walked to another host.
    #[tokio::test]
    async fn egress_client_refuses_a_307_that_identity_client_follows() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Second hop: counts the bodies it receives.
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let replayed = Arc::new(AtomicUsize::new(0));
        let replayed_bg = replayed.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut sock, _)) = target.accept().await {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if String::from_utf8_lossy(&buf[..n]).contains("secret=leaked") {
                    replayed_bg.fetch_add(1, Ordering::SeqCst);
                }
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}")
                    .await;
            }
        });
        // First hop: 307s to the second, preserving method + body.
        let hop = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hop_url = format!(
            "http://127.0.0.1:{}/token",
            hop.local_addr().unwrap().port()
        );
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut sock, _)) = hop.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        format!(
                            "HTTP/1.1 307 Temporary Redirect\r\nlocation: \
                             http://127.0.0.1:{target_port}/token\r\ncontent-length: 0\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });

        let policy = dev_policy(vec![]); // loopback http admitted, as in the e2e
        let post = |c: reqwest::Client, url: String| async move {
            c.post(url)
                .header("content-type", "application/x-www-form-urlencoded")
                .body("secret=leaked")
                .timeout(Duration::from_secs(5))
                .send()
                .await
        };
        // identity_http FOLLOWS: the body lands on the second host.
        let followed = post(build_identity_http(&policy), hop_url.clone()).await;
        assert!(
            followed.is_ok(),
            "the identity client should follow the 307"
        );
        assert_eq!(
            replayed.load(Ordering::SeqCst),
            1,
            "fixture is inert — the redirect-following client did not replay the body"
        );
        // egress_http does NOT: the 3xx is returned as-is, nothing is replayed.
        let res = post(build_egress_http(&policy), hop_url)
            .await
            .expect("a 3xx is a response, not a transport error");
        assert_eq!(res.status().as_u16(), 307);
        assert_eq!(
            replayed.load(Ordering::SeqCst),
            1,
            "the no-redirect client replayed the request body to the redirect target"
        );
    }

    #[test]
    fn dns_filter_range_logic() {
        use std::net::SocketAddr;
        let p = |s: &str| s.parse::<SocketAddr>().unwrap();
        let addrs = || {
            vec![
                p("93.184.216.34:443"),
                p("10.0.0.1:443"),
                p("127.0.0.1:443"),
                p("169.254.169.254:443"),
            ]
            .into_iter()
        };
        assert_eq!(
            filter_public_addrs(addrs(), false, &[]),
            vec![p("93.184.216.34:443")]
        );
        let out = filter_public_addrs(addrs(), true, &[]);
        assert!(out.contains(&p("93.184.216.34:443")));
        assert!(out.contains(&p("127.0.0.1:443")));
        assert!(!out.contains(&p("10.0.0.1:443")));
        assert!(!out.contains(&p("169.254.169.254:443")));
    }
}
