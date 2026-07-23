//! The production guard.
//!
//! A load harness is, by construction, a tool for degrading a service. This
//! module decides whether the thing on the other end of `--base-url` looks like
//! somebody's production, and refuses unless the operator says otherwise with
//! `--force-unsafe-target`.
//!
//! "LOOKS LIKE PRODUCTION" IS DEFINED ONLY FROM WHAT THE HARNESS CAN OBSERVE.
//! There is no configuration flag saying "this is prod" — that would be trivial
//! to forget. The four signals below are each independently sufficient:
//!
//!   1. the control plane is not on loopback — a load test worth running lives
//!      beside the deployment; a remote target is somebody else's service;
//!   2. the control plane is behind TLS — nothing in a local/CI deployment
//!      terminates TLS, so `https://` means a real ingress;
//!   3. the DATABASE is not on loopback — this is the signal that matters most
//!      in this repository: the seeding path writes `sessions` and `api_tokens`
//!      rows DIRECTLY, and the project's own database is a hosted Neon whose
//!      connection string sits in a dotenv that any shell can pick up. A remote
//!      database host is an unconditional stop;
//!   4. the admin token does not open `/v1` — under `FLUIDBOX_REQUIRE_SSO=1`
//!      the admin token is confined to `/v1/admin/*`, so a 401/403 from a
//!      routine `/v1` read means either a multi-user (hosted) deployment or a
//!      wrong token. BOTH readings say "do not load-test this blindly", which
//!      is why one signal covers them.
//!
//! The signals are reported individually rather than folded into a boolean, so
//! the refusal message can name exactly which fact triggered it.

use std::net::IpAddr;

/// Everything the guard is allowed to reason about. Constructed by the caller
/// from the CLI plus ONE cheap probe; the guard itself does no I/O, which is
/// what makes it a pure function with real tests.
#[derive(Clone, Debug)]
pub struct TargetFacts {
    pub control_scheme: String,
    pub control_host: String,
    /// `None` when the harness was not given a database URL (scenarios that
    /// need no seeding). Absence is NOT a signal — it is simply nothing to say.
    pub database_host: Option<String>,
    /// `Some(false)` = a routine `/v1` read with the admin token was refused.
    /// `None` = not probed (the caller could not reach the deployment at all,
    /// which it reports separately).
    pub admin_token_opens_v1: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProductionSignal {
    NonLoopbackControlPlane(String),
    TlsControlPlane,
    RemoteDatabase(String),
    AdminTokenConfined,
}

impl ProductionSignal {
    pub fn explain(&self) -> String {
        match self {
            ProductionSignal::NonLoopbackControlPlane(h) => format!(
                "the control plane is at a NON-loopback host ({h}) — this harness \
                 degrades whatever it points at"
            ),
            ProductionSignal::TlsControlPlane => {
                "the control plane is behind https — nothing in a local or CI deployment \
                 terminates TLS, so this is a real ingress"
                    .into()
            }
            ProductionSignal::RemoteDatabase(h) => format!(
                "the seeding database is at a NON-loopback host ({h}) — the seeding path \
                 INSERTs sessions and api_tokens rows directly, and this repository's own \
                 database is a hosted Postgres shared with real data"
            ),
            ProductionSignal::AdminTokenConfined => {
                "the admin token did not open a routine /v1 read — either \
                 FLUIDBOX_REQUIRE_SSO=1 (a multi-user deployment) or the token is wrong; \
                 neither is a safe load-test target"
                    .into()
            }
        }
    }
}

/// Loopback in the sense that matters here: a host that cannot be anybody
/// else's deployment.
///
/// `0.0.0.0` is deliberately NOT loopback. As a *target* it is a wildcard that
/// resolves to whatever the OS picks, so treating it as safe would defeat the
/// guard on exactly the machine that has a real interface.
pub fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    let h = h.to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// Every signal the facts support, in a stable order.
pub fn production_signals(f: &TargetFacts) -> Vec<ProductionSignal> {
    let mut out = Vec::new();
    if !is_loopback_host(&f.control_host) {
        out.push(ProductionSignal::NonLoopbackControlPlane(
            f.control_host.clone(),
        ));
    }
    if f.control_scheme.eq_ignore_ascii_case("https") {
        out.push(ProductionSignal::TlsControlPlane);
    }
    if let Some(db) = &f.database_host {
        if !is_loopback_host(db) {
            out.push(ProductionSignal::RemoteDatabase(db.clone()));
        }
    }
    if f.admin_token_opens_v1 == Some(false) {
        out.push(ProductionSignal::AdminTokenConfined);
    }
    out
}

/// Host component of a URL-ish string by TEXT — the naive parser the guard used
/// to trust. RETAINED ONLY IN TESTS, as the foil that [`effective_db_host`] /
/// [`effective_target_host`] are measured against: it cannot see a libpq `host=`
/// override or a userinfo/path trick, which is exactly the bypass those two close.
/// Production must never reason about the host from this function.
#[cfg(test)]
pub fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    // Strip userinfo (postgres URLs carry `user:password@`), then path/query.
    let authority = after_scheme
        .rsplit_once('@')
        .map(|(_, r)| r)
        .unwrap_or(after_scheme);
    let authority = authority
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(authority)
        .trim();
    if authority.is_empty() {
        return None;
    }
    // IPv6 literal: `[::1]:5432`.
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map(|(h, _)| h.to_ascii_lowercase());
    }
    let host = authority.split(':').next().unwrap_or(authority);
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

pub fn scheme_of(url: &str) -> String {
    url.split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .unwrap_or_else(|| "http".into())
}

/// The host the DATABASE connection will ACTUALLY reach, resolved the way sqlx
/// resolves it — which HONORS the libpq `host=`/`hostaddr=` query parameter that
/// OVERRIDES the URL authority. A textual parser ([`host_of`]) cannot see that
/// override: `postgres://prod_user:prod_pw@127.0.0.1/db?host=ep-prod.neon.tech`
/// reads loopback to the eye while sqlx dials prod, which is exactly how the guard
/// is bypassed. The guard must ask the SAME parser that opens the connection.
/// `None` only when the string does not parse as a Postgres URL at all.
pub fn effective_db_host(url: &str) -> Option<String> {
    use std::str::FromStr;
    sqlx::postgres::PgConnectOptions::from_str(url)
        .ok()
        .map(|o| o.get_host().to_ascii_lowercase())
}

/// The host the TARGET requests will ACTUALLY reach, resolved the way reqwest's
/// URL parser resolves it — so a userinfo/path trick like
/// `http://prod.example/x@127.0.0.1/..` (which a textual `rsplit('@')` misreads as
/// loopback but `url` normalizes to `prod.example`) is seen for what it is.
/// `None` when the string does not parse as an absolute URL with a host.
pub fn effective_target_host(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_facts() -> TargetFacts {
        TargetFacts {
            control_scheme: "http".into(),
            control_host: "127.0.0.1".into(),
            database_host: Some("127.0.0.1".into()),
            admin_token_opens_v1: Some(true),
        }
    }

    #[test]
    fn a_fully_local_deployment_raises_no_signal() {
        assert!(production_signals(&local_facts()).is_empty());
    }

    #[test]
    fn each_signal_fires_on_its_own() {
        let mut f = local_facts();
        f.control_host = "fluidbox.example.com".into();
        assert_eq!(
            production_signals(&f),
            vec![ProductionSignal::NonLoopbackControlPlane(
                "fluidbox.example.com".into()
            )]
        );

        let mut f = local_facts();
        f.control_scheme = "https".into();
        assert_eq!(
            production_signals(&f),
            vec![ProductionSignal::TlsControlPlane]
        );

        let mut f = local_facts();
        f.database_host = Some("ep-cool-name.us-east-2.aws.neon.tech".into());
        assert_eq!(
            production_signals(&f),
            vec![ProductionSignal::RemoteDatabase(
                "ep-cool-name.us-east-2.aws.neon.tech".into()
            )]
        );

        let mut f = local_facts();
        f.admin_token_opens_v1 = Some(false);
        assert_eq!(
            production_signals(&f),
            vec![ProductionSignal::AdminTokenConfined]
        );
    }

    /// The signal this repository actually needs: a loopback control plane
    /// pointed at a hosted Neon is the shape of every accidental
    /// "I sourced .env first" run, and it MUST still refuse.
    #[test]
    fn a_local_control_plane_with_a_remote_database_still_refuses() {
        let f = TargetFacts {
            control_scheme: "http".into(),
            control_host: "127.0.0.1".into(),
            database_host: Some("ep-x-y-z.aws.neon.tech".into()),
            admin_token_opens_v1: Some(true),
        };
        let s = production_signals(&f);
        assert_eq!(s.len(), 1);
        assert!(matches!(s[0], ProductionSignal::RemoteDatabase(_)));
    }

    #[test]
    fn an_absent_database_is_not_a_signal() {
        let mut f = local_facts();
        f.database_host = None;
        assert!(production_signals(&f).is_empty());
    }

    #[test]
    fn an_unprobed_admin_token_is_not_a_signal() {
        let mut f = local_facts();
        f.admin_token_opens_v1 = None;
        assert!(production_signals(&f).is_empty());
    }

    #[test]
    fn loopback_recognition() {
        for h in [
            "127.0.0.1",
            "127.9.9.9",
            "localhost",
            "LOCALHOST",
            "::1",
            "[::1]",
            "db.localhost",
        ] {
            assert!(is_loopback_host(h), "{h} should be loopback");
        }
        for h in [
            "0.0.0.0",
            "10.0.0.5",
            "192.168.1.10",
            "host.docker.internal",
            "example.com",
            "",
        ] {
            assert!(!is_loopback_host(h), "{h} must NOT be loopback");
        }
    }

    #[test]
    fn host_extraction_covers_http_and_postgres_shapes() {
        assert_eq!(
            host_of("http://127.0.0.1:8787").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            host_of("https://fluid.example.com/v1").as_deref(),
            Some("fluid.example.com")
        );
        assert_eq!(
            host_of("postgres://user:p%40ss@ep-a-b.aws.neon.tech:5432/db?sslmode=require")
                .as_deref(),
            Some("ep-a-b.aws.neon.tech")
        );
        assert_eq!(
            host_of("postgres://postgres:postgres@127.0.0.1:5432/fluidbox_scale").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(host_of("http://[::1]:8787/v1").as_deref(), Some("::1"));
        assert_eq!(host_of("").as_deref(), None);
        assert_eq!(scheme_of("https://x/y"), "https");
        assert_eq!(scheme_of("127.0.0.1:8787"), "http");
    }

    /// A password containing an `@` must not shift the parsed host — the rsplit
    /// on `@` is what makes that true, and getting it wrong would read the
    /// password's tail as the hostname and (being unparseable) refuse. Assert
    /// the safe-and-correct answer explicitly.
    #[test]
    fn a_password_with_an_at_sign_does_not_confuse_the_host() {
        assert_eq!(
            host_of("postgres://u:p@ss@127.0.0.1:5432/db").as_deref(),
            Some("127.0.0.1")
        );
    }

    /// THE BYPASS `host_of` COULD NOT SEE: libpq's `host=` query parameter
    /// OVERRIDES the URL authority, so sqlx dials prod while the authority reads
    /// loopback. `effective_db_host` must report the endpoint sqlx will actually
    /// connect to, so the `RemoteDatabase` signal fires.
    #[test]
    fn a_libpq_host_override_is_seen_as_the_real_database_host() {
        let sneaky =
            "postgres://prod_user:prod_pw@127.0.0.1/fluidbox?host=ep-production.us-east-2.aws.neon.tech&sslmode=require";
        // The textual parser is fooled (this is the bug being closed)…
        assert_eq!(host_of(sneaky).as_deref(), Some("127.0.0.1"));
        // …but the connector-faithful parser is not.
        assert_eq!(
            effective_db_host(sneaky).as_deref(),
            Some("ep-production.us-east-2.aws.neon.tech")
        );
        assert!(!is_loopback_host(&effective_db_host(sneaky).unwrap()));
        // A plain local URL still reads loopback.
        assert_eq!(
            effective_db_host("postgres://postgres:postgres@127.0.0.1:5432/fluidbox_scale")
                .as_deref(),
            Some("127.0.0.1")
        );
    }

    /// THE BYPASS `host_of` COULD NOT SEE on the TARGET side: a userinfo/path
    /// trick where the real authority is prod but `rsplit('@')` reads loopback.
    /// `effective_target_host` parses it the way reqwest will and sees prod.
    #[test]
    fn a_userinfo_path_trick_is_seen_as_the_real_target_host() {
        let sneaky = "http://production.example/x@127.0.0.1/..";
        assert_eq!(host_of(sneaky).as_deref(), Some("127.0.0.1")); // fooled
        assert_eq!(
            effective_target_host(sneaky).as_deref(),
            Some("production.example")
        ); // not fooled
        assert_eq!(
            effective_target_host("http://127.0.0.1:8787").as_deref(),
            Some("127.0.0.1")
        );
    }
}
