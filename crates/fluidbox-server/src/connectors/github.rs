//! The GitHub connector — the ONLY module that knows GitHub's shapes
//! (design §6.3; GitHub is the first tenant of the connector seam, not the
//! feature). Duties here: (1) verify webhook deliveries, (2) normalize PR
//! events, (3) resolve the event workspace; matching stays generic in
//! events.rs; (5) publish comments/checks (added with the publisher).

use super::{NormalizeCtx, NormalizedEvent, VerifiedDelivery};
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use fluidbox_core::spec::{CheckoutMode, ResultDestination, TrustTier, WorkspaceSpec};
use serde_json::{json, Value};
use std::collections::BTreeMap;

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

    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("hmac accepts any key length");
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
        return Err(format!("payload repository '{repository}' is not owner/name"));
    }

    let pr = &payload["pull_request"];
    let pr_number = pr["number"].as_i64().ok_or("payload has no pull_request.number")?;
    let head_sha = pr["head"]["sha"]
        .as_str()
        .ok_or("payload has no pull_request.head.sha")?
        .to_string();
    if !valid_sha(&head_sha) {
        return Err(format!("payload head sha '{head_sha}' is not a commit sha"));
    }
    let pr_title = pr["title"].as_str().unwrap_or("").to_string();
    let pr_url = pr["html_url"].as_str().unwrap_or("").to_string();
    let pr_author = pr["user"]["login"].as_str().unwrap_or("unknown").to_string();
    let head_ref = pr["head"]["ref"].as_str().unwrap_or("").to_string();
    let base_sha = pr["base"]["sha"].as_str().unwrap_or("").to_string();
    let base_ref = pr["base"]["ref"].as_str().unwrap_or("").to_string();

    // Fork detection keys on repo identity, and FAILS TOWARD FORK: a payload
    // that hides the head repo gets the untrusted tier, never the trusted one.
    let fork = match (pr["head"]["repo"]["id"].as_i64(), pr["base"]["repo"]["id"].as_i64()) {
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
        let upper = format!("sha256={}", sig.trim_start_matches("sha256=").to_uppercase());
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
        assert_eq!(ev.context["head_sha"], "abcdef0123456789abcdef0123456789abcdef01");
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
        assert!(normalize("pull_request", &pr_payload("labeled", 7, 7), &ctx())
            .unwrap()
            .is_none());
        assert!(normalize("ping", &json!({"zen": "x"}), &ctx()).unwrap().is_none());
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
