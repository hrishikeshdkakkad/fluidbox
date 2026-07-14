use super::*;

/// Parse a provider from the same camelCase JSON shape open-connector emits to
/// `catalog/apps/<service>.json`, so fixtures exercise the real wire format.
fn provider(v: Value) -> OcProvider {
    serde_json::from_value(v).expect("fixture parses as OcProvider")
}

const SHA: &str = "abc123def456";

#[test]
fn oauth2_provider_imports_as_reference_only_oauth() {
    let out = transform(
        vec![provider(json!({
            "service": "asana",
            "displayName": "Asana",
            "description": "Tasks and projects.",
            "categories": ["Productivity"],
            "authTypes": ["oauth2"],
            "auth": [{ "type": "oauth2", "authorizationUrl": "https://app.asana.com/-/oauth_authorize" }],
            "homepageUrl": "https://asana.com",
            "actions": [
                { "name": "list_workspaces", "requiredScopes": ["workspaces:read"] },
                { "name": "create_project", "requiredScopes": ["projects:write", "workspaces:read"] }
            ]
        }))],
        HOSTED_MCP,
    );
    assert!(
        out.dropped.is_empty(),
        "clean provider must not drop: {:?}",
        out.dropped
    );
    let r = &out.rows[0];
    assert_eq!(r.slug, "asana");
    assert_eq!(r.name, "Asana");
    assert_eq!(r.auth_mode, "oauth");
    assert_eq!(
        r.transport, "rest_action",
        "no hosted MCP endpoint → reference-only"
    );
    assert_eq!(r.url.as_deref(), Some("https://asana.com"));
    assert_eq!(r.egress, vec!["asana.com"]);
    // Scopes are the de-duplicated, sorted union across actions.
    assert_eq!(r.scopes, vec!["projects:write", "workspaces:read"]);
    // oauth carries no static header hint.
    assert_eq!(r.auth_hints, json!({}));
}

#[test]
fn api_key_provider_defaults_bearer_and_keeps_placeholder() {
    let out = transform(
        vec![provider(json!({
            "service": "abstract",
            "displayName": "Abstract",
            "authTypes": ["api_key"],
            "auth": [{ "type": "api_key", "placeholder": "abstract_key_…" }],
            "homepageUrl": "https://www.abstractapi.com/",
            "actions": []
        }))],
        HOSTED_MCP,
    );
    let r = &out.rows[0];
    assert_eq!(r.auth_mode, "api_key");
    assert_eq!(r.auth_hints["scheme"], "Bearer");
    assert_eq!(r.auth_hints["placeholder"], "abstract_key_…");
    assert_eq!(r.transport, "rest_action");
    assert_eq!(r.egress, vec!["www.abstractapi.com"]);
}

#[test]
fn custom_credential_maps_to_api_key() {
    let out = transform(
        vec![provider(json!({
            "service": "sentry_like",
            "displayName": "Sentry-like",
            "authTypes": ["custom_credential"],
            "auth": [{ "type": "custom_credential", "fields": [] }],
            "actions": []
        }))],
        HOSTED_MCP,
    );
    assert_eq!(out.rows[0].auth_mode, "api_key");
}

#[test]
fn no_auth_provider_imports_as_none() {
    let out = transform(
        vec![provider(json!({
            "service": "public_holidays",
            "displayName": "Public Holidays",
            "authTypes": ["no_auth"],
            "auth": [{ "type": "no_auth" }],
            "actions": []
        }))],
        HOSTED_MCP,
    );
    let r = &out.rows[0];
    assert_eq!(r.auth_mode, "none");
    assert_eq!(r.auth_hints, json!({}));
}

#[test]
fn poisoned_description_drops_the_whole_provider() {
    let out = transform(
        vec![provider(json!({
            "service": "evil",
            "displayName": "Evil",
            // zero-width space smuggled into the model-visible description.
            "description": "totally\u{200B} benign",
            "authTypes": ["api_key"],
            "auth": [{ "type": "api_key" }],
            "actions": []
        }))],
        HOSTED_MCP,
    );
    assert!(out.rows.is_empty(), "poisoned provider must not smuggle in");
    assert_eq!(out.dropped.len(), 1);
    assert_eq!(out.dropped[0].service, "evil");
    assert!(out.dropped[0].reason.contains("poison"));
}

#[test]
fn missing_auth_drops_provider() {
    let out = transform(
        vec![provider(json!({
            "service": "mystery",
            "displayName": "Mystery",
            "actions": []
        }))],
        HOSTED_MCP,
    );
    assert!(out.rows.is_empty());
    assert_eq!(out.dropped[0].reason, "no resolvable auth_mode");
}

#[test]
fn slug_collision_gets_a_numeric_suffix() {
    // Two distinct services that slugify to the same base.
    let out = transform(
        vec![
            provider(
                json!({ "service": "my.tool", "displayName": "A", "authTypes": ["no_auth"], "auth": [{"type":"no_auth"}] }),
            ),
            provider(
                json!({ "service": "my_tool", "displayName": "B", "authTypes": ["no_auth"], "auth": [{"type":"no_auth"}] }),
            ),
        ],
        HOSTED_MCP,
    );
    let slugs: Vec<&str> = out.rows.iter().map(|r| r.slug.as_str()).collect();
    assert!(
        slugs.contains(&"my-tool"),
        "one keeps the base slug: {slugs:?}"
    );
    assert!(
        slugs.contains(&"my-tool-2"),
        "the collision gets suffixed: {slugs:?}"
    );
}

#[test]
fn hosted_allowlist_marks_a_provider_connectable() {
    let hosted = &[("linear-oss", "https://mcp.linear-oss.test/mcp")][..];
    let out = transform(
        vec![provider(json!({
            "service": "linear_oss",
            "displayName": "Linear OSS",
            "authTypes": ["oauth2"],
            "auth": [{ "type": "oauth2" }],
            "homepageUrl": "https://linear-oss.test"
        }))],
        hosted,
    );
    let r = &out.rows[0];
    assert_eq!(r.slug, "linear-oss");
    assert_eq!(
        r.transport, "streamable_http",
        "allowlisted → connectable now"
    );
    assert_eq!(r.url.as_deref(), Some("https://mcp.linear-oss.test/mcp"));
    assert_eq!(r.egress, vec!["mcp.linear-oss.test"]);
}

#[test]
fn tool_hints_match_the_curated_shape() {
    let out = transform(
        vec![provider(json!({
            "service": "acme",
            "displayName": "Acme",
            "authTypes": ["api_key"],
            "auth": [{ "type": "api_key" }]
        }))],
        HOSTED_MCP,
    );
    let hints = out.rows[0].tool_hints.as_array().unwrap();
    assert_eq!(hints.len(), 4);
    assert_eq!(hints[0]["pattern"], "mcp__acme__*get*");
    assert_eq!(hints[0]["action"], "allow");
    assert_eq!(hints[3]["pattern"], "mcp__acme__*");
    assert_eq!(hints[3]["action"], "approve");
}

#[test]
fn emitted_sql_is_valid_shaped_and_deterministic() {
    let providers = || {
        vec![
            provider(json!({
                "service": "bravo", "displayName": "Bravo",
                "authTypes": ["api_key"], "auth": [{ "type": "api_key", "placeholder": "bk_…" }],
                "homepageUrl": "https://bravo.test", "description": "Bravo it's fine",
                "actions": [{ "name": "get_thing", "requiredScopes": ["read"] }]
            })),
            provider(json!({
                "service": "alpha", "displayName": "Alpha",
                "authTypes": ["oauth2"], "auth": [{ "type": "oauth2" }]
            })),
        ]
    };
    let sql1 = emit_migration(&transform(providers(), HOSTED_MCP).rows, SHA);
    let sql2 = emit_migration(&transform(providers(), HOSTED_MCP).rows, SHA);
    assert_eq!(sql1, sql2, "same input + SHA → byte-identical migration");

    // Rows are sorted by slug (alpha before bravo).
    assert!(sql1.find("'alpha'").unwrap() < sql1.find("'bravo'").unwrap());
    // Structural expectations.
    assert!(sql1.contains("insert into connector_catalog"));
    assert!(sql1.contains("'community'"));
    assert!(sql1.contains("Pinned commit: abc123def456"));
    assert!(sql1.contains("on conflict (slug) do update set"));
    assert!(sql1.contains("where connector_catalog.provenance->>'source' = 'open-connector'"));
    assert!(sql1.contains("jsonb_build_object('source','open-connector'"));
    assert!(
        sql1.contains("'imported_at',now()"),
        "imported_at is apply-time now()"
    );
    // No raw generation timestamp is baked in.
    assert!(
        !sql1.contains("imported_at\":\""),
        "no literal imported_at value"
    );
}

#[test]
fn single_quote_in_a_field_is_sql_escaped() {
    let out = transform(
        vec![provider(json!({
            "service": "quoter", "displayName": "O'Brien's Tool",
            "authTypes": ["no_auth"], "auth": [{ "type": "no_auth" }]
        }))],
        HOSTED_MCP,
    );
    let sql = emit_migration(&out.rows, SHA);
    assert!(sql.contains("'O''Brien''s Tool'"), "quotes doubled: {sql}");
}

#[test]
fn empty_batch_emits_a_safe_noop_migration() {
    let sql = emit_migration(&[], SHA);
    assert!(sql.contains("no providers survived screening"));
    assert!(!sql.contains("insert into connector_catalog"));
}

#[test]
fn slugify_and_valid_slug_agree_with_catalog_rules() {
    assert_eq!(slugify("My_Cool.Service"), "my-cool-service");
    assert!(valid_slug("github"));
    assert!(!valid_slug("Under_Score"));
    assert!(!valid_slug(""));
    assert!(slugify(&"x".repeat(200)).len() <= 58);
}
