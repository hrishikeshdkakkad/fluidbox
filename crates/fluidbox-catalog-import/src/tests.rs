use super::*;

/// Parse an open-connector provider from the camelCase JSON shape it emits to
/// `catalog/apps/<service>.json`.
fn provider(v: Value) -> OcProvider {
    serde_json::from_value(v).expect("fixture parses as OcProvider")
}

/// Parse a Registry entry from the `GET /v0/servers` `servers[]` shape.
fn entry(v: Value) -> RegistryEntry {
    serde_json::from_value(v).expect("fixture parses as RegistryEntry")
}

fn official(status: &str, is_latest: bool) -> Value {
    json!({ "io.modelcontextprotocol.registry/official": { "status": status, "isLatest": is_latest } })
}

fn pins() -> Pins {
    Pins {
        registry_ref: Some("2026-07-14:cursorX".into()),
        open_connector_sha: Some("abc123def456".into()),
    }
}

// ─── MCP Registry mapping ─────────────────────────────────────────────────

#[test]
fn registry_streamable_http_remote_is_connectable() {
    let out = build(
        &[entry(json!({
            "server": {
                "name": "ac.inference.sh/mcp",
                "title": "inference.sh",
                "description": "Run 150+ AI apps.",
                "version": "1.0.0",
                "remotes": [{ "type": "streamable-http", "url": "https://api.inference.sh/mcp" }]
            },
            "_meta": official("active", true)
        }))],
        vec![],
        &pins(),
    );
    assert!(out.rows.len() == 1, "one row; drops={:?}", out.dropped);
    let r = &out.rows[0];
    assert_eq!(r.slug, "inference-sh");
    assert_eq!(r.name, "inference.sh");
    assert_eq!(
        r.transport, "streamable_http",
        "remote URL → connectable now"
    );
    assert_eq!(r.url.as_deref(), Some("https://api.inference.sh/mcp"));
    assert_eq!(r.egress, vec!["api.inference.sh"]);
    assert_eq!(
        r.auth_mode, "none",
        "probe decides auth at Connect (plan O3)"
    );
    assert_eq!(r.source, "mcp-registry");
    assert_eq!(r.status.as_deref(), Some("active"));
}

#[test]
fn registry_packaged_only_imports_reference_only() {
    let out = build(
        &[entry(json!({
            "server": {
                "name": "io.github.acme/cli",
                "title": "Acme CLI",
                "description": "A packaged server, no remote.",
                "version": "2.0.0",
                "websiteUrl": "https://acme.example"
            },
            "_meta": official("active", true)
        }))],
        vec![],
        &pins(),
    );
    let r = &out.rows[0];
    assert_eq!(r.transport, "rest_action", "no remote URL → reference-only");
    assert_eq!(
        r.url.as_deref(),
        Some("https://acme.example"),
        "website is informational"
    );
}

#[test]
fn registry_non_active_is_skipped() {
    let out = build(
        &[entry(json!({
            "server": { "name": "x.y/z", "title": "Z", "version": "1.0.0",
                        "remotes": [{ "type": "streamable-http", "url": "https://z.test/mcp" }] },
            "_meta": official("deprecated", true)
        }))],
        vec![],
        &pins(),
    );
    assert!(out.rows.is_empty(), "deprecated server must not import");
    assert_eq!(out.dropped.len(), 1);
    assert!(out.dropped[0].reason.contains("no active version"));
}

#[test]
fn registry_keeps_only_the_latest_version() {
    let out = build(
        &[
            entry(json!({
                "server": { "name": "dup/srv", "title": "Srv", "version": "1.0.0",
                            "remotes": [{ "type": "streamable-http", "url": "https://old.test/mcp" }] },
                "_meta": official("active", false)
            })),
            entry(json!({
                "server": { "name": "dup/srv", "title": "Srv", "version": "1.10.0",
                            "remotes": [{ "type": "streamable-http", "url": "https://new.test/mcp" }] },
                "_meta": official("active", true)
            })),
        ],
        vec![],
        &pins(),
    );
    assert_eq!(out.rows.len(), 1, "one row per server name");
    assert_eq!(out.rows[0].url.as_deref(), Some("https://new.test/mcp"));
}

#[test]
fn registry_poisoned_description_drops_the_server() {
    let out = build(
        &[entry(json!({
            "server": { "name": "evil/srv", "title": "Evil", "version": "1.0.0",
                        "description": "sneaky\u{202E}reversed",
                        "remotes": [{ "type": "streamable-http", "url": "https://e.test/mcp" }] },
            "_meta": official("active", true)
        }))],
        vec![],
        &pins(),
    );
    assert!(out.rows.is_empty());
    assert!(out.dropped[0].reason.contains("poison"));
}

// ─── open-connector mapping (supplement) ──────────────────────────────────

#[test]
fn open_connector_is_always_reference_only() {
    let out = build(
        &[],
        vec![provider(json!({
            "service": "asana", "displayName": "Asana",
            "description": "Tasks and projects.", "categories": ["Productivity"],
            "authTypes": ["oauth2"], "auth": [{ "type": "oauth2" }],
            "homepageUrl": "https://asana.com",
            "actions": [
                { "name": "list_workspaces", "requiredScopes": ["workspaces:read"] },
                { "name": "create_project", "requiredScopes": ["projects:write", "workspaces:read"] }
            ]
        }))],
        &pins(),
    );
    let r = &out.rows[0];
    assert_eq!(r.slug, "asana");
    assert_eq!(r.transport, "rest_action", "open-connector never hosts MCP");
    assert_eq!(r.auth_mode, "oauth");
    assert_eq!(r.scopes, vec!["projects:write", "workspaces:read"]);
    assert_eq!(r.source, "open-connector");
    assert_eq!(r.source_ref, "abc123def456");
    assert!(r.status.is_none());
}

#[test]
fn open_connector_api_key_defaults_bearer_and_keeps_placeholder() {
    let out = build(
        &[],
        vec![provider(json!({
            "service": "abstract", "displayName": "Abstract",
            "authTypes": ["api_key"], "auth": [{ "type": "api_key", "placeholder": "abstract_key_…" }],
            "homepageUrl": "https://www.abstractapi.com/"
        }))],
        &pins(),
    );
    let r = &out.rows[0];
    assert_eq!(r.auth_mode, "api_key");
    assert_eq!(r.auth_hints["scheme"], "Bearer");
    assert_eq!(r.auth_hints["placeholder"], "abstract_key_…");
    assert_eq!(r.egress, vec!["www.abstractapi.com"]);
}

#[test]
fn open_connector_custom_credential_maps_to_api_key() {
    let out = build(
        &[],
        vec![provider(json!({
            "service": "s", "displayName": "S",
            "authTypes": ["custom_credential"], "auth": [{ "type": "custom_credential", "fields": [] }]
        }))],
        &pins(),
    );
    assert_eq!(out.rows[0].auth_mode, "api_key");
}

#[test]
fn open_connector_missing_auth_drops_provider() {
    let out = build(
        &[],
        vec![provider(
            json!({ "service": "mystery", "displayName": "Mystery" }),
        )],
        &pins(),
    );
    assert!(out.rows.is_empty());
    assert_eq!(out.dropped[0].reason, "no resolvable auth_mode");
}

#[test]
fn open_connector_poisoned_description_drops_provider() {
    let out = build(
        &[],
        vec![provider(json!({
            "service": "evil", "displayName": "Evil",
            "description": "totally\u{200B} benign",
            "authTypes": ["api_key"], "auth": [{ "type": "api_key" }]
        }))],
        &pins(),
    );
    assert!(out.rows.is_empty());
    assert!(out.dropped[0].reason.contains("poison"));
}

#[test]
fn open_connector_slug_collision_gets_a_numeric_suffix() {
    let out = build(
        &[],
        vec![
            provider(
                json!({ "service": "my.tool", "displayName": "A", "authTypes": ["no_auth"], "auth": [{"type":"no_auth"}] }),
            ),
            provider(
                json!({ "service": "my_tool", "displayName": "B", "authTypes": ["no_auth"], "auth": [{"type":"no_auth"}] }),
            ),
        ],
        &pins(),
    );
    let slugs: Vec<&str> = out.rows.iter().map(|r| r.slug.as_str()).collect();
    assert!(slugs.contains(&"my-tool"), "one keeps the base: {slugs:?}");
    assert!(
        slugs.contains(&"my-tool-2"),
        "the collision is suffixed: {slugs:?}"
    );
}

// ─── merge / dedup across sources ─────────────────────────────────────────

#[test]
fn registry_supersedes_open_connector_on_slug_collision() {
    // Both sources describe "stripe": the Registry (connectable) wins the slug,
    // and the open-connector card is dropped (plan D6).
    let out = build(
        &[entry(json!({
            "server": { "name": "com.stripe/mcp", "title": "Stripe", "version": "1.0.0",
                        "remotes": [{ "type": "streamable-http", "url": "https://mcp.stripe.com" }] },
            "_meta": official("active", true)
        }))],
        vec![provider(json!({
            "service": "stripe", "displayName": "Stripe",
            "authTypes": ["api_key"], "auth": [{ "type": "api_key" }]
        }))],
        &pins(),
    );
    let stripe_rows: Vec<&CatalogRow> = out.rows.iter().filter(|r| r.slug == "stripe").collect();
    assert_eq!(stripe_rows.len(), 1, "exactly one 'stripe' row");
    assert_eq!(stripe_rows[0].source, "mcp-registry");
    assert_eq!(stripe_rows[0].transport, "streamable_http");
    assert!(
        out.dropped
            .iter()
            .any(|d| d.service == "stripe" && d.reason.contains("superseded")),
        "the open-connector stripe is dropped as superseded: {:?}",
        out.dropped
    );
}

#[test]
fn rows_are_sorted_by_slug_across_sources() {
    let out = build(
        &[entry(json!({
            "server": { "name": "z/srv", "title": "Zeta", "version": "1.0.0",
                        "remotes": [{ "type": "streamable-http", "url": "https://z.test/mcp" }] },
            "_meta": official("active", true)
        }))],
        vec![provider(json!({
            "service": "alpha", "displayName": "Alpha",
            "authTypes": ["no_auth"], "auth": [{ "type": "no_auth" }]
        }))],
        &pins(),
    );
    let slugs: Vec<&str> = out.rows.iter().map(|r| r.slug.as_str()).collect();
    assert_eq!(slugs, vec!["alpha", "zeta"]);
}

// ─── SQL emission ─────────────────────────────────────────────────────────

#[test]
fn tool_hints_match_the_curated_shape() {
    let out = build(
        &[],
        vec![provider(json!({
            "service": "acme", "displayName": "Acme",
            "authTypes": ["api_key"], "auth": [{ "type": "api_key" }]
        }))],
        &pins(),
    );
    let hints = out.rows[0].tool_hints.as_array().unwrap();
    assert_eq!(hints.len(), 4);
    assert_eq!(hints[0]["pattern"], "mcp__acme__*get*");
    assert_eq!(hints[0]["action"], "allow");
    assert_eq!(hints[3]["pattern"], "mcp__acme__*");
    assert_eq!(hints[3]["action"], "approve");
}

#[test]
fn emitted_sql_is_shaped_and_deterministic() {
    let make = || {
        build(
            &[entry(json!({
                "server": { "name": "b/srv", "title": "Bravo", "version": "1.0.0",
                            "description": "Bravo it's fine",
                            "remotes": [{ "type": "streamable-http", "url": "https://bravo.test/mcp" }] },
                "_meta": official("active", true)
            }))],
            vec![provider(json!({
                "service": "alpha", "displayName": "Alpha",
                "authTypes": ["oauth2"], "auth": [{ "type": "oauth2" }]
            }))],
            &pins(),
        )
    };
    let sql1 = emit_migration(&make().rows, &pins());
    let sql2 = emit_migration(&make().rows, &pins());
    assert_eq!(sql1, sql2, "same input + pins → byte-identical migration");

    // Rows sorted by slug (alpha before bravo).
    assert!(sql1.find("'alpha'").unwrap() < sql1.find("'bravo'").unwrap());
    assert!(sql1.contains("insert into connector_catalog"));
    assert!(sql1.contains("'community'"));
    assert!(sql1.contains("pinned 2026-07-14:cursorX"));
    assert!(sql1.contains("pinned abc123def456"));
    assert!(sql1.contains("on conflict (slug) do update set"));
    assert!(sql1.contains("in ('mcp-registry', 'open-connector')"));
    assert!(sql1.contains("jsonb_build_object('source','mcp-registry'"));
    assert!(
        sql1.contains("'status','active'"),
        "registry rows carry status"
    );
    assert!(sql1.contains("jsonb_build_object('source','open-connector'"));
    assert!(sql1.contains("'imported_at',now()"));
    assert!(
        !sql1.contains("imported_at\":\""),
        "no literal imported_at value"
    );
}

#[test]
fn single_quote_in_a_field_is_sql_escaped() {
    let out = build(
        &[],
        vec![provider(json!({
            "service": "quoter", "displayName": "O'Brien's Tool",
            "authTypes": ["no_auth"], "auth": [{ "type": "no_auth" }]
        }))],
        &pins(),
    );
    let sql = emit_migration(&out.rows, &pins());
    assert!(sql.contains("'O''Brien''s Tool'"), "quotes doubled: {sql}");
}

#[test]
fn empty_build_emits_a_safe_noop_migration() {
    let sql = emit_migration(&[], &pins());
    assert!(sql.contains("no entries survived screening"));
    assert!(!sql.contains("insert into connector_catalog"));
}

#[test]
fn registry_page_parses_and_paginates() {
    let page: RegistryPage = serde_json::from_value(json!({
        "servers": [{
            "server": { "name": "a/b", "title": "AB", "version": "1.0.0",
                        "remotes": [{ "type": "streamable-http", "url": "https://ab.test/mcp" }] },
            "_meta": official("active", true)
        }],
        "metadata": { "nextCursor": "a/b:1.0.0", "count": 1 }
    }))
    .unwrap();
    assert_eq!(page.servers.len(), 1);
    assert_eq!(page.metadata.next_cursor.as_deref(), Some("a/b:1.0.0"));
}
