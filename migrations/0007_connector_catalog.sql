-- Phase 5.5 of "borrow the agent, on demand": connector catalog & OAuth custody.
-- (docs/handovers/2026-07-11-connector-catalog-session-brief.md §B;
--  plan: docs/superpowers/plans/2026-07-11-phase5-5-connector-catalog-oauth.md)
--
-- Settled 2026-07-11 (user, at the boundary): both increments one phase;
-- catalog is API-ONLY (rows managed via /v1/catalog; the curated seed ships
-- in THIS migration — no seed file, no boot-sync); generic confidential-
-- client support now (Slack seed deferred to Phase 7; Notion seeded);
-- catalog Connect auto-registers the bundle.

-- The catalog is GLOBAL (tenant-less) reference data — a curated superset of
-- the official MCP registry's server.json, import-friendly by design. It is
-- UNTRUSTED input everywhere it is consumed: tool_hints are policy-default
-- SEEDS for display/suggestion, never enforcement (the permission gate stays
-- the judge). Tenant-less also keeps this migration self-contained: the
-- default tenant row is boot-seeded AFTER migrations run.
create table connector_catalog (
    id uuid primary key default gen_random_uuid(),
    slug text not null unique,          -- becomes the server alias AND the default bundle name
    name text not null,
    icon text,                          -- short glyph for the dashboard grid card
    description text,
    categories jsonb not null default '[]',
    tier text not null default 'custom',                 -- verified | community | custom
    url text,                                            -- remote MCP endpoint (null for in-image entries)
    transport text not null default 'streamable_http',   -- streamable_http | stdio
    auth_mode text not null default 'none',              -- none | api_key | oauth
    auth_hints jsonb not null default '{}',              -- {header_name?, scheme?, composite?, key_url?, placeholder?}
    scopes jsonb not null default '[]',
    egress jsonb not null default '[]',                  -- informational host list for the card
    tool_hints jsonb not null default '[]',              -- UNTRUSTED policy-default seeds: [{pattern, action, note}]
    sandbox_launch jsonb,                                -- in-image entries: {command, args, tools[]}
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- Curated remote connectors (headless-ready today over the existing mcp_http
-- flavor, except Notion which is OAuth-only — increment 2's showcase).
insert into connector_catalog (slug, name, icon, description, categories, tier, url, auth_mode, auth_hints, egress, tool_hints) values
 ('github', 'GitHub', '🐙',
  'Repos, issues and pull requests via the hosted GitHub MCP server. Use a PAT — App installation tokens are not accepted.',
  '["dev","vcs"]', 'verified', 'https://api.githubcopilot.com/mcp/', 'api_key',
  '{"scheme":"Bearer","placeholder":"ghp_… (personal access token)","key_url":"https://github.com/settings/tokens"}',
  '["api.githubcopilot.com"]',
  '[{"pattern":"mcp__github__list_*","action":"allow","note":"read"},{"pattern":"mcp__github__get_*","action":"allow","note":"read"},{"pattern":"mcp__github__search_*","action":"allow","note":"read"},{"pattern":"mcp__github__*","action":"approve","note":"writes (create/update/merge) should ask"}]'),
 ('stripe', 'Stripe', '💳',
  'Payments data via mcp.stripe.com. A restricted API key is strongly recommended.',
  '["payments"]', 'verified', 'https://mcp.stripe.com', 'api_key',
  '{"scheme":"Bearer","placeholder":"rk_… (restricted key)","key_url":"https://dashboard.stripe.com/apikeys"}',
  '["mcp.stripe.com"]',
  '[{"pattern":"mcp__stripe__list_*","action":"allow","note":"read"},{"pattern":"mcp__stripe__get_*","action":"allow","note":"read"},{"pattern":"mcp__stripe__*","action":"approve","note":"money movement should ask"}]'),
 ('linear', 'Linear', '📐',
  'Issues and projects via mcp.linear.app.',
  '["project-mgmt"]', 'verified', 'https://mcp.linear.app/mcp', 'api_key',
  '{"scheme":"Bearer","placeholder":"lin_api_…","key_url":"https://linear.app/settings/api"}',
  '["mcp.linear.app"]',
  '[{"pattern":"mcp__linear__list_*","action":"allow","note":"read"},{"pattern":"mcp__linear__get_*","action":"allow","note":"read"},{"pattern":"mcp__linear__*","action":"approve"}]'),
 ('sentry', 'Sentry', '🛰',
  'Issues and events via mcp.sentry.dev. NOTE: authenticates with a custom header (Sentry-Bearer), not Authorization.',
  '["observability"]', 'verified', 'https://mcp.sentry.dev/mcp', 'api_key',
  '{"header_name":"Sentry-Bearer","scheme":"","placeholder":"sntrys_… (sent as Sentry-Bearer: <token>)"}',
  '["mcp.sentry.dev"]',
  '[{"pattern":"mcp__sentry__find_*","action":"allow","note":"read"},{"pattern":"mcp__sentry__*","action":"approve"}]'),
 ('atlassian', 'Atlassian', '🧩',
  'Jira and Confluence (cloud only) via mcp.atlassian.com. Paste email:api_token — sent as HTTP Basic.',
  '["project-mgmt","docs"]', 'verified', 'https://mcp.atlassian.com/v1/mcp', 'api_key',
  '{"scheme":"Basic","composite":"email:api_token","placeholder":"you@company.com:ATATT…","key_url":"https://id.atlassian.com/manage-profile/security/api-tokens"}',
  '["mcp.atlassian.com"]',
  '[{"pattern":"mcp__atlassian__get*","action":"allow","note":"read"},{"pattern":"mcp__atlassian__*","action":"approve"}]'),
 ('notion', 'Notion', '🗂',
  'Pages and databases via mcp.notion.com. OAuth-only: integration tokens are rejected on the MCP endpoint.',
  '["docs","knowledge"]', 'verified', 'https://mcp.notion.com/mcp', 'oauth',
  '{}',
  '["mcp.notion.com"]',
  '[{"pattern":"mcp__notion__*search*","action":"allow","note":"read"},{"pattern":"mcp__notion__*get*","action":"allow","note":"read"},{"pattern":"mcp__notion__*","action":"approve"}]');

-- The in-image sandbox server (credential-free by construction) as an
-- authless catalog entry: Connect registers the declared bundle directly.
insert into connector_catalog (slug, name, icon, description, categories, tier, transport, auth_mode, sandbox_launch, tool_hints) values
 ('workspace-info', 'Workspace info', '📁',
  'In-image sandbox stdio server: file and grep counts over /workspace. Credential-free, sandbox-contained.',
  '["workspace"]', 'verified', 'stdio', 'none',
  '{"command":"node","args":["/opt/fluidbox-runner/servers/workspace-info.mjs"],"tools":[{"name":"workspace_file_count","description":"Count files in the workspace","input_schema":{"type":"object","properties":{},"additionalProperties":false}},{"name":"workspace_grep_count","description":"Count lines containing a plain pattern","input_schema":{"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}}]}',
  '[{"pattern":"mcp__workspace-info__*","action":"allow","note":"read-only, sandbox-contained"}]');

-- OAuth custody rides the SAME connection object (design: the connection is
-- the credential-custody object; bundles keep referencing it).
--   auth_kind 'static'  → credential_sealed = the pasted secret, sent per
--                         metadata.header_name/scheme (default Authorization: Bearer)
--   auth_kind 'oauth'   → credential_sealed = the ROTATING refresh token
--                         (atomic overwrite per rotation — OAuth 2.1 MUST);
--                         access tokens are minted at call time and cached
--                         in memory only, never persisted.
-- credential_sealed becomes nullable: a pending OAuth connection has no
-- credential until the callback exchange; every unseal path is status-gated
-- (status='pending' joins active|revoked|error).
alter table integration_connections
    alter column credential_sealed drop not null,
    add column auth_kind text not null default 'static',
    add column oauth jsonb,
    add column client_secret_sealed bytea;
