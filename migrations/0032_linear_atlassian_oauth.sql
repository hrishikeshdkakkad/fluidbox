-- Linear and Atlassian move from api_key to OAuth.
--
-- 0007 seeded both as `api_key` (Linear: a `lin_api_…` Bearer token; Atlassian:
-- `email:api_token` as HTTP Basic). Both hosted MCP endpoints now answer an
-- unauthenticated `initialize` with `401 WWW-Authenticate: Bearer realm="OAuth"`,
-- so those static-credential shapes no longer authenticate at all — the entries
-- were not merely "not OAuth", they were unusable.
--
-- Verified against the live endpoints before writing this migration:
--
--   linear     mcp.linear.app/mcp        401 + resource_metadata=…/oauth-protected-resource/mcp
--              PRM -> authorization_servers ["https://mcp.linear.app"]
--              AS  -> registration_endpoint https://mcp.linear.app/register  (DCR)
--                     code_challenge_methods_supported ["S256"]
--
--   atlassian  mcp.atlassian.com/v1/mcp  401 Bearer realm="OAuth", NO resource_metadata
--              no PRM at either well-known path (both 404)
--              AS  -> /.well-known/oauth-authorization-server 200
--                     issuer https://mcp.atlassian.com  (matches RFC 8414 §3.3)
--                     registration_endpoint https://mcp.atlassian.com/v1/register  (DCR)
--                     code_challenge_methods_supported ["plain","S256"]
--
-- DCR on both matters: CIMD is only offered when FLUIDBOX_PUBLIC_URL is https +
-- non-loopback, so local and loopback deployments resolve client identity
-- through Dynamic Client Registration or not at all.
--
-- Atlassian additionally needed a code change — `oauth::discover` required a
-- protected-resource document and gave up before reading the AS metadata that
-- Atlassian does publish. That fallback ships alongside this migration.
--
-- `auth_hints` is reset to `{}` (the shape the `notion` OAuth seed uses): the
-- old hints described a credential paste-box — placeholder, key_url, scheme,
-- composite — none of which apply to a flow that mints its own token.
--
-- Scoped to the GLOBAL curated rows (`tenant_id is null`) and guarded on
-- `auth_mode = 'api_key'`, so a deployment that already re-pointed these
-- entries, or a tenant-scoped custom row shadowing the same slug, is untouched.

update connector_catalog
   set auth_mode  = 'oauth',
       auth_hints = '{}'::jsonb,
       updated_at = now()
 where slug in ('linear', 'atlassian')
   and tenant_id is null
   and auth_mode = 'api_key';
