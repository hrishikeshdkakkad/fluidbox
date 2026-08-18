-- Atlassian: move to the authv2 OAuth endpoint and request Jira-only scopes.
--
-- 0007 pointed the entry at https://mcp.atlassian.com/v1/mcp. Atlassian's own
-- README (github.com/atlassian/atlassian-mcp-server) calls that endpoint the
-- API-TOKEN alternative and names /v1/mcp/authv2 as the RECOMMENDED OAuth one.
-- The difference is not cosmetic — measured against both endpoints:
--
--   /v1/mcp          401 Bearer realm="OAuth"      no resource_metadata
--                    no PRM at either well-known path (404, 404)
--                    AS = mcp.atlassian.com itself, publishing NO
--                    scopes_supported, so we sent no `scope` at all and the
--                    gateway substituted a FIXED Jira+Confluence+identity set.
--                    That is why consent demanded a site carrying BOTH products
--                    and a Jira-only site was refused ("Access denied … requires
--                    access to a Jira & Confluence & User identity site").
--
--   /v1/mcp/authv2   401 Bearer resource_metadata="…/oauth-protected-resource/v1/mcp/authv2"
--                    PRM 200 -> authorization_servers
--                      ["https://auth.atlassian.com/VCeDsk8ZHncYF1g234fKtc4lNipbBhu3"]
--                    AS metadata 200 at the RFC 8414 path-suffixed well-known
--                      issuer  https://auth.atlassian.com/VCeDsk8ZHncYF1g234fKtc4lNipbBhu3
--                      DCR     …/dcr/register
--                      PKCE    ["S256"]
--                    and a real scopes_supported list, so a client may request a
--                    SUBSET instead of the whole product matrix.
--
-- Hence the scopes below. `catalog.rs` copies this column into the connection's
-- oauth bag and `oauth.rs` joins it into the authorize request's `scope`, so a
-- Jira-only site now satisfies consent. offline_access is required for the
-- refresh token the exchange insists on (oauth.rs adds it when the AS advertises
-- it; naming it here keeps the intent legible rather than implicit).
--
-- Confluence/Compass scopes are deliberately omitted — adding a product means
-- adding its scopes here, which keeps least-privilege an explicit decision
-- instead of "whatever the gateway felt like asking for".
--
-- authv2 also publishes a proper PRM, so it no longer depends on the no-PRM
-- discovery fallback added alongside 0032; that fallback stays because it is
-- correct for any server with the same gap, but it is no longer load-bearing here.
--
-- Guarded on the global curated row still holding the old URL, so a deployment
-- that already re-pointed this entry, or a tenant-scoped custom row shadowing
-- the slug, is untouched. Re-running is a no-op.

update connector_catalog
   set url        = 'https://mcp.atlassian.com/v1/mcp/authv2',
       scopes     = '["read:me","read:account","offline_access","read:jira-work","write:jira-work"]'::jsonb,
       updated_at = now()
 where slug = 'atlassian'
   and tenant_id is null
   and url = 'https://mcp.atlassian.com/v1/mcp';
