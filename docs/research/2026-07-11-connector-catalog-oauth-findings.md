# Connector catalog & OAuth custody — research findings + design sketch

**Date:** 2026-07-11 · **Question:** how do OAuth-authenticated MCP servers get
registered, and what does a user-selectable connector catalog (à la Claude's
connectors directory) look like on fluidbox's Phase-5 seams? Sources: Anthropic
connector docs, MCP spec 2025-11-25, vendor MCP docs, official registry docs
(as-of dates inline; full detail in the session research brief).

## Five platform-critical facts

1. **Audience binding is spec-mandated, not our invention.** MCP clients MUST send
   RFC 8707 `resource=<canonical server URL>` in both authorization and token
   requests; servers MUST validate `aud`. Our `mcp_http` connection's
   `base_url` binding is exactly this model — the OAuth flavor extends it.
2. **Client registration flipped in 2025-11-25: CIMD is SHOULD, DCR is MAY.**
   With Client ID Metadata Documents, fluidbox hosts ONE JSON document whose
   HTTPS URL *is* the `client_id` for every authorization server — no per-server
   registration state. DCR stays as fallback (store the minted client_id per
   connection). Spec priority: pre-registered → CIMD → DCR.
3. **One stable redirect URI + signed state** is the hosted-platform pattern
   (Claude uses exactly one: `https://claude.ai/api/mcp/auth_callback`). For us:
   `https://<control-plane>/v1/oauth/callback`, with an opaque signed `state`
   carrying (connection_id, PKCE-verifier handle).
4. **Refresh-token rotation is MUST for public clients.** Custody = seal the
   rotating refresh token, atomically overwrite on every refresh; refresh
   proactively (~5 min before expiry) + reactively on 401; `invalid_grant` ⇒
   connection status → needs-reauth (our fail-closed create_run check already
   refuses runs on non-active connections).
5. **Headless splits the ecosystem in two.** Static-bearer paths exist for
   GitHub (PAT), Stripe (restricted key), Linear (API key or true
   `client_credentials`), Sentry (`Sentry-Bearer`), Atlassian (API token) — all
   of these work **today** with the existing `mcp_http` flavor, no OAuth code.
   Notion and Slack are user-delegated-OAuth-only: they need a ONE-TIME
   interactive browser consent, after which the broker custodies the refresh
   token. Claude itself supports no pure M2M — every connection is
   user-consent-gated.

## How Claude's connectors directory works (patterns to mirror)

- **Three trust tiers:** Verified (checkmark; Anthropic-reviewed) / Community
  (automated checks only; "not reviewed in depth" warning) / Custom (user URL,
  no card). One catalog across all Claude surfaces; category browse; usage-based
  ranking; listing page with description/screenshots/Connect button.
- **Connect flow:** always OAuth 2.1 + PKCE S256; discovery via 401 →
  RFC 9728 PRM → first `authorization_servers[]` entry → RFC 8414/OIDC.
  Registration modes: DCR, CIMD (only when the AS advertises it + `none` token
  auth), Anthropic-held per-connector client credentials, custom per-org
  client id/secret ("Advanced settings"), `static_headers` (beta), none.
  Directory connectors share ONE OAuth app per connector; custom = per-org.
- **Custody:** Anthropic-side, encrypted at rest, per-user, never shown again;
  refresh reactive-on-401 + proactive-5-min; `offline_access` requested when
  advertised.
- **Per-tool governance:** submissions MUST separate read vs write tools and
  annotate `readOnlyHint`/`destructiveHint` (mixed catch-all tools are
  auto-rejected); annotations drive auto-permission (read-only runs without
  per-call confirmation, destructive always prompts; org tri-state
  Always allow / Needs approval / Blocked). Maps 1:1 onto our
  Allow/Approve/Deny verdicts — as *policy-default seeds*, never enforcement
  (annotations remain untrusted input; our gate stays the judge).
- **Admin curation:** org-level allowlists (Owner-gated); registry-only
  enforcement modes (GitHub/VS Code "Registry only" blocks unlisted servers at
  runtime); enterprise registries implement the official MCP Registry v0.1 API
  + server.json — an internal allowlist is a filtered fork of that schema.

## Per-server headless verdicts (catalog seed data)

| Server | Endpoint | Headless today (mcp_http) | Needs OAuth custody |
|---|---|---|---|
| GitHub | api.githubcopilot.com/mcp/ | ✅ PAT bearer | optional (Copilot-gated OAuth) |
| Stripe | mcp.stripe.com | ✅ restricted key | optional |
| Linear | mcp.linear.app/mcp | ✅ API key / client_credentials (actor=app, 30d, re-fetch on 401) | optional |
| Sentry | mcp.sentry.dev/mcp | ✅ `Sentry-Bearer` static token (note: custom header name, not `Authorization: Bearer`) | optional |
| Atlassian | mcp.atlassian.com/v1/mcp | ✅ API token (admin-gated) | else OAuth (1h access + rotating refresh) |
| Notion | mcp.notion.com/mcp | ❌ (integration tokens NOT accepted on MCP) | **required** (1h access; refresh ≤180d/30d-idle, rotation mandatory, ≤2 valid) |
| Slack | mcp.slack.com/mcp | ❌ (test header only, discouraged) | **required** (confidential client — needs our own Slack app client_id+secret; NO DCR) |

## Design sketch on the Phase-5 seams (a future slice — nothing here is built)

**The connection stays the custody object; the bundle keeps referencing it.**
Nothing in the frozen RunSpec, gate, or broker call path changes — only how
`broker::brokered_auth` resolves a header.

1. `integration_connections` grows OAuth fields (all sealed/derived):
   `auth_kind` (static_bearer | oauth_auto | oauth_client_credentials),
   sealed refresh token (rotated atomically), cached access token + expiry (in
   the existing `connector_tokens` in-memory cache), AS issuer + token endpoint,
   granted scopes, client identity (CIMD URL | DCR client_id | pre-registered).
2. **Connect flow (interactive, dashboard):** pick catalog entry → control
   plane runs discovery → client identity (CIMD doc served at
   `/.well-known/fluidbox-client-metadata.json`; DCR fallback) → browser popup
   to the AS with PKCE S256 + `resource=` → `/v1/oauth/callback` (signed
   state) → token exchange → seal refresh → connection active → **bundle
   auto-registered (photograph runs with the fresh token)** → attachable.
3. **Broker at run time:** unseal refresh → mint/refresh access (proactive
   5-min + reactive 401), audience-bound to the connection base_url as today;
   `invalid_grant` ⇒ connection → `error` (needs re-consent) ⇒ new runs fail
   closed at create, in-flight brokered calls fail visibly in the ledger.
4. **Catalog:** `connector_catalog` seed data as a **superset of the official
   registry's server.json** (import-friendly; could later serve the v0.1 API as
   an enterprise allowlist): name/slug/icon/description/categories/tier
   (verified|community|custom)/remote URL/transport/auth mode/scopes/egress/
   per-tool read-write hints → **policy-default seeds**. UI: Capabilities page
   gains an "Add from catalog" grid; Connect button branches authless →
   register now; api-key → paste (today's flavor); oauth → popup dance.
5. **Cheap first increment (works with zero new auth code):** seed the catalog
   with the five static-bearer connectors above as one-click templates over the
   existing `mcp_http` flavor + declared-bundle registration; OAuth custody
   (Notion/Slack class) is the second increment. Slack additionally needs a
   fluidbox-owned Slack app (confidential client) — per-deployment client_id +
   sealed client_secret config.

**Unconfirmed/watch:** Claude popup-vs-redirect UX (undocumented); MCP Registry
still pre-GA (API frozen v0.1); Sentry DCR medium-confidence; per-server CIMD
support is effectively zero today (it lives in the AS layer — WorkOS/Stytch/
Auth0 "Auth for MCP") — so ship DCR fallback from day one.
