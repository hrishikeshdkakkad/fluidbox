# Next-session brief — connector catalog & OAuth custody ("Phase 5.5")

**Date:** 2026-07-11 · **User-selected 2026-07-11 as the next slice, ahead of design-doc
Phase 6 (Codex).** Phases 0–5 are shipped & verified (`just e2e` = 306 checks/8 phases,
HANDOVER rev 7). This brief is self-contained: §B carries the full design + research
digest. Companion research notes (read them — they carry sources + flagged unknowns):
`docs/research/2026-07-11-connector-catalog-oauth-findings.md` (this slice) and
`docs/research/2026-07-10-mcp-ecosystem-findings.md` (Phase 5 baseline).

---

## A. Ready-to-paste session goal

Continue the fluidbox "borrow the agent, on demand" build. ultrathink

READ FIRST (in order):
1. CLAUDE.md — commands, invariants (capability classes bullet especially), gotchas
2. docs/HANDOVER.md (rev 7) — current state
3. docs/handovers/2026-07-11-connector-catalog-session-brief.md §B — THE design
4. docs/research/2026-07-11-connector-catalog-oauth-findings.md — research + sources

WHERE WE ARE: Phase 5 shipped the capability catalog: `mcp_http` connections (sealed
static bearer + base_url audience binding), append-only `capability_bundles`
(registration = the photograph), pin-only attachment (§17 #7), the ONE gate with
frozen-set availability, and the broker (`broker.rs`) turning credentials server-side.
This slice adds the USER-FACING layer: a curated connector catalog ("select capabilities
onto your agent") + OAuth credential custody for connectors that have no static-key path.

YOUR TASK — two increments, one phase:
INCREMENT 1 — catalog (no new auth machinery):
- `connector_catalog` seed (checked-in seed file, boot-synced like policies/default.yaml;
  records = superset of the official MCP registry server.json: slug, name, icon,
  description, categories, tier verified|community|custom, remote url, transport,
  auth_mode none|api_key|oauth, credential hints (env/header name), scopes, egress,
  per-tool read/write hints as POLICY-DEFAULT SEEDS — annotations stay untrusted).
- Seed entries (headless-ready today, static bearer over existing mcp_http): GitHub
  (api.githubcopilot.com/mcp/, PAT), Stripe (mcp.stripe.com, restricted key), Linear
  (mcp.linear.app/mcp, API key), Sentry (mcp.sentry.dev/mcp — NOTE custom header
  `Sentry-Bearer`, needs the header_name field below), Atlassian (mcp.atlassian.com/
  v1/mcp, API token via Basic email:token — needs a scheme field). Plus the in-image
  sandbox bundle (workspace-info) as an authless catalog entry.
- `mcp_http` connections gain optional `header_name`/`scheme` (default
  `authorization: Bearer`) — broker uses it.
- Dashboard: Capabilities page gains "Add from catalog" grid (tier badges, categories);
  Connect branches: authless → register bundle now (photograph); api_key → paste key →
  connection + auto-register bundle; oauth → increment 2 flow. Attach stays pins (§17 #7).
INCREMENT 2 — OAuth custody (unlocks Notion/Slack-class connectors):
- Connections grow `auth_kind` (static_bearer | oauth) + sealed ROTATING refresh token
  (atomic overwrite per rotation — OAuth 2.1 MUST), cached access token+expiry (reuse
  connector_tokens cache), AS issuer + token endpoint, granted scopes, client identity.
- Client identity: serve a CIMD document (our HTTPS URL IS the client_id — 2025-11-25
  SHOULD) + DCR fallback (store minted client_id per connection; DCR is what most
  servers actually support today). Priority: pre-registered → CIMD → DCR.
- Connect dance (interactive ONCE, dashboard): 401 → RFC 9728 PRM → RFC 8414/OIDC AS
  metadata (verify code_challenge_methods_supported has S256 else refuse) → authorize
  URL w/ PKCE S256 + `resource=<canonical base_url>` (audience binding, send both legs)
  → ONE stable callback `GET /v1/oauth/callback` + opaque SIGNED state
  (connection_id + PKCE verifier handle) → token exchange → seal refresh → active →
  auto-register the bundle (photograph with the fresh token).
- Broker: mint/refresh access at call time (proactive ~5min-before-expiry + reactive
  401; ≤2 valid refresh tokens at Notion — rotation must be atomic); `invalid_grant` ⇒
  connection status `error` (needs re-consent) ⇒ create_run already fails closed;
  in-flight brokered calls fail visibly (tool.brokered error).
- Nothing in RunSpec/gate/freeze changes — only credential RESOLUTION in
  broker::brokered_auth.
SETTLE WITH ME BEFORE SCHEMA: (1) increments 1+2 in this one phase (rec: yes); (2) seed
catalog as checked-in file + boot sync (rec) vs API-only; (3) confidential-client
support now (sealed client_secret on connection — Slack needs it; rec: generic support
yes, Slack seed entry deferred to the Phase-7 Slack vertical); (4) catalog Connect
auto-registers the bundle (rec) vs prefill-only.
Acceptance/E2E: NEW suite phase (pattern e2e-capabilities.sh; no-model always, live
self-skips): fake MCP server + FAKE AS (python: PRM on the fake MCP; /.well-known
AS metadata; /authorize auto-consents via redirect; /token mints code→access+ROTATING
refresh, honors resource=, invalid_grant after revoke) — the "browser" step is a curl
of the authorize URL. Assert: catalog list/one-click api_key template → bundle
photographed; header_name honored (Sentry-shaped fake); full OAuth dance → sealed
rotating refresh (two refreshes rotate atomically; old refresh dead); access minted
with resource= audience; broker call works end-to-end; token expiry mid-run →
proactive/reactive refresh; AS revoke → invalid_grant → connection error → new run
400 fail-closed + reconnect flow revives; secrets never in responses/RunSpec/ledger/
sandbox env; CIMD doc served; DCR fallback exercised. Live tier: an agent uses a
catalog-attached connector end-to-end.
WORKING AGREEMENT (locked): mechanical, ONE phase; done only when `just check` AND
`just e2e` fully green incl. the NEW phase; update docs/HANDOVER.md (rev 8); HAND BACK.
Do not start Phase 6 (Codex) — its brief: docs/handovers/2026-07-10-phase6-session-brief.md.
OPERATIONAL NOTES: `just e2e` owns the stack (stop :8787). Unit tests need the stack
stopped; DB tests `set -a; source .env; set +a`. Live runs AUTONOMOUS; disable earlier
subs before live tiers. Check `git status` FIRST — clean + synced; else ask me.
`docs/reviews/2026-07-10-phase4-review-findings.md` is an UNTRACKED user-owned review
ledger (P1/P2 Phase-4 findings) — do not commit or act on it unprompted. ultrathink

---

## B. Design + research digest (the load-bearing facts)

### B.1 Why the seams already fit
Phase 5 made the **connection** the credential-custody object and the **bundle** a
connection_ref holder; the broker resolves auth per call and audience-binds to the
connection's `base_url`. Research confirmed: RFC 8707 audience binding is a spec MUST
(send `resource=` on both authorization and token requests) — our binding is the spec's
own model. OAuth = new `auth_kind` on the same object; zero changes to frozen RunSpecs,
the gate, narrowing, or the photograph rule.

### B.2 Client identity (the registration problem)
- **CIMD (2025-11-25 SHOULD):** we host one JSON doc (client_id = its URL, client_name,
  redirect_uris) at a well-known path; works against every AS with zero stored state.
  Caveat: almost no MCP vendor AS supports CIMD yet (it lives in the WorkOS/Stytch/
  Auth0 "Auth for MCP" layer) — so:
- **DCR (RFC 7591, MAY):** POST registration_endpoint per AS → store client_id on the
  connection (avoid re-registering per connect — client sprawl).
- **Pre-registered/confidential:** manual client_id (+ sealed client_secret) fields —
  required for Slack (explicitly NO DCR; confidential client).
- Claude's four modes for reference: oauth_dcr, oauth_cimd (only when AS advertises
  `client_id_metadata_document_supported` + `none` token auth), Anthropic-held per-
  connector creds, custom per-org client id/secret. Claude callback (verbatim):
  `https://claude.ai/api/mcp/auth_callback` — ONE stable URI + state. ChatGPT uses
  per-connector URIs; we follow Claude's model.

### B.3 Token custody rules (spec + vendor realities)
- Refresh rotation is MUST for public clients: atomically overwrite the sealed refresh
  token; Notion invalidates beyond 2 valid tokens; refresh ≤180d from consent / 30d
  idle (Notion), 90d idle (Atlassian). Access tokens ~1h (Notion/Atlassian).
- Refresh proactively (~5 min pre-expiry, Claude's behavior) + reactively on 401;
  request `offline_access` when the AS advertises it; expect RFC 6749 `invalid_grant`
  on dead refresh → surface "reconnect" on the connection row.
- Never token-passthrough (spec prohibition): the sandbox never sees any of this —
  unchanged inversion.

### B.4 Per-server headless matrix (catalog seeds; as-of 2026-07-11)
| Connector | Endpoint | Headless path TODAY | OAuth notes |
|---|---|---|---|
| GitHub | api.githubcopilot.com/mcp/ | PAT bearer (precedence over OAuth; no Copilot license) | OAuth GA but Copilot-gated; App install tokens NOT accepted |
| Stripe | mcp.stripe.com | restricted API key bearer | OAuth exists; key path recommended |
| Linear | mcp.linear.app/mcp | API key bearer OR true client_credentials (actor=app, 30d token, re-fetch on 401, no refresh) | OAuth 2.1 + DCR |
| Sentry | mcp.sentry.dev/mcp | static token via CUSTOM header `Sentry-Bearer` | OAuth + DCR (medium confidence) |
| Atlassian | mcp.atlassian.com/v1/mcp (cloud-only) | API token (Basic email:token or service-account Bearer; org-admin-gated) | OAuth 3LO: 1h access + rotating refresh/90d |
| Notion | mcp.notion.com/mcp | NONE (integration tokens rejected on MCP) | **OAuth-only**: PKCE S256, DCR supported, rotation mandatory |
| Slack | mcp.slack.com/mcp | none viable (test header discouraged) | **OAuth-only, confidential client, NO DCR** — needs our own Slack app; defer seed to Phase 7 |

### B.5 Catalog patterns worth mirroring (Claude connectors directory)
- Tiers: **Verified** (checkmark, human-reviewed) / **Community** (automated checks,
  warning before connect) / **Custom** (user URL, no card). Category browse; logo cards;
  Connect button; per-entry description/screenshots.
- Per-tool governance: submissions MUST split read vs write tools and annotate
  `readOnlyHint`/`destructiveHint` (mixed catch-all tools auto-rejected); annotations
  drive auto-permissions (read-only unprompted; destructive always asks; org tri-state
  Always allow / Needs approval / Blocked) → maps 1:1 to our Allow/Approve/Deny as
  **policy-default seeds** — our gate remains the judge, annotations stay untrusted.
- Catalog record = superset of official registry `server.json` (reverse-DNS name,
  version, packages[]/remotes[], _meta) → import-compatible; fluidbox could later serve
  the registry v0.1 API as an enterprise allowlist (VS Code `chat.mcp.access=registry` /
  GitHub "Registry only" block unlisted servers at runtime — the enterprise pattern).
- Enterprise Managed Auth (Claude, beta): admin authorizes once, users inherit via IdP
  (Okta) — future multi-user fluidbox reference, not this slice.

### B.6 Flagged unknowns (do not treat as facts)
Claude popup-vs-redirect UX undocumented; exact GitHub/Slack/Stripe OAuth TTLs
unpublished; Sentry DCR medium-confidence; MCP Registry still pre-GA (API frozen v0.1);
CIMD support ~absent among vendor ASes today (ship DCR fallback from day one).
