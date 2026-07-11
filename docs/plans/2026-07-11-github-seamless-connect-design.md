# fluidbox — Seamless GitHub connect (App manifest + install dance)

Status: rev 3 (final; implements review rounds 1 & 2) · 2026-07-11
Slice name: **Phase 5.6** (user-inserted, follows the Phase 5.5 pattern)
Parent design: `2026-07-10-agent-workspaces-triggers-integrations-design.md` (§3.2, §7, §17 #1)
Review: adversarial design review by codex `gpt-5.6-sol` @ xhigh. Round 1
(rev 1) = REDESIGN, 6 blockers. Round 2 (rev 2) = SHIP WITH FIXES, 1 blocker
+ 10 should-fixes. Rev 3 incorporates all of them; round-1 deltas are marked
**[R‑n]**, round-2 deltas **[F‑n]**.

## 1. Problem

Connecting GitHub today means hand-carrying four secrets. The dashboard's
`github_app` form demands `app_id`, `installation_id`, a private-key PEM, and
a webhook secret — the operator must manually register a GitHub App, set its
permissions and events, generate and download a key, invent a webhook secret
and paste it in two places, install the app, dig the installation id out of a
URL, and then paste the ingress URL back into GitHub.

The standard experience is a **"Connect GitHub" button**. GitHub provides two
primitives that make this fully automatable for a self-hosted control plane:

- **App manifest flow**: fluidbox POSTs a manifest describing the app it
  needs; the user confirms on GitHub; GitHub redirects back with a one-hour,
  single-use code; exchanging it at `POST /app-manifests/{code}/conversions`
  (201, unauthenticated) returns `id`, `slug`, `client_id`, `client_secret`,
  `webhook_secret`, `pem`, `html_url`, `owner` — every field the form asks
  for today.
- **Installation flow**: `{web}/apps/{slug}/installations/new` lets the user
  pick the account and repositories; GitHub then redirects the browser to the
  app's **setup URL** with `installation_id` (+ `setup_action`).

Verified against current GitHub docs (2026-07-11):

- Manifest POST: form field `manifest` to `{web}/settings/apps/new?state=…`
  (org variant `{web}/organizations/{org}/settings/apps/new?state=…`);
  redirect to `redirect_url?code=…&state=…` (state echoed on this leg).
- Conversion: single-use code, 1-hour expiry, no auth, 201; `webhook_secret`
  is `string | null`; the owner login is `owner.login`, not top-level.
- Setup URL: receives `installation_id` (+ `setup_action=install|update`);
  GitHub explicitly warns the value is **spoofable**.
- `state` pass-through on `installations/new` has a flaky history ⇒ never
  load-bearing on the install leg.
- **A `public: false` app installs only on the account that owns it.** One
  registration therefore serves exactly one GitHub account/org. **[R‑1]**
- Not every App webhook carries `installation.id` (ping is the canonical
  counterexample) — extraction is Optional, never asserted. **[F‑10]**

## 2. Approaches considered

**A. App registration as a first-class deployment object (chosen).** A new
`github_app_registrations` table custodies the app identity (sealed pem,
webhook secret, client secret). Connections stay one-per-installation and
carry a real FK to their registration. Webhook ingress gains an app-level
route (GitHub App webhooks ARE app-level; deliveries carry
`installation.id` when installation-scoped).

**B. Copy app credentials into each installation connection.** Rejected:
GitHub delivers ALL installations' webhooks to ONE app-level URL; with
per-connection ingress paths a second installation's events would arrive at
the first connection's URL and match the wrong subscriptions. Secret
duplication also multiplies rotation surface.

**C. OAuth App ("Sign in with GitHub") instead of a GitHub App.** Rejected:
user-to-server tokens can't post Checks, die with the user's membership, and
have no repo-scoped installation model. §17 #1 settled App-only identity.

## 3. Trust model (the load-bearing part) **[R‑2, R‑3, F‑1…F‑4]**

Creating a connection is an act of **fluidbox-admin authority** (today:
admin-token'd `POST /v1/connections`). The browser dance must not weaken
that.

**Two-token flow discipline.** Every browser journey is one row in
`github_app_flows`, driven by two DIFFERENT sealed tokens that are never
interchangeable:

1. `manifest/start` / `install/start` (admin-token'd) mint the flow row and
   return a `go_url` carrying **bootstrap token B** = sealed
   `{t:"gh-boot", f: flow_id, x}`. B never goes to GitHub. **[F‑1]**
2. `GET …/go?boot=B` claims the bootstrap atomically
   (`set bootstrap_consumed_at = now() … where bootstrap_consumed_at is
   null and expires_at > now()`), mints a fresh cookie nonce N, stores
   `browser_hash = sha256(N)`, sets cookie **`fbx_gh_<flow_id>`** = N
   (`HttpOnly; SameSite=Lax; Path=/v1/github/app; Max-Age=3600;
   Secure` iff public_url is https — per-flow name so concurrent flows
   never clobber each other **[F‑2]**), and only THEN emits **state S** =
   sealed `{t:"gh-manifest"|"gh-install", f, r, x}` into the GitHub form /
   redirect. A leaked B is single-use; visiting go with S is refused (wrong
   tag); replaying go after the claim is refused.
3. The returning callback/setup claims the flow in ONE conditional UPDATE
   whose predicate carries everything: flow id + purpose + registration +
   `consumed_at is null` + `bootstrap_consumed_at is not null` +
   `expires_at > now()` + `browser_hash = sha256(presented cookie)`.
   Zero rows ⇒ refusal — so an attacker holding leaked state but no cookie
   cannot even burn the flow. **[F‑4]** Required query params are validated
   before the claim is attempted; the cookie is expired on completion.

**GitHub-supplied identifiers are never trusted.** `installation_id` must
resolve via `GET /app/installations/{id}` under OUR app's JWT (only succeeds
for this app's installations); `suspended_at` in the response gates the
resulting status. The manifest `code` is only honored after the full flow
claim.

**Activation requires admin intent; discovery does not.** Dashboard-initiated
installs (valid flow) activate directly — the admin clicked the button.
GitHub-initiated discovery lands **pending**: a signature-verified
`installation.created` webhook creates a pending row (no GitHub call).
`sync` (admin-token'd) imports and ACTIVATES — the admin call is the intent
**[F‑5]**: unknown live installations upsert active, existing pending rows
activate, suspended ones (per GitHub) land/stay `suspended`, and revoked
rows are NEVER revived by sync. `POST /v1/connections/{id}/approve` (admin)
re-verifies via app JWT then activates — it accepts `pending` AND `revoked`
`github_app` rows (revival is this one explicit per-row admin act, keeping
the connection id — and therefore dedup history — continuous **[F‑6]**).
A setup hit with no/invalid state performs **zero writes and zero GitHub
calls** — it renders "finish from the dashboard" (kills the rate-limit
oracle **[R‑15]**). GitHub-side repo-selection updates
(`setup_action=update`, no fluidbox state) land on that same guidance page;
Sync performs the actual refresh **[F‑12]**.

**Log hygiene [R‑3]:** the default `TraceLayer` span records full URIs; it is
replaced with a method+path-only span so `state`/`code`/`boot` query values
never reach logs (also fixes the existing `/v1/oauth/callback` exposure).
Browser endpoints answer `Cache-Control: no-store`, `Referrer-Policy:
no-referrer`, `X-Frame-Options: DENY`, and a restrictive CSP; interpolated
values are HTML-escaped, the org name is charset-validated, and the
conversion code rides a percent-encoded path segment **[R‑16]**.

## 4. Design

### 4.1 Objects

```text
github_app_registrations                # NEW — one per created app = one GitHub account/org [R‑1]
  id uuid pk
  tenant_id → tenants
  status                                # pending | active | revoked
  target_kind, target_org               # personal | organization (+ org login)
  app_id, slug, name, client_id, html_url, owner_login    # from conversion (null while pending)
  pem_sealed bytea                      # AEAD; reader is active-only, like credentials
  webhook_secret_sealed bytea           # AEAD; NULL ⇒ degraded: fetch/publish work, ingress
                                        # cannot authenticate — surfaced on the card [F‑11]
  client_secret_sealed bytea            # AEAD; unused today, kept because conversion returns
                                        # it exactly once (future user-OAuth) [R‑18]
  created_at, updated_at

github_app_flows                        # NEW — one-time admin intents [R‑2, R‑3, F‑1, F‑13]
  id uuid pk                            # rides inside B and S
  registration_id → github_app_registrations (cascade)
  purpose                               # manifest | install
  browser_hash text                     # sha256(cookie nonce); NULL until go binds a browser
  bootstrap_consumed_at                 # go's one-time claim [F‑1]
  consumed_at                           # callback/setup's one-time claim
  expires_at                            # claims require > now(); start endpoints sweep
  created_at                            #   expired unconsumed rows opportunistically [F‑13]

integration_connections                 # existing table, two additions
  + registration_id uuid null → github_app_registrations ON DELETE RESTRICT   [R‑5]
  + partial unique (tenant_id, provider, external_account_id)
      where provider = 'github_app' and status <> 'revoked'                   [R‑4]
  status gains 'pending' and 'suspended' values (text column, no DDL) [R‑9]
```

Migration remediation **[R‑4, F‑7]** (before the unique index): for each
duplicated live (tenant, github_app, installation) group, the canonical row
is the one owning the most trigger_subscriptions, ties broken by newest;
subscriptions on losing rows are retargeted to the canonical row (same
installation ⇒ semantically identical), then losers are revoked. Deliveries
history stays on the losers for audit. (Real deployments of this repo are
single-admin and dupe-free; the SQL is still written total.)

Seamless connections: `provider = github_app`, `external_account_id =
installation_id`, `credential_sealed = NULL`, `webhook_secret_sealed = NULL`,
`registration_id` set, metadata carries display copies (`app_slug`,
`account_login`, `app_id`, `installation_id`). Legacy hand-pasted rows
(`registration_id NULL`) keep per-connection custody and their per-connection
ingress path, unmodified.

**Custody resolution is by the typed column, and it fails closed** **[R‑5]**:
`registration_id` present → the registration must exist, be tenant-matched,
and be `active`, else refuse — NO fallback to connection custody.
`registration_id` absent → legacy path exactly as today.

**Re-creation discipline [F‑6]:** setup/sync NEVER insert a second row for an
installation that has a revoked one — reviving a revoked installation is
`approve` (explicit, per-row, re-verified), which keeps the connection id and
its dedup history continuous. The live-rows partial unique index makes the
resolution deterministic; a genuine GitHub reinstall arrives with a NEW
installation id anyway.

### 4.2 Flow 1 — create the app (once per GitHub account/org)

```text
dashboard                    control plane                                GitHub
  │ POST /v1/github/app/manifest/start {target?: {org}}     (admin)
  │──────────────────────────▶ insert pending registration R + flow F(manifest)
  │ ◀────────────────────────  { registration, go_url(boot=B) }
  │ window.open(go_url)
  │   GET /v1/github/app/manifest/go?boot=B
  │     └─ claim bootstrap; Set-Cookie fbx_gh_F=N; mint state S₁ [F‑1]
  │     └─ HTML page, ONE visible button: form field `manifest`
  │        POST ▶ {web}/settings/apps/new?state=S₁   (org variant when target.org)
  │                                                   user confirms name & owner
  │   GET /v1/github/app/manifest/callback?code&state=S₁ ◀──────────────────┘
  │     └─ params validated → ONE conditional flow claim (incl. cookie hash) [F‑4]
  │     └─ POST {api}/app-manifests/{code}/conversions  (strict typed parse [R‑17])
  │     └─ one atomic UPDATE … WHERE id = R AND status = 'pending':
  │        seal pem/webhook_secret/client_secret, store ids, status = 'active'
  │        (0 rows ⇒ lost the race / not pending ⇒ discard result, refuse)  [R‑7]
  │     └─ mint install flow F₂ + HTML "App created" whose continue link is the
  │        API-origin install go_url(boot=B₂) — the browser gets bound to F₂
  │        by the SAME go discipline before it ever reaches GitHub [F‑3]
```

Manifest content (built server-side; the dashboard never sees GitHub shapes):

```json
{
  "name": "fluidbox-<host-hint>",
  "url": "<public_url>",
  "hook_attributes": { "url": "<public_url>/v1/ingress/github/app/<R>", "active": true },
  "redirect_url": "<public_url>/v1/github/app/manifest/callback",
  "setup_url": "<public_url>/v1/github/app/<R>/setup",
  "setup_on_update": true,
  "public": false,
  "default_permissions": { "contents": "read", "pull_requests": "write", "checks": "write" },
  "default_events": ["pull_request"]
}
```

The registration id is minted BEFORE the manifest so the webhook and setup
URLs embed it — that is what lets app-level ingress and the setup callback
identify their registration without trusting any GitHub-supplied value.

If the conversion returns `webhook_secret: null` despite the manifest
requesting an active hook, the registration still activates but is marked
**degraded**: fetch/publish work, event ingress cannot authenticate, and the
card says so with remediation ("recreate the app") **[F‑11]**.

Local deployments **[R‑13]** (behavior verified against real github.com,
which REJECTS manifests whose hook URL is loopback): when
`FLUIDBOX_PUBLIC_URL` is not publicly reachable (`webhook_capable` = false:
loopback, localhost, private/link-local IPs), the manifest **omits
`hook_attributes` entirely** — the app still creates, browser redirects
(redirect/setup URLs) work on any host, fetch/publish work, and the
registration lands in the degraded no-webhook state with explicit
remediation copy ("set a public FLUIDBOX_PUBLIC_URL and create a new app").
Any webhook secret in the conversion response is discarded when hooks were
omitted — never custody what wasn't wired. The e2e presents a
webhook-capable internal host (curl `--connect-to`) so the hook path stays
fully exercised.

### 4.3 Flow 2 — connect (install; per registration)

```text
  │ POST /v1/github/app/{R}/install/start        (admin) → flow F₂(install)
  │ ◀── { go_url(boot=B₂) }
  │ window.open(go_url)
  │   GET /v1/github/app/install/go?boot=B₂
  │     └─ claim bootstrap; Set-Cookie fbx_gh_F₂=N₂; mint S₂; 302 →
  │        {web}/apps/{slug}/installations/new?state=S₂
  │                                   user picks account + repositories
  │   GET /v1/github/app/{R}/setup?installation_id=I&setup_action=…&state=S₂
  │     ├─ valid state (+ONE-predicate flow claim incl. cookie): app JWT →
  │     │    GET /app/installations/I
  │     │    404 ⇒ refusal page (spoofed id)
  │     │    200 ⇒ upsert the live row for I: active (suspended_at ⇒ suspended)
  │     │        (a revoked row for I ⇒ refusal page pointing at approve) [F‑6]
  │     │    → HTML "Connected — close this tab"
  │     └─ missing/invalid state: NO writes, NO GitHub calls; page says
  │        "finish from the dashboard (Sync installs)"          [R‑2, R‑15, F‑12]
```

### 4.4 Discovery & reconciliation (no webhook/redirect required) **[R‑8, F‑5]**

- App-level ingress on a signature-verified `installation.created` for an
  unknown installation creates a **pending** connection (account login from
  the verified payload; no GitHub call). Never revives revoked rows.
- `POST /v1/github/app/{R}/sync` (admin): `GET /app/installations` under the
  app JWT; unknown live installations upsert **active**, existing `pending`
  rows activate, GitHub-suspended ones land `suspended`, metadata refreshes,
  revoked rows untouched. UI labels it "Sync & activate installs".
- `POST /v1/connections/{id}/approve` (admin): `pending` or `revoked`
  github_app row → re-verify via app JWT (existence + suspended_at) →
  active.
- The dashboard re-fetches on window focus and offers Sync on the card, so
  even a lost redirect converges in one click.

### 4.5 App-level ingress

```text
POST /v1/ingress/github/app/{registration_id}      (unauth; HMAC IS the auth)
  └─ registration must be active AND have a webhook secret; verify
     X-Hub-Signature-256 against ITS sealed secret (else 401)
  └─ no installation.id in the payload (ping, app-level events) → 202 ignored [F‑10]
  └─ installation lifecycle (GitHub knowledge in github_app.rs / connectors/github.rs):
       installation.created  (unknown)  → pending connection            [R‑8]
       installation.deleted             → connection revoked + token eviction
       installation.suspend/unsuspend   → reconcile against
         GET /app/installations/{id}: suspended_at set ⇒ suspended, clear ⇒
         active (suspend falls toward suspended if GitHub is unreachable;
         unsuspend then makes no change) — webhook ORDER is never
         authoritative [R‑9, F‑9]; revoked stays terminal
  └─ payload.installation.id → resolve the live connection row
       none / not active → 202 { "ignored": … }   (an ack, not a 404)   [R‑10]
  └─ hand off to the SAME provider-ignorant pipeline events.rs already runs
```

Mechanically: today's `events::ingress` body after signature verification is
extracted into `events::process_delivery(state, conn, connector, verified,
payload, raw_digest)` — the raw-body digest is computed from the exact
signed bytes at each call site **[R‑11]**; the 2 MiB body bound applies at
both handlers. events.rs and run_service.rs remain grep-clean of provider
names (the connector name flows through as data); the new route handler and
all GitHub payload shapes live in `github_app.rs` / `connectors/github.rs`.
Axum routing: `/ingress/github/app/{id}` (4 segments) cannot collide with
`/ingress/{provider}/{connection_id}` (3 segments).

Dedup is unchanged: level 1 is `unique(connection_id, external_event_id)`;
the partial unique index + the no-recreate discipline **[F‑6]** make "which
connection" deterministic for an installation's whole life.

### 4.6 Token minting, cache discipline, and downstream consumers **[R‑6, F‑8]**

`connectors::github::installation_token` becomes status-gated and
registration-aware, with the DATABASE as the boundary (in-memory eviction is
an optimization, not the security mechanism **[F‑8]**):

1. ONE fresh custody read by connection id: connection status +
   registration_id (+ registration status / app_id / sealed pem via an
   active-only reader when linked). Connection not `active` OR linked
   registration not `active` ⇒ refuse — before any cache read, no
   cross-fallback.
2. Only then may the cache serve; misses mint as today (legacy rows keep
   minting from connection custody).

Eviction joins every lifecycle transition: connection revoke (API), approve,
suspend/unsuspend/delete (webhook), registration revoke — which cascades in
one transaction to revoking child connections, then evicts each child's
cached token **[R‑12]**.

Consumers are untouched above `installation_token`: `fetch_auth_header`
(git workspaces), `list_repos` (picker), `publish_pr_comment` /
`publish_check`.

`api::resolve_workspace_input` widens from `provider == "github"` to any
provider whose connector is `github`, and its clone-URL handling drops the
hardcoded host: the default clone URL derives from
`FLUIDBOX_GITHUB_CLONE_BASE`, and a caller-supplied `clone_url` must share
that base's parsed origin (scheme+host+port), keeping the e2e `file://` seam
and GHES honest **[R‑14]**.

### 4.7 Config

`FLUIDBOX_GITHUB_WEB_URL` (default `https://github.com`) joins the existing
`FLUIDBOX_GITHUB_API_URL` / `FLUIDBOX_GITHUB_CLONE_BASE` seams: the
browser-facing GitHub base for manifest form targets and install URLs — and
the e2e's web seam. `FLUIDBOX_PUBLIC_URL` (existing) feeds every URL GitHub
must reach: manifest redirect, setup, webhook.

### 4.8 Dashboard (presentation-only)

Connections page:

- **No active registration** → primary button **"Set up GitHub App"**
  (`manifest/start` → `window.open(go_url)`), optional "create in
  organization" input, one-line explanation including the private-app
  scoping rule ("the app installs on the account that owns it") **[R‑1]**.
- **Registrations list** (multiple allowed, each explicit — no silent
  "newest wins" **[R‑1]**): app name/slug linking to `html_url`, webhook
  route, degraded-webhook warning **[F‑11]**, "webhook delivery needs a
  public FLUIDBOX_PUBLIC_URL" note when loopback, per-registration
  **"Connect GitHub"** + **"Sync & activate installs"** + **Revoke**.
- Pending connections render **Approve**; revoked registration-backed rows
  render **Reconnect** (same endpoint); suspended/error rows explain
  themselves.
- Legacy PAT + manual-App forms move under an "advanced" toggle, unchanged.
- The page re-fetches on window focus.
- New admin APIs: `GET /v1/github/app` (registrations, non-secret columns
  only), plus the endpoints named above.

### 4.9 What does NOT change

RunSpec freezing, the permission gate, capability freezing, policy,
approvals, result delivery, trigger matching, PAT connections, legacy
github_app connections (per-connection custody + ingress), the connector
dispatch seam (`connectors/mod.rs` gains no new arms), and the grep-clean
files. `POST /v1/connections` keeps accepting the manual App paste as the
fallback path.

## 5. Threat table (delta)

| Surface | Auth | Abuse case | Mitigation |
|---|---|---|---|
| `GET …/go?boot=B` | one-time sealed bootstrap | leaked go_url replay; flow takeover | bootstrap claims once; go never accepts callback state (tag split); replay ⇒ refusal |
| `GET …/manifest/callback` | sealed state + one-predicate flow claim + per-flow cookie | leaked S replayed; cookie-less burn; attacker races conversion with own app | claim requires cookie hash IN the predicate (no burn) [F‑4]; atomic `pending→active` accepts exactly one conversion; losing results discarded; path-only trace spans |
| `GET …/{R}/setup` (valid state) | flow + cookie + app-JWT verification of `installation_id` | spoofed id; foreign install auto-activating | 404 ⇒ refusal; activation only via admin-minted flow; revoked rows only revive via approve |
| `GET …/{R}/setup` (no state) | none | oracle/junk-row farming | zero writes, zero GitHub calls — static guidance page |
| `POST /v1/ingress/github/app/{R}` | HMAC vs registration secret | forged deliveries; unknown installations; ping | nothing stored pre-verification; no-installation events + unknown installations ⇒ 202 acks; only installation.created creates (pending) rows |
| conversion/webhook/client secrets | — | leak via logs/responses | sealed at rest; list APIs select non-secret columns; path-only trace spans; browser pages escape all interpolations, no-store/no-referrer/CSP/DENY |
| token cache | — | revoked/suspended custody still publishing | fresh DB custody read gates BEFORE cache [F‑8]; eviction on every transition; registration revoke cascades |

## 6. Testing

**Unit (fluidbox-server):** manifest JSON builder (URLs embed the
registration id; permissions/events exact; org target switches the form
action); boot/state seal/open (tag split B↔S↔oauth, expiry); installation-id
extraction returns None for ping **[F‑10]**; lifecycle reconciliation
mapping (suspended_at → status, unreachable-GitHub direction) **[F‑9]**;
signing-material resolution (registration vs legacy, fail-closed on revoked
registration); clone-URL origin validation.

**e2e — extend `scripts/e2e-github.sh` in-process** (one fake, both
connection flavors share caches/resolvers/uniqueness) **[R‑19]**: fake grows
`POST /app-manifests/{code}/conversions` (one-time code; real RSA pem;
webhook secret; client id/secret) and `GET /app/installations` (list).
Script drives: `manifest/start` → go (cookie set; SECOND go on the same boot
refused **[F‑1]**) → callback (sealed custody, no plaintext anywhere; state
replay refused; callback without the cookie refused AND the flow stays
unburned **[F‑4]**) → chained install link is an API-origin go **[F‑3]** →
setup with a SPOOFED installation id (refused) → setup with the real id
(active connection, `registration_id` set) → repo picker via
registration-minted token → subscription + app-level ingress: signed ping
(202 **[F‑10]**), PR event (fan-out at exact SHA), webhook retry (no
duplicates), setup replay (no duplicate rows) → `installation.suspend`
(suspended; publish fails closed) → `unsuspend` (active) →
`installation.deleted` (revoked; ingress 202-ignores; workspace resolution
refuses; approve revives **[F‑6]**) → legacy-paste connection still works
alongside (existing sections unchanged).

## 7. Decisions settled at this boundary (§17 addendum)

1. **App visibility/cardinality** → `public: false`; one registration per
   GitHub account/org; multiple registrations first-class; the dashboard
   never guesses silently. **[R‑1]**
2. **Trust anchor** → two-token one-time browser-bound flows (bootstrap ≠
   state) for activation; app-JWT lookups for identifier truth;
   GitHub-initiated discovery lands `pending`; sync/approve are the admin
   intents; revoked rows revive only via approve. **[R‑2, F‑1…F‑6]**
3. **Custody linkage** → typed `registration_id` FK, fail-closed resolution,
   live-rows partial unique + no-recreate discipline, DB-fresh custody gate
   before the token cache, revocation cascades with eviction.
   **[R‑4, R‑5, R‑6, F‑6, F‑8]**
4. **`installation.created`** → creates pending rows only (discovery, not
   authority). **[R‑8]**
5. **Known accepted limitation (reviewer dissent recorded).** Import
   (setup/sync), approve, and revocation are serialized per path but not
   against EACH OTHER: the fresh-import insert carries the F‑6 predicate
   inside one statement (`insert … where not exists any-status row`), and
   approve compensates by re-reading the registration after its transition —
   which closes the application-level windows — but sub-statement MVCC
   interleavings remain (e.g. another import's commit+revoke landing inside
   one INSERT's snapshot, or an import landing just after a registration
   revoke). The round‑4/5 reviewer (codex gpt‑5.6‑sol) rates this a blocker
   absent per-(tenant, installation) advisory transaction locks; shipped
   judgment: every involved path requires admin authority or a verified
   installation + admin-blessed flow, the failure modes are VISIBLE rows
   that fail closed at use time (custody re-reads registration status
   before any token leaves the cache), and no attacker can drive the
   interleaving. Follow-up when multi-admin concurrency becomes real:
   `pg_advisory_xact_lock(hash(tenant, installation_id))` around
   apply/approve/revoke plus a registration lock in approve, with
   barrier-controlled interleaving tests.
