# Hosted network architecture

**Date:** 2026-07-21
**Status:** Phase A deliverable of the multi-user MCP control plane epic (#28); egress edges re-verified against shipped code at the end of Phase E
**Authority:** [`../plans/2026-07-14-multi-user-mcp-control-plane-design.md`](../plans/2026-07-14-multi-user-mcp-control-plane-design.md) (v4), [`../plans/2026-07-17-idp-agnostic-identity-design.md`](../plans/2026-07-17-idp-agnostic-identity-design.md) (v5), and — for the shipped substrate — [`../plans/2026-07-15-kubernetes-native-provider-design.md`](../plans/2026-07-15-kubernetes-native-provider-design.md) and the [Kubernetes guide](../guides/kubernetes.md).

This is the hosted network diagram: every plane, every listener, and every edge — who initiates it, how it authenticates, what crosses it, and what must never cross it. Edges are annotated with the phase that lands them where they are not shipped today — browser sessions/PATs shipped in Phase B; run resource bindings shipped in Phase C; the egress boundary and audience-scoped run credentials shipped in Phase E — and every current-vs-target difference is listed explicitly in [Target-state deltas](#target-state-deltas), never implied.

## The diagram

    ─────────────────────────── external, untrusted ───────────────────────────

      user browser          CLI / API client        webhook senders
      (__Host- cookies)     (Bearer fbx_pat_…,      (GitHub App & connection
            │                trigger tokens)         webhooks, HMAC-signed)
            │                       │                       │
            │   browser redirects   │                       │
            │   (authorization code)│                       │
            ▼                       │                       │
      ┌───────────────┐             │                       │
      │ per-org IdP   │             │                       │
      │ (any conform- │             │                       │
      │  ant OIDC AS) │             │                       │
      └───────▲───────┘             │                       │
              │ server-side:        │                       │
              │ discovery · JWKS ·  │                       │
              │ token exchange      │                       │
              │ (SSRF-validated)    │                       │
    ──────────┼─────────────────────┼───────────────────────┼──────────────────
              │              ┌──────▼───────────────────────▼──────┐
              │              │  TLS ingress — ONE origin           │
              │              │    `/`   → Next.js dashboard        │
              │              │    `/v1` → control plane :8787      │
              │              └──────┬──────────────────────────────┘
              │                     │  (sso mode: cookie passthrough only;
              │                     │   no admin token in the web app env)
              │              ┌──────▼──────────────────────────────┐
              └──────────────┤  fluidbox control plane (Rust)      │
                             │                                     │
                             │  public listener :8787              │
                             │    /v1 API · /v1/auth · /v1/admin   │
                             │    /v1/ingress (signature IS auth)  │
                             │    ── /internal is ABSENT here ──   │
                             │                                     │
                             │  internal listener :8788            │
                             │    /internal runner gateway         │
                             │    /internal/llm facade             │
                             │                                     │
                             │  orchestrator · workers · broker    │
                             └──┬────────┬─────────┬─────────┬─────┘
             session token only │        │         │         │
                    (:8788 only)│        │         │         │
      ┌─────────────────────────▼──┐  ┌──▼──────┐  │   ┌─────▼──────────────┐
      │ sandbox namespace          │  │ LiteLLM │  │   │ egress proxy /     │
      │ (fluidbox-sandboxes)       │  │ private │  │   │ firewall           │
      │                            │  │ network │  │   └─────┬──────────────┘
      │  per-run pod:              │  └──┬──────┘  │         │ Streamable HTTP,
      │   workspace init →         │     │         │         │ audience-bound
      │   runner (agent) →         │     ▼         │         ▼ credential
      │   collector (diff)         │  Anthropic /  │   admitted remote
      │                            │  OpenAI       │   MCP endpoints
      │  default-deny NetworkPolicy│  (provider    │
      │  zeroEgress: only :8788;   │   keys live   │   also from the control
      │  no DNS; no public route   │   here ONLY)  │   plane, same posture:
      └────────────────────────────┘               │    · git workspace fetch
                                                   │    · GitHub API (App JWT)
                             ┌─────────────────────▼───┐· result callbacks
                             │ Neon Postgres           │  (HMAC-signed)
                             │ direct (non-pooler),    │
                             │ TLS, LISTEN/NOTIFY      │
                             └─────────────────────────┘

The remote MCP server is normally not deployed by fluidbox; fluidbox brokers and governs access to an already-deployed remote endpoint.

## Listeners

| Listener | Serves | Reachable by |
|---|---|---|
| Public `:8787` | `/v1` API, `/v1/auth/*`, `/v1/admin/*`, `/v1/ingress/*`, dashboard proxy target | Browsers (via the single-origin ingress), CLI/API clients, webhook senders |
| Internal `:8788` | `/internal` runner gateway (`/permission`, `/events`, `/heartbeat`, `/result`, `/tools/call`), `/internal/llm` facade | **Only** sandbox pods, via the `zeroEgress` NetworkPolicy |

Under the Kubernetes provider, `/internal` is structurally **absent** from the public listener — route absence, not an authorization check. The sandbox namespace carries a default-deny Ingress+Egress NetworkPolicy whose default `zeroEgress` profile allows exactly one flow: sandbox → control-plane internal service `:8788`. No DNS, no public route, no LiteLLM, no `:8787`.

**Run admission is gated on proven enforcement.** A boot-time probe must demonstrate `+:8788 −:8787` before any run is admitted (`FLUIDBOX_REQUIRE_ENFORCED_NETPOL=true` by default); a cluster that does not enforce NetworkPolicy keeps runs blocked — fail-closed, never silently unprotected. `helm test` re-certifies the same property per release.

Additional pod hardening (shipped): sandbox pods mount no service-account token (`automountServiceAccountToken: false`), and the run tokens ride an immutable pod-owned Secret (garbage-collected with the pod), never a PodSpec literal. Since Phase E that Secret holds **four** keys — one per audience — and each container references only the keys it needs (the workspace-init container references only the workspace key).

## The outbound egress boundary (shipped, Phase E)

Every control-plane→outside dial goes through one of three lanes, and the first two are hardened:

| Lane | Client | Redirects | Used by |
|---|---|---|---|
| Broker / discovery / result callbacks | `egress_http` | **Refused** — `Policy::none`, and a 3xx *status* is refused identically; the `Location` target is never followed and never logged (a digest of the request URL at debug only) | Brokered MCP calls, the registration/refresh photograph, delivery callbacks |
| Identity + connector OAuth | `identity_http` | Re-validated per hop | Per-org OIDC discovery/JWKS/token exchange; and — new in Phase E — every connector-OAuth fetch (PRM, AS metadata, DCR, exchange, refresh) |
| Operator-configured seams | plain `http` client | Follows redirects | GitHub API, the LiteLLM upstream, LiteLLM key provisioning — deployment-configured destinations, deliberately not user-supplied |

Both hardened clients use an address-filtering DNS resolver. Because reqwest dials an **IP literal** without ever consulting the resolver, a pure pre-flight (`admit_url`: scheme policy + host-literal address class) fronts *every* dial site — this is the check that stops `https://169.254.169.254/…` from being reached directly. Blocked classes: private, loopback, link-local, multicast, reserved, benchmarking, documentation, IPv6 site-local, and the cloud-metadata address. Two knobs adjust it: `FLUIDBOX_EGRESS_ALLOW_CIDRS` (an opt-in allowlist for a deliberately-private endpoint; a malformed entry fails boot) and `FLUIDBOX_EGRESS_PROXY` (applied to both hardened clients *and* the git fetch subprocess). **With a proxy set, target DNS resolution moves to the proxy**, so the resolver's name-filtering no longer applies to proxied requests — `admit_url`'s literal/scheme checks still do, and the proxy becomes the egress control point, so it must be an allowlisting forward proxy.

Admission is enforced at **two** layers, not one: at **save** time (a connection's base URL on both `mcp_http` create paths; a subscription's callback URL) and again at **dial** time. Save-time admission is literal + scheme only — handlers deliberately do not resolve DNS — so it catches the typed-in mistake without turning a create request into a resolver.

**Workspace clone URLs are egress too**, including a credentialless (`authority: none`) fetch of a "public" repo. The clone guard runs before `git`: scheme allowlist (`https`, `http` only under the dev-loopback seam, `file://` only under the configured `FLUIDBOX_GITHUB_CLONE_BASE` prefix or that same dev seam), then host resolution with **every** returned address validated by the shared predicate. The subprocess additionally carries `-c http.followRedirects=false`, `GIT_LFS_SKIP_SMUDGE=1`, and `GIT_ALLOW_PROTOCOL=http:https:file`. **Disclosed residual:** this is resolve-then-validate — `git` is out-of-process and re-resolves the host independently, so a rebinding resolver can move the target between check and use.

## Edge inventory

Every edge, its initiator, its authentication, and its cargo:

| # | Edge | Initiator | Authentication | Carries | Never carries |
|---|---|---|---|---|---|
| 1 | Browser → ingress `/` (dashboard) — sso mode shipped (Phase B) | Browser | `__Host-fbx_web` session cookie (sso mode) | UI assets; proxied API calls with forwarded cookies, CSRF header, normalized `Origin`, and propagated `Set-Cookie` | The admin token — in `sso` mode it is not present in the web app's environment at all; a missing cookie fails 401, never falls back to operator authority. (The `admin` mode — local/single-admin deployments — injects the admin token server-side instead.) |
| 2 | Browser → `/v1` (same origin, via proxy) — shipped (Phase B) | Browser | Session cookie; CSRF custom header + `Origin` check on every non-GET; dual-credential requests (cookie **and** bearer) rejected | API requests/responses, SSE timelines (re-authorized on a ≤60 s interval) | Browser-supplied `tenant_id`/`user_id` as trusted fields — principals derive solely from verified sessions |
| 3 | CLI/API → `/v1` | Client | `Bearer fbx_pat_…` (shipped, Phase B; membership rechecked per use); trigger tokens for exactly their one subscription (shipped); admin token — confined to `/v1/admin/*` when `FLUIDBOX_REQUIRE_SSO=1` (shipped, Phase B) | API requests | CSRF headers (bearer clients are exempt — not ambient authority) |
| 4 | Webhook sender → `/v1/ingress/{provider}/{connection}` and `/v1/ingress/github/app/{registration}` | External service | Endpoint deliberately unauthenticated; the HMAC signature — against the connection's sealed secret, or the GitHub App **registration's** sealed secret on the App-level path — **is** the authentication; nothing is stored before it verifies | Signed event payloads (raw-body digests recorded) | Anything unverified reaching storage or run creation |
| 5 | Browser ↔ per-org IdP (login) — shipped (Phase B) | Browser | The IdP's own session/consent | OIDC authorization redirects (code + sealed `state`; `__Host-fbx_login_{flow}` cookie binds the initiating browser) | fluidbox credentials of any kind |
| 6 | Control plane → per-org IdP — shipped (Phase B) | Control plane | Sealed client secret (or PKCE-only public client) at the token endpoint | Discovery documents, JWKS, code exchange — all SSRF-validated (https, re-validated redirects, forbidden address classes), and never inside a DB transaction | `offline_access` requests; refresh tokens are discarded in v1 |
| 7 | Browser ↔ external authorization servers (connector OAuth consent legs → `GET /v1/oauth/callback`; GitHub App manifest/install round trips) | Browser | Both callbacks are deliberately unauthenticated routes: the AEAD-sealed `state` is the authentication. GitHub App flows additionally bind a per-flow `HttpOnly` cookie hash inside the one-time claim predicate (shipped); connector OAuth now does the same — one-time `connector_oauth_flows` rows + the `__Host-fbx_oauth_flow` browser binding, with endpoints/client/`resource`/verifier/generation frozen in the row (shipped, Phase D) | Authorization codes, sealed state, consent redirects | fluidbox bearer tokens (browser redirects cannot carry them — that is why the state must authenticate the full context) |
| 8 | Control plane → connector authorization servers | Control plane | A resolved OAuth client identity (pre-registered sealed secret → CIMD → DCR, shipped; shared, reusable client-registration objects — one `oauth_client_registrations` row per `(issuer, redirect_uri)`, DCR singleflighted by a Postgres advisory lock — now serve many grants (shipped, Phase D)) with PKCE S256 and RFC 8707 `resource=` on both legs | RFC 9728 protected-resource metadata, RFC 8414/OIDC discovery, token exchange, refresh-token rotation | Client/refresh credentials toward anything but the bound token endpoint; access tokens outside the connection's canonical resource base (audience binding). These fetches now ride `identity_http` behind an `admit_url` pre-flight at all six sites — PRM probe, AS metadata, DCR, exchange, refresh (shipped, Phase E, Gap 7) |
| 9 | Sandbox pod → internal `:8788` | Runner in pod | Four audience-scoped per-run session tokens, all `fbx_sess_…` (shipped, Phase E, Gap 10): `tool` for `/permission` + `/tools/call`, `control` for `/events`/`/heartbeat`/`/result`/token renew, `workspace` for the workspace fetch, `llm` for the facade. Each route requires its audience as the first thing its handler does; a mismatch is `403 {"error":"wrong_audience"}`, which the runner treats as a fatal misconfiguration. A legacy `'all'` token (minted before the split, or by a test forger) is still accepted everywhere — that DEFAULT is permanent, for in-flight sessions | Runner contract (`/permission`, `/events`, `/heartbeat`, `/result`), brokered tool intents, model traffic to the facade | Upstream MCP URLs/credentials, connection IDs, OAuth metadata, tenant keys — see [the sandbox contract](#the-sandbox-contract) |
| 10 | Facade → LiteLLM | Control plane | `LITELLM_MASTER_KEY` in `shared` mode; per-tenant LiteLLM virtual keys in `tenant` mode (`FLUIDBOX_LLM_KEY_MODE`, shipped Phase D — the master key mints/deletes virtual keys and never rides a routine model request) | Model requests with the real upstream credential swapped in; usage metering tees | The provider key toward the sandbox; LiteLLM is on a private network sandboxes cannot address |
| 11 | LiteLLM → model providers | Gateway | Provider API keys (they live **only** here) | Inference traffic | — |
| 12 | Broker → remote MCP endpoint | Control plane (broker) over the hardened `egress_http`, optionally via `FLUIDBOX_EGRESS_PROXY` (shipped, Phase E, Gap 7) | Per-call minted OAuth access token or sealed static credential, audience-bound to the connection's canonical resource URI, resolved after a live binding recheck | `initialize` (always, before any call) + `notifications/initialized`, `tools/call`, `MCP-Protocol-Version` on every post-initialize request, optional `MCP-Session-Id` (routing state, never authentication; the authorization header rides every request, including the terminal `DELETE`, whose credential is re-resolved live rather than cached) | Ambient transport state — the shared clients have no cookie jar (the `cookies` feature is off workspace-wide) and no cached per-host authentication (invariant 22); credentials toward non-admitted hosts; any redirect follow |
| 13 | Control plane → Kubernetes API | Control plane | Namespace-scoped service-account Role (plus an optional narrow probe ClusterRole when the sandbox namespace differs), used to manage per-run pods and their owner-referenced Secrets | Pod/Secret lifecycle for sandbox runs; pod status and enforcement-probe results back | Cluster-wide authority; and Kubernetes credentials never enter sandbox pods — they mount no service-account token at all |
| 14 | Control plane → Neon Postgres | Control plane | TLS, direct (non-pooler) connection string | All persistence; `LISTEN/NOTIFY` wakeups (the seq catch-up query remains the delivery source of truth) | — |
| 15 | Control plane → GitHub API | Control plane | App JWT → installation tokens (custody DB-gated, fresh status reads before the token cache serves) | Clone-credential minting, comment/check publishing via `result_deliveries` | Tokens in argv or on-disk git config — git credentials pass via ephemeral `GIT_CONFIG_*` env only |
| 16 | Delivery worker → result receivers | Control plane | `v1=hmac-sha256(secret, "{ts}.{body}")` per-subscription signatures | Terminal-state result payloads; at-least-once with receiver dedup on `x-fluidbox-delivery` | The ability to mutate a run — a dead receiver never affects the session (delivery is decoupled from lifecycle) |
| 17 | Control plane → git remotes (workspace fetch) | Control plane (orchestrator, `initializing` state) | Bound credential per the run's `workspace_fetch` binding — rechecked (status + generation + owner membership) immediately before the fetch — or explicitly `authority: none` (shipped, Phase C; pre-Phase-C in-flight runs resolve the embedded connection directly). The clone URL passes the git egress policy first: scheme allowlist, `file://` only under the configured clone base or the dev seam, and resolve-then-validate on every address (shipped, Phase E — TOCTOU residual disclosed above) | The repo fetch/copy; base commit recording | Redirect follows (`http.followRedirects=false`); LFS smudge fetches (`GIT_LFS_SKIP_SMUDGE=1`); protocols outside `http:https:file` (`GIT_ALLOW_PROTOCOL`); submodule/LFS endpoints without their own admission; any credential reaching the sandbox — the sandbox sees only the materialized copy at `/workspace` |

## The sandbox contract

The hosted sandbox has **no general internet route**. It reaches only the internal fluidbox run gateway (plus explicitly designed artifact/workspace channels and substrate control endpoints required by the execution provider).

The sandbox **receives**:

- task and system prompt;
- the workspace (a disposable materialized copy);
- frozen tool schemas and brokered server aliases;
- audience-scoped run credentials (LLM, tool-intent, runner-control, and workspace — each accepted only by its own endpoints; shipped, Phase E, Gap 10, with the same-uid `/proc/<pid>/environ` residual recorded in the [threat model](threat-model.md#accepted-residual-risks-documented-not-mitigated)); and
- tool results.

The sandbox **never receives**:

- a remote MCP URL;
- an OAuth access or refresh token;
- an API key;
- a connection ID;
- a connection owner identity;
- an OAuth client secret; or
- a tenant encryption key.

The model may choose a tool from the run's frozen set. It can never choose or change the credential, connection, or identity that executes it (invariants 4, 5).

## Provider postures

| Provider | Network posture | Hosted status |
|---|---|---|
| **Kubernetes** | Default-deny NetworkPolicy; `zeroEgress` profile (`:8788` only, no DNS); boot-gate-proven enforcement; optional gVisor/Kata runtime classes | **The hosted substrate** |
| **Docker** | `HostDev` mode (host-gateway reachability) for local dev; hardened per-session `internal: true` bridge for compose deployments | **Local development and single-host self-hosting — outside the hosted SaaS boundary.** The `HostDev` mode is a local-dev convenience, never a hosted security boundary; the provider itself is never demoted (dual-provider permanence) |
| Future substrates (MicroVM fleets, …) | Must provide structural guarantees equivalent to the Kubernetes path (Gap 6) before hosting runs | Deferred |

## Deployment invariants

- **One origin.** `/` → dashboard, `/v1` → API, same https origin — the Helm chart's ingress implements this; the CSRF/`Origin` model and cookie scope depend on it.
- **`FLUIDBOX_PUBLIC_URL` is the browser/AS-facing https base.** It feeds connector OAuth `redirect_uri`s, the CIMD client-id document, GitHub App flows, and the login callback. Hosted multi-user mode requires https + non-loopback; login refuses to start over plain http outside loopback dev.
- **The dashboard proxy's credential behavior is static deployment configuration** (`FLUIDBOX_WEB_MODE=admin|sso`), never a per-request decision. Hosted = `sso` = cookie passthrough only.
- **LiteLLM is reachable only on its private network.** Sandboxes can never address it directly; the facade is the only client.
- **The database is reached via the direct (non-pooler) string** — `LISTEN/NOTIFY` and sqlx prepared statements require it.

## Target-state deltas

What this diagram already guarantees structurally versus what later phases add on top:

| Delta | Today | Target | Phase |
|---|---|---|---|
| Browser authentication | Both modes shipped (Phase B): `sso` = `__Host-fbx_web` sessions, PATs, CSRF/`Origin` enforcement, per-org OIDC (edges 1–3, 5–6); `admin` = admin-token proxy for local/single-admin (Gaps 1–2 closed) | — (delivered) | B (shipped) |
| Run resource bindings | Typed `mcp`/`workspace_fetch`/`result_publish` bindings resolved before provisioning and written in the session transaction; broker, orchestrator, and delivery worker consume binding IDs and recheck status + generation + owner membership before secret access (Gap 3 closed; pre-Phase-C in-flight runs keep the embedded-connection path) | — (delivered) | C (shipped) |
| Connector OAuth callback binding | One-time `connector_oauth_flows` rows + per-flow `__Host-fbx_oauth_flow` cookie hash inside the atomic claim predicate (edge 7); endpoints/client/resource/verifier/generation frozen at start; shared reusable client registrations | — (delivered) | D (shipped) |
| Internal-gateway workload identity | Per-run bearer tokens, now narrowed to four audiences | Workload identity / mTLS **in addition to** run bearer tokens | **Still open** — Phase E did not build this; Gap 6's remainder carries forward |
| Sandbox credential audiences | Four audience-scoped tokens, enforced server-side at every internal route; both runners delete the runner-control token from `process.env` before spawning anything | Process-boundary isolation (uid split or sidecar) so a same-uid child cannot read the runner's initial `/proc/<pid>/environ` | E (shipped, Gap 10) for the server-enforced split; the process boundary is a follow-up — mTLS alone would not help while runner and untrusted code share one workload identity |
| Broker egress boundary | Shared hardened clients, `admit_url` pre-flight at every dial, redirect refusal, save-time admission on connection/callback URLs, clone-URL admission, optional egress proxy | — (delivered; residuals: git-clone TOCTOU, proxy-mode DNS) | E (shipped, Gap 7; the [admission policy](connector-admission-policy.md) is now enforced) |
| LLM quota | `shared` gateway key or per-tenant LiteLLM virtual keys (`FLUIDBOX_LLM_KEY_MODE`, master key confined to provisioning — shipped); durable request-keyed per-run reservations booked under a session-row lock | — (delivered; sole-claimant carve-out and the aggressive sweeper projection are disclosed residuals) | D (quota, shipped); E (reservation race, shipped, Gap 14) |
| Replicas | Approval single-emission + `pg_notify`, per-session orchestrator lease with epoch fencing, and per-row delivery claims are shipped (Phase E); the deployment shape is still single replica + `Recreate` with an RWO archive PVC | 2–3 stateless replicas: archive off RWO, durable cross-replica rate limiting, MCP session affinity | F (the remaining blockers), E (the coordination primitives, shipped) |

## Related documents

- [Product compatibility matrix](product-compatibility-matrix.md)
- [Connector admission policy](connector-admission-policy.md)
- [Threat model](threat-model.md)
- [Kubernetes deployment guide](../guides/kubernetes.md) — operational bring-up and enforcement certification
