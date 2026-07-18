# Hosted network architecture

**Date:** 2026-07-17
**Status:** Phase A deliverable of the multi-user MCP control plane epic (#28)
**Authority:** [`../plans/2026-07-14-multi-user-mcp-control-plane-design.md`](../plans/2026-07-14-multi-user-mcp-control-plane-design.md) (v4), [`../plans/2026-07-17-idp-agnostic-identity-design.md`](../plans/2026-07-17-idp-agnostic-identity-design.md) (v5), and — for the shipped substrate — [`../plans/2026-07-15-kubernetes-native-provider-design.md`](../plans/2026-07-15-kubernetes-native-provider-design.md) and the [Kubernetes guide](../guides/kubernetes.md).

This is the hosted network diagram: every plane, every listener, and every edge — who initiates it, how it authenticates, what crosses it, and what must never cross it. Edges are annotated with the phase that lands them where they are not shipped today — browser sessions/PATs shipped in Phase B; run resource bindings are Phase C — and every current-vs-target difference is listed explicitly in [Target-state deltas](#target-state-deltas), never implied.

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

Additional pod hardening (shipped): sandbox pods mount no service-account token (`automountServiceAccountToken: false`), and the run token rides an immutable pod-owned Secret (garbage-collected with the pod), never a PodSpec literal.

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
| 7 | Browser ↔ external authorization servers (connector OAuth consent legs → `GET /v1/oauth/callback`; GitHub App manifest/install round trips) | Browser | Both callbacks are deliberately unauthenticated routes: the AEAD-sealed `state` is the authentication. GitHub App flows additionally bind a per-flow `HttpOnly` cookie hash inside the one-time claim predicate (shipped); connector OAuth gains one-time server-side state rows + the same browser binding in **Phase D** | Authorization codes, sealed state, consent redirects | fluidbox bearer tokens (browser redirects cannot carry them — that is why the state must authenticate the full context) |
| 8 | Control plane → connector authorization servers | Control plane | A resolved OAuth client identity (pre-registered sealed secret → CIMD → DCR, shipped; today's DCR identities are stored per connection — shared, reusable client-registration objects serving many grants are **Phase D**) with PKCE S256 and RFC 8707 `resource=` on both legs | RFC 9728 protected-resource metadata, RFC 8414/OIDC discovery, token exchange, refresh-token rotation | Client/refresh credentials toward anything but the bound token endpoint; access tokens outside the connection's canonical resource base (audience binding); the full SSRF boundary for these fetches completes in **Phase E** (Gap 7) |
| 9 | Sandbox pod → internal `:8788` | Runner in pod | Per-run session token (`fbx_sess_…`) — today a single bearer for all audiences; Phase E splits LLM / tool-intent / runner-control audiences (Gap 10) | Runner contract (`/permission`, `/events`, `/heartbeat`, `/result`), brokered tool intents, model traffic to the facade | Upstream MCP URLs/credentials, connection IDs, OAuth metadata, tenant keys — see [the sandbox contract](#the-sandbox-contract) |
| 10 | Facade → LiteLLM | Control plane | `LITELLM_MASTER_KEY` today; per-tenant virtual keys land in Phase D (master key confined to provisioning) | Model requests with the real upstream credential swapped in; usage metering tees | The provider key toward the sandbox; LiteLLM is on a private network sandboxes cannot address |
| 11 | LiteLLM → model providers | Gateway | Provider API keys (they live **only** here) | Inference traffic | — |
| 12 | Broker → remote MCP endpoint | Control plane (broker), via the egress proxy (**Phase E**, Gap 7) | Per-call minted OAuth access token or sealed static credential, audience-bound to the connection's canonical resource URI | `initialize`, `tools/call`, optional `MCP-Session-Id` (routing state, never authentication; authorization header sent on every request) | Ambient transport state — shared HTTP clients have no cookie jar and no cached per-host authentication (invariant 22); credentials toward non-admitted hosts |
| 13 | Control plane → Kubernetes API | Control plane | Namespace-scoped service-account Role (plus an optional narrow probe ClusterRole when the sandbox namespace differs), used to manage per-run pods and their owner-referenced Secrets | Pod/Secret lifecycle for sandbox runs; pod status and enforcement-probe results back | Cluster-wide authority; and Kubernetes credentials never enter sandbox pods — they mount no service-account token at all |
| 14 | Control plane → Neon Postgres | Control plane | TLS, direct (non-pooler) connection string | All persistence; `LISTEN/NOTIFY` wakeups (the seq catch-up query remains the delivery source of truth) | — |
| 15 | Control plane → GitHub API | Control plane | App JWT → installation tokens (custody DB-gated, fresh status reads before the token cache serves) | Clone-credential minting, comment/check publishing via `result_deliveries` | Tokens in argv or on-disk git config — git credentials pass via ephemeral `GIT_CONFIG_*` env only |
| 16 | Delivery worker → result receivers | Control plane | `v1=hmac-sha256(secret, "{ts}.{body}")` per-subscription signatures | Terminal-state result payloads; at-least-once with receiver dedup on `x-fluidbox-delivery` | The ability to mutate a run — a dead receiver never affects the session (delivery is decoupled from lifecycle) |
| 17 | Control plane → git remotes (workspace fetch) | Control plane (orchestrator, `initializing` state) | Bound credential per the run's `workspace_fetch` binding (**bindings are Phase C** — today the orchestrator resolves the workspace credential directly) — or explicitly `authority: none` | The repo fetch/copy; base commit recording | Cross-origin redirect follows; submodule/LFS fetches without their own admission; any credential reaching the sandbox — the sandbox sees only the materialized copy at `/workspace` |

## The sandbox contract

The hosted sandbox has **no general internet route**. It reaches only the internal fluidbox run gateway (plus explicitly designed artifact/workspace channels and substrate control endpoints required by the execution provider).

The sandbox **receives**:

- task and system prompt;
- the workspace (a disposable materialized copy);
- frozen tool schemas and brokered server aliases;
- audience-scoped run credentials (LLM, tool-intent, and runner-control — each reaching only its own endpoints; the split is Phase E, Gap 10); and
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
| Run resource bindings | Brokered capability pins embed a concrete connection; the orchestrator resolves the workspace credential and the delivery worker resolves publish credentials directly (Gap 3) | Typed `mcp`/`workspace_fetch`/`result_publish` bindings; orchestrator, broker, and delivery worker consume binding IDs (edge 17) | C |
| Connector OAuth callback binding | Stateless sealed `state`; no server-side one-time row, no browser binding | One-time state rows + per-flow cookie hash inside the claim predicate (edge 7) | D |
| Internal-gateway workload identity | Per-session bearer token only | Workload identity / mTLS in addition to run bearer tokens | E (Gap 6 remainder) |
| Sandbox credential audiences | One token holds every audience; agent-executed code can read it | LLM / tool-intent / runner-control split; runner-control credential unreachable from agent subprocesses (OS identity or sidecar separation — mTLS alone does not help when runner and untrusted code share one workload identity) | E (Gap 10) |
| Broker egress boundary | URL audience binding; discovery/custom-endpoint fetches not yet a complete SSRF boundary | Egress proxy, IP/redirect/DNS-rebinding validation everywhere, private-endpoint admission policy | E (Gap 7; policy stated in the [admission policy](connector-admission-policy.md)) |
| LLM quota | Shared gateway key | One LiteLLM virtual key per tenant per environment; master key confined to provisioning; durable per-run budget reservations | D (quota), E (reservation race, Gap 14) |
| Replicas | Single replica + `Recreate`; RWO archive PVC | 2–3 stateless replicas behind the statelessness inventory (leases, epoch fencing, delivery claims, archive off RWO) | F |

## Related documents

- [Product compatibility matrix](product-compatibility-matrix.md)
- [Connector admission policy](connector-admission-policy.md)
- [Threat model](threat-model.md)
- [Kubernetes deployment guide](../guides/kubernetes.md) — operational bring-up and enforcement certification
