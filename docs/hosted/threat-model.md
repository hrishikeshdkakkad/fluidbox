# Hosted threat model

**Date:** 2026-07-21
**Status:** Phase A deliverable of the multi-user MCP control plane epic (#28); rows re-verified against shipped code at the end of Phase E
**Authority:** [`../plans/2026-07-14-multi-user-mcp-control-plane-design.md`](../plans/2026-07-14-multi-user-mcp-control-plane-design.md) (v4, security invariants 1–22 and Gaps 1–14) and [`../plans/2026-07-17-idp-agnostic-identity-design.md`](../plans/2026-07-17-idp-agnostic-identity-design.md) (v5, identity invariants 1–12). Vulnerability reporting: [`SECURITY.md`](../../SECURITY.md).

This threat model covers the hosted multi-user deployment (~300 seats). It is deliberately honest about time: Phase B landed per-organization identity and per-tenant repository scoping, Phase C landed connection ownership + per-run resource bindings, Phase D landed KMS envelope sealing + one-time browser-bound / reusable connector OAuth + per-tenant LiteLLM virtual keys + database-enforced RLS, and Phase E landed the shared egress boundary, the per-run MCP session manager + 2025-11-25 conformance, server-side frozen-schema enforcement, durable execution claims, audience-scoped sandbox credentials, multi-replica approval/lease/delivery coordination, and durable LLM budget reservations; every mitigation below still carries a **status** — `shipped` or the phase (F) that closes it. A row marked with an unshipped phase is a *known open risk* until that phase lands. **Two Phase E rows are only partly closed and say so in place** (the runner-control audience split, which is enforced at the server but not by process isolation; and Gap 6's workload-identity remainder). Everything Phase E closed is enforced in code and covered by `scripts/hardening-e2e.sh` except the three properties named under [Verification](#verification).

## Core assumption: the sandbox is compromised

fluidbox does not try to prevent sandbox compromise — it **assumes** it. Prompt injection means the agent itself must be modeled as adversarial, and the agent executes arbitrary code by design. The security model therefore never depends on sandbox good behavior: everything of value is structurally unreachable from inside (no credentials, no upstream URLs, no general egress), and everything the sandbox *can* do passes the control plane's single decision gate. Capability ≠ permission ≠ containment: three independent layers, and weakening one never weakens the others.

## Assets

| # | Asset | Where it lives |
|---|---|---|
| A1 | Upstream connector credentials (OAuth refresh tokens, static API keys, GitHub App private keys, webhook/delivery secrets) | AEAD-sealed at rest (`seal.rs`): v1 under the deployment-wide `FLUIDBOX_CREDENTIAL_KEY`, or — when KMS envelope sealing is enabled (`FLUIDBOX_KMS_MODE`, off by default) — v2 under a per-tenant DEK wrapped by a KEK, with a per-column `_key_version` companion; access tokens minted at call time, cached in memory only |
| A2 | Identity secrets (IdP client secrets, PKCE verifiers, browser-session tokens, PATs) | Sealed columns; session/PAT secrets stored only as sha256 |
| A3 | Tenant data (runs, event ledger, artifacts, workspace source code, connection metadata) | Postgres + workspace archive volume |
| A4 | Model spend and compute (LLM budgets, sandbox capacity) | Facade budget stops; per-run budgets; LiteLLM keys |
| A5 | Audit integrity (append-only ledger, auth audit log) | `append_event()` gapless sequences; `Redacted<EventEnvelope>`-only sink; INSERT/SELECT-only audit role |
| A6 | Control-plane infrastructure secrets (`DATABASE_URL`, sealer key, admin token, LiteLLM master key) | Deployment Secret; never in sandboxes or the ledger |
| A7 | External side-effect authority (the power to execute writes upstream: MCP writes, PR comments/checks, result callbacks) | Exercisable only through the gate + frozen run resource bindings |

## Adversaries

| # | Adversary | Capability assumed |
|---|---|---|
| T1 | Prompt-injected / misbehaving model | Full control of tool-call intents and sandbox-side output; reads everything in the sandbox |
| T2 | Compromised sandbox workload | Arbitrary code execution inside the pod/container, including reading the process environment |
| T3 | Malicious or compromised remote MCP server | Controls tool names/descriptions/schemas/results; can rug-pull, drift schemas, set cookies, redirect, stall streams |
| T4 | Malicious tenant insider | A valid low-privilege membership in the organization |
| T5 | Cross-tenant attacker | A valid membership in a *different* organization |
| T6 | Unauthenticated network attacker | Can reach public endpoints: webhook ingress, login/OAuth callbacks, the ingress origin |
| T7 | Stolen-credential holder | Possesses a leaked PAT, session cookie, trigger token, or authorization URL |
| T8 | Compromised or rogue org IdP | Controls ID tokens for its own organization |
| T9 | Malicious connector definition | A crafted custom endpoint/catalog entry used as an SSRF or exfiltration vehicle |
| T10 | Operator error | Honest-but-fallible break-glass and configuration actions |

## Trust boundaries

The [network architecture](network-architecture.md) enumerates the edges; the boundaries that matter are:

| # | Boundary | Crossing discipline |
|---|---|---|
| B1 | Browser ↔ control plane | `__Host-` cookies, CSRF header + `Origin` on cookie-authenticated non-GETs, one-time browser-bound flows, dual-credential rejection |
| B2 | Sandbox ↔ internal gateway (`:8788`) | Four audience-scoped per-run tokens (`llm`/`tool`/`control`/`workspace`), each accepted only by its own routes; `zeroEgress` NetworkPolicy is the only route; every tool intent passes the single gate |
| B3 | Control plane ↔ remote MCP endpoints | Broker-only egress through the shared SSRF-hardened client (admission pre-flight at every dial, no redirect following); admission policy enforced at save and dial; audience-bound credentials; ambient-state-free transport; per-tenant/connection/host rate limits and per-(connection, host) circuit breakers |
| B4 | Control plane ↔ per-org IdP | Discovery/JWKS/token fetches SSRF-validated; full ID-token verification; no DB transaction spans IdP I/O |
| B5 | Webhook senders ↔ ingress | HMAC against sealed secrets is the authentication; verify-before-store; DB-unique dedup |
| B6 | Tenant ↔ tenant (inside one deployment) | `TenantScope` repository methods (primary), composite `(tenant_id, id)` FKs, RLS as depth |
| B7 | Control plane ↔ model gateway | Facade-only path; provider keys live only in LiteLLM; sandboxes cannot address it |
| B8 | Operator ↔ deployment | Admin token confined to `/v1/admin/*` under `FLUIDBOX_REQUIRE_SSO=1`; transactional audit |

## Scenarios and controls

Statuses: **shipped** = enforced in code today (`shipped (Phase B)`/`shipped (Phase C)`/`shipped (Phase D)`/`shipped (Phase E)` mark a row that phase closed); **partially shipped** = the row names exactly which half is enforced and which is not; **Phase F** = the phase that closes it (open risk until then).

### T1/T2 — the compromised sandbox and the model itself

| Attack | Control | Status |
|---|---|---|
| Exfiltrate an upstream credential from the sandbox | Credentials never enter the sandbox (invariants 1, 2): LLM key swapped at the facade, git credentials control-plane-side via ephemeral `GIT_CONFIG_*`, MCP credentials used only by the broker | shipped |
| Reach the internet / LiteLLM / metadata endpoints directly | `zeroEgress` NetworkPolicy (only `:8788`; no DNS), boot-gate-proven enforcement, no service-account token in the pod (invariant 3) | shipped (Kubernetes provider; subject to the accepted EKS pod-start enforcement window below) |
| Call a tool outside the frozen set, or a rug-pulled/drifted tool | Frozen-set availability check at the gate — drifted or vanished tools are denied (`source=capability`); a live upstream tools-list change never mutates an in-flight run (invariant 14) | shipped |
| Choose *whose* credential executes a tool | The model chooses only among frozen tools; bindings are frozen at run creation; the broker resolves the credential solely from the run's `run_resource_bindings` row (invariants 4, 5) | shipped (Phase C; pre-Phase-C in-flight runs keep the embedded-connection path with a status-only recheck — see residuals) |
| Bypass the permission callback (autonomy modes) | The callback stays wired in both modes — never the SDK's `bypassPermissions`; autonomous mode rewrites `RequireApproval` to the policy fallback inside `evaluate()`, ledgering both verdicts | shipped |
| Impersonate runner-control actions (report results, heartbeats) after reading the process env | The run's bearer is split into **four audience-scoped tokens** (`llm`, `tool`, `control`, `workspace`) — separate `api_tokens` rows sharing the `fbx_sess_` prefix — and every internal route requires its audience as the first statement of its handler; a mismatch is `403 {"error":"wrong_audience"}`. The Kubernetes provider routes one key per audience out of the pod-owned Secret (the workspace-init container references only the workspace key), and both runner images `delete process.env.FLUIDBOX_SESSION_TOKEN` (the runner-control token) before spawning any agent or tool subprocess; the shims are handed only the tool/LLM tokens. **The narrowing is real and server-enforced; process isolation is not.** Agent code running as the same uid can still read the runner's *initial* environment via `/proc/<pid>/environ` — the scrub covers the spawned environment only | **partially shipped (Phase E)** — invariant 19's testable acceptance bullet ("agent code cannot reach runner-control endpoints with the LLM or tool-intent credential") is enforced; true process isolation (uid split or sidecar) is **not built** — see residuals |
| Overspend the per-run LLM budget with parallel calls | Durable request-ID-keyed reservations (`llm_reservations`, migration 0022): each facade request books a conservative estimate inside a transaction that takes the session row `FOR UPDATE` first, so two concurrent requests can no longer pass the same remaining budget; the reservation reconciles against the authoritative usage row (same request id ⇒ idempotent under the `usage_entries.external_id` unique index) and the sweeper converts an expired un-reconciled reservation into a conservative charge rather than assuming zero. **Carve-out, stated plainly:** when a request is the *sole* claimant (zero other live reservations) the budget arms are skipped, so one request can proceed over budget — bounded and disclosed in the residuals. **shipped (Phase D)**: per-tenant LiteLLM virtual keys (`FLUIDBOX_LLM_KEY_MODE=tenant`) remain the fairness backstop — each carries its own server-side spend/token/rate ceiling | shipped (Phase E — concurrency race, Gap 14; the terminal "out of budget" verdict still comes from the accumulated check + the budget sweeper) |
| Replay a decided tool call to execute the write twice | Durable execution claims (`tool_execution_claims`, migration 0019) unique on `(session_id, tool_call_id, input_digest)` and tenant-scoped by a composite FK: one dispatch per claim, a duplicate adopts the stored outcome verbatim instead of re-sending, and states are `claimed → succeeded \| failed_upstream \| failed_before_send \| ambiguous`. Only `failed_before_send` — reached solely on positive proof that no request was written (URL admission refusal, auth/binding failure, breaker-open, `reqwest` `is_connect()`) — is ever re-claimed (invariant 16) | shipped (Phase E) |
| Execute a late-approved call after cancellation/budget termination | The claim transaction takes the session row `FOR UPDATE` and reads terminality from that locked row, so a claim is refused the moment the session stops accepting work; the approval waiter additionally re-reads terminality *after* the wait, not just before it (invariant 18) | shipped (Phase E) |
| Poison the ledger with prompts/secrets | The sink accepts only `Redacted<EventEnvelope>` (constructible solely via the redactor) — digests, usage, cost only | shipped |

### T3 — the malicious MCP server

| Attack | Control | Status |
|---|---|---|
| Poisoned tool names/descriptions (ANSI, zero-width, injection copy) | Names and schemas are screened and validated at the registration photograph; descriptions, annotations, arguments, and results are untrusted input end to end (invariant 13) | shipped |
| Schema rug-pull between registration and run | Snapshots append-only; runs execute against their frozen schemas and digests | shipped |
| Malicious arguments accepted because the schema is only advertised | Server-side argument validation against the run's **frozen** input schema, run at the gate immediately after frozen-set availability and before trust tier/policy: the schema itself is pre-guarded as untrusted input (≤256 KiB serialized, depth ≤32, every `$ref` must be local — a violation makes the tool un-callable), arguments are bounded (≤1 MiB, depth ≤64), external `$ref` resolution is denied by a deny-everything retriever, and the JSON Schema dialect is chosen from the snapshot's protocol version (`2025-11-25` ⇒ 2020-12 per SEP-1613; any other recorded version ⇒ draft-07; a surface frozen before the field ⇒ 2020-12). Rejections ride the existing deny plumbing (`source=schema`) and surface to the model as a tool-execution error, never a protocol error (Gap 12, invariant 17) | shipped (Phase E) |
| Cross-user/run session bleed via `MCP-Session-Id` or cookies | A per-run upstream session registry keyed `(run, peer)` — never shared across runs or users (invariant 11); `initialize` happens before any call (the stateless-first path is deleted), `MCP-Protocol-Version` rides every post-initialize request, and the authorization header is sent on **every** upstream request including the terminal `DELETE`, whose credential is re-resolved live rather than cached. The shared transport is ambient-state-free: no cookie jar (the reqwest `cookies` feature is off workspace-wide) and no cached per-host authentication (invariant 22) | shipped (Phase E — per-run session manager + conformance contract, Gap 8) |
| Insufficient-scope challenge used to phish scope escalation | An SEP-835 `insufficient_scope` challenge on a 401/403 is terminal for the call — no re-mint, no retry — and marks the connection `status='error'` with `insufficient_scope: reconnect with more scopes` (the server's requested scopes recorded in the note only) plus token eviction; create_run, photograph, and the broker all already fail closed off connection status. The broker never auto-escalates a frozen grant | shipped (Phase E) |
| Blind retry of an ambiguous write | Ambiguous outcomes are ledgered as such (`tool.brokered` carries the outcome; the dashboard paints `ambiguous` amber, not red) and never auto-retried (invariant 15); only positively-proven `failed_before_send` is re-claimable, and a `claimed` row swept past its expiry becomes `ambiguous` rather than being re-dispatched | shipped (Phase E) |
| Server-to-client requests (sampling/elicitation) abused to stall or socially engineer | Unsupported client capabilities are never advertised; a server→client **request** gets a JSON-RPC `-32601` posted back on the same session, notifications are ignored (`tools/list_changed` logged, never applied to an in-flight run), and the SSE reader is a bounded incremental assembler (per-event cap, total cap) so a stalled or oversized stream errors instead of hanging (Gaps 8, 9 — the [compatibility matrix](product-compatibility-matrix.md) states the boundary) | shipped (Phase E) |

### T4/T5 — insiders and cross-tenant attackers

| Attack | Control | Status |
|---|---|---|
| Read or bind another user's personal connection | Connection ownership (`owner_type`, `owner_user_id`); binding verification; personal connections invisible to other members — 404-not-403, admins included (they act through their own viewer lens) | shipped (Phase C) |
| Approve an action so it runs under someone else's credential | Approval permits the proposed action under the credential already frozen into the run — never the approver's (invariant 8); approvers need `approval.decide_own`/`approval.decide_org`; no role — including admin or the operator — authorizes approval under another user's personal connection, and only its owner-who-invoked may decide it (`authorize_approval_decision`) | shipped (approval RBAC Phase B; personal-connection authority Phase C) |
| Read another tenant's runs/events/artifacts by UUID | `TenantScope` repository signatures (primary), composite tenant FKs, cross-tenant negative test matrix; UUID unpredictability is not authorization (invariant 10); RLS now enforces the same tenant floor in the database (migration 0018: 37 tenant-owned tables `ENABLE`+`FORCE`, GUC-driven policies via `scoped_tx`/`worker_tx`; the negative tests run as the non-owner `fluidbox_runtime` role). **Two caveats, both operational:** the two tables holding cross-tenant SHARED rows (`connector_catalog`, `oauth_client_registrations`) are readable by every scope by design — writes to those global rows are bypass-only, so the floor covers mutation but not visibility of shared reference data; and RLS is **inert for a SUPERUSER or BYPASSRLS role** (Neon's default `neon_superuser`), which is not inherited through role membership — set `FLUIDBOX_RUNTIME_ROLE` and verify with `just doctor`. Multi-user boot now **REFUSES** that state (`FLUIDBOX_REQUIRE_SSO=1` + a bypassing effective pool role ⇒ `REFUSING TO BOOT`, unless `FLUIDBOX_ALLOW_RLS_BYPASS=1` accepts it for local single-user work), and the runtime role itself is posture-validated (no LOGIN/SUPERUSER/BYPASSRLS/CREATEROLE/CREATEDB/REPLICATION, no memberships, no other members) in both the migration and every boot, since PostgreSQL roles are cluster-global while the grants are database-local. **`SET ROLE` is not a credential boundary** — see below | shipped (Phase B `TenantScope` + composite keys; Phase D RLS depth) |
| See tenant existence via login routing | The neutral entry page never enumerates organizations and answers identically for unknown and IdP-less slugs | shipped (Phase B) |
| A trigger token used beyond its subscription | Subscription-scoped, sha256-hashed tokens: invoke exactly one subscription, poll only runs it created; invoke overrides are opt-in and can only narrow | shipped |
| A member reads runs they shouldn't | `run.read` visibility rules (own runs; token-created runs; `subscriptions.manage`; `runs.read_all`) on every session/event/artifact/approval/SSE query | shipped (Phase B) |
| Custom connector admitted by one tenant becomes bindable in another | Custom definitions tenant-scoped (partial unique indexes: global slug + per-tenant custom slug); unattributable legacy rows disabled at the 0013 backfill | shipped (Phase C) |

> **Do not size this model around the runtime role.** `SET ROLE` narrows the
> authority of the ordinary application queries this process issues; it is NOT a
> credential boundary. `RESET ROLE` returns the same connection to the migration
> owner, and the process still holds the owner `DATABASE_URL` and can open a fresh
> owner connection — so it does not defend against process compromise or SQL
> injection. Genuine separation needs distinct migration-owner and runtime-LOGIN
> connection strings, with the runtime login owning no schema objects and carrying
> no bypass attributes; fluidbox runs one `DATABASE_URL` today. What the split does
> buy is containment of fluidbox's OWN bugs: a query that lost its tenant scope
> returns zero rows instead of every tenant's. Operational residuals, stated plainly:
> the role's membership checks are DIRECT-only (a transitive path runs through a
> role that is already an admin over the connecting user, so flagging it would
> refuse every managed host); `audit_select` remains tenant-or-null-or-bypass (the
> INSERT floor is the one that was tightened); and the RLS-bypass boot gate is fatal
> only under `FLUIDBOX_REQUIRE_SSO=1` — single-user deployments warn.

### T6 — the unauthenticated network

| Attack | Control | Status |
|---|---|---|
| Forged webhook creates runs | HMAC is the authentication — against the connection's sealed secret, or the GitHub App registration's sealed secret on the App-level ingress path; nothing stored before verification | shipped |
| Replayed webhook duplicates fan-out | Two DB-unique dedup levels bound to the session insert in one transaction — retries heal, never duplicate | shipped |
| Login CSRF / forced login into an attacker's session | Session replacement is never silent: `pending_login_switches` one-time browser-bound confirmation (cookie hash inside the claim predicate, 120 s expiry, current-session equality in the predicate) | shipped (Phase B) |
| Replayed / attacker-completed OAuth or login callback | One-time server-side state rows; a per-flow `HttpOnly` `__Host-fbx_oauth_flow` cookie whose sha256 sits inside the atomic single-use claim predicate — a leaked authorization URL can neither complete nor burn a flow. Connector OAuth (invariant 20) freezes its full binding set into the `connector_oauth_flows` row at start — authorization/token endpoints, resolved client, `resource`, sealed PKCE verifier, and the connection's `authorization_generation` — and the callback exchanges against the frozen row (closing AS mix-up) and refuses a moved generation; the GitHub App and login flows use the same one-time cookie-hash claim mechanism with their own, flow-appropriate binding sets | shipped (GitHub App, login; connector OAuth Phase D, invariant 20) |
| Cross-user grant injection (victim's consent seals into attacker's connection) | The completing browser must prove it started the flow — the `__Host-fbx_oauth_flow` cookie-hash predicate sits inside the one-time claim, so a *leaked* authorization URL can neither complete nor burn a flow (shipped). It does NOT stop a **transferable `go_url`**: the `/go` boot token carries the cookie plaintext, so whichever browser opens the link *becomes* the initiating browser. The callback then activates directly, with no connected-account confirmation — and a confirmation only helps under the conditions spelled out in the [residual below](#residual-detail--the-transferable-connector-oauth-go_url) | partially shipped (Phase D — leaked-URL binding); **transferable-`go_url` lure OPEN** |
| CSRF against cookie-authenticated APIs | Custom header + `Origin` check on every cookie-authenticated non-GET; `CorsLayer::permissive()` removed in the same change; GET writes limited to the enumerated protocol-forced flows, each with its own one-time claims | shipped (Phase B) |
| SSRF via crafted endpoints, discovery documents, redirects, or DNS rebinding | One shared egress boundary (`egress.rs`) behind two hardened clients: `egress_http` (broker MCP + discovery + delivery callbacks) refuses redirects outright (`Policy::none`, and a 3xx status is refused identically — the `Location` is never echoed, only digested at debug), and `identity_http` (OIDC **and**, since Phase E, all connector-OAuth traffic) re-validates every hop. Both use an address-filtering DNS resolver, and because reqwest dials an **IP literal** without ever consulting the resolver, a pure `admit_url` pre-flight (scheme + host-literal address class) fronts every dial site: broker, deliveries, and all six connector-OAuth fetches. Blocked classes include private, loopback, link-local, multicast, reserved, benchmarking, documentation, and the cloud-metadata address — with an explicit operator escape hatch (`FLUIDBOX_EGRESS_ALLOW_CIDRS`, malformed ⇒ boot failure) and an optional `FLUIDBOX_EGRESS_PROXY` applied to both clients and the git subprocess. Admission also runs at **save** time (connection base URL, subscription callback URL) so a bad endpoint is refused where it is typed, not only at first dial | shipped (Phase E — Gap 7; the [admission policy](connector-admission-policy.md) is now enforced, not just stated). Residuals: with a proxy configured, DNS moves to the proxy so name-filtering no longer applies to proxied requests (`admit_url` literal/scheme checks still do — point it at an allowlisting forward proxy); and the git clone path resolves-then-validates while git re-resolves independently (TOCTOU) |
| Amplification via unauthenticated login/callback endpoints | Rate limits per IP and per org; caps on outstanding unconsumed flows; flow claims commit before any IdP I/O so slow IdPs cannot hold DB connections | shipped (Phase B) |

### T7 — stolen credentials

| Attack | Control | Status |
|---|---|---|
| Stolen PAT self-replicates | A PAT can never mint, extend, or revoke PATs (including itself); TTL clamped (90 d default / 1 y max) | shipped (Phase B) |
| Stolen PAT outlives the person | Membership status and roles re-read on every use; deactivation kills sessions and PATs in one transaction | shipped (Phase B) |
| Stolen session cookie rides forever | Server-side session rows (revocable), sliding idle expiry capped by an absolute expiry, `__Host-` prefix, HttpOnly, SameSite=Lax; long-lived streams re-authorize on a ≤60 s interval | shipped (Phase B) |
| Stolen trigger token reaches the admin surface | Token kinds are mutually exclusive (relationally CHECK-enforced); trigger tokens never touch `/v1`-admin routes; the admin token can never invoke a trigger | shipped |
| Leaked run session token used from outside | Reaching `:8788` requires being inside the sandbox network path, and since Phase E a leaked token is narrowed to its audience — an exfiltrated tool token cannot report results or heartbeats, an exfiltrated LLM token cannot call a tool. What is still missing is a *second factor on the caller*: nothing binds the connection to a workload identity, and there is no mTLS on the internal gateway — the bearer alone authenticates | shipped (network + audience narrowing) / **Gap 6 remainder OPEN**: workload identity / mTLS is **not built** in Phase E |
| Revoked connection's cached access token keeps working | Custody is DB-gated, not cache-gated: every credentialed consumer (broker MCP call, workspace fetch, result publish) rechecks live status + authorization generation + owner membership before any cached token is minted or served; the in-memory token cache is keyed by `(connection, generation)` and a generation bump evicts it | shipped (GitHub custody pattern; Phase C broker/workspace/publish rechecks + generation-keyed cache; a per-connection Postgres advisory lock — `pg_advisory_xact_lock` keyed on the connection id — serializes OAuth refresh across replicas, closing Gap 4) |

### T8 — the compromised IdP

A compromised org IdP mints valid identities **for that organization only** — the blast radius is bounded by construction:

| Attack | Control | Status |
|---|---|---|
| Forge identities in another org | Identity key is `(tenant_id, idp_config_id, subject)`; `iss` verified per token; `sub` never trusted across issuers | shipped (Phase B) |
| Mint the org's root authority from a claim | `owner` is never grantable from IdP claims absent explicit operator opt-in (`allow_owner_mapping`); bootstrap-owner promotion is a single-winner atomic claim requiring a verified email match, an unexpired arm, and no active owner | shipped (Phase B) |
| Symmetric-key forgery (`alg=HS256` with the shared client secret) | `none` and all symmetric algorithms rejected unconditionally; the allowlist can only narrow within the asymmetric set | shipped (Phase B) |
| Token substitution/replay across flows | Full verification: exact `iss`, `aud`+`azp` rules, `exp`/`iat`/`nbf` with bounded skew, `iat` bound to the flow's lifetime, `nonce` single-use, `at_hash` when present | shipped (Phase B) |
| Locked-out org after IdP death | Break-glass rides the operator admin token, independent of any IdP; issuer migration is a staged atomic swap that cancels old flows and revokes old sessions | shipped (Phase B) |

### T9/T10 — malicious definitions and operator error

| Attack | Control | Status |
|---|---|---|
| Custom endpoint as an internal-network probe | Admission address rules are now **enforced in code** at three layers — connection create (both `mcp_http` paths), subscription callback save, and every dial — plus broker-only egress and per-connection rate limits/circuit breakers that bound probe volume from one replica. Private endpoints remain BYOC/relay/explicit-approval only | shipped (Phase E enforcement; the rate limits and breakers are **per-replica**, so an N-replica deployment's ceiling is N× the configured value) |
| Catalog entry masquerading as trusted | Catalog is untrusted reference data; curated display bypasses no verification, policy, or approval | shipped |
| Operator break-glass abuse or mistakes | Explicit `/v1/admin/*` surface; accepted mutations audit in the same transaction (fail together); rejected attempts audited after rollback; arming refused while an active owner exists; arms expire | shipped (Phase B) |
| Sealer-key loss orphans credentials | KMS envelope sealing moves the trust root off the single deployment key onto per-tenant DEKs wrapped by a KEK you control (`FLUIDBOX_KMS_MODE` `static`/`aws`); a resumable, count-parity-verified re-seal job (`POST /v1/admin/reseal`) migrates legacy v1 blobs to v2, and the legacy key retires only when boot proves zero v1 rows. Retiring `FLUIDBOX_CREDENTIAL_KEY` is now a supported migration (losing it before the re-seal orphans the remaining v1 rows). Custody then roots on the KEK: *losing the KEK is unrecoverable* from the moment any v2 row exists, and after retirement it loses ALL custody — by design, so back it up (see [kms-operations.md](kms-operations.md)) | shipped (Phase D) |
| Gateway supply chain (the LiteLLM malware incident) | Image pinned by digest, never floating tags; private network only; replaceable below the governance plane — Rust owns identity, policy, budget decisions, and the canonical ledger | shipped |

## Explicitly out of scope (assumed trusted)

- **The substrate**: Kubernetes control plane, the enforcing CNI (though enforcement is *probed*, never assumed — runs stay blocked without proof), node kernels (optional gVisor/Kata runtime classes raise this tier), and the cloud provider.
- **Neon Postgres** as a data custodian (TLS, direct connections; DB compromise is game over for A3/A5 by definition — mitigated by sealed credentials for A1/A2 and, as of Phase D (shipped), KMS envelope keys whose KEK lives outside Postgres, so a stolen database dump cannot open v2 custody).
- **Model providers** (Anthropic/OpenAI) receiving prompts via the gateway.
- **The org's own IdP within its org** — see T8: trusted *for its organization*, structurally unable to cross tenants.
- Malicious code changes in fluidbox itself (supply chain of this repo; CI, review, and release signing are process controls outside this document).

## Accepted residual risks (documented, not mitigated)

| Residual | Rationale |
|---|---|
| **Bootstrap owner shared-email**: if two distinct IdP subjects share the armed verified email, the first to log in wins | Email is not an identity; the operator armed a specific address deliberately; the audit row records the winning `sub`; re-arming is one break-glass call away |
| **IdP-side-only deactivation window**: an actively-used session survives until its absolute expiry (default 7 d) if the org deactivates the user only at the IdP | Stated honestly (identity design, Lifecycle): sliding idle expiry bounds only inactive sessions. Operators needing tighter bounds lower the absolute TTL or deactivate in fluidbox (immediate cascade) |
| **At-most-once dispatch, not exactly-once**: an ambiguous upstream outcome stays ambiguous | True exactly-once side effects are not achievable over MCP; ambiguity is surfaced to policy/user/model, never hidden or blindly retried |
| **VPC CNI standard-mode pod-start window** (EKS): a just-created pod is briefly fail-open until the node agent programs its eBPF rules | Observed live on EKS; strict mode is worse (it starves system pods). No duration or ordering guarantee relative to runner startup is claimed — the boot gate and long-lived probes are the authoritative enforcement signals, and the shipped isolation row above is qualified by this window |
| **Result delivery is at-least-once** | Receivers dedup on `x-fluidbox-delivery`; provider idempotency / deterministic markers cover the crash window between remote creation and recording. Phase E added per-row delivery claims (`FOR UPDATE SKIP LOCKED`, re-stamped immediately before each attempt), which stop two replicas delivering the same row concurrently — a crashed claimant's rows still park for up to the claim TTL (300 s, derived from the worst-case single publish attempt) before another replica may take them |
| **Same-uid `/proc/<pid>/environ` read of the runner-control token** | The env scrub covers the *spawned* environment; a same-uid child can still read the runner's initial environ. Closing it needs a uid split or a sidecar (a follow-up ticket, not a Phase E deliverable). Docker's `HostDev` network mode is explicitly not a boundary at all — it is a local-dev convenience |
| **Outbound rate limits and circuit breakers are per-replica** | They are in-memory on `AppState`, so the deployment-wide ceiling is N× the configured value with N replicas — the same class as the pre-existing per-replica `MINT_BUDGET`. They are an abuse/fairness control, not a quota system; durable cross-replica limiting is Phase F |
| **Git clone resolve-then-validate (TOCTOU)** | The clone URL's host is resolved and *every* returned address validated with the shared predicate before `git` runs — but `git` is out-of-process and re-resolves independently, so a rebinding resolver can still move the target between check and use. Bounded by: the fetch is credential-scoped to its binding, redirects are disabled (`-c http.followRedirects=false`), LFS smudging is off, and `GIT_ALLOW_PROTOCOL` is pinned. `file://` clone URLs are permitted only under the configured `FLUIDBOX_GITHUB_CLONE_BASE` prefix or the dev-loopback seam |
| **No result-vs-`outputSchema` validation** | `outputSchema` and `structuredContent` are now *preserved* end to end (schema folded into the tool digest when present; structured content relayed to the runner and covered by the result digest) — but a result is not validated against the tool's `outputSchema`. Untrusted-result handling is unchanged: results are untrusted input regardless |
| **Per-tenant egress destination allowlists: deferred** | Admission is deployment-wide (the address-class rules plus the operator `FLUIDBOX_EGRESS_ALLOW_CIDRS` escape hatch); one tenant cannot be restricted to a narrower set of upstream hosts than another. Custom connector definitions are already tenant-scoped, so a tenant's *own* endpoints stay private to it — what is missing is an operator-imposed per-tenant destination policy |
| **The upstream MCP session registry is replica-local** | Entries live only on the replica that made the calls, and the terminal cleanup (evict + best-effort `DELETE`) runs on the finalizing replica. If a run's calls were made on replica A and A does not finalize the run, A's entries are not `DELETE`d and are freed only at process exit — an upstream-side session leak, not a credential or authorization leak. Session affinity is Phase F |
| **The LLM reservation sole-claimant carve-out** | With zero other live reservations the budget arms are skipped, so a single request can proceed over budget. Bounded: each re-entry still requires recorded usage below the budget, so total spend ≤ budget + one request's actual usage — no worse than the pre-Gap-14 behavior — and the terminal verdict still comes from the accumulated check plus the budget sweeper. Without the carve-out a run whose single-request conservative estimate exceeds its remaining budget would 429-livelock forever with nothing in flight to drain |
| **The budget sweeper's projection is deliberately aggressive** | It counts live reservations, so a run within one conservative reservation of its ceiling can be stopped while an in-flight request would in fact have fit. Magnitude measured: an opus-4-class run gives up ~$0.82 of the $2.50 default budget (~33%) while a request is in flight; haiku ~6.6%. This is the safe-direction counterpart to the sole-claimant carve-out |
| **An OLD pinned runner image on a NEW server is unsupported** | `runner_image` is a per-revision API field that is carried forward, so this is reachable without a bad deploy. The current runner-lib treats a `wrong_audience` body code as fatal: named diagnostic on the timeline, non-zero exit, watchdog terminalizes the run. **That behavior lives in the image** — an image built before Phase E maps the 403 to a plain deny and would run to completion with every tool denied while model spend continued. The guards were deliberately not widened; widening them would gut the audience split |
| **Pre-Phase-C in-flight runs use the legacy broker path**: a run created before the Phase C cutover froze no `run_resource_bindings` row, so its brokered calls resolve the `connection_id` embedded in the RunSpec and recheck only live status — not authorization generation or owner membership | Bounded and self-draining: only runs already in flight at the cutover; historical RunSpecs are never rewritten; every new run freezes bindings and gets the full status+generation+membership recheck, and a revision still pinning a brokered bundle is refused at creation, so no new legacy-path run can start |
| **Transferable connector-OAuth `go_url`**: an attacker starts Connect on their OWN pending connection and sends the returned `go_url` to a victim; the victim's browser is bound as "the initiating browser", the victim consents at the authorization server, and the victim's refresh grant seals into the ATTACKER's connection | Requires a social step against a signed-in target and yields an attacker-held connection to the victim's account, not the reverse. The shipped binding removes the passive variants (a leaked or replayed authorization URL, a replayed callback, an attacker-completed callback). Detail, and the closure path, below |

**Closed in Phase E, recorded here because earlier revisions listed it:** the **approval `approval.decided` double-emission** (each blocked waiter appended its own copy) was a defect, not an accepted risk. The emission now happens *inside* the decision compare-and-swap transaction — only the CAS winner appends, waiters emit nothing, and `tool.decision` got the same treatment — with a `fluidbox_approvals` `pg_notify` in the same transaction waking waiters on every replica (the ≤2 s poll floor stays as the missed-notify backstop). One consequence worth stating: because the append is in-transaction, a ledger-append failure now rolls back the decision itself — fail-closed by choice.

### Residual detail — the transferable connector-OAuth `go_url`

**Correction (2026-07-20, #32).** Earlier revisions of this document and of
`CLAUDE.md` recorded this residual as closed by the deferred "connected-account
confirmation before activation" UI. That was wrong as stated, and the correction
matters because it changes what has to be built:

> A connected-account confirmation closes the transferable-`go_url` lure ONLY if it
> gives the EXTERNAL ACCOUNT HOLDER informed consent — i.e. it is shown to the
> browser COMPLETING the flow, or it binds an expected external subject captured at
> start. A confirmation shown to the flow's INITIATOR closes nothing: in the lure
> the initiator IS the attacker, who would simply confirm the victim's account.

**Why the binding does not already stop it.** The `/go` boot token is AEAD-sealed
but *transferable*: it carries the flow-cookie plaintext (`c`), and the `/go` page
is what sets `__Host-fbx_oauth_flow`. Anyone who opens the link therefore becomes
the initiating browser. The cookie predicate defeats a *leaked authorization URL*
(the AS leg), not a *deliberately shared start URL*.

**Why the obvious fixes do not work.** `__Host-` cookies are host-locked, and in
`FLUIDBOX_WEB_MODE=sso` the dashboard proxy hands each `Set-Cookie` back to the
browser — so the session cookie lives on the DASHBOARD origin while
`/v1/oauth/go` and `/v1/oauth/callback` live on the CONTROL-PLANE origin. Both
one-line fixes die on that split: the control plane cannot see the session cookie
at `/go` (which is why the flow cookie is minted there rather than at the
authenticated start), and a flow cookie set on the authenticated start would be
stored against the dashboard origin and never sent to a control-plane callback.
Whichever end you move the cookie to, the callback has to move with it.

**Known closure path (proposed, NOT built).** Move the browser-facing leg onto the
origin that already holds the session:

1. make the browser-facing OAuth callback URI **configurable** (today it is
   derived from `FLUIDBOX_PUBLIC_URL` as `/v1/oauth/callback`);
2. in hosted mode place it on the **dashboard origin**, behind the existing
   same-origin proxy;
3. set the HttpOnly flow cookie on the **authenticated start response** — where the
   browser stores it against the dashboard origin, bound to the session that
   started the flow;
4. have the authorization server redirect to that dashboard-origin proxy callback,
   which forwards the cookie to the control plane;
5. **drop `c` from the `/go` token**, so the start URL stops being a bearer of the
   browser binding;
6. keep today's control-plane callback for direct/local deployments.

Cost: a dashboard-proxy cookie-allowlist change and a **registered** dashboard
callback URI at every authorization server (a redirect-URI change is an
operational event for pre-registered clients). Not scheduled here — recorded so the
follow-up starts from the real mechanism rather than from the confirmation UI.

## Gap register

The parent design's production gaps, restated as the risk schedule this threat model depends on:

| Gap | Summary | Closed by |
|---|---|---|
| 1 | Global admin authentication (no users/memberships/roles) | **B** (shipped) |
| 2 | One boot-selected tenant | **B** (shipped) |
| 3 | Capability bundle embeds a concrete connection | **C** (shipped) |
| 4 | Process-local OAuth locking → per-connection Postgres advisory-lock refresh serialization (+ the Phase D reusable-registration DCR singleflight) | **shipped (C/D)** |
| 5 | One deployment credential key (no KMS envelope) | **D (shipped)** |
| 6 | Workload identity/mTLS on the internal gateway (network hardening itself largely shipped) | **OPEN** — Phase E narrowed the bearer to four audiences but built no workload identity or mTLS; the remainder carries forward |
| 7 | SSRF boundary for custom endpoints/discovery | **E (shipped)** — shared clients, admission at save and at dial, redirect refusal, clone-URL admission, optional egress proxy (TOCTOU + proxy-DNS residuals disclosed) |
| 8 | Minimal/stateless-first MCP client (2025-11-25 conformance) | **E (shipped)** — per-run session manager, offered `2025-11-25`, bounded SSE assembler, `-32601` to unsupported server requests, `outputSchema`/`structuredContent` preserved |
| 9 | Tools-only boundary implicit | **A** (documented — the [compatibility matrix](product-compatibility-matrix.md)); conformance mechanics **E (shipped)** |
| 10 | One sandbox bearer token holds every audience | **E (partially shipped)** — four audience-scoped tokens enforced server-side; the same-uid `/proc/<pid>/environ` read remains |
| 11 | Decision idempotency without execution idempotency | **E (shipped)** — four-state durable claims |
| 12 | Frozen schemas advertised, not enforced | **E (shipped)** — validated at the gate, dialect by snapshot protocol version |
| 13 | Process-local lifecycle/delivery workers | **E (shipped)** for approvals (in-transaction single emission + `pg_notify`), session lease + epoch fencing, and delivery claims; **F** for the RWO archive volume, durable rate limiting, and MCP session affinity |
| 14 | Per-run LLM budget race in the facade | **E (shipped)** — durable request-keyed reservations (sole-claimant carve-out disclosed) |

## Verification

Enforcement is proven, not asserted:

- **Network**: the boot-time netpol gate (`+:8788 −:8787`) blocks run admission until enforcement is demonstrated; `helm test` re-certifies per release; CI runs kind + Calico.
- **Tenancy (Phase B acceptance — shipped; the CI identity job runs `scripts/identity-e2e.sh` against a digest-pinned Dex)**: cross-tenant negative test matrix; workers cannot fall back to a default tenant; OIDC round-trip against a real conformant issuer (Keycloak/Dex) with replayed, wrong-browser, and expired flows all refused; algorithm allowlist rejects `none`/HS256.
- **Connection binding (Phase C acceptance — shipped; the CI bindings job runs `scripts/bindings-e2e.sh` on its own database)**: ownership isolation (a member cannot read or bind another's personal connection); per-user bindings resolved from an identical shared requirement; approval identity (only the owner-who-invoked decides a personal-connection call); and the fail-closed matrix — unsatisfiable requirement, stale generation, deactivated owner, and missing snapshot each refuse before provisioning.
- **Sealing / keys / RLS (Phase D acceptance — shipped; the CI secrets job runs `scripts/secrets-e2e.sh`, matrix sections (a)–(k))**: the KMS boot matrix (config refusals + the legacy-key retirement gate proved both ways — retires at zero parity, refuses on a straggler), re-seal count-parity + the dump/wipe/restore drill, the one-time browser-bound connector OAuth flow (replayed and wrong-browser completions refused, flow consumed exactly once), reusable client-registration singleflight (two connects to one issuer ⇒ one `/register`), per-tenant virtual-key selection with the master key confined to provisioning, and RLS negative tests run as the non-owner `fluidbox_runtime` role — section (k) greps every per-boot server log to prove no secret leaks.
- **Broker/network hardening (Phase E acceptance — the CI `hardening` job runs `scripts/hardening-e2e.sh` on its own database, with `psql` required because claim states, the schema-denial ledger source, and the SEP-835 status write are not provable from HTTP alone)**: broker SSRF refusals (private/metadata literals, redirect refusal, plain-http outside the dev seam), MCP conformance (offered version, protocol-drift denial, `-32601`, terminal `DELETE` carrying the same authorization a call carried), frozen-schema denials with the gate-order proof, execution-claim states (at most one dispatch, duplicate adoption, `failed_upstream` never ambiguous, only `failed_before_send` re-claimed), the **exhaustive** route × audience matrix asserting the body is byte-equal to `{"error":"wrong_audience"}`, two-replica single-emission/lease/delivery-claim sections, reservation admission, and the rate-limit/breaker messages. **Three properties are documented as uncovered rather than weakly asserted** — MCP session-registry eviction (replica-local map with no read surface; it would need an introspection seam), OAuth re-mint on the terminal `DELETE` (no fake authorization server in this suite; a weaker proxy check would pass with a stale token), and circuit-breaker half-open close (needs a >60 s window, or a 1 s window that races everything) — the last is covered by `governor.rs`'s injected-clock unit tests.
- **Governance**: `scripts/governance-e2e.sh` drives verdicts, approval pause/resume, idempotency, and autonomous auto-deny over real HTTP; the e2e greps keep provider knowledge out of the event spine.
- **Scale/failure (Phase F)**: load tests at 60/150/300 concurrent sandboxes, OAuth refresh storms, revocation during active runs, upstream 401/404/429/5xx, broker restarts, DB failover, and tenant-isolation fuzzing.

## Related documents

- [Product compatibility matrix](product-compatibility-matrix.md) — what is in and out of the supported surface
- [Connector admission policy](connector-admission-policy.md) — the SSRF/admission boundary in policy form
- [Hosted network architecture](network-architecture.md) — the planes and edges referenced by B1–B8
