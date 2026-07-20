# Hosted threat model

**Date:** 2026-07-17
**Status:** Phase A deliverable of the multi-user MCP control plane epic (#28)
**Authority:** [`../plans/2026-07-14-multi-user-mcp-control-plane-design.md`](../plans/2026-07-14-multi-user-mcp-control-plane-design.md) (v4, security invariants 1–22 and Gaps 1–14) and [`../plans/2026-07-17-idp-agnostic-identity-design.md`](../plans/2026-07-17-idp-agnostic-identity-design.md) (v5, identity invariants 1–12). Vulnerability reporting: [`SECURITY.md`](../../SECURITY.md).

This threat model covers the hosted multi-user deployment (~300 seats). It is deliberately honest about time: Phase B landed per-organization identity and per-tenant repository scoping, Phase C landed connection ownership + per-run resource bindings, and Phase D landed KMS envelope sealing + one-time browser-bound / reusable connector OAuth + per-tenant LiteLLM virtual keys + database-enforced RLS; every mitigation below still carries a **status** — `shipped` or the phase (E–F) that closes it. A row marked with an unshipped phase is a *known open risk* until that phase lands; hosted multi-tenant operation is not offered before Phase E closes its remaining rows.

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
| B2 | Sandbox ↔ internal gateway (`:8788`) | Per-run token(s); `zeroEgress` NetworkPolicy is the only route; every tool intent passes the single gate |
| B3 | Control plane ↔ remote MCP endpoints | Broker-only egress; admission policy; audience-bound credentials; ambient-state-free transport |
| B4 | Control plane ↔ per-org IdP | Discovery/JWKS/token fetches SSRF-validated; full ID-token verification; no DB transaction spans IdP I/O |
| B5 | Webhook senders ↔ ingress | HMAC against sealed secrets is the authentication; verify-before-store; DB-unique dedup |
| B6 | Tenant ↔ tenant (inside one deployment) | `TenantScope` repository methods (primary), composite `(tenant_id, id)` FKs, RLS as depth |
| B7 | Control plane ↔ model gateway | Facade-only path; provider keys live only in LiteLLM; sandboxes cannot address it |
| B8 | Operator ↔ deployment | Admin token confined to `/v1/admin/*` under `FLUIDBOX_REQUIRE_SSO=1`; transactional audit |

## Scenarios and controls

Statuses: **shipped** = enforced on `main` today (`shipped (Phase B)`/`shipped (Phase C)`/`shipped (Phase D)` mark a row that phase closed); **Phase E–F** = the phase that closes it (open risk until then).

### T1/T2 — the compromised sandbox and the model itself

| Attack | Control | Status |
|---|---|---|
| Exfiltrate an upstream credential from the sandbox | Credentials never enter the sandbox (invariants 1, 2): LLM key swapped at the facade, git credentials control-plane-side via ephemeral `GIT_CONFIG_*`, MCP credentials used only by the broker | shipped |
| Reach the internet / LiteLLM / metadata endpoints directly | `zeroEgress` NetworkPolicy (only `:8788`; no DNS), boot-gate-proven enforcement, no service-account token in the pod (invariant 3) | shipped (Kubernetes provider; subject to the accepted EKS pod-start enforcement window below) |
| Call a tool outside the frozen set, or a rug-pulled/drifted tool | Frozen-set availability check at the gate — drifted or vanished tools are denied (`source=capability`); a live upstream tools-list change never mutates an in-flight run (invariant 14) | shipped |
| Choose *whose* credential executes a tool | The model chooses only among frozen tools; bindings are frozen at run creation; the broker resolves the credential solely from the run's `run_resource_bindings` row (invariants 4, 5) | shipped (Phase C; pre-Phase-C in-flight runs keep the embedded-connection path with a status-only recheck — see residuals) |
| Bypass the permission callback (autonomy modes) | The callback stays wired in both modes — never the SDK's `bypassPermissions`; autonomous mode rewrites `RequireApproval` to the policy fallback inside `evaluate()`, ledgering both verdicts | shipped |
| Impersonate runner-control actions (report results, heartbeats) after reading the process env | Today one bearer holds every audience — agent code **can** read it (Gap 10) | **Phase E**: audience-scoped credentials; runner-control unreachable from agent subprocesses |
| Overspend the per-run LLM budget with parallel calls | Facade checks-then-records today — concurrent calls can pass the same remaining budget (Gap 14) | **Phase E**: durable request-ID-keyed reservations; **shipped (Phase D)**: per-tenant LiteLLM virtual keys (`FLUIDBOX_LLM_KEY_MODE=tenant`) as the fairness backstop — each carries its own server-side spend/token/rate ceiling |
| Replay a decided tool call to execute the write twice | Decision idempotency exists; execution idempotency does not yet (Gap 11) | **Phase E**: durable execution claims keyed `(tenant, run, tool_call_id, input_digest)`, at most one dispatch attempt (invariant 16) |
| Execute a late-approved call after cancellation/budget termination | Terminality checked before the wait today, not before send | **Phase E**: claim conditional on nonterminal session (invariant 18) |
| Poison the ledger with prompts/secrets | The sink accepts only `Redacted<EventEnvelope>` (constructible solely via the redactor) — digests, usage, cost only | shipped |

### T3 — the malicious MCP server

| Attack | Control | Status |
|---|---|---|
| Poisoned tool names/descriptions (ANSI, zero-width, injection copy) | Names and schemas are screened and validated at the registration photograph; descriptions, annotations, arguments, and results are untrusted input end to end (invariant 13) | shipped |
| Schema rug-pull between registration and run | Snapshots append-only; runs execute against their frozen schemas and digests | shipped |
| Malicious arguments accepted because the schema is only advertised | Server-side argument validation against the frozen schema (bounded depth/size, no external `$ref`), dialect per snapshot protocol version, rejections surfaced as tool-execution errors (Gap 12, invariant 17) | **Phase E** |
| Cross-user/run session bleed via `MCP-Session-Id` or cookies | Per-run upstream sessions, never shared (invariant 11); authorization header on every request; shared HTTP transport is ambient-state-free — no cookie jars, no cached per-host auth (invariant 22) | **Phase E** (per-run session manager; conformance contract, Gap 8) |
| Insufficient-scope challenge used to phish scope escalation | SEP-835 challenges are terminal for the call; the connection is marked "reconnect with more scopes" for its **owner**; the broker never auto-escalates a frozen grant | **Phase E** |
| Blind retry of an ambiguous write | Ambiguous outcomes are ledgered as such and never blindly retried (invariant 15); only positively-proven `failed_before_send` is re-claimable | **Phase E** (claims); retry discipline shipped in broker behavior today |
| Server-to-client requests (sampling/elicitation) abused to stall or socially engineer | Unsupported client capabilities are never advertised; such requests receive JSON-RPC errors (Gaps 8, 9 — the [compatibility matrix](product-compatibility-matrix.md) makes the boundary explicit) | boundary documented (this phase); conformance mechanics Phase E |

### T4/T5 — insiders and cross-tenant attackers

| Attack | Control | Status |
|---|---|---|
| Read or bind another user's personal connection | Connection ownership (`owner_type`, `owner_user_id`); binding verification; personal connections invisible to other members — 404-not-403, admins included (they act through their own viewer lens) | shipped (Phase C) |
| Approve an action so it runs under someone else's credential | Approval permits the proposed action under the credential already frozen into the run — never the approver's (invariant 8); approvers need `approval.decide_own`/`approval.decide_org`; no role — including admin or the operator — authorizes approval under another user's personal connection, and only its owner-who-invoked may decide it (`authorize_approval_decision`) | shipped (approval RBAC Phase B; personal-connection authority Phase C) |
| Read another tenant's runs/events/artifacts by UUID | `TenantScope` repository signatures (primary), composite tenant FKs, cross-tenant negative test matrix; UUID unpredictability is not authorization (invariant 10); RLS now enforces the same tenant floor in the database (migration 0018: 37 tenant-owned tables `ENABLE`+`FORCE`, GUC-driven policies via `scoped_tx`/`worker_tx`; the negative tests run as the non-owner `fluidbox_runtime` role). **Two caveats, both operational:** the two tables holding cross-tenant SHARED rows (`connector_catalog`, `oauth_client_registrations`) are readable by every scope by design — writes to those global rows are bypass-only, so the floor covers mutation but not visibility of shared reference data; and RLS is **inert for a SUPERUSER or BYPASSRLS role** (Neon's default `neon_superuser`), which is not inherited through role membership — set `FLUIDBOX_RUNTIME_ROLE` and verify with `just doctor` | shipped (Phase B `TenantScope` + composite keys; Phase D RLS depth) |
| See tenant existence via login routing | The neutral entry page never enumerates organizations and answers identically for unknown and IdP-less slugs | shipped (Phase B) |
| A trigger token used beyond its subscription | Subscription-scoped, sha256-hashed tokens: invoke exactly one subscription, poll only runs it created; invoke overrides are opt-in and can only narrow | shipped |
| A member reads runs they shouldn't | `run.read` visibility rules (own runs; token-created runs; `subscriptions.manage`; `runs.read_all`) on every session/event/artifact/approval/SSE query | shipped (Phase B) |
| Custom connector admitted by one tenant becomes bindable in another | Custom definitions tenant-scoped (partial unique indexes: global slug + per-tenant custom slug); unattributable legacy rows disabled at the 0013 backfill | shipped (Phase C) |

### T6 — the unauthenticated network

| Attack | Control | Status |
|---|---|---|
| Forged webhook creates runs | HMAC is the authentication — against the connection's sealed secret, or the GitHub App registration's sealed secret on the App-level ingress path; nothing stored before verification | shipped |
| Replayed webhook duplicates fan-out | Two DB-unique dedup levels bound to the session insert in one transaction — retries heal, never duplicate | shipped |
| Login CSRF / forced login into an attacker's session | Session replacement is never silent: `pending_login_switches` one-time browser-bound confirmation (cookie hash inside the claim predicate, 120 s expiry, current-session equality in the predicate) | shipped (Phase B) |
| Replayed / attacker-completed OAuth or login callback | One-time server-side state rows; a per-flow `HttpOnly` `__Host-fbx_oauth_flow` cookie whose sha256 sits inside the atomic single-use claim predicate — a leaked authorization URL can neither complete nor burn a flow. Connector OAuth (invariant 20) freezes its full binding set into the `connector_oauth_flows` row at start — authorization/token endpoints, resolved client, `resource`, sealed PKCE verifier, and the connection's `authorization_generation` — and the callback exchanges against the frozen row (closing AS mix-up) and refuses a moved generation; the GitHub App and login flows use the same one-time cookie-hash claim mechanism with their own, flow-appropriate binding sets | shipped (GitHub App, login; connector OAuth Phase D, invariant 20) |
| Cross-user grant injection (victim's consent seals into attacker's connection) | The completing browser must prove it started the flow — the same `__Host-fbx_oauth_flow` cookie-hash predicate binds consent to the initiating browser (shipped). A displayed connected-account confirmation before activation is NOT built — the callback activates directly (see the go-URL-lure residual below) | shipped (Phase D — browser binding); account-confirmation display deferred |
| CSRF against cookie-authenticated APIs | Custom header + `Origin` check on every cookie-authenticated non-GET; `CorsLayer::permissive()` removed in the same change; GET writes limited to the enumerated protocol-forced flows, each with its own one-time claims | shipped (Phase B) |
| SSRF via crafted endpoints, discovery documents, redirects, or DNS rebinding | Admission address-class rules enforced at resolution time on every fetch; redirect re-validation; egress proxy | **Phase E** (Gap 7); policy stated now in the [admission policy](connector-admission-policy.md) |
| Amplification via unauthenticated login/callback endpoints | Rate limits per IP and per org; caps on outstanding unconsumed flows; flow claims commit before any IdP I/O so slow IdPs cannot hold DB connections | shipped (Phase B) |

### T7 — stolen credentials

| Attack | Control | Status |
|---|---|---|
| Stolen PAT self-replicates | A PAT can never mint, extend, or revoke PATs (including itself); TTL clamped (90 d default / 1 y max) | shipped (Phase B) |
| Stolen PAT outlives the person | Membership status and roles re-read on every use; deactivation kills sessions and PATs in one transaction | shipped (Phase B) |
| Stolen session cookie rides forever | Server-side session rows (revocable), sliding idle expiry capped by an absolute expiry, `__Host-` prefix, HttpOnly, SameSite=Lax; long-lived streams re-authorize on a ≤60 s interval | shipped (Phase B) |
| Stolen trigger token reaches the admin surface | Token kinds are mutually exclusive (relationally CHECK-enforced); trigger tokens never touch `/v1`-admin routes; the admin token can never invoke a trigger | shipped |
| Leaked run session token used from outside | Reaching `:8788` requires being inside the sandbox network path; workload identity/mTLS additionally binds the caller | shipped (network) / **Phase E** (identity, Gap 6 remainder) |
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
| Custom endpoint as an internal-network probe | Admission address rules; broker-only egress; private endpoints only via BYOC/relay/explicit approval | **Phase E** enforcement; policy stated now |
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
| **Result delivery is at-least-once** | Receivers dedup on `x-fluidbox-delivery`; provider idempotency / deterministic markers cover the crash window between remote creation and recording |
| **Pre-Phase-C in-flight runs use the legacy broker path**: a run created before the Phase C cutover froze no `run_resource_bindings` row, so its brokered calls resolve the `connection_id` embedded in the RunSpec and recheck only live status — not authorization generation or owner membership | Bounded and self-draining: only runs already in flight at the cutover; historical RunSpecs are never rewritten; every new run freezes bindings and gets the full status+generation+membership recheck, and a revision still pinning a brokered bundle is refused at creation, so no new legacy-path run can start |

Not a residual: the **approval `approval.decided` double-emission** inside one process is a *current known defect* with an assigned fix — the transactional outbox in the Phase E statelessness work (Gap 13) — not an accepted post-mitigation risk.

## Gap register

The parent design's production gaps, restated as the risk schedule this threat model depends on:

| Gap | Summary | Closed by |
|---|---|---|
| 1 | Global admin authentication (no users/memberships/roles) | **B** (shipped) |
| 2 | One boot-selected tenant | **B** (shipped) |
| 3 | Capability bundle embeds a concrete connection | **C** (shipped) |
| 4 | Process-local OAuth locking → per-connection Postgres advisory-lock refresh serialization (+ the Phase D reusable-registration DCR singleflight) | **shipped (C/D)** |
| 5 | One deployment credential key (no KMS envelope) | **D (shipped)** |
| 6 | Workload identity/mTLS on the internal gateway (network hardening itself largely shipped) | **E** |
| 7 | SSRF boundary for custom endpoints/discovery | **E** |
| 8 | Minimal/stateless-first MCP client (2025-11-25 conformance) | **E** |
| 9 | Tools-only boundary implicit | **A** (documented — the [compatibility matrix](product-compatibility-matrix.md)); conformance tests **E** |
| 10 | One sandbox bearer token holds every audience | **E** |
| 11 | Decision idempotency without execution idempotency | **E** |
| 12 | Frozen schemas advertised, not enforced | **E** |
| 13 | Process-local lifecycle/delivery workers | **E/F** |
| 14 | Per-run LLM budget race in the facade | **E** |

## Verification

Enforcement is proven, not asserted:

- **Network**: the boot-time netpol gate (`+:8788 −:8787`) blocks run admission until enforcement is demonstrated; `helm test` re-certifies per release; CI runs kind + Calico.
- **Tenancy (Phase B acceptance — shipped; the CI identity job runs `scripts/identity-e2e.sh` against a digest-pinned Dex)**: cross-tenant negative test matrix; workers cannot fall back to a default tenant; OIDC round-trip against a real conformant issuer (Keycloak/Dex) with replayed, wrong-browser, and expired flows all refused; algorithm allowlist rejects `none`/HS256.
- **Connection binding (Phase C acceptance — shipped; the CI bindings job runs `scripts/bindings-e2e.sh` on its own database)**: ownership isolation (a member cannot read or bind another's personal connection); per-user bindings resolved from an identical shared requirement; approval identity (only the owner-who-invoked decides a personal-connection call); and the fail-closed matrix — unsatisfiable requirement, stale generation, deactivated owner, and missing snapshot each refuse before provisioning.
- **Sealing / keys / RLS (Phase D acceptance — shipped; the CI secrets job runs `scripts/secrets-e2e.sh`, matrix sections (a)–(k))**: the KMS boot matrix (config refusals + the legacy-key retirement gate proved both ways — retires at zero parity, refuses on a straggler), re-seal count-parity + the dump/wipe/restore drill, the one-time browser-bound connector OAuth flow (replayed and wrong-browser completions refused, flow consumed exactly once), reusable client-registration singleflight (two connects to one issuer ⇒ one `/register`), per-tenant virtual-key selection with the master key confined to provisioning, and RLS negative tests run as the non-owner `fluidbox_runtime` role — section (k) greps every per-boot server log to prove no secret leaks.
- **Governance**: `scripts/governance-e2e.sh` drives verdicts, approval pause/resume, idempotency, and autonomous auto-deny over real HTTP; the e2e greps keep provider knowledge out of the event spine.
- **Scale/failure (Phase F)**: load tests at 60/150/300 concurrent sandboxes, OAuth refresh storms, revocation during active runs, upstream 401/404/429/5xx, broker restarts, DB failover, and tenant-isolation fuzzing.

## Related documents

- [Product compatibility matrix](product-compatibility-matrix.md) — what is in and out of the supported surface
- [Connector admission policy](connector-admission-policy.md) — the SSRF/admission boundary in policy form
- [Hosted network architecture](network-architecture.md) — the planes and edges referenced by B1–B8
