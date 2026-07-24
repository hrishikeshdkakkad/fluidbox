# Changelog

All notable, user-visible changes to fluidbox are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org).

## [Unreleased]

## [0.3.0] — 2026-07-24

**Multi-user MCP control plane.** Six phases (A–F) and migrations `0011`→`0025` turn fluidbox from a single-admin control plane into one that can host many organizations, many users, and many separately-owned credentials without ever letting a model pick an identity. Every hosted capability is **opt-in behind a flag, and the default single-admin Docker deployment is byte-for-byte the same product** — `FLUIDBOX_REQUIRE_SSO` unset means today's behavior, unchanged.

The organizing idea: **connector definition ≠ credential-bearing connection ≠ agent connection requirement ≠ per-run resource binding.** An agent declares *what* it requires, never *whose* credential satisfies it. Run creation resolves each requirement to an explicit, frozen authority source before any model spend. The model picks tools; it can never pick an identity.

Highlights:

- **Per-organization, IdP-agnostic identity** — `FLUIDBOX_REQUIRE_SSO=1` confines the admin token to `/v1/admin/*` as break-glass and introduces three principals: Operator (admin token), User (`__Host-fbx_web` session cookie), and Pat (`fbx_pat_` bearer). Any conformant OIDC issuer is configured **per org** (issuer + client + sealed secret + claim mappings); logins are two-phase and browser-bound; sessions are server-side with idle/absolute/re-auth windows. No IdP configured ⇒ single-admin mode.
- **Tenant isolation with a database floor** — every tenant-owned `fluidbox-db` method now takes a `TenantScope` that carries its id into a `tenant_id = $n` predicate, so isolation is a *signature requirement* rather than a remember-to-filter convention. Migration `0018` adds the floor underneath: 37 tables `ENABLE`+`FORCE` row-level security keyed on a transaction-local `fluidbox.tenant_id` GUC, with `FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime` splitting the pool onto a non-owner role holding enumerated per-table grants. Cross-tenant access exists only through a short, named, grep-able set of audited bypasses.
- **Connection ownership and per-run resource bindings** — brokered MCP tools moved off capability bundles onto four objects: catalog connector definition → **connection** (owns the credential, plus append-only tool snapshots) → agent-revision **`connection_requirements`** → per-run **`run_resource_bindings`** (migration `0013`), resolved to a tagged authority (`connection` | `subscription_secret` | `none`) across typed slots (`mcp` | `workspace_fetch` | `result_publish`) *before* provisioning. Connections gained personal vs. organization ownership; a personal-connection approval is decidable **only by its owner-who-invoked** — no role, admin, or operator override.
- **Versioned envelope sealing with a real key-retirement path** — migration `0014` makes every sealed column carry a `_key_version` companion: `1` is the legacy `FLUIDBOX_CREDENTIAL_KEY` format, `2` is a per-tenant DEK wrapped by a KEK (`FLUIDBOX_KMS_MODE=off|static|aws`) with AAD binding `fbx:v2:{tenant}:{table.column}` so a blob is untransplantable across tenants *or* columns. Thirteen sealed families; a resumable, CAS-guarded `POST /v1/admin/reseal` migrates v1→v2; two boot gates fail closed in both directions. Runbook: `docs/hosted/kms-operations.md`.
- **One hardened egress boundary for all control-plane traffic** — two filtering-resolver clients plus a pure `admit_url` pre-flight that blocks private/loopback/link-local/multicast/reserved and cloud-metadata address classes at every dial site (reqwest dials an IP literal without consulting a resolver, so the pre-flight is what actually stops `169.254.169.254`). Broker, delivery callbacks, and both connector-OAuth token legs ride a client that **refuses redirects outright**. Git gets its own out-of-process policy. `FLUIDBOX_EGRESS_ALLOW_CIDRS` opts specific CIDRs back in; `FLUIDBOX_EGRESS_PROXY` re-points everything, including the git subprocess, through one waypoint.
- **MCP `2025-11-25` conformance, with version drift denying the call** — upstream MCP is now a per-run session (`initialize` + `notifications/initialized` before every call, `MCP-Protocol-Version` on every request, credential re-resolved live on the terminal `DELETE`). A run's negotiated version must match its frozen surface exactly or the call is denied with a message naming the refresh endpoint. SSE is a real incremental assembler with per-event and total ceilings; `outputSchema`/`structuredContent` are preserved.
- **Frozen tool schemas enforced server-side** — arguments are validated against the schema photographed at freeze time, with the JSON Schema dialect chosen by the snapshot's protocol version (`2025-11-25` ⇒ 2020-12 per SEP-1613, otherwise draft-07). The schema is untrusted input, so it is pre-guarded (size, depth, local-`$ref`-only) before compilation; a violation makes the tool un-callable rather than being silently ignored. This inserts exactly one new stage into the permission gate and moves nothing else.
- **At-most-once brokered dispatch** — migration `0019` wraps every brokered call in a durable four-state execution claim keyed `(session, tool_call_id, input_digest)`. `failed_before_send` requires positive proof nothing was written and is the only re-claimable state; a definitive upstream response is terminal; timeouts and mid-stream failures are recorded as `ambiguous` rather than retried. Decision idempotency and execution idempotency are now distinct properties.
- **Audience-scoped sandbox credentials** — migration `0020` splits the sandbox's single bearer into four tokens (`llm` | `tool` | `control` | `workspace`), each checked as the first statement of its handler. Kubernetes ships one Secret with four keys routed per container, so the workspace init container never sees the others.
- **Replica coordination primitives** — migration `0021`: approval emission rides the deciding CAS inside one transaction (only the winner emits) with cross-replica `pg_notify` wakeups and the poll floor kept as a missed-notify backstop; sessions carry an orchestrator lease + epoch so a fenced-out driver cannot mutate lifecycle while a user's cancel stays deliberately unfenced; deliveries claim rows `FOR UPDATE SKIP LOCKED`, and the GitHub double-post window closes by reconcile-before-create on both comments and checks.
- **Durable LLM budget admission** — migration `0022` replaces best-effort budget checks with a request-keyed reservation whose primary key *is* the usage entry's external id, which is what makes a 401 replay and a late drain idempotent. Booking uses a deliberately-high upper bound; release happens only on positively-proven non-dispatch; charging requires a durable usage write before the CAS.
- **Operations** — a bounded-cardinality metrics registry at admin-gated `GET /v1/admin/metrics` (plus optional unauthenticated `FLUIDBOX_METRICS_BIND`), durable cross-replica egress governance and capacity ceilings (`0023`), cross-replica MCP session teardown (`0024`), workload identity (`0025`), S3-compatible archive storage alongside the filesystem backend, and a guarded load harness (`fluidbox-loadgen`) with its own manual `scale` CI job.

Validation: five hermetic acceptance suites green against CI-identical throwaway databases — identity **87/0**, bindings **104/0**, secrets **128/0**, hardening **274/0**, scale **18/0** = **611/0** — plus live Docker-provider tiers (demo A, Codex) and a second live EKS acceptance on arm64/Graviton with the runtime-role RLS split active and an AWS-audited zero-orphan teardown (`docs/reviews/2026-07-22-eks-acceptance-phase-f.md`).

Still deferred: the gated 60/150/300-seat load campaign and the final two rollout gates (owner approval + cost estimate) remain open on [#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34) — real spend, tracked separately from code. The hosted OAuth Connect flow also carries one documented residual: a deliberately-shared *start* URL can still route a victim's grant into the initiating connection, closed only by moving the browser-facing leg onto the dashboard origin (full write-up in `docs/hosted/threat-model.md`).

### Added

- **Identity and access** — per-org OIDC login (`/v1/auth/*`), logout, `/v1/auth/me`, PAT mint/list/revoke, org + IdP-config lifecycle and membership roles (`/v1/admin/orgs*`), break-glass owner arming, and staged issuer migration. All three token shapes (`fbx_sess_`, `fbx_web_`, `fbx_pat_`) are sha256-only at rest and scrubbed by the ledger redactor.
- **Dashboard SSO mode** — `FLUIDBOX_WEB_MODE=admin|sso` (static per deployment). In `sso` the proxy carries no admin token and forwards the session cookie plus a CSRF header on same-origin non-GETs; `apps/web/proxy.ts` redirects sessionless browsers to `/login?next=…` before first paint while authority stays in the control plane.
- **Per-tenant LLM keys** — `FLUIDBOX_LLM_KEY_MODE=tenant` (migration `0017`) mints a per-tenant LiteLLM virtual key and confines the master key to provisioning; `POST /v1/admin/orgs/{slug}/llm-key/rotate`. Requires a LiteLLM backed by its own Postgres, so local deployments stay on `shared`.
- **Connection tool snapshots** — a forced-`initialize` photograph per connection (`GET /v1/connections/{id}/tools`, `POST /v1/connections/{id}/tools/refresh`) recording the negotiated protocol version, with cursor caps fail-closed.
- **Hosted operator documentation** — `docs/hosted/`: product compatibility matrix, threat model, network architecture, connector admission policy, rollout gates, and KMS operations runbook. Plus `docs/guides/kubernetes.md`, a zero-to-certified-cluster guide with real cloud acceptance costs and gotchas.

### Changed

- **Brokered tools no longer ride capability bundles.** `capability_bundles` survives for sandbox stdio tools only; registering a `class:brokered` server is refused with a cutover error. Migration `0013` appends converted agent revisions and repoints pinned subscriptions; a revision still pinning a brokered bundle is refused at run creation. Mixed brokered+sandbox bundles drop whole, with a raise-notice.
- **Custom connector-catalog entries are tenant-scoped.** Curated and imported entries stay deployment-global; a tenant's custom entry shadows a same-slug global one. Migration `0013` backfills the single boot tenant, otherwise disabling the row.
- **Connector OAuth is a one-time, browser-bound flow.** `oauth/start` returns only a `go_url`; navigating it sets a `__Host-` flow cookie whose hash sits inside the atomic single-use claim, so a leaked authorization URL can neither complete nor burn a flow. Endpoints, resolved client, `resource`, sealed PKCE verifier, and expected generation are frozen at start and the callback exchanges against that row. Client identities are shared per `(issuer, redirect_uri)`, DCR singleflighted by advisory lock. The stateless `seal_state`/`open_state` helpers are gone.
- **`authorization_generation` bumps on reconnect of ever-activated OAuth connections**, so stale-generation bindings refuse mid-run. Rotation within a generation is unaffected, and GitHub App lifecycle never bumps.
- Multi-user boot now **refuses** a pool role that bypasses RLS (`SUPERUSER`/`BYPASSRLS`, e.g. Neon's default owner) unless `FLUIDBOX_ALLOW_RLS_BYPASS=1`; single-user only warns. `just doctor` inspects the role the server will actually run as and fails on every unbootable combination.

### Security

- Prompts still never reach the ledger, and the redactor now also scrubs every session, web-session, and PAT token shape.
- The permission gate grew exactly one stage (frozen-schema argument validation) and reordered nothing: budget → frozen-set availability → schema → trust tier → policy → approvals.
- Before any brokered secret access, binding status, `authorization_generation`, and — for personal connections — owner-membership-active are re-verified fail-closed.
- Both connector-OAuth token legs ride the no-redirect client on purpose: a 307/308 replays the request body, which would forward an authorization code plus PKCE verifier, or a refresh token, to the redirect target. A source-grep test pins this.

### Upgrading

Migration `0018` (RLS enforcement) is **stop the old binary, migrate, then deploy** — not a rolling upgrade. A pre-`0018` binary sets no tenant GUC and would therefore see zero rows, and it holds transactions across outbound HTTP that would block the migration's `ACCESS EXCLUSIVE` locks.

Do not drop `FLUIDBOX_CREDENTIAL_KEY` when enabling `FLUIDBOX_KMS_MODE`: run `POST /v1/admin/reseal` and let boot prove zero remaining v1 rows first. From the moment any v2 row exists, **the KEK is the root of custody and losing it is unrecoverable** — back it up before enabling.

## [0.2.0] — 2026-07-17

**Kubernetes-native execution provider.** Runs now execute as bare Pods in a dedicated, zero-egress sandbox namespace — additive to Docker (dual-provider permanence: Docker stays the default and fully supported). Highlights:

- **`FLUIDBOX_PROVIDER=kubernetes`** — one Pod per run (init → runner → collector), per-run Secrets with ownerRef GC, UID-preconditioned mutations, immutable workspace archives pulled by the pod, and in-pod diff collection against a pristine `.git` baseline (agent-mutated git state is never executed).
- **Helm chart on OCI** — `helm install fluidbox oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox --version 0.2.0` works out of the box: chart `appVersion` is bound to the release images at package time; digest pinning (`images.*.digest`) validated at render time; per-cloud presets (`values/{eks,gke,aks,doks,kind}.yaml`); Ingress routes `/` → dashboard, `/v1` → API.
- **Verified network enforcement, fail-closed** — a boot probe (carrying the sandbox's own placement) plus `helm test` must prove the CNI enforces NetworkPolicy (+:8788 / −:8787) before any run is admitted.
- **Durable finalization** — every terminal path funnels through a persisted intent; collection happens before the terminal transition; crash-recovery re-drives interrupted finalizations; `/result` is no longer lossy. Fixes land on the Docker path too.
- **Self-healing reconciliation** — a periodic adopt-or-terminate sweep heals crash windows (orphaned pods, handle-less sessions) in ≤60 s; node loss maps to `Unknown` instead of live-forever; rolling-deploy-safe strict status parsing.
- **Streaming archives with safety ceilings** — pack/serve/download never hold the archive in RAM; `FLUIDBOX_MAX_ARCHIVE_BYTES` fails oversized runs at zero model spend (malformed caps fail boot); atomic `.partial`+rename writes; a session-state-aware TTL sweep reclaims leaks.
- **Hardening series** — all 30 findings (5 High / 10 Medium / 15 Low) from a three-round joint Claude+Codex review of the epic fixed or explicitly dispositioned (`docs/reviews/2026-07-16-pr47-k8s-review-findings.md`): symlink-safe extraction with `canonicalize` as the sole containment authority, integrity-checked exec collection with resume, dual-listener isolation (no `/internal` on the public plane under K8s), UID-guarded deletes, quiesce replay, and more.
- **New crates/images** — `fluidbox-workspace`, `fluidbox-provider-k8s`, `workspaced` (+ the `fluidbox-workspaced` image, published multi-arch from this release); kind+Calico CI tier green on fresh installs.

Still deferred: live EKS acceptance + teardown (kind+Calico is CI-proven; one managed cloud remains the epic's acceptance bar).

### Added

- **Connector-catalog bulk import (schema + tooling)** — the catalog is now import-ready without importing a single row. A `provenance` column (migration 0009) makes every entry auditable and refreshable; curated seeds carry `{"source":"fluidbox"}` and can never be clobbered by an import. A new reference-only transport, `rest_action`, lets an imported entry that has no hosted MCP endpoint to photograph show up as a browsable Store card whose **Connect is refused** (`400`, "reference-only"); `GET /v1/catalog` now derives a `connectable` flag per entry so the dashboard can badge those cards. An offline dev tool, `just catalog-import-registry` (`crates/fluidbox-catalog-import`), imports from **two Apache-2.0 sources**: the official **[MCP Registry](https://github.com/modelcontextprotocol/registry)** (primary — real MCP servers; entries with a `streamable-http` remote import **connectable today** through the existing broker/photograph path) and **[open-connector](https://github.com/oomol-lab/open-connector)** (supplement — REST-only reference cards). It pages the Registry live (or from a pinned snapshot), keeps only `active`/latest servers, merges Registry-wins on slug collision, runs the SAME poison screen as capability registration over every imported string (offenders drop their whole entry), and emits a deterministic, append-only, sorted `INSERT … ON CONFLICT` migration of untrusted **community**-tier rows — each provenance-tagged with its source + pinned snapshot/commit. The tool never runs at boot or request time and is not in the server crate graph; attribution is recorded in `NOTICE`. The actual breadth (the generated import migration) is a separate, legally-gated merge.
- **Bring your own MCP server** — a guided "Add your own server" flow on the Capabilities page: paste a URL, and a non-committing probe (`POST /v1/mcp/probe`) detects whether it needs no auth, an API key, or OAuth and previews its tools without storing anything or sending a secret; one confirm (`POST /v1/mcp/servers`) registers a `tier=custom` catalog entry and connects it in a single call, rolling the entry back if the connect fails so no orphan card survives. Bundle rows now expand to show their photographed tools.
- **Server-authoritative harness/model catalog** — `GET /v1/harnesses` is the single source of truth for the supported harness + model set; the dashboard's pickers fetch it instead of hardcoding models, and `create_agent`/`add_revision` now reject a model that doesn't belong to its harness with a clean **422** at agent-write time instead of a murky failure at the first model call.
- **CI now tells the truth** — the rust job runs against a real Postgres service (the DB tests no longer silently self-skip), an `e2e` job builds both runner images and runs the full no-model acceptance suite (closes the vacuous-green gap of #14), and `cargo deny check` (advisories/licenses/bans/sources, `deny.toml`) gates the supply chain. The `e2e` job is **manual-only** (`workflow_dispatch`) — it costs real Actions minutes, so it never runs on a PR or push; the cheap gates (rust/web/deny) still run on every PR. Live model tiers stay local/manual — CI never spends credits. Coverage (lcov artifact) runs on main pushes.
- **Property tests for the policy engine** — generated-input invariants in `fluidbox-core`: an autonomous run can never surface `RequireApproval`, autonomy rewrites exactly the approval verdicts (original always ledgered), the read-only tier denies any shell metacharacter and any unlisted tool, shell prefixes are token-bounded, first match wins.
- **Try-it-with-Docker distribution** — `deploy/server.Dockerfile` + `deploy/web.Dockerfile` (Next standalone output), a `release` workflow publishing multi-arch images to GHCR on version tags or manual dispatch, and `deploy/docker-compose.eval.yml`: bundled Postgres + LiteLLM + server + dashboard in one `docker compose up`.
- **User guides** (`docs/guides/`) — writing policies, triggers/schedules/signed results (with the HMAC verification recipe and a pinned test vector), and capabilities (sandbox vs brokered MCP tools, pinning, the connector catalog).
- **`ROADMAP.md`** — the public distillation of `PLAN.md` §7.

- **`just setup`** — one-command idempotent bootstrap for a fresh clone: tools check, `.env` with generated secrets (`FLUIDBOX_ADMIN_TOKEN`, `FLUIDBOX_CREDENTIAL_KEY`, `LITELLM_MASTER_KEY`), dashboard env (`apps/web/.env.local`) kept in sync, `pnpm install`, and the sandbox runner image build. Only fills placeholders — never overwrites values you set.
- **`just doctor`** — environment preflight (#13): validates every documented gotcha (pooled vs direct `DATABASE_URL`, loopback `FLUIDBOX_BIND`, credential key shape, missing runner images, dashboard token drift, missing web deps) and prints the exact fix per failure; exits non-zero only on hard failures, never echoes secret values.

### Changed

- `just neon-setup` now writes the DIRECT connection string into `.env` when `DATABASE_URL` is still the placeholder (an existing value is never clobbered).
- README quickstart, CONTRIBUTING dev setup, and the dashboard README (`apps/web/README.md`) rewritten around the `just setup` → `just neon-setup` → `just dev` flow.

## [0.1.0] — 2026-07-12

The first tagged release: the complete governed vertical slice, verified by a 10-phase live-inclusive acceptance suite (468 checks).

### Highlights

- **Governed agent runs end to end** — frozen RunSpecs, fresh sandboxes, live timelines, policy-gated tool calls with human approvals, and a diff + cost report per run.
- **Two harnesses behind one contract** — Claude Agent SDK and Codex, with an in-server LLM facade that meters usage and keeps provider keys out of every sandbox.
- **Borrow the agent, on demand** — API triggers, signed webhooks, cron schedules, and GitHub PR fan-out, all converging on one governed run path.

### Added

- **Governed runs end to end** — versioned agent definitions, immutable per-run `RunSpec` snapshots (model, prompts, policy, capability pins), fresh Docker sandboxes per run, live SSE event timelines with `Last-Event-ID` resume, and a final diff + cost report.
- **Policy engine & human approvals** — YAML policies evaluated on every tool call (allow / deny / require-approval), idempotent restart-safe approvals with expiry, and an autonomous mode that rewrites approval verdicts to a policy fallback while recording both verdicts.
- **Append-only audit ledger** — redaction enforced at the type level; prompts never reach the database, only digests, usage, cost, and decisions, with gapless per-session sequencing.
- **Two agent harnesses** — Claude Agent SDK and Codex runner images behind one HTTP runner contract; the LLM facade speaks both the Anthropic Messages and OpenAI Responses dialects.
- **Credential inversion** — the sandbox's `ANTHROPIC_API_KEY` is a session token; an in-server LLM facade validates it, enforces budget stops, meters streamed usage, and swaps in the real upstream credential held only by the LiteLLM gateway.
- **Git workspaces** — credentialed fetch/copy happens control-plane-side before the agent starts; sandboxes only ever see a bind-mounted copy and stay egress-free.
- **Triggers** — subscription-scoped API tokens, signed webhook ingress with two-level dedup that heals partial fan-outs, cron schedules with exactly-once firing and explicit missed-run/concurrency policies, and HMAC-signed result delivery with retry/backoff.
- **GitHub integration** — seamless GitHub App connect (manifest + install flows), PR fan-out with one stable comment per PR and one check per head SHA, and fork PRs frozen to `ReadOnly` trust with no approval escape.
- **Capability catalog** — append-only versioned MCP tool bundles pinned at run creation; sandbox tools run as contained stdio subprocesses while brokered tools execute on the control plane with sealed credentials the sandbox never sees.
- **Connector catalog + OAuth** — catalog-driven connect flows with PKCE (S256), RFC 8707 resource indicators, DCR/CIMD client identity, sealed refresh tokens with atomic rotation, and fail-closed error states.
- **Dashboard** — Next.js UI (Runs, Agents, Integrations, Automations, Settings); presentation-only, all logic in the Rust API.
- **CLI** — `fluidbox run --repo … --task …` to drive runs from the terminal.
- **Ops** — `just` recipes for the full dev loop, an end-to-end acceptance suite (`just e2e`), Neon setup and DB-cleanup scripts, and CI (fmt, clippy `-D warnings`, tests, dashboard build).

### Changed

- Dependency refresh: `sha2` 0.11, `hmac` 0.13, `chacha20poly1305` 0.11, `jsonwebtoken` 10 (pinned to the pure-Rust `rust_crypto` provider), React 19.2.7, TypeScript 6, and current GitHub Actions. The sealed-credential wire format (`nonce ‖ ciphertext`) is unchanged — existing sealed credentials open fine.
