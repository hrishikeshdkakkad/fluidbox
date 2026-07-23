-- Phase F (Task 5) — WORKLOAD IDENTITY on the sandbox-facing internal gateway
-- (Gap 6; design 2026-07-14 :1233-1240, threat-model row T7).
--
-- WHY
-- The ONLY thing authenticating the :8788 internal listener today is a per-run
-- bearer token. Phase E (Gap 10, migration 0020) narrowed that bearer into four
-- audience-scoped tokens, which bounds what ONE stolen credential can do — but it
-- says nothing about WHO is holding it. The design has always required "workload
-- identity or mTLS in addition to run bearer tokens", and T7 states the residual
-- plainly: "nothing binds the connection to a workload identity, and there is no
-- mTLS on the internal gateway — the bearer alone authenticates."
--
-- This column is the workload-identity half. It records, at provision time, the
-- network address(es) the control plane ITSELF observed the workload being given,
-- so a later request bearing that run's token can be checked against the identity
-- the control plane issued it to. It is NOT mTLS: see the "WHAT THIS IS NOT"
-- section below, which is deliberately blunt about the difference.
--
-- WHAT
-- `sessions.workload_addrs text[]` — the provider-reported addresses of the
-- workload for this run. NULL (the default, and the value on every pre-0025 row)
-- means "no provider-asserted identity", which is a first-class, COUNTED state,
-- never an implicit allow-everything: see `auth.rs::workload_verdict`.
--
-- WHY AN ARRAY, NOT ONE `inet`.
--   1. Dual-stack Kubernetes pods have `status.podIPs[]` — a pod may legitimately
--      source traffic from its IPv4 OR its IPv6 address depending on the
--      destination. A single-address column would make a dual-stack cluster
--      produce false mismatches, which is the single fastest way to get a
--      security control switched back off.
--   2. `text[]` over `inet[]` deliberately: the value is written from a provider's
--      API response, and a `::inet` cast makes a malformed value ERROR the
--      provisioning UPDATE — turning a cosmetic provider bug into a failed run.
--      Text stores whatever the provider said; `auth.rs` parses it to `IpAddr` and
--      treats an unparseable entry as UNVERIFIABLE (loud, and fail-closed under
--      `enforce`) rather than silently as "no match".
--
-- NO NEW RLS OBJECTS — VERIFIED, not assumed (the 0021 precedent). This is a
-- column-add on `sessions`, a table migration 0018 already protects, and 0018's
-- policy for it is COLUMN-AGNOSTIC: `tenant_id::text =
-- current_setting('fluidbox.tenant_id', true) or bypass` (0018:164-181) names
-- exactly one column, `tenant_id`, which is unchanged. 0018's grants are
-- TABLE-level (`grant select, insert, update, delete on table %I`, 0018:439-441),
-- so the new column is reachable by the deployment's runtime role with no new
-- grant, and 0018's drift guard keys on TABLES carrying our policies — it sees no
-- new table. This migration therefore adds no policy and no grant, by construction.
--
-- NO INDEX, deliberately. The column is only ever read on the path that already
-- resolves a session token: `session_for_token` gains a LEFT JOIN to `sessions` on
-- the primary key, so the read is an existing-index probe inside a statement that
-- was already running. Nothing ever searches BY address.
--
-- DEPLOY ORDER: safe in EITHER order (unlike 0018). The column is nullable with no
-- default, and a pre-0025 binary neither reads nor writes it. A post-0025 binary
-- defaults to `FLUIDBOX_WORKLOAD_IDENTITY=off`, which is today's behaviour byte for
-- byte, so migrate-then-deploy needs no downtime and rolling the binary back needs
-- no down-migration. Rows provisioned by an old replica during a rolling deploy
-- simply carry NULL and are counted as unbindable.
--
-- WHAT THIS IS NOT (put here so it is read by whoever next touches the column).
-- A source address is a NETWORK-layer fact, not a cryptographic one. It proves the
-- packets arrived from an address the control plane recorded; it does not prove
-- WHICH PROCESS at that address sent them, and it does not survive an attacker who
-- can choose their source address. Concretely it does NOT stop: another process in
-- the SAME pod (identical address by construction), a node-level attacker who can
-- originate traffic from a pod's address, or a network that permits source-address
-- spoofing between workloads. mTLS (the stronger follow-up, deliberately not built
-- here) replaces "came from the right address" with "holds the right private key",
-- which none of those three can forge.

set local lock_timeout = '5s';

alter table sessions
    -- Provider-reported network addresses of this run's workload, captured at
    -- provision time from data the provider ALREADY had in hand (Kubernetes:
    -- `status.podIP` + `status.podIPs[]`, taken from the poll response that
    -- already proved the runner container Running — zero extra API calls, zero
    -- added provisioning latency). NULL = this provider does not report one (the
    -- Docker provider today), or the row predates this migration.
    add column workload_addrs text[];

comment on column sessions.workload_addrs is
    'Gap 6 workload identity: provider-reported source addresses for this run''s '
    'sandbox, recorded at provision time. Compared against the SOCKET PEER of every '
    'internal-gateway request bearing this run''s tokens (never against a forwarded-for '
    'header — a sandbox can set headers). NULL = unbindable; see FLUIDBOX_WORKLOAD_IDENTITY.';
