# KMS operations — envelope sealing, re-seal, and legacy-key retirement

> Phase D (#32). Companion code: `crates/fluidbox-server/src/{seal,kms,reseal}.rs`,
> `crates/fluidbox-db/src/system_worker.rs`, migration `0014_envelope_seal.sql`.

fluidbox seals durable custody (integration credentials, OAuth refresh tokens,
GitHub App private keys, webhook/callback secrets, OIDC client secrets, PKCE
verifiers) at rest. Historically every seal used ONE deployment-wide key,
`FLUIDBOX_CREDENTIAL_KEY` — losing or rotating it orphaned every stored
credential. KMS envelope sealing moves the trust root off that single key and
onto a per-tenant key hierarchy wrapped by a Key Encryption Key (KEK) you control
in AWS KMS (or a static KEK for local/CI). This document is the operator runbook:
the key model, the boot matrix, the IAM grant, KEK rotation, the legacy-key
retirement procedure, and disaster recovery.

---

## 1. The key model (DEK / KEK)

Two on-disk seal formats, discriminated by a per-column `<base>_key_version`
companion (NOT an in-band magic byte — legacy blobs begin with 24 random nonce
bytes, so any prefix scheme is only probabilistic):

- **v1 (legacy):** `nonce(24) ‖ ciphertext`, one deployment-wide
  XChaCha20-Poly1305 key from `FLUIDBOX_CREDENTIAL_KEY`. `key_version = 1`.
- **v2 (envelope):** `[0x02][dek_version u32][nonce 24][ciphertext]`, sealed under
  a **per-tenant Data Encryption Key (DEK)**. `key_version = 2`. The AEAD's
  additional data binds the blob's own 5-byte **header** followed by
  `fbx:v2:{tenant_id}:{table.column}`, so a blob transplanted across tenants OR
  columns fails to open even under the right DEK, and the declared `dek_version` is
  authenticated rather than advisory (flip a header bit and the open fails).
  The KEK **wrap** is bound the same way — `(tenant_id, purpose, dek_version)` — so
  a wrapped DEK cannot be moved between tenants or between versions of one tenant.

> **AT-REST COMPATIBILITY BREAK (KMS mode only, this release).** Binding
> `dek_version` into the wrap AAD / AWS `EncryptionContext` and authenticating the
> v2 header **changes the at-rest format**: DEKs wrapped by an earlier build no
> longer unwrap, and v2 blobs sealed by an earlier build no longer open. There is
> no migration path and none is offered. This is acceptable for exactly one
> reason — **KMS mode ships in this release and has never run in production**, so
> no such bytes exist outside development and CI databases. If any do, the KEK
> compatibility gate (§2) makes it a LOUD boot refusal rather than silent data
> loss. Legacy (v1) blobs are untouched: they carry no AAD and are byte-identical
> to pre-Phase-D.

The DEK hierarchy:

```
 KEK  (AWS KMS key, or a 32-byte static KEK)     ← you back this up / control access
  │   wraps (kms:Encrypt / kms:Decrypt)
  ▼
 tenant_deks.wrapped_dek   (one wrapped DEK per (tenant, version), in Postgres)
  │   unwrapped in memory only (zeroized on drop; never persisted in the clear)
  ▼
 per-tenant DEK  (XChaCha20-Poly1305)  ← seals that tenant's custody columns
```

- A tenant's DEK is minted **lazily** on its first v2 seal (`getrandom` → wrap
  with the KEK → `insert … on conflict do nothing` → re-read the winner, so
  concurrent first-seals converge on one DEK).
- Unwrapping a DEK is the single **auditable KMS `Decrypt`**; unwrapped DEKs cache
  in memory (`Zeroizing<[u8;32]>`, scrubbed on drop) and re-mint on restart.
- **Losing the KEK — not this process's memory — is what makes custody
  unrecoverable.** That is the entire point of moving the trust root off a single
  deployment key.

### KEK backends

| `FLUIDBOX_KMS_MODE` | KEK source | Use |
|---|---|---|
| `off` (default) | — | Legacy single-key sealing (v1). Today's behavior. |
| `static` | `FLUIDBOX_KMS_STATIC_KEK` (32-byte hex/base64) | Local dev + CI. Wraps DEKs with XChaCha20-Poly1305, AEAD-bound to `(tenant_id, purpose, dek_version)`. |
| `aws` | `FLUIDBOX_KMS_AWS_KEY_ID` (key id/ARN) | Production. `kms:Encrypt`/`kms:Decrypt` with `EncryptionContext {tenant_id, purpose=fluidbox-dek, dek_version}`. Credential chain supports IRSA. `FLUIDBOX_KMS_AWS_ENDPOINT` overrides the endpoint (test seam only). |

---

## 2. Boot matrix (KMS × legacy key)

Boot runs three gates: `seal::build_sealer` (config coherence),
`seal::check_retirement_gates` (stored-custody coherence, cross-tenant row counts),
and — in `static`/`aws` mode — `kms::check_kek_compatibility` (**can the configured
KEK actually read the DEKs already stored?**).

| KMS mode | `FLUIDBOX_CREDENTIAL_KEY` | Boot behavior |
|---|---|---|
| **off** | present | **OK — legacy sealing (v1).** Refuses only if any **v2** row exists (rolling back to legacy-only with KMS-sealed custody would orphan it — re-enable KMS). |
| **off** | absent | **OK — sealing DISABLED.** Integration connections + event ingress refuse to operate (no key to seal with). |
| **static/aws** | present | **OK — migration state.** New seals are v2; existing v1 blobs are still readable (legacy key present). Run the re-seal job here. |
| **static/aws** | absent | **OK only if ZERO v1 rows remain.** Boot counts v1 rows across all thirteen sealed columns; a single leftover v1 blob is now unreadable, so boot **REFUSES** with per-family counts and points you at the re-seal job. This is the retired steady state. |

Config-level refusals (in `build_sealer`, before the row counts): `FLUIDBOX_KMS_MODE=static`
without `FLUIDBOX_KMS_STATIC_KEK`, or `=aws` without `FLUIDBOX_KMS_AWS_KEY_ID`,
fail boot naming the missing variable. At runtime, unsealing a v1 blob with the
legacy key absent, or a v2 blob with KMS off, fails closed (belt behind the boot
gates).

### The KEK compatibility gate (WRONG-KEK boot refusals)

The retirement gates only prove the configured sealing state can *in principle*
open what is stored (v1 needs the legacy key, v2 needs KMS). They cannot see
*which* KEK wrapped the stored DEKs. So a syntactically valid but **wrong** KEK —
a re-generated `FLUIDBOX_KMS_STATIC_KEK`, a different AWS key ARN, a restored
environment pointed at the wrong secret — used to boot happily and produce
**split-key custody**: every existing tenant silently failed to unwrap, while
every new tenant minted a DEK under the wrong KEK. There is no recovery from that
state and no re-wrap tooling. Boot now refuses instead:

| `tenant_deks` state | Boot behavior |
|---|---|
| **zero DEK rows** | OK — nothing to prove; the configured KEK wraps the first DEK. |
| **one distinct `kek_id`, matching + unwrappable** | OK — logged as `KEK compatibility probe passed`. |
| **one distinct `kek_id`, not the configured one** | **REFUSES** — *"stored per-tenant DEKs were wrapped by a DIFFERENT KEK… Restore the original KEK."* |
| **id matches but the unwrap FAILS** | **REFUSES** — the probe is a real `Decrypt`, so a missing IAM grant, a disabled/deleted key, or a format change is caught here, not on the first user request. |
| **two or more distinct `kek_id`s** | **REFUSES** — fluidbox has no multi-KEK routing or re-wrap tooling, so serving would read some tenants and orphan others. Restore a single KEK. |

The remedy is always to restore the KEK the data was written under — never to
"clear `tenant_deks` and let it re-mint" (that orphans every v2 blob). The probe
reads `tenant_deks` through the audited `system_worker` lens on purpose: without
that GUC, `FORCE` RLS would return zero rows and the gate would read "no DEKs
stored" and **fail open**.

---

## 3. IAM — broker-only decrypt

Only the control-plane role may unwrap DEKs. Grant `kms:Encrypt` (mint/wrap a new
DEK) + `kms:Decrypt` (unwrap on a cache miss) on the KEK to the control plane's
role **and no other principal** — that is what makes decrypt broker-only. Scope it
to the one key and pin the purpose in the encryption context:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FluidboxDekWrapUnwrap",
      "Effect": "Allow",
      "Action": ["kms:Encrypt", "kms:Decrypt"],
      "Resource": "arn:aws:kms:REGION:ACCOUNT_ID:key/KEK_KEY_ID",
      "Condition": {
        "StringEquals": { "kms:EncryptionContext:purpose": "fluidbox-dek" }
      }
    }
  ]
}
```

Attach this to the control plane's IRSA role only. The KEK's own **key policy**
must not grant `kms:Decrypt` to any human/CI/backup principal — a sandbox never
holds KMS access (the broker turns the key server-side, the same inversion as the
LLM facade and git fetch).

> The encryption context is now `{tenant_id, purpose, dek_version}` (it gained
> `dek_version`), but the policy above pins **only** `purpose` — so this document's
> published condition remains valid as written and needs no edit. If you have
> tightened it further with a `kms:EncryptionContextKeys` condition, that key list
> must now include `dek_version` or every wrap/unwrap is denied.

---

## 4. KEK rotation

v1 code mints exactly **one active DEK version** per tenant (`DEK_VERSION = 1`);
`tenant_deks` already carries `(tenant, version)` + `kek_id` + `retired_at` so a
future multi-version rotation can route, but the automated re-wrap is not built
yet. Be honest about what rotation means today:

- **`aws` + AWS-managed key rotation (recommended):** enable automatic rotation on
  the KMS key. AWS rotates the key's backing material transparently and retains old
  material for decrypt, so existing `wrapped_dek` blobs keep unwrapping and new
  wraps use fresh material. `kek_id` (the key ARN) is unchanged — **no fluidbox
  action, no re-wrap, no re-seal.**
- **`static` KEK rotation:** changing `FLUIDBOX_KMS_STATIC_KEK` invalidates every
  existing `wrapped_dek` (they were wrapped under the old KEK and fail to unwrap
  under the new one). There is **no automated static-KEK re-wrap in v1** — treat
  the static KEK as fixed per deployment (it exists for local/CI). Use `aws` for
  any deployment that needs rotation.
- **Manual DEK re-wrap under a new KEK** (decrypt-wrapped-DEK-under-old →
  encrypt-under-new for every `tenant_deks` row) is **future work**. The schema
  supports it; the runbook tooling does not exist yet.

> Rotating the DEKs themselves (not the KEK) — minting DEK version 2 and re-sealing
> custody under it — reuses the exact same machinery as the legacy→KMS re-seal
> (§5); it is also future work in v1.

---

## 5. Retiring `FLUIDBOX_CREDENTIAL_KEY` (the re-seal procedure)

Retire the legacy key only after 100% of custody is v2. The re-seal job is
resumable and idempotent (predicate-driven paging + a CAS write), so it is safe to
re-run and safe across restarts.

1. **Enable KMS, keep the legacy key.** Set `FLUIDBOX_KMS_MODE=static|aws` (+ the
   KEK) and leave `FLUIDBOX_CREDENTIAL_KEY` in place. Restart (boot: migration
   state). New seals are now v2; existing v1 blobs still open with the legacy key.
2. **Run the re-seal.** As the operator (admin token):
   ```
   POST /v1/admin/reseal          # 202 Accepted; 409 if already running or KMS off
   GET  /v1/admin/reseal          # poll: { running, legacy_total, families:[{family,legacy,envelope}], job:{…} }
   ```
   The job walks all thirteen families, unsealing each v1 blob and re-sealing it v2
   under the row's per-tenant DEK. Poll `GET` until `legacy_total == 0` (every
   family's `legacy` is 0) and `running` is `false`. A row it cannot unseal (wrong
   legacy key / corrupt blob) is tallied in `job.families[].failed` + `last_error`
   and **skipped**, so one bad row never wedges the migration — investigate any
   `failed > 0` and re-run (a re-run re-attempts failures). `reseal.start` /
   `reseal.finish` rows land in `auth_audit_log`.

   **Read `job.state`, not `job.finished_at`.** `finished_at` says only that the
   task returned; the terminal verdict is the explicit `job.state` field:

   | `job.state` | Meaning |
   |---|---|
   | `null` | Still running, or never run. |
   | `completed` | Every row re-sealed or already v2 — zero failures. |
   | `completed_with_errors` | The walk finished but ≥1 row failed (see `job.families[].failed` + `last_error`). **Not migrated** — fix and re-run. |
   | `failed` | The job itself aborted (see `last_error`). |

   The same verdict is the `reseal.finish` audit detail and drives that row's
   `success` flag, so an operator or an automation can never read "finished" as
   "migrated".
3. **Drop the legacy key.** Remove `FLUIDBOX_CREDENTIAL_KEY` from the environment
   and restart. Boot re-counts v1 rows: **zero → boots** (retired steady state);
   **any remaining → refuses** with per-family counts (the retirement gate proves
   parity for you). Never delete the key from your secret store until a clean boot
   confirms zero legacy rows.

The job is a singleton — a second `POST` while one runs gets a 409. A restart
mid-job needs no reconciliation: re-`POST` and it re-scans, skipping the rows
already at v2.

---

## 6. Disaster recovery

**What you MUST back up (both, or custody is unrecoverable):**

1. **The Postgres database** — `tenant_deks` holds the only copy of each tenant's
   wrapped DEK. No DEK is ever persisted in the clear; a wiped `tenant_deks` row is
   an orphaned custody column.
2. **KEK custody** —
   - `aws`: the KMS key itself (do not schedule it for deletion) and its key
     policy. Multi-Region keys / replicas if you run multi-region.
   - `static`: the `FLUIDBOX_KMS_STATIC_KEK` secret, in your secret manager.

**Restart / restore behavior:** the in-memory DEK cache is rebuilt lazily — on the
first seal/open for a tenant after restart, the control plane re-unwraps that
tenant's DEK from the persisted `wrapped_dek` via one `kms:Decrypt`. Nothing DEK-
or plaintext-shaped survives a restart in the clear.

**Restore drill (acceptance §b):** dump a sealed row, wipe it, restore the dump →
it still opens (the wrapped DEK + KEK + the row's tenant/column AAD are sufficient;
the process memory is not). Restarting the server and re-unsealing exercises the
same unwrap-from-persisted path. Run this drill after any KEK/key-policy change.

---

## 7. Deployment prerequisites

- **Transit tokens key off the boot tenant's DEK.** Ephemeral wire tokens (the
  GitHub App flow tokens and the OAuth/login `state` params) are not stored
  columns; in KMS mode they seal under the **boot/seed tenant's** DEK
  (`Sealer::seal_token`), since their owning tenant is not knowable at open time.
  The seed tenant is a real `tenants` row, so its DEK mints lazily like any other.
  A KMS mode flip mid-flight invalidates in-flight transit tokens — they live
  minutes (TTL), so a user simply restarts the login/connect flow.
- **⚠ Do not rename the boot tenant.** The deployment tenant is resolved at boot by
  `ensure_default_tenant`, which upserts `on conflict (name)` — i.e. by the MUTABLE
  key `name = 'default'`. Rename that row (or hand-edit it) and the next boot seeds
  a *different* tenant, whose DEK cannot open anything sealed under the old one:
  every deployment-global secret (the `oauth_client_registrations` client secret and
  registration access token) and every in-flight transit token becomes unopenable.
  It fails closed, not silently — but the only recovery is renaming the row back. If
  you need a friendlier display name, add it elsewhere; leave `name='default'` alone.
- **⚠ Rolling deploys: flip `FLUIDBOX_KMS_MODE` on ALL replicas and finish the
  restart BEFORE starting the re-seal job.** The KMS boot matrix (§2) is a
  **boot-time** gate, not a runtime one: a replica that started with KMS off keeps
  serving happily against a database that is filling with v2 rows, and only fails
  when it happens to touch one (unsealing a v2 blob with KMS off fails closed). A
  half-rolled fleet therefore produces intermittent, replica-dependent custody
  errors that look like data corruption. Order: set the mode + KEK everywhere →
  confirm every replica has restarted → only then `POST /v1/admin/reseal`.
- **`aws` mode** needs the control plane's role wired to the KEK per §3 (IRSA on
  Kubernetes). No KMS access is ever granted to a sandbox.
- **`static` mode** is for local dev and CI only — it is a plaintext 32-byte key in
  the environment, not a managed KEK.

---

## 8. Per-tenant LiteLLM virtual keys

> Phase D (#32). Companion code: `crates/fluidbox-server/src/llm_keys.rs`, `facade.rs`,
> migration `0017_tenant_llm_keys.sql`. Same custody theme as the KEK above: confine a
> privileged credential (here the LiteLLM **master key**) to a narrow provisioning
> role so it never rides a routine request.

Per-run budget stops in the facade do not provide tenant FAIRNESS on a shared
gateway. `FLUIDBOX_LLM_KEY_MODE` selects how the facade authenticates each upstream
model request:

| `FLUIDBOX_LLM_KEY_MODE` | Facade behavior |
|---|---|
| `shared` (default) | Presents ONE deployment key (`LLM_UPSTREAM_URL`'s `LITELLM_MASTER_KEY`, or `ANTHROPIC_API_KEY` for the direct-Anthropic fallback) on every call. Today's behavior, now an explicit choice. |
| `tenant` | Selects a per-tenant **LiteLLM virtual key** (one per tenant, minted on demand) from the authenticated session's tenant. The master key is used ONLY to mint/delete those virtual keys — **never on a routine model request** (design :1093). |

Each tenant virtual key carries its own server-side spend/token/rate ceiling, so a
noisy tenant cannot starve others on the shared gateway. It is the fairness
**backstop**, not the per-run budget-race fix (durable reservations, Phase E).

### The master-key confinement model

- The virtual key is minted with `POST {admin}/key/generate` (master-key bearer),
  sealed at rest (`tenant_llm_keys.litellm_key_sealed`, versioned + envelope-sealed
  under the tenant's own DEK exactly like every §1 custody column), and cached
  UNSEALED in memory. It is never returned in an API response and never enters a
  sandbox (the facade swaps it in upstream, the same inversion as git fetch / the
  KEK broker).
- The forbidden act — a routine model request on a shared key in a HOSTED
  deployment — is refused AT THE FACADE: `FLUIDBOX_REQUIRE_SSO=1` + `shared` mode ⇒
  every facade call returns `503 tenant_llm_keys_required`. Set
  `FLUIDBOX_LLM_KEY_MODE=tenant` for hosted deployments.
- Boot fails closed on an incoherent config: `shared` mode with an EMPTY resolved
  upstream key (kills the old silent empty-key boot), `tenant` mode without
  `LITELLM_MASTER_KEY`, or `tenant` mode against a direct-Anthropic upstream
  (virtual keys are a LiteLLM feature; direct Anthropic cannot mint them).

### Deployment prerequisite — LiteLLM needs its OWN Postgres

**`tenant` mode requires the LiteLLM proxy to be backed by its own Postgres**
(`DATABASE_URL` + `store_model_in_db`), because the `/key/*` CRUD is a
Postgres-backed LiteLLM feature. **None of the current deployments wire this** — the
dev compose (`deploy/docker-compose.dev.yml`), the eval compose, and the Helm chart
all run LiteLLM without a database. Wiring a Postgres to the LiteLLM container (a
DEDICATED LiteLLM database — never the fluidbox app DB; LiteLLM manages its own
schema) is a hard prerequisite before enabling `tenant` mode. The local default
stays `shared` (zero deployment churn).

### Config knobs (all optional; serialized into `/key/generate` only when set)

| Env | Meaning |
|---|---|
| `FLUIDBOX_LLM_KEY_MODE` | `shared` (default) \| `tenant`. |
| `FLUIDBOX_LLM_ADMIN_URL` | LiteLLM admin base for `/key/*`. Defaults to `LLM_UPSTREAM_URL`. |
| `FLUIDBOX_LLM_TENANT_MODELS` | CSV model allowlist for the virtual key. |
| `FLUIDBOX_LLM_TENANT_MAX_BUDGET` | USD spend cap (f64). |
| `FLUIDBOX_LLM_TENANT_BUDGET_DURATION` | Budget window, e.g. `30d`. |
| `FLUIDBOX_LLM_TENANT_TPM` / `_RPM` | Tokens/requests-per-minute ceilings (i64). |

A key is minted lazily on a tenant's first model call and eagerly (best-effort) at
org creation; a mint failure is non-fatal (the lazy path retries).

### Rotation

`POST /v1/admin/orgs/{slug}/llm-key/rotate` (operator only): mints a fresh virtual
key, swaps the sealed row (bumping `rotated_at`), evicts + re-seeds the in-memory
cache, and best-effort deletes the old key at LiteLLM. Returns `{"rotated": true}` —
never the key. 404 on an unknown org.

---

## 9. Row-Level Security (RLS) operations

> Phase D (#32, #75). Companion: migration `0018_rls_enforcement.sql`, `fluidbox-db`
> `scoped_tx`/`worker_tx` + the `connect()` owner-migrate / app-pool split.

Migration 0018 enables + `FORCE`s RLS on 37 tenant-owned tables. `FORCE` binds the
policy even against the table OWNER (a plain owner otherwise bypasses RLS — the
reason Phase B deferred this). Enforcement is a GUC contract, transaction-local so
a pooled connection never leaks context:

- `fluidbox.tenant_id` set (`scoped_tx`) ⇒ that tenant's rows are visible/writable;
- `fluidbox.bypass = 'system_worker'` (`worker_tx`) ⇒ the audited cross-tenant
  bypass — the category rides IN the GUC value, one grep-able choke point. `worker_tx`
  is `pub(crate)`, so the server crate cannot assemble a bypass ad-hoc; it reaches one
  only through a NAMED `fluidbox-db::system_worker` function. A couple of those
  (`reseal_begin`, `global_registration_tx`) are `pub` and deliberately hand out a
  bypass-armed transaction, because their callers drive a multi-statement critical
  section. The property is "a short, named, grep-able set of escape hatches", not
  "unreachable";
- neither set ⇒ zero rows on a policy'd table.

**Two tables split read from write.** `connector_catalog` and
`oauth_client_registrations` hold cross-tenant SHARED state: rows with `tenant_id
NULL` are deployment-global (curated catalog entries; the deployment-wide OAuth
`client_id` and its sealed `client_secret`). Their policies are therefore split —
`FOR SELECT` is tenant-or-global-or-bypass (every tenant reads shared reference
data), but `FOR INSERT/UPDATE/DELETE` is tenant-or-**bypass only**. A tenant-scoped
transaction can neither mint a global row nor mutate/delete one another tenant
depends on; writing a global row is principal-less deployment work and goes through
`system_worker` (`insert_/touch_/delete_global_registration`,
`global_registration_tx`). This is the only place in 0018 where USING and WITH CHECK
differ per command, and it is why those two tables get four policies each rather
than one `FOR ALL`.

**`auth_audit_log` INSERT carries the tenant floor too.** The insert policy was
`with check (true)`, which made this the one tenant-owned write surface whose
database floor did not match the verified scope: a transaction scoped to tenant A
could append a row stamped `tenant_id = B` into B's permanent history, and because
the log is append-only the forgery could never be retracted through the runtime
role. It now requires the tenant GUC to match, or the system-worker bypass — the
same floor as every other tenant-owned write. Operationally: **an audit insert no
longer works GUC-less**, so an audit that is not already inside a mutation's
transaction goes through `identity::insert_audit_standalone` (one-statement
`scoped_tx` when the tenant is known; `worker_tx` for deployment-level rows with
`tenant_id IS NULL`). `audit_select` is deliberately UNCHANGED
(tenant-or-null-or-bypass): the finding was INSERT-only, deployment-level rows carry
no tenant data, and there is no such reader in production code.

**Is RLS actually armed on YOUR database?** Postgres skips policies entirely for a
`SUPERUSER` or `BYPASSRLS` role, and **role attributes are not inherited through
membership** — granting the app a bound role proves nothing about the role it
connects *as*. Neon's default `neon_superuser` carries `BYPASSRLS`, so a stock Neon
connection string makes this whole section inert. Check it:

```sql
select current_user, rolsuper, rolbypassrls from pg_roles where rolname = current_user;
```

Both `false` ⇒ enforcing. Otherwise set `FLUIDBOX_RUNTIME_ROLE` (below).

### The multi-user boot gate (`FLUIDBOX_ALLOW_RLS_BYPASS`)

Under `FLUIDBOX_REQUIRE_SSO=1` that check is no longer advice. Boot reads the
**effective** role of a POOLED connection (`current_user` *after* any
`after_connect SET ROLE` — attributes are not inherited, so `current_user` is the
only correct question) and REFUSES:

```
REFUSING TO BOOT: FLUIDBOX_REQUIRE_SSO=1 (multi-user) but the database role this pool runs as
('<user>') is SUPERUSER or has BYPASSRLS, so PostgreSQL SKIPS every row-level-security policy from
migration 0018 and tenant isolation falls back to the `where tenant_id = $n` convention alone.
Fix (either one):
  1. set FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime — migration 0018 creates that NOLOGIN
     least-privilege role and every pooled connection SET ROLEs to it; or
  2. point DATABASE_URL at a role that is neither SUPERUSER nor BYPASSRLS.
  Verify with: select rolsuper, rolbypassrls from pg_roles where rolname = current_user;
  For local single-user operation on a superuser database, set FLUIDBOX_ALLOW_RLS_BYPASS=1 to accept this.
```

It exists because the shipped default was fail-OPEN on exactly the posture this
runbook documents: a stock Neon credential carries `BYPASSRLS`, so a default
install applied 0018, `FORCE`d it, and skipped every policy — a later missing
`tenant_id` predicate would have returned ALL tenants.

- `FLUIDBOX_ALLOW_RLS_BYPASS=1` (or `true`) downgrades the refusal to a warning.
  **Local single-user operation on a superuser database only** — it turns 0018 into
  decoration and puts tenant isolation back on the query predicates alone.
- **The gate is fatal ONLY under `FLUIDBOX_REQUIRE_SSO=1`.** Single-user mode warns
  and names what will happen when SSO is turned on; a clean pool logs an INFO
  confirming enforcement.
- `just doctor` runs the same query against the `DATABASE_URL` role (it cannot see
  the pool's `SET ROLE`). It **fails** — not warns — when `.env` combines
  `FLUIDBOX_REQUIRE_SSO=1` with a bypassing role, no `FLUIDBOX_RUNTIME_ROLE`, and no
  `FLUIDBOX_ALLOW_RLS_BYPASS`: that deployment cannot boot, so a green preflight
  would be a lie. Every other combination stays a warning.

### The runtime role (`FLUIDBOX_RUNTIME_ROLE`; chart default `fluidbox_runtime`)

Set `FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime` and every pooled connection
`SET ROLE`s (via `after_connect`) to the migration's NOLOGIN `fluidbox_runtime`
role — a NON-owner that cannot bypass RLS and cannot `UPDATE`/`DELETE`
`auth_audit_log` (the 0012 deferred grant lands here). Unset = single-role mode:
RLS still binds even the owner via `FORCE`, so a single-role deployment is fully
enforced *provided its role does not bypass RLS* (the gate above). Boot fails if
the env var names a role that does not exist. On a managed host that restricts
`CREATE ROLE` (Neon), the migration **WARNS** instead of aborting — create the role
out-of-band
(`CREATE ROLE fluidbox_runtime NOLOGIN; GRANT fluidbox_runtime TO CURRENT_USER;`
plus the table grants), then set the env var and restart.

**ONE ROLE NAME PER DEPLOYMENT on a shared cluster.** The name is no longer a pool
detail: `connect()` publishes it to migration 0018 as the session GUC
`fluidbox.runtime_role`, and 0018 creates, posture-validates and GRANTs *that* role
(default `fluidbox_runtime` when unset). This matters because PostgreSQL roles are
**cluster-global** while the grants are **database-local** — on a cluster hosting
more than one fluidbox database, a single hardcoded name is a collision with
someone else's principal, and granting it DML here would hand that principal every
tenant's rows (`set role <name>; set fluidbox.bypass = 'system_worker';`). Give each
deployment its own name.

**Posture refusals.** 0018 raises the last three as `migration 0018: role …`
exceptions (a role it cannot `CREATE` is a WARNING instead — the managed-host case),
and `connect()` re-checks the same conditions at EVERY boot, because a role can be
`ALTER`ed or re-`GRANT`ed long after the migration ran:

| Boot message | Meaning | Fix |
|---|---|---|
| `FLUIDBOX_RUNTIME_ROLE='…' is set but the role does not exist` | 0018 could not `CREATE ROLE` (managed host) | create it out-of-band (above), restart |
| `… carries unsafe attribute(s): …` | LOGIN / SUPERUSER / BYPASSRLS / CREATEROLE / CREATEDB / REPLICATION — LOGIN makes it an authenticable principal, SUPERUSER/BYPASSRLS make the split theatre | `ALTER ROLE … NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;` or pick a name this deployment owns |
| `… is a member of …` | it silently inherits privileges fluidbox never granted | `REVOKE` those memberships, or pick a deployment-specific name |
| `… is granted to …` | the shared-cluster collision: those principals can `SET ROLE` in, then set `fluidbox.bypass` and read every tenant | `REVOKE <role> FROM` them, or pick a deployment-specific name |

Both membership questions read **DIRECT** `pg_auth_members` rows, not the transitive
closure: a transitive path necessarily runs through a role that is already an admin
over the connecting user, so flagging it would refuse every managed host whose owner
sits under a platform admin group (Neon's `neon_superuser`) while describing no
capability that principal lacks. Posture is verified at boot, not continuously.

**Helm defaults** (chart `deploy/helm/fluidbox`): `server.runtimeRole` now defaults
to `"fluidbox_runtime"` — a Helm install is a hosted deployment — and
`server.allowRlsBypass: false` renders `FLUIDBOX_ALLOW_RLS_BYPASS=1` when flipped.
The previous default (`server.runtimeRole: ""`) left RLS **fail-open** against the
documented Neon credential; if you pinned that value, drop the override. Set
`runtimeRole: ""` only for a deployment whose `DATABASE_URL` role is itself neither
SUPERUSER nor BYPASSRLS.

> **`SET ROLE` narrows the authority of the ordinary application queries this
> process issues; it is NOT a credential boundary.** `RESET ROLE` returns the same
> connection to the migration owner, and the process still holds the owner
> `DATABASE_URL` and can open a fresh owner connection — so it does not defend
> against process compromise or SQL injection. Genuine separation needs distinct
> migration-owner and runtime-LOGIN connection strings, with the runtime login
> owning no schema objects and carrying no bypass attributes.
>
> What the runtime role actually buys is that **the default posture of every fixed
> application query is least-privilege** — a repository function that forgets
> `scoped_tx` returns zero rows here and would have returned rows under the owner,
> and a stray `UPDATE auth_audit_log` is denied outright. It catches fluidbox's own
> bugs. fluidbox does not require the two-connection-string split today (one
> `DATABASE_URL` runs migrations and serves traffic), so treat the runtime role as
> bug containment until it does.

### CONVENTION — every new tenant-owned table

There is deliberately **no `ALTER DEFAULT PRIVILEGES`** and no `GRANT … ON ALL
TABLES IN SCHEMA public` (0018 enumerates exactly the 37 tables plus `append_event`,
so unrelated objects in a shared `public` schema — and a deliberately revoked
`PUBLIC EXECUTE` — are never touched). A new tenant-owned table shipped without its
own policy is silently *unprotected* under the owner and silently *invisible* under
the runtime role. So every migration that adds a tenant-owned table MUST, in the
same file: (1) `ENABLE` + `FORCE ROW LEVEL SECURITY`; (2) attach a policy — the
standard `current_setting('fluidbox.tenant_id')` shape, or a parent `EXISTS(...)`
for a child table with no `tenant_id` column; and (3) `GRANT SELECT, INSERT, UPDATE,
DELETE` to the **deployment's** runtime role, resolved exactly as 0018 resolves it
(`coalesce(nullif(current_setting('fluidbox.runtime_role', true), ''),
'fluidbox_runtime')` — `connect()` publishes that GUC session-level before running
any migration), and guarded for the restricted-host case (`if not exists (select 1
from pg_roles …) then return;`). A hardcoded `fluidbox_runtime` is wrong on a
deployment that chose another name. A sealed column additionally joins the
seal-family lockstep (§1) so it is re-seal-covered.

**A drift guard enforces step 3 inside 0018**: any table carrying one of fluidbox's
policy names (`tenant_isolation`, `catalog_*`, `registration_*`, `audit_*`) that is
absent from the grant list ABORTS the migration with `migration 0018: fluidbox RLS
policies exist on table(s) … that are absent from the runtime grant list` (a second
guard aborts on a listed table that does not exist — typo/rename). It is keyed on
our policy names, not on `relrowsecurity`, so an unrelated RLS table sharing the
schema is none of our business. The guard only sees tables 0018 itself policies —
a table added by a LATER migration is invisible to it, which is exactly why all
three steps belong in that migration's own file.

### CONVENTION — a migration that seeds rows into an RLS'd table

Migrations run as the table OWNER with no GUC, and `FORCE` binds the owner. Any
migration that writes DATA into a table 0018 (or a later migration) protects must
open with:

```sql
set local fluidbox.bypass = 'system_worker';
```

Otherwise every INSERT is refused (`new row violates row-level security policy`)
and every UPDATE/DELETE silently affects zero rows. This bites hardest on the two
global tables — a generated `just catalog-import` file inserts `tenant_id NULL`
rows into `connector_catalog`, which the write-side policy admits only under the
bypass. Migrations that only run DDL need nothing.

### Deploy order — STOP the old binary, migrate, THEN deploy

0018 is **not** a migrate-then-deploy. Two independent reasons:

1. **Pre-0018 binaries break on a 0018 database** — they set no GUC, so every
   policy'd table reads zero rows. An old replica left running does not error; it
   serves empty results.
2. **The migration can be blocked by the old binary.** 0018 takes `ACCESS EXCLUSIVE`
   on all 37 tables in one transaction, and the pre-Phase-D OAuth paths hold a
   transaction open across outbound HTTP (the token exchange; the DCR `/register`).
   A slow authorization server therefore parks the migration behind a lock request
   that in turn queues every subsequent query — a full stall. The migration sets
   `lock_timeout = '3s'` so this surfaces as a fast, retryable failure instead, but
   the ordering is what avoids it.

The changes themselves are catalog-only (no table rewrite): with no competing
traffic, 0018 is milliseconds. Roll back by dropping the policies, not by
redeploying the old binary against the new schema.
