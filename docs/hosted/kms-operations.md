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
  additional data binds `fbx:v2:{tenant_id}:{table.column}`, so a blob transplanted
  across tenants OR columns fails to open even under the right DEK.

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
| `static` | `FLUIDBOX_KMS_STATIC_KEK` (32-byte hex/base64) | Local dev + CI. Wraps DEKs with XChaCha20-Poly1305, AEAD-bound to `(tenant_id, purpose)`. |
| `aws` | `FLUIDBOX_KMS_AWS_KEY_ID` (key id/ARN) | Production. `kms:Encrypt`/`kms:Decrypt` with `EncryptionContext {tenant_id, purpose=fluidbox-dek}`. Credential chain supports IRSA. `FLUIDBOX_KMS_AWS_ENDPOINT` overrides the endpoint (test seam only). |

---

## 2. Boot matrix (KMS × legacy key)

Boot runs two gates: `seal::build_sealer` (config coherence) and
`seal::check_retirement_gates` (stored-custody coherence, cross-tenant row counts).

| KMS mode | `FLUIDBOX_CREDENTIAL_KEY` | Boot behavior |
|---|---|---|
| **off** | present | **OK — legacy sealing (v1).** Refuses only if any **v2** row exists (rolling back to legacy-only with KMS-sealed custody would orphan it — re-enable KMS). |
| **off** | absent | **OK — sealing DISABLED.** Integration connections + event ingress refuse to operate (no key to seal with). |
| **static/aws** | present | **OK — migration state.** New seals are v2; existing v1 blobs are still readable (legacy key present). Run the re-seal job here. |
| **static/aws** | absent | **OK only if ZERO v1 rows remain.** Boot counts v1 rows across all nine sealed columns; a single leftover v1 blob is now unreadable, so boot **REFUSES** with per-family counts and points you at the re-seal job. This is the retired steady state. |

Config-level refusals (in `build_sealer`, before the row counts): `FLUIDBOX_KMS_MODE=static`
without `FLUIDBOX_KMS_STATIC_KEK`, or `=aws` without `FLUIDBOX_KMS_AWS_KEY_ID`,
fail boot naming the missing variable. At runtime, unsealing a v1 blob with the
legacy key absent, or a v2 blob with KMS off, fails closed (belt behind the boot
gates).

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
   The job walks all nine families, unsealing each v1 blob and re-sealing it v2
   under the row's per-tenant DEK. Poll `GET` until `legacy_total == 0` (every
   family's `legacy` is 0) and `running` is `false`. A row it cannot unseal (wrong
   legacy key / corrupt blob) is tallied in `job.families[].failed` + `last_error`
   and **skipped**, so one bad row never wedges the migration — investigate any
   `failed > 0` and re-run (a re-run re-attempts failures). `reseal.start` /
   `reseal.finish` rows land in `auth_audit_log`.
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
