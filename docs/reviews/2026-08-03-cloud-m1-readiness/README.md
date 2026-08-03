# M1.0 readiness ledger — Fluidbox Cloud

Autonomous build session, 2026-08-03. Records what was **proved**, what is
**built and validated but awaiting a user-approved apply**, and the one
**blocking finding**. The M1.0 gate ("no EKS deployment until…") is assessed
against the M1 brief §6 list, item by item.

## Gate status

| M1.0 gate item | status | evidence |
|---|---|---|
| Scoped AWS deploy role, root key retired | **BUILT, awaiting apply** | `deploy/cloud/terraform/bootstrap/` (validates clean); ceremony in its README; `scripts/cloud/verify-bootstrap.sh` is the pass/fail recorder |
| `iam:PassRole` restricted | **BUILT** | `bootstrap/iam.tf` — `/fluidbox-cloud/` path + `iam:PassedToService` ∈ {eks, ec2, pods.eks} |
| Encrypted/versioned/locked TF state | **BUILT** | `bootstrap/state.tf` (S3-native lockfile, TLS-only policy, 90d noncurrent expiry) |
| Tag-filtered fluidbox budget | **BUILT** | `bootstrap/budgets.tf` + `aws_ce_cost_allocation_tag` |
| Account-wide budget (2nd breaker) | **BUILT** | same; number is decision #1 (recommend $400 — shared account already forecasts ~$179) |
| CloudTrail + root-activity alarm | **BUILT** | `bootstrap/cloudtrail.tf`, `bootstrap/alarms.tf` |
| Log retention + ECR/S3 lifecycle | **BUILT** | precreated EKS log group w/ 30d (`platform/eks.tf`), ECR keep-5, S3 lifecycles |
| **Cost model re-verified** | ✅ **PASS** | `docs/hosted/cloud-cost-model.md` — **≈$131.6/mo**, live AWS Pricing API, inside the $130–140 band |
| **OIDC login path proved** | ⚠️ **PASS with a blocking finding** | below + `p3`–`p7` files here |
| **Vercel cookie + SSE probe** | ✅ **code path PASS** (9/9); platform cap pending project link | below + `sse-*`, `cookie-*` files here |
| Fallback if Vercel can't carry streams | ✅ **documented** | `docs/hosted/cloud-architecture.md` §"Event streaming" |

**Verdict:** the gate is **not yet closed** — it closes when the bootstrap
apply + ceremony run and `verify-bootstrap.sh` reports all-pass. Everything
that could be proved without spending money or making a reserved decision has
been proved.

## Proof 1 — OIDC login path (17/18)

`scripts/cloud/oidc-login-proof.sh` — real core, `FLUIDBOX_REQUIRE_SSO=1`,
RLS runtime-role split, throwaway database `fluidbox_m1proof` on the local
container Postgres. **No live Neon, no model calls, no AWS.**

Passed: multi-user boot with `row-level security is ENFORCED for this pool`;
**admin-token confinement** (`/v1/sessions` → 401, `/v1/admin/orgs` → 200 —
this is what makes the M1.2 operator surface safe); org create; IdP config
create **through core's live-discovery conformance floor**; activation; and
the authorize leg carrying **nonce + `code_challenge` + `code_challenge_method=S256`
+ state + the browser-bound one-time `__Host-fbx_login_*` cookie**.

So: *nonce handling and PKCE are proven on core's side*, which is what the M1
brief §5 asks for.

### 🚩 BLOCKING FINDING — WorkOS Connect apps are not per-org OIDC IdPs

The authorize leg was **rejected by WorkOS**:
`https://error.workos.com/sso/client-id-invalid` (`p7-idp-response-headers.txt`).

Controlled comparison (`p7-client-id-comparison.txt`), same URL, only the
`client_id` swapped:

| client_id | WorkOS response |
|---|---|
| Connect app `client_01KZ49JD6R…` | `error.workos.com/sso/client-id-invalid` |
| Environment AuthKit `client_01KGA8EC…` | past client validation → `redirect-uri-invalid` (that URI was deliberately not registered) |

Corroborating: OIDC discovery is served **only** at
`/user_management/{authkit-client-id}/.well-known/openid-configuration`; the
Connect app's client id 404s there, as do six other candidate paths.

**Therefore:** a WorkOS environment exposes **exactly one OIDC issuer and one
client**. PLAN rev 3 identity §1 ("per-org WorkOS Connect app … each org's
`org_idp_configs` row gets that app's issuer/client_id/secret") **does not
hold as written** — Connect applications are a different product surface, not
per-org IdPs a third-party relying party can authenticate against.

**Options (decision #4 must be re-taken — see the decision sheet):**

1. **One WorkOS environment per beta org** — each has its own AuthKit
   client/issuer, so core's per-org IdP model fits exactly. Cleanest
   isolation; heaviest operationally (a WorkOS project/environment per
   customer), and untested against WorkOS plan limits.
2. **One shared AuthKit issuer for all orgs** — every `org_idp_configs` row
   carries the same issuer+client_id. There is then **no IdP-side org
   binding**, and the enforced floor is core's armed-membership model (an
   authenticated subject with no armed membership in org X cannot enter org
   X). This is precisely the fallback PLAN rev 3 pre-defined ("closed beta,
   residual risk documented"). Passing WorkOS's `organization_id` parameter
   would fix the binding, but core builds the authorize URL and has no
   per-org extra-params knob — that is a **core change ⇒ M3**, out of M1 scope.
3. **Bring-your-own IdP per org** (Auth0/Okta/Entra/Google Workspace) — core
   is IdP-agnostic and this is arguably the most natural fit for a private
   beta of trusted organizations; each customer's own IdP gives real per-org
   isolation with zero core changes.

### ⚠️ Second finding, unresolved — the token-endpoint auth mismatch

WorkOS's discovery document omits `token_endpoint_auth_methods_supported`.
Core's rule (correctly, per OIDC) treats an absent list as
**`client_secret_basic` only** — and indeed `client_secret_basic` is the
method that was accepted at create (`p4-create-idp.txt`), while
`client_secret_post` was refused. But WorkOS's token endpoint
(`/user_management/authenticate`) documents client credentials **in the
request body**. If it does not accept HTTP Basic, the token exchange will
fail even after a successful consent.

This could not be tested here: the Connect app's client **secret is not
retrievable through the WorkOS API** (dashboard-only), so the token leg was
never exercised. **This is the single highest-value thing to verify next**:

```bash
IDP_CLIENT_SECRET='<real secret>' scripts/cloud/oidc-login-proof.sh
# then complete the consent in a browser and watch for a token-leg failure
```

### Drill objects created (WorkOS **staging**, sandbox environment)

Left in place so the token-leg proof can be completed; delete when done.

| object | id |
|---|---|
| organization `fluidbox-m1-drill` | `org_01KZ49HYE27XQ4DYAWVHAH8ZES` |
| user `hrishidkakkad+m1drill@gmail.com` | `user_01KZ49J18958GA4EVDV2VN2MWR` |
| Connect app `fluidbox-m1-drill-oidc` | `app_01KZ49JD6R4FZ50A8D90JFHCB8` / `client_01KZ49JD6RHKP71APAQWMNSNAG` |

No production-environment objects were created; the shared staging AuthKit
app was **not** modified (its redirect-URI list belongs to another project).

## Proof 2 — Vercel cookie + SSE (9/9 on the code path)

`scripts/cloud/vercel-sse-probe.sh`, run against a local production build of
`apps/web` in **sso mode** with a deterministic SSE/cookie origin — so the
measurement isolates the proxy rather than core.

| # | proof | result |
|---|---|---|
| S1 | proxy streams SSE unbuffered | first byte < 1s |
| S2 | stream survives with keepalives | 60s held, 6/6 ticks delivered |
| S3 | `Last-Event-ID` forwarded upstream | origin saw `resumed_from: 42` — **resume works through the proxy**, which is what makes any duration cap survivable |
| C1 | `__Host-fbx_web` survives the proxy hop | yes — the cookie lands on the dashboard origin (the review's callback-host trap) |
| C2 | multiple `Set-Cookie` kept distinct + redirect `Location` propagated | yes |

**Not measured:** the Vercel **function duration cap**, which needs a real
deployment. Linking the Vercel project is a reserved §12 decision, so it was
not created autonomously. The script prints the exact 6-command recipe and
runs unchanged against a preview URL (`TARGET=…`). Because S3 passes, a cap
degrades the UX to a reconnect, never to lost events (core's hybrid
seq-catch-up SSE contract) — the fallback is documented in
`docs/hosted/cloud-architecture.md`.

Build-time trap confirmed in passing: `FLUIDBOX_API_URL` is baked into the
`/v1` rewrite at **build** time (`next.config.ts`), so changing it requires a
redeploy.

## Artifacts validated but NOT applied

Four Terraform stacks (`bootstrap`, `platform`, `app`, `edge`) — all
`terraform fmt`-clean and `terraform validate`-clean; ten operator scripts;
five `docs/hosted/cloud-*` documents; the §12 decision sheet. Nothing was
applied to AWS; the account survey that informed them was strictly read-only.

## Files here

`p3-create-org.txt`, `p4-create-idp.txt` (the conformance verdict, both auth
methods), `p5-activate.txt`, `p6-start-headers.txt`, `p6-authorize-url.txt`,
`p7-idp-response-headers.txt`, `p7-idp-body.html`,
`p7-client-id-comparison.txt`, `sse-stream-sample.txt`,
`sse-resume-sample.txt`, `cookie-proxy-headers.txt`.
