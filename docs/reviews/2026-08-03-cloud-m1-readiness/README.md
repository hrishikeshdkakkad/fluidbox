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

**Verdict (superseded — see "M1.0 gate — CLOSED by apply" at the end of this
file):** the bootstrap stack was applied on 2026-08-03 with explicit approval.
The rows above marked "BUILT, awaiting apply" are now LIVE and verified; two
human steps remain (SNS email confirmation, and the root-key decision).

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

## M1.0 gate — CLOSED by apply (2026-08-03)

The bootstrap stack was applied with explicit user approval: **27 added, 0
changed, 0 destroyed**. Live and verified:

| guardrail | state |
|---|---|
| Scoped deployer role | `arn:aws:iam::471112572248:role/fluidbox-cloud/fluidbox-cloud-deployer` |
| Operator user + both AWS profiles | configured; `fluidbox-operator` → assumes deployer, verified |
| Account-wide breaker | **$600/mo** (the decided number) |
| Tag-filtered fluidbox budget | $50/mo (raise to ~175 with the platform apply) |
| CloudTrail `fluidbox-cloud` | `IsLogging=True`, validation on, 90-day lifecycle |
| Root-activity alarm | EventBridge rule `ENABLED` |
| Terraform state | S3, versioned, encrypted, public-access-blocked, TLS-only; migrated off local disk |

`verify-bootstrap.sh` as the **assumed deployer**: 10 pass, 2 outstanding —
both human steps (below).

### Two findings from the apply itself

1. **The bootstrap stack is root-only for every change** — verified, not
   assumed. Both non-root profiles were tried against the applied stack and
   both fail at *plan*: the deployer deliberately lacks `iam:GetUser` on the
   operator, `budgets:ListTagsForResource`, `events:DescribeRule`,
   `sns:GetTopicAttributes` and the trail bucket's `s3:GetBucket*`. Granting
   them would let the deployer read and then rewrite the policies that bound
   it. An earlier draft of the bootstrap README claimed budget tuning could be
   applied with the deployer profile; that was wrong and is corrected.
2. **The root key is still ACTIVE, deliberately.** §9-1's *capability* is
   already proven — the scoped deployer applied and verified without it. But
   CloudTrail shows root was used on **2026-08-01** (a broad read-only account
   inventory: ListStacks, ListSecrets, ListHostedZones, ListClusters,
   ListFunctions, ListBuckets…) and **2026-07-30** (ECR
   `DescribeRepositories`) — i.e. by something other than this session, on an
   account shared with four other projects. Deactivating it could break
   another project's tooling, which was not part of the approval given. The
   decision is one command once you have confirmed nothing else depends on it:

   ```bash
   aws iam update-access-key --access-key-id AKIAW3MD7LVMAE45DEVP --status Inactive
   AWS_PROFILE=fluidbox-deployer scripts/cloud/verify-bootstrap.sh   # expect 12/12
   # then, after a day with nothing broken:
   aws iam delete-access-key --access-key-id AKIAW3MD7LVMAE45DEVP
   ```

   Reversible from the console if anything does break. The
   `fluidbox-root-activity` alarm now announces every future root use, so a
   surprise consumer will identify itself.

### Also outstanding

- **SNS email subscription is `PendingConfirmation`** — budget and root alarms
  will not reach you until you click the link SNS sent to
  hrishidkakkad@gmail.com.
- **Cost-allocation tag `project` is `Inactive`** — expected: AWS refuses to
  activate a tag it has never seen on billed usage. Re-apply bootstrap with
  `-var activate_cost_allocation_tag=true` ~24h after the platform stack bills.
