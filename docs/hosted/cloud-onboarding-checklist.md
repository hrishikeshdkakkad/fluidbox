# Fluidbox Cloud M1 — beta org onboarding checklist

One page per org; fill every box, attach it to the onboarding ledger (M1
brief §5.8). Another operator must be able to run this without asking
questions. Prereqs: platform+app+edge applied, origin secret rotated, Vercel
dashboard live in sso mode, `FLUIDBOX_REQUIRE_SSO=1` (the M1.2 app apply).

Conventions: same as the runbook header (`$API`, `$A`).

## A. Decide + reserve

- [ ] Org slug `______` (lowercase/digits/hyphens; the tenants CHECK enforces
      the shape — a 400 on create means the slug, fix it here).
- [ ] Display name `______`, owner email `______` (the invited human).
- [ ] Ledger row opened (date, slug, owner, operator).

## B. Create the tenant

- [ ] `curl -fsS -X POST -H "$A" -H 'content-type: application/json' \
        -d '{"slug":"<slug>","display_name":"<name>"}' "$API/v1/admin/orgs"`
- [ ] `GET $API/v1/admin/orgs` shows it.

## C. Identity (per-org OIDC app)

**Bring-your-own IdP per org** (§12 decision #4). The org supplies any
standards-conformant OIDC issuer; core is untouched.

> **WorkOS cannot be used.** Its `/user_management/authorize` rejects core's
> fully compliant request (`response_type=code`, `scope=openid email profile`,
> nonce, PKCE S256, state) with `invalid-connection-selector`, and only works
> with the proprietary `provider=authkit` parameter. Supporting that means a
> vendor parameter in core — forbidden by PLAN rev 3, so it is an M3 proposal,
> not an onboarding step. Do not spend time on it. Auth0, Okta, Microsoft
> Entra ID, Google, and Keycloak all work as-is.

- [ ] Create the org's OIDC application at their IdP. Redirect URI =
      `https://<vercel-origin>/v1/auth/callback` (the sso rewrite carries it to
      core; the cookie must land on the Vercel origin — never the CloudFront
      host).
- [ ] If the IdP supports an organization restriction, set it to the org —
      IdP-side org binding is the zero-core-change control (PLAN rev 3
      identity §1); record whether it is enforced at authorize time.
- [ ] Collect issuer URL, client id, client secret.
- [ ] Create the core IdP config (runbook §2) **with
      `bootstrap_owner_email` = the owner** — this is what arms first login.
      Note it is consumed only when the ID token carries a **true**
      `email_verified`; issuers that omit it (Entra) need the explicit
      promotion below instead.
- [ ] `POST …/idp/<id>/activate`.
- [ ] Secret handed to core custody only — delete any local copy.

**Microsoft Entra ID is fully scripted** — `scripts/cloud/entra-idp-setup.sh`
does app registration, optional claims, secret, core registration, and
activation in one pass. It needs one human step first, a browser consent that
grants the Azure CLI a Microsoft Graph scope (an ARM session is not enough and
cannot silently upgrade):

```
az login --tenant <tenant-id> --scope https://graph.microsoft.com/.default
scripts/cloud/entra-idp-setup.sh <org-slug>
# after the owner's first sign-in:
scripts/cloud/entra-idp-setup.sh --promote <org-slug> <owner-email>
```

Entra needs two accommodations, both handled by that script and neither
requiring a core change: it does not advertise
`code_challenge_methods_supported` (core sends PKCE S256 regardless, and its
conformance floor accepts "advertised-or-absent"), and it emits no
`email_verified` boolean (mapped to the `xms_edov` optional claim, with
`require_email_verified: false` so authentication cannot hard-fail on it).

## D. Model access

- [ ] Nothing to do for the default path: the tenant LiteLLM virtual key
      mints lazily on first model call (haiku-only, $5/30d rolling).
- [ ] Non-default access (different models/budget): change the app-stack
      variables (deployment-wide) or record an explicit exception in the
      ledger. There is NO per-tenant override knob in M1 — that is a
      documented gap, not an oversight.

## E. Verify the login path BEFORE inviting

- [ ] Private browser window → `https://<vercel-origin>/login` → slug →
      IdP → authenticate AS THE OPERATOR TEST USER (staging) or with the
      owner on a call → lands on `/app`.
- [ ] `GET $API/v1/admin/orgs/<slug>/members` shows the arrived membership,
      owner role, active.
- [ ] Logout works (`/app` → sign out → `/login`).
- [ ] Wrong-org probe: attempt `…/login` with ANOTHER org's slug using this
      user → refused at the IdP (org restriction) or by core (no armed
      membership) — record which layer refused; **a success here is a STOP
      THE LINE finding.**

## F. Hand over

- [ ] Send the owner: their login URL (`https://<vercel-origin>/login`),
      their slug, the beta expectations note (quota gaps: no per-tenant
      concurrent-run cap, budgets are rolling-30d not calendar; single-node
      availability tier; support contact).
- [ ] Owner signs in unaided (M1.2 gate) — confirm receipt.
- [ ] Ledger row completed: outcome, dates, IdP config id, quirks observed.

## G. Rollback (org created wrong / abandoned)

- [ ] `POST …/idp/<id>/disable`, deactivate any memberships (runbook §7 a+b).
- [ ] Record in the ledger. (There is no tenant delete/purge in M1 — the row
      stays, disabled; purge is an M3 workflow. This is a documented gap.)
