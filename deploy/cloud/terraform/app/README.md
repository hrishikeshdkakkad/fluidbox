# App — the unchanged chart + composed LiteLLM (deployer-role apply)

Order is enforced by `scripts/cloud/deploy-app.sh` (use it — it checks the
out-of-band Secrets exist before terraform ever runs):

1. Neon databases exist (fluidbox app DB direct/non-pooler + a SMALL separate
   LiteLLM DB) — `docs/hosted/cloud-operator-runbook.md` §"Provision databases".
2. `scripts/cloud/make-secrets.sh` created `fluidbox-secrets` +
   `fluidbox-litellm-db` in the fluidbox namespace (values never touch
   Terraform state).
3. `terraform apply` here: LiteLLM (DB-backed, 2Gi limit — the proven OOM fix)
   then the fluidbox chart (OCI, `chart_version`, `web.enabled=false`,
   `fullnameOverride=fluidbox` so the Pod Identity association's
   `fluidbox/fluidbox-server` service-account target holds).
4. `scripts/cloud/rotate-origin-secret.sh` right after the EDGE stack applies —
   it adds the origin-header conditions annotation the values file deliberately
   omits.

Staged flags (helm values changes, never chart changes):

| Phase | `require_sso` | `public_url` |
|---|---|---|
| M1.1 platform gate (replay via admin API) | `false` | `""` |
| M1.2 onboarding (Vercel dashboard live) | `true` | `https://<vercel-origin>` |

The M1.2 flip confines the admin token to `/v1/admin/*` (exactly the operator
onboarding surface) and turns on per-org OIDC login. `FLUIDBOX_LLM_KEY_MODE`
is `tenant` from the start — hosted + `shared` is a deliberate 503 in core.
