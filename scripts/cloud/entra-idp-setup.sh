#!/usr/bin/env bash
# Stand up a DURABLE identity provider for a Fluidbox Cloud org, using
# Microsoft Entra ID driven entirely from the Azure CLI.
#
# WHY ENTRA. The M1 drill org was proven with a Dex container on the operator's
# laptop behind an ngrok tunnel. That works, but a reboot breaks sign-in for the
# whole org. Entra is hosted by Microsoft, so the issuer outlives the laptop.
# It is also standards-conformant, which is the binding constraint: WorkOS's
# /user_management/authorize rejects core's compliant OIDC request unless a
# proprietary `provider=authkit` parameter is present, and putting a vendor
# parameter in core is forbidden by PLAN rev 3. Entra needs no core change.
#
# TWO ENTRA QUIRKS THIS SCRIPT EXISTS TO ABSORB:
#
#   1. Entra's v2.0 discovery document does NOT advertise
#      code_challenge_methods_supported. That is fine — core always SENDS
#      code_challenge + code_challenge_method=S256 itself (login.rs), and its
#      conformance floor accepts PKCE "advertised-or-absent". Entra does
#      support S256; it just doesn't say so in metadata.
#
#   2. Entra emits no `email_verified` boolean, and core requires one — both
#      for the require_email_verified floor and, unconditionally, for
#      bootstrap-owner promotion. Entra's answer is the `xms_edov` optional
#      claim ("email domain owner verified"), which carries exactly that
#      semantic as a real bool. We request it, and map email_verified -> it.
#      Because xms_edov only lands when the email domain is tenant-verified, we
#      ALSO set require_email_verified=false so authentication cannot hard-fail
#      on it, and promote the owner explicitly afterwards rather than depending
#      on the bootstrap arm. Belt and braces, deliberately.
#
# Run AFTER granting the CLI a Microsoft Graph scope (this script tells you the
# exact command if the token is missing). Idempotent: re-running reuses the
# existing app registration and only appends a fresh secret.
#
#   scripts/cloud/entra-idp-setup.sh [org-slug]

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

API="$CLOUD_API"
admin_token() { cloud_admin_token; }

# Shared with auth0-idp-setup.sh — see promote_owner() in lib.sh for why
# promotion is a separate admin act rather than a bootstrap-owner arm.
if [ "${1:-}" = "--promote" ]; then
  promote_owner "${2:?usage: --promote <org-slug> <email> [membership-id]}" \
    "${3:?usage: --promote <org-slug> <email> [membership-id]}" "${4:-}"
  exit 0
fi

SLUG="${1:-${ENTRA_ORG_SLUG:-fluidzero}}"
APP_NAME="${ENTRA_APP_NAME:-Fluidbox Cloud M1}"
PUBLIC_URL="${FLUIDBOX_PUBLIC_URL:-https://fluidbox-cloud-dashboard.vercel.app}"
REDIRECT_URI="$PUBLIC_URL/v1/auth/callback"
# Which Entra claim carries the address. `email` is right when the directory
# record has a mail attribute; tenants without one must fall back to the UPN.
EMAIL_CLAIM="${ENTRA_EMAIL_CLAIM:-email}"
EV=$(evidence_dir cloud-m1-entra-idp)

say "P0 preflight — Azure CLI must hold a Microsoft GRAPH token"
# An ARM token is not enough. `az ad app` calls Graph, and a session logged in
# for resource management cannot silently upgrade its scope: AAD answers
# AADSTS9002313 and the CLI tells you to re-login. Only a human can complete
# that browser consent, so fail loudly with the exact command rather than
# emitting a confusing Graph error from three calls deeper.
if ! az account get-access-token --resource https://graph.microsoft.com -o none 2>/dev/null; then
  TENANT_HINT=$(az account show --query tenantId -o tsv 2>/dev/null || echo '<your-tenant-id>')
  die "Azure CLI has no Microsoft Graph token" \
    "This is the ONE step that needs a human — it is a browser consent." \
    "" \
    "  az login --tenant $TENANT_HINT --scope https://graph.microsoft.com/.default" \
    "" \
    "Then re-run this script; everything after the login is automated."
fi
TENANT=$(az account show --query tenantId -o tsv)
UPN=$(az account show --query user.name -o tsv)
ok "graph token present — tenant $TENANT (signed in as $UPN)"

ADMIN_TOKEN=$(admin_token)
[ -n "$ADMIN_TOKEN" ] || die "could not read /fluidbox/cloud/admin-token from SSM"
AUTH="Authorization: Bearer $ADMIN_TOKEN"
curl -sS -o /dev/null --max-time 20 "$API/v1/health" || die "control plane unreachable at $API"
ok "control plane healthy at $API"

say "P1 app registration (idempotent)"
APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null)
if [ -n "$APP_ID" ] && [ "$APP_ID" != "None" ]; then
  ok "reusing existing app registration $APP_ID"
else
  APP_ID=$(az ad app create --display-name "$APP_NAME" \
    --sign-in-audience AzureADMyOrg \
    --web-redirect-uris "$REDIRECT_URI" \
    --query appId -o tsv) || die "app registration failed"
  ok "created app registration $APP_ID"
fi
OBJ_ID=$(az ad app show --id "$APP_ID" --query id -o tsv) || die "could not resolve app object id"

# Ensure the redirect URI is present even on the reuse path (a previous run may
# have targeted a different public URL).
az ad app update --id "$APP_ID" --web-redirect-uris "$REDIRECT_URI" >/dev/null 2>&1 \
  && ok "redirect URI set: $REDIRECT_URI" \
  || warn "could not update redirect URI — verify it manually"

say "P2 optional claims — email + xms_edov on the ID token"
# xms_edov is the whole reason this step exists; see the header note.
az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications/$OBJ_ID" \
  --headers 'Content-Type=application/json' \
  --body '{"optionalClaims":{"idToken":[{"name":"email","essential":false},{"name":"xms_edov","essential":false}],"accessToken":[],"saml2Token":[]}}' \
  >/dev/null 2>&1 \
  && ok "optional claims requested (email, xms_edov)" \
  || warn "optional-claim PATCH failed — login still works, but owner bootstrap will rely on the explicit promote below"

say "P3 client secret"
SECRET=$(az ad app credential reset --id "$APP_ID" --append \
  --display-name "fluidbox-cloud-m1" --years 2 --query password -o tsv 2>/dev/null) \
  || die "could not mint a client secret"
ok "client secret minted (2y) — never written to disk by this script"

ISSUER="https://login.microsoftonline.com/$TENANT/v2.0"
say "P4 register the issuer with core"
printf 'issuer=%s\nclient_id=%s\nredirect_uri=%s\ntenant=%s\n' \
  "$ISSUER" "$APP_ID" "$REDIRECT_URI" "$TENANT" > "$EV/entra-app.txt"

CLAIMS=$(python3 -c "
import json,sys
print(json.dumps({
  'email': sys.argv[1],
  'email_verified': 'xms_edov',
  'name': 'name',
  'require_email_verified': False,
  'default_role': 'member',
  'role_map': {},
  'roles_path': 'groups',
}))" "$EMAIL_CLAIM")

# Is there an active config to migrate, or is this a first registration? An
# issuer change is a MIGRATE (it bumps the generation and keeps the org's
# identity history); a fresh org is a CREATE.
ACTIVE_ID=$(curl -sS --max-time 20 -H "$AUTH" "$API/v1/admin/orgs/$SLUG/idp" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(0)
for c in d.get('idp_configs',[]):
    if c.get('status')=='active':
        print(c['id']); break
" 2>/dev/null)

# Entra accepts both; core records whichever its discovery probe validates, so
# try the stricter POST form first and fall back rather than guessing.
IDP_ID=""
for METHOD in client_secret_post client_secret_basic; do
  BODY=$(python3 -c "
import json,sys
b={'issuer':sys.argv[1],'client_id':sys.argv[2],'client_secret':sys.argv[3],
   'token_endpoint_auth':sys.argv[4],'scopes':['openid','profile','email'],
   'claim_mappings':json.loads(sys.argv[5])}
if sys.argv[6]=='migrate': b['carry_forward']=False
print(json.dumps(b))" "$ISSUER" "$APP_ID" "$SECRET" "$METHOD" "$CLAIMS" \
       "$([ -n "$ACTIVE_ID" ] && echo migrate || echo create)")

  if [ -n "$ACTIVE_ID" ]; then
    URL="$API/v1/admin/orgs/$SLUG/idp/$ACTIVE_ID/migrate"
  else
    URL="$API/v1/admin/orgs/$SLUG/idp"
  fi
  OUT=$(curl -sS --max-time 40 -w '\n%{http_code}' -X POST -H "$AUTH" \
    -H 'Content-Type: application/json' -d "$BODY" "$URL")
  CODE=$(printf '%s' "$OUT" | tail -1)
  { echo "### token_endpoint_auth=$METHOD -> $CODE"; printf '%s\n' "$OUT" | sed '$d'; } \
    >> "$EV/idp-register.txt"
  case "$CODE" in
    200|201)
      IDP_ID=$(printf '%s' "$OUT" | sed '$d' | python3 -c "
import sys,json
d=json.load(sys.stdin); print((d.get('idp') or d).get('id',''))" 2>/dev/null)
      ok "issuer registered with token_endpoint_auth=$METHOD — passed core's live discovery floor"
      break;;
  esac
  warn "core refused token_endpoint_auth=$METHOD ($CODE)"
done
[ -n "$IDP_ID" ] || die "no token_endpoint_auth method was accepted" \
  "read $EV/idp-register.txt — that output IS core's conformance verdict"

say "P5 activate"
CODE=$(curl -sS -o "$EV/activate.txt" -w '%{http_code}' --max-time 30 \
  -X POST -H "$AUTH" "$API/v1/admin/orgs/$SLUG/idp/$IDP_ID/activate")
case "$CODE" in
  200|204) ok "IdP $IDP_ID is ACTIVE for org $SLUG";;
  *) die "activation failed ($CODE) — see $EV/activate.txt";;
esac

say "done — one human step remains"
cat <<EOF

  Sign in here:  $PUBLIC_URL/login
  Org slug:      $SLUG
  Identity:      $UPN  (your Entra account — same password as Azure)

  On FIRST login you are provisioned as a *member*. Promote yourself to owner:

    scripts/cloud/entra-idp-setup.sh --promote $SLUG "$UPN"

  Evidence: $EV
  The Dex container is now redundant:  docker rm -f dex

EOF
