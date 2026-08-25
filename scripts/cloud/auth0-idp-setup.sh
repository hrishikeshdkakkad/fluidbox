#!/usr/bin/env bash
# Stand up a DURABLE identity provider for a Fluidbox Cloud org using Auth0,
# driven entirely from the Auth0 CLI. This is the path M1 actually shipped on.
#
# WHY AUTH0. The drill org was first proven with a Dex container on the
# operator's laptop behind an ngrok tunnel — fine as a proof, fatal for a beta
# org, since a reboot breaks sign-in for everyone in it. Auth0 is hosted, so the
# issuer outlives the laptop, and it is standards-conformant, which is the
# binding constraint (core is not allowed to change).
#
# It is also the cleanest of the conformant options, and the reason is one
# claim. Core requires a true `email_verified` — for the require_email_verified
# floor, and UNCONDITIONALLY for bootstrap-owner promotion. Auth0 emits it
# natively as a real boolean. Microsoft Entra does not, and needs its `xms_edov`
# optional claim mapped in as a substitute (see entra-idp-setup.sh). Auth0 also
# advertises code_challenge_methods_supported=[S256], which Entra omits.
# Net effect: this script needs ZERO claim overrides — core's defaults are right.
#
# NOT AUTOMATED HERE, on purpose: creating the org's human users. A real beta
# org's users come from that org's own directory or an invite, not from us
# minting passwords. `--with-drill-user` exists only for an internal drill org.
#
#   scripts/cloud/auth0-idp-setup.sh <org-slug> [--with-drill-user <email>]
#   scripts/cloud/auth0-idp-setup.sh --promote <org-slug> <email> [membership-id]

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

if [ "${1:-}" = "--promote" ]; then
  promote_owner "${2:?usage: --promote <org-slug> <email> [membership-id]}" \
    "${3:?usage: --promote <org-slug> <email> [membership-id]}" "${4:-}"
  exit 0
fi

# The auth0 CLI wraps its --json output in a human header and, depending on the
# subcommand and version, trailing chatter. `json.loads(raw[raw.find('{'):])`
# therefore fails whenever anything follows the closing brace - and it fails
# SILENTLY into an empty client_id, which this script then reports as
# "app creation failed" for an app it just successfully created.
#
# raw_decode stops at the end of the first complete JSON value, so it is immune
# to both.
_json_field() {  # _json_field <field> [open-char]  — reads stdin
  local field="${1:?}" open="${2:-{}"
  python3 -c "
import json,sys
raw=sys.stdin.read()
i=raw.find(sys.argv[2])
if i<0: print(''); raise SystemExit
try:
    obj,_=json.JSONDecoder().raw_decode(raw[i:])
except Exception:
    print(''); raise SystemExit
if isinstance(obj,list):
    print(''); raise SystemExit
print(obj.get(sys.argv[1],'') or '')
" "$field" "$open"
}

SLUG="${1:-${AUTH0_ORG_SLUG:-fluidzero}}"
APP_NAME="${AUTH0_APP_NAME:-Fluidbox Cloud M1}"
PUBLIC_URL="${FLUIDBOX_PUBLIC_URL:-https://fluidbox-cloud-dashboard.vercel.app}"
REDIRECT_URI="$PUBLIC_URL/v1/auth/callback"
DRILL_USER=""
[ "${2:-}" = "--with-drill-user" ] && DRILL_USER="${3:?--with-drill-user needs an email}"
EV=$(evidence_dir cloud-m1-auth0-idp)

say "P0 preflight"
command -v auth0 >/dev/null || die "auth0 CLI not installed" "brew install auth0"
TENANT=$(auth0 tenants list 2>/dev/null | awk '/→/{print $2}' | head -1)
[ -n "$TENANT" ] || die "auth0 CLI is not logged in" "run: auth0 login"
ok "auth0 tenant: $TENANT"
ISSUER="https://$TENANT/"   # Auth0's `iss` carries a TRAILING SLASH. Keep it.

ADMIN_TOKEN=$(cloud_admin_token)
[ -n "$ADMIN_TOKEN" ] || die "could not read /fluidbox/cloud/admin-token from SSM"
AUTH="Authorization: Bearer $ADMIN_TOKEN"
curl -sS -o /dev/null --max-time 20 "$CLOUD_API/v1/health" || die "control plane unreachable at $CLOUD_API"
ok "control plane healthy"

say "P1 discovery conformance (what core will re-check live)"
curl -sS --max-time 20 "$ISSUER.well-known/openid-configuration" > "$EV/discovery.json" \
  || die "issuer discovery unreachable: $ISSUER"
python3 - "$EV/discovery.json" <<'EOF' || exit 1
import json,sys
d=json.load(open(sys.argv[1])); bad=[]
if 'code' not in d.get('response_types_supported',[]): bad.append('response_type=code')
for k in ('authorization_endpoint','token_endpoint','jwks_uri','issuer'):
    if not d.get(k): bad.append(k)
pk=d.get('code_challenge_methods_supported')
if pk is not None and 'S256' not in pk: bad.append('PKCE S256 advertised but absent')
if 'RS256' not in d.get('id_token_signing_alg_values_supported',[]): bad.append('RS256')
print('  issuer   :', d.get('issuer'))
print('  pkce     :', pk)
print('  claims   :', 'email_verified' in d.get('claims_supported',[]) and 'email_verified native' or 'NO email_verified')
if bad: print('  REFUSED  :', bad); sys.exit(1)
EOF
ok "issuer satisfies core's conformance floor"

say "P2 application (idempotent)"
CLIENT_ID=$(auth0 apps list --json 2>/dev/null | python3 -c "
import json,sys
raw=sys.stdin.read(); i=raw.find('[')
try: apps=json.loads(raw[i:])
except Exception: sys.exit(0)
for a in apps:
    if a.get('name')==sys.argv[1]: print(a.get('client_id')); break
" "$APP_NAME")

if [ -n "$CLIENT_ID" ]; then
  ok "reusing app $CLIENT_ID"
  SECRET=$(auth0 apps show "$CLIENT_ID" --reveal-secrets --json 2>/dev/null | _json_field client_secret)
else
  OUT=$(auth0 apps create --name "$APP_NAME" \
    --description "Fluidbox Cloud — per-org OIDC login" \
    --type regular --callbacks "$REDIRECT_URI" --reveal-secrets --json 2>&1)
  CLIENT_ID=$(printf '%s' "$OUT" | _json_field client_id)
  SECRET=$(printf '%s' "$OUT" | _json_field client_secret)
  # Deliberately NOT echoing $OUT: `apps create --reveal-secrets` embeds the
  # client secret, and a failure path that dumps it puts a live credential into
  # every terminal scrollback and CI log that ever runs this.
  [ -n "$CLIENT_ID" ] || die "app creation failed" \
    "re-run with: auth0 apps list --json | grep -F '$APP_NAME'" \
    "(the raw CLI output is withheld here because it contains the client secret)"
  ok "created app $CLIENT_ID"
fi

# `auth0 apps create` sets the callback and nothing else, which leaves three
# real gaps that only show up later:
#
#   allowed_logout_urls  EMPTY. Auth0 refuses a /v2/logout returnTo that is not
#                        listed, so sign-out dead-ends on an Auth0 error page.
#   web_origins          EMPTY. Needed for any browser-origin call to Auth0.
#   grant_types          includes `implicit` and `client_credentials` by
#                        default. This app is an OIDC authorization-code client
#                        with PKCE; implicit is deprecated and returns tokens in
#                        the URL fragment, and client_credentials is a
#                        machine-to-machine grant this app never uses. Both are
#                        standing attack surface for a capability nothing needs.
#
# Idempotent: PATCH sets the same values on every run.
say "P2c application URLs + grant hardening"
LOGOUT_URLS="[\"$PUBLIC_URL\", \"$PUBLIC_URL/login\", \"$PUBLIC_URL/app\"]"
if auth0 api patch "clients/$CLIENT_ID" --data "{
  \"allowed_logout_urls\": $LOGOUT_URLS,
  \"web_origins\": [\"$PUBLIC_URL\"],
  \"grant_types\": [\"authorization_code\", \"refresh_token\"],
  \"token_endpoint_auth_method\": \"client_secret_post\",
  \"oidc_conformant\": true
}" >/dev/null 2>&1; then
  ok "callbacks + logout URLs set; implicit and client_credentials removed"
else
  warn "could not patch application URLs — set allowed_logout_urls in the Auth0 dashboard, or sign-out will dead-end"
fi
[ -n "$SECRET" ] || die "could not obtain the client secret"
# The secret goes to core's custody and nowhere else. Never write it to $EV.
printf 'issuer=%s\nclient_id=%s\nredirect_uri=%s\n' "$ISSUER" "$CLIENT_ID" "$REDIRECT_URI" > "$EV/app.txt"

if [ -n "$DRILL_USER" ]; then
  say "P2b drill user (internal orgs only)"
  PW="Fbx-$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)-9aZ"
  UID_=$(auth0 users create --name "Drill Owner" --email "$DRILL_USER" \
    --connection-name "Username-Password-Authentication" --password "$PW" --json 2>&1 |
    python3 -c "
import json,sys
raw=sys.stdin.read(); i=raw.find('{')
try: print(json.loads(raw[i:]).get('user_id',''))
except Exception: pass")
  if [ -n "$UID_" ]; then
    # `users create` has no --email-verified flag, and core's default floor
    # REQUIRES a true email_verified, so patch it or first login is refused.
    auth0 api patch "users/$(printf '%s' "$UID_" | sed 's/|/%7C/')" \
      --data '{"email_verified":true}' >/dev/null 2>&1 \
      && ok "drill user $DRILL_USER (email_verified=true)" \
      || warn "created $DRILL_USER but could NOT set email_verified — login will be refused"
    echo "  password: $PW"
  else
    warn "drill user not created (may already exist)"
  fi
fi

say "P3 register the issuer with core"
CLAIMS='{"email":"email","email_verified":"email_verified","name":"name","require_email_verified":true,"default_role":"member","role_map":{},"roles_path":"groups"}'
CUR=$(curl -sS --max-time 20 -H "$AUTH" "$CLOUD_API/v1/admin/orgs/$SLUG/idp" | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for c in d.get('idp_configs',[]):
    if c.get('status')=='active':
        print(c['id'], c.get('issuer',''), c.get('client_id','')); break
" 2>/dev/null)
ACTIVE_ID=$(printf '%s' "$CUR" | awk '{print $1}')

# Re-running must be a NO-OP when the active config already points at this same
# issuer + client. Registering again would MIGRATE, and a migrate bumps the
# generation — which is a real event, not bookkeeping: it is how an operator
# signals "the identity moved". Churning it on an idempotent re-run would
# invalidate sessions for no reason.
if [ "$(printf '%s' "$CUR" | awk '{print $2}')" = "$ISSUER" ] \
   && [ "$(printf '%s' "$CUR" | awk '{print $3}')" = "$CLIENT_ID" ]; then
  ok "active config already points at this issuer + client — nothing to change"
  say "done (no-op)"
  echo "  Sign in: $PUBLIC_URL/login   (org slug: $SLUG)"
  exit 0
fi

OK_=0
for METHOD in client_secret_post client_secret_basic; do
  BODY=$(python3 -c "
import json,sys
b={'issuer':sys.argv[1],'client_id':sys.argv[2],'client_secret':sys.argv[3],
   'token_endpoint_auth':sys.argv[4],'scopes':['openid','profile','email'],
   'claim_mappings':json.loads(sys.argv[5])}
if sys.argv[6]=='migrate': b['carry_forward']=False
print(json.dumps(b))" "$ISSUER" "$CLIENT_ID" "$SECRET" "$METHOD" "$CLAIMS" \
       "$([ -n "$ACTIVE_ID" ] && echo migrate || echo create)")
  if [ -n "$ACTIVE_ID" ]; then
    URL="$CLOUD_API/v1/admin/orgs/$SLUG/idp/$ACTIVE_ID/migrate"
  else
    URL="$CLOUD_API/v1/admin/orgs/$SLUG/idp"
  fi
  CODE=$(curl -sS -o "$EV/register-$METHOD.json" -w '%{http_code}' --max-time 60 \
    -X POST -H "$AUTH" -H 'Content-Type: application/json' -d "$BODY" "$URL")
  if [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; then
    ok "registered with token_endpoint_auth=$METHOD — passed core's LIVE discovery floor"; OK_=1; break
  fi
  warn "core refused token_endpoint_auth=$METHOD ($CODE): $(head -c 200 "$EV/register-$METHOD.json")"
done
[ "$OK_" = 1 ] || die "no token_endpoint_auth method was accepted" \
  "read $EV/register-*.json — that output IS core's conformance verdict"

# A migrate ACTIVATES the new generation; a fresh create needs an explicit call.
NEW=$(curl -sS --max-time 20 -H "$AUTH" "$CLOUD_API/v1/admin/orgs/$SLUG/idp" | python3 -c "
import json,sys
for c in json.load(sys.stdin)['idp_configs']:
    if c.get('status')=='active': print(c['id'], c['generation'], c['issuer']); break
")
if [ -z "$NEW" ]; then
  say "P4 activate"
  ID=$(curl -sS --max-time 20 -H "$AUTH" "$CLOUD_API/v1/admin/orgs/$SLUG/idp" | python3 -c "
import json,sys
cs=json.load(sys.stdin)['idp_configs']; print(sorted(cs,key=lambda c:c['generation'])[-1]['id'])")
  curl -sS -o /dev/null --max-time 30 -X POST -H "$AUTH" \
    "$CLOUD_API/v1/admin/orgs/$SLUG/idp/$ID/activate" && ok "activated $ID"
else
  ok "active: $NEW"
fi

say "done"
cat <<EOF

  Sign in:   $PUBLIC_URL/login   (org slug: $SLUG)
  Issuer:    $ISSUER

  First sign-in provisions a MEMBER. Grant owner with:
    scripts/cloud/auth0-idp-setup.sh --promote $SLUG <email>

  Evidence: $EV
EOF
