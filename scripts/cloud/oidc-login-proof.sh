#!/usr/bin/env bash
# M1.0 gate proof — "Prove the manually configured OIDC login path".
#
# Runs core's REAL per-org OIDC flow (FLUIDBOX_REQUIRE_SSO=1, RLS runtime role)
# against a manually configured IdP, on a THROWAWAY local database. Proves, in
# order, with recorded evidence:
#
#   P1  multi-user boot posture (REQUIRE_SSO + non-owner RLS role) comes up
#   P2  admin token is CONFINED to /v1/admin/* (the operator onboarding surface)
#   P3  org create via the admin API
#   P4  IdP config create runs LIVE DISCOVERY and enforces the conformance floor
#       (endpoints present, PKCE-S256 advertised-or-absent, response_type=code,
#       token_endpoint_auth method) — a non-conformant issuer is REFUSED here
#   P5  activation
#   P6  /v1/auth/login/{slug}/start builds an authorize URL carrying nonce +
#       PKCE S256 + state, and sets the browser-bound one-time login cookie
#   P7  the IdP ACCEPTS that authorize request (HTTP-level; a human completes
#       the consent leg)
#
# Everything is local + free: no AWS, no model calls, no live Neon.
#
#   IDP_ISSUER=… IDP_CLIENT_ID=… [IDP_CLIENT_SECRET=…] scripts/cloud/oidc-login-proof.sh
#
# Defaults target the WorkOS staging drill objects created for the M1.0 proof.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

PORT="${PROOF_PORT:-8790}"
INTERNAL_PORT="${PROOF_INTERNAL_PORT:-8791}"
DB="${PROOF_DB:-fluidbox_m1proof}"
DB_URL="postgres://fluidbox:fluidbox@127.0.0.1:5433/$DB"
API="http://127.0.0.1:$PORT"
SLUG="${PROOF_SLUG:-m1drill}"
IDP_ISSUER="${IDP_ISSUER:-https://api.workos.com/user_management/client_01KGA8ECKMDH8GWPZR00QGPTBZ}"
IDP_CLIENT_ID="${IDP_CLIENT_ID:-client_01KZ49JD6RHKP71APAQWMNSNAG}"
IDP_CLIENT_SECRET="${IDP_CLIENT_SECRET:-placeholder-not-used-before-the-token-leg}"
OWNER_EMAIL="${OWNER_EMAIL:-hrishidkakkad+m1drill@gmail.com}"
BIN="${PROOF_SERVER_BIN:-target/debug/fluidbox-server}"
WORK="${SCRATCH:-/tmp/fluidbox-m1proof}"
EV=$(evidence_dir cloud-m1-readiness)
LOG="$WORK/server.log"
mkdir -p "$WORK/data"

PASS=0; FAILN=0
pass() { ok "$1"; PASS=$((PASS+1)); }
bad()  { fail "$1"; FAILN=$((FAILN+1)); }

cleanup() {
  [ -f "$WORK/server.pid" ] && kill "$(cat "$WORK/server.pid")" 2>/dev/null
  return 0
}
trap cleanup EXIT

[ -x "$BIN" ] || die "server binary not found at $BIN" "build it: cargo build -p fluidbox-server"

say "P0 preflight — throwaway DB, never the dev database"
[ "$DB" = "fluidbox" ] && die "refusing to run against the DEV database"
PGPASSWORD=fluidbox psql -h 127.0.0.1 -p 5433 -U fluidbox -d postgres -tAc \
  "SELECT 1 FROM pg_database WHERE datname='$DB'" | grep -q 1 \
  || PGPASSWORD=fluidbox psql -h 127.0.0.1 -p 5433 -U fluidbox -d postgres -qc "CREATE DATABASE $DB" >/dev/null
pass "database $DB ready (dev database untouched)"

say "P1 boot the control plane in MULTI-USER posture"
# The server calls dotenvy::dotenv() on its CWD, so it is launched from the
# scratch dir: no repo .env can leak dev settings (or the dev DATABASE_URL)
# into this proof. Every variable below is therefore explicit.
ADMIN_TOKEN="fbx_admin_$(openssl rand -hex 16)"
ABS_BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
cd "$WORK" || exit 1
env -i PATH="$PATH" HOME="$HOME" \
  DATABASE_URL="$DB_URL" \
  FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime \
  FLUIDBOX_REQUIRE_SSO=1 \
  FLUIDBOX_ADMIN_TOKEN="$ADMIN_TOKEN" \
  FLUIDBOX_CREDENTIAL_KEY="$(openssl rand -hex 32)" \
  FLUIDBOX_BIND="127.0.0.1:$PORT" \
  FLUIDBOX_INTERNAL_BIND="127.0.0.1:$INTERNAL_PORT" \
  FLUIDBOX_PUBLIC_URL="$API" \
  FLUIDBOX_DATA_DIR="$WORK/data" \
  LITELLM_MASTER_KEY=proof-only-no-model-calls \
  LLM_UPSTREAM_URL="http://127.0.0.1:4999" \
  "$ABS_BIN" > "$LOG" 2>&1 &
echo $! > "$WORK/server.pid"
cd "$OLDPWD" || exit 1

for _ in $(seq 1 60); do
  curl -fsS --max-time 2 "$API/v1/health" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS --max-time 2 "$API/v1/health" >/dev/null 2>&1 \
  || { tail -25 "$LOG"; die "control plane did not become healthy" "log: $LOG"; }
pass "booted (migrations applied on boot)"
grep -qi "row-level security is ENFORCED" "$LOG" \
  && pass "RLS ENFORCED for the pool (non-owner runtime role)" \
  || bad "RLS enforcement line absent from the boot log"
grep -qi "multi-user\|REQUIRE_SSO\|sso" "$LOG" && pass "multi-user mode acknowledged at boot" || warn "no explicit sso boot line (not fatal)"

say "P2 admin token confinement"
A="authorization: Bearer $ADMIN_TOKEN"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$A" "$API/v1/sessions")
[ "$CODE" = "200" ] && bad "admin token reached /v1/sessions ($CODE) — confinement NOT holding" \
                    || pass "admin token refused outside /v1/admin (/v1/sessions → $CODE)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$A" "$API/v1/admin/orgs")
[ "$CODE" = "200" ] && pass "admin token accepted on /v1/admin/orgs (200)" || bad "/v1/admin/orgs → $CODE"

say "P3 create the org (operator onboarding step 1)"
OUT=$(curl -s -w '\n%{http_code}' -X POST -H "$A" -H 'content-type: application/json' \
  -d "{\"slug\":\"$SLUG\",\"display_name\":\"M1 Drill Org\"}" "$API/v1/admin/orgs")
CODE=$(printf '%s' "$OUT" | tail -1)
printf '%s\n' "$OUT" > "$EV/p3-create-org.txt"
case "$CODE" in 200|201) pass "org '$SLUG' created ($CODE)";; 409) pass "org '$SLUG' already existed (409, idempotent re-run)";; *) bad "org create → $CODE";; esac

say "P4 create the IdP config — LIVE DISCOVERY + conformance floor"
# token_endpoint_auth is REQUIRED by CreateIdpBody and must appear in the
# issuer's discovered token_endpoint_auth_methods_supported — where an ABSENT
# list implies the OIDC default client_secret_basic ONLY. Both methods are
# tried so the evidence records which one the issuer actually satisfies.
IDP_ID=""
for AUTH_METHOD in ${IDP_AUTH_METHODS:-client_secret_basic client_secret_post}; do
  BODY=$(python3 - "$IDP_ISSUER" "$IDP_CLIENT_ID" "$IDP_CLIENT_SECRET" "$OWNER_EMAIL" "$AUTH_METHOD" <<'PY'
import json, sys
print(json.dumps({"issuer": sys.argv[1], "client_id": sys.argv[2],
                  "client_secret": sys.argv[3], "bootstrap_owner_email": sys.argv[4],
                  "token_endpoint_auth": sys.argv[5]}))
PY
)
  OUT=$(curl -s -w '\n%{http_code}' -X POST -H "$A" -H 'content-type: application/json' \
    -d "$BODY" "$API/v1/admin/orgs/$SLUG/idp")
  CODE=$(printf '%s' "$OUT" | tail -1)
  { echo "### token_endpoint_auth=$AUTH_METHOD"; printf '%s\n' "$OUT"; } >> "$EV/p4-create-idp.txt"
  case "$CODE" in
    200|201)
      pass "IdP config created with token_endpoint_auth=$AUTH_METHOD ($CODE) — issuer passed core's live-discovery conformance floor"
      IDP_ID=$(printf '%s' "$OUT" | sed '$d' | python3 -c "import sys,json;d=json.load(sys.stdin);print((d.get('idp') or d).get('id',''))" 2>/dev/null || true)
      break;;
    *)
      warn "token_endpoint_auth=$AUTH_METHOD refused ($CODE): $(printf '%s' "$OUT" | sed '$d' | head -c 200)";;
  esac
done
[ -n "$IDP_ID" ] || bad "no token_endpoint_auth method was accepted for this issuer (see $EV/p4-create-idp.txt — this IS the conformance verdict)"

say "P5 activate"
if [ -n "$IDP_ID" ]; then
  CODE=$(curl -s -o "$EV/p5-activate.txt" -w '%{http_code}' -X POST -H "$A" "$API/v1/admin/orgs/$SLUG/idp/$IDP_ID/activate")
  case "$CODE" in 200|204) pass "IdP activated ($CODE)";; *) bad "activate → $CODE";; esac
else
  bad "no IdP id captured — skipping activation"
fi

say "P6 login start — nonce + PKCE S256 + state + browser-bound cookie"
curl -s -D "$EV/p6-start-headers.txt" -o /dev/null "$API/v1/auth/login/$SLUG/start" -c "$WORK/cookies.txt"
AUTHZ=$(grep -i '^location:' "$EV/p6-start-headers.txt" | tail -1 | sed 's/^[Ll]ocation: *//' | tr -d '\r')
printf '%s\n' "$AUTHZ" > "$EV/p6-authorize-url.txt"
if [ -n "$AUTHZ" ]; then
  pass "authorize redirect issued"
  for q in "nonce=" "code_challenge=" "code_challenge_method=S256" "state=" "response_type=code" "client_id=$IDP_CLIENT_ID"; do
    case "$AUTHZ" in *"$q"*) pass "authorize URL carries $q";; *) bad "authorize URL MISSING $q";; esac
  done
  grep -qi "set-cookie: *__Host-fbx_login" "$EV/p6-start-headers.txt" \
    && pass "browser-bound one-time login cookie set (__Host-fbx_login_*)" \
    || bad "no __Host-fbx_login cookie on the start response"
else
  bad "no Location header from login start (see $EV/p6-start-headers.txt)"
fi

say "P7 does the IdP accept that authorize request?"
if [ -n "$AUTHZ" ]; then
  curl -s -D "$EV/p7-idp-response-headers.txt" -o "$EV/p7-idp-body.html" --max-time 20 "$AUTHZ"
  IDP_CODE=$(head -1 "$EV/p7-idp-response-headers.txt" | awk '{print $2}')
  IDP_LOC=$(grep -i '^location:' "$EV/p7-idp-response-headers.txt" | tail -1 | tr -d '\r')
  echo "  IdP status: $IDP_CODE"; [ -n "$IDP_LOC" ] && echo "  $IDP_LOC"
  case "$IDP_CODE" in
    200|302|303) grep -qi "error\|invalid" "$EV/p7-idp-body.html" 2>/dev/null \
        && bad "IdP returned $IDP_CODE but the body mentions an error — READ $EV/p7-idp-body.html" \
        || pass "IdP accepted the authorize request ($IDP_CODE) — human completes consent";;
    *) bad "IdP rejected the authorize request ($IDP_CODE) — see $EV/p7-idp-*";;
  esac
fi

say "verdict"
echo "  PASS=$PASS FAIL=$FAILN   evidence: $EV/"
echo "  NOTE: the token-exchange leg needs the REAL client secret; re-run with"
echo "        IDP_CLIENT_SECRET=… and complete the consent in a browser to prove it end to end."
[ "$FAILN" -eq 0 ] || exit 1
