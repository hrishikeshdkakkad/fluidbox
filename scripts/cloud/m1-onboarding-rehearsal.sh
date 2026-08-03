#!/usr/bin/env bash
# Substrate-independent half of the M1.2 gate + §9 criterion 11, rehearsed
# LOCALLY against a real REQUIRE_SSO core on a throwaway database.
#
# M1.2 asks for two things. One is AWS/Vercel-specific (a browser login through
# the Vercel origin) and needs the deployment. The other is the OPERATOR
# PROCEDURE — can another operator follow docs/hosted/cloud-onboarding-checklist.md
# and get a correctly isolated tenant? That half is provable here, and it is the
# half most likely to contain a mistake.
#
# Proven:
#   R1  checklist §B — org create through the admin API, twice (two beta orgs)
#   R2  checklist §C — per-org IdP config create + activate, live discovery
#   R3  admin-token confinement (the M1.2 flip's whole point)
#   R4  §9-11 CROSS-TENANT DENIAL at the ENFORCED FLOOR — RLS with the
#       non-owner runtime role: org A's GUC sees only org A's rows, org B's
#       only B's, and a GUC-less connection sees NOTHING
#   R5  a bad slug is refused (the checklist's "a 400 means the slug" note)
#
# No AWS, no Vercel, no model calls, no live Neon.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

PORT="${REHEARSAL_PORT:-8792}"
INTERNAL_PORT="${REHEARSAL_INTERNAL_PORT:-8793}"
DB="${REHEARSAL_DB:-fluidbox_m1onboard}"
PGHOST=127.0.0.1; PGPORT=5433; PGUSER=fluidbox; export PGPASSWORD=fluidbox
DB_URL="postgres://fluidbox:fluidbox@$PGHOST:$PGPORT/$DB"
API="http://127.0.0.1:$PORT"
BIN="${PROOF_SERVER_BIN:-target/debug/fluidbox-server}"
IDP_ISSUER="${IDP_ISSUER:-https://api.workos.com/user_management/client_01KGA8ECKMDH8GWPZR00QGPTBZ}"
WORK="${SCRATCH:-/tmp/fluidbox-m1onboard}"
EV=$(evidence_dir cloud-m1-readiness)
mkdir -p "$WORK/data"

PASS=0; FAILN=0
pass() { ok "$1"; PASS=$((PASS+1)); }
bad()  { fail "$1"; FAILN=$((FAILN+1)); }
psql_q() { psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$DB" -tAc "$1" 2>/dev/null; }
cleanup() { [ -f "$WORK/server.pid" ] && kill "$(cat "$WORK/server.pid")" 2>/dev/null; return 0; }
trap cleanup EXIT

[ -x "$BIN" ] || die "server binary not found at $BIN" "cargo build -p fluidbox-server"
[ "$DB" = "fluidbox" ] && die "refusing to run against the DEV database"

say "0. throwaway database (never the dev one)"
psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAc \
  "SELECT 1 FROM pg_database WHERE datname='$DB'" | grep -q 1 \
  || psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -qc "CREATE DATABASE $DB" >/dev/null
pass "database $DB ready"

say "1. boot core in the M1.2 posture (REQUIRE_SSO=1 + RLS runtime role)"
ADMIN="fbx_admin_$(openssl rand -hex 16)"
ABS_BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
# `exec` + the & OUTSIDE the parens so $! is the SERVER's pid, not the
# subshell's — otherwise cleanup kills a wrapper and leaves the server holding
# the port for whatever runs next.
( cd "$WORK" && exec env -i PATH="$PATH" HOME="$HOME" \
  DATABASE_URL="$DB_URL" FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime FLUIDBOX_REQUIRE_SSO=1 \
  FLUIDBOX_ADMIN_TOKEN="$ADMIN" FLUIDBOX_CREDENTIAL_KEY="$(openssl rand -hex 32)" \
  FLUIDBOX_BIND="127.0.0.1:$PORT" FLUIDBOX_INTERNAL_BIND="127.0.0.1:$INTERNAL_PORT" \
  FLUIDBOX_PUBLIC_URL="$API" FLUIDBOX_DATA_DIR="$WORK/data" \
  LITELLM_MASTER_KEY=rehearsal-no-model-calls LLM_UPSTREAM_URL="http://127.0.0.1:4999" \
  "$ABS_BIN" ) > "$WORK/server.log" 2>&1 &
echo $! > "$WORK/server.pid"
for _ in $(seq 1 60); do curl -fsS --max-time 2 "$API/v1/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS --max-time 2 "$API/v1/health" >/dev/null 2>&1 \
  || { tail -20 "$WORK/server.log"; die "core did not boot" "$WORK/server.log"; }
grep -q "row-level security is ENFORCED" "$WORK/server.log" \
  && pass "booted; RLS ENFORCED under the non-owner runtime role" \
  || bad "RLS not reported as enforced — the isolation floor is NOT active"

A="authorization: Bearer $ADMIN"

say "2. R5 — the checklist's slug rule is enforced"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$A" -H 'content-type: application/json' \
  -d '{"slug":"Not A Valid Slug!","display_name":"bad"}' "$API/v1/admin/orgs")
[ "$CODE" = "400" ] && pass "invalid slug refused (400) — matches the checklist note" \
                    || bad "invalid slug returned $CODE, expected 400"

say "3. R1 — checklist §B: provision two beta orgs"
for slug in acmebeta globexbeta; do
  CODE=$(curl -s -o "$WORK/org-$slug.json" -w '%{http_code}' -X POST -H "$A" -H 'content-type: application/json' \
    -d "{\"slug\":\"$slug\",\"display_name\":\"${slug} Inc\"}" "$API/v1/admin/orgs")
  case "$CODE" in 200|201) pass "org '$slug' created";; *) bad "org '$slug' create → $CODE";; esac
done
curl -sS -H "$A" "$API/v1/admin/orgs" > "$EV/onboarding-orgs.json"

say "4. R2 — checklist §C: per-org IdP config + activate (live discovery each time)"
for slug in acmebeta globexbeta; do
  OUT=$(curl -s -w '\n%{http_code}' -X POST -H "$A" -H 'content-type: application/json' -d "$(python3 - "$IDP_ISSUER" "$slug" <<'PY'
import json, sys
print(json.dumps({"issuer": sys.argv[1], "client_id": f"client_rehearsal_{sys.argv[2]}",
                  "client_secret": "rehearsal-secret", "token_endpoint_auth": "client_secret_basic",
                  "bootstrap_owner_email": f"owner@{sys.argv[2]}.example"}))
PY
)" "$API/v1/admin/orgs/$slug/idp")
  CODE=$(printf '%s' "$OUT" | tail -1)
  ID=$(printf '%s' "$OUT" | sed '$d' | python3 -c "import sys,json;print((json.load(sys.stdin).get('idp') or {}).get('id',''))" 2>/dev/null)
  if [ "$CODE" = "200" ] && [ -n "$ID" ]; then
    ACODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$A" "$API/v1/admin/orgs/$slug/idp/$ID/activate")
    case "$ACODE" in 200|204) pass "$slug: IdP configured + activated (owner armed)";; *) bad "$slug: activate → $ACODE";; esac
  else
    bad "$slug: IdP create → $CODE"
  fi
done

say "5. R3 — admin-token confinement (what the M1.2 flip buys)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$A" "$API/v1/sessions")
[ "$CODE" = "401" ] && pass "admin token refused on /v1/sessions (401)" || bad "/v1/sessions → $CODE, expected 401"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$A" "$API/v1/admin/orgs")
[ "$CODE" = "200" ] && pass "admin token accepted on /v1/admin/* (200)" || bad "/v1/admin/orgs → $CODE"

say "6. R4 — §9-11 CROSS-TENANT DENIAL at the enforced RLS floor"
# Each org is a tenant row. Query a tenant-owned table AS the runtime role with
# the tenant GUC set — exactly how every pooled connection runs.
TA=$(psql_q "SELECT id FROM tenants WHERE slug='acmebeta'")
TB=$(psql_q "SELECT id FROM tenants WHERE slug='globexbeta'")
if [ -z "$TA" ] || [ -z "$TB" ]; then
  bad "could not resolve both tenant ids ($TA / $TB)"
else
  ok "tenant A=$TA  tenant B=$TB"
  # org_idp_configs is tenant-owned and now has exactly one row per org.
  SEES_A=$(psql_q "SET ROLE fluidbox_runtime; SET LOCAL fluidbox.tenant_id='$TA'; SELECT count(*) FROM org_idp_configs;")
  SEES_B=$(psql_q "SET ROLE fluidbox_runtime; SET LOCAL fluidbox.tenant_id='$TB'; SELECT count(*) FROM org_idp_configs;")
  SEES_NONE=$(psql_q "SET ROLE fluidbox_runtime; SELECT count(*) FROM org_idp_configs;")
  TOTAL=$(psql_q "SELECT count(*) FROM org_idp_configs;")
  A_OF_B=$(psql_q "SET ROLE fluidbox_runtime; SET LOCAL fluidbox.tenant_id='$TA'; SELECT count(*) FROM org_idp_configs WHERE tenant_id='$TB';")
  {
    echo "# §9-11 cross-tenant denial at the RLS floor — $(date -u +%FT%TZ)"
    echo "owner sees (no RLS, superuser): $TOTAL rows"
    echo "runtime role + GUC=A:           $SEES_A"
    echo "runtime role + GUC=B:           $SEES_B"
    echo "runtime role, NO GUC:           $SEES_NONE"
    echo "runtime role + GUC=A, explicitly selecting B's tenant_id: $A_OF_B"
  } > "$EV/cross-tenant-rls.txt"
  [ "$TOTAL" = "2" ] && pass "two tenant-owned rows exist in total (owner view)" || warn "unexpected total: $TOTAL"
  [ "$SEES_A" = "1" ] && pass "GUC=A sees exactly its own row" || bad "GUC=A saw $SEES_A rows"
  [ "$SEES_B" = "1" ] && pass "GUC=B sees exactly its own row" || bad "GUC=B saw $SEES_B rows"
  [ "$SEES_NONE" = "0" ] && pass "no tenant GUC ⇒ ZERO rows (fails closed)" || bad "GUC-less connection saw $SEES_NONE rows"
  [ "$A_OF_B" = "0" ] \
    && pass "tenant A explicitly asking for tenant B's rows gets NOTHING — cross-tenant read is impossible at the database" \
    || bad "tenant A read $A_OF_B of tenant B's rows — ISOLATION BREACH"
fi

say "verdict"
echo "  PASS=$PASS FAIL=$FAILN   evidence: $EV/"
[ "$FAILN" -eq 0 ] \
  && ok "the onboarding procedure is executable and tenant isolation holds at the enforced floor" \
  || fail "see the ✗ lines above"
exit $((FAILN > 0))
