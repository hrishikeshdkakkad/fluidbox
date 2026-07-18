#!/usr/bin/env bash
# Identity acceptance E2E — the IdP-agnostic OIDC login surface driven against a
# REAL conformant issuer (Dex in a container) over real HTTP, plus the flow-level
# negative matrix. This owns its stack: it boots Dex + the fluidbox control plane
# and drives everything with curl cookie jars (a jar == a browser).
#
# Design: docs/plans/2026-07-17-idp-agnostic-identity-design.md (login flow
# 470-582, acceptance 936-948) + parent 2026-07-14 Phase B acceptance (1456-1474).
# House style mirrors scripts/governance-e2e.sh: pass/fail counters, section
# banners, curl helpers, a cleanup trap.
#
# Scope note: this proves the FLOW-level cases (round-trip, replay, wrong-browser,
# expired, switch, deactivation, issuer migration, REQUIRE_SSO, no-IdP). The
# token-crafting negatives (HS256/none/azp/at_hash/kid-less-JWKS) are already
# UNIT-tested in login.rs (`mod tests`) and are deliberately NOT duplicated here.
#
# `set -e` is intentionally OMITTED (matching governance-e2e.sh): this script
# expects a great many non-2xx responses, and aborting on the first would defeat
# the negative matrix. Failures are counted explicitly; a nonzero exit follows a
# nonzero `fail`.
# File-wide suppressions (must precede the first command to apply file-wide):
#  SC2015: `[ test ] && ok … || no …` is the house idiom (governance-e2e.sh);
#          `ok`/`no` always return 0, so `|| no` never fires on a passing test.
#  SC2030/SC2031: DATABASE_URL is exported ONLY inside the server subshell; the
#          top-level `db()` reads the unmodified outer value — false positive.
# shellcheck disable=SC2015,SC2030,SC2031
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)

# ── Preconditions ────────────────────────────────────────────────────────────
# DATABASE_URL is REQUIRED — refuse loudly rather than self-skip (unlike the DB
# unit tests). CI provides the Postgres service; a bare Neon/local URL works too.
if [ -z "${DATABASE_URL:-}" ]; then
  echo "identity-e2e: DATABASE_URL is required (CI provides the Postgres service)." >&2
  echo "  This script drives real cookies + a real issuer against a real DB;" >&2
  echo "  it will not run — and must never silently skip — without one." >&2
  exit 2
fi
command -v docker >/dev/null 2>&1 || { echo "identity-e2e: docker is required (for Dex)." >&2; exit 2; }
command -v curl   >/dev/null 2>&1 || { echo "identity-e2e: curl is required." >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "identity-e2e: python3 is required (JSON + URL joins)." >&2; exit 2; }
HAVE_PSQL=0; command -v psql >/dev/null 2>&1 && HAVE_PSQL=1

# ── Config ───────────────────────────────────────────────────────────────────
API=http://127.0.0.1:8787
ISSUER=http://127.0.0.1:5556/dex
# Pinned by the multi-arch INDEX digest (tag kept for readability; the @sha256
# is what Docker resolves). Re-pin with:
#   docker buildx imagetools inspect ghcr.io/dexidp/dex:<tag>   # → Digest:
# Dex's staticPasswords set email_verified=true by default, which the gate needs.
DEX_IMAGE=${DEX_IMAGE:-ghcr.io/dexidp/dex:v2.45.0@sha256:b8469881d3cb3a73001506f0d3aaefecb9c45d2311c1e0f405d8ac538316c59d}
SLUG=acme
SLUG2=beta          # a real org with NO IdP config (fail-closed browser path)
SLUG3=gamma-never   # never created (enumeration-parity comparison)
PW=password         # matches the embedded bcrypt hash below (non-secret test creds)
U1=alice@acme.test
U2=bob@acme.test
U3=carol@acme.test

ADMIN_TOKEN=$(openssl rand -hex 32)
CRED_KEY=$(openssl rand -hex 32)
CLIENT1_SECRET=$(openssl rand -hex 16)
CLIENT2_SECRET=$(openssl rand -hex 16)
CLIENT1_ID=fluidbox-acme
CLIENT2_ID=fluidbox-acme-2

WORK=$(mktemp -d)
DEX_NAME="fbx-dex-e2e-$$"
SERVER_LOG="$WORK/server.log"
SERVER_PID=""
DATA_DIR="$WORK/data"; mkdir -p "$DATA_DIR"

pass=0; fail=0
ok()  { printf "  \033[1;32m✓\033[0m %s\n" "$1"; pass=$((pass+1)); }
no()  { printf "  \033[1;31m✗\033[0m %s\n" "$1"; fail=$((fail+1)); }
skip(){ printf "  \033[1;33m∼\033[0m %s\n" "$1"; }
say() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }
urlenc() { python3 -c "import sys,urllib.parse as u;print(u.quote(sys.argv[1],safe=''))" "$1"; }
urljoin() { python3 -c "import sys,urllib.parse as u;print(u.urljoin(sys.argv[1],sys.argv[2]))" "$1" "$2"; }

# ── Cleanup ──────────────────────────────────────────────────────────────────
# shellcheck disable=SC2329  # invoked via the EXIT/INT/TERM trap
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  docker rm -f "$DEX_NAME" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ── Dex ──────────────────────────────────────────────────────────────────────
# Two static clients on ONE Dex so the issuer-migration section can swap to a
# second client id without a second issuer. Three static users: alice (bootstrap
# owner), bob (member, switch + deactivation), carol (member, REQUIRE_SSO cookie
# proof). All share the embedded bcrypt hash of "password" (verified locally with
# htpasswd; Dex accepts $2y$). skipApprovalScreen removes the consent form so the
# curl driver never has to POST an approval.
start_dex() {
  cat > "$WORK/dex.yaml" <<YAML
issuer: $ISSUER
storage:
  type: memory
web:
  http: 0.0.0.0:5556
oauth2:
  skipApprovalScreen: true
enablePasswordDB: true
staticClients:
  - id: $CLIENT1_ID
    name: fluidbox acme
    secret: $CLIENT1_SECRET
    redirectURIs:
      - $API/v1/auth/callback
  - id: $CLIENT2_ID
    name: fluidbox acme 2
    secret: $CLIENT2_SECRET
    redirectURIs:
      - $API/v1/auth/callback
staticPasswords:
  - email: $U1
    hash: "\$2y\$10\$KpzrbYoCGuADz8/.HvAWquPKsITtUSs5TcVTnFIA0F01q43rphRx2"
    username: alice
    userID: "aaaaaaaa-0000-0000-0000-000000000001"
  - email: $U2
    hash: "\$2y\$10\$KpzrbYoCGuADz8/.HvAWquPKsITtUSs5TcVTnFIA0F01q43rphRx2"
    username: bob
    userID: "bbbbbbbb-0000-0000-0000-000000000002"
  - email: $U3
    hash: "\$2y\$10\$KpzrbYoCGuADz8/.HvAWquPKsITtUSs5TcVTnFIA0F01q43rphRx2"
    username: carol
    userID: "cccccccc-0000-0000-0000-000000000003"
YAML
  docker rm -f "$DEX_NAME" >/dev/null 2>&1
  docker run -d --name "$DEX_NAME" \
    -p 127.0.0.1:5556:5556 \
    -v "$WORK/dex.yaml:/etc/dex/config.yaml:ro" \
    --entrypoint dex "$DEX_IMAGE" serve /etc/dex/config.yaml >/dev/null || {
      echo "identity-e2e: failed to start Dex container" >&2; exit 1; }
  # Wait for discovery to serve.
  for _ in $(seq 1 60); do
    if curl -sf "$ISSUER/.well-known/openid-configuration" >/dev/null 2>&1; then
      ok "Dex up ($DEX_IMAGE) — discovery serving at $ISSUER"; return 0
    fi
    sleep 1
  done
  echo "identity-e2e: Dex did not become ready" >&2
  docker logs "$DEX_NAME" 2>&1 | tail -30 >&2
  exit 1
}

# ── Server ───────────────────────────────────────────────────────────────────
# FLUIDBOX_SERVER_BIN lets CI reuse a prebuilt binary (recommended: `exec` then
# makes $SERVER_PID the server itself, so the trap kills it cleanly); otherwise
# `cargo run` (a fallback — cargo's child may outlive a kill, so CI passes the
# binary). SESSION_REAUTH_SECS=2 keeps the SSE re-auth loop tight enough to see.
start_server() {
  local require_sso=$1
  : > "$SERVER_LOG"
  (
    cd "$ROOT" || exit 1
    export DATABASE_URL="$DATABASE_URL"
    export FLUIDBOX_BIND=127.0.0.1:8787
    export FLUIDBOX_PUBLIC_URL=http://127.0.0.1:8787
    export FLUIDBOX_ADMIN_TOKEN="$ADMIN_TOKEN"
    export FLUIDBOX_CREDENTIAL_KEY="$CRED_KEY"
    export FLUIDBOX_PROVIDER=docker
    export FLUIDBOX_DATA_DIR="$DATA_DIR"
    export FLUIDBOX_SESSION_REAUTH_SECS=2
    # This run declares a trusted proxy so the per-call spoofed X-Forwarded-For
    # (see xff()) is honored for the rate-limit buckets; without it the socket
    # peer is authoritative and every curl would share one bucket and trip.
    export FLUIDBOX_TRUST_FORWARDED_FOR=1
    export FLUIDBOX_REQUIRE_SSO="$require_sso"
    export RUST_LOG="${RUST_LOG:-warn,fluidbox_server=info}"
    if [ -n "${FLUIDBOX_SERVER_BIN:-}" ] && [ -x "${FLUIDBOX_SERVER_BIN}" ]; then
      exec "$FLUIDBOX_SERVER_BIN"
    fi
    exec cargo run -q -p fluidbox-server
  ) >>"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 180); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "identity-e2e: server process exited during boot" >&2
      tail -40 "$SERVER_LOG" >&2; exit 1
    fi
    if curl -sf "$API/v1/health" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "identity-e2e: server did not become ready" >&2
  tail -40 "$SERVER_LOG" >&2
  exit 1
}
stop_server() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  for _ in $(seq 1 30); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.3; done
  SERVER_PID=""
}

# ── HTTP helpers ─────────────────────────────────────────────────────────────
AH="authorization: Bearer $ADMIN_TOKEN"
# admin_* return the http code in $CODE and the body in $BODY.
BODY=""; CODE=""
admin_post() { BODY=$(curl -s -o "$WORK/b" -w '%{http_code}' -X POST -H "$AH" -H 'content-type: application/json' -d "$2" "$API$1"); CODE=$BODY; BODY=$(cat "$WORK/b"); }
admin_get()  { BODY=$(curl -s -o "$WORK/b" -w '%{http_code}' -H "$AH" "$API$1"); CODE=$BODY; BODY=$(cat "$WORK/b"); }

# The __Host-fbx_switch_<id> cookie's id, parsed from a header dump.
switch_id_from_headers() { # header_file
  grep -io '__Host-fbx_switch_[0-9a-f]\{32\}' "$1" | head -1 | sed 's/__Host-fbx_switch_//'
}
# The Location header from a dump.
location_from_headers() { grep -i '^location:' "$1" | head -1 | sed -E 's/^[Ll]ocation: *//' | tr -d '\r'; }

# Write a fresh cookie jar carrying ONLY the __Host-fbx_web cookie copied from
# `src` — strips the issuer's session cookie so the next login prompts fresh
# (used to drive a DIFFERENT Dex user in a browser that already holds a session).
web_only_jar() { # src_jar dst_jar
  printf '# Netscape HTTP Cookie File\n' > "$2"
  grep -E '__Host-fbx_web[[:space:]]' "$1" >> "$2" 2>/dev/null || true
}

# ── OIDC driving ─────────────────────────────────────────────────────────────
# The login start + callback are per-IP rate limited (10/min). curl sends no
# X-Forwarded-For, so without this every request would share one "unknown"
# bucket and trip after ~10 logins. The rate limiter is NOT under test here (the
# design trusts XFF behind its proxy), so we spread requests across buckets with
# a fresh spoofed IP per call. The per-ORG cap (30/min) is unaffected and this
# run stays well under it.
xff() { printf 'x-forwarded-for: 203.0.%d.%d' $((RANDOM % 256)) $(((RANDOM % 254) + 1)); }

# fbx_start: hit /start, store the login cookie in `jar`, echo the 302 Location
# (the issuer's authorization URL) — empty if start did not 302 (fail-closed).
fbx_start() { # jar slug [redirect_to]
  local jar=$1 slug=$2 rt=${3:-/}
  curl -s -c "$jar" -b "$jar" -H "$(xff)" -D "$WORK/h.start" -o /dev/null \
    "$API/v1/auth/login/$slug/start?redirect_to=$(urlenc "$rt")"
  location_from_headers "$WORK/h.start"
}

# dex_login: drive Dex's password form for (email,pw) in `jar`, following the
# issuer-side redirect chain, and echo the fluidbox callback URL (code+state)
# WITHOUT completing it — so the caller can replay/expire/complete it at will.
dex_login() { # jar authorize_url email pw
  local jar=$1 authz=$2 email=$3 pw=$4
  # GET the authorize URL, following redirects to the rendered login form.
  local raw eff page
  raw=$(curl -s -c "$jar" -b "$jar" -L -w '@@EFF@@%{url_effective}' "$authz")
  eff=${raw##*@@EFF@@}; page=${raw%@@EFF@@*}
  # Extract the form action; decode the HTML-escaped '&' the template emits.
  local action
  action=$(printf '%s' "$page" | grep -oiE 'action="[^"]*"' | head -1 \
    | sed -E 's/[Aa]ction="([^"]*)"/\1/' | sed 's/&amp;/\&/g')
  if [ -z "$action" ]; then echo "DEX_NO_FORM"; return 1; fi
  local post_url; post_url=$(urljoin "$eff" "$action")
  # POST the credentials; capture the redirect (no -L so we can inspect it).
  curl -s -c "$jar" -b "$jar" -D "$WORK/h.post" -o /dev/null \
    --data-urlencode "login=$email" --data-urlencode "password=$pw" "$post_url"
  local loc; loc=$(location_from_headers "$WORK/h.post")
  if [ -z "$loc" ]; then echo "DEX_LOGIN_FAILED"; return 1; fi
  # Follow issuer-side hops until a Location resolves to the fluidbox callback;
  # return that URL (do NOT fetch it — that is the caller's choice).
  local cur=$post_url hops=0 abs
  while [ -n "$loc" ] && [ "$hops" -lt 8 ]; do
    abs=$(urljoin "$cur" "$loc")
    case "$abs" in
      "$API"/v1/auth/callback*) echo "$abs"; return 0;;
    esac
    curl -s -c "$jar" -b "$jar" -D "$WORK/h.hop" -o /dev/null "$abs"
    cur=$abs
    loc=$(location_from_headers "$WORK/h.hop")
    hops=$((hops+1))
  done
  echo "DEX_NO_CALLBACK"; return 1
}

# complete_cb: GET the callback URL in `jar`, dump headers to $WORK/h.cb, echo
# the http code. On success it sets __Host-fbx_web (302 → redirect_to); a refusal
# is a 400 page; a pending switch is a 200 page that sets __Host-fbx_switch_<id>.
complete_cb() { # jar callback_url
  curl -s -c "$1" -b "$1" -H "$(xff)" -D "$WORK/h.cb" -o "$WORK/cb.body" -w '%{http_code}' "$2"
}

# login: full round-trip in a FRESH jar; echoes "CODE<TAB>callback_url".
login() { # jar email pw slug [redirect_to]
  : > "$1"
  local authz cb code
  authz=$(fbx_start "$1" "$4" "${5:-/}")
  if [ -z "$authz" ]; then echo "NOSTART"; return 1; fi
  cb=$(dex_login "$1" "$authz" "$2" "$3") || { echo "$cb"; return 1; }
  code=$(complete_cb "$1" "$cb")
  printf '%s\t%s\n' "$code" "$cb"
}

# me: echo a compact "slug|email|roles|auth_kind" for a jar's session.
me_line() { # jar
  curl -s -b "$1" "$API/v1/auth/me" | python3 -c "
import sys,json
try: d=json.load(sys.stdin)
except Exception: print('ERR'); sys.exit()
if d.get('operator'): print('operator'); sys.exit()
o=d.get('org') or {}; u=d.get('user') or {}
print('%s|%s|%s|%s' % (o.get('slug'), u.get('email'), ','.join(d.get('roles') or []), d.get('auth_kind')))
"
}

# psql shortcut (only when psql is present). stderr is left to flow to the log
# (not swallowed): db() is always used in `$(…)`, so psql errors reach the
# terminal/log without polluting the captured stdout — and a healthy run is silent.
db() { psql "$DATABASE_URL" -tAX -c "$1"; }

# ═════════════════════════════════════════════════════════════════════════════
say "BOOT — Dex + control plane"
start_dex
start_server ""   # REQUIRE_SSO unset for the whole first phase
ok "control plane up (REQUIRE_SSO unset)"

# ── (a) Bootstrap: org + IdP config + activate, bootstrap owner armed ─────────
say "(a) Operator bootstrap — org, IdP config, activation"
admin_post "/v1/admin/orgs" "{\"slug\":\"$SLUG\",\"display_name\":\"Acme\"}"
[ "$CODE" = 200 ] && ok "org '$SLUG' created" || no "create org → $CODE: $BODY"

CFG_BODY=$(cat <<JSON
{"issuer":"$ISSUER","client_id":"$CLIENT1_ID","client_secret":"$CLIENT1_SECRET",
 "token_endpoint_auth":"client_secret_basic","bootstrap_owner_email":"$U1"}
JSON
)
admin_post "/v1/admin/orgs/$SLUG/idp" "$CFG_BODY"
[ "$CODE" = 200 ] && ok "IdP config staged (discovery validated against live Dex)" || no "create idp → $CODE: $BODY"
CFG1=$(echo "$BODY" | j "['idp']['id']")
[ -n "$CFG1" ] && ok "config id captured ($CFG1)" || no "no config id in $BODY"

admin_post "/v1/admin/orgs/$SLUG/idp/$CFG1/activate" '{}'
[ "$CODE" = 200 ] && ok "IdP config activated" || no "activate → $CODE: $BODY"

# ── (b) Full OIDC round-trip — first login wins bootstrap owner ───────────────
say "(b) OIDC round-trip — alice logs in, wins bootstrap owner"
jarA="$WORK/jarA"
RES=$(login "$jarA" "$U1" "$PW" "$SLUG"); C=$(printf '%s' "$RES" | cut -f1)
[ "$C" = 302 ] && ok "callback set the session (302 → redirect_to)" || no "round-trip code $C (want 302); server log:\n$(tail -5 "$SERVER_LOG")"
WEBVAL=$(grep -oE '__Host-fbx_web[[:space:]]+[^[:space:]]+' "$jarA" | awk '{print $2}')
[ -n "$WEBVAL" ] && ok "__Host-fbx_web cookie captured" || no "no web cookie in jar"
ML=$(me_line "$jarA")
echo "  /me → $ML"
case "$ML" in
  "$SLUG|$U1|"*owner*"|browser") ok "/me: org=$SLUG, email=$U1, roles include owner, auth=browser";;
  *) no "/me unexpected: $ML";;
esac
AGCODE=$(curl -s -o /dev/null -w '%{http_code}' -b "$jarA" "$API/v1/agents")
[ "$AGCODE" = 200 ] && ok "GET /v1/agents with the session cookie → 200" || no "agents with cookie → $AGCODE"

# ── (c) Arming refused while an active owner exists ───────────────────────────
say "(c) Break-glass arming refused while an owner is active"
admin_post "/v1/admin/orgs/$SLUG/break-glass-owner" "{\"email\":\"$U1\"}"
[ "$CODE" = 409 ] && ok "break-glass-owner while owner active → 409" || no "want 409, got $CODE: $BODY"

# ── (d) Replay / wrong-browser / expired ──────────────────────────────────────
say "(d) Negative flows — replay, wrong-browser, expired"
# Replay: complete once, then GET the identical callback URL again.
jarRP="$WORK/jarRP"; : > "$jarRP"
authz=$(fbx_start "$jarRP" "$SLUG"); cbRP=$(dex_login "$jarRP" "$authz" "$U1" "$PW")
c1=$(complete_cb "$jarRP" "$cbRP")
[ "$c1" = 302 ] && ok "fresh flow completes (302)" || no "fresh flow → $c1"
c2=$(complete_cb "$jarRP" "$cbRP")
[ "$c2" = 400 ] && ok "replay of the exact callback (same code+state+jar) → 400 (flow burned)" || no "replay → $c2 (want 400)"

# Wrong-browser: a fresh flow's callback hit WITHOUT the login cookie is refused
# AND does not burn the flow (transaction A never runs); the right jar then wins.
jarWB="$WORK/jarWB"; : > "$jarWB"
authz=$(fbx_start "$jarWB" "$SLUG"); cbWB=$(dex_login "$jarWB" "$authz" "$U1" "$PW")
jarEmpty="$WORK/jarEmpty"; : > "$jarEmpty"
cWrong=$(complete_cb "$jarEmpty" "$cbWB")
[ "$cWrong" = 400 ] && ok "wrong-browser callback (no login cookie) → 400" || no "wrong-browser → $cWrong (want 400)"
cRight=$(complete_cb "$jarWB" "$cbWB")
[ "$cRight" = 302 ] && ok "…and the flow was NOT burned — the right browser still completes (302)" || no "right-browser after wrong attempt → $cRight (want 302)"

# Expired: age the flow's expires_at via psql, then the callback is refused.
if [ "$HAVE_PSQL" = 1 ]; then
  jarEX="$WORK/jarEX"; : > "$jarEX"
  authz=$(fbx_start "$jarEX" "$SLUG"); cbEX=$(dex_login "$jarEX" "$authz" "$U1" "$PW")
  TID=$(db "select id from tenants where slug='$SLUG'")
  db "update login_flows set expires_at = now() - interval '1 minute'
      where id = (select id from login_flows
                  where tenant_id='$TID' and consumed_at is null
                  order by created_at desc limit 1)" >/dev/null
  cEX=$(complete_cb "$jarEX" "$cbEX")
  [ "$cEX" = 400 ] && ok "expired flow (expires_at aged via psql) → 400" || no "expired flow → $cEX (want 400)"
else
  skip "expired-flow case: psql unavailable (expiry is covered by the login-flow claim predicate; unit + DB-layer)"
fi

# ── (e) Dual credential ───────────────────────────────────────────────────────
say "(e) Dual credential — cookie + bearer on one request"
DUAL=$(curl -s -o /dev/null -w '%{http_code}' -b "$jarA" -H "$AH" "$API/v1/agents")
[ "$DUAL" = 400 ] && ok "cookie + Authorization bearer together → 400 (never resolved by precedence)" || no "dual credential → $DUAL (want 400)"

# ── (f) CSRF ──────────────────────────────────────────────────────────────────
say "(f) CSRF — a cookie-authenticated write needs the custom header"
NOCSRF=$(curl -s -o /dev/null -w '%{http_code}' -X POST -b "$jarA" -H 'content-type: application/json' \
  -d '{"name":"csrf-probe","expires_in":3600}' "$API/v1/auth/tokens")
[ "$NOCSRF" = 403 ] && ok "cookie POST WITHOUT x-fluidbox-csrf → 403" || no "no-CSRF write → $NOCSRF (want 403)"
WITHCSRF=$(curl -s -o "$WORK/pat.json" -w '%{http_code}' -X POST -b "$jarA" \
  -H 'content-type: application/json' -H 'x-fluidbox-csrf: 1' \
  -d '{"name":"csrf-probe","expires_in":3600}' "$API/v1/auth/tokens")
[ "$WITHCSRF" = 200 ] && ok "cookie POST WITH x-fluidbox-csrf → 200" || no "CSRF write → $WITHCSRF (want 200)"

# ── (g) PAT lifecycle ─────────────────────────────────────────────────────────
say "(g) Personal access tokens — mint, use, no-self-mint, revoke"
PAT=$(j "['token']" < "$WORK/pat.json")
[ -n "$PAT" ] && case "$PAT" in fbx_pat_*) ok "PAT minted via the browser session ($PAT prefix)";; *) no "unexpected PAT: $PAT";; esac
PATID=$(python3 -c "import sys,json;print(json.load(open('$WORK/pat.json'))['pat']['id'])" 2>/dev/null)
USEPAT=$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $PAT" "$API/v1/agents")
[ "$USEPAT" = 200 ] && ok "GET /v1/agents with the PAT bearer → 200" || no "PAT use → $USEPAT (want 200)"
PATMINT=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "authorization: Bearer $PAT" \
  -H 'content-type: application/json' -d '{"name":"child"}' "$API/v1/auth/tokens")
[ "$PATMINT" = 403 ] && ok "a PAT minting a PAT → 403 (no self-replication)" || no "PAT-mints-PAT → $PATMINT (want 403)"
DELPAT=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -b "$jarA" -H 'x-fluidbox-csrf: 1' "$API/v1/auth/tokens/$PATID")
[ "$DELPAT" = 200 ] && ok "DELETE the PAT via the browser session → 200" || no "delete PAT → $DELPAT (want 200)"
AFTERDEL=$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $PAT" "$API/v1/agents")
[ "$AFTERDEL" = 401 ] && ok "the revoked PAT no longer authenticates → 401" || no "revoked PAT → $AFTERDEL (want 401)"

# ── (h) Second user + forced-login switch ─────────────────────────────────────
say "(h) Forced-login switch — never silent, confirmed by POST"
# Drive bob's login in a browser that already holds alice's session. The jar is
# seeded with ONLY alice's web cookie (no Dex session), so Dex prompts fresh and
# returns bob — the callback then sees a different user and stages a switch.
jarSW="$WORK/jarSW"; web_only_jar "$jarA" "$jarSW"
authz=$(fbx_start "$jarSW" "$SLUG")
cbSW=$(dex_login "$jarSW" "$authz" "$U2" "$PW")
codeSW=$(complete_cb "$jarSW" "$cbSW")
[ "$codeSW" = 200 ] && ok "second user in alice's browser → 200 interstitial (not a silent replacement)" || no "switch callback → $codeSW (want 200)"
SWID=$(switch_id_from_headers "$WORK/h.cb")
[ -n "$SWID" ] && ok "pending-switch cookie __Host-fbx_switch_$SWID set" || no "no switch cookie set"
# The OLD session still resolves to alice while the switch is only pending.
MLold=$(me_line "$jarA")
case "$MLold" in "$SLUG|$U1|"*owner*) ok "/me with the pre-switch cookie still shows alice (owner)";; *) no "pre-confirm /me: $MLold";; esac
# Confirm (CSRF header; a form cannot set it). The switch cookie + the current
# web cookie are both in jarSW.
CONF=$(curl -s -o /dev/null -w '%{http_code}' -D "$WORK/h.conf" -X POST -b "$jarSW" -c "$jarSW" \
  -H 'x-fluidbox-csrf: 1' "$API/v1/auth/switch/$SWID")
[ "$CONF" = 302 ] && ok "confirm POST → 302 (new session minted)" || no "confirm → $CONF (want 302)"
MLnew=$(me_line "$jarSW")
echo "  /me after switch → $MLnew"
case "$MLnew" in "$SLUG|$U2|"*) ok "the switched session is bob";; *) no "post-switch /me: $MLnew";; esac
REPLAY=$(curl -s -o /dev/null -w '%{http_code}' -X POST -b "$jarSW" -c "$jarSW" -H 'x-fluidbox-csrf: 1' "$API/v1/auth/switch/$SWID")
[ "$REPLAY" != 302 ] && ok "replayed confirm → refused (got $REPLAY, not a 302)" || no "replayed confirm unexpectedly succeeded (302)"

# ── (i) Deactivation kills the session AND its PATs ───────────────────────────
say "(i) Membership deactivation — cookie + PAT die on next use"
# Mint a PAT for bob while alive, then deactivate bob's membership.
BOBPAT=$(curl -s -H 'x-fluidbox-csrf: 1' -b "$jarSW" -H 'content-type: application/json' \
  -d '{"name":"bob-pat","expires_in":3600}' "$API/v1/auth/tokens" | j "['token']")
[ -n "$BOBPAT" ] && ok "bob minted a PAT while active" || no "bob PAT mint failed"
admin_get "/v1/admin/orgs/$SLUG/members"
BOBMID=$(echo "$BODY" | python3 -c "
import sys,json
for m in json.load(sys.stdin).get('members',[]):
    if m.get('email')=='$U2': print(m['membership_id'])
" 2>/dev/null)
[ -n "$BOBMID" ] && ok "bob's membership id resolved via /members" || no "no bob membership in $BODY"
admin_post "/v1/admin/orgs/$SLUG/members/$BOBMID/deactivate" '{}'
[ "$CODE" = 200 ] && ok "operator deactivated bob's membership" || no "deactivate → $CODE: $BODY"
BOBCK=$(curl -s -o /dev/null -w '%{http_code}' -b "$jarSW" "$API/v1/agents")
[ "$BOBCK" = 401 ] && ok "bob's session cookie → 401 on the next request" || no "deactivated cookie → $BOBCK (want 401)"
BOBPC=$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $BOBPAT" "$API/v1/agents")
[ "$BOBPC" = 401 ] && ok "bob's PAT → 401 (died with the membership)" || no "deactivated PAT → $BOBPC (want 401)"

# ── (k) Issuer migration mid-flight ───────────────────────────────────────────
say "(k) Issuer migration — mid-flight login fails closed; old session dies"
# A FRESH alice/config1 session (alice's membership is still active — the switch
# only revoked one of her sessions, jarA's shared token). This one proves the
# swap revokes config1 sessions.
jarKold="$WORK/jarKold"
RES=$(login "$jarKold" "$U1" "$PW" "$SLUG"); C=$(printf '%s' "$RES" | cut -f1)
[ "$C" = 302 ] && ok "seeded a fresh alice/config1 session (pre-swap)" || no "pre-swap alice login → $C"
# Hold a SEPARATE config1 login (get a real callback URL, do NOT complete it).
jarHold="$WORK/jarHold"; : > "$jarHold"
authz=$(fbx_start "$jarHold" "$SLUG")
cbHold=$(dex_login "$jarHold" "$authz" "$U1" "$PW")
[ -n "$cbHold" ] && case "$cbHold" in "$API"*) ok "held a config1 login (callback captured, not completed)";; *) no "hold failed: $cbHold";; esac
# Swap config1 → config2 (new client id on the SAME Dex; carry_forward absent).
MIG_BODY=$(cat <<JSON
{"issuer":"$ISSUER","client_id":"$CLIENT2_ID","client_secret":"$CLIENT2_SECRET",
 "token_endpoint_auth":"client_secret_basic"}
JSON
)
admin_post "/v1/admin/orgs/$SLUG/idp/$CFG1/migrate" "$MIG_BODY"
[ "$CODE" = 200 ] && ok "migrate config1 → config2 (default deactivation)" || no "migrate → $CODE: $BODY"
# Completing the held callback now fails at the flow claim (config1 no longer active).
cHold=$(complete_cb "$jarHold" "$cbHold")
[ "$cHold" = 400 ] && ok "held callback completed post-swap → 400 (fails closed at the flow claim)" || no "held callback → $cHold (want 400)"
# alice's old (config1) session cookie is revoked by the swap.
OLD=$(curl -s -o /dev/null -w '%{http_code}' -b "$jarKold" "$API/v1/agents")
[ "$OLD" = 401 ] && ok "alice's pre-swap session cookie → 401" || no "old session post-swap → $OLD (want 401)"
# Re-arm the owner under config2 (arming works — the old owner was deactivated),
# then alice re-logs in under config2 as a NEW user row and wins owner again.
admin_post "/v1/admin/orgs/$SLUG/break-glass-owner" "{\"email\":\"$U1\"}"
[ "$CODE" = 200 ] && ok "break-glass arm under config2 → 200 (no active owner after the swap)" || no "post-swap arm → $CODE: $BODY"
jarK2="$WORK/jarK2"
RES=$(login "$jarK2" "$U1" "$PW" "$SLUG"); C=$(printf '%s' "$RES" | cut -f1)
[ "$C" = 302 ] && ok "alice re-logs in under config2 (302)" || no "config2 login → $C"
MLk=$(me_line "$jarK2")
case "$MLk" in "$SLUG|$U1|"*owner*) ok "alice is owner again under config2 (a new user row)";; *) no "config2 /me: $MLk";; esac

# ── (m) No-IdP org + single-admin data-plane (REQUIRE_SSO unset) ──────────────
say "(m) No-IdP org fail-closed + admin still works on the data plane"
admin_post "/v1/admin/orgs" "{\"slug\":\"$SLUG2\",\"display_name\":\"Beta\"}"
[ "$CODE" = 200 ] && ok "org '$SLUG2' created with NO IdP config" || no "create $SLUG2 → $CODE: $BODY"
# The browser path for an IdP-less org must be indistinguishable from a
# never-created slug (no org-existence enumeration).
S2=$(curl -s -H "$(xff)" -o "$WORK/s2" -w '%{http_code}' "$API/v1/auth/login/$SLUG2/start")
B2=$(cat "$WORK/s2")
S3=$(curl -s -H "$(xff)" -o "$WORK/s3" -w '%{http_code}' "$API/v1/auth/login/$SLUG3/start")
B3=$(cat "$WORK/s3")
[ "$S2" = "$S3" ] && [ "$B2" = "$B3" ] && ok "IdP-less org and never-created slug answer IDENTICALLY ($S2, byte-equal body)" \
  || no "enumeration leak: ($S2 vs $S3) or bodies differ"
echo "$B2" | grep -qi 'not configured' && ok "…and it is the neutral fail-closed page" || no "unexpected start body: $(head -c120 "$WORK/s2")"
# Admin token still authorizes the data plane while REQUIRE_SSO is unset.
ADP=$(curl -s -o /dev/null -w '%{http_code}' -H "$AH" "$API/v1/agents")
[ "$ADP" = 200 ] && ok "admin bearer on /v1/agents → 200 (single-admin mode, REQUIRE_SSO unset)" || no "admin data-plane → $ADP (want 200)"

# Log carol in under config2 now (a live member that survives the restart) — she
# proves the browser data-plane still works once REQUIRE_SSO is on.
jarL="$WORK/jarL"
RES=$(login "$jarL" "$U3" "$PW" "$SLUG"); C=$(printf '%s' "$RES" | cut -f1)
[ "$C" = 302 ] && ok "carol logs in under config2 (member) — cookie kept for the REQUIRE_SSO check" || no "carol login → $C"

# ── (j) SSE stream terminates within the re-auth interval after deactivation ──
say "(j) SSE termination — a revoked session's stream closes within the re-auth window"
SSE_DONE=0
if [ "$HAVE_PSQL" = 1 ]; then
  # An SSE stream needs a real session row the principal can SEE. Creating one
  # via a run would cost model spend and a runner image (forbidden here), so we
  # seed a minimal session row directly: alice is an OWNER (runs.read_all), so
  # she can stream ANY session in her org. The row references the boot-seeded
  # claude-fixer agent/revision (sessions.agent_id is a non-composite FK, so a
  # default-tenant agent is reachable from an org-tenant session). No sandbox,
  # no model, no lifecycle — the row exists purely so the timeline endpoint
  # opens and the cookie re-auth loop can be observed.
  TID=$(db "select id from tenants where slug='$SLUG'")
  SID=$(db "insert into sessions
      (id, tenant_id, agent_id, agent_revision_id, status, autonomy, trust_tier,
       task, repo_source, run_spec, budgets, invoked_by_kind)
    select gen_random_uuid(), '$TID', a.id, r.id, 'running', 'supervised', 'trusted',
       'identity-e2e sse fixture', '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, 'operator'
    from agents a join agent_revisions r on r.agent_id = a.id
    where a.name = 'claude-fixer'
    order by r.created_at desc limit 1
    returning id")
  if [ -n "$SID" ]; then
    ok "seeded a cookie-reachable session fixture ($SID)"
    # Open the stream in the background with alice's (owner) cookie.
    ( curl -s -N --max-time 30 -b "$jarK2" "$API/v1/sessions/$SID/events/stream" > "$WORK/sse.out" 2>/dev/null ) &
    SSE_PID=$!
    sleep 2
    if kill -0 "$SSE_PID" 2>/dev/null; then ok "SSE stream open and following"; else no "SSE stream closed before deactivation"; fi
    # Deactivate alice mid-stream; the reauth loop (2s) must break the stream.
    admin_get "/v1/admin/orgs/$SLUG/members"
    ALMID=$(echo "$BODY" | python3 -c "
import sys,json
rows=[m for m in json.load(sys.stdin).get('members',[]) if m.get('email')=='$U1' and m.get('membership_status')=='active']
print(rows[0]['membership_id'] if rows else '')" 2>/dev/null)
    admin_post "/v1/admin/orgs/$SLUG/members/$ALMID/deactivate" '{}'
    [ "$CODE" = 200 ] && ok "deactivated alice's (config2) membership mid-stream" || no "deactivate alice → $CODE: $BODY"
    # Wait up to ~6s (≈ reauth 2s + select sleep 2s + slack) for the stream to close.
    CLOSED=0
    for _ in $(seq 1 12); do
      kill -0 "$SSE_PID" 2>/dev/null || { CLOSED=1; break; }
      sleep 0.5
    done
    kill "$SSE_PID" 2>/dev/null
    [ "$CLOSED" = 1 ] && ok "SSE stream closed within the re-auth interval after deactivation" || no "SSE stream did NOT close within ~6s"
    SSE_DONE=1
  else
    no "could not seed the SSE fixture (no claude-fixer agent/revision?)"
  fi
fi
[ "$SSE_DONE" = 0 ] && skip "SSE live-stream: psql unavailable — cookie re-auth termination is covered by web_session_live + the sse.rs reauth loop (see report)"

# ── (l) REQUIRE_SSO confines the operator token to /v1/admin/* ────────────────
say "(l) REQUIRE_SSO — operator confined to /v1/admin/*, cookie still works"
stop_server
start_server 1     # restart with FLUIDBOX_REQUIRE_SSO=1
ok "control plane restarted with REQUIRE_SSO=1"
ADMDATA=$(curl -s -o /dev/null -w '%{http_code}' -H "$AH" "$API/v1/agents")
[ "$ADMDATA" = 401 ] && ok "admin bearer on /v1/agents → 401 (confined)" || no "admin data-plane under require_sso → $ADMDATA (want 401)"
ADMADMIN=$(curl -s -o /dev/null -w '%{http_code}' -H "$AH" "$API/v1/admin/orgs")
[ "$ADMADMIN" = 200 ] && ok "admin bearer on /v1/admin/orgs → 200 (operator surface intact)" || no "admin admin-plane → $ADMADMIN (want 200)"
COOKIEDATA=$(curl -s -o /dev/null -w '%{http_code}' -b "$jarL" "$API/v1/agents")
[ "$COOKIEDATA" = 200 ] && ok "carol's session cookie on /v1/agents → 200 (browser data-plane unaffected)" || no "cookie under require_sso → $COOKIEDATA (want 200)"

# ── Result ───────────────────────────────────────────────────────────────────
say "RESULT"
printf "  \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
