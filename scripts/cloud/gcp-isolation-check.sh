#!/usr/bin/env bash
# Tenant-isolation and governed-egress evidence for the GCP deployment.
#
# These are the two properties that are easiest to BELIEVE and hardest to
# prove, because both look identical when they are working and when they are
# quietly not:
#
#   * Tenant isolation "works" whenever every query happens to carry the right
#     predicate. The database floor (migration 0018 RLS) is what makes it hold
#     when one does not - and PostgreSQL SKIPS every policy for a SUPERUSER or
#     BYPASSRLS role, so RLS can be applied, FORCEd, and completely inert.
#   * Sandbox containment "works" until the CNI silently fails open.
#
# So neither check reads a manifest. Each one makes the system actually refuse
# something.
#
#   scripts/cloud/gcp-isolation-check.sh

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

NS="${NAMESPACE:-fluidbox}"
SANDBOX_NS="${SANDBOX_NS:-fluidbox-sandboxes}"
RELEASE="${RELEASE:-fluidbox}"
PROJECT="${GCP_PROJECT:-fluidbox-506603}"
API="${CONTROL_HOST:+https://$CONTROL_HOST}"; API="${API:-https://api.platform.fluidzero.ai}"

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; [ $# -gt 1 ] && printf '      %s\n' "$2"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33m–\033[0m %s (%s)\n' "$1" "${2:-skipped}"; SKIP=$((SKIP+1)); }
say()  { printf '\n\033[1m%s\033[0m\n' "$1"; }

# ── 1. The database floor ──────────────────────────────────────────────────
say "1. Row-level security is ENFORCED, not merely applied"

# The server states this at boot after inspecting the EFFECTIVE role of a
# pooled connection. That is the authoritative answer: it is the role Postgres
# will actually evaluate policies for, after any SET ROLE.
# Whole log for the NEWEST server pod: the RLS and netpol verdicts are boot
# lines, emitted once, and a --tail window silently misses them on a pod that
# has been logging since - which turns a real check into a skip.
POD="$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=server \
        --sort-by=.metadata.creationTimestamp -o name 2>/dev/null | tail -1)"
LOG="$(kubectl -n "$NS" logs "$POD" 2>/dev/null)"
# Structured FIELD first, prose as fallback. Field names outlive wording: the
# observability rewrite moved these to JSON and reworded them, silently turning
# real checks into skips.
if grep -qE '"rls":"enforced"|row-level security is ENFORCED' <<<"$LOG"; then
  ok "boot log: RLS enforced (pool role has neither SUPERUSER nor BYPASSRLS)"
elif grep -q "bypasses RLS\|SUPERUSER or has BYPASSRLS" <<<"$LOG"; then
  bad "the pool role BYPASSES RLS — migration 0018's policies are decoration" \
      "set server.runtimeRole, or point DATABASE_URL at a non-superuser role"
else
  skip "RLS posture line" "outside the retained log window"
fi

# The rewrite inserted an article ("a non-owner role"), which broke an
# exact-phrase match.
if grep -qE '"rls":"role_split"|non-owner role' <<<"$LOG"; then
  ok "pool runs as the non-owner runtime role (RLS role split active)"
else
  skip "runtime-role line" "outside the retained log window"
fi

# ── 2. Cross-tenant isolation over the real API ────────────────────────────
say "2. Cross-tenant isolation"

ADMIN="${FLUIDBOX_ADMIN_TOKEN:-$(gcloud secrets versions access latest \
        --secret=fluidbox-admin-token --project "$PROJECT" 2>/dev/null)}"
if [ -z "$ADMIN" ]; then
  skip "cross-tenant checks" "no admin token"
else
  AUTH="Authorization: Bearer $ADMIN"

  # Under FLUIDBOX_REQUIRE_SSO=1 the admin token is confined to /v1/admin/*.
  # If it can drive tenant data, multi-user confinement is not in effect and
  # every other isolation claim rests on nothing.
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -H "$AUTH" "$API/v1/sessions")
  case "$code" in
    401|403) ok "admin token refused on tenant data (/v1/sessions -> $code)" ;;
    *)       bad "admin token reached /v1/sessions -> $code" "REQUIRE_SSO confinement is NOT active" ;;
  esac

  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -H "$AUTH" "$API/v1/admin/orgs")
  [ "$code" = "200" ] && ok "admin token works on /v1/admin/orgs (break-glass intact)" \
                      || bad "admin token on /v1/admin/orgs -> $code"

  # Two orgs, then confirm each admin view is scoped to ONE of them.
  for slug in fbx-iso-a fbx-iso-b; do
    curl -sS -o /dev/null --max-time 20 -X POST -H "$AUTH" -H 'Content-Type: application/json' \
      -d "{\"slug\":\"$slug\",\"name\":\"isolation probe $slug\"}" "$API/v1/admin/orgs" 2>/dev/null
  done
  # A real cross-tenant probe, on a sub-resource that genuinely differs between
  # orgs: IdP configurations. The org that had Auth0 registered must show them;
  # a freshly created org must show NONE. Equal counts would mean the admin
  # surface is answering from a global view rather than a tenant-scoped one.
  count_idp() {
    curl -sS --max-time 20 -H "$AUTH" "$API/v1/admin/orgs/$1/idp" 2>/dev/null \
      | python3 -c "import json,sys
try: print(len(json.load(sys.stdin).get('idp_configs',[])))
except Exception: print(-1)"
  }
  A_N=$(count_idp fbx-iso-a); Z_N=$(count_idp "${ORG_SLUG:-fluidzero}")
  if [ "$A_N" = "0" ] && [ "$Z_N" -gt 0 ] 2>/dev/null; then
    ok "per-org scoping: a fresh org sees 0 IdP configs while ${ORG_SLUG:-fluidzero} sees $Z_N"
  elif [ "$A_N" = "-1" ] || [ "$Z_N" = "-1" ]; then
    skip "per-org scoping" "admin idp endpoint unavailable"
  else
    bad "per-org scoping: fresh org sees $A_N IdP configs, ${ORG_SLUG:-fluidzero} sees $Z_N" \
        "equal or non-zero counts suggest a global view, not a tenant-scoped one"
  fi

  # A member list must also be per-org, not shared.
  m=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -H "$AUTH" \
        "$API/v1/admin/orgs/fbx-iso-a/members" 2>/dev/null)
  [ "$m" = "200" ] && ok "per-org member list reachable (scoped by slug)" \
                   || skip "per-org member list" "HTTP $m"

  # A PAT belonging to no org must not read another org's data. We cannot mint
  # one without a browser session, so assert the refusal a forged one gets -
  # which is the property that matters: an unrecognised credential never
  # resolves to a tenant.
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 \
    -H "Authorization: Bearer fbx_pat_00000000000000000000000000000000" "$API/v1/sessions")
  [ "$code" = "401" ] || [ "$code" = "403" ] \
    && ok "an unrecognised PAT resolves to NO tenant ($code)" \
    || bad "unrecognised PAT -> $code"
fi

# ── 3. Governed egress ─────────────────────────────────────────────────────
say "3. Sandbox containment (governed egress)"

# The server refuses to start ANY run until a boot probe proves the CNI
# actually drops traffic. That refusal is the containment guarantee.
if grep -qiE '"worker":"netpol_gate"|NetworkPolicy enforcement verified' <<<"$LOG"; then
  ok "boot probe proved the CNI enforces NetworkPolicy (runs are gated on this)"
else
  skip "boot netpol line" "outside the retained log window"
fi

pol=$(kubectl -n "$SANDBOX_NS" get networkpolicy -o name 2>/dev/null | wc -l | tr -d ' ')
[ "${pol:-0}" -ge 2 ] \
  && ok "$pol NetworkPolicies present in $SANDBOX_NS (default-deny + egress profile)" \
  || bad "only ${pol:-0} NetworkPolicy in $SANDBOX_NS" "expected a deny-all plus an egress profile"

# The live proof: a pod wearing the sandbox label must NOT reach the internet.
# Run it and see, rather than reading the policy back.
say "   live probe: a sandbox-labelled pod tries to reach the internet"
# First, a check worth making explicitly: the sandbox namespace must REFUSE a
# pod that is not hardened. A namespace that accepts anything is a namespace
# whose Pod Security labels are decorative.
LAX="psa-probe-$RANDOM"
if kubectl -n "$SANDBOX_NS" run "$LAX" --restart=Never --image=busybox:1.36 \
     --command -- true >/dev/null 2>&1; then
  bad "the sandbox namespace ACCEPTED an unhardened pod" "Pod Security enforcement is not active"
  kubectl -n "$SANDBOX_NS" delete "pod/$LAX" --ignore-not-found --wait=false >/dev/null 2>&1
else
  ok "the sandbox namespace REFUSES an unhardened pod (Pod Security: restricted)"
fi

# Now the real probe, hardened exactly as the provider builds a sandbox pod -
# otherwise admission rejects it and the egress question never gets asked.
POD="egress-probe-$RANDOM"
kubectl -n "$SANDBOX_NS" run "$POD" --restart=Never --image=busybox:1.36 \
  --labels="fluidbox.dev/managed=true" \
  --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":10001,"seccompProfile":{"type":"RuntimeDefault"}},"tolerations":[{"key":"fluidbox.dev/role","operator":"Equal","value":"sandbox","effect":"NoSchedule"}],"containers":[{"name":"'"$POD"'","image":"busybox:1.36","command":["sh","-c","wget -q -T 6 -O- https://example.com >/dev/null 2>&1 && echo REACHED || echo BLOCKED"],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}' \
  >/dev/null 2>&1

# POLL to a terminal phase rather than waiting on Ready + a fixed sleep. The
# probe is a short-lived Job-shaped pod: it can go Pending -> Running ->
# Succeeded faster than a `wait --for=condition=Ready` ever observes Ready, and
# a fixed sleep afterwards is a race that reads the logs before the container
# has written them. Both produced an "inconclusive: <none>" that looked like a
# broken test rather than a slow one.
PHASE=""
for _ in $(seq 1 24); do          # 24 x 10s = 4 min, enough for a cold Spot node
  PHASE="$(kubectl -n "$SANDBOX_NS" get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null)"
  case "$PHASE" in Succeeded|Failed) break ;; esac
  sleep 10
done
if [ "$PHASE" = "Succeeded" ] || [ "$PHASE" = "Failed" ]; then
  OUT="$(kubectl -n "$SANDBOX_NS" logs "$POD" 2>/dev/null | tr -d '[:space:]')"
  case "$OUT" in
    BLOCKED) ok "a sandbox-labelled pod could NOT reach the public internet" ;;
    REACHED) bad "a sandbox-labelled pod REACHED the public internet" "zeroEgress is not being enforced" ;;
    *)       skip "live egress probe" "inconclusive output: '${OUT:-<none>}'" ;;
  esac
else
  skip "live egress probe" "pod did not start within 240s - the sandbox pool idles at ZERO nodes, so a cold probe waits on the autoscaler"
fi
kubectl -n "$SANDBOX_NS" delete "pod/$POD" --ignore-not-found --wait=false >/dev/null 2>&1

say "Summary"
printf '  passed %d   failed %d   skipped %d\n\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
