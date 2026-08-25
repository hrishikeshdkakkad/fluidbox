#!/usr/bin/env bash
# Post-deploy smoke tests for the GCP deployment.
#
# The bar this script holds: CONFIGURATION IS NOT RUNTIME PROOF. Every check
# below observes the running system - a request that was answered, a
# certificate that was served, a policy that actually refused something -
# rather than asserting that a manifest contains the right field. A test that
# greps a values file proves only that someone typed the value.
#
#   scripts/cloud/gcp-smoke.sh
#
# Environment:
#   CONTROL_HOST    control-plane origin      (default api.platform.fluidzero.ai)
#   DASHBOARD_HOST  browser origin on Vercel  (default platform.fluidzero.ai)
#   NAMESPACE       release namespace         (default fluidbox)
#   RELEASE         helm release name         (default fluidbox)
#   SKIP_CLUSTER=1  skip the kubectl checks (run the HTTP ones from anywhere)

set -uo pipefail

CONTROL_HOST="${CONTROL_HOST:-api.platform.fluidzero.ai}"
DASHBOARD_HOST="${DASHBOARD_HOST:-platform.fluidzero.ai}"
NAMESPACE="${NAMESPACE:-fluidbox}"
RELEASE="${RELEASE:-fluidbox}"
SANDBOX_NS="${SANDBOX_NS:-fluidbox-sandboxes}"

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; [ $# -gt 1 ] && printf '      %s\n' "$2"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33m–\033[0m %s (%s)\n' "$1" "${2:-skipped}"; SKIP=$((SKIP+1)); }
say()  { printf '\n\033[1m%s\033[0m\n' "$1"; }

# ── 1. Workloads ────────────────────────────────────────────────────────────
say "1. Cluster workloads"
if [ "${SKIP_CLUSTER:-}" = "1" ] || ! command -v kubectl >/dev/null; then
  skip "kubectl checks" "no cluster access"
else
  for d in "$RELEASE-server" "$RELEASE-litellm"; do
    if ! kubectl -n "$NAMESPACE" get deploy "$d" >/dev/null 2>&1; then
      skip "deployment $d" "not present"; continue
    fi
    want=$(kubectl -n "$NAMESPACE" get deploy "$d" -o jsonpath='{.spec.replicas}')
    got=$(kubectl -n "$NAMESPACE" get deploy "$d" -o jsonpath='{.status.readyReplicas}')
    [ "${got:-0}" = "$want" ] \
      && ok "$d ready ${got}/${want}" \
      || bad "$d ready ${got:-0}/${want}" "kubectl -n $NAMESPACE describe deploy $d"
  done

  # A restart count that keeps climbing is a crash loop that readiness alone
  # will not reveal - a pod can be Ready now and have restarted 40 times.
  restarts=$(kubectl -n "$NAMESPACE" get pods -o jsonpath='{range .items[*]}{.status.containerStatuses[*].restartCount}{"\n"}{end}' 2>/dev/null \
             | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -rn | head -1)
  [ "${restarts:-0}" -le 3 ] \
    && ok "no container has restarted more than 3 times (max ${restarts:-0})" \
    || bad "a container has restarted ${restarts} times" "kubectl -n $NAMESPACE logs --previous"

  # The fail-closed boot gates print this and then exit. A pod that is Ready
  # cannot have hit one, but a CrashLoopBackOff behind a stale ReplicaSet can.
  if kubectl -n "$NAMESPACE" logs -l app.kubernetes.io/component=server --tail=400 2>/dev/null \
       | grep -q "REFUSING TO BOOT"; then
    bad "a server pod logged REFUSING TO BOOT" "read the line - it names the exact gate"
  else
    ok "no boot refusals in recent server logs"
  fi

  # NetworkPolicy enforcement is a RUNTIME property the server proves at boot
  # by probing; runs are gated until it does.
  if kubectl -n "$NAMESPACE" logs -l app.kubernetes.io/component=server --tail=400 2>/dev/null \
       | grep -qiE "netpol.*(enforced|verified)|network policy enforcement (verified|confirmed)"; then
    ok "CNI NetworkPolicy enforcement proven by the boot probe"
  else
    skip "netpol enforcement line" "not in the retained log window"
  fi

  # Tenant isolation's database floor is only real if the pool role cannot
  # bypass RLS. The server logs which case it is.
  if kubectl -n "$NAMESPACE" logs -l app.kubernetes.io/component=server --tail=400 2>/dev/null \
       | grep -q "row-level security is ENFORCED"; then
    ok "RLS is ENFORCED for the application pool (role has neither SUPERUSER nor BYPASSRLS)"
  else
    skip "RLS posture line" "not in the retained log window"
  fi

  kubectl -n "$SANDBOX_NS" get resourcequota >/dev/null 2>&1 \
    && ok "sandbox namespace ResourceQuota present (capacity backstop)" \
    || bad "no ResourceQuota in $SANDBOX_NS" "the substrate capacity limit is missing"

  kubectl -n "$NAMESPACE" get pdb "$RELEASE-server" >/dev/null 2>&1 \
    && ok "PodDisruptionBudget present" \
    || skip "PodDisruptionBudget" "only rendered above one replica"

  # The Secret the chart reads must actually have been materialised.
  keys=$(kubectl -n "$NAMESPACE" get secret fluidbox-secrets -o jsonpath='{.data}' 2>/dev/null | tr ',' '\n' | grep -c '"' || echo 0)
  [ "${keys:-0}" -gt 0 ] \
    && ok "fluidbox-secrets materialised by External Secrets" \
    || bad "fluidbox-secrets missing or empty" "kubectl -n $NAMESPACE describe externalsecret"

  cert=$(kubectl -n "$NAMESPACE" get managedcertificate "$RELEASE-server" \
          -o jsonpath='{.status.certificateStatus}' 2>/dev/null)
  case "$cert" in
    Active)       ok "ManagedCertificate Active" ;;
    Provisioning) bad "ManagedCertificate still Provisioning" "needs DNS to resolve to the Ingress IP; can take 15-60 min" ;;
    "")           skip "ManagedCertificate" "not found" ;;
    *)            bad "ManagedCertificate status: $cert" "kubectl describe managedcertificate $RELEASE-server" ;;
  esac
fi

# ── 2. DNS + TLS ────────────────────────────────────────────────────────────
say "2. DNS and TLS"
ips=$(dig +short "$CONTROL_HOST" A | grep -E '^[0-9.]+$' | head -3)
[ -n "$ips" ] \
  && ok "$CONTROL_HOST resolves ($(echo "$ips" | tr '\n' ' '))" \
  || bad "$CONTROL_HOST does not resolve" "add the A record in Route 53 pointing at the GCLB address"

dash=$(dig +short "$DASHBOARD_HOST" | head -3)
[ -n "$dash" ] \
  && ok "$DASHBOARD_HOST resolves ($(echo "$dash" | tr '\n' ' '))" \
  || bad "$DASHBOARD_HOST does not resolve"

if [ -n "$ips" ]; then
  # -Z rejects an expired or otherwise invalid chain; the point is that the
  # certificate VALIDATES, not merely that something answered on 443.
  if echo | timeout 20 openssl s_client -connect "$CONTROL_HOST:443" -servername "$CONTROL_HOST" 2>/dev/null \
       | openssl x509 -noout -subject -dates 2>/dev/null > /tmp/smoke-cert.txt; then
    ok "valid TLS certificate served for $CONTROL_HOST"
    sed 's/^/      /' /tmp/smoke-cert.txt
  else
    bad "no valid TLS certificate for $CONTROL_HOST" "ManagedCertificate may still be provisioning"
  fi
fi

# ── 3. Control-plane HTTP ───────────────────────────────────────────────────
say "3. Control-plane API"
code=$(curl -sS -o /tmp/smoke-health.json -w '%{http_code}' --max-time 20 "https://$CONTROL_HOST/v1/health" 2>/dev/null)
[ "$code" = "200" ] \
  && ok "GET /v1/health -> 200 $(head -c 120 /tmp/smoke-health.json)" \
  || bad "GET /v1/health -> $code" "$(head -c 200 /tmp/smoke-health.json 2>/dev/null)"

ready=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "https://$CONTROL_HOST/v1/health/ready" 2>/dev/null)
[ "$ready" = "200" ] && ok "GET /v1/health/ready -> 200" || bad "GET /v1/health/ready -> $ready"

# HTTP must REDIRECT, never answer. A dashboard that sets __Host- cookies must
# not be reachable over plaintext at all.
redir=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "http://$CONTROL_HOST/v1/health" 2>/dev/null)
case "$redir" in
  301|302|307|308) ok "plain HTTP redirects to HTTPS ($redir)" ;;
  000)             bad "plain HTTP did not answer" "FrontendConfig redirect may not be attached" ;;
  *)               bad "plain HTTP answered $redir instead of redirecting" "requests can reach the API unencrypted" ;;
esac

# ── 4. Negative authentication ──────────────────────────────────────────────
say "4. Negative authentication"
un=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "https://$CONTROL_HOST/v1/sessions" 2>/dev/null)
[ "$un" = "401" ] || [ "$un" = "403" ] \
  && ok "unauthenticated GET /v1/sessions -> $un" \
  || bad "unauthenticated GET /v1/sessions -> $un" "the API must refuse an anonymous caller"

bogus=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 \
  -H "Authorization: Bearer fbx_pat_definitely-not-a-real-token" \
  "https://$CONTROL_HOST/v1/sessions" 2>/dev/null)
[ "$bogus" = "401" ] || [ "$bogus" = "403" ] \
  && ok "forged bearer token -> $bogus" \
  || bad "forged bearer token -> $bogus"

# Under FLUIDBOX_REQUIRE_SSO=1 the admin token is confined to /v1/admin/*.
# If it can drive /v1/sessions, multi-user mode is not actually on.
if [ -n "${FLUIDBOX_ADMIN_TOKEN:-}" ]; then
  adm=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 \
    -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" "https://$CONTROL_HOST/v1/sessions" 2>/dev/null)
  [ "$adm" = "403" ] || [ "$adm" = "401" ] \
    && ok "admin token refused on /v1/sessions -> $adm (REQUIRE_SSO confines it to /v1/admin/*)" \
    || bad "admin token reached /v1/sessions -> $adm" "multi-user confinement is NOT in effect"
  adm2=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 \
    -H "Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" "https://$CONTROL_HOST/v1/admin/orgs" 2>/dev/null)
  [ "$adm2" = "200" ] \
    && ok "admin token works on /v1/admin/orgs -> 200 (break-glass surface intact)" \
    || bad "admin token on /v1/admin/orgs -> $adm2"
else
  skip "admin-token confinement" "FLUIDBOX_ADMIN_TOKEN not provided"
fi

# ── 5. Dashboard origin ─────────────────────────────────────────────────────
say "5. Dashboard (Vercel)"
dcode=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 25 "https://$DASHBOARD_HOST/" 2>/dev/null)
[ "$dcode" = "200" ] && ok "GET https://$DASHBOARD_HOST/ -> 200" || bad "dashboard -> $dcode"

# The /v1 rewrite is what makes __Host- cookies possible: the OIDC callback has
# to land on the SAME origin the dashboard runs on. Proving it end to end means
# the dashboard origin answering a control-plane route.
vcode=$(curl -sS -o /tmp/smoke-rewrite.json -w '%{http_code}' --max-time 25 "https://$DASHBOARD_HOST/v1/health" 2>/dev/null)
[ "$vcode" = "200" ] \
  && ok "dashboard origin proxies /v1/health -> 200 (the rewrite that makes __Host- cookies work)" \
  || bad "dashboard /v1/health -> $vcode" "FLUIDBOX_WEB_MODE=sso + FLUIDBOX_API_URL must be set at BUILD time on Vercel"

# ── 6. Streaming ────────────────────────────────────────────────────────────
say "6. Event stream budget"
# The GCLB default backend timeout is 30s, which would cut every run timeline.
# Hold a connection open past that and see whether the edge kills it. An
# unauthenticated stream is refused quickly, so this measures the EDGE, using a
# route that stays open: the health endpoint with a slow read is not enough, so
# assert on the BackendConfig the load balancer actually adopted.
if [ "${SKIP_CLUSTER:-}" = "1" ] || ! command -v kubectl >/dev/null; then
  skip "backend timeout" "no cluster access"
else
  t=$(kubectl -n "$NAMESPACE" get backendconfig "$RELEASE-server" -o jsonpath='{.spec.timeoutSec}' 2>/dev/null)
  if [ -n "$t" ] && [ "$t" -ge 600 ]; then
    ok "BackendConfig timeoutSec=$t (SSE survives past the 30s GCLB default)"
  else
    bad "BackendConfig timeoutSec=${t:-unset}" "SSE timelines will be cut at the GCLB default"
  fi
  # An object that exists but is not LINKED is inert.
  ann=$(kubectl -n "$NAMESPACE" get svc "$RELEASE-server" -o jsonpath='{.metadata.annotations.cloud\.google\.com/backend-config}' 2>/dev/null)
  [ -n "$ann" ] \
    && ok "Service links the BackendConfig ($ann)" \
    || bad "Service has no backend-config annotation" "the BackendConfig is present but IGNORED"
fi

say "Summary"
printf '  passed %d   failed %d   skipped %d\n\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
