#!/usr/bin/env bash
# Chart render assertions (findings M3/M9/M10/L12 + the values→PodSpec chart
# test from L13): `helm template` with distinctive values, assert the rendered
# manifests actually carry them, then lint + render every per-cloud preset.
# Pure render-time — no cluster needed. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")"
CHART=fluidbox

fail() { echo "ASSERT FAIL: $1" >&2; exit 1; }

render() { helm template fluidbox "$CHART" "$@"; }

# ---------------------------------------------------------------------------
# M3: values.sandbox.* → FLUIDBOX_K8S_* env on the server Deployment.
server="$(render -f test-values/assert.yaml -s templates/server.yaml)"
assert_env() {
  grep -qF -- "{ name: $1, value: $2 }" <<<"$server" \
    || fail "server env $1=$2 not rendered (M3)"
}
assert_env FLUIDBOX_K8S_RUN_AS_USER '"12345"'
assert_env FLUIDBOX_K8S_CPU_REQUEST '"750m"'
assert_env FLUIDBOX_K8S_MEM_REQUEST '"3Gi"'
assert_env FLUIDBOX_K8S_EPHEMERAL_REQUEST '"2Gi"'
assert_env FLUIDBOX_K8S_CPU_LIMIT '"3"'
assert_env FLUIDBOX_K8S_MEM_LIMIT '"6Gi"'
assert_env FLUIDBOX_K8S_EPHEMERAL_LIMIT '"20Gi"'
assert_env FLUIDBOX_K8S_VOLUME_SIZE_LIMIT '"42Gi"'
assert_env FLUIDBOX_K8S_NODE_SELECTOR '"pool=sandbox"'
assert_env FLUIDBOX_K8S_PRIORITY_CLASS '"sandbox-low"'
grep -qF -- 'name: FLUIDBOX_K8S_TOLERATIONS' <<<"$server" \
  || fail "FLUIDBOX_K8S_TOLERATIONS env not rendered (M3)"
grep -qF -- '\"key\":\"dedicated\"' <<<"$server" \
  || fail "tolerations JSON payload not rendered via toJson (M3)"
grep -qF -- '\"tolerationSeconds\":300' <<<"$server" \
  || fail "tolerationSeconds lost in the tolerations payload (M3 fidelity)"

# M10: pull-secret names reach the provider (sandbox + probe pods).
assert_env FLUIDBOX_K8S_IMAGE_PULL_SECRETS '"regcred,mirror-cred"'

# M9: digest pin renders repo@sha256:… (server), tag renders repo:tag (web);
# flat images pass a digest ref through untouched.
grep -qF 'image: "ghcr.io/example/fluidbox-server@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' <<<"$server" \
  || fail "server image digest not rendered as repo@sha256 (M9)"
grep -qF 'value: "ghcr.io/example/fluidbox-sandbox-runner@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' <<<"$server" \
  || fail "flat sandboxRunner digest ref not passed through (M9)"
web="$(render -f test-values/assert.yaml -s templates/web.yaml)"
grep -qF 'image: "ghcr.io/example/fluidbox-web:9.9.9"' <<<"$web" \
  || fail "web image tag not rendered as repo:tag (M9)"

# M9: the DEFAULT values bind to the chart appVersion (published by release),
# never a floating :dev that release.yml does not push.
appv="$(awk '/^appVersion:/ { gsub(/"/, "", $2); print $2 }' "$CHART/Chart.yaml")"
def_server="$(render -s templates/server.yaml)"
grep -qF "image: \"ghcr.io/hrishikeshdkakkad/fluidbox-server:${appv}\"" <<<"$def_server" \
  || fail "default server image not bound to appVersion ${appv} (M9)"
grep -qF "value: \"ghcr.io/hrishikeshdkakkad/fluidbox-workspaced:${appv}\"" <<<"$def_server" \
  || fail "default collector image not bound to appVersion ${appv} (M9)"
grep -qF "value: \"ghcr.io/hrishikeshdkakkad/fluidbox-sandbox-runner:${appv}\"" <<<"$def_server" \
  || fail "default sandboxRunner image not bound to appVersion ${appv} (M9)"
if grep -qF ':dev"' <<<"$def_server"; then
  fail "default render still references a :dev image (M9)"
fi

# M10: the helm-test probe pod carries placement + pull secrets (gate parity).
probe="$(render -f test-values/assert.yaml -s templates/tests/netpol-probe.yaml)"
grep -qF 'priorityClassName: sandbox-low' <<<"$probe" \
  || fail "helm-test probe missing sandbox priorityClassName (M3 parity)"
grep -qF 'name: regcred' <<<"$probe" \
  || fail "helm-test probe missing imagePullSecrets (M10)"
grep -qF 'pool: sandbox' <<<"$probe" \
  || fail "helm-test probe missing sandbox nodeSelector (M3 parity)"

# L12: with the dashboard enabled, / routes to the web Service and the API
# stays reachable under /v1 (+ /.well-known for CIMD). Assert the PAIRING
# (path → backend), not just token presence — a swapped mapping must fail.
ingress="$(render -f test-values/assert.yaml -s templates/ingress.yaml)"
pairs="$(awk '/- path:/ { p = $3 } /name:/ { if (p) print p, $2 }' <<<"$ingress")"
assert_route() {
  grep -qx -- "$1 $2" <<<"$pairs" || fail "ingress must route $1 → $2 (L12); got: $(tr '\n' ';' <<<"$pairs")"
}
assert_route "/v1" "fluidbox-fluidbox-server"
assert_route "/.well-known" "fluidbox-fluidbox-server"
assert_route "/" "fluidbox-fluidbox-web"
# Without the dashboard, / falls back to the API.
ingress_api="$(render -f test-values/assert.yaml --set web.enabled=false -s templates/ingress.yaml)"
pairs="$(awk '/- path:/ { p = $3 } /name:/ { if (p) print p, $2 }' <<<"$ingress_api")"
grep -qF 'fluidbox-fluidbox-web' <<<"$pairs" \
  && fail "ingress routes to a web Service that is not deployed (L12)"
assert_route "/" "fluidbox-fluidbox-server"

# Hostile values must FAIL the render, not silently degrade.
if render -f test-values/assert.yaml --set-string images.server.digest="deadbeef" \
  -s templates/server.yaml >/dev/null 2>&1; then
  fail "a malformed digest (missing sha256: prefix) must fail the render (M9)"
fi
if render -f test-values/assert.yaml --set-string sandbox.nodeSelector.pool="a=b" \
  -s templates/server.yaml >/dev/null 2>&1; then
  fail "a nodeSelector value containing '=' must fail the render (M3 encoding)"
fi

# ---------------------------------------------------------------------------
# The controlled resolver must keep NET_BIND_SERVICE. Without it the container
# cannot even exec (file capabilities + NO_NEW_PRIVS), so every granted run
# loses DNS and `helm upgrade --wait` hangs. A render assertion is the only
# cheap guard: the kind job's runtime does not reproduce the exec failure.
dns="$(render --set networkGrants.enabled=true \
  --set networkGrants.dnsClusterIP=172.20.0.53 -s templates/netgrant.yaml)"
grep -qF 'add: ["NET_BIND_SERVICE"]' <<<"$dns" \
  || fail "sandbox-dns lost NET_BIND_SERVICE — the resolver will fail to exec"
grep -qF 'allowPrivilegeEscalation: false' <<<"$dns" \
  || fail "sandbox-dns must keep allowPrivilegeEscalation: false"

# ---------------------------------------------------------------------------
# Every preset must lint and render.
helm lint "$CHART" >/dev/null || fail "helm lint (default values)"
for preset in "$CHART"/values/*.yaml; do
  helm lint "$CHART" -f "$preset" >/dev/null || fail "helm lint ($preset)"
  render -f "$preset" >/dev/null || fail "helm template ($preset)"
done
# The kind preset keeps its locally-loaded :dev images.
kind_out="$(render -f "$CHART/values/kind.yaml" -s templates/server.yaml)"
grep -qF 'image: "fluidbox-server:dev"' <<<"$kind_out" \
  || fail "kind preset no longer renders the locally-loaded fluidbox-server:dev"

# ---------------------------------------------------------------------------
# Production hardening surface (GCP deployment, 2026-08). Each assertion below
# pins a default whose WRONG value is silent in every other test: the manifest
# still renders, the pods still start, and the defect only appears under load,
# during an upgrade, or on a certificate that never provisions.

# S3 archive mode is what unlocks a rolling (zero-downtime) upgrade; the
# node-local backend must keep Recreate because one RWO volume cannot be held
# by two pods. Assert BOTH directions - a swap would be invisible until a
# deploy either 502'd or deadlocked on a volume.
s3="$(render --set server.archiveStore=s3 --set server.archiveS3.bucket=b \
  --set server.archiveS3.region=us-central1 --set server.replicas=2 \
  -s templates/server.yaml)"
grep -qF 'type: RollingUpdate' <<<"$s3" \
  || fail "archiveStore=s3 must render strategy RollingUpdate (zero-downtime deploys)"
fs="$(render -s templates/server.yaml)"
grep -qF 'type: Recreate' <<<"$fs" \
  || fail "the node-local archive backend must render strategy Recreate (one RWO volume)"

# Placement: the control plane must be pinnable off preemptible capacity.
place="$(render --set 'server.nodeSelector.fluidbox\.dev/role=system' \
  --set server.priorityClassName=fluidbox-control-plane \
  --set 'server.serviceAccount.annotations.iam\.gke\.io/gcp-service-account=x@y.iam.gserviceaccount.com' \
  -s templates/server.yaml)"
grep -qF 'fluidbox.dev/role: system' <<<"$place" \
  || fail "server.nodeSelector did not reach the PodSpec"
grep -qF 'priorityClassName: "fluidbox-control-plane"' <<<"$place" \
  || fail "server.priorityClassName did not reach the PodSpec"
grep -qF 'iam.gke.io/gcp-service-account: x@y.iam.gserviceaccount.com' <<<"$place" \
  || fail "server.serviceAccount.annotations did not reach the ServiceAccount"

# GKE edge. The BackendConfig object is inert unless the Service LINKS to it -
# and an unlinked BackendConfig is the exact shape of "we configured the SSE
# timeout" while GCLB still cuts every stream at its 30s default.
gke="$(render --set gke.enabled=true --set gke.backendConfig.enabled=true \
  --set gke.frontendConfig.enabled=true --set gke.managedCertificate.enabled=true \
  --set 'gke.managedCertificate.domains[0]=api.example.test')"
grep -qF 'cloud.google.com/backend-config' <<<"$gke" \
  || fail "the server Service must carry the backend-config annotation, or the BackendConfig is ignored"
grep -qF 'cloud.google.com/neg' <<<"$gke" \
  || fail "container-native load balancing (NEG) annotation missing"
grep -qF 'timeoutSec: 3600' <<<"$gke" \
  || fail "BackendConfig.timeoutSec must be long enough for SSE (GCLB defaults to 30s)"
grep -qF 'requestPath: "/v1/health"' <<<"$gke" \
  || fail "BackendConfig health check must target /v1/health (GCLB probes / by default, which 404s)"
grep -qF 'kind: ManagedCertificate' <<<"$gke" || fail "ManagedCertificate not rendered"
grep -qF 'kind: FrontendConfig' <<<"$gke" || fail "FrontendConfig not rendered"

# Fail-closed guards. Each of these MUST refuse to render.
guard() {
  local desc="$1"; shift
  if render "$@" >/dev/null 2>&1; then fail "$desc"; fi
}
guard "an HPA on the fs archive backend must fail (RWO volume caps it at 1 replica)" \
  --set autoscaling.server.enabled=true
guard "podDisruptionBudget.server.minAvailable at 1 replica must fail (undrainable pod)" \
  --set podDisruptionBudget.server.minAvailable=1
guard "a ManagedCertificate with no domains must fail (never leaves Provisioning)" \
  --set gke.enabled=true --set gke.managedCertificate.enabled=true
guard "externalSecrets with an empty data list must fail (would create an empty Secret)" \
  --set externalSecrets.enabled=true --set externalSecrets.projectID=p
guard "an unwired externalSecrets provider must fail rather than sync nothing" \
  --set externalSecrets.enabled=true --set externalSecrets.projectID=p \
  --set externalSecrets.provider=vault --set 'externalSecrets.data[0].secretKey=A' \
  --set 'externalSecrets.data[0].remoteRef=a'

# A PDB must appear once the fleet can actually lose a pod.
pdb="$(render --set server.archiveStore=s3 --set server.archiveS3.bucket=b \
  --set server.archiveS3.region=us-central1 --set server.replicas=2 \
  -s templates/pdb.yaml)"
grep -qF 'kind: PodDisruptionBudget' <<<"$pdb" \
  || fail "a multi-replica server must get a PodDisruptionBudget"

# LLM key mode. A hosted deployment (FLUIDBOX_REQUIRE_SSO=1) on the default
# "shared" mode is not degraded, it is NON-FUNCTIONAL: the facade answers 503
# tenant_llm_keys_required on every model call. These assertions pin the wiring
# and the two guards that stop the broken combinations from rendering at all.
tenant="$(render --set litellm.enabled=true --set litellm.database.enabled=true \
  --set litellm.image=ghcr.io/berriai/litellm-database:main-stable \
  --set llm.keyMode=tenant --set 'llm.tenant.models[0]=claude-haiku-4-5' \
  -s templates/server.yaml)"
grep -qF '{ name: FLUIDBOX_LLM_KEY_MODE, value: "tenant" }' <<<"$tenant" \
  || fail "llm.keyMode=tenant did not reach FLUIDBOX_LLM_KEY_MODE"
grep -qF '{ name: FLUIDBOX_LLM_TENANT_MODELS, value: "claude-haiku-4-5" }' <<<"$tenant" \
  || fail "llm.tenant.models did not reach FLUIDBOX_LLM_TENANT_MODELS"
lldb="$(render --set litellm.enabled=true --set litellm.database.enabled=true \
  --set litellm.image=ghcr.io/berriai/litellm-database:main-stable -s templates/litellm.yaml)"
grep -qF 'STORE_MODEL_IN_DB' <<<"$lldb" \
  || fail "litellm.database.enabled must set STORE_MODEL_IN_DB"
grep -qF 'key: "LITELLM_DATABASE_URL"' <<<"$lldb" \
  || fail "litellm database mode must read its OWN database URL, not the app's"
grep -qF '/health/readiness' <<<"$lldb" \
  || fail "litellm must have a readiness probe (rollouts otherwise serve upstream errors)"

guard "llm.keyMode=tenant against the STATELESS bundled LiteLLM must fail (/key/generate 404s)" \
  --set litellm.enabled=true --set llm.keyMode=tenant
guard "litellm.database.enabled on the non-database image variant must fail (no prisma, no key store)" \
  --set litellm.enabled=true --set litellm.database.enabled=true
guard "an unknown llm.keyMode must fail" --set llm.keyMode=bogus

# The dashboard needs a readiness probe or every rollout serves 502s while
# Next.js boots.
webout="$(render --set web.enabled=true -s templates/web.yaml)"
grep -qF 'readinessProbe' <<<"$webout" || fail "web Deployment lost its readinessProbe"

# Pre-upgrade migration gate. Three properties, each of which is silently
# wrong in a way no other test would catch.
mig="$(render --set migrationJob.enabled=true -s templates/migrate-job.yaml)"
grep -qF '"helm.sh/hook": pre-upgrade' <<<"$mig" \
  || fail "the migration Job must be a pre-upgrade hook (Helm has to WAIT for it, or it is not a gate)"
grep -qF 'pre-install' <<<"$mig" \
  && fail "pre-install would deadlock: the Secret it reads is created by a NORMAL chart resource, and hooks run first"
grep -qF '{ name: FLUIDBOX_MIGRATE_ONLY, value: "1" }' <<<"$mig" \
  || fail "the migration Job must set FLUIDBOX_MIGRATE_ONLY=1, or it starts serving instead of exiting"
# It must carry the SERVER's environment, not a hand-written subset - that is
# what makes it a config gate and not just a schema gate.
grep -qF '{ name: FLUIDBOX_BIND, value: "0.0.0.0:8787" }' <<<"$mig" \
  || fail "the migration Job must share the server environment (fluidbox.serverEnv)"
grep -qF '"helm.sh/hook-delete-policy": before-hook-creation' <<<"$mig" \
  || fail "hook-succeeded would delete the finished Job and with it the migration log"

# Pod Security Admission `restricted` requires allowPrivilegeEscalation=false
# and capabilities.drop=[ALL] on EVERY container, not just at pod level. A
# namespace labelled enforce=restricted refuses the pod otherwise, and the only
# clue is an admission warning on the Deployment.
psa="$(render --set litellm.enabled=true -s templates/litellm.yaml)"
grep -qF 'allowPrivilegeEscalation: false' <<<"$psa" \
  || fail "the litellm container must set allowPrivilegeEscalation=false (PSA restricted)"
grep -qF 'capabilities: { drop: ["ALL"] }' <<<"$psa" \
  || fail "the litellm container must drop ALL capabilities (PSA restricted)"

# The migration Job must run as the SERVER's ServiceAccount. As `default` it has
# no RBAC and emits a stream of "pods is forbidden" warnings that read like a
# broken deployment.
migsa="$(render --set migrationJob.enabled=true -s templates/migrate-job.yaml)"
grep -qF 'serviceAccountName: fluidbox-fluidbox-server' <<<"$migsa" \
  || fail "the migration Job must use the server ServiceAccount, not default"

echo "chart assertions: OK"
