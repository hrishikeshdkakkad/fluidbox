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

echo "chart assertions: OK"
