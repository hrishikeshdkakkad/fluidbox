#!/usr/bin/env bash
# Local Kubernetes dev: a kind cluster with Calico (kindnet does NOT enforce
# NetworkPolicy, so the boot probe would correctly block runs on it), local
# images loaded, and fluidbox helm-installed with values/kind.yaml.
set -euo pipefail
CLUSTER="${KIND_CLUSTER:-fluidbox}"
NS="${FLUIDBOX_NS:-fluidbox}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v kind >/dev/null || { echo "install kind: https://kind.sigs.k8s.io"; exit 1; }
command -v helm >/dev/null || { echo "install helm 3.8+"; exit 1; }

if ! kind get clusters | grep -qx "$CLUSTER"; then
  echo "==> creating kind cluster '$CLUSTER' (disableDefaultCNI → Calico)"
  cat <<KIND | kind create cluster --name "$CLUSTER" --config -
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16"
KIND
  echo "==> installing Calico"
  kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml
  kubectl -n kube-system rollout status ds/calico-node --timeout=180s || true
fi

echo "==> building + loading images"
docker build -q -t fluidbox-server:dev -f "$ROOT/deploy/server.Dockerfile" "$ROOT"
docker build -q -t fluidbox-web:dev -f "$ROOT/deploy/web.Dockerfile" "$ROOT" 2>/dev/null || true
docker build -q -t fluidbox-workspaced:dev -f "$ROOT/deploy/workspaced.Dockerfile" "$ROOT"
for img in fluidbox-server:dev fluidbox-web:dev fluidbox-workspaced:dev fluidbox-sandbox-runner:dev; do
  docker image inspect "$img" >/dev/null 2>&1 && kind load docker-image --name "$CLUSTER" "$img" || true
done

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
echo "==> ensure the credential Secret exists (see 'just k8s-doctor $NS'), then:"
echo "    helm upgrade --install fluidbox $ROOT/deploy/helm/fluidbox -n $NS -f $ROOT/deploy/helm/fluidbox/values/kind.yaml"
echo "    helm test fluidbox -n $NS      # must PASS (+:8788 -:8787)"
echo "    kubectl -n $NS port-forward svc/fluidbox-fluidbox-server 8787:8787"
