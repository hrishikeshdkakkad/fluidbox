#!/usr/bin/env bash
# The Kubernetes twin of `just doctor`: preflight the cluster + install
# prerequisites for the fluidbox K8s provider. Every ✗ prints its exact fix.
set -uo pipefail
NS="${1:-fluidbox}"
ok(){ printf "  \033[1;32m✓\033[0m %s\n" "$1"; }
no(){ printf "  \033[1;31m✗\033[0m %s\n  → %s\n" "$1" "$2"; FAIL=1; }
FAIL=0
command -v kubectl >/dev/null || { no "kubectl not found" "install kubectl"; exit 1; }
command -v helm >/dev/null || no "helm not found" "install helm 3.8+"
CTX=$(kubectl config current-context 2>/dev/null) && ok "kube context: $CTX" \
  || no "no current kube context" "kubectl config use-context <ctx>"
kubectl version -o json >/dev/null 2>&1 && ok "apiserver reachable" \
  || no "apiserver unreachable" "check your kubeconfig / cluster is up"
# Default StorageClass (PVC for archives).
if kubectl get sc -o jsonpath='{range .items[*]}{.metadata.annotations.storageclass\.kubernetes\.io/is-default-class}{"\n"}{end}' 2>/dev/null | grep -q true; then
  ok "a default StorageClass exists (archive PVC will bind)"
else
  no "no default StorageClass" "set one, or pass server.archivePvc.storageClass in values"
fi
# CNI enforcement is the load-bearing one — the boot probe fails closed, but
# warn early. kindnet (kind default) does NOT enforce.
if kubectl -n kube-system get ds 2>/dev/null | grep -qiE "calico|cilium|aws-node"; then
  ok "an enforcing-capable CNI is present (verify with 'helm test')"
else
  no "no Calico/Cilium/VPC-CNI DaemonSet seen" "install an enforcing CNI; kindnet does NOT enforce NetworkPolicy"
fi
# The credential Secret.
if kubectl -n "$NS" get secret fluidbox-secrets >/dev/null 2>&1; then
  ok "existing Secret fluidbox-secrets present in $NS"
else
  no "Secret fluidbox-secrets missing in $NS" \
     "kubectl -n $NS create secret generic fluidbox-secrets --from-literal=DATABASE_URL=... --from-literal=FLUIDBOX_ADMIN_TOKEN=... --from-literal=FLUIDBOX_CREDENTIAL_KEY=... --from-literal=LITELLM_MASTER_KEY=... --from-literal=ANTHROPIC_API_KEY=..."
fi
[ "$FAIL" = 0 ] && printf "\n\033[1;32mk8s preflight OK\033[0m\n" || printf "\n\033[1;31mfix the ✗ items above\033[0m\n"
exit "$FAIL"
