#!/usr/bin/env bash
# §9 criterion 15 evidence: sandbox node capacity returns to ZERO after the
# idle window. Samples the sandbox nodegroup + nodes until empty (or timeout),
# writing a timestamped log the validation report can cite.
#
#   scripts/cloud/idle-scaledown-watch.sh            # default: wait up to 45m
#   TIMEOUT_MINS=90 scripts/cloud/idle-scaledown-watch.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

require_non_root
ensure_kubeconfig
TIMEOUT_MINS="${TIMEOUT_MINS:-45}"
EV=$(evidence_dir cloud-m1-scaledown)
LOG="$EV/idle-scaledown.log"

say "watching sandbox capacity (nodegroup 'sandbox', label fluidbox.dev/role=sandbox)"
echo "# idle scale-down watch started $(date -u +%FT%TZ) (timeout ${TIMEOUT_MINS}m)" | tee "$LOG"
END=$(( $(date +%s) + TIMEOUT_MINS * 60 ))
while :; do
  NOW=$(date -u +%FT%TZ)
  DESIRED=$(aws eks describe-nodegroup --cluster-name "$CLOUD_CLUSTER" --nodegroup-name sandbox \
    --query 'nodegroup.scalingConfig.desiredSize' --output text 2>/dev/null || echo "?")
  NODES=$(kubectl get nodes -l fluidbox.dev/role=sandbox --no-headers 2>/dev/null | wc -l | tr -d ' ')
  PODS=$(kubectl get pods -n "$CLOUD_SANDBOX_NS" --no-headers 2>/dev/null | wc -l | tr -d ' ')
  echo "$NOW desired=$DESIRED nodes=$NODES sandbox_pods=$PODS" | tee -a "$LOG"
  if [ "$DESIRED" = "0" ] && [ "$NODES" = "0" ]; then
    echo "# reached zero at $NOW" | tee -a "$LOG"
    ok "sandbox capacity at ZERO (evidence: $LOG)"
    exit 0
  fi
  [ "$(date +%s)" -ge "$END" ] && die "sandbox capacity did not reach zero within ${TIMEOUT_MINS}m" \
    "check cluster-autoscaler logs: kubectl logs -n kube-system deploy/cluster-autoscaler-aws-cluster-autoscaler" \
    "common cause: a lingering pod without the sandbox taint toleration pinned the node"
  sleep 60
done
