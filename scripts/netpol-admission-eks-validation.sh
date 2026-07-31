#!/usr/bin/env bash
# EKS validation of the netpol startup-admission protocol against the REAL
# AWS VPC CNI `standard`-mode fail-open behavior (the race is NATIVE here —
# no simulation: every fresh pod's policy is programmed asynchronously).
#
# Phases (stand-in topology, chart-rendered policies, production fixtures —
# same as scripts/netpol-admission-validation.sh):
#   N1 (determination): a PRE-FIX-shaped pod (no gate) whose runner samples
#      forbidden egress once per second from its own t=0 — measuring whether
#      the fail-open window exposes REAL sandbox workloads (not just the
#      certification probe) and how long it lasts.
#   N2 (fix): the production gated pod — the netpol-gate must observe the
#      open network, hold the runner, release only after enforcement; the
#      runner's first instruction must find egress blocked.
#   N3 (certification): the OLD one-sample probe fails closed (the measured
#      cause of "every POST /v1/sessions is 503 on EKS"); the NEW bounded
#      observation probe converges and Succeeds.
#
# Safety: everything lives in ONE uniquely-named eksctl cluster tagged
# fluidbox-ephemeral=true + fluidbox-validation=k8s-network-admission.
# Teardown runs on EXIT (even on failure): eksctl delete + the two known
# EKS leak sweeps (detached VPC-CNI ENIs; the EKS-created cluster SG that is
# created OUTSIDE CloudFormation and otherwise holds the VPC), then an audit
# that must come back empty.
#
# Cost envelope: control plane $0.10/h + 1× t4g.small $0.0168/h + single NAT
# $0.045/h ⇒ ≈$0.17/h; a full run is ~1h ⇒ well under $1 (hard cap $40).
set -euo pipefail

REGION="${REGION:-us-east-1}"
RUN_ID="${RUN_ID:-$(date +%m%d%H%M)}"
CLUSTER="fbx-netadm-${RUN_ID}"
NS_CTRL=fbxval
NS_SANDBOX=fbxval-sandboxes
BUSYBOX=busybox:1.36
WAIT_SECS=60
LOG_DIR="${NETPOL_VAL_LOG_DIR:-$(mktemp -d /tmp/netpol-eks.XXXXXX)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0; declare -a RESULTS=()
SKIP_TEARDOWN="${SKIP_TEARDOWN:-0}"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
pass() { PASS=$((PASS+1)); RESULTS+=("PASS  $1"); printf '  \033[1;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); RESULTS+=("FAIL  $1"); printf '  \033[1;31mFAIL\033[0m %s\n' "$1"; }

for tool in aws eksctl kubectl helm jq cargo python3; do
  command -v "$tool" >/dev/null || { echo "missing: $tool"; exit 1; }
done

say "preflight: identity + existing clusters (read-only)"
aws sts get-caller-identity --output json | tee "$LOG_DIR/identity.json"
EXISTING=$(aws eks list-clusters --region "$REGION" --query 'clusters' --output text)
echo "existing clusters in $REGION: ${EXISTING:-<none>} (this run creates '$CLUSTER' and touches ONLY it)"

say "building production fixtures"
cargo build -q -p fluidbox-provider-k8s --example netpol_fixtures
FIX="$ROOT/target/debug/examples/netpol_fixtures"

# ── teardown + audit, guaranteed on exit ────────────────────────────────────
VPC_ID=""
teardown() {
  local rc=$?
  set +e
  if [ "$SKIP_TEARDOWN" = 1 ]; then
    echo "SKIP_TEARDOWN=1 — cluster '$CLUSTER' LEFT RUNNING (delete with: eksctl delete cluster --name $CLUSTER --region $REGION)"
    exit $rc
  fi
  say "TEARDOWN (always runs; exit code was $rc)"
  # No kubectl pre-clean: this validation creates no Services of type LB and
  # no PVCs, so nothing in the namespaces holds cloud resources — and a bare
  # kubectl here would hit whatever the CURRENT context is, which is unsafe
  # if another validation run switched it. The cluster delete removes it all.
  eksctl delete cluster --name "$CLUSTER" --region "$REGION" --disable-nodegroup-eviction --wait 2>&1 | tail -8

  # Known leak #1: detached VPC-CNI ENIs (GC race) hold subnets → DELETE_FAILED.
  if [ -n "$VPC_ID" ]; then
    for eni in $(aws ec2 describe-network-interfaces --region "$REGION" \
        --filters "Name=vpc-id,Values=$VPC_ID" "Name=status,Values=available" \
        --query 'NetworkInterfaces[].NetworkInterfaceId' --output text 2>/dev/null); do
      echo "sweeping detached ENI $eni"
      aws ec2 delete-network-interface --region "$REGION" --network-interface-id "$eni"
    done
    # Known leak #2: the EKS-created cluster SG (created outside CFN, holds the VPC).
    for sg in $(aws ec2 describe-security-groups --region "$REGION" \
        --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=eks-cluster-sg-${CLUSTER}-*" \
        --query 'SecurityGroups[].GroupId' --output text 2>/dev/null); do
      echo "sweeping cluster SG $sg"
      aws ec2 delete-security-group --region "$REGION" --group-id "$sg"
    done
    # If the VPC stack went DELETE_FAILED because of the above, retry it.
    for st in $(aws cloudformation list-stacks --region "$REGION" \
        --stack-status-filter DELETE_FAILED \
        --query "StackSummaries[?contains(StackName,'$CLUSTER')].StackName" --output text 2>/dev/null); do
      echo "retrying DELETE_FAILED stack $st"
      aws cloudformation delete-stack --region "$REGION" --stack-name "$st"
      aws cloudformation wait stack-delete-complete --region "$REGION" --stack-name "$st"
    done
  fi

  say "AUDIT — every line below must be empty"
  {
    echo "-- resources tagged fluidbox-run-id=$RUN_ID:"
    aws resourcegroupstaggingapi get-resources --region "$REGION" \
      --tag-filters "Key=fluidbox-run-id,Values=$RUN_ID" \
      --query 'ResourceTagMappingList[].ResourceARN' --output text
    echo "-- CFN stacks *$CLUSTER* (any status but DELETE_COMPLETE):"
    aws cloudformation list-stacks --region "$REGION" \
      --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE DELETE_FAILED DELETE_IN_PROGRESS ROLLBACK_COMPLETE \
      --query "StackSummaries[?contains(StackName,'$CLUSTER')].[StackName,StackStatus]" --output text
    if [ -n "$VPC_ID" ]; then
      echo "-- VPC $VPC_ID (must be gone):"
      aws ec2 describe-vpcs --region "$REGION" --vpc-ids "$VPC_ID" \
        --query 'Vpcs[].VpcId' --output text 2>/dev/null
      echo "-- ENIs in $VPC_ID:"
      aws ec2 describe-network-interfaces --region "$REGION" \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query 'NetworkInterfaces[].NetworkInterfaceId' --output text 2>/dev/null
    fi
    echo "-- NAT gateways for the cluster:"
    aws ec2 describe-nat-gateways --region "$REGION" \
      --filter "Name=state,Values=available,pending" \
      --query "NatGateways[?Tags[?Key=='fluidbox-run-id'&&Value=='$RUN_ID']].NatGatewayId" --output text
    echo "-- unattached EIPs tagged with the run:"
    aws ec2 describe-addresses --region "$REGION" \
      --query "Addresses[?AssociationId==null] | [?Tags[?Key=='fluidbox-run-id'&&Value=='$RUN_ID']].AllocationId" --output text
    echo "-- EKS clusters remaining:"
    aws eks list-clusters --region "$REGION" --query 'clusters[?contains(@,`fbx-netadm`)]' --output text
  } | tee "$LOG_DIR/teardown-audit.txt"
  exit $rc
}
trap teardown EXIT

say "creating ephemeral cluster '$CLUSTER' (~15 min; every resource tagged fluidbox-run-id=$RUN_ID)"
cat > "$LOG_DIR/cluster.yaml" <<YAML
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: $CLUSTER
  region: $REGION
  version: "1.33"
  tags:
    fluidbox-ephemeral: "true"
    fluidbox-validation: k8s-network-admission
    fluidbox-run-id: "$RUN_ID"
availabilityZones: [us-east-1b, us-east-1c]
vpc:
  nat: { gateway: Single }
addons:
  - name: vpc-cni
    configurationValues: |-
      enableNetworkPolicy: "true"
  - name: kube-proxy
  - name: coredns
managedNodeGroups:
  - name: ng-1
    amiFamily: AmazonLinux2023
    # t4g.medium: the validation pods are tiny, but ~1.3Gi allocatable on
    # t4g.small left no headroom over the EKS daemonsets + addons.
    instanceType: t4g.medium
    availabilityZones: [us-east-1b]
    desiredCapacity: 1
    minSize: 1
    maxSize: 1
    volumeSize: 20
    volumeType: gp3
    tags:
      fluidbox-ephemeral: "true"
      fluidbox-run-id: "$RUN_ID"
YAML
eksctl create cluster -f "$LOG_DIR/cluster.yaml" 2>&1 | tail -12

say "resource inventory (post-create)"
VPC_ID=$(aws eks describe-cluster --region "$REGION" --name "$CLUSTER" \
  --query 'cluster.resourcesVpcConfig.vpcId' --output text)
{
  echo "run-id: $RUN_ID  cluster: $CLUSTER  vpc: $VPC_ID  region: $REGION"
  echo "-- CFN stacks:"
  aws cloudformation list-stacks --region "$REGION" --stack-status-filter CREATE_COMPLETE \
    --query "StackSummaries[?contains(StackName,'$CLUSTER')].StackName" --output text
  echo "-- tagged resources:"
  aws resourcegroupstaggingapi get-resources --region "$REGION" \
    --tag-filters "Key=fluidbox-run-id,Values=$RUN_ID" \
    --query 'ResourceTagMappingList[].ResourceARN' --output text
  echo "-- NAT:"
  aws ec2 describe-nat-gateways --region "$REGION" \
    --filter "Name=vpc-id,Values=$VPC_ID" --query 'NatGateways[].NatGatewayId' --output text
  echo "-- nodes:"
  kubectl get nodes -o wide | sed 's/^/   /'
} | tee "$LOG_DIR/inventory.txt"

say "verifying the netpol nodeagent is enforcing (standard mode)"
kubectl -n kube-system get ds aws-node -o jsonpath='{.spec.template.spec.containers[*].name}' | tr ' ' '\n' | sed 's/^/  ds container: /'
kubectl -n kube-system get pods -l k8s-app=aws-node -o name | head -3

say "topology: stand-in server + chart-rendered policies"
kubectl create namespace "$NS_CTRL" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
helm template fluidbox "$ROOT/deploy/helm/fluidbox" -n "$NS_CTRL" \
  -s templates/sandbox.yaml \
  --set sandbox.namespace="$NS_SANDBOX" \
  --set sandbox.quota.enabled=false > "$LOG_DIR/rendered-sandbox.yaml"
kubectl apply -f "$LOG_DIR/rendered-sandbox.yaml" >/dev/null
kubectl -n "$NS_CTRL" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: fbxval-server
  labels: { app.kubernetes.io/name: fluidbox, app.kubernetes.io/component: server }
spec:
  securityContext: { runAsNonRoot: true, runAsUser: 10001, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: listeners
      image: $BUSYBOX
      command: ["/bin/sh","-c","httpd -p 8787; httpd -p 8788; exec tail -f /dev/null"]
      securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] } }
---
apiVersion: v1
kind: Service
metadata: { name: fbxval-internal }
spec:
  selector: { app.kubernetes.io/name: fluidbox, app.kubernetes.io/component: server }
  ports: [ { port: 8788, targetPort: 8788 } ]
---
apiVersion: v1
kind: Service
metadata: { name: fbxval-public }
spec:
  selector: { app.kubernetes.io/name: fluidbox, app.kubernetes.io/component: server }
  ports: [ { port: 8787, targetPort: 8787 } ]
YAML
kubectl -n "$NS_CTRL" wait --for=condition=Ready pod/fbxval-server --timeout=180s >/dev/null
INT_IP=$(kubectl -n "$NS_CTRL" get svc fbxval-internal -o jsonpath='{.spec.clusterIP}')
PUB_IP=$(kubectl -n "$NS_CTRL" get svc fbxval-public -o jsonpath='{.spec.clusterIP}')
echo "  internal=$INT_IP:8788 public=$PUB_IP:8787  (logs: $LOG_DIR)"

# Sandbox-shaped pod builder (see the kind script for the stubbing contract).
WINDOW_PROBE='echo "winprobe: runner started t=$(date +%s)"; end=$(( $(date +%s) + 120 )); openseen=0; while :; do t=$(date +%s); p=blocked; nc -z -w 1 PUBIP 8787 && p=OPEN; w=blocked; nc -z -w 1 1.1.1.1 443 && w=OPEN; echo "winprobe t=$t public=$p internet=$w"; if [ "$p" = OPEN ] || [ "$w" = OPEN ]; then openseen=1; fi; if [ "$p" = blocked ] && [ "$w" = blocked ]; then echo "winprobe: converged t=$t openseen=$openseen"; break; fi; if [ "$t" -ge "$end" ]; then echo "winprobe: DEADLINE still-open openseen=$openseen"; break; fi; sleep 1; done; sleep 2'
RUNNER_PROBE='echo "runner: started t=$(date +%s)"; p=blocked; nc -z -w 2 PUBIP 8787 && p=OPEN; w=blocked; nc -z -w 2 1.1.1.1 443 && w=OPEN; a=fail; nc -z -w 2 INTIP 8788 && a=ok; echo "runner: forbidden public:8787=$p internet:443=$w allowed internal:8788=$a"; sleep 2'
sandbox_pod_json() { # $1 name, $2 with_gate (1|0), $3 runner script
  local rs=${3//PUBIP/$PUB_IP}; rs=${rs//INTIP/$INT_IP}
  FLUIDBOX_COLLECTOR_IMAGE="$BUSYBOX" FLUIDBOX_NETPOL_PROBE_IMAGE="$BUSYBOX" \
    "$FIX" sandbox-pod "$INT_IP" 8788 "$PUB_IP" 8787 "$WAIT_SECS" \
    | jq --arg name "$1" --arg rs "$rs" --arg img "$BUSYBOX" '
        .metadata.name = $name
        | .spec.initContainers[-1].image = $img
        | .spec.initContainers[-1].command = ["/bin/sh","-c","echo workspace-init: stub"]
        | .spec.initContainers[-1].env = []
        | .spec.initContainers[-1].resources = {"requests":{"cpu":"10m","memory":"16Mi"},"limits":{"cpu":"200m","memory":"64Mi"}}
        | .spec.containers[0].image = $img
        | .spec.containers[0].command = ["/bin/sh","-c",$rs]
        | .spec.containers[0].resources = {"requests":{"cpu":"50m","memory":"64Mi"},"limits":{"cpu":"500m","memory":"256Mi"}}
        | .spec.containers[1].image = $img
        | .spec.containers[1].command = ["/bin/sh","-c","sleep 15"]
      ' \
    | if [ "$2" = 1 ]; then cat; else jq 'del(.spec.initContainers[0])'; fi
}
wait_runner_done() { # $1 pod, $2 timeout_s
  local end=$(( $(date +%s) + $2 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    local st
    st=$(kubectl -n "$NS_SANDBOX" get pod "$1" -o jsonpath='{.status.containerStatuses[?(@.name=="runner")].state.terminated.exitCode}' 2>/dev/null || true)
    [ -n "$st" ] && return 0
    sleep 2
  done
  return 1
}

say "phase N1 ×2: DETERMINATION — does the native fail-open window expose a real (pre-fix) sandbox workload?"
for i in 1 2; do
  POD="fbxval-n1-$i"
  sandbox_pod_json "$POD" 0 "$WINDOW_PROBE" | kubectl -n "$NS_SANDBOX" apply -f - >/dev/null
  wait_runner_done "$POD" 200 || true
  LOG=$(kubectl -n "$NS_SANDBOX" logs "$POD" -c runner 2>/dev/null || true)
  echo "$LOG" > "$LOG_DIR/n1-$i.log"
  echo "$LOG" | sed 's/^/    /' | head -30
  OPEN_SAMPLES=$(echo "$LOG" | grep -c '=OPEN' || true)
  if echo "$LOG" | grep -q 'converged.*openseen=1'; then
    FIRST=$(echo "$LOG" | grep -m1 'winprobe: runner started' | sed 's/.*t=//')
    CONV=$(echo "$LOG" | grep -m1 'winprobe: converged' | sed 's/.*t=\([0-9]*\).*/\1/')
    pass "[N1.$i] REAL WORKLOADS AFFECTED: runner saw open egress ($OPEN_SAMPLES open sample(s)) for $((CONV-FIRST))s before policy landed"
  elif echo "$LOG" | grep -q 'converged.*openseen=0'; then
    pass "[N1.$i] window not observed from this pod (policy landed before runner start) — samples: $OPEN_SAMPLES open"
  else
    fail "[N1.$i] runner never converged: $(echo "$LOG" | tail -2 | tr '\n' ' ')"
  fi
  kubectl -n "$NS_SANDBOX" delete pod "$POD" --ignore-not-found >/dev/null
done

say "phase N2 ×3: THE FIX — gated production pod on the native race"
for i in 1 2 3; do
  POD="fbxval-n2-$i"
  sandbox_pod_json "$POD" 1 "$RUNNER_PROBE" | kubectl -n "$NS_SANDBOX" apply -f - >/dev/null
  if ! wait_runner_done "$POD" 200; then
    fail "[N2.$i] runner never completed"
    kubectl -n "$NS_SANDBOX" describe pod "$POD" | tail -15
    kubectl -n "$NS_SANDBOX" delete pod "$POD" --ignore-not-found >/dev/null
    continue
  fi
  GATE_LOG=$(kubectl -n "$NS_SANDBOX" logs "$POD" -c netpol-gate 2>/dev/null || true)
  REPORT=$(kubectl -n "$NS_SANDBOX" logs "$POD" -c runner 2>/dev/null | grep '^runner: forbidden' || true)
  { echo "$GATE_LOG"; echo "$REPORT"; } > "$LOG_DIR/n2-$i.log"
  OPEN_OBS=$(echo "$GATE_LOG" | grep -c 'neg=open' || true)
  OBS=$(echo "$GATE_LOG" | grep -c '^obs' || true)
  if echo "$GATE_LOG" | grep -q '^enforced' \
     && echo "$REPORT" | grep -q 'public:8787=blocked' \
     && echo "$REPORT" | grep -q 'internet:443=blocked' \
     && echo "$REPORT" | grep -q 'internal:8788=ok'; then
    pass "[N2.$i] gate held through $OBS observation(s) ($OPEN_OBS saw the open net), then runner egress blocked — $REPORT"
  else
    fail "[N2.$i] gate: $(echo "$GATE_LOG" | tail -2 | tr '\n' ' ') runner: $REPORT"
  fi
  kubectl -n "$NS_SANDBOX" delete pod "$POD" --ignore-not-found >/dev/null
done

say "phase N3 ×2: CERTIFICATION — old one-sample probe vs the shipped observation probe, natively"
OLD_SCRIPT="set -u; if nc -z -w 4 $INT_IP 8788; then echo pos-ok; else echo pos-fail; exit 2; fi; if nc -z -w 4 $PUB_IP 8787; then echo neg-fail; exit 3; else echo neg-ok; fi; echo enforced"
for i in 1 2; do
  # old
  POD="fbxval-n3-old-$i"
  FLUIDBOX_NETPOL_PROBE_IMAGE="$BUSYBOX" "$FIX" probe-pod "$POD" "$BUSYBOX" "$INT_IP" 8788 "$PUB_IP" 8787 "$WAIT_SECS" \
    | jq --arg s "$OLD_SCRIPT" --arg n "$POD" '.metadata.name=$n | .spec.containers[0].command=["/bin/sh","-c",$s] | .spec.containers[0].resources = {"requests":{"cpu":"10m","memory":"16Mi"},"limits":{"cpu":"200m","memory":"64Mi"}}' \
    | kubectl -n "$NS_SANDBOX" apply -f - >/dev/null
  for _ in $(seq 1 60); do
    PHASE=$(kubectl -n "$NS_SANDBOX" get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    [ "$PHASE" = "Failed" ] || [ "$PHASE" = "Succeeded" ] && break
    sleep 2
  done
  CODE=$(kubectl -n "$NS_SANDBOX" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || true)
  kubectl -n "$NS_SANDBOX" logs "$POD" > "$LOG_DIR/n3-old-$i.log" 2>/dev/null || true
  if [ "$PHASE" = "Failed" ] && { [ "$CODE" = "3" ] || [ "$CODE" = "2" ]; }; then
    pass "[N3.$i-old] pre-fix probe races and loses natively: phase=$PHASE exit=$CODE (the 503 cause)"
  elif [ "$PHASE" = "Succeeded" ]; then
    pass "[N3.$i-old] pre-fix probe got lucky this round (policy landed first) — phase=$PHASE (race, not determinism)"
  else
    fail "[N3.$i-old] unexpected: phase=$PHASE exit=$CODE"
  fi
  kubectl -n "$NS_SANDBOX" delete pod "$POD" --ignore-not-found >/dev/null

  # new
  POD="fbxval-n3-new-$i"
  T0=$(date +%s)
  FLUIDBOX_NETPOL_PROBE_IMAGE="$BUSYBOX" "$FIX" probe-pod "$POD" "$BUSYBOX" "$INT_IP" 8788 "$PUB_IP" 8787 "$WAIT_SECS" \
    | jq --arg n "$POD" '.metadata.name=$n | .spec.containers[0].resources = {"requests":{"cpu":"10m","memory":"16Mi"},"limits":{"cpu":"200m","memory":"64Mi"}}' \
    | kubectl -n "$NS_SANDBOX" apply -f - >/dev/null
  for _ in $(seq 1 80); do
    PHASE=$(kubectl -n "$NS_SANDBOX" get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    [ "$PHASE" = "Failed" ] || [ "$PHASE" = "Succeeded" ] && break
    sleep 2
  done
  T1=$(date +%s)
  LOGS=$(kubectl -n "$NS_SANDBOX" logs "$POD" 2>/dev/null || true); echo "$LOGS" > "$LOG_DIR/n3-new-$i.log"
  OBS=$(echo "$LOGS" | grep -c '^obs' || true)
  if [ "$PHASE" = "Succeeded" ] && echo "$LOGS" | grep -q '^enforced'; then
    pass "[N3.$i-new] shipped probe certifies in $((T1-T0))s over $OBS observation(s) — the gate can now pass on EKS"
  else
    fail "[N3.$i-new] expected Succeeded, got phase=$PHASE ($(echo "$LOGS" | tail -1))"
  fi
  kubectl -n "$NS_SANDBOX" delete pod "$POD" --ignore-not-found >/dev/null
done

say "summary"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo "  logs: $LOG_DIR"
[ "$FAIL" -eq 0 ] && echo "  ALL $PASS ASSERTIONS PASSED" || echo "  $FAIL FAILED / $PASS passed"
# teardown + audit run via the EXIT trap
[ "$FAIL" -eq 0 ]
