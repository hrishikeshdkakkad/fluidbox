#!/usr/bin/env bash
# Live validation of the netpol startup-admission protocol on a kind cluster
# with an ENFORCING CNI (Calico — kind's default kindnet does not enforce
# NetworkPolicy at all).
#
# What it proves, with the PRODUCTION bytes (script + pod shapes come from
# `cargo run -p fluidbox-provider-k8s --example netpol_fixtures`, policies
# from `helm template … -s templates/sandbox.yaml`):
#
#   A  (×N) steady state, repeatedly: a gated sandbox-shaped pod starts, the
#      netpol-gate observes enforcement immediately, and the runner's FIRST
#      instruction finds forbidden egress (public :8787, internet 1.1.1.1:443)
#      BLOCKED while allowed traffic (internal :8788) works.
#   B  (×N) the admission RACE, simulated: the pod is created while the
#      namespace has NO NetworkPolicies (the fail-open analog of AWS VPC CNI
#      `standard` mode programming policy asynchronously); policies are
#      applied seconds later. The gate must OBSERVE the open network (neg=open
#      in its log), HOLD the runner, then release only after enforcement — and
#      the runner's first instruction must find egress blocked. Runner
#      startedAt must be AFTER the policy-apply timestamp.
#   B0 the vulnerability, reproduced: the same pod WITHOUT the gate (pre-fix
#      shape) created in the same window reports FORBIDDEN EGRESS OPEN from
#      the runner — the reason the gate exists.
#   C  the certification probe: the OLD single-t=0-sample script fails closed
#      (exit 3) under late-applied policy — the measured cause of "every
#      POST /v1/sessions is 503 on EKS" — while the NEW bounded observation
#      probe converges and Succeeds under identical conditions.
#   D  the bound: with policies never applied, the gate fails CLOSED with
#      exit 3 at its deadline (no runner start, no hang).
#
# Usage: scripts/netpol-admission-validation.sh [--keep] [--iterations N]
# Requires: kind, kubectl, helm, jq, docker (colima or Docker Desktop), cargo.
set -euo pipefail

KEEP=0
ITER=5
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1 ;;
    --iterations) ITER="$2"; shift ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
  shift
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER="${KIND_CLUSTER:-fbx-netadm-val}"
NS_CTRL=fbxval
NS_SANDBOX=fbxval-sandboxes
BUSYBOX=busybox:1.36
RACE_ITER=3
WAIT_SECS=60
LOG_DIR="${NETPOL_VAL_LOG_DIR:-$(mktemp -d /tmp/netpol-val.XXXXXX)}"
PASS=0; FAIL=0; declare -a RESULTS=()

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
pass() { PASS=$((PASS+1)); RESULTS+=("PASS  $1"); printf '  \033[1;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); RESULTS+=("FAIL  $1"); printf '  \033[1;31mFAIL\033[0m %s\n' "$1"; }

for tool in kind kubectl helm jq docker cargo python3; do
  command -v "$tool" >/dev/null || { echo "missing: $tool"; exit 1; }
done

# Prefer colima's socket if the default daemon is unreachable (macOS setups
# where Docker Desktop owns /var/run/docker.sock but is not running).
if ! docker info >/dev/null 2>&1; then
  if [ -S "$HOME/.colima/default/docker.sock" ]; then
    export DOCKER_HOST="unix://$HOME/.colima/default/docker.sock"
  fi
fi
docker info >/dev/null 2>&1 || { echo "no reachable docker daemon"; exit 1; }

say "building the production fixture generator"
cargo build -q -p fluidbox-provider-k8s --example netpol_fixtures
FIX="$ROOT/target/debug/examples/netpol_fixtures"

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  say "creating kind cluster '$CLUSTER' (disableDefaultCNI → Calico)"
  # No --wait: with disableDefaultCNI the node cannot go Ready until the CNI
  # below is applied, so a readiness wait here would always time out.
  cat <<KIND | kind create cluster --name "$CLUSTER" --config -
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16"
KIND
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null
# Idempotent on rerun: apply is a no-op when Calico is already installed.
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml >/dev/null
kubectl -n kube-system rollout status ds/calico-node --timeout=240s
# Preload busybox via a docker-save archive: `kind load docker-image` trips on
# containerd-snapshotter multi-platform manifests ("content digest … not
# found"), while a saved archive carries only the local platform. Best-effort
# — on failure the node pulls the tiny image from the registry itself.
docker image inspect "$BUSYBOX" >/dev/null 2>&1 || docker pull "$BUSYBOX" >/dev/null
BBTAR=$(mktemp /tmp/busybox.XXXXXX.tar)
if docker save "$BUSYBOX" -o "$BBTAR" && kind load image-archive "$BBTAR" --name "$CLUSTER" >/dev/null 2>&1; then
  echo "  preloaded $BUSYBOX onto the node"
else
  echo "  preload failed; the node will pull $BUSYBOX from the registry"
fi
rm -f "$BBTAR"

say "topology: control-plane stand-in ($NS_CTRL) + sandbox namespace ($NS_SANDBOX) with the chart's rendered policies"
kubectl create namespace "$NS_CTRL" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# The REAL policy bytes: rendered from the chart with the release namespace
# this validation uses, so the namespaceSelector/podSelector pairs are exactly
# what production applies. Quota off — orthogonal to netpol.
render_policies() {
  helm template fluidbox "$ROOT/deploy/helm/fluidbox" -n "$NS_CTRL" \
    -s templates/sandbox.yaml \
    --set sandbox.namespace="$NS_SANDBOX" \
    --set sandbox.quota.enabled=false
}
render_policies > "$LOG_DIR/rendered-sandbox.yaml"
kubectl apply -f "$LOG_DIR/rendered-sandbox.yaml" >/dev/null

# Stand-in "server": the chart's Service selector labels, two busybox httpd
# listeners on the real ports. Reachability of BOTH ports is therefore known
# independently of policy — "blocked" is evidence of policy, not a dead host.
kubectl -n "$NS_CTRL" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: fbxval-server
  labels:
    app.kubernetes.io/name: fluidbox
    app.kubernetes.io/component: server
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
kubectl -n "$NS_CTRL" wait --for=condition=Ready pod/fbxval-server --timeout=120s >/dev/null
INT_IP=$(kubectl -n "$NS_CTRL" get svc fbxval-internal -o jsonpath='{.spec.clusterIP}')
PUB_IP=$(kubectl -n "$NS_CTRL" get svc fbxval-public -o jsonpath='{.spec.clusterIP}')
echo "  internal=$INT_IP:8788 public=$PUB_IP:8787  (logs: $LOG_DIR)"

# The two NetworkPolicy objects the race phases remove/apply.
yq_policies() { # extract just the NetworkPolicies from the rendered file
  python3 - "$LOG_DIR/rendered-sandbox.yaml" <<'PY'
import sys
docs = open(sys.argv[1]).read().split("\n---")
for d in docs:
    if "kind: NetworkPolicy" in d:
        print(d.strip("\n"))
        print("---")
PY
}
yq_policies > "$LOG_DIR/policies.yaml"

policies_delete() {
  kubectl -n "$NS_SANDBOX" delete networkpolicy fluidbox-sandbox-default-deny fluidbox-sandbox-egress --ignore-not-found >/dev/null
}
policies_apply() { kubectl apply -f "$LOG_DIR/policies.yaml" >/dev/null; }

# Production sandbox pod (gate + workspace-init + runner + collector) with the
# non-gate workloads stubbed to busybox (images/commands only — placement,
# ordering, env routing and securityContext stay exactly as build_pod emits).
# The runner's stub is the ADVERSARY: its very first instruction attempts the
# forbidden egress a hostile agent would.
RUNNER_PROBE='echo "runner: started t=$(date +%s)"; p=blocked; nc -z -w 2 PUBIP 8787 && p=OPEN; w=blocked; nc -z -w 2 1.1.1.1 443 && w=OPEN; a=fail; nc -z -w 2 INTIP 8788 && a=ok; echo "runner: forbidden public:8787=$p internet:443=$w allowed internal:8788=$a"; sleep 2'
sandbox_pod_json() { # $1 = pod name, $2 = with_gate (1|0)
  local name="$1" with_gate="$2"
  local runner_script=${RUNNER_PROBE//PUBIP/$PUB_IP}
  runner_script=${runner_script//INTIP/$INT_IP}
  FLUIDBOX_COLLECTOR_IMAGE="$BUSYBOX" FLUIDBOX_NETPOL_PROBE_IMAGE="$BUSYBOX" \
    "$FIX" sandbox-pod "$INT_IP" 8788 "$PUB_IP" 8787 "$WAIT_SECS" \
    | jq --arg name "$name" --arg rs "$runner_script" --arg img "$BUSYBOX" '
        .metadata.name = $name
        | .spec.initContainers[-1].image = $img
        | .spec.initContainers[-1].command = ["/bin/sh","-c","echo workspace-init: stub fetch; sleep 1"]
        | .spec.initContainers[-1].env = []
        | .spec.containers[0].image = $img
        | .spec.containers[0].command = ["/bin/sh","-c",$rs]
        | .spec.containers[0].resources = {"requests":{"cpu":"50m","memory":"64Mi"},"limits":{"cpu":"500m","memory":"256Mi"}}
        | .spec.containers[1].image = $img
        | .spec.containers[1].command = ["/bin/sh","-c","sleep 15"]
      ' \
    | if [ "$with_gate" = 1 ]; then cat; else jq 'del(.spec.initContainers[0])'; fi
}

runner_report() { # $1 pod — the runner's first-instruction egress report line
  kubectl -n "$NS_SANDBOX" logs "$1" -c runner 2>/dev/null | grep '^runner: forbidden' || true
}
runner_started_epoch() { # $1 pod
  local t
  t=$(kubectl -n "$NS_SANDBOX" get pod "$1" -o jsonpath='{.status.containerStatuses[?(@.name=="runner")].state.running.startedAt}' 2>/dev/null)
  [ -z "$t" ] && t=$(kubectl -n "$NS_SANDBOX" get pod "$1" -o jsonpath='{.status.containerStatuses[?(@.name=="runner")].state.terminated.startedAt}' 2>/dev/null)
  [ -z "$t" ] && { echo 0; return; }
  python3 -c "import datetime,sys; print(int(datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')).timestamp()))" "$t"
}
wait_runner_done() { # $1 pod, $2 timeout_s — until the runner container terminated
  local end=$(( $(date +%s) + $2 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    local st
    st=$(kubectl -n "$NS_SANDBOX" get pod "$1" -o jsonpath='{.status.containerStatuses[?(@.name=="runner")].state.terminated.exitCode}' 2>/dev/null || true)
    [ -n "$st" ] && return 0
    sleep 2
  done
  return 1
}

say "phase A: steady state ×$ITER — gate admits immediately, forbidden egress blocked, allowed traffic works"
for i in $(seq 1 "$ITER"); do
  POD="fbxval-a$i"
  T0=$(date +%s)
  sandbox_pod_json "$POD" 1 | kubectl -n "$NS_SANDBOX" apply -f - >/dev/null
  if ! wait_runner_done "$POD" 120; then
    fail "[A$i] runner never completed"; kubectl -n "$NS_SANDBOX" describe pod "$POD" | tail -20; continue
  fi
  T1=$(date +%s)
  GATE_LOG=$(kubectl -n "$NS_SANDBOX" logs "$POD" -c netpol-gate 2>/dev/null || true)
  REPORT=$(runner_report "$POD")
  echo "$GATE_LOG" > "$LOG_DIR/a$i-gate.log"; echo "$REPORT" >> "$LOG_DIR/a$i-gate.log"
  if echo "$GATE_LOG" | grep -q '^enforced' \
     && echo "$REPORT" | grep -q 'public:8787=blocked' \
     && echo "$REPORT" | grep -q 'internet:443=blocked' \
     && echo "$REPORT" | grep -q 'internal:8788=ok'; then
    pass "[A$i] $((T1-T0))s end-to-end; $(echo "$GATE_LOG" | grep -c '^obs') gate observation(s); $REPORT"
  else
    fail "[A$i] gate/log mismatch — gate: $(echo "$GATE_LOG" | tail -2 | tr '\n' ' ') runner: $REPORT"
  fi
  kubectl -n "$NS_SANDBOX" delete pod "$POD" --ignore-not-found >/dev/null
done

say "phase B0: the VULNERABILITY, reproduced — pre-fix pod (no gate) created while policies are absent"
policies_delete
sleep 2
POD=fbxval-b0
sandbox_pod_json "$POD" 0 | kubectl -n "$NS_SANDBOX" apply -f - >/dev/null
wait_runner_done "$POD" 90 || true
REPORT=$(runner_report "$POD"); echo "$REPORT" > "$LOG_DIR/b0-runner.log"
if echo "$REPORT" | grep -q 'public:8787=OPEN'; then
  pass "[B0] pre-fix shape leaks: runner's first instruction reached forbidden targets — $REPORT"
else
  fail "[B0] expected the unprotected runner to see an open network, got: $REPORT"
fi
kubectl -n "$NS_SANDBOX" delete pod "$POD" --ignore-not-found >/dev/null

say "phase B: the RACE ×$RACE_ITER — pod created before policy exists; gate must hold the runner until enforcement"
for i in $(seq 1 "$RACE_ITER"); do
  POD="fbxval-b$i"
  policies_delete
  sleep 2
  sandbox_pod_json "$POD" 1 | kubectl -n "$NS_SANDBOX" apply -f - >/dev/null
  sleep 8   # let the gate observe the open network for a few iterations
  MID=$(kubectl -n "$NS_SANDBOX" get pod "$POD" -o jsonpath='{.status.containerStatuses[?(@.name=="runner")].state.waiting.reason}' 2>/dev/null || true)
  APPLY_TS=$(date +%s)
  policies_apply
  if ! wait_runner_done "$POD" 120; then
    fail "[B$i] runner never completed after policies applied"; continue
  fi
  GATE_LOG=$(kubectl -n "$NS_SANDBOX" logs "$POD" -c netpol-gate 2>/dev/null || true)
  REPORT=$(runner_report "$POD")
  STARTED=$(runner_started_epoch "$POD")
  { echo "$GATE_LOG"; echo "runner startedAt epoch: $STARTED (policies applied: $APPLY_TS)"; echo "$REPORT"; } > "$LOG_DIR/b$i-gate.log"
  OPEN_OBS=$(echo "$GATE_LOG" | grep -c 'neg=open' || true)
  if [ "$OPEN_OBS" -ge 1 ] \
     && echo "$GATE_LOG" | grep -q '^enforced' \
     && [ -n "$MID" ] \
     && [ "$STARTED" -ge "$APPLY_TS" ] \
     && echo "$REPORT" | grep -q 'public:8787=blocked' \
     && echo "$REPORT" | grep -q 'internet:443=blocked' \
     && echo "$REPORT" | grep -q 'internal:8788=ok'; then
    pass "[B$i] gate observed open net ${OPEN_OBS}×, runner held (waiting=$MID), started ${STARTED}s ≥ apply ${APPLY_TS}s, then egress blocked"
  else
    fail "[B$i] open_obs=$OPEN_OBS mid_waiting='$MID' started=$STARTED apply=$APPLY_TS report='$REPORT'"
  fi
  kubectl -n "$NS_SANDBOX" delete pod "$POD" --ignore-not-found >/dev/null
done

say "phase C: certification probe — old t=0 sample fails closed; new bounded observation converges (policy applied late)"
# C-old: the exact pre-fix script (one sample per assertion at t=0).
policies_delete
sleep 2
OLD_SCRIPT="set -u; if nc -z -w 4 $INT_IP 8788; then echo pos-ok; else echo pos-fail; exit 2; fi; if nc -z -w 4 $PUB_IP 8787; then echo neg-fail; exit 3; else echo neg-ok; fi; echo enforced"
FLUIDBOX_NETPOL_PROBE_IMAGE="$BUSYBOX" "$FIX" probe-pod fbxval-c-old "$BUSYBOX" "$INT_IP" 8788 "$PUB_IP" 8787 "$WAIT_SECS" \
  | jq --arg s "$OLD_SCRIPT" '.metadata.name="fbxval-c-old" | .spec.containers[0].command=["/bin/sh","-c",$s]' \
  | kubectl -n "$NS_SANDBOX" apply -f - >/dev/null
( sleep 10; policies_apply ) &
LATE_APPLY_PID=$!
for _ in $(seq 1 45); do
  PHASE=$(kubectl -n "$NS_SANDBOX" get pod fbxval-c-old -o jsonpath='{.status.phase}' 2>/dev/null || true)
  [ "$PHASE" = "Failed" ] || [ "$PHASE" = "Succeeded" ] && break
  sleep 2
done
CODE=$(kubectl -n "$NS_SANDBOX" get pod fbxval-c-old -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || true)
kubectl -n "$NS_SANDBOX" logs fbxval-c-old > "$LOG_DIR/c-old.log" 2>/dev/null || true
if [ "$PHASE" = "Failed" ] && [ "$CODE" = "3" ]; then
  pass "[C-old] pre-fix probe under late policy: phase=$PHASE exit=$CODE (the measured EKS 503 cause, reproduced)"
else
  fail "[C-old] expected Failed/exit 3, got phase=$PHASE exit=$CODE"
fi
wait "$LATE_APPLY_PID" 2>/dev/null || true
kubectl -n "$NS_SANDBOX" delete pod fbxval-c-old --ignore-not-found >/dev/null

# C-new: identical late-policy conditions, the SHIPPED observation script.
policies_delete
sleep 2
T0=$(date +%s)
FLUIDBOX_NETPOL_PROBE_IMAGE="$BUSYBOX" "$FIX" probe-pod fbxval-c-new "$BUSYBOX" "$INT_IP" 8788 "$PUB_IP" 8787 "$WAIT_SECS" \
  | kubectl -n "$NS_SANDBOX" apply -f - >/dev/null
( sleep 10; policies_apply ) &
LATE_APPLY_PID=$!
for _ in $(seq 1 60); do
  PHASE=$(kubectl -n "$NS_SANDBOX" get pod fbxval-c-new -o jsonpath='{.status.phase}' 2>/dev/null || true)
  [ "$PHASE" = "Failed" ] || [ "$PHASE" = "Succeeded" ] && break
  sleep 2
done
T1=$(date +%s)
LOGS=$(kubectl -n "$NS_SANDBOX" logs fbxval-c-new 2>/dev/null || true); echo "$LOGS" > "$LOG_DIR/c-new.log"
OPEN_OBS=$(echo "$LOGS" | grep -c 'neg=open' || true)
if [ "$PHASE" = "Succeeded" ] && [ "$OPEN_OBS" -ge 1 ] && echo "$LOGS" | grep -q '^enforced'; then
  pass "[C-new] shipped probe converged in $((T1-T0))s after observing the open network ${OPEN_OBS}× — certification now passes where the old probe 503'd"
else
  fail "[C-new] expected Succeeded with observed transition, got phase=$PHASE open_obs=$OPEN_OBS"
fi
wait "$LATE_APPLY_PID" 2>/dev/null || true
kubectl -n "$NS_SANDBOX" delete pod fbxval-c-new --ignore-not-found >/dev/null

say "phase D: the bound — policies never applied; gate must fail CLOSED with exit 3 at its deadline"
policies_delete
sleep 2
T0=$(date +%s)
FLUIDBOX_NETPOL_PROBE_IMAGE="$BUSYBOX" "$FIX" probe-pod fbxval-d "$BUSYBOX" "$INT_IP" 8788 "$PUB_IP" 8787 15 \
  | kubectl -n "$NS_SANDBOX" apply -f - >/dev/null
for _ in $(seq 1 40); do
  PHASE=$(kubectl -n "$NS_SANDBOX" get pod fbxval-d -o jsonpath='{.status.phase}' 2>/dev/null || true)
  [ "$PHASE" = "Failed" ] || [ "$PHASE" = "Succeeded" ] && break
  sleep 2
done
T1=$(date +%s)
CODE=$(kubectl -n "$NS_SANDBOX" get pod fbxval-d -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || true)
kubectl -n "$NS_SANDBOX" logs fbxval-d > "$LOG_DIR/d.log" 2>/dev/null || true
if [ "$PHASE" = "Failed" ] && [ "$CODE" = "3" ] && [ $((T1-T0)) -lt 60 ]; then
  pass "[D] unenforced cluster fails closed: exit 3 after ~15s window ($((T1-T0))s total)"
else
  fail "[D] expected Failed/exit 3 within a minute, got phase=$PHASE exit=$CODE in $((T1-T0))s"
fi
kubectl -n "$NS_SANDBOX" delete pod fbxval-d --ignore-not-found >/dev/null
policies_apply   # leave the namespace in its enforced state

say "summary"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo "  logs: $LOG_DIR"
if [ "$FAIL" -eq 0 ]; then
  echo "  ALL $PASS ASSERTIONS PASSED"
  if [ "$KEEP" = 0 ]; then
    say "teardown (pass --keep to retain the cluster)"
    kind delete cluster --name "$CLUSTER"
  fi
  exit 0
else
  echo "  $FAIL FAILED / $PASS passed — cluster '$CLUSTER' kept for forensics (kind delete cluster --name $CLUSTER)"
  exit 1
fi
