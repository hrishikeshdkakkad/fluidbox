#!/usr/bin/env bash
# Substrate-independent half of the M1.1 gate, proven LOCALLY and for free.
#
# The M1.1 acceptance criteria split into two kinds of claim:
#   AWS-SPECIFIC  — ALB/CloudFront edge lock, Pod Identity → KMS, scale-from-zero,
#                   EKS addons. Only an EKS apply can prove these.
#   SUBSTRATE-INDEPENDENT — do the M1 chart values actually INSTALL; does the
#                   released 0.4.0 server boot in the M1 posture; does the
#                   zero-egress NetworkPolicy enforce; does a governed replay
#                   run complete on-cluster with an approval pause and a diff.
#
# This script proves the second kind on kind + Calico (a real enforcing CNI),
# against the REAL published 0.4.0 images M1 deploys — no AWS, no spend, no
# model calls. It is the same recipe the repo's k8s CI tier uses, pointed at
# deploy/cloud/values/eks-m1.yaml instead of the CI values.
#
# Deliberate substrate overrides (kind is one untainted node; EKS has a tainted
# scale-from-zero sandbox nodegroup), each of which is AWS-specific by nature:
#   sandbox.nodeSelector/tolerations  → emptied (no sandbox nodegroup here)
#   server.archivePvc.storageClass    → "standard" (kind's local-path name)
#   litellm.enabled/llm.upstreamUrl   → off/empty (replay makes NO model calls)
#   ingress.className stays "alb"     → the Ingress object is still created, so
#                                       the API server validates the manifest
#
#   scripts/cloud/m1-kind-validation.sh            # full run, tears down after
#   KEEP=1 scripts/cloud/m1-kind-validation.sh     # leave the cluster up
#   SKIP_REPLAY=1 …                                # chart + netpol only
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.colima/default/docker.sock}"
CLUSTER="${CLUSTER:-fluidbox-m1}"
NS=fluidbox
SBNS=fluidbox-sandboxes
CHART_VERSION="${CHART_VERSION:-0.4.0}"
REPLAY_IMAGE=fluidbox-replay-runner:m1kind
EV=$(evidence_dir cloud-m1-kind)
WORK="${SCRATCH:-/tmp/fluidbox-m1-kind}"
mkdir -p "$WORK"

PASS=0; FAILN=0
pass() { ok "$1"; PASS=$((PASS+1)); }
bad()  { fail "$1"; FAILN=$((FAILN+1)); }

dump() {
  { echo "### pods"; kubectl get pods -A -o wide
    echo "### events"; kubectl -n "$NS" get events --sort-by=.lastTimestamp | tail -40
    echo "### server log"; kubectl -n "$NS" logs deploy/fluidbox-server --tail=120
  } > "$EV/failure-dump.txt" 2>&1
  warn "diagnostics: $EV/failure-dump.txt"
}

teardown() {
  if [ "${KEEP:-0}" = "1" ]; then
    warn "KEEP=1 — cluster '$CLUSTER' left up (kind delete cluster --name $CLUSTER)"
    return 0
  fi
  say "teardown"
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
  ok "kind cluster removed"
}
trap teardown EXIT

command -v kind >/dev/null || die "kind required"
docker info >/dev/null 2>&1 || die "docker unreachable" "colima status / colima start"

say "1. kind cluster with Calico (kindnet does NOT enforce NetworkPolicy)"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
kind create cluster --name "$CLUSTER" --config .github/kind-calico.yaml >"$WORK/kind.log" 2>&1 \
  || die "kind create failed" "$WORK/kind.log"
kubectl config use-context "kind-$CLUSTER" >/dev/null
pass "cluster up"
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml >/dev/null 2>&1 \
  || die "calico apply failed"
kubectl -n kube-system rollout status ds/calico-node --timeout=300s >/dev/null 2>&1 \
  || die "calico did not become ready"
pass "Calico enforcing"

say "2. throwaway in-cluster Postgres (the server migrates on boot)"
kubectl create namespace "$NS" >/dev/null 2>&1
kubectl apply -f .github/k8s-ci-postgres.yaml >/dev/null || die "postgres manifest failed"
kubectl -n "$NS" rollout status deploy/postgres --timeout=240s >/dev/null \
  || die "postgres never became ready"
pass "postgres ready"

say "3. credential Secret (out-of-band, exactly like make-secrets.sh)"
kubectl -n "$NS" create secret generic fluidbox-secrets \
  --from-literal=DATABASE_URL="postgres://fluidbox:fluidbox-ci@postgres.$NS.svc.cluster.local:5432/fluidbox?sslmode=disable" \
  --from-literal=FLUIDBOX_ADMIN_TOKEN=m1-kind-admin \
  --from-literal=FLUIDBOX_CREDENTIAL_KEY="$(openssl rand -hex 32)" \
  --from-literal=LITELLM_MASTER_KEY=unused-no-model-calls \
  --from-literal=ANTHROPIC_API_KEY=unused-no-model-calls >/dev/null \
  || die "secret creation failed"
pass "fluidbox-secrets created"

say "4. install the RELEASED $CHART_VERSION chart with the REAL M1 values"
cat > "$WORK/kind-overlay.yaml" <<'EOF'
# Substrate overrides only — see the header for why each one is AWS-specific.
server:
  archivePvc:
    storageClass: standard
litellm:
  enabled: false
llm:
  upstreamUrl: ""
sandbox:
  # Lists are REPLACED by a later -f, so emptying this one works.
  tolerations: []
EOF
# sandbox.nodeSelector must be unset with --set …=null, NOT with `{}` in the
# overlay: Helm DEEP-MERGES maps across -f files, so an empty map cannot remove
# keys the earlier file set. Written the obvious way, the EKS
# `fluidbox.dev/role: sandbox` selector survives, every sandbox pod (including
# the netpol probe) becomes unschedulable on kind's single untainted node, and
# the failure surfaces minutes later as an inscrutable Pending. Lists are
# replaced rather than merged, which is why `tolerations: []` above is fine.
helm install fluidbox "oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox" \
  --version "$CHART_VERSION" -n "$NS" \
  -f deploy/cloud/values/eks-m1.yaml -f "$WORK/kind-overlay.yaml" \
  --set sandbox.nodeSelector=null \
  --wait --timeout 600s > "$WORK/helm.log" 2>&1 \
  || { tail -20 "$WORK/helm.log"; dump; die "helm install FAILED with the M1 values" "$WORK/helm.log"; }
kubectl -n "$NS" get deploy fluidbox-server -o yaml | grep -q "FLUIDBOX_K8S_NODE_SELECTOR" \
  && { dump; die "sandbox nodeSelector survived the override — sandbox pods cannot schedule on kind"; }
pass "sandbox nodeSelector correctly unset for this substrate"
pass "chart installed with deploy/cloud/values/eks-m1.yaml — server READY (readiness probe gated the wait)"

kubectl -n "$NS" get all,ingress,networkpolicy -o wide > "$EV/installed-objects.txt" 2>&1
kubectl -n "$SBNS" get networkpolicy,resourcequota -o yaml > "$EV/sandbox-plane.txt" 2>&1
kubectl -n "$NS" get ingress fluidbox-server >/dev/null 2>&1 \
  && pass "Ingress object accepted by the API server (alb class, empty host)" \
  || bad "Ingress not created"
kubectl -n "$SBNS" get resourcequota >/dev/null 2>&1 \
  && pass "sandbox ResourceQuota present (the only concurrent-run admission gate)" \
  || bad "sandbox ResourceQuota missing"

say "5. server boot posture (the M1 claims that are substrate-independent)"
kubectl -n "$NS" logs deploy/fluidbox-server > "$EV/server-boot.log" 2>&1
grep -q "execution provider: kubernetes" "$EV/server-boot.log" \
  && pass "kubernetes execution provider active" || bad "provider line missing"
grep -qi "netpol gate: enforcement verified" "$EV/server-boot.log" \
  && pass "netpol boot gate VERIFIED enforcement (runs admitted)" \
  || warn "boot gate not yet verified — expected on a cold cluster; helm test below is the authoritative check"

say "6. helm test — the chart's own netpol enforcement probe"
if helm test fluidbox -n "$NS" --timeout 420s > "$WORK/helmtest.log" 2>&1; then
  pass "helm test PASSED (+:8788 reachable, -:8787 blocked) on a real enforcing CNI"
else
  tail -15 "$WORK/helmtest.log" > "$EV/helm-test-failure.txt"
  bad "helm test failed — see $EV/helm-test-failure.txt"
fi

if [ "${SKIP_REPLAY:-0}" = "1" ]; then
  say "verdict (replay skipped)"; echo "  PASS=$PASS FAIL=$FAILN"; exit $((FAILN > 0))
fi

say "7. governed replay run ON-CLUSTER — the M1.1 acceptance vehicle, \$0"
docker build -q -t "$REPLAY_IMAGE" -f images/replay-runner/Dockerfile images > "$WORK/build.log" 2>&1 \
  || { dump; die "replay image build failed" "$WORK/build.log"; }
kind load docker-image --name "$CLUSTER" "$REPLAY_IMAGE" >/dev/null 2>&1 \
  || die "kind load failed"
pass "replay-runner image built + loaded"

kubectl -n "$NS" port-forward deploy/fluidbox-server 18787:8787 > "$WORK/pf.log" 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null; teardown' EXIT
API="http://127.0.0.1:18787"
for _ in $(seq 1 40); do curl -fsS --max-time 2 "$API/v1/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS --max-time 5 "$API/v1/health" >/dev/null || { dump; die "port-forward never became usable"; }
H="authorization: Bearer m1-kind-admin"

SERVER_POD=$(kubectl -n "$NS" get pods -l app.kubernetes.io/component=server -o jsonpath='{.items[0].metadata.name}')
kubectl -n "$NS" exec "$SERVER_POD" -- rm -rf /tmp/demo-fixture 2>/dev/null
kubectl cp scripts/demo-fixture "$NS/$SERVER_POD:/tmp/demo-fixture" >/dev/null 2>&1 \
  || { dump; die "fixture copy into the server pod failed"; }
pass "fixture staged in the server pod (local_copy workspace path)"

python3 - scripts/demo-policy.yaml > "$WORK/policy.json" <<'PY'
import json, sys
print(json.dumps({"name": "demo", "yaml": open(sys.argv[1]).read()}))
PY
curl -sS -X POST -H "$H" -H 'content-type: application/json' -d @"$WORK/policy.json" "$API/v1/policies" >/dev/null
curl -sS -X POST -H "$H" -H 'content-type: application/json' -d "$(python3 - "$REPLAY_IMAGE" <<'PY'
import json, sys
print(json.dumps({
  "name": "m1-replay", "description": "M1 substrate validation (deterministic replay)",
  "harness": "claude-agent-sdk", "model": "claude-haiku-4-5",
  "system_prompt": "Deterministic replay of a recorded run. No model is consulted.",
  "policy": "demo", "runner_image": sys.argv[1],
}))
PY
)" "$API/v1/agents" >/dev/null
pass "policy + agent seeded"

SID=$(curl -fsS -X POST -H "$H" -H 'content-type: application/json' -d "$(python3 <<'PY'
import json
print(json.dumps({"agent": "m1-replay",
  "task": "Fix the failing test in demo-service, then deploy. [deterministic replay - no model calls]",
  "workspace": {"kind": "local_copy", "path": "/tmp/demo-fixture"}, "autonomous": False}))
PY
)" "$API/v1/sessions" | python3 -c "import sys,json;print(json.load(sys.stdin)['session']['id'])") \
  || { dump; die "run creation failed"; }
ok "run $SID"

FBX_API="$API" FBX_TOKEN=m1-kind-admin FBX_SID="$SID" FBX_EV="$EV" python3 -u - <<'PY' > "$EV/timeline.txt" 2>&1
import json, os, sys, time, urllib.request
API, TOKEN, SID, EV = (os.environ[k] for k in ("FBX_API","FBX_TOKEN","FBX_SID","FBX_EV"))
def api(p, body=None):
    r = urllib.request.Request(API+p, headers={"authorization":"Bearer "+TOKEN})
    if body is not None:
        r.data = json.dumps(body).encode(); r.add_header("content-type","application/json")
    with urllib.request.urlopen(r, timeout=30) as x: return json.loads(x.read() or b"{}")
# §9-7 is "the run pauses for an approval and resumes after approval". The
# evidence for that is the approval CHAIN — approval.requested, then a decided
# approval, then a tool.decision with source=human — NOT a session status of
# `awaiting_approval`. A quickly-decided approval blocks inside the permission
# handler while the session stays `running` and emits no such transition, so
# asserting on it fails a perfectly good run (observed: this exact script did).
seq=0; status=None; decided=False; requested=False; human_allow=False; denied=0; t0=time.time()
while status is None and time.time()-t0 < 900:
    try: evs = api(f"/v1/sessions/{SID}/events?after={seq}&limit=200").get("events", [])
    except Exception as e: print("poll:", e); time.sleep(2); continue
    for e in evs:
        seq = e["seq"]; k = e["payload"]["type"]; d = e["payload"].get("data") or {}
        print(f"[{seq:>3}] {k}: {json.dumps(d)[:140]}")
        if k == "session.status_changed" and d.get("to") in ("completed","failed","cancelled","budget_exceeded"):
            status = d.get("to")
        if k == "tool.decision":
            if d.get("source") == "human" and d.get("verdict") == "allow": human_allow = True
            if d.get("verdict") == "deny": denied += 1
        if k == "approval.requested":
            requested = True
            if not decided:
                time.sleep(1); api(f"/v1/approvals/{d.get('approval_id')}/decision", {"decision":"approved_once"})
                decided = True; print(">>> operator approved")
    if not evs: time.sleep(1.5)
result = {"status":status,"approval_requested":requested,"approved":decided,
          "resumed_via_human_allow":human_allow,"policy_denials":denied}
json.dump(result, open(f"{EV}/replay-result.json","w"))
print("result:", result)
sys.exit(0 if status=="completed" and requested and decided and human_allow and denied >= 1 else 1)
PY
RC=$?
[ "$RC" = "0" ] && pass "replay run COMPLETED with a governed approval pause + resume" \
                || { bad "replay run did not complete cleanly (see $EV/timeline.txt)"; dump; }

curl -sS -H "$H" "$API/v1/sessions/$SID/artifacts" > "$EV/artifacts.json" 2>/dev/null
curl -sS -H "$H" "$API/v1/sessions/$SID/cost" > "$EV/cost.json" 2>/dev/null
FBX_EV="$EV" FBX_API="$API" FBX_TOKEN=m1-kind-admin FBX_SID="$SID" python3 - <<'PY' 2>/dev/null || true
import json, os, urllib.request
EV, API, TOKEN, SID = (os.environ[k] for k in ("FBX_EV","FBX_API","FBX_TOKEN","FBX_SID"))
arts = json.load(open(f"{EV}/artifacts.json")).get("artifacts", [])
d = next((a for a in arts if a.get("kind") == "diff"), None)
if d:
    r = urllib.request.Request(f"{API}/v1/sessions/{SID}/artifacts/{d['id']}", headers={"authorization":"Bearer "+TOKEN})
    open(f"{EV}/changes.patch","w").write(json.loads(urllib.request.urlopen(r, timeout=30).read())["artifact"].get("content",""))
PY
if grep -q "return a \* b" "$EV/changes.patch" 2>/dev/null; then
  pass "diff artifact carries the canonical fix (return a * b)"
else
  [ -s "$EV/changes.patch" ] && pass "diff artifact captured" || bad "no diff artifact"
fi

sleep 15
LEFT=$(kubectl -n "$SBNS" get pods --no-headers 2>/dev/null | grep -cv "netpol-probe" || echo 0)
[ "$LEFT" -eq 0 ] && pass "sandbox namespace reclaimed after terminal (ownerRef GC)" \
                  || warn "$LEFT sandbox pod(s) remain — GC can lag a few seconds"

say "verdict"
echo "  PASS=$PASS FAIL=$FAILN   evidence: $EV/"
[ "$FAILN" -eq 0 ] && ok "M1 substrate-independent claims PROVEN on a real enforcing cluster" \
                   || fail "some claims did not hold — see $EV/"
exit $((FAILN > 0))
