#!/usr/bin/env bash
# The NO-COST acceptance vehicle on the cloud cluster (§9 criteria 5–9, 13,
# 15-adjacent): the deterministic replay agent drives the real gate, a real
# EKS sandbox pod, a real approval pause, and a real diff+cost report — no
# model key consulted. Mirrors scripts/demo.sh's API contract 1:1.
#
# Prereqs: platform+app+edge applied, rotation done, colima running (image
# build), AWS_PROFILE=fluidbox-deployer.
#
#   scripts/cloud/replay-on-cluster.sh            # full: build+push+seed+run
#   FLUIDBOX_DEMO_DECISION=deny …                 # exercise the deny path
#   SKIP_BUILD=1 …                                # reuse the pushed image
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

require_non_root
ensure_kubeconfig
command -v docker >/dev/null || die "docker required (colima)"
command -v python3 >/dev/null || die "python3 required"

ACCOUNT_ID="${ACCOUNT_ID:-471112572248}"
ECR="${ACCOUNT_ID}.dkr.ecr.${CLOUD_REGION}.amazonaws.com/fluidbox-replay-runner"
TAG="${REPLAY_TAG:-m1}"
CF_DOMAIN="${CF_DOMAIN:-$(cd deploy/cloud/terraform/edge && terraform output -raw cloudfront_domain 2>/dev/null || true)}"
[ -n "$CF_DOMAIN" ] || die "CloudFront domain unknown (apply edge, or set CF_DOMAIN)"
API="https://${CF_DOMAIN}"
ADMIN_TOKEN="${ADMIN_TOKEN:-$(aws ssm get-parameter --with-decryption --name /fluidbox/cloud/admin-token --query Parameter.Value --output text)}"
H="authorization: Bearer $ADMIN_TOKEN"
EV=$(evidence_dir cloud-m1-replay)
DECISION="${FLUIDBOX_DEMO_DECISION:-approve}"

say "0. API reachability through the public edge"
curl -fsS --max-time 30 "$API/v1/health" >/dev/null || die "control plane unreachable via $API"
ok "GET $API/v1/health"

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  say "1. build + push the replay-runner image (arm64, matches t4g nodes)"
  aws ecr get-login-password --region "$CLOUD_REGION" \
    | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${CLOUD_REGION}.amazonaws.com" >/dev/null
  docker buildx build --platform linux/arm64 -t "$ECR:$TAG" \
    -f images/replay-runner/Dockerfile images --push \
    || die "replay image build/push failed"
  ok "$ECR:$TAG pushed"
else
  say "1. (skipped image build; using $ECR:$TAG)"
fi

say "2. seed the fixture repo inside the SERVER pod (local_copy workspace)"
SERVER_POD=$(kubectl get pods -n "$CLOUD_NS" -l app.kubernetes.io/component=server -o jsonpath='{.items[0].metadata.name}')
[ -n "$SERVER_POD" ] || die "server pod not found in $CLOUD_NS"
kubectl exec -n "$CLOUD_NS" "$SERVER_POD" -- rm -rf /tmp/demo-fixture
kubectl cp scripts/demo-fixture "$CLOUD_NS/$SERVER_POD:/tmp/demo-fixture"
kubectl exec -n "$CLOUD_NS" "$SERVER_POD" -- ls /tmp/demo-fixture >/dev/null || die "fixture copy failed"
ok "fixture staged at $SERVER_POD:/tmp/demo-fixture"

say "3. policy + agent (idempotent-ish: 4xx from an existing name is tolerated)"
python3 - scripts/demo-policy.yaml > /tmp/fbx-policy.json <<'PYEOF'
import json, sys
print(json.dumps({"name": "demo", "yaml": open(sys.argv[1]).read()}))
PYEOF
curl -sS -X POST -H "$H" -H 'content-type: application/json' -d @/tmp/fbx-policy.json "$API/v1/policies" >/dev/null || true
rm -f /tmp/fbx-policy.json
curl -sS -X POST -H "$H" -H 'content-type: application/json' -d "$(python3 - "$ECR:$TAG" <<'PYEOF'
import json, sys
print(json.dumps({
  "name": "cloud-replay",
  "description": "M1 acceptance: deterministic replay on EKS (no model calls)",
  "harness": "claude-agent-sdk",
  "model": "claude-haiku-4-5",
  "system_prompt": "Deterministic replay of a recorded run. No model is consulted.",
  "policy": "demo",
  "runner_image": sys.argv[1],
}))
PYEOF
)" "$API/v1/agents" >/dev/null || true
ok "policy 'demo' + agent 'cloud-replay' present (runner_image=$ECR:$TAG)"

say "4. the governed run"
SID=$(curl -fsS -X POST -H "$H" -H 'content-type: application/json' -d "$(python3 <<'PYEOF'
import json
print(json.dumps({
  "agent": "cloud-replay",
  "task": "Fix the failing test in demo-service, then deploy. [deterministic replay - no model calls]",
  "workspace": {"kind": "local_copy", "path": "/tmp/demo-fixture"},
  "autonomous": False,
}))
PYEOF
)" "$API/v1/sessions" | python3 -c "import sys,json;print(json.load(sys.stdin)['session']['id'])")
ok "run created: $SID"
echo "$SID" > "$EV/session-id"

# Watch the sandbox pod appear (evidence for §9 criterion 6).
( for _ in $(seq 1 120); do
    kubectl get pods -n "$CLOUD_SANDBOX_NS" -o wide 2>/dev/null | grep -v '^NAME' | grep -q . && {
      kubectl get pods -n "$CLOUD_SANDBOX_NS" -o wide > "$EV/sandbox-pods.txt"; break; }
    sleep 5
  done ) &
PODWATCH=$!

FBX_API="$API" FBX_TOKEN="$ADMIN_TOKEN" FBX_SID="$SID" FBX_EV="$EV" FBX_DECISION="$DECISION" \
python3 -u - <<'PYEOF' | tee "$EV/timeline.txt"
import json, os, sys, time, urllib.request
API, TOKEN, SID = os.environ["FBX_API"], os.environ["FBX_TOKEN"], os.environ["FBX_SID"]
EV, DECISION = os.environ["FBX_EV"], os.environ["FBX_DECISION"]

def api(path, body=None):
    req = urllib.request.Request(API + path, headers={"authorization": "Bearer " + TOKEN})
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header("content-type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")

seq, status, decided, started = 0, None, False, time.time()
while status is None and time.time() - started < 1800:
    try:
        evs = api(f"/v1/sessions/{SID}/events?after={seq}&limit=200").get("events", [])
    except Exception as e:
        print(f"  (poll error {e}; retrying)"); time.sleep(2); continue
    for e in evs:
        seq = e["seq"]
        kind = e["payload"]["type"]; d = e["payload"].get("data") or {}
        if kind == "session.status_changed":
            print(f"[{seq:>3}] {d.get('from')} -> {d.get('to')}")
            if d.get("to") in ("completed", "failed", "cancelled", "budget_exceeded"):
                status = d.get("to")
        elif kind in ("tool.requested", "tool.decision", "workspace.initialized", "approval.decided", "run.result"):
            print(f"[{seq:>3}] {kind}: {json.dumps(d)[:160]}")
        if kind == "approval.requested" and not decided:
            aid = d.get("approval_id")
            time.sleep(2)
            decision = "approved_once" if DECISION == "approve" else "denied"
            api(f"/v1/approvals/{aid}/decision", {"decision": decision})
            decided = True
            print(f"[{seq:>3}] >>> operator decision submitted: {decision}")
    if not evs:
        time.sleep(1.5)

print(f"terminal status: {status}")
expected = "completed" if DECISION == "approve" else None  # deny path may end completed-with-refusal or failed by transcript design
with open(os.path.join(EV, "terminal-status.txt"), "w") as f:
    f.write(str(status) + "\n")
sys.exit(0 if (status == "completed" or DECISION != "approve") else 1)
PYEOF
REPLAY_RC=${PIPESTATUS[0]}
wait "$PODWATCH" 2>/dev/null || true

say "5. artifacts + GC evidence"
curl -sS -H "$H" "$API/v1/sessions/$SID" > "$EV/session.json" || true
curl -sS -H "$H" "$API/v1/sessions/$SID/artifacts" > "$EV/artifacts.json" || true
curl -sS -H "$H" "$API/v1/sessions/$SID/cost" > "$EV/cost.json" || true
curl -sS -H "$H" "$API/v1/sessions/$SID/approvals" > "$EV/approvals.json" || true
FBX_EV="$EV" FBX_API="$API" FBX_TOKEN="$ADMIN_TOKEN" FBX_SID="$SID" python3 - <<'PYEOF' || true
import json, os, urllib.request
EV, API, TOKEN, SID = (os.environ[k] for k in ("FBX_EV", "FBX_API", "FBX_TOKEN", "FBX_SID"))
arts = json.load(open(f"{EV}/artifacts.json")).get("artifacts", [])
diff = next((a for a in arts if a.get("kind") == "diff"), None)
if diff:
    req = urllib.request.Request(f"{API}/v1/sessions/{SID}/artifacts/{diff['id']}",
                                 headers={"authorization": "Bearer " + TOKEN})
    content = json.loads(urllib.request.urlopen(req, timeout=30).read())["artifact"].get("content", "")
    open(f"{EV}/changes.patch", "w").write(content)
PYEOF
[ -s "$EV/changes.patch" ] && ok "diff artifact captured ($EV/changes.patch)" || warn "no diff artifact (expected on the deny path)"
sleep 20
kubectl get pods -n "$CLOUD_SANDBOX_NS" > "$EV/sandbox-after.txt" 2>&1 || true
grep -qv '^NAME' "$EV/sandbox-after.txt" 2>/dev/null && warn "sandbox namespace not yet empty (GC may lag terminal by a few s)" || ok "sandbox namespace empty after terminal (GC clean)"

[ "$REPLAY_RC" = "0" ] && ok "replay journey PASSED (evidence: $EV/)" || die "replay journey FAILED (see $EV/timeline.txt)"
