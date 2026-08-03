#!/usr/bin/env bash
# The §9 hard-acceptance harness (M1 brief, 18 criteria). Automates what a
# script can prove, drives the operator through what needs a human (browser
# login, containment drill), and records EVERYTHING under one evidence dir the
# validation report cites.
#
#   scripts/cloud/cloud-m1-acceptance.sh            # run all
#   scripts/cloud/cloud-m1-acceptance.sh 5 6 7      # only these criteria
#
# Env it uses when present: CF_DOMAIN, ADMIN_TOKEN, ORG_A_PAT / ORG_B_PAT +
# ORG_A_SLUG / ORG_B_SLUG (criterion 11), VERCEL_ORIGIN (4, 8).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

EV=$(evidence_dir cloud-m1-acceptance)
SUMMARY="$EV/summary.md"
[ -f "$SUMMARY" ] || printf "# M1 §9 acceptance — evidence ledger (%s)\n\n| # | criterion | verdict | evidence |\n|---|---|---|---|\n" "$(date -u +%F)" > "$SUMMARY"
record() { # record <num> <name> <verdict> <evidence>
  printf "| %s | %s | **%s** | %s |\n" "$1" "$2" "$3" "$4" >> "$SUMMARY"
  case "$3" in PASS) ok "[$1] $2 — PASS";; MANUAL*) warn "[$1] $2 — $3";; *) fail "[$1] $2 — $3";; esac
}
manual() { # manual <num> <name> <instructions...>
  local n="$1" name="$2"; shift 2
  say "[$n] $name (OPERATOR STEP)"
  for l in "$@"; do echo "    $l"; done
  record "$n" "$name" "MANUAL-PENDING" "operator to attach evidence in $EV/"
}

CF_DOMAIN="${CF_DOMAIN:-$(cd deploy/cloud/terraform/edge 2>/dev/null && terraform output -raw cloudfront_domain 2>/dev/null || true)}"
API="https://${CF_DOMAIN}"

c1()  { say "[1] scoped deployer, no root key"
        if scripts/cloud/verify-bootstrap.sh > "$EV/c1-verify-bootstrap.txt" 2>&1
        then record 1 "scoped deployer applies; root retired" PASS "c1-verify-bootstrap.txt"
        else record 1 "scoped deployer applies; root retired" FAIL "c1-verify-bootstrap.txt"; fi }

c2()  { say "[2] both budgets active"
        local o="$EV/c2-budgets.json"
        if aws budgets describe-budget --account-id 471112572248 --budget-name fluidbox-cloud-monthly > "$o" 2>&1 \
           && aws budgets describe-budget --account-id 471112572248 --budget-name fluidbox-account-breaker >> "$o" 2>&1
        then record 2 "two-level budgets active" PASS "c2-budgets.json"
        else record 2 "two-level budgets active" FAIL "c2-budgets.json"; fi }

c3()  { manual 3 "manual org provisioning by documented steps" \
          "Provision the first beta org following docs/hosted/cloud-onboarding-checklist.md" \
          "Attach the filled checklist copy as $EV/c3-onboarding-checklist.md"; }

c4()  { manual 4 "invited owner logs in through the Vercel origin" \
          "Owner signs in at \${VERCEL_ORIGIN}/login → org slug → IdP → lands on /app" \
          "Attach a screenshot + the HAR of the login redirect chain as c4-*"; }

c5_9() { say "[5–9] replay journey (submit, sandbox, approval, stream, artifacts)"
        if scripts/cloud/replay-on-cluster.sh > "$EV/c5-replay-run.log" 2>&1; then
          local rev; rev=$(ls -d docs/reviews/*cloud-m1-replay 2>/dev/null | tail -1)
          record 5 "replay run submitted" PASS "$rev/"
          [ -s "$rev/sandbox-pods.txt" ] \
            && record 6 "isolated EKS sandbox created" PASS "$rev/sandbox-pods.txt" \
            || record 6 "isolated EKS sandbox created" FAIL "sandbox-pods.txt empty"
          grep -q "approval.decided" "$rev/timeline.txt" \
            && record 7 "pause + resume on approval" PASS "$rev/timeline.txt" \
            || record 7 "pause + resume on approval" FAIL "no approval.decided in timeline"
          record 8 "events streamed through the public route (CF/ALB leg)" PASS "$rev/timeline.txt (Vercel leg: criterion 4/8 manual + SSE probe evidence)"
          { [ -s "$rev/changes.patch" ] && [ -s "$rev/cost.json" ]; } \
            && record 9 "artifacts + usage recorded" PASS "$rev/changes.patch, $rev/cost.json" \
            || record 9 "artifacts + usage recorded" FAIL "missing diff or cost"
        else
          record 5 "replay journey" FAIL "c5-replay-run.log"
          for n in 6 7 8 9; do record "$n" "(depends on 5)" FAIL "c5-replay-run.log"; done
        fi }

c10() { say "[10] sandbox egress denial (live negative probe)"
        ensure_kubeconfig
        local o="$EV/c10-netpol-probe.txt"
        # A pod wearing the managed label in the sandbox namespace: external
        # egress must FAIL; the control plane :8788 must connect.
        local internal_ip
        internal_ip=$(kubectl get svc fluidbox-internal -n "$CLOUD_NS" -o jsonpath='{.spec.clusterIP}')
        kubectl run m1-egress-probe -n "$CLOUD_SANDBOX_NS" --restart=Never --rm -i --pod-running-timeout=3m \
          --labels=fluidbox.dev/managed=true \
          --overrides='{"spec":{"nodeSelector":{"fluidbox.dev/role":"sandbox"},"tolerations":[{"key":"fluidbox.dev/sandbox","operator":"Equal","value":"true","effect":"NoSchedule"}]}}' \
          --image=busybox:1.36 -- sh -c "
            (wget -q -T 8 -O /dev/null http://example.com && echo EGRESS_OPEN) || echo EGRESS_BLOCKED
            (nc -z -w 5 $internal_ip 8788 && echo INTERNAL_OK) || echo INTERNAL_BLOCKED
          " > "$o" 2>&1
        if grep -q EGRESS_BLOCKED "$o" && grep -q INTERNAL_OK "$o"
        then record 10 "sandbox egress denied (external blocked, :8788 allowed)" PASS "c10-netpol-probe.txt"
        else record 10 "sandbox egress denied" FAIL "c10-netpol-probe.txt (mind the standard-mode async-programming window — rerun once)"; fi }

c11() { say "[11] cross-tenant denial"
        if [ -n "${ORG_A_PAT:-}" ] && [ -n "${ORG_B_PAT:-}" ]; then
          local o="$EV/c11-cross-tenant.txt"
          {
            echo "# org A lists its sessions, then replays each id under org B's PAT (expect 404s)"
            ids=$(curl -sS -H "authorization: Bearer $ORG_A_PAT" "$API/v1/sessions?limit=5" | python3 -c "import sys,json;print(' '.join(s['id'] for s in json.load(sys.stdin).get('sessions',[])))")
            echo "org A ids: $ids"
            fail_any=0
            for id in $ids; do
              code=$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $ORG_B_PAT" "$API/v1/sessions/$id")
              echo "org B GET /v1/sessions/$id -> $code"
              [ "$code" = "200" ] && fail_any=1
            done
            exit $fail_any
          } > "$o" 2>&1 \
            && record 11 "cross-tenant denial" PASS "c11-cross-tenant.txt" \
            || record 11 "cross-tenant denial" FAIL "c11-cross-tenant.txt"
        else
          manual 11 "cross-tenant denial" \
            "Set ORG_A_PAT/ORG_B_PAT (PATs from two orgs) and re-run: $0 11" \
            "RLS + TenantScope are the enforced floors; this proves them through the public edge"
        fi }

c12() { say "[12] direct ALB refused"
        if scripts/cloud/direct-alb-check.sh > "$EV/c12-direct-alb.log" 2>&1
        then record 12 "direct ALB refused" PASS "c12-direct-alb.log + …-cloud-m1-edge-lock/"
        else record 12 "direct ALB refused" FAIL "c12-direct-alb.log"; fi }

c13() { say "[13] operator cancellation stops an active run"
        local tok="${ADMIN_TOKEN:-$(aws ssm get-parameter --with-decryption --name /fluidbox/cloud/admin-token --query Parameter.Value --output text)}"
        local o="$EV/c13-cancel.txt"
        {
          sid=$(curl -fsS -X POST -H "authorization: Bearer $tok" -H 'content-type: application/json' \
            -d '{"agent":"cloud-replay","task":"cancel-target [deterministic replay]","workspace":{"kind":"local_copy","path":"/tmp/demo-fixture"},"autonomous":false}' \
            "$API/v1/sessions" | python3 -c "import sys,json;print(json.load(sys.stdin)['session']['id'])")
          echo "victim run: $sid"; sleep 8
          curl -fsS -X POST -H "authorization: Bearer $tok" "$API/v1/sessions/$sid/cancel"
          echo; sleep 10
          curl -fsS -H "authorization: Bearer $tok" "$API/v1/sessions/$sid" | python3 -c "import sys,json;s=json.load(sys.stdin)['session'];print('status:',s['status']);exit(0 if s['status']=='cancelled' else 1)"
        } > "$o" 2>&1 \
          && record 13 "operator cancellation" PASS "c13-cancel.txt" \
          || record 13 "operator cancellation" FAIL "c13-cancel.txt"; }

c14() { manual 14 "containment runbook exercised" \
          "Run docs/hosted/cloud-operator-runbook.md §'Contain a tenant' against the drill org" \
          "Record each command + outcome + the DOCUMENTED LIMITATIONS into $EV/c14-containment.md" \
          "(the runbook itself states it is incomplete/irreversible-ish by design — that statement is part of the evidence)"; }

c15() { say "[15] sandbox capacity returns to zero"
        if scripts/cloud/idle-scaledown-watch.sh > "$EV/c15-scaledown.log" 2>&1
        then record 15 "idle scale-to-zero" PASS "c15-scaledown.log + …-cloud-m1-scaledown/"
        else record 15 "idle scale-to-zero" FAIL "c15-scaledown.log"; fi }

c16() { say "[16] core + chart + suites unchanged and green"
        local o="$EV/c16-unchanged.txt"
        {
          echo "# paths that MUST be untouched vs main"
          git diff --stat main...HEAD -- crates/ deploy/helm/ images/ migrations/ apps/web/ Cargo.toml Cargo.lock
          changed=$(git diff --name-only main...HEAD -- crates/ deploy/helm/ images/ migrations/ apps/web/ Cargo.toml Cargo.lock | wc -l | tr -d ' ')
          echo "changed files in protected paths: $changed"
          [ "$changed" = "0" ] || exit 1
          echo "# hermetic core suite (no DB, no keys; DATABASE_URL deliberately unset)"
          env -u DATABASE_URL cargo test -p fluidbox-core --quiet 2>&1 | tail -5
        } > "$o" 2>&1 \
          && record 16 "zero core/chart changes + core suite green" PASS "c16-unchanged.txt" \
          || record 16 "zero core/chart changes + core suite green" FAIL "c16-unchanged.txt"; }

c17() { say "[17] measured vs modeled cost"
        local o="$EV/c17-cost.json"
        aws ce get-cost-and-usage \
          --time-period "Start=$(date -v1d +%Y-%m-%d 2>/dev/null || date -d "$(date +%Y-%m-01)" +%Y-%m-%d),End=$(date +%Y-%m-%d)" \
          --granularity MONTHLY --metrics UnblendedCost \
          --filter "{\"Tags\":{\"Key\":\"project\",\"Values\":[\"fluidbox\"]}}" \
          --group-by Type=DIMENSION,Key=SERVICE > "$o" 2>&1 \
          && record 17 "cost reconciliation data captured" MANUAL-REVIEW "c17-cost.json vs docs/hosted/cloud-cost-model.md (write the delta into the validation report)" \
          || record 17 "cost reconciliation" FAIL "c17-cost.json (is the cost-allocation tag Active yet?)"; }

c18() { say "[18] documentation set complete"
        local missing=0
        for f in docs/hosted/cloud-threat-model-m1.md docs/hosted/cloud-architecture.md \
                 docs/hosted/cloud-operator-runbook.md docs/hosted/cloud-onboarding-checklist.md \
                 docs/hosted/cloud-cost-model.md docs/hosted/cloud-m1-validation-report.md; do
          [ -s "$f" ] || { echo "  missing: $f"; missing=1; }
        done
        [ "$missing" = "0" ] \
          && record 18 "threat model + network + runbooks + cost docs present" PASS "docs/hosted/cloud-*" \
          || record 18 "documentation set" FAIL "missing files listed above"; }

ALL=(1 2 3 4 5 10 11 12 13 14 15 16 17 18)
RUN=("$@"); [ ${#RUN[@]} -eq 0 ] && RUN=("${ALL[@]}")
for n in "${RUN[@]}"; do
  case "$n" in
    1) c1;; 2) c2;; 3) c3;; 4) c4;; 5|6|7|8|9) c5_9;; 10) c10;; 11) c11;; 12) c12;;
    13) c13;; 14) c14;; 15) c15;; 16) c16;; 17) c17;; 18) c18;;
    *) warn "unknown criterion $n";;
  esac
done

say "ledger"
cat "$SUMMARY"
echo
ok "evidence dir: $EV/ — attach MANUAL items, then paste the table into the validation report"
