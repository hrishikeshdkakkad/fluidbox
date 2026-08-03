#!/usr/bin/env bash
# M1.0 gate evidence: verifies every bootstrap guardrail is live and prints a
# PASS/FAIL table (append the output to docs/reviews/…-cloud-m1-readiness/).
#
# Run as the OPERATOR profile (it proves the non-root path works):
#   AWS_PROFILE=fluidbox-operator scripts/cloud/verify-bootstrap.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

ACCOUNT_ID="${ACCOUNT_ID:-471112572248}"
STATE_BUCKET="fluidbox-cloud-tfstate-${ACCOUNT_ID}"
PASS=0; FAIL=0
check() { # check <name> <cmd...>
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$name"; PASS=$((PASS+1)); else fail "$name"; FAIL=$((FAIL+1)); fi
}

say "identity path (root retired?)"
IDENT=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null || true)
echo "  caller: $IDENT"
case "$IDENT" in
  *:root) fail "running as ROOT — the point of the ceremony is to stop doing this"; FAIL=$((FAIL+1));;
  *) ok "non-root caller"; PASS=$((PASS+1));;
esac
check "deployer role assumable" aws sts assume-role \
  --role-arn "$DEPLOYER_ROLE_ARN" --role-session-name verify-bootstrap \
  --duration-seconds 900 --query 'AssumedRoleUser.Arn' --output text

# Root access keys still present? (GetAccountSummary needs no iam:List* on others)
ROOT_KEYS=$(aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text 2>/dev/null || echo "?")
if [ "$ROOT_KEYS" = "0" ]; then
  ok "root access key: RETIRED (AccountAccessKeysPresent=0)"; PASS=$((PASS+1))
elif [ "$ROOT_KEYS" = "?" ]; then
  warn "root key presence unreadable from this profile (fine once hardening removed iam read) — check from the console"
else
  warn "root access key STILL PRESENT (AccountAccessKeysPresent=$ROOT_KEYS) — finish README step 6"
  FAIL=$((FAIL+1))
fi

say "budgets (two-level breaker)"
check "fluidbox-cloud-monthly budget"  aws budgets describe-budget --account-id "$ACCOUNT_ID" --budget-name fluidbox-cloud-monthly
check "fluidbox-account-breaker budget" aws budgets describe-budget --account-id "$ACCOUNT_ID" --budget-name fluidbox-account-breaker

say "cloudtrail + root alarm"
TRAIL_LOGGING=$(aws cloudtrail get-trail-status --name fluidbox-cloud --query IsLogging --output text 2>/dev/null || echo "false")
if [ "$TRAIL_LOGGING" = "True" ] || [ "$TRAIL_LOGGING" = "true" ]; then ok "trail fluidbox-cloud logging"; PASS=$((PASS+1)); else fail "trail fluidbox-cloud NOT logging"; FAIL=$((FAIL+1)); fi
check "root-activity rule" aws events describe-rule --name fluidbox-root-activity
check "alerts SNS topic" aws sns get-topic-attributes --topic-arn "arn:aws:sns:${CLOUD_REGION}:${ACCOUNT_ID}:fluidbox-cloud-alerts"
CONFIRMED=$(aws sns list-subscriptions-by-topic --topic-arn "arn:aws:sns:${CLOUD_REGION}:${ACCOUNT_ID}:fluidbox-cloud-alerts" \
  --query 'Subscriptions[?Protocol==`email`].SubscriptionArn' --output text 2>/dev/null || true)
case "$CONFIRMED" in
  *PendingConfirmation*|"") warn "email subscription NOT confirmed — click the link SNS sent"; FAIL=$((FAIL+1));;
  *) ok "email subscription confirmed"; PASS=$((PASS+1));;
esac

say "terraform state hygiene"
check "state bucket exists"    aws s3api head-bucket --bucket "$STATE_BUCKET"
VER=$(aws s3api get-bucket-versioning --bucket "$STATE_BUCKET" --query Status --output text 2>/dev/null || true)
[ "$VER" = "Enabled" ] && { ok "state bucket versioned"; PASS=$((PASS+1)); } || { fail "state bucket NOT versioned"; FAIL=$((FAIL+1)); }
check "state bucket encrypted" aws s3api get-bucket-encryption --bucket "$STATE_BUCKET"
check "state bucket public-access-blocked" bash -c "aws s3api get-public-access-block --bucket '$STATE_BUCKET' --query 'PublicAccessBlockConfiguration.BlockPublicPolicy' --output text | grep -qi true"

say "cost-allocation tag"
TAG_STATUS=$(aws ce list-cost-allocation-tags --tag-keys project --query 'CostAllocationTags[0].Status' --output text 2>/dev/null || echo "unknown")
if [ "$TAG_STATUS" = "Active" ]; then ok "project tag ACTIVE (fluidbox budget filter live)"; PASS=$((PASS+1));
else warn "project tag status: $TAG_STATUS — the tag-filtered budget matches nothing until Active (24h lag is normal; account breaker covers meanwhile)"; fi

say "result"
echo "  PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && ok "M1.0 guardrail proofs: ALL PASSING" || fail "M1.0 guardrails incomplete — fix the ✗ lines before any platform apply"
exit "$([ "$FAIL" -eq 0 ] && echo 0 || echo 1)"
