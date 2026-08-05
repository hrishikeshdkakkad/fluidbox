#!/usr/bin/env bash
# One command to run when you sit down to start the apply queue.
#
# Everything M1 needs BEFORE the first apply, checked in one place: tooling
# versions, which AWS identity you are, whether the root key is still live,
# whether the two profiles exist, the EKS version's support tier (the
# difference between $73 and $438 a month), account capacity, and the one
# input the platform stack cannot default — operator_cidrs, which it detects
# and offers to write for you.
#
# Read-only. It creates nothing in AWS and (unless you pass --write-tfvars)
# nothing on disk.
#
#   scripts/cloud/cloud-preflight.sh                # report only
#   scripts/cloud/cloud-preflight.sh --write-tfvars # also stage operator_cidrs
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
. scripts/cloud/lib.sh

WRITE=0; [ "${1:-}" = "--write-tfvars" ] && WRITE=1
ACCOUNT="${ACCOUNT_ID:-471112572248}"
REGION="${CLOUD_REGION:-us-east-1}"
K8S="${K8S_VERSION:-1.35}"
READY=0; BLOCKED=0
good() { ok "$1"; READY=$((READY+1)); }
block(){ fail "$1"; BLOCKED=$((BLOCKED+1)); }

say "1. tooling"
need() { # need <cmd> <label> [min-version-note]
  if command -v "$1" >/dev/null 2>&1; then good "$2: $(command -v "$1")"; else block "$2 MISSING${3:+ — $3}"; fi
}
need terraform "terraform" ">= 1.10 (S3-native state locking)"
need aws        "aws cli"
need kubectl    "kubectl"
need helm       "helm"
need jq         "jq"
need docker     "docker (colima)"
TFV=$(terraform version -json 2>/dev/null | jq -r .terraform_version 2>/dev/null)
if [ -n "$TFV" ]; then
  printf '%s\n1.10.0\n' "$TFV" | sort -V -C && block "terraform $TFV is older than 1.10 (S3 use_lockfile)" || good "terraform $TFV supports S3-native locking"
fi

say "2. identity — who would run the applies"
ARN=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null)
[ -n "$ARN" ] && ok "current: $ARN" || block "no usable AWS credentials"
case "$ARN" in
  *:root) warn "you are ROOT — correct ONLY for the one bootstrap apply; everything after needs the operator profile";;
esac
ROOTKEYS=$(aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text 2>/dev/null || echo "?")
case "$ROOTKEYS" in
  0) good "root access key: RETIRED";;
  ?) warn "root key state unreadable from this identity";;
  *) warn "root access key STILL PRESENT — retire it in the bootstrap ceremony (§9-1)";;
esac
for p in fluidbox-operator fluidbox-deployer; do
  if aws configure list-profiles 2>/dev/null | grep -qx "$p"; then good "profile '$p' configured"
  else warn "profile '$p' not configured yet — bootstrap README step 4 creates it"; fi
done

say "3. the EKS version's support tier (a 6x billing difference)"
TIER=$(aws eks describe-cluster-versions --region "$REGION" \
  --query "clusterVersions[?clusterVersion=='$K8S'].versionStatus" --output text 2>/dev/null)
END=$(aws eks describe-cluster-versions --region "$REGION" \
  --query "clusterVersions[?clusterVersion=='$K8S'].endOfStandardSupportDate" --output text 2>/dev/null)
case "$TIER" in
  STANDARD_SUPPORT) good "K8s $K8S is in STANDARD support (standard billing) until ${END%%T*}";;
  EXTENDED_SUPPORT) block "K8s $K8S is in EXTENDED support — \$0.60/cluster-hour instead of \$0.10 (+~\$365/mo). Raise kubernetes_version.";;
  *) warn "could not read the support tier for $K8S";;
esac

say "4. capacity + collisions"
VCPU=$(aws service-quotas get-service-quota --service-code ec2 --quota-code L-1216C47A \
  --region "$REGION" --query 'Quota.Value' --output text 2>/dev/null)
[ -n "$VCPU" ] && good "on-demand standard vCPU quota: ${VCPU%.*} (M1 needs ~4)" || warn "vCPU quota unreadable"
if aws s3api head-bucket --bucket "fluidbox-cloud-tfstate-$ACCOUNT" >/dev/null 2>&1; then
  warn "state bucket already exists — bootstrap has been applied before (that is fine; plan will show 0 to add for it)"
else
  good "state bucket name free: fluidbox-cloud-tfstate-$ACCOUNT"
fi
CLUSTERS=$(aws eks list-clusters --region "$REGION" --query 'clusters' --output text 2>/dev/null)
case "$CLUSTERS" in
  *fluidbox-cloud*) warn "an EKS cluster named fluidbox-cloud already exists";;
  *) good "no fluidbox-cloud cluster yet";;
esac

say "5. operator_cidrs — the one input with no default"
MYIP=$(curl -fsS --max-time 8 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')
if printf '%s' "$MYIP" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
  good "your public IP: $MYIP → operator_cidrs = [\"$MYIP/32\"]"
  TFVARS=deploy/cloud/terraform/platform/terraform.auto.tfvars
  if [ "$WRITE" = "1" ]; then
    if [ -f "$TFVARS" ]; then
      warn "$TFVARS already exists — not overwriting; check its operator_cidrs matches $MYIP/32"
    else
      printf '# staged by scripts/cloud/cloud-preflight.sh on %s\noperator_cidrs = ["%s/32"]\n' \
        "$(date -u +%F)" "$MYIP" > "$TFVARS"
      good "wrote $TFVARS"
    fi
  else
    echo "      (re-run with --write-tfvars to stage it, or set it by hand)"
  fi
  echo "      NOTE: a changing home/office IP means a later apply must update this,"
  echo "      or kubectl stops reaching the API endpoint."
else
  warn "could not detect a public IP — set operator_cidrs by hand ([] and 0.0.0.0/0 are refused at plan time)"
fi

say "6. decisions still owed (M1 brief §12)"
echo "      These are yours; the kit cannot proceed past them:"
echo "        1. account-wide budget number          (recommended \$400)"
echo "        2. AWS account + region                (471112572248 / us-east-1)"
echo "        3. IAM bootstrap approval              (the one root apply)"
echo "        4. identity for M1  ⚠️ MUST BE RE-TAKEN — WorkOS exposes ONE issuer"
echo "           and ONE client per environment, so per-org Connect apps cannot work"
echo "           (docs/reviews/2026-08-03-cloud-m1-readiness/README.md)"
echo "        5. Vercel project link"
echo "        6. first beta org + owner"
echo "        7. approval for any real-model run     (replay covers \$0 acceptance)"

say "verdict"
echo "  ready=$READY blocked=$BLOCKED"
if [ "$BLOCKED" -eq 0 ]; then
  ok "environment is ready for the apply queue (docs/plans/2026-08-03-cloud-m1-decisions.md)"
  echo "  first command, once you have decided: "
  echo "    cd deploy/cloud/terraform/bootstrap && terraform init && terraform plan -var account_budget_limit=<N>"
else
  fail "fix the ✗ items before starting the apply queue"
fi
exit $((BLOCKED > 0))
